"""_drive_interactive_reauth (see mcp_gateway.upstream) drives the MCP SDK's
private async_auth_flow generator directly instead of waiting for a real 401
from the upstream server.

That's necessary because start_connect used to just ping the backend and
wait for the SDK's redirect_handler to fire off the back of a 401 response.
Two things can each independently make that ping succeed without ever
hitting a 401 -- leaving the interactive flow's authorize_url unresolved
until the whole connect attempt times out:

- a still-valid (or proactively-refreshed) stored access token
- a backend that, like GitHub's Copilot MCP server, answers basic protocol
  methods (initialize/ping) unauthenticated and only enforces auth on tool
  calls

The first two tests simulate the second case: every real request the mock
backend sees succeeds (never a 401), so the fix under test must be the one
forcing the interactive path itself, not merely clearing the stored token.

The rest guard against hand-rolling a generator driver instead of using
httpx's own (``Client._send_handling_auth``): forgetting to close the
generator on error/cancellation leaks the lock ``async_auth_flow`` holds for
its whole body forever, forgetting ``follow_redirects=True`` breaks any
discovery/registration/token endpoint behind a redirect, and naively
replaying the generator's very last step re-sends the original probe for
real a second time.
"""

from __future__ import annotations

import asyncio
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from mcp.shared.auth import OAuthClientInformationFull, OAuthClientMetadata, OAuthToken
from pydantic import AnyUrl

from mcp_gateway import upstream
from mcp_gateway.storage import Storage
from mcp_gateway.upstream import (
    DbTokenStorage,
    JsonTokenOAuthClientProvider,
    _drive_interactive_reauth,
)

SERVER_URL = "https://mcp.example.test/mcp/"
REDIRECT_URI = "http://localhost/oauth/callback"


def make_provider(storage: Storage, redirect_handler, callback_handler) -> JsonTokenOAuthClientProvider:
    return JsonTokenOAuthClientProvider(
        server_url=SERVER_URL,
        client_metadata=OAuthClientMetadata(
            redirect_uris=[AnyUrl(REDIRECT_URI)],
            grant_types=["authorization_code", "refresh_token"],
            response_types=["code"],
            token_endpoint_auth_method="none",
        ),
        storage=DbTokenStorage(storage, "test-backend"),
        redirect_handler=redirect_handler,
        callback_handler=callback_handler,
    )


@pytest.fixture
def storage(tmp_path):
    s = Storage(tmp_path / "t.db", "test-passphrase")
    yield s
    s.close()


def make_mock_backend_handler(mcp_path_calls: list[str] | None = None):
    """A backend that never 401s anything -- discovery/registration/token
    endpoints behave normally, but nothing here ever challenges auth.

    ``mcp_path_calls`` (if given) records every request to ``/mcp/`` --
    that's the initial probe, sent for real before being judged non-401 and
    overridden. ``_drive_interactive_reauth`` must not hit it a second time
    to replay the generator's final step.
    """

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.startswith("/.well-known/"):
            return httpx.Response(404)
        if request.url.path == "/register":
            info = OAuthClientInformationFull(
                client_id="dcr-client-id",
                redirect_uris=[AnyUrl(REDIRECT_URI)],
                grant_types=["authorization_code", "refresh_token"],
                response_types=["code"],
                token_endpoint_auth_method="none",
            )
            return httpx.Response(201, json=info.model_dump(mode="json"))
        if request.url.path == "/token":
            return httpx.Response(
                200,
                json={
                    "access_token": "at-from-interactive-flow",
                    "refresh_token": "rt-from-interactive-flow",
                    "expires_in": 3600,
                    "token_type": "bearer",
                },
            )
        if request.url.path == "/mcp/":
            if mcp_path_calls is not None:
                mcp_path_calls.append(request.method)
            return httpx.Response(200)
        raise AssertionError(f"unexpected request in test: {request.method} {request.url}")

    return handler


_mock_backend_handler = make_mock_backend_handler()


async def test_drive_interactive_reauth_completes_without_a_real_401(storage, monkeypatch):
    captured: dict[str, str] = {}

    async def redirect_handler(authorization_url: str) -> None:
        captured["url"] = authorization_url
        captured["state"] = parse_qs(urlparse(authorization_url).query)["state"][0]

    async def callback_handler() -> tuple[str, str | None]:
        return "auth-code-123", captured["state"]

    provider = make_provider(storage, redirect_handler, callback_handler)

    real_async_client = httpx.AsyncClient

    def fake_async_client(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(_mock_backend_handler)
        return real_async_client(*args, **kwargs)

    monkeypatch.setattr(upstream.httpx, "AsyncClient", fake_async_client)

    await _drive_interactive_reauth(provider)

    # The redirect handler was actually invoked -- the interactive path ran
    # end to end despite nothing ever 401ing.
    assert "url" in captured
    assert captured["url"].startswith("https://mcp.example.test/authorize")

    assert provider.context.current_tokens is not None
    assert provider.context.current_tokens.access_token == "at-from-interactive-flow"

    stored = await provider.context.storage.get_tokens()
    assert stored is not None
    assert stored.access_token == "at-from-interactive-flow"


async def test_drive_interactive_reauth_clears_a_still_valid_stored_token(storage, monkeypatch):
    """A stored, still-valid token must not short-circuit the interactive
    flow -- start_connect's whole point is to let the admin re-authorize
    on demand (e.g. after revoking access upstream)."""
    token_storage = DbTokenStorage(storage, "test-backend")
    await token_storage.set_tokens(
        OAuthToken.model_validate(
            {"access_token": "stale-but-unexpired", "token_type": "bearer", "expires_in": 3600}
        )
    )

    redirected = {"called": False}
    captured_url: dict[str, str] = {}

    async def redirect_handler(authorization_url: str) -> None:
        redirected["called"] = True
        captured_url["url"] = authorization_url

    async def callback_handler() -> tuple[str, str | None]:
        state = parse_qs(urlparse(captured_url["url"]).query)["state"][0]
        return "auth-code-456", state

    provider = make_provider(storage, redirect_handler, callback_handler)

    real_async_client = httpx.AsyncClient

    def fake_async_client(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(_mock_backend_handler)
        return real_async_client(*args, **kwargs)

    monkeypatch.setattr(upstream.httpx, "AsyncClient", fake_async_client)

    await _drive_interactive_reauth(provider)

    assert redirected["called"] is True
    assert provider.context.current_tokens.access_token == "at-from-interactive-flow"


async def test_drive_interactive_reauth_does_not_replay_the_probe(storage, monkeypatch):
    """Once the token exchange has completed, the generator's one remaining
    step -- re-yielding the original probe with the new Authorization header
    -- must not be sent for real a second time."""
    captured: dict[str, str] = {}

    async def redirect_handler(authorization_url: str) -> None:
        captured["url"] = authorization_url

    async def callback_handler() -> tuple[str, str | None]:
        state = parse_qs(urlparse(captured["url"]).query)["state"][0]
        return "auth-code-789", state

    provider = make_provider(storage, redirect_handler, callback_handler)

    mcp_path_calls: list[str] = []
    handler = make_mock_backend_handler(mcp_path_calls)
    real_async_client = httpx.AsyncClient

    def fake_async_client(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        return real_async_client(*args, **kwargs)

    monkeypatch.setattr(upstream.httpx, "AsyncClient", fake_async_client)

    await _drive_interactive_reauth(provider)

    # Exactly one hit: the real, initial probe attempt (judged non-401 and
    # overridden with a synthetic 401). The final replay is skipped.
    assert mcp_path_calls == ["GET"]


async def test_drive_interactive_reauth_releases_lock_on_failure(storage, monkeypatch):
    """A network failure partway through must not leave the provider's
    context lock held -- async_auth_flow holds it for its entire body, and a
    hand-rolled driver that doesn't close the generator on the way out wedges
    every later connect attempt and every proactive token refresh."""

    def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("network down", request=request)

    provider = make_provider(storage, redirect_handler=None, callback_handler=None)

    real_async_client = httpx.AsyncClient

    def fake_async_client(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(boom)
        return real_async_client(*args, **kwargs)

    monkeypatch.setattr(upstream.httpx, "AsyncClient", fake_async_client)

    with pytest.raises(httpx.ConnectError):
        await _drive_interactive_reauth(provider)

    assert not provider.context.lock.locked()


async def test_drive_interactive_reauth_releases_lock_on_cancellation(storage, monkeypatch):
    """Cancelling the driving task (start_connect does this for a stale or
    timed-out flow) must also release the lock, not just a raised
    exception."""
    started = asyncio.Event()

    async def slow_get(*args, **kwargs):
        started.set()
        await asyncio.sleep(10)
        raise AssertionError("should have been cancelled first")

    provider = make_provider(storage, redirect_handler=None, callback_handler=None)

    real_async_client = httpx.AsyncClient

    def fake_async_client(*args, **kwargs):
        client = real_async_client(*args, **kwargs)
        monkeypatch.setattr(client, "send", slow_get)
        return client

    monkeypatch.setattr(upstream.httpx, "AsyncClient", fake_async_client)

    task = asyncio.ensure_future(_drive_interactive_reauth(provider))
    await started.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert not provider.context.lock.locked()


async def test_drive_interactive_reauth_follows_redirects(storage, monkeypatch):
    """discovery/registration/token requests must follow redirects, matching
    the SDK's own client (create_mcp_http_client always sets
    follow_redirects=True) -- otherwise a 30x anywhere in that chain breaks
    the flow.

    DCR's registration request is the one under test here: it 307s once
    before the real registration endpoint answers.
    """
    captured: dict[str, str] = {}

    async def redirect_handler(authorization_url: str) -> None:
        captured["url"] = authorization_url

    async def callback_handler() -> tuple[str, str | None]:
        state = parse_qs(urlparse(captured["url"]).query)["state"][0]
        return "auth-code-redirected", state

    provider = make_provider(storage, redirect_handler, callback_handler)

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.startswith("/.well-known/"):
            return httpx.Response(404)
        if request.url.path == "/register":
            return httpx.Response(307, headers={"location": "/register-final"})
        if request.url.path == "/register-final":
            info = OAuthClientInformationFull(
                client_id="dcr-client-id",
                redirect_uris=[AnyUrl(REDIRECT_URI)],
                grant_types=["authorization_code", "refresh_token"],
                response_types=["code"],
                token_endpoint_auth_method="none",
            )
            return httpx.Response(201, json=info.model_dump(mode="json"))
        if request.url.path == "/token":
            return httpx.Response(
                200,
                json={
                    "access_token": "at-after-redirect",
                    "expires_in": 3600,
                    "token_type": "bearer",
                },
            )
        if request.url.path == "/mcp/":
            return httpx.Response(200)
        raise AssertionError(f"unexpected request in test: {request.method} {request.url}")

    real_async_client = httpx.AsyncClient

    def fake_async_client(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        return real_async_client(*args, **kwargs)

    monkeypatch.setattr(upstream.httpx, "AsyncClient", fake_async_client)

    await _drive_interactive_reauth(provider)

    assert provider.context.current_tokens.access_token == "at-after-redirect"
