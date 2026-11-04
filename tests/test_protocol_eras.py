"""MCP protocol eras on both legs of the gateway.

FastMCP 4 serves the sessionless ``2026-07-28`` protocol (``server/discover``,
no ``Mcp-Session-Id``, every request self-describing) and the older
handshake era (``initialize`` + session) from the same ``/mcp`` endpoint,
negotiated per connection. The gateway's backend clients negotiate the same
way (``mode="auto"``), falling back to the handshake for backends that only
speak that.

These run without ``server.stateless_http``: modern clients never need a
session, regardless of that setting.
"""

from __future__ import annotations

import asyncio

import httpx
import httpx2
import pytest
from fastmcp import Client, FastMCP
from fastmcp.client.transports import StreamableHttpTransport
from mcp_types.version import LATEST_HANDSHAKE_VERSION, LATEST_MODERN_VERSION
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from mcp_gateway import app as app_module
from mcp_gateway.app import create_app
from tests.conftest import free_port, gateway_config, obtain_tokens, register_client


def make_backend(name: str, seen_versions: list, *, legacy_only: bool = False):
    backend = FastMCP(name=f"{name}-backend")

    @backend.tool
    def echo(text: str) -> str:
        """Echo text back."""
        return f"{name}: {text}"

    app = backend.http_app(path="/mcp")

    class RecordVersion(BaseHTTPMiddleware):
        async def dispatch(self, request, call_next):
            if request.url.path.startswith("/mcp"):
                version = request.headers.get("mcp-protocol-version")
                seen_versions.append(version)
                if legacy_only and version == LATEST_MODERN_VERSION:
                    # Verbatim what a handshake-only server (fastmcp 3.x /
                    # MCP SDK v1) answers the modern server/discover probe with.
                    return JSONResponse(
                        {
                            "jsonrpc": "2.0",
                            "id": "server-error",
                            "error": {
                                "code": -32600,
                                "message": "Bad Request: Missing session ID",
                            },
                        },
                        status_code=400,
                    )
            return await call_next(request)

    app.add_middleware(RecordVersion)
    return app


@pytest.fixture
async def stack(run_server):
    modern_seen: list = []
    legacy_seen: list = []
    modern = run_server(make_backend("modern", modern_seen))
    legacy = run_server(make_backend("legacy", legacy_seen, legacy_only=True))

    port = free_port()
    config = gateway_config(
        port,
        backends={
            "modern": {"url": f"{modern.base_url}/mcp", "auth": {"type": "none"}},
            "legacy": {"url": f"{legacy.base_url}/mcp", "auth": {"type": "none"}},
        },
    )
    base = run_server(create_app(config), port).base_url
    async with httpx.AsyncClient() as http:
        client_id = await register_client(http, base)
        token = (await obtain_tokens(http, base, client_id))["access_token"]
    return base, token, modern_seen, legacy_seen


def recording_client(base: str, token: str, mode: str, responses: list) -> Client:
    async def record(response: httpx2.Response) -> None:
        responses.append(response)

    transport = StreamableHttpTransport(
        f"{base}/mcp",
        headers={"Authorization": f"Bearer {token}"},
        httpx_client_factory=lambda **kwargs: httpx2.AsyncClient(
            event_hooks={"response": [record]}, **kwargs
        ),
    )
    return Client(transport, mode=mode)


@pytest.mark.parametrize(
    ("mode", "expected_version", "sessionful"),
    [("auto", LATEST_MODERN_VERSION, False), ("legacy", LATEST_HANDSHAKE_VERSION, True)],
)
async def test_client_eras_reach_modern_and_legacy_backends(
    stack, mode, expected_version, sessionful
):
    base, token, modern_seen, legacy_seen = stack
    responses: list[httpx2.Response] = []

    async with recording_client(base, token, mode, responses) as client:
        assert client.protocol_version == expected_version
        names = {t.name for t in await client.list_tools()}
        assert {"gateway_status", "modern_echo", "legacy_echo"} <= names
        result = await client.call_tool("modern_echo", {"text": "hi"})
        assert result.content[0].text == "modern: hi"
        result = await client.call_tool("legacy_echo", {"text": "hi"})
        assert result.content[0].text == "legacy: hi"

    session_ids = {r.headers.get("mcp-session-id") for r in responses} - {None}
    assert bool(session_ids) is sessionful
    # Not even a rejected probe on the way: the pre-FastMCP-4 gateway answered
    # every modern client's opening server/discover with 400 and only worked
    # because the client fell back to the handshake.
    assert [r.status_code for r in responses if r.status_code >= 400] == []

    # Backend legs negotiate independently of the front: the modern backend
    # is only ever spoken to sessionlessly, the legacy-only one falls back to
    # the handshake after rejecting the discover probe.
    assert modern_seen and set(modern_seen) == {LATEST_MODERN_VERSION}
    assert LATEST_HANDSHAKE_VERSION in legacy_seen


async def test_modern_request_needs_no_prior_handshake(stack):
    """One self-contained 2026-07-28 request is a complete exchange: no
    server/discover or initialize first, no session header, not even with
    server.stateless_http off."""
    base, token, _, _ = stack
    headers = {
        "Accept": "application/json, text/event-stream",
        "MCP-Protocol-Version": LATEST_MODERN_VERSION,
        "Mcp-Method": "tools/call",
        "Mcp-Name": "modern_echo",
    }
    body = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "modern_echo",
            "arguments": {"text": "raw"},
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": LATEST_MODERN_VERSION,
                "io.modelcontextprotocol/clientCapabilities": {},
            },
        },
    }
    async with httpx.AsyncClient() as http:
        r = await http.post(f"{base}/mcp", headers=headers, json=body)
        assert r.status_code == 401
        assert "resource_metadata=" in r.headers["www-authenticate"]

        r = await http.post(
            f"{base}/mcp", headers={**headers, "Authorization": f"Bearer {token}"}, json=body
        )
    assert r.status_code == 200, r.text
    assert "mcp-session-id" not in r.headers
    assert r.json()["result"]["content"][0]["text"] == "modern: raw"


async def test_connection_test_probes_each_backend_era(stack):
    """``ping`` no longer exists on the modern protocol; the connection test's
    liveness check must still pass against both backend eras."""
    base, _, _, _ = stack
    async with httpx.AsyncClient(base_url=base) as http:
        r = await http.post("/auth/api/login", json={"username": "admin", "password": "pw"})
        http.cookies.update(r.cookies)
        details = {}
        for name in ("modern", "legacy"):
            r = await http.post(f"/auth/api/backends/{name}/test-connection")
            assert r.status_code == 200
            assert '"status": "error"' not in r.text, r.text
            details[name] = r.text
    assert f"Connected (protocol {LATEST_MODERN_VERSION})" in details["modern"]
    assert f"Ping succeeded (protocol {LATEST_HANDSHAKE_VERSION})" in details["legacy"]


async def test_idle_handshake_session_is_reaped_with_404(run_server, monkeypatch):
    """A handshake-era session must not live forever, and a request on one that
    has been reaped must get 404 -- the spec's "re-initialize" signal.

    Regression for the empty-tool-list bug: on the pre-FastMCP-4 stack
    sessions never expired, Claude kept reusing days-old ones, and once such a
    request was answered with 400 instead, Claude showed the connector with no
    tools until "Refresh tool list" was clicked.
    """
    monkeypatch.setattr(app_module, "MCP_SESSION_IDLE_TIMEOUT_SECONDS", 1)
    port = free_port()
    base = run_server(create_app(gateway_config(port)), port).base_url
    async with httpx.AsyncClient() as http:
        client_id = await register_client(http, base)
        token = (await obtain_tokens(http, base, client_id))["access_token"]
        headers = {
            "Accept": "application/json, text/event-stream",
            "Authorization": f"Bearer {token}",
        }
        initialize = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": LATEST_HANDSHAKE_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "pytest", "version": "0"},
            },
        }
        r = await http.post(f"{base}/mcp", headers=headers, json=initialize)
        assert r.status_code == 200, r.text
        session = {
            **headers,
            "Mcp-Session-Id": r.headers["mcp-session-id"],
            "MCP-Protocol-Version": LATEST_HANDSHAKE_VERSION,
        }
        r = await http.post(
            f"{base}/mcp",
            headers=session,
            json={"jsonrpc": "2.0", "method": "notifications/initialized"},
        )
        assert r.status_code == 202
        list_tools = {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}
        r = await http.post(f"{base}/mcp", headers=session, json=list_tools)
        assert r.status_code == 200
        assert "gateway_status" in r.text

        # Any request on the session counts as activity, so wait it out once
        # rather than polling.
        await asyncio.sleep(2.5)
        r = await http.post(f"{base}/mcp", headers=session, json=list_tools)
        assert r.status_code == 404, r.text

        # ...and re-initializing, as the client is then supposed to, works.
        r = await http.post(f"{base}/mcp", headers=headers, json=initialize)
        assert r.status_code == 200, r.text
