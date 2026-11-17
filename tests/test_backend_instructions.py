"""Forwarding of backend server instructions: sanitising, background refresh,
failure handling and the OAuth-specific rules.

The gateway-level happy path (both protocol eras, over the full OAuth leg)
lives in test_aggregation.py; these tests drive ``BackendInstructionsMiddleware``
directly so its intervals can be shortened, still against real HTTP backends.
"""

from __future__ import annotations

import asyncio
import threading
import time
from typing import Self

import pytest
from fastmcp import FastMCP
from starlette.applications import Starlette
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import PlainTextResponse
from starlette.routing import Route

from mcp_gateway.backend_instructions import (
    BackendInstructionsMiddleware,
    sanitize_instructions,
)
from mcp_gateway.storage import Storage
from mcp_gateway.upstream import (
    BackendManager,
    ConnectFlow,
    NotConnectedError,
    _driving_flow,
)
from tests.conftest import free_port, gateway_config

FAST = {"ttl": 0.2, "failure_ttl": 0.2, "startup_grace": 2.0}


def instructed_app(instructions: str | None, seen_auth_headers: list | None = None):
    backend = FastMCP(name="instructed-backend", instructions=instructions)

    @backend.tool
    def noop() -> str:
        """A tool."""
        return "ok"

    app = backend.http_app(path="/mcp")
    if seen_auth_headers is not None:

        class RecordHeaders(BaseHTTPMiddleware):
            async def dispatch(self, request, call_next):
                seen_auth_headers.append(request.headers.get("authorization"))
                return await call_next(request)

        app.add_middleware(RecordHeaders)
    return app


@pytest.fixture
def hung_backend(run_server):
    """A backend that accepts connections and then never answers."""
    release = threading.Event()

    async def hang(request):
        while not release.is_set():
            await asyncio.sleep(0.05)
        return PlainTextResponse("released", status_code=503)

    app = Starlette(routes=[Route("/mcp", hang, methods=["GET", "POST", "DELETE"])])
    server = run_server(app)
    yield server
    # Let the parked requests finish so the server can shut down promptly.
    release.set()


@pytest.fixture
def make_middleware():
    """Build a middleware (plus its BackendManager) for ``{name: backend config}``."""
    storages: list[Storage] = []

    def _make(backends: dict, **kwargs) -> tuple[BackendInstructionsMiddleware, BackendManager]:
        config = gateway_config(free_port(), backends=backends)
        storage = Storage(config.storage.path, config.auth.encryption_key)
        storages.append(storage)
        manager = BackendManager(config, storage)
        clients = {
            name: manager.build_client(name, backend) for name, backend in config.backends.items()
        }
        return BackendInstructionsMiddleware(clients, manager, **{**FAST, **kwargs}), manager

    yield _make
    for storage in storages:
        storage.close()


def public(url: str) -> dict:
    return {"url": f"{url}/mcp", "auth": {"type": "none"}}


async def eventually(predicate, timeout: float = 10.0) -> None:
    """Wait until the async `predicate` holds."""
    deadline = time.monotonic() + timeout
    while not await predicate():
        if time.monotonic() > deadline:
            raise AssertionError("condition not met in time")
        await asyncio.sleep(0.05)


# --------------------------------------------------------------- sanitising


def test_sanitize_demotes_headings_below_the_gateway_section():
    text = "# Top\n## Backend `github` (its tools are exposed with the prefix `github_`)\n###### Deep"
    assert sanitize_instructions(text).split("\n") == [
        "### Top",
        "#### Backend `github` (its tools are exposed with the prefix `github_`)",
        "###### Deep",
    ]


def test_sanitize_demotes_setext_headings():
    assert sanitize_instructions("Title\n=====\n\nSub\n---\n\ntext\n\n---\n") == (
        "### Title\n\n#### Sub\n\ntext\n\n---"
    )


def test_sanitize_leaves_code_fences_and_inline_hashes_alone():
    text = "Use ## inline freely.\n\n```bash\n# a comment\n## another\n```\n\n#hashtag"
    assert sanitize_instructions(text) == text


def test_sanitize_strips_control_characters_and_normalises_newlines():
    assert sanitize_instructions("a\x00b\x1b[31m\r\nc\td\x7f") == "ab[31m\nc\td"


def test_sanitize_caps_length():
    out = sanitize_instructions("x" * 50_000, max_chars=100)
    assert out.startswith("x" * 100 + "\n\n")
    assert out.endswith("[Instructions truncated by the gateway]")
    assert len(out) < 200
    assert sanitize_instructions("x" * 100, max_chars=100) == "x" * 100


@pytest.mark.parametrize("empty", [None, "", "  \n\t "])
def test_sanitize_empty(empty):
    assert sanitize_instructions(empty) == ""


# ---------------------------------------------------- background refreshing


async def test_refresh_picks_up_changes_and_keeps_last_value_while_backend_is_down(
    run_server, make_middleware
):
    port = free_port()
    server = run_server(instructed_app("Version one."), port)
    middleware, _ = make_middleware({"wiki": public(server.base_url)})

    async with middleware.refreshing():
        assert "Version one." in await middleware.merged("base")

        # Backend goes away: several failed refreshes later the last value
        # that was read successfully is still served.
        await asyncio.to_thread(server.stop)
        await asyncio.sleep(1.0)
        assert "Version one." in await middleware.merged("base")

        # Backend comes back with new text: picked up without a new handshake
        # having to wait for it.
        run_server(instructed_app("Version two."), port)

        async def updated() -> bool:
            return "Version two." in await middleware.merged("base")

        await eventually(updated)
        assert "Version one." not in await middleware.merged("base")


async def test_backend_that_drops_its_instructions_loses_its_section(run_server, make_middleware):
    port = free_port()
    server = run_server(instructed_app("Soon gone."), port)
    middleware, _ = make_middleware({"wiki": public(server.base_url)})

    async with middleware.refreshing():
        assert "Soon gone." in await middleware.merged("base")
        await asyncio.to_thread(server.stop)
        run_server(instructed_app(None), port)

        async def dropped() -> bool:
            return await middleware.merged("base") == "base"

        await eventually(dropped)


async def test_hung_backend_never_delays_the_handshake_past_startup_grace(
    run_server, make_middleware, hung_backend
):
    wiki = run_server(instructed_app("Always cite the wiki page title."))
    middleware, _ = make_middleware(
        {"wiki": public(wiki.base_url), "hung": public(hung_backend.base_url)},
        startup_grace=0.5,
    )

    async with middleware.refreshing():
        # During startup a handshake waits for the initial reads, but only
        # until the grace period ends -- not for the hung backend.
        started = time.monotonic()
        first = await middleware.merged("base")
        assert time.monotonic() - started < 2.0
        assert "Always cite the wiki page title." in first
        assert "hung" not in first

        # From then on the handshake path does no waiting at all, however
        # many clients arrive at once and however long the backend hangs.
        started = time.monotonic()
        results = await asyncio.gather(*(middleware.merged("base") for _ in range(20)))
        assert time.monotonic() - started < 0.2
        assert all(r == first for r in results)


async def test_handshake_before_refreshing_started_serves_only_the_base(make_middleware):
    middleware, _ = make_middleware({"dead": {"url": "http://127.0.0.1:1/mcp"}})
    assert await middleware.merged("base") == "base"
    assert await middleware.merged(None) is None


@pytest.mark.parametrize(
    "failure",
    [
        asyncio.CancelledError(),
        BaseExceptionGroup("connect failed", [asyncio.CancelledError()]),
        RuntimeError("boom"),
    ],
    ids=["cancelled", "base-exception-group", "exception"],
)
async def test_non_exception_failures_from_a_read_do_not_stop_refreshing(make_middleware, failure):
    """fastmcp's connect path can raise CancelledError / BaseExceptionGroup
    without this task having been cancelled; that is a failed read, not a
    reason to stop refreshing (or to fail anybody's handshake)."""

    class FlakyClient:
        def __init__(self) -> None:
            self.attempts = 0
            self.instructions = "Recovered."

        def new(self) -> FlakyClient:
            return self

        async def __aenter__(self) -> Self:
            self.attempts += 1
            if self.attempts == 1:
                raise failure
            return self

        async def __aexit__(self, *exc_info) -> None:
            return None

    middleware, _ = make_middleware({"flaky": {"url": "http://127.0.0.1:1/mcp"}})
    flaky = FlakyClient()
    middleware._clients["flaky"] = flaky

    async with middleware.refreshing():
        assert await middleware.merged("base") == "base"

        async def recovered() -> bool:
            return "Recovered." in (await middleware.merged("base"))

        await eventually(recovered)
    assert flaky.attempts >= 2


async def test_stopping_cancels_reads_in_flight(run_server, make_middleware, hung_backend):
    middleware, _ = make_middleware({"hung": public(hung_backend.base_url)}, startup_grace=0.1)
    async with middleware.refreshing():
        await middleware.merged("base")
    leftover = [t for t in asyncio.all_tasks() if t.get_name().startswith("instructions-")]
    assert leftover == []


# ------------------------------------------------------------ OAuth backends


async def test_oauth_backend_is_read_only_while_connected(run_server, make_middleware):
    seen: list = []
    server = run_server(instructed_app("OAuth backend guidance.", seen))
    middleware, manager = make_middleware(
        {"up": {"url": f"{server.base_url}/mcp", "auth": {"type": "oauth"}}}
    )

    async def has_section() -> bool:
        return "OAuth backend guidance." in (await middleware.merged("base"))

    async with middleware.refreshing():
        # Not connected yet: the backend is never contacted, so the refresher
        # can't wander into the interactive OAuth machinery.
        await asyncio.sleep(0.8)
        assert await middleware.merged("base") == "base"
        assert seen == []

        # Connected: read with the gateway's own upstream token.
        manager.storage.save_upstream(
            "up", "tokens", {"access_token": "upstream-token", "token_type": "Bearer"}
        )
        await eventually(has_section)
        assert seen and set(seen) == {"Bearer upstream-token"}

        # An admin's connect flow is running: stay off the backend's OAuth
        # provider, but keep serving what is cached.
        flow = ConnectFlow("up")
        flow.task = asyncio.create_task(asyncio.sleep(3600))
        manager._flows_by_backend["up"] = flow
        await asyncio.sleep(0.5)  # let a read that was already in flight finish
        seen.clear()
        await asyncio.sleep(0.8)
        assert seen == []
        assert await has_section()
        flow.task.cancel()
        del manager._flows_by_backend["up"]

        # Disconnected on purpose: the section goes away with the tools.
        manager.disconnect("up")

        async def dropped() -> bool:
            return await middleware.merged("base") == "base"

        await eventually(dropped)


async def test_only_the_task_driving_a_connect_flow_gets_its_authorize_url(make_middleware):
    """A request that merely shares the backend's OAuth provider (MCP traffic,
    an instruction read) must not be handed an admin's pending connect flow."""
    _, manager = make_middleware({"up": {"url": "http://127.0.0.1:1/mcp", "auth": {"type": "oauth"}}})
    flow = ConnectFlow("up")
    manager._flows_by_backend["up"] = flow
    redirect_handler = manager._make_redirect_handler("up")
    url = "https://as.example.test/authorize?state=abc"

    with pytest.raises(NotConnectedError):
        await redirect_handler(url)
    assert not flow.authorize_url.done()
    assert manager._flows_by_state == {}

    async def drive() -> None:
        _driving_flow.set(flow)
        await redirect_handler(url)

    await asyncio.create_task(drive())
    assert flow.authorize_url.result() == url
    assert manager._flows_by_state == {"abc": flow}
