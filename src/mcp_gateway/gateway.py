"""The aggregating FastMCP server.

Each enabled backend is mounted as a live proxy under its configured name, so
its tools/resources/prompts appear namespaced (e.g. tool ``create_issue`` of
backend ``github`` becomes ``github_create_issue``). Requests are forwarded to
the backend in real time with the gateway's own upstream credentials; a
backend that is down or not yet connected only removes its own tools from the
listing instead of breaking the whole gateway.
"""

from __future__ import annotations

import asyncio
import base64
import dataclasses
import functools
import logging
import time

from fastmcp import Client, FastMCP
from fastmcp.client.transports.base import TransportOptions
from fastmcp.server import create_proxy
from fastmcp.server.middleware import Middleware
from mcp.types import DiscoverResult, Icon, ToolAnnotations

from mcp_gateway.config import GatewayConfig
from mcp_gateway.oauth_server import GatewayOAuthProvider
from mcp_gateway.upstream import BackendManager, NoForwardStreamableHttpTransport
from mcp_gateway.web import STATIC_DIR

logger = logging.getLogger(__name__)

# Single source of truth for the gateway's mark: ui/public/favicon.svg,
# copied verbatim into the built UI's static root by `npm run build` (see
# ui/index.html, which points its own <link rel="icon"> at the same file).
# Read it from there at runtime and re-encode as a data URI so MCP clients
# (e.g. connector pickers) get the identical icon via the initialize
# response's serverInfo.icons -- no second copy of the SVG to keep in sync.
_FAVICON_PATH = STATIC_DIR / "favicon.svg"


@functools.lru_cache(maxsize=1)
def _server_icons() -> list[Icon]:
    try:
        svg = _FAVICON_PATH.read_bytes()
    except OSError:
        # UI not built yet (e.g. local dev, tests) -- omit the icon rather
        # than failing gateway startup; see web.py's handling of the same
        # missing-build case for /ui/.
        logger.debug("Favicon not found at %s; MCP server will advertise no icon", _FAVICON_PATH)
        return []
    data_uri = "data:image/svg+xml;base64," + base64.b64encode(svg).decode("ascii")
    return [Icon(src=data_uri, mime_type="image/svg+xml")]


def _require_no_header_forwarding(name: str, client: Client) -> None:
    """Refuse to start unless `client` can't pass the caller's token upstream.

    FastMCP proxies forward the inbound request's headers (Authorization
    included) to the backend by default. That is token passthrough, which the
    MCP authorization spec explicitly forbids, and the single most important
    invariant in the gateway. ``NoForwardStreamableHttpTransport`` turns it
    off by overriding ``TransportOptions.forward_incoming_headers``; fail
    startup loudly if a backend client bypasses that transport, or if a future
    fastmcp release renames or removes the option -- either would re-enable
    passthrough (or break every backend call) with no error at startup.
    """
    transport = getattr(client, "transport", None)
    if not isinstance(transport, NoForwardStreamableHttpTransport):
        raise TypeError(
            f"Backend {name!r}: transport {type(transport).__name__} is not "
            "NoForwardStreamableHttpTransport; cannot guarantee the "
            "no-token-passthrough invariant."
        )
    if "forward_incoming_headers" not in {f.name for f in dataclasses.fields(TransportOptions)}:
        raise RuntimeError(
            "fastmcp's TransportOptions has no 'forward_incoming_headers' field; "
            "cannot guarantee the no-token-passthrough invariant. This likely "
            "means the installed fastmcp version changed its proxy transport API."
        )


class BackendInstructionsMiddleware(Middleware):
    """Append every backend's own server ``instructions`` to the gateway's.

    fastmcp forwards a proxied backend's instructions only when the proxy is
    the root server (``ProxyMetadataMiddleware``). Mounted under the gateway,
    that middleware never runs, and the gateway sets its own instructions
    anyway, so without this the guidance a backend ships for its model would
    be silently dropped. Each backend's text goes in its own section, headed by
    the namespace its tools were mounted under, since the text refers to the
    backend's un-prefixed tool names.

    Works for both protocol eras: ``initialize`` (handshake) and
    ``server/discover`` (sessionless ``2026-07-28``). Discover can arrive on
    every client connection, so results are cached for ``ttl`` seconds, and
    backends that couldn't be read (down, OAuth not connected yet, slow) are
    retried after only ``failure_ttl``. A backend never delays or fails the
    gateway's own handshake by more than ``timeout`` seconds.
    """

    def __init__(
        self,
        clients: dict[str, Client],
        *,
        ttl: float = 300.0,
        failure_ttl: float = 30.0,
        timeout: float = 5.0,
    ) -> None:
        self._clients = clients
        self._ttl = ttl
        self._failure_ttl = failure_ttl
        self._timeout = timeout
        # name -> (instructions or None, monotonic expiry)
        self._cache: dict[str, tuple[str | None, float]] = {}
        self._lock = asyncio.Lock()

    async def _read(self, name: str, client: Client) -> tuple[str | None, bool]:
        """Return ``(instructions, ok)`` read from a fresh session to the backend."""

        async def read() -> str | None:
            # A separate client instance: never touch the proxy's own sessions.
            fresh = client.new()
            async with fresh:
                return fresh.instructions

        try:
            return await asyncio.wait_for(read(), timeout=self._timeout), True
        except Exception as exc:  # noqa: BLE001 - one backend must not break initialize
            logger.debug(
                "Backend %s: could not read server instructions: %s: %s",
                name,
                type(exc).__name__,
                exc,
            )
            return None, False

    async def _backend_instructions(self) -> dict[str, str]:
        async with self._lock:
            now = time.monotonic()
            stale = [n for n in self._clients if self._cache.get(n, (None, 0.0))[1] <= now]
            if stale:
                results = await asyncio.gather(*(self._read(n, self._clients[n]) for n in stale))
                now = time.monotonic()
                for name, (text, ok) in zip(stale, results, strict=True):
                    self._cache[name] = (text, now + (self._ttl if ok else self._failure_ttl))
            return {
                name: text.strip()
                for name in self._clients
                if (text := self._cache[name][0]) and text.strip()
            }

    async def _merged(self, base: str | None) -> str | None:
        sections = [
            f"## Backend `{name}` (its tools are exposed with the prefix `{name}_`)\n\n{text}"
            for name, text in (await self._backend_instructions()).items()
        ]
        if not sections:
            return base
        return "\n\n".join([base, *sections] if base else sections)

    async def on_initialize(self, context, call_next):
        result = await call_next(context)
        if result is None:
            return None
        return result.model_copy(update={"instructions": await self._merged(result.instructions)})

    async def on_discover(self, context, call_next):
        result = await call_next(context)
        if not isinstance(result, DiscoverResult):
            return result
        return result.model_copy(update={"instructions": await self._merged(result.instructions)})


def build_gateway(
    config: GatewayConfig,
    provider: GatewayOAuthProvider,
    manager: BackendManager,
    clients: dict[str, Client],
) -> FastMCP:
    mcp: FastMCP = FastMCP(
        name="MCP Gateway",
        instructions=(
            "Aggregating gateway in front of multiple backend MCP servers. "
            "Tools are namespaced by backend name (e.g. github_create_issue). "
            "Use the gateway_status tool to inspect configured backends."
        ),
        icons=_server_icons(),
        auth=provider,
        # Don't leak backend URLs, HTTP error bodies or internal exception
        # types to MCP clients; diagnose failures from the server logs
        # instead (run with --log-level debug for detail).
        mask_error_details=True,
    )

    # Status icon: simple circle with dot indicator
    _status_icon_svg = (
        '<svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">'
        '<circle cx="12" cy="12" r="11" stroke="currentColor" stroke-width="2" fill="none"/>'
        '<circle cx="12" cy="12" r="5" fill="currentColor"/>'
        '</svg>'
    )
    _status_icon_data_uri = (
        "data:image/svg+xml;base64," +
        base64.b64encode(_status_icon_svg.encode("utf-8")).decode("ascii")
    )

    @mcp.tool(
        name="gateway_status",
        annotations=ToolAnnotations(
            title="Gateway Status",
            read_only_hint=True,
            open_world_hint=False
        ),
        icons=[Icon(src=_status_icon_data_uri, mime_type="image/svg+xml")]
    )
    def gateway_status() -> list[dict]:
        """List the backends configured in this gateway and their connection state."""
        logger.debug("gateway_status tool invoked")
        return manager.backend_status()

    mounted: dict[str, Client] = {}
    for name, backend in config.backends.items():
        if not backend.enabled:
            logger.info("Backend %s is disabled; skipping", name)
            continue
        _require_no_header_forwarding(name, clients[name])
        proxy = create_proxy(clients[name], name=f"proxy-{name}", mask_error_details=True)
        mcp.mount(proxy, namespace=name)
        mounted[name] = clients[name]
        logger.info("Mounted backend %s (%s, auth=%s)", name, backend.url, backend.auth.type)

    if mounted:
        mcp.add_middleware(BackendInstructionsMiddleware(mounted))

    return mcp
