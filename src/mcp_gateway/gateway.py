"""The aggregating FastMCP server.

Each enabled backend is mounted as a live proxy under its configured name, so
its tools/resources/prompts appear namespaced (e.g. tool ``create_issue`` of
backend ``github`` becomes ``github_create_issue``). Requests are forwarded to
the backend in real time with the gateway's own upstream credentials; a
backend that is down or not yet connected only removes its own tools from the
listing instead of breaking the whole gateway.
"""

from __future__ import annotations

import logging

from fastmcp import Client, FastMCP
from fastmcp.server import create_proxy
from mcp.types import Icon

from mcp_gateway.config import GatewayConfig
from mcp_gateway.oauth_server import GatewayOAuthProvider
from mcp_gateway.upstream import BackendManager

logger = logging.getLogger(__name__)

# Same mark as the inline-SVG favicon in ui/index.html, advertised to MCP
# clients (e.g. connector pickers) via the initialize response so the
# gateway shows up with an icon instead of a blank/fallback avatar. Kept as
# a data URI -- like the favicon -- so no external image host is ever
# loaded (see the img-src CSP directive in app.py).
_ICON_SVG = (
    "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 360 240'%3E"
    "%3Ccircle cx='26' cy='156' r='13' fill='%23152C6B'/%3E"
    "%3Cline x1='39' y1='156' x2='110' y2='156' stroke='%23152C6B' stroke-width='12' "
    "stroke-linecap='round'/%3E"
    "%3Cpath d='M 118 200 L 118 108 A 58 58 0 0 1 234 108 L 234 200' fill='none' "
    "stroke='%23152C6B' stroke-width='20' stroke-linecap='round'/%3E"
    "%3Cpath d='M 166 86 Q 171.2 106.8 192 112 Q 171.2 117.2 166 138 Q 160.8 117.2 140 112 "
    "Q 160.8 106.8 166 86 Z' fill='%23152C6B'/%3E"
    "%3Cpath d='M 204 77 Q 206.2 85.8 215 88 Q 206.2 90.2 204 99 Q 201.8 90.2 193 88 "
    "Q 201.8 85.8 204 77 Z' fill='%233556B8'/%3E"
    "%3Cpath d='M 244 156 H 271 A 18 18 0 0 0 289 138 V 114 A 18 18 0 0 1 307 96 H 316' "
    "fill='none' stroke='%233556B8' stroke-width='12' stroke-linecap='round'/%3E"
    "%3Cpath d='M 244 156 H 316' fill='none' stroke='%233556B8' stroke-width='12' "
    "stroke-linecap='round'/%3E"
    "%3Cpath d='M 244 156 H 271 A 18 18 0 0 1 289 174 V 198 A 18 18 0 0 0 307 216 H 316' "
    "fill='none' stroke='%233556B8' stroke-width='12' stroke-linecap='round'/%3E"
    "%3Ccircle cx='330' cy='96' r='13' fill='%233556B8'/%3E"
    "%3Ccircle cx='330' cy='156' r='13' fill='%233556B8'/%3E"
    "%3Ccircle cx='330' cy='216' r='13' fill='%233556B8'/%3E"
    "%3C/svg%3E"
)


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
        icons=[Icon(src=_ICON_SVG, mimeType="image/svg+xml")],
        auth=provider,
        # Don't leak backend URLs, HTTP error bodies or internal exception
        # types to MCP clients; diagnose failures from the server logs
        # instead (run with --log-level debug for detail).
        mask_error_details=True,
    )

    @mcp.tool(name="gateway_status")
    def gateway_status() -> list[dict]:
        """List the backends configured in this gateway and their connection state."""
        logger.debug("gateway_status tool invoked")
        return manager.backend_status()

    for name, backend in config.backends.items():
        if not backend.enabled:
            logger.info("Backend %s is disabled; skipping", name)
            continue
        proxy = create_proxy(clients[name], name=f"proxy-{name}", mask_error_details=True)
        # FastMCP proxies forward the inbound Authorization header upstream by
        # default. That is token passthrough, which the MCP authorization spec
        # explicitly forbids: the gateway token issued to the MCP client must
        # never reach a backend. Backends only ever see credentials the
        # gateway itself holds (static headers or its own upstream OAuth tokens).
        #
        # This is the single most important invariant in the gateway, so fail
        # startup loudly rather than silently no-op if a future fastmcp
        # release renames or removes the attribute -- a silent no-op here
        # would re-enable token passthrough with no error and no test
        # failure to catch it.
        transport = getattr(clients[name], "transport", None)
        if not hasattr(transport, "forward_incoming_headers"):
            raise RuntimeError(
                f"Backend {name!r}: transport {type(transport).__name__} has no "
                "'forward_incoming_headers' attribute; cannot guarantee the "
                "no-token-passthrough invariant. This likely means the "
                "installed fastmcp version changed its proxy transport API."
            )
        transport.forward_incoming_headers = False
        mcp.mount(proxy, namespace=name)
        logger.info("Mounted backend %s (%s, auth=%s)", name, backend.url, backend.auth.type)

    return mcp
