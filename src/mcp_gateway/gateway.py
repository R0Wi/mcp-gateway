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

from mcp_gateway.config import GatewayConfig
from mcp_gateway.oauth_server import GatewayOAuthProvider
from mcp_gateway.upstream import BackendManager

logger = logging.getLogger(__name__)


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
        auth=provider,
        mask_error_details=False,
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
        proxy = create_proxy(clients[name], name=f"proxy-{name}")
        # FastMCP proxies forward the inbound Authorization header upstream by
        # default. That is token passthrough, which the MCP authorization spec
        # explicitly forbids: the gateway token issued to the MCP client must
        # never reach a backend. Backends only ever see credentials the
        # gateway itself holds (static headers or its own upstream OAuth tokens).
        transport = getattr(clients[name], "transport", None)
        if hasattr(transport, "forward_incoming_headers"):
            transport.forward_incoming_headers = False
        mcp.mount(proxy, namespace=name)
        logger.info("Mounted backend %s (%s, auth=%s)", name, backend.url, backend.auth.type)

    return mcp
