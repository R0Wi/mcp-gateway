"""MCP Gateway package.

Logging is configured here — as the package `__init__`, this runs before any
submodule, regardless of entry point (`mcp-gateway run`, or the app served
directly by an external ASGI server such as `uvicorn mcp_gateway.app:create_app`)
and before anything imports FastMCP.

Level is controlled by the ``MCP_GATEWAY_LOG_LEVEL`` environment variable
(``debug``, ``info``, ``warning``, ``error``, ``critical``; default ``info``).
"""

from __future__ import annotations

import logging
import os

from mcp_gateway.log_redaction import install_url_query_filters

_LOG_LEVEL = os.environ.get("MCP_GATEWAY_LOG_LEVEL", "info").upper()

# FastMCP reads its own log level from $FASTMCP_LOG_LEVEL (via pydantic-settings)
# the moment it is first imported, into a separate "fastmcp" logger that does
# not propagate to the root logger. Sync it to MCP_GATEWAY_LOG_LEVEL so one
# knob controls both; this must happen before anything imports fastmcp, which
# is guaranteed here since this module runs before any mcp_gateway submodule.
os.environ.setdefault("FASTMCP_LOG_LEVEL", _LOG_LEVEL)

logging.basicConfig(
    level=getattr(logging, _LOG_LEVEL, logging.INFO),
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)

# httpx2 logs every outgoing request, full URL included, at INFO. A backend URL
# can carry a credential in its query string (``?api_key=...``), and secrets
# must never reach the logs at any level -- so strip query strings from those
# records rather than merely raising the level.
install_url_query_filters()

logging.getLogger(__name__).info("Log level set to %s", _LOG_LEVEL)
