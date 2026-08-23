"""Application assembly: FastAPI outer app + FastMCP gateway."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI

from mcp_gateway.config import GatewayConfig, load_config
from mcp_gateway.gateway import build_gateway
from mcp_gateway.oauth_server import GatewayOAuthProvider
from mcp_gateway.storage import Storage
from mcp_gateway.upstream import BackendManager
from mcp_gateway.users import SessionManager
from mcp_gateway.web import build_auth_router, build_oauth_router, build_ui_router

logger = logging.getLogger(__name__)


def create_app(config: GatewayConfig | str) -> FastAPI:
    if isinstance(config, str):
        config = load_config(config)

    storage = Storage(config.storage.path, config.auth.encryption_key)
    provider = GatewayOAuthProvider(config, storage)
    manager = BackendManager(config, storage)

    clients = {
        name: manager.build_client(name, backend)
        for name, backend in config.backends.items()
        if backend.enabled
    }

    mcp = build_gateway(config, provider, manager, clients)
    # The MCP endpoint lives at <public_url>/mcp; auth + well-known routes sit
    # at the root of the same app per RFC 8414/9728.
    mcp_app = mcp.http_app(path="/mcp")

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        storage.purge_expired()
        async with mcp_app.lifespan(mcp_app):
            yield
        storage.close()

    app = FastAPI(title="MCP Gateway", lifespan=lifespan, docs_url=None, redoc_url=None)

    session_secret = config.auth.session_secret or storage.get_or_create_secret(
        "session_secret"
    )
    app.state.config = config
    app.state.storage = storage
    app.state.oauth_provider = provider
    app.state.backend_manager = manager
    app.state.backend_clients = clients
    app.state.sessions = SessionManager(
        session_secret, config.auth.login_session_expiry_seconds
    )

    app.include_router(build_auth_router())
    app.include_router(build_oauth_router())
    app.include_router(build_ui_router())

    @app.get("/")
    async def root():
        from fastapi.responses import RedirectResponse

        return RedirectResponse("/ui/")

    # Everything else (MCP endpoint, /authorize, /token, /register, /revoke,
    # /.well-known/*) is handled by the FastMCP app mounted as catch-all.
    app.mount("/", mcp_app)

    return app
