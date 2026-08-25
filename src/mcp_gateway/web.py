"""FastAPI routes for the interactive parts of the gateway.

- ``/auth/api/*``   – JSON API consumed by the Svelte login/consent UI
- ``/oauth/*``      – upstream backend connect flow + hosted CIMD document
- ``/ui/*``         – the built Svelte single-page app
- ``/healthz``      – liveness probe
"""

from __future__ import annotations

import logging
from pathlib import Path

import anyio
from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from pydantic import BaseModel

from mcp_gateway.users import SESSION_COOKIE, SessionManager, verify_user

logger = logging.getLogger(__name__)

STATIC_DIR = Path(__file__).parent / "static" / "ui"


class LoginRequest(BaseModel):
    username: str
    password: str


class ConsentRequest(BaseModel):
    txn_id: str
    approve: bool


def _session_user(request: Request) -> str | None:
    sessions: SessionManager = request.app.state.sessions
    return sessions.validate(request.cookies.get(SESSION_COOKIE))


def _require_session(request: Request) -> str:
    user = _session_user(request)
    if user is None:
        raise HTTPException(status_code=401, detail="Not logged in")
    return user


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def build_auth_router() -> APIRouter:
    router = APIRouter(prefix="/auth/api")

    @router.get("/me")
    async def me(request: Request):
        return {"username": _session_user(request)}

    @router.get("/txn/{txn_id}")
    async def get_txn(txn_id: str, request: Request):
        info = request.app.state.oauth_provider.describe_txn(txn_id)
        if info is None:
            raise HTTPException(status_code=404, detail="Unknown or expired authorization request")
        info["username"] = _session_user(request)
        return info

    @router.post("/login")
    async def login(body: LoginRequest, request: Request, response: Response):
        config = request.app.state.config
        if not request.app.state.login_limiter.allow(_client_ip(request)):
            logger.warning("Login rate limit exceeded for %s", _client_ip(request))
            raise HTTPException(status_code=429, detail="Too many login attempts, try again later")
        # bcrypt.checkpw is a blocking CPU call; run it off the event loop so
        # a flood of login attempts can't stall every other request (MCP
        # traffic included) the way a fully synchronous checkpw would.
        # verify_user() itself keeps a constant bcrypt cost across the
        # known/unknown-username and hashed/plaintext-password cases, so the
        # rate limiter above (not a per-request sleep) is what blunts guessing.
        ok = await anyio.to_thread.run_sync(
            verify_user, config.auth, body.username, body.password
        )
        if not ok:
            logger.warning("Failed login attempt for username %r", body.username)
            raise HTTPException(status_code=401, detail="Invalid username or password")
        logger.info("User %r logged in", body.username)
        sessions: SessionManager = request.app.state.sessions
        response.set_cookie(
            SESSION_COOKIE,
            sessions.create(body.username),
            max_age=config.auth.login_session_expiry_seconds,
            httponly=True,
            secure=config.server.public_url.startswith("https://"),
            samesite="lax",
            path="/",
        )
        return {"username": body.username}

    @router.post("/logout")
    async def logout(request: Request, response: Response):
        sessions: SessionManager = request.app.state.sessions
        sessions.revoke(request.cookies.get(SESSION_COOKIE))
        response.delete_cookie(SESSION_COOKIE, path="/")
        return {"ok": True}

    @router.post("/consent")
    async def consent(body: ConsentRequest, request: Request):
        user = _require_session(request)
        provider = request.app.state.oauth_provider
        try:
            redirect_to = provider.complete_authorization(
                body.txn_id, subject=user, approve=body.approve
            )
        except Exception as exc:  # AuthorizeError or expired txn
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return {"redirect_to": redirect_to}

    @router.get("/backends")
    async def backends(request: Request):
        _require_session(request)
        return request.app.state.backend_manager.backend_status()

    @router.post("/backends/{name}/disconnect")
    async def disconnect(name: str, request: Request):
        user = _require_session(request)
        manager = request.app.state.backend_manager
        if name not in request.app.state.config.backends:
            raise HTTPException(status_code=404, detail="Unknown backend")
        logger.info("User %r requested disconnect of backend %r", user, name)
        manager.disconnect(name)
        return {"ok": True}

    return router


def build_oauth_router() -> APIRouter:
    router = APIRouter()

    @router.get("/oauth/client-metadata.json")
    async def client_metadata(request: Request):
        # Client ID Metadata Document the gateway presents to upstream
        # authorization servers (CIMD; draft-ietf-oauth-client-id-metadata-document).
        return JSONResponse(
            request.app.state.backend_manager.client_metadata_document(),
            headers={"Cache-Control": "public, max-age=3600"},
        )

    @router.get("/oauth/connect/{name}")
    async def connect(name: str, request: Request):
        user = _session_user(request)
        if user is None:
            return RedirectResponse(f"/ui/backends?login_next=connect:{name}")
        manager = request.app.state.backend_manager
        clients = request.app.state.backend_clients
        if name not in clients:
            raise HTTPException(status_code=404, detail="Unknown or disabled backend")
        logger.info("User %r requested connect of backend %r", user, name)
        try:
            authorize_url = await manager.start_connect(name, clients[name])
        except Exception as exc:
            logger.exception("Connect flow for backend %s failed to start", name)
            return RedirectResponse(f"/ui/backends?error=Could+not+start+authorization:+{exc}")
        return RedirectResponse(authorize_url)

    @router.get("/oauth/callback")
    async def oauth_callback(request: Request):
        # The connect flow can only have been started by a logged-in admin
        # (see /oauth/connect above), and the same browser session carries
        # through the redirect to the upstream AS and back. Requiring a
        # session here means an anonymous request with a forged/guessed
        # `state` is rejected before it can touch backend_manager state at
        # all, rather than relying solely on deliver_callback's state match.
        if _session_user(request) is None:
            return RedirectResponse("/ui/backends?error=Sign+in+required+to+complete+authorization")
        params = request.query_params
        error = params.get("error")
        if error:
            desc = params.get("error_description") or error
            return RedirectResponse(f"/ui/backends?error={desc}")
        code, state = params.get("code"), params.get("state")
        if not code:
            raise HTTPException(status_code=400, detail="Missing authorization code")
        manager = request.app.state.backend_manager
        backend = manager.deliver_callback(code, state)
        if backend is None:
            return RedirectResponse("/ui/backends?error=No+matching+authorization+flow")
        result = await manager.wait_connect_result(backend)
        if result:
            return RedirectResponse(f"/ui/backends?error={result}")
        return RedirectResponse(f"/ui/backends?connected={backend}")

    return router


def _is_asset_path(rest: str) -> bool:
    """Whether ``/ui/<rest>`` addresses a file rather than a client route.

    Client-side routes ("", "authorize", "backends") never contain a dot in
    their last segment, so a suffix is a reliable tell -- and everything Vite
    emits lands under ``assets/``.
    """
    return rest.startswith("assets/") or "." in rest.rsplit("/", 1)[-1]


def _static_cache_headers(rest: str) -> dict[str, str]:
    """Cache policy for a served UI file.

    Vite gives files under ``assets/`` content-hashed names, so they are safe
    to cache forever. index.html must always be revalidated: a stale copy
    would keep requesting asset names that a newer build has already dropped.
    """
    if rest.startswith("assets/"):
        return {"Cache-Control": "public, max-age=31536000, immutable"}
    return {"Cache-Control": "no-cache"}


def build_ui_router() -> APIRouter:
    router = APIRouter()

    @router.get("/healthz")
    async def healthz():
        return {"status": "ok"}

    @router.get("/ui")
    @router.get("/ui/{rest:path}")
    async def ui(rest: str = ""):
        # Serve built assets; an unknown *route* falls back to the SPA entry
        # point (client-side routing). A missing *file* must not: handing
        # index.html to a <script type="module"> or <link rel="stylesheet">
        # only yields an opaque "MIME type ('text/html') is not supported"
        # console error and a blank page. That happens whenever a browser
        # holds an index.html whose content-hashed asset names no longer
        # exist on the server -- a stale cache, or a half-finished deploy
        # where an old container is still serving the previous build.
        static_root = STATIC_DIR.resolve()
        if rest:
            candidate = (STATIC_DIR / rest).resolve()
            if candidate.is_file() and candidate.is_relative_to(static_root):
                return FileResponse(candidate, headers=_static_cache_headers(rest))
            if _is_asset_path(rest):
                logger.warning("UI asset not found: /ui/%s", rest)
                raise HTTPException(status_code=404, detail="Not found")
        index = STATIC_DIR / "index.html"
        if not index.exists():
            logger.error("UI assets not built; serving 503 for /ui/%s", rest)
            return JSONResponse(
                {
                    "error": "UI assets not built",
                    "hint": "run `npm install && npm run build` in the ui/ directory",
                },
                status_code=503,
            )
        return FileResponse(index, headers=_static_cache_headers("index.html"))

    return router
