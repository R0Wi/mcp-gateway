"""Opt-in raw-HTTP passthrough to backend routes (e.g. large uploads).

MCP tool arguments travel through the calling model's context window, which
makes them useless for multi-MB binaries. A backend can instead declare
``passthrough`` routes in the config; each is exposed at
``<public_url>/backends/<name><path>`` and streamed through to
``<backend origin><path>``.

This is a separate code path from the MCP proxy in ``gateway.py`` and keeps
the same guarantees:

- Clients authenticate with the *same* bearer-token check as ``/mcp``
  (the provider's own ``AuthenticationMiddleware`` + ``RequireAuthMiddleware``).
- The backend only ever sees the gateway's own credential for it (static
  headers or its upstream OAuth token), never the client's token: request
  headers are forwarded from a short allowlist, not a denylist.
- Bodies are streamed in both directions, never buffered, and capped per
  route on the gateway side.
- Backend 5xx and transport errors are masked (the passthrough analogue of
  ``mask_error_details=True``); details go to the server log only.
"""

from __future__ import annotations

import logging
import time
from collections.abc import AsyncIterator
from urllib.parse import unquote, urlsplit

import httpx
from fastmcp.server.auth.middleware import RequireAuthMiddleware
from mcp.server.auth.routes import build_resource_metadata_url
from starlette.applications import Starlette
from starlette.background import BackgroundTask
from starlette.requests import Request
from starlette.responses import JSONResponse, Response, StreamingResponse
from starlette.routing import Route
from starlette.types import Receive, Scope, Send

from mcp_gateway.config import BackendConfig, GatewayConfig, PassthroughRoute
from mcp_gateway.oauth_server import GatewayOAuthProvider
from mcp_gateway.upstream import BackendManager, NotConnectedError

logger = logging.getLogger(__name__)

PASSTHROUGH_PREFIX = "/backends"

# Client -> backend. Everything else (Authorization, Cookie, Host,
# X-Forwarded-*, ...) is dropped; the backend's own credential is added by
# BackendManager.upstream_auth_headers.
_REQUEST_HEADERS = frozenset(
    {"content-type", "content-length", "content-encoding", "content-disposition", "accept"}
)
# Backend -> client. Location/Set-Cookie in particular are dropped: they
# would leak backend URLs or backend-scoped cookies.
_RESPONSE_HEADERS = frozenset(
    {
        "content-type",
        "content-length",
        "content-disposition",
        "content-encoding",
        "cache-control",
        "etag",
        "last-modified",
    }
)

_ALL_METHODS = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]


class _BodyTooLarge(Exception):
    pass


def _error(status: int, error: str, description: str) -> Response:
    return JSONResponse({"error": error, "error_description": description}, status_code=status)


def _backend_origin(url: str) -> str:
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}"


def _match_route(routes: list[PassthroughRoute], path: str) -> PassthroughRoute | None:
    for route in routes:
        if path == route.path or path.startswith(route.path + "/"):
            return route
    return None


def _split_raw_path(scope: Scope) -> tuple[str, str] | None:
    """Return ``(backend_name, raw_backend_path)`` or None if malformed.

    Works on the raw (still percent-encoded) request path so an encoded
    ``/`` can't smuggle a ``..`` or an extra segment past the allowlist, and
    so the path reaches the backend exactly as the client encoded it.
    """
    raw = scope.get("raw_path") or scope["path"].encode()
    raw_path = raw.decode("latin-1").split("?", 1)[0]
    if not raw_path.startswith(PASSTHROUGH_PREFIX + "/"):
        return None
    segments = raw_path[len(PASSTHROUGH_PREFIX) + 1 :].split("/")
    if len(segments) < 2:
        return None
    for segment in segments:
        decoded = unquote(segment)
        if decoded in ("", ".", "..") or "/" in decoded or "\\" in decoded:
            return None
    return segments[0], "/" + "/".join(segments[1:])


class PassthroughProxy:
    """The ``/backends`` sub-application; mount it before the MCP catch-all."""

    def __init__(
        self,
        config: GatewayConfig,
        provider: GatewayOAuthProvider,
        manager: BackendManager,
    ) -> None:
        self._backends: dict[str, BackendConfig] = {
            name: backend
            for name, backend in config.backends.items()
            if backend.enabled and backend.passthrough
        }
        self._manager = manager
        self._http = httpx.AsyncClient(follow_redirects=False)

        resource_url = provider._get_resource_url("/mcp")
        resource_metadata_url = (
            build_resource_metadata_url(resource_url) if resource_url else None
        )
        # Same auth stack FastMCP builds for /mcp (fastmcp/server/http.py):
        # the provider's middleware authenticates the bearer token, and
        # RequireAuthMiddleware turns "no/invalid token" into the same 401 +
        # WWW-Authenticate challenge.
        self.app = Starlette(
            routes=[
                Route(
                    "/{rest:path}",
                    endpoint=RequireAuthMiddleware(
                        self._handle, provider.required_scopes, resource_metadata_url
                    ),
                    methods=_ALL_METHODS,
                )
            ],
            middleware=provider.get_middleware(),
        )

    async def aclose(self) -> None:
        await self._http.aclose()

    async def _handle(self, scope: Scope, receive: Receive, send: Send) -> None:
        response = await self._proxy(Request(scope, receive))
        await response(scope, receive, send)

    async def _proxy(self, request: Request) -> Response:
        split = _split_raw_path(request.scope)
        if split is None:
            return _error(404, "not_found", "No such passthrough route")
        name, raw_path = split
        backend = self._backends.get(name)
        route = _match_route(backend.passthrough, unquote(raw_path)) if backend else None
        if backend is None or route is None:
            return _error(404, "not_found", "No such passthrough route")
        if request.method not in route.methods:
            return _error(405, "method_not_allowed", "Method not allowed for this route")

        declared = request.headers.get("content-length")
        if declared is not None:
            try:
                declared_len = int(declared)
            except ValueError:
                return _error(400, "invalid_request", "Invalid Content-Length")
            if declared_len > route.max_body_bytes:
                return _error(413, "payload_too_large", "Request body too large")

        try:
            auth_headers = await self._manager.upstream_auth_headers(name, backend)
        except NotConnectedError:
            logger.warning("Passthrough to backend %s refused: backend not connected", name)
            return _error(503, "backend_unavailable", "Backend is not connected")
        except Exception:
            logger.exception("Passthrough to backend %s: loading upstream credential failed", name)
            return _error(502, "bad_gateway", "Backend request failed")

        headers = {k: v for k, v in request.headers.items() if k in _REQUEST_HEADERS}
        headers.update(auth_headers)

        started = time.monotonic()
        bytes_in = 0

        async def body() -> AsyncIterator[bytes]:
            nonlocal bytes_in
            async for chunk in request.stream():
                bytes_in += len(chunk)
                if bytes_in > route.max_body_bytes:
                    raise _BodyTooLarge
                if chunk:
                    yield chunk

        has_body = (declared is not None and declared != "0") or (
            "transfer-encoding" in request.headers
        )
        url = _backend_origin(backend.url) + raw_path
        if request.url.query:
            url += "?" + request.url.query
        upstream_request = self._http.build_request(
            request.method,
            url,
            headers=headers,
            content=body() if has_body else None,
            timeout=httpx.Timeout(route.timeout_seconds, connect=10.0),
        )

        def log(status: int, bytes_out: int) -> None:
            logger.info(
                "Passthrough %s %s%s -> %d (in=%d bytes, out=%d bytes, %.2fs)",
                request.method,
                name,
                route.path,
                status,
                bytes_in,
                bytes_out,
                time.monotonic() - started,
            )

        try:
            upstream = await self._http.send(upstream_request, stream=True)
        except Exception as exc:  # noqa: BLE001 - masked below, logged
            if isinstance(exc, _BodyTooLarge) or isinstance(exc.__context__, _BodyTooLarge):
                log(413, 0)
                return _error(413, "payload_too_large", "Request body too large")
            if isinstance(exc, httpx.TimeoutException):
                logger.warning("Passthrough to backend %s timed out: %s", name, exc)
                log(504, 0)
                return _error(504, "gateway_timeout", "Backend request timed out")
            logger.warning("Passthrough to backend %s failed: %s: %s", name, type(exc).__name__, exc)
            log(502, 0)
            return _error(502, "bad_gateway", "Backend request failed")

        if upstream.status_code >= 500:
            await upstream.aclose()
            logger.warning(
                "Passthrough to backend %s: backend answered %d", name, upstream.status_code
            )
            log(502, 0)
            return _error(502, "bad_gateway", "Backend request failed")

        async def relay() -> AsyncIterator[bytes]:
            bytes_out = 0
            try:
                async for chunk in upstream.aiter_raw():
                    bytes_out += len(chunk)
                    yield chunk
            finally:
                log(upstream.status_code, bytes_out)

        return StreamingResponse(
            relay(),
            status_code=upstream.status_code,
            headers={k: v for k, v in upstream.headers.items() if k in _RESPONSE_HEADERS},
            background=BackgroundTask(upstream.aclose),
        )


def build_passthrough(
    config: GatewayConfig, provider: GatewayOAuthProvider, manager: BackendManager
) -> PassthroughProxy | None:
    """The passthrough sub-app, or None when no enabled backend declares any route."""
    enabled = {n: b for n, b in config.backends.items() if b.enabled and b.passthrough}
    if not enabled:
        return None
    for name, backend in enabled.items():
        logger.info(
            "Backend %s: HTTP passthrough enabled for %s",
            name,
            ", ".join(f"{'/'.join(r.methods)} {r.path}" for r in backend.passthrough),
        )
    return PassthroughProxy(config, provider, manager)
