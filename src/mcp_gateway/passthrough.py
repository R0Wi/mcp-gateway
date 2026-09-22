"""Opt-in raw-HTTP passthrough to backend routes (e.g. large uploads).

MCP tool arguments travel through the calling model's context window, which
makes them useless for multi-MB binaries. A backend can instead declare
``passthrough`` routes in the config; each is exposed at
``<public_url>/backends/<name><path>`` and streamed through to
``<backend base><path>`` (``passthrough_base_url``, else the origin of the
backend's MCP ``url``).

Model-driven clients (Claude Code, claude.ai connectors) never see the
gateway's OAuth token -- it lives in the harness -- so they can't call a
bearer-protected URL with ``curl``. For them the ``gateway_create_upload_url``
MCP tool mints a presigned URL, ``<public_url>/backends/<name>/t/<ticket>``:
the ticket is 128-bit random, single use, short-lived, bound to backend +
path + method, and stored hashed. It sits in a fixed path segment (never the
query string) so the access log can redact it; the caller's own query string
(e.g. ``?filename=``) is forwarded.

This is a separate code path from the MCP proxy in ``gateway.py`` and keeps
the same guarantees:

- Clients authenticate with the *same* bearer-token check as ``/mcp``
  (the provider's own ``AuthenticationMiddleware`` + ``RequireAuthMiddleware``),
  or with a ticket that was itself minted over authenticated MCP.
- The backend only ever sees the gateway's own credential for it (static
  headers or its upstream OAuth token), never the client's token: request
  headers are forwarded from a short allowlist, not a denylist.
- Bodies are streamed in both directions, never buffered, and capped per
  route on the gateway side.
- Backend 4xx bodies are relayed verbatim (they're actionable: too large,
  not a capture, ...). Backend 5xx and transport errors are masked (the
  passthrough analogue of ``mask_error_details=True``); details go to the
  server log only. Tickets are never logged.
"""

from __future__ import annotations

import logging
import re
import secrets
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
from mcp_gateway.storage import Storage
from mcp_gateway.upstream import BackendManager, NotConnectedError

logger = logging.getLogger(__name__)

PASSTHROUGH_PREFIX = "/backends"
TICKET_SEGMENT = "t"

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


def _target_base(backend: BackendConfig) -> str:
    if backend.passthrough_base_url:
        return backend.passthrough_base_url
    parts = urlsplit(backend.url)
    return f"{parts.scheme}://{parts.netloc}"


def _match_route(routes: list[PassthroughRoute], path: str) -> PassthroughRoute | None:
    """Exact match only: an explicit allowlist, no free prefixes."""
    return next((route for route in routes if route.path == path), None)


# ------------------------------------------------------------------ tickets


class UploadTicketError(ValueError):
    """The requested (backend, path, method) can't get an upload URL."""


def create_upload_ticket(
    config: GatewayConfig, storage: Storage, backend: str, path: str, method: str = "POST"
) -> dict[str, object]:
    """Mint a single-use presigned URL for a declared passthrough route."""
    method = method.upper()
    backend_config = config.backends.get(backend)
    if backend_config is None or not backend_config.enabled:
        raise UploadTicketError(f"Unknown or disabled backend {backend!r}")
    route = _match_route(backend_config.passthrough, path.rstrip("/") or "/")
    if route is None:
        declared = ", ".join(r.path for r in backend_config.passthrough) or "none"
        raise UploadTicketError(
            f"Backend {backend!r} declares no passthrough path {path!r} (declared: {declared})"
        )
    if method not in route.methods:
        raise UploadTicketError(
            f"Method {method} is not allowed for {backend}{route.path} "
            f"(allowed: {', '.join(route.methods)})"
        )
    ttl = config.auth.upload_ticket_expiry_seconds
    ticket = secrets.token_urlsafe(16)  # 128 bits
    storage.save_upload_ticket(
        ticket, backend=backend, path=route.path, method=method, expires_at=time.time() + ttl
    )
    logger.info("Minted upload URL for %s %s%s (ttl=%ds)", method, backend, route.path, ttl)
    return {
        "url": f"{config.server.public_url}{PASSTHROUGH_PREFIX}/{backend}/{TICKET_SEGMENT}/{ticket}",
        "method": method,
        "max_body_bytes": route.max_body_bytes,
        "expires_in_seconds": ttl,
    }


_TICKET_IN_PATH = re.compile(
    rf"({re.escape(PASSTHROUGH_PREFIX)}/[^/\s?]+/{TICKET_SEGMENT}/)[^/\s?\"]+"
)


class RedactTicketFilter(logging.Filter):
    """Redact upload tickets from log records (notably uvicorn's access log)."""

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.args, tuple) and record.args:
            record.args = tuple(
                _TICKET_IN_PATH.sub(r"\1[redacted]", a) if isinstance(a, str) else a
                for a in record.args
            )
        if isinstance(record.msg, str):
            record.msg = _TICKET_IN_PATH.sub(r"\1[redacted]", record.msg)
        return True


def install_ticket_log_redaction() -> None:
    access_logger = logging.getLogger("uvicorn.access")
    if not any(isinstance(f, RedactTicketFilter) for f in access_logger.filters):
        access_logger.addFilter(RedactTicketFilter())


def _split_raw_path(scope: Scope) -> tuple[str, str] | None:
    """Return ``(backend_name, raw_backend_path)`` or None if malformed.

    Works on the raw (still percent-encoded) request path so an encoded
    ``/`` can't smuggle a ``..`` or an extra segment past the allowlist. The
    backend is always sent the configured ``route.path``, never this one.
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
        self._storage = provider.storage
        self._http = httpx.AsyncClient(follow_redirects=False)

        resource_url = provider._get_resource_url("/mcp")
        resource_metadata_url = (
            build_resource_metadata_url(resource_url) if resource_url else None
        )
        # Same auth stack FastMCP builds for /mcp (fastmcp/server/http.py):
        # the provider's middleware authenticates the bearer token, and
        # RequireAuthMiddleware turns "no/invalid token" into the same 401 +
        # WWW-Authenticate challenge. The ticket route comes first and isn't
        # wrapped: the ticket itself is the credential.
        self.app = Starlette(
            routes=[
                Route(
                    f"/{{name}}/{TICKET_SEGMENT}/{{ticket}}",
                    endpoint=self._proxy_ticket,
                    methods=_ALL_METHODS,
                ),
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
        response = await self._proxy_bearer(Request(scope, receive))
        await response(scope, receive, send)

    async def _proxy_bearer(self, request: Request) -> Response:
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
        return await self._forward(request, name, backend, route)

    async def _proxy_ticket(self, request: Request) -> Response:
        name = request.path_params["name"]
        ticket = request.path_params["ticket"]
        info = self._storage.get_upload_ticket(ticket)
        if info is None or info["backend"] != name:
            return _error(401, "invalid_ticket", "Upload URL is invalid, expired or already used")
        if request.method != info["method"]:
            # Not consumed: a stray HEAD/GET mustn't burn the caller's URL.
            return _error(405, "method_not_allowed", f"This upload URL only accepts {info['method']}")
        backend = self._backends.get(name)
        route = _match_route(backend.passthrough, info["path"]) if backend else None
        if backend is None or route is None:
            # Config changed since the ticket was minted.
            return _error(404, "not_found", "No such passthrough route")
        if not self._storage.consume_upload_ticket(ticket):
            return _error(401, "invalid_ticket", "Upload URL is invalid, expired or already used")
        return await self._forward(request, name, backend, route)

    async def _forward(
        self, request: Request, name: str, backend: BackendConfig, route: PassthroughRoute
    ) -> Response:
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
        url = _target_base(backend) + route.path
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
