"""Failure details for the admin UI's backend connection test.

The MCP SDK collapses most non-2xx responses from a backend into a bare
``MCPError: Server returned an error response`` -- the HTTP status, the
``WWW-Authenticate`` challenge and the error body are all gone by the time the
exception reaches the gateway. During a connection test the gateway records
every HTTP exchange the backend connection makes (``trace_http``) so a failed
check can show the admin what actually happened without reading server logs.

This is only ever shown to a logged-in gateway admin, never to MCP clients
(those still get masked errors). Even so, nothing the gateway *sends* is
recorded: no request headers (``Authorization``), no request bodies, and URLs
lose their query string, which is where a backend URL might carry an API key.
"""

from __future__ import annotations

import contextlib
from collections.abc import Iterator
from contextvars import ContextVar
from typing import Any

import httpx2
from mcp.shared._httpx_utils import create_mcp_http_client

# Response headers worth showing; everything else (Set-Cookie in particular)
# is dropped.
_SHOWN_RESPONSE_HEADERS = (
    "content-type",
    "www-authenticate",
    "location",
    "retry-after",
    "mcp-protocol-version",
    "server",
)
_MAX_BODY_CHARS = 2000
_MAX_EXCHANGES = 20
_MAX_EXCEPTIONS = 10

_http_trace: ContextVar[list[dict[str, Any]] | None] = ContextVar(
    "mcp_gateway_http_trace", default=None
)


@contextlib.contextmanager
def trace_http() -> Iterator[list[dict[str, Any]]]:
    """Record backend HTTP exchanges made from this context into the yielded list.

    Only connections *opened* inside the block are traced: the context var is
    inherited by the tasks the MCP client spawns for its session, so the
    caller must use a fresh client (``Client.new()``), not one that may
    already be connected.
    """
    exchanges: list[dict[str, Any]] = []
    token = _http_trace.set(exchanges)
    try:
        yield exchanges
    finally:
        _http_trace.reset(token)


def strip_query(url: str) -> str:
    return str(httpx2.URL(url).copy_with(query=None, fragment=None))


async def _record_response(response: httpx2.Response) -> None:
    exchanges = _http_trace.get()
    if exchanges is None or len(exchanges) >= _MAX_EXCHANGES:
        return
    entry: dict[str, Any] = {
        "method": response.request.method,
        "url": strip_query(str(response.request.url)),
        "status": response.status_code,
        "reason": response.reason_phrase,
        "headers": {
            name: response.headers[name]
            for name in _SHOWN_RESPONSE_HEADERS
            if name in response.headers
        },
    }
    if response.status_code >= 400:
        # Reading here caches the body on the response, so whoever handles
        # it next (the SDK, the OAuth flow) still sees it. Success bodies are
        # never touched: a 200 may be a long-lived SSE stream.
        try:
            body = (await response.aread()).decode("utf-8", errors="replace")
        except Exception:  # noqa: BLE001 - best effort, the status is what matters
            body = ""
        if len(body) > _MAX_BODY_CHARS:
            body = body[:_MAX_BODY_CHARS] + "\n… (truncated)"
        entry["body"] = body
    exchanges.append(entry)


def traced_http_client_factory(
    headers: dict[str, str] | None = None,
    timeout: httpx2.Timeout | None = None,
    auth: httpx2.Auth | None = None,
    **_: Any,
) -> httpx2.AsyncClient:
    """``httpx_client_factory`` for backend transports: the SDK's default client
    plus the ``trace_http`` hook, which is a no-op outside a connection test.

    FastMCP also passes ``follow_redirects=True`` to a factory; it's ignored so
    the client keeps the SDK default (off -- the transport follows same-origin
    redirects itself), exactly as without a factory.
    """
    client = create_mcp_http_client(headers=headers, timeout=timeout, auth=auth)
    client.event_hooks.setdefault("response", []).append(_record_response)
    return client


def _walk(exc: BaseException) -> Iterator[BaseException]:
    """`exc`, then grouped sub-exceptions and causes, depth first, each once."""
    seen: set[int] = set()

    def walk(e: BaseException | None) -> Iterator[BaseException]:
        if e is None or id(e) in seen:
            return
        seen.add(id(e))
        yield e
        if isinstance(e, BaseExceptionGroup):
            for sub in e.exceptions:
                yield from walk(sub)
        yield from walk(e.__cause__ or e.__context__)

    return walk(exc)


def exception_chain(exc: BaseException) -> list[str]:
    """``Type: message`` for `exc`, its causes and any grouped sub-exceptions.

    The groups themselves are left out: they're anyio task-group wrappers
    ("unhandled errors in a TaskGroup") that say nothing about the failure.
    """
    out: list[str] = []
    for e in _walk(exc):
        line = describe_exception(e)
        # Transports often re-raise as the same type and message; one is enough.
        if isinstance(e, BaseExceptionGroup) or (out and out[-1] == line):
            continue
        out.append(line)
        if len(out) >= _MAX_EXCEPTIONS:
            break
    return out


def describe_exception(exc: BaseException) -> str:
    message = str(exc)
    return f"{type(exc).__name__}: {message}" if message else type(exc).__name__


def last_error_response(exchanges: list[dict[str, Any]]) -> dict[str, Any] | None:
    return next((e for e in reversed(exchanges) if e["status"] >= 400), None)


def hint_for(auth_type: str, exchanges: list[dict[str, Any]], exc: BaseException) -> str | None:
    """A one-line, best-guess next step for the admin."""
    failed = last_error_response(exchanges)
    if failed is None:
        if not exchanges and any(
            isinstance(e, (httpx2.ConnectError, httpx2.TimeoutException, OSError))
            for e in _walk(exc)
        ):
            return (
                "The gateway could not reach the backend at all. Check the URL, DNS, "
                "and that the backend is running and reachable from the gateway."
            )
        return None
    status = failed["status"]
    if status == 401:
        return {
            "none": "The backend requires authentication, but none is configured for it.",
            "bearer": "The backend rejected the configured bearer token.",
            "headers": "The backend rejected the configured auth headers.",
            "oauth": "The backend rejected the gateway's OAuth tokens. Try reconnecting it.",
        }.get(auth_type, "The backend rejected the gateway's credentials.")
    if status == 403:
        return "The backend accepted the credentials but denied access (missing permission/scope)."
    if status == 404:
        return "The backend URL path may be wrong (MCP servers usually serve /mcp)."
    if status >= 500:
        return "The backend itself failed; check its logs."
    return None


def failure(
    exc: BaseException, *, backend_url: str, auth_type: str, exchanges: list[dict[str, Any]]
) -> tuple[str, dict[str, Any]]:
    """Return ``(summary, details)`` for a failed connection-test check."""
    summary = describe_exception(exc)
    failed = last_error_response(exchanges)
    if failed is not None:
        status = " ".join(str(p) for p in (failed["status"], failed["reason"]) if p)
        summary += f" (HTTP {status})"
    details = {
        "backend_url": strip_query(backend_url),
        "auth_type": auth_type,
        "error": describe_exception(exc),
        "hint": hint_for(auth_type, exchanges, exc),
        "exceptions": exception_chain(exc),
        "http": list(exchanges),
    }
    return summary, details
