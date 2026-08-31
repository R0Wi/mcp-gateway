"""Live per-backend connection test: /auth/api/backends/{name}/test-connection."""

from __future__ import annotations

import json

import httpx
import pytest
from fastmcp import FastMCP
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from mcp_gateway.app import create_app
from tests.conftest import free_port, gateway_config

BACKEND_TOKEN = "backend-secret-token"


def make_echo_backend():
    backend = FastMCP(name="echo-backend")

    @backend.tool
    def echo(text: str) -> str:
        """Echo text back."""
        return f"echo: {text}"

    app = backend.http_app(path="/mcp")

    class RequireToken(BaseHTTPMiddleware):
        async def dispatch(self, request, call_next):
            if request.url.path.startswith("/mcp") and request.headers.get(
                "authorization"
            ) != f"Bearer {BACKEND_TOKEN}":
                return JSONResponse({"error": "unauthorized"}, status_code=401)
            return await call_next(request)

    app.add_middleware(RequireToken)
    return app


def make_public_backend():
    backend = FastMCP(name="docs-backend")

    @backend.tool
    def search(query: str) -> str:
        """Search the docs."""
        return f"result: {query}"

    return backend.http_app(path="/mcp")


@pytest.fixture
def stack(run_server):
    echo_server = run_server(make_echo_backend())
    public_server = run_server(make_public_backend())
    upstream_port = free_port()
    upstream = run_server(create_app(gateway_config(upstream_port)), upstream_port)

    port = free_port()
    config = gateway_config(
        port,
        backends={
            "echo": {
                "url": f"{echo_server.base_url}/mcp",
                "auth": {"type": "bearer", "token": BACKEND_TOKEN},
            },
            "docs": {"url": f"{public_server.base_url}/mcp", "auth": {"type": "none"}},
            "dead": {"url": "http://127.0.0.1:1/mcp", "auth": {"type": "none"}},
            "up": {"url": f"{upstream.base_url}/mcp", "auth": {"type": "oauth"}},
            "off": {
                "url": f"{public_server.base_url}/mcp",
                "auth": {"type": "none"},
                "enabled": False,
            },
        },
    )
    return run_server(create_app(config), port)


async def _login(http: httpx.AsyncClient, base: str) -> None:
    r = await http.post(f"{base}/auth/api/login", json={"username": "admin", "password": "pw"})
    assert r.status_code == 200, r.text
    http.cookies.update(r.cookies)


def _events(response: httpx.Response) -> list[dict]:
    return [json.loads(line) for line in response.text.strip().splitlines() if line.strip()]


async def test_requires_login(stack):
    async with httpx.AsyncClient() as http:
        r = await http.post(f"{stack.base_url}/auth/api/backends/echo/test-connection")
        assert r.status_code == 401


async def test_unknown_backend(stack):
    async with httpx.AsyncClient() as http:
        await _login(http, stack.base_url)
        r = await http.post(f"{stack.base_url}/auth/api/backends/nope/test-connection")
        assert r.status_code == 404


async def test_disabled_backend(stack):
    async with httpx.AsyncClient() as http:
        await _login(http, stack.base_url)
        r = await http.post(f"{stack.base_url}/auth/api/backends/off/test-connection")
        assert r.status_code == 404


async def test_all_checks_pass_for_healthy_backend(stack):
    async with httpx.AsyncClient(timeout=30) as http:
        await _login(http, stack.base_url)
        r = await http.post(f"{stack.base_url}/auth/api/backends/echo/test-connection")
        assert r.status_code == 200
        events = _events(r)
        by_check = {(e["check"], e["status"]): e for e in events}
        assert ("ping", "running") in by_check
        assert ("ping", "ok") in by_check
        assert ("auth", "ok") in by_check
        assert by_check[("auth", "ok")]["detail"] == "Static bearer token configured"
        assert ("list_tools", "ok") in by_check
        assert by_check[("list_tools", "ok")]["detail"] == "Listed 1 tool(s)"


async def test_no_auth_backend_reports_no_auth_configured(stack):
    async with httpx.AsyncClient(timeout=30) as http:
        await _login(http, stack.base_url)
        r = await http.post(f"{stack.base_url}/auth/api/backends/docs/test-connection")
        assert r.status_code == 200
        events = _events(r)
        auth_ok = next(e for e in events if e["check"] == "auth" and e["status"] == "ok")
        assert auth_ok["detail"] == "No authentication configured"


async def test_unreachable_backend_fails_at_ping(stack):
    async with httpx.AsyncClient(timeout=30) as http:
        await _login(http, stack.base_url)
        r = await http.post(f"{stack.base_url}/auth/api/backends/dead/test-connection")
        assert r.status_code == 200
        events = _events(r)
        assert [e["check"] for e in events] == ["ping", "ping"]
        assert events[-1]["status"] == "error"


async def test_unconnected_oauth_backend_fails_before_list_tools(stack):
    async with httpx.AsyncClient(timeout=30) as http:
        await _login(http, stack.base_url)
        r = await http.post(f"{stack.base_url}/auth/api/backends/up/test-connection")
        assert r.status_code == 200
        events = _events(r)
        # ping requires an authenticated request against this upstream, so it
        # (not auth or list_tools) is where the missing connection shows up.
        assert not any(e["check"] == "list_tools" for e in events)
        assert events[-1]["status"] == "error"
