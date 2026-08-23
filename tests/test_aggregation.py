"""Aggregation: namespacing, upstream header injection, no token passthrough."""

from __future__ import annotations

import httpx
import pytest
from fastmcp import Client, FastMCP
from fastmcp.client.transports import StreamableHttpTransport
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from mcp_gateway.app import create_app
from tests.conftest import free_port, gateway_config, obtain_tokens, register_client

BACKEND_TOKEN = "backend-secret-token"


def make_echo_backend(seen_auth_headers: list):
    backend = FastMCP(name="echo-backend")

    @backend.tool
    def echo(text: str) -> str:
        """Echo text back."""
        return f"echo: {text}"

    app = backend.http_app(path="/mcp")

    class RecordAndRequireToken(BaseHTTPMiddleware):
        async def dispatch(self, request, call_next):
            if request.url.path.startswith("/mcp"):
                seen_auth_headers.append(request.headers.get("authorization"))
                if request.headers.get("authorization") != f"Bearer {BACKEND_TOKEN}":
                    return JSONResponse({"error": "unauthorized"}, status_code=401)
            return await call_next(request)

    app.add_middleware(RecordAndRequireToken)
    return app


def make_public_backend(seen_auth_headers: list):
    backend = FastMCP(name="docs-backend")

    @backend.tool
    def search(query: str) -> str:
        """Search the docs."""
        return f"result: {query}"

    app = backend.http_app(path="/mcp")

    class RecordHeaders(BaseHTTPMiddleware):
        async def dispatch(self, request, call_next):
            if request.url.path.startswith("/mcp"):
                seen_auth_headers.append(request.headers.get("authorization"))
            return await call_next(request)

    app.add_middleware(RecordHeaders)
    return app


@pytest.fixture
def stack(run_server):
    echo_headers: list = []
    public_headers: list = []
    echo_server = run_server(make_echo_backend(echo_headers))
    public_server = run_server(make_public_backend(public_headers))

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
        },
    )
    gateway_server = run_server(create_app(config), port)
    return gateway_server, echo_headers, public_headers


async def gateway_mcp_client(base: str) -> Client:
    async with httpx.AsyncClient() as http:
        client_id = await register_client(http, base)
        tokens = await obtain_tokens(http, base, client_id)
    return Client(
        StreamableHttpTransport(
            f"{base}/mcp", headers={"Authorization": f"Bearer {tokens['access_token']}"}
        )
    )


async def test_namespaced_tools_and_calls(stack):
    gateway_server, _, _ = stack
    client = await gateway_mcp_client(gateway_server.base_url)
    async with client:
        names = sorted(t.name for t in await client.list_tools())
        assert "echo_echo" in names
        assert "docs_search" in names
        assert "gateway_status" in names
        # The dead backend must not break listing.
        result = await client.call_tool("echo_echo", {"text": "hi"})
        assert result.content[0].text == "echo: hi"
        result = await client.call_tool("docs_search", {"query": "mcp"})
        assert result.content[0].text == "result: mcp"


async def test_gateway_injects_backend_credentials(stack):
    gateway_server, echo_headers, _ = stack
    client = await gateway_mcp_client(gateway_server.base_url)
    async with client:
        await client.call_tool("echo_echo", {"text": "x"})
    assert echo_headers, "backend never saw a request"
    assert all(h == f"Bearer {BACKEND_TOKEN}" for h in echo_headers)


async def test_no_token_passthrough_to_backends(stack):
    """The MCP spec forbids forwarding the client's token to upstream servers."""
    gateway_server, echo_headers, public_headers = stack
    base = gateway_server.base_url
    async with httpx.AsyncClient() as http:
        client_id = await register_client(http, base)
        tokens = await obtain_tokens(http, base, client_id)
    gateway_token = tokens["access_token"]

    client = Client(
        StreamableHttpTransport(
            f"{base}/mcp", headers={"Authorization": f"Bearer {gateway_token}"}
        )
    )
    async with client:
        await client.call_tool("echo_echo", {"text": "x"})
        await client.call_tool("docs_search", {"query": "y"})

    # The gateway-issued token must never appear at any backend.
    for header in echo_headers + public_headers:
        assert header != f"Bearer {gateway_token}"
    # Public backend gets no Authorization header at all.
    assert all(h is None for h in public_headers)


async def test_gateway_status_tool(stack):
    gateway_server, _, _ = stack
    client = await gateway_mcp_client(gateway_server.base_url)
    async with client:
        result = await client.call_tool("gateway_status", {})
        payload = result.structured_content or {}
        names = {entry["name"] for entry in payload.get("result", [])}
        assert names == {"echo", "docs", "dead"}
