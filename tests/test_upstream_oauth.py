"""Gateway-to-backend OAuth: discovery, DCR, PKCE, interactive connect flow.

Uses a second gateway instance as the OAuth-protected upstream, which
exercises both sides of the MCP authorization spec in one test.
"""

from __future__ import annotations

from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport

from mcp_gateway.app import create_app
from tests.conftest import free_port, gateway_config, obtain_tokens, register_client


@pytest.fixture
def two_gateways(run_server):
    upstream_port = free_port()
    upstream = run_server(create_app(gateway_config(upstream_port)), upstream_port)

    port = free_port()
    config = gateway_config(
        port,
        backends={"up": {"url": f"{upstream.base_url}/mcp", "auth": {"type": "oauth"}}},
    )
    app = create_app(config)
    gateway = run_server(app, port)
    return gateway, upstream, app


async def test_connect_flow_and_proxying(two_gateways):
    gateway, upstream, app = two_gateways
    a, b = gateway.base_url, upstream.base_url

    # Two separate clients/cookie jars, one per host, mirroring how a real
    # browser scopes cookies per origin. Both servers happen to run on
    # 127.0.0.1 in tests (different ports only), so a single shared jar would
    # let the upstream's session cookie clobber the gateway's -- the gateway
    # now requires a live session on /oauth/callback (see M-2), so that
    # clobbering would incorrectly look like "not logged in".
    async with (
        httpx.AsyncClient(follow_redirects=False, timeout=30) as http,
        httpx.AsyncClient(follow_redirects=False, timeout=30) as http_upstream,
    ):
        # Connect endpoint requires a logged-in admin.
        r = await http.get(f"{a}/oauth/connect/up")
        assert r.status_code in (302, 307)
        assert "/ui/backends" in r.headers["location"]

        r = await http.post(f"{a}/auth/api/login", json={"username": "admin", "password": "pw"})
        http.cookies.update(r.cookies)

        r = await http.get(f"{a}/auth/api/backends")
        assert r.json()[0]["connected"] is False

        # Start the connect flow: gateway discovers upstream metadata, performs
        # DCR, and redirects the admin's browser to the upstream /authorize.
        r = await http.get(f"{a}/oauth/connect/up")
        assert r.status_code in (302, 307)
        authorize_url = r.headers["location"]
        assert authorize_url.startswith(f"{b}/authorize")
        query = parse_qs(urlparse(authorize_url).query)
        assert query["code_challenge_method"] == ["S256"]
        assert query["redirect_uri"] == [f"{a}/oauth/callback"]

        # Upstream parks the request for login/consent.
        r = await http_upstream.get(authorize_url)
        txn = parse_qs(urlparse(r.headers["location"]).query)["txn"][0]
        r = await http_upstream.post(
            f"{b}/auth/api/login", json={"username": "admin", "password": "pw"}
        )
        http_upstream.cookies.update(r.cookies)
        r = await http_upstream.post(f"{b}/auth/api/consent", json={"txn_id": txn, "approve": True})
        redirect_to = r.json()["redirect_to"]
        assert redirect_to.startswith(f"{a}/oauth/callback")

        # Browser lands on the gateway callback (still carrying the gateway's
        # own session cookie in `http`); the gateway exchanges the code.
        r = await http.get(redirect_to)
        assert "connected=up" in r.headers["location"], r.headers["location"]

        r = await http.get(f"{a}/auth/api/backends")
        status = r.json()[0]
        assert status["connected"] is True
        assert status["has_refresh_token"] is True
        assert status["registration"] == "dcr"

    # Tokens are persisted encrypted.
    stored = app.state.storage.get_upstream("up", "tokens")
    assert stored and stored["access_token"]

    # End-to-end: MCP client -> gateway -> upstream gateway.
    async with httpx.AsyncClient() as http:
        client_id = await register_client(http, a)
        tokens = await obtain_tokens(http, a, client_id)
    client = Client(
        StreamableHttpTransport(
            f"{a}/mcp", headers={"Authorization": f"Bearer {tokens['access_token']}"}
        )
    )
    async with client:
        names = sorted(t.name for t in await client.list_tools())
        assert "up_gateway_status" in names
        result = await client.call_tool("up_gateway_status", {})
        assert result.structured_content == {"result": []}


async def test_mcp_traffic_never_starts_interactive_flow(two_gateways):
    """An unconnected OAuth backend must not hang MCP requests waiting for a browser."""
    gateway, _, _ = two_gateways
    a = gateway.base_url
    async with httpx.AsyncClient() as http:
        client_id = await register_client(http, a)
        tokens = await obtain_tokens(http, a, client_id)
    client = Client(
        StreamableHttpTransport(
            f"{a}/mcp", headers={"Authorization": f"Bearer {tokens['access_token']}"}
        ),
        timeout=15,
    )
    async with client:
        names = sorted(t.name for t in await client.list_tools())
        # The unconnected backend contributes nothing but the gateway still works.
        assert names == ["gateway_status"]


async def test_disconnect_removes_credentials(two_gateways):
    gateway, _, app = two_gateways
    a = gateway.base_url
    app.state.storage.save_upstream("up", "tokens", {"access_token": "x", "token_type": "Bearer"})
    async with httpx.AsyncClient() as http:
        r = await http.post(f"{a}/auth/api/login", json={"username": "admin", "password": "pw"})
        http.cookies.update(r.cookies)
        r = await http.get(f"{a}/auth/api/backends")
        assert r.json()[0]["connected"] is True
        r = await http.post(f"{a}/auth/api/backends/up/disconnect")
        assert r.status_code == 200
        r = await http.get(f"{a}/auth/api/backends")
        assert r.json()[0]["connected"] is False


async def test_hosted_client_metadata_document(two_gateways):
    gateway, _, _ = two_gateways
    a = gateway.base_url
    async with httpx.AsyncClient() as http:
        r = await http.get(f"{a}/oauth/client-metadata.json")
        assert r.status_code == 200
        doc = r.json()
        assert doc["client_id"] == f"{a}/oauth/client-metadata.json"
        assert doc["redirect_uris"] == [f"{a}/oauth/callback"]
        assert doc["token_endpoint_auth_method"] == "none"
