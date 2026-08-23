"""CIMD (Client ID Metadata Document) support on the client-facing AS.

The gateway must accept HTTPS URLs as client IDs, fetch the metadata document,
validate redirect URIs against it, and complete the flow without any prior
registration — per draft-ietf-oauth-client-id-metadata-document and the MCP
2025-11-25 authorization spec.

The document fetch itself is stubbed (no real HTTPS server in tests); everything
else runs the real code paths.
"""

from __future__ import annotations

from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from fastmcp.server.auth.cimd import CIMDDocument

from tests.conftest import pkce_pair

CLIENT_ID_URL = "https://client.example.com/oauth/client-metadata.json"
REDIRECT_URI = "https://claude.ai/api/mcp/auth_callback"


@pytest.fixture
def cimd_gateway(gateway, monkeypatch):
    server, app = gateway
    provider = app.state.oauth_provider

    doc = CIMDDocument(
        client_id=CLIENT_ID_URL,
        client_name="Claude",
        client_uri="https://claude.ai",
        redirect_uris=[REDIRECT_URI, "http://localhost:*/callback"],
        grant_types=["authorization_code", "refresh_token"],
        response_types=["code"],
        token_endpoint_auth_method="none",
    )

    async def fake_fetch(client_id_url: str) -> CIMDDocument:
        assert client_id_url == CLIENT_ID_URL
        return doc

    monkeypatch.setattr(provider.cimd_manager._fetcher, "fetch", fake_fetch)
    return server


async def test_cimd_client_full_flow(cimd_gateway):
    base = cimd_gateway.base_url
    async with httpx.AsyncClient() as http:
        verifier, challenge = pkce_pair()
        r = await http.get(
            f"{base}/authorize",
            params={
                "client_id": CLIENT_ID_URL,
                "response_type": "code",
                "redirect_uri": REDIRECT_URI,
                "state": "cimd-state",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "resource": f"{base}/mcp",
            },
        )
        assert r.status_code in (302, 307), r.text
        txn = parse_qs(urlparse(r.headers["location"]).query)["txn"][0]

        # The consent UI should see the client name from the CIMD document.
        r = await http.get(f"{base}/auth/api/txn/{txn}")
        info = r.json()
        assert info["client_id"] == CLIENT_ID_URL
        assert info["client_name"] == "Claude"

        r = await http.post(f"{base}/auth/api/login", json={"username": "admin", "password": "pw"})
        http.cookies.update(r.cookies)
        r = await http.post(f"{base}/auth/api/consent", json={"txn_id": txn, "approve": True})
        query = parse_qs(urlparse(r.json()["redirect_to"]).query)
        assert query["state"][0] == "cimd-state"

        r = await http.post(
            f"{base}/token",
            data={
                "grant_type": "authorization_code",
                "code": query["code"][0],
                "redirect_uri": REDIRECT_URI,
                "client_id": CLIENT_ID_URL,
                "code_verifier": verifier,
                "resource": f"{base}/mcp",
            },
        )
        assert r.status_code == 200, r.text
        assert r.json()["access_token"]


async def test_cimd_client_wildcard_loopback_redirect(cimd_gateway):
    """CIMD documents may declare loopback wildcards (localhost:*) for CLI clients."""
    base = cimd_gateway.base_url
    async with httpx.AsyncClient() as http:
        _, challenge = pkce_pair()
        r = await http.get(
            f"{base}/authorize",
            params={
                "client_id": CLIENT_ID_URL,
                "response_type": "code",
                "redirect_uri": "http://localhost:54321/callback",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            },
        )
        assert r.status_code in (302, 307), r.text


async def test_cimd_client_disallowed_redirect_rejected(cimd_gateway):
    base = cimd_gateway.base_url
    async with httpx.AsyncClient() as http:
        _, challenge = pkce_pair()
        r = await http.get(
            f"{base}/authorize",
            params={
                "client_id": CLIENT_ID_URL,
                "response_type": "code",
                "redirect_uri": "https://attacker.example.com/callback",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            },
        )
        assert r.status_code == 400


async def test_non_https_url_client_id_not_treated_as_cimd(gateway):
    server, _ = gateway
    base = server.base_url
    async with httpx.AsyncClient() as http:
        _, challenge = pkce_pair()
        r = await http.get(
            f"{base}/authorize",
            params={
                "client_id": "http://client.example.com/metadata.json",
                "response_type": "code",
                "redirect_uri": REDIRECT_URI,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            },
        )
        assert r.status_code == 400
