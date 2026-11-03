"""End-to-end tests for the client-facing OAuth 2.1 authorization server."""

from __future__ import annotations

import asyncio
import time
from urllib.parse import parse_qs, urlparse

import httpx
import pytest

from mcp_gateway.app import create_app
from mcp_gateway.storage import token_hash
from tests.conftest import (
    free_port,
    gateway_config,
    obtain_tokens,
    pkce_pair,
    register_client,
)

MCP_INIT = {
    "jsonrpc": "2.0",
    "method": "initialize",
    "id": 1,
    "params": {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": {"name": "pytest", "version": "0"},
    },
}
MCP_HEADERS = {"Accept": "application/json, text/event-stream"}


@pytest.fixture
def base(gateway):
    server, _ = gateway
    return server.base_url


async def test_unauthenticated_mcp_request_gets_401_with_resource_metadata(base):
    async with httpx.AsyncClient() as http:
        r = await http.post(f"{base}/mcp", json=MCP_INIT, headers=MCP_HEADERS)
        assert r.status_code == 401
        challenge = r.headers.get("www-authenticate", "")
        assert challenge.startswith("Bearer")
        assert f'resource_metadata="{base}/.well-known/oauth-protected-resource/mcp"' in challenge


async def test_protected_resource_metadata(base):
    async with httpx.AsyncClient() as http:
        r = await http.get(f"{base}/.well-known/oauth-protected-resource/mcp")
        assert r.status_code == 200
        prm = r.json()
        assert prm["resource"] == f"{base}/mcp"
        assert prm["authorization_servers"], "PRM must name at least one authorization server"


async def test_authorization_server_metadata(base):
    async with httpx.AsyncClient() as http:
        r = await http.get(f"{base}/.well-known/oauth-authorization-server")
        assert r.status_code == 200
        meta = r.json()
        assert meta["authorization_endpoint"] == f"{base}/authorize"
        assert meta["token_endpoint"] == f"{base}/token"
        assert meta["registration_endpoint"] == f"{base}/register"
        # PKCE is mandatory per the MCP spec; clients refuse to proceed without this.
        assert meta["code_challenge_methods_supported"] == ["S256"]
        # CIMD support must be advertised for clients to use URL client IDs.
        assert meta["client_id_metadata_document_supported"] is True
        assert "none" in meta["token_endpoint_auth_methods_supported"]
        assert "private_key_jwt" in meta["token_endpoint_auth_methods_supported"]
        # OIDC-discovery alias must exist as well (clients try both).
        r = await http.get(f"{base}/.well-known/openid-configuration")
        assert r.status_code == 200


async def test_full_dcr_pkce_flow_and_authenticated_mcp_call(base):
    async with httpx.AsyncClient() as http:
        client_id = await register_client(http, base)
        tokens = await obtain_tokens(http, base, client_id)
        assert tokens["token_type"].lower() == "bearer"
        assert tokens["refresh_token"]

        r = await http.post(
            f"{base}/mcp",
            json=MCP_INIT,
            headers={**MCP_HEADERS, "Authorization": f"Bearer {tokens['access_token']}"},
        )
        assert r.status_code == 200


async def test_loopback_redirect_port_may_vary(base):
    """Claude Code CLI registers one loopback port but authorizes with another."""
    async with httpx.AsyncClient() as http:
        client_id = await register_client(
            http, base, redirect_uri="http://localhost:11111/callback"
        )
        tokens = await obtain_tokens(
            http, base, client_id, redirect_uri="http://localhost:22222/callback"
        )
        assert tokens["access_token"]


async def test_non_loopback_unregistered_redirect_is_rejected(base):
    async with httpx.AsyncClient() as http:
        client_id = await register_client(
            http, base, redirect_uri="https://legit.example.com/callback"
        )
        _, challenge = pkce_pair()
        r = await http.get(
            f"{base}/authorize",
            params={
                "client_id": client_id,
                "response_type": "code",
                "redirect_uri": "https://evil.example.com/callback",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            },
        )
        assert r.status_code == 400


async def test_wrong_pkce_verifier_rejected(base):
    async with httpx.AsyncClient() as http:
        client_id = await register_client(http, base)
        _verifier, challenge = pkce_pair()
        r = await http.get(
            f"{base}/authorize",
            params={
                "client_id": client_id,
                "response_type": "code",
                "redirect_uri": "http://localhost:1234/callback",
                "state": "s",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            },
        )
        txn = parse_qs(urlparse(r.headers["location"]).query)["txn"][0]
        r = await http.post(f"{base}/auth/api/login", json={"username": "admin", "password": "pw"})
        http.cookies.update(r.cookies)
        r = await http.post(f"{base}/auth/api/consent", json={"txn_id": txn, "approve": True})
        code = parse_qs(urlparse(r.json()["redirect_to"]).query)["code"][0]

        wrong_verifier, _ = pkce_pair()
        r = await http.post(
            f"{base}/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": "http://localhost:1234/callback",
                "client_id": client_id,
                "code_verifier": wrong_verifier,
            },
        )
        assert r.status_code in (400, 401)
        assert r.json()["error"] == "invalid_grant"


async def test_authorization_code_single_use(base):
    async with httpx.AsyncClient() as http:
        client_id = await register_client(http, base)
        verifier, challenge = pkce_pair()
        r = await http.get(
            f"{base}/authorize",
            params={
                "client_id": client_id,
                "response_type": "code",
                "redirect_uri": "http://localhost:1234/callback",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            },
        )
        txn = parse_qs(urlparse(r.headers["location"]).query)["txn"][0]
        r = await http.post(f"{base}/auth/api/login", json={"username": "admin", "password": "pw"})
        http.cookies.update(r.cookies)
        r = await http.post(f"{base}/auth/api/consent", json={"txn_id": txn, "approve": True})
        code = parse_qs(urlparse(r.json()["redirect_to"]).query)["code"][0]

        form = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": "http://localhost:1234/callback",
            "client_id": client_id,
            "code_verifier": verifier,
        }
        first = await http.post(f"{base}/token", data=form)
        assert first.status_code == 200
        second = await http.post(f"{base}/token", data=form)
        assert second.status_code in (400, 401)


async def _refresh(http: httpx.AsyncClient, base: str, client_id: str, refresh_token: str):
    return await http.post(
        f"{base}/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": client_id,
        },
    )


@pytest.fixture
def strict_rotation_base(run_server):
    """A gateway with refresh-token reuse grace disabled (strict single use)."""
    port = free_port()
    app = create_app(gateway_config(port, refresh_token_reuse_grace_seconds=0))
    return run_server(app, port).base_url


async def test_refresh_token_rotation(strict_rotation_base):
    base = strict_rotation_base
    async with httpx.AsyncClient() as http:
        client_id = await register_client(http, base)
        tokens = await obtain_tokens(http, base, client_id)

        r = await _refresh(http, base, client_id, tokens["refresh_token"])
        assert r.status_code == 200
        new_tokens = r.json()
        assert new_tokens["access_token"] != tokens["access_token"]
        assert new_tokens["refresh_token"] != tokens["refresh_token"]

        # With no grace window, the old refresh token is dead after rotation.
        r = await _refresh(http, base, client_id, tokens["refresh_token"])
        assert r.status_code in (400, 401)

        # New access token works.
        r = await http.post(
            f"{base}/mcp",
            json=MCP_INIT,
            headers={**MCP_HEADERS, "Authorization": f"Bearer {new_tokens['access_token']}"},
        )
        assert r.status_code == 200


async def test_concurrent_refresh_with_same_token_both_succeed(base):
    """Clients like Claude share one connector's credentials across several
    surfaces and can refresh concurrently (or retry a refresh whose response
    was lost). With instant revocation the loser got invalid_grant and the
    client silently dropped the connector's tool list."""
    async with httpx.AsyncClient() as http:
        client_id = await register_client(http, base)
        tokens = await obtain_tokens(http, base, client_id)

        first, second = await asyncio.gather(
            _refresh(http, base, client_id, tokens["refresh_token"]),
            _refresh(http, base, client_id, tokens["refresh_token"]),
        )
        assert first.status_code == 200, first.text
        assert second.status_code == 200, second.text

        # Every pair handed out is independently usable: the client may keep
        # whichever response it stored last.
        for pair in (first.json(), second.json()):
            r = await http.post(
                f"{base}/mcp",
                json=MCP_INIT,
                headers={**MCP_HEADERS, "Authorization": f"Bearer {pair['access_token']}"},
            )
            assert r.status_code == 200
            r = await _refresh(http, base, client_id, pair["refresh_token"])
            assert r.status_code == 200, r.text


async def test_rotated_refresh_token_dies_after_grace_window(gateway):
    server, app = gateway
    base = server.base_url
    storage = app.state.storage
    async with httpx.AsyncClient() as http:
        client_id = await register_client(http, base)
        tokens = await obtain_tokens(http, base, client_id)

        r = await _refresh(http, base, client_id, tokens["refresh_token"])
        assert r.status_code == 200

        # A rotated token only lives for the grace window, not its original
        # 30-day lifetime -- and a reuse inside the window doesn't extend it.
        old = storage.get_refresh_token(tokens["refresh_token"])
        grace = app.state.config.auth.refresh_token_reuse_grace_seconds
        assert old is not None
        assert old["expires_at"] <= time.time() + grace
        r = await _refresh(http, base, client_id, tokens["refresh_token"])
        assert r.status_code == 200
        assert storage.get_refresh_token(tokens["refresh_token"])["expires_at"] == old["expires_at"]

        # Simulate the window elapsing.
        with storage._lock:
            storage._conn.execute(
                "UPDATE refresh_tokens SET expires_at=? WHERE token_hash=?",
                (time.time() - 1, token_hash(tokens["refresh_token"])),
            )
            storage._conn.commit()
        r = await _refresh(http, base, client_id, tokens["refresh_token"])
        assert r.status_code in (400, 401)


async def test_revoked_refresh_token_gets_no_grace(base):
    """Explicit revocation (RFC 7009) is immediate; the grace window only
    applies to rotation."""
    async with httpx.AsyncClient() as http:
        client_id = await register_client(http, base)
        tokens = await obtain_tokens(http, base, client_id)

        r = await http.post(
            f"{base}/revoke",
            # client_secret must be present (may be empty) per the SDK's
            # request model, even for public clients.
            data={
                "token": tokens["refresh_token"],
                "token_type_hint": "refresh_token",
                "client_id": client_id,
                "client_secret": "",
            },
        )
        assert r.status_code == 200
        r = await _refresh(http, base, client_id, tokens["refresh_token"])
        assert r.status_code in (400, 401)


async def test_denied_consent_returns_access_denied(base):
    async with httpx.AsyncClient() as http:
        client_id = await register_client(http, base)
        result = await obtain_tokens(http, base, client_id, approve=False)
        assert result["error"] == "access_denied"
        assert result["state"] == "test-state"


async def test_consent_requires_login(base):
    async with httpx.AsyncClient() as http:
        client_id = await register_client(http, base)
        _, challenge = pkce_pair()
        r = await http.get(
            f"{base}/authorize",
            params={
                "client_id": client_id,
                "response_type": "code",
                "redirect_uri": "http://localhost:1234/callback",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            },
        )
        txn = parse_qs(urlparse(r.headers["location"]).query)["txn"][0]
        r = await http.post(f"{base}/auth/api/consent", json={"txn_id": txn, "approve": True})
        assert r.status_code == 401


async def test_login_rejects_bad_password(base):
    async with httpx.AsyncClient() as http:
        r = await http.post(
            f"{base}/auth/api/login", json={"username": "admin", "password": "nope"}
        )
        assert r.status_code == 401


async def test_invalid_bearer_token_rejected(base):
    async with httpx.AsyncClient() as http:
        r = await http.post(
            f"{base}/mcp",
            json=MCP_INIT,
            headers={**MCP_HEADERS, "Authorization": "Bearer not-a-real-token"},
        )
        assert r.status_code == 401


async def test_revocation_endpoint(base):
    async with httpx.AsyncClient() as http:
        client_id = await register_client(http, base)
        tokens = await obtain_tokens(http, base, client_id)
        r = await http.post(
            f"{base}/revoke",
            # client_secret must be present (may be empty) per the SDK's
            # request model, even for public clients.
            data={
                "token": tokens["access_token"],
                "token_type_hint": "access_token",
                "client_id": client_id,
                "client_secret": "",
            },
        )
        assert r.status_code == 200
        r = await http.post(
            f"{base}/mcp",
            json=MCP_INIT,
            headers={**MCP_HEADERS, "Authorization": f"Bearer {tokens['access_token']}"},
        )
        assert r.status_code == 401
