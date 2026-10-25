"""Pre-registered ("static") inbound OAuth clients from config.

Covers MCP clients that support neither DCR nor CIMD (e.g. Gemini Enterprise),
which are configured with a fixed client ID/secret and authenticate at the
token endpoint via client_secret_post or client_secret_basic.
"""

from __future__ import annotations

from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from pydantic import ValidationError

from mcp_gateway.app import create_app
from tests.conftest import free_port, gateway_config, obtain_tokens, pkce_pair, register_client

CLIENT_ID = "gemini-enterprise"
CLIENT_SECRET = "s3cr3t:with/special%chars"
REDIRECT_URI = "https://vertexaisearch.cloud.google.com/oauth-redirect"

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


def static_client(**overrides) -> dict:
    return {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "client_name": "Gemini Enterprise",
        "redirect_uris": [REDIRECT_URI],
        **overrides,
    }


@pytest.fixture
def base(run_server):
    port = free_port()
    app = create_app(gateway_config(port, static_clients=[static_client()]))
    return run_server(app, port).base_url


async def _code(http: httpx.AsyncClient, base: str) -> tuple[str, str]:
    """Authorize, log in and consent; returns (code, verifier)."""
    verifier, challenge = pkce_pair()
    r = await http.get(
        f"{base}/authorize",
        params={
            "client_id": CLIENT_ID,
            "response_type": "code",
            "redirect_uri": REDIRECT_URI,
            "state": "s",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        },
    )
    assert r.status_code in (302, 307), r.text
    txn = parse_qs(urlparse(r.headers["location"]).query)["txn"][0]
    r = await http.post(f"{base}/auth/api/login", json={"username": "admin", "password": "pw"})
    http.cookies.update(r.cookies)
    r = await http.get(f"{base}/auth/api/txn/{txn}")
    assert r.json()["client_name"] == "Gemini Enterprise"
    r = await http.post(f"{base}/auth/api/consent", json={"txn_id": txn, "approve": True})
    redirect_to = r.json()["redirect_to"]
    assert redirect_to.startswith(REDIRECT_URI)
    return parse_qs(urlparse(redirect_to).query)["code"][0], verifier


def _code_form(code: str, verifier: str, **extra) -> dict:
    return {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REDIRECT_URI,
        "code_verifier": verifier,
        **extra,
    }


@pytest.mark.parametrize("auth_style", ["post", "basic", "basic_only"])
async def test_static_client_full_flow(base, auth_style):
    async with httpx.AsyncClient() as http:
        tokens = await obtain_tokens(
            http,
            base,
            CLIENT_ID,
            redirect_uri=REDIRECT_URI,
            client_secret=CLIENT_SECRET,
            auth_style=auth_style,
        )
        assert tokens["token_type"].lower() == "bearer"
        assert tokens["refresh_token"]

        r = await http.post(
            f"{base}/mcp",
            json=MCP_INIT,
            headers={**MCP_HEADERS, "Authorization": f"Bearer {tokens['access_token']}"},
        )
        assert r.status_code == 200


async def test_static_client_refresh_rotation(base):
    async with httpx.AsyncClient() as http:
        tokens = await obtain_tokens(
            http, base, CLIENT_ID, redirect_uri=REDIRECT_URI, client_secret=CLIENT_SECRET
        )
        # Basic auth without client_id in the body, as Basic-only clients do.
        r = await http.post(
            f"{base}/token",
            data={"grant_type": "refresh_token", "refresh_token": tokens["refresh_token"]},
            auth=httpx.BasicAuth(CLIENT_ID, CLIENT_SECRET),
        )
        assert r.status_code == 200, r.text
        assert r.json()["refresh_token"] != tokens["refresh_token"]

        # Refresh requires the secret too.
        r = await http.post(
            f"{base}/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": r.json()["refresh_token"],
                "client_id": CLIENT_ID,
            },
        )
        assert r.status_code == 401
        assert r.json()["error"] == "invalid_client"


@pytest.mark.parametrize(
    ("extra", "auth"),
    [
        ({"client_id": CLIENT_ID}, None),  # no secret at all
        ({"client_id": CLIENT_ID, "client_secret": "wrong"}, None),
        ({}, httpx.BasicAuth(CLIENT_ID, "wrong")),
        ({"client_id": "someone-else"}, httpx.BasicAuth(CLIENT_ID, CLIENT_SECRET)),
    ],
    ids=["missing", "wrong-post", "wrong-basic", "client-id-mismatch"],
)
async def test_static_client_bad_credentials_rejected(base, extra, auth):
    async with httpx.AsyncClient() as http:
        code, verifier = await _code(http, base)
        r = await http.post(f"{base}/token", data=_code_form(code, verifier, **extra), auth=auth)
        assert r.status_code == 401
        assert r.json()["error"] == "invalid_client"


async def test_static_client_unregistered_redirect_rejected(base):
    async with httpx.AsyncClient() as http:
        _, challenge = pkce_pair()
        r = await http.get(
            f"{base}/authorize",
            params={
                "client_id": CLIENT_ID,
                "response_type": "code",
                "redirect_uri": "https://evil.example.com/callback",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            },
        )
        assert r.status_code == 400


async def test_static_client_requires_pkce(base):
    async with httpx.AsyncClient() as http:
        r = await http.get(
            f"{base}/authorize",
            params={
                "client_id": CLIENT_ID,
                "response_type": "code",
                "redirect_uri": REDIRECT_URI,
                "state": "s",
            },
        )
        # Redirected back with an error, never parked as a login transaction.
        assert r.status_code in (302, 307)
        location = r.headers["location"]
        assert location.startswith(REDIRECT_URI)
        assert parse_qs(urlparse(location).query)["error"] == ["invalid_request"]


async def test_dcr_clients_unaffected(base):
    """DCR (token_endpoint_auth_method=none) keeps working next to static clients."""
    async with httpx.AsyncClient() as http:
        client_id = await register_client(http, base)
        tokens = await obtain_tokens(http, base, client_id)
        assert tokens["access_token"]


async def test_static_client_not_persisted(run_server):
    port = free_port()
    app = create_app(gateway_config(port, static_clients=[static_client()]))
    run_server(app, port)
    assert app.state.storage.get_client(CLIENT_ID) is None


@pytest.mark.parametrize(
    "clients",
    [
        [static_client(), static_client()],
        [static_client(client_id="https://example.com/client.json")],
        [static_client(redirect_uris=[])],
        [static_client(client_secret="")],
    ],
    ids=["duplicate", "url-client-id", "no-redirect-uris", "empty-secret"],
)
def test_static_client_config_validation(clients):
    with pytest.raises(ValidationError):
        gateway_config(8000, static_clients=clients)
