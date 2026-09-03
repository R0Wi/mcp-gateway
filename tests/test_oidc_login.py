"""End-to-end tests for the optional OpenID Connect browser login.

Like the rest of the suite these run against real HTTP: a small FastAPI app
plays the identity provider (discovery document, JWKS, authorization and
token endpoints, RS256-signed ID tokens from a freshly generated RSA key),
and the gateway's own routes are driven with httpx exactly as a browser
would drive them.
"""

from __future__ import annotations

import time
from urllib.parse import parse_qs, urlparse

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, RedirectResponse

from mcp_gateway.app import create_app
from mcp_gateway.oidc import OIDC_FLOW_COOKIE

from .conftest import free_port, gateway_config, register_client

KEY_ID = "test-key-1"


class FakeIdP:
    """A minimal OIDC provider: discovery, JWKS, /authorize, /token."""

    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        # Authorization requests seen, keyed by the code handed back.
        self.codes: dict[str, dict] = {}
        self.token_requests: list[dict] = []
        # Overridable per test.
        self.claims_override: dict = {}
        self.issuer_override: str | None = None
        self.sign_with_wrong_key = False
        self.omit_id_token = False

    @property
    def issuer(self) -> str:
        return self.issuer_override or self.base_url

    def _jwks(self) -> dict:
        # PyJWT can render a public key as a JWK dict directly.
        from jwt.algorithms import RSAAlgorithm

        jwk = RSAAlgorithm.to_jwk(self.private_key.public_key(), as_dict=True)
        jwk.update({"kid": KEY_ID, "use": "sig", "alg": "RS256"})
        return {"keys": [jwk]}

    def id_token(self, *, audience: str, nonce: str, subject: str = "user-1") -> str:
        now = int(time.time())
        claims = {
            "iss": self.issuer,
            "sub": subject,
            "aud": audience,
            "exp": now + 300,
            "iat": now,
            "nonce": nonce,
            "preferred_username": "alice",
            "email": "alice@example.com",
            "groups": ["mcp-admins"],
            **self.claims_override,
        }
        key = self.private_key
        if self.sign_with_wrong_key:
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        return jwt.encode(claims, key, algorithm="RS256", headers={"kid": KEY_ID})

    def build_app(self) -> FastAPI:
        app = FastAPI()
        idp = self

        @app.get("/.well-known/openid-configuration")
        async def discovery():
            return {
                "issuer": idp.issuer,
                "authorization_endpoint": f"{idp.base_url}/authorize",
                "token_endpoint": f"{idp.base_url}/token",
                "jwks_uri": f"{idp.base_url}/jwks",
                "id_token_signing_alg_values_supported": ["RS256"],
                "response_types_supported": ["code"],
                "code_challenge_methods_supported": ["S256"],
            }

        @app.get("/jwks")
        async def jwks():
            return idp._jwks()

        @app.get("/authorize")
        async def authorize(request: Request):
            params = dict(request.query_params)
            code = f"code-{len(idp.codes)}"
            idp.codes[code] = params
            redirect = httpx.URL(params["redirect_uri"]).copy_merge_params(
                {"code": code, "state": params["state"]}
            )
            return RedirectResponse(str(redirect), status_code=303)

        @app.post("/token")
        async def token(request: Request):
            form = dict(await request.form())
            idp.token_requests.append(form)
            authorize_params = idp.codes.get(form.get("code", ""))
            if authorize_params is None:
                return JSONResponse({"error": "invalid_grant"}, status_code=400)
            body = {"access_token": "idp-access-token", "token_type": "Bearer"}
            if not idp.omit_id_token:
                body["id_token"] = idp.id_token(
                    audience=authorize_params["client_id"],
                    nonce=authorize_params.get("nonce", ""),
                )
            return body

        return app


@pytest.fixture
def idp(run_server):
    """A running fake identity provider; yields the FakeIdP."""
    port = free_port()
    provider = FakeIdP(f"http://127.0.0.1:{port}")
    run_server(provider.build_app(), port)
    return provider


def oidc_settings(idp: FakeIdP, **overrides) -> dict:
    return {
        "issuer": idp.base_url,
        "client_id": "mcp-gateway",
        "client_secret": "idp-client-secret",
        **overrides,
    }


@pytest.fixture
def oidc_gateway(run_server, idp):
    """Gateway with both password and OIDC login; yields (LiveServer, idp)."""
    port = free_port()
    config = gateway_config(port, oidc=oidc_settings(idp))
    return run_server(create_app(config), port), idp


async def drive_login(http: httpx.AsyncClient, base: str, next_url: str = "/ui/backends"):
    """Follow the whole browser round-trip: gateway -> IdP -> gateway."""
    start = await http.get(f"{base}/auth/oidc/login", params={"next": next_url})
    assert start.status_code == 303, start.text
    idp_url = start.headers["location"]

    at_idp = await http.get(idp_url)
    assert at_idp.status_code == 303, at_idp.text

    return await http.get(at_idp.headers["location"])


# ------------------------------------------------------------------ discovery


async def test_login_methods_lists_password_and_oidc(oidc_gateway):
    server, _ = oidc_gateway
    async with httpx.AsyncClient() as http:
        r = await http.get(f"{server.base_url}/auth/api/login-methods")
    assert r.status_code == 200
    assert r.json() == {
        "password": True,
        "oidc": {"name": "SSO", "start_url": "/auth/oidc/login"},
    }


async def test_login_methods_without_oidc(gateway):
    server, _ = gateway
    async with httpx.AsyncClient() as http:
        r = await http.get(f"{server.base_url}/auth/api/login-methods")
    assert r.json() == {"password": True, "oidc": None}


async def test_oidc_routes_absent_without_provider(gateway):
    server, _ = gateway
    async with httpx.AsyncClient() as http:
        assert (await http.get(f"{server.base_url}/auth/oidc/login")).status_code == 404
        assert (await http.get(f"{server.base_url}/auth/oidc/callback")).status_code == 404


async def test_password_login_disabled_when_no_users(run_server, idp):
    port = free_port()
    config = gateway_config(port, users=[], oidc=oidc_settings(idp))
    server = run_server(create_app(config), port)
    async with httpx.AsyncClient() as http:
        methods = (await http.get(f"{server.base_url}/auth/api/login-methods")).json()
        assert methods["password"] is False
        r = await http.post(
            f"{server.base_url}/auth/api/login", json={"username": "admin", "password": "pw"}
        )
    assert r.status_code == 400


# ------------------------------------------------------------- the happy path


async def test_full_login_flow_sets_session(oidc_gateway):
    server, idp = oidc_gateway
    async with httpx.AsyncClient() as http:
        start = await http.get(f"{server.base_url}/auth/oidc/login")
        assert start.status_code == 303
        authorize = httpx.URL(start.headers["location"])
        query = dict(authorize.params)
        assert authorize.host == "127.0.0.1"
        assert query["response_type"] == "code"
        assert query["client_id"] == "mcp-gateway"
        assert query["code_challenge_method"] == "S256"
        assert query["redirect_uri"] == f"{server.base_url}/auth/oidc/callback"
        assert "openid" in query["scope"].split()
        assert OIDC_FLOW_COOKIE in start.cookies

        at_idp = await http.get(str(authorize))
        callback = await http.get(at_idp.headers["location"])

    assert callback.status_code == 303
    assert callback.headers["location"] == "/ui/backends"
    # The code exchange used PKCE and the configured client credentials.
    exchange = idp.token_requests[-1]
    assert exchange["grant_type"] == "authorization_code"
    assert exchange["code_verifier"]
    assert exchange["client_id"] == "mcp-gateway"
    # The in-flight flow cookie is cleared once consumed.
    assert callback.cookies.get(OIDC_FLOW_COOKIE) in (None, "")


async def test_session_from_oidc_login_is_usable(oidc_gateway):
    server, _ = oidc_gateway
    async with httpx.AsyncClient(base_url=server.base_url) as http:
        await drive_login(http, server.base_url)
        me = await http.get("/auth/api/me")
        assert me.json()["username"] == "alice"
        # And it authenticates the rest of the session-guarded API.
        assert (await http.get("/auth/api/backends")).status_code == 200


async def test_username_claim_is_configurable(run_server, idp):
    port = free_port()
    config = gateway_config(port, oidc=oidc_settings(idp, username_claim="email"))
    server = run_server(create_app(config), port)
    async with httpx.AsyncClient(base_url=server.base_url) as http:
        await drive_login(http, server.base_url)
        assert (await http.get("/auth/api/me")).json()["username"] == "alice@example.com"


async def test_username_falls_back_to_subject(run_server, idp):
    port = free_port()
    idp.claims_override = {"preferred_username": None}
    config = gateway_config(port, oidc=oidc_settings(idp))
    server = run_server(create_app(config), port)
    async with httpx.AsyncClient(base_url=server.base_url) as http:
        await drive_login(http, server.base_url)
        assert (await http.get("/auth/api/me")).json()["username"] == "user-1"


async def test_oidc_user_can_approve_an_mcp_client(run_server, idp):
    """The whole point: an SSO session is what grants an MCP client a token."""
    port = free_port()
    config = gateway_config(port, users=[], oidc=oidc_settings(idp))
    base = f"http://127.0.0.1:{port}"
    run_server(create_app(config), port)

    async with httpx.AsyncClient(base_url=base) as http:
        client_id = await register_client(http, base)
        r = await http.get(
            "/authorize",
            params={
                "client_id": client_id,
                "response_type": "code",
                "redirect_uri": "http://localhost:1234/callback",
                "state": "s",
                "code_challenge": "e" * 43,
                "code_challenge_method": "S256",
            },
        )
        txn = parse_qs(urlparse(r.headers["location"]).query)["txn"][0]

        # No password anywhere: the browser logs in through the IdP instead.
        await drive_login(http, base, next_url=f"/ui/authorize?txn={txn}")

        consent = await http.post("/auth/api/consent", json={"txn_id": txn, "approve": True})
        assert consent.status_code == 200, consent.text
        code = parse_qs(urlparse(consent.json()["redirect_to"]).query)["code"][0]
        assert code


# ----------------------------------------------------------------- rejections


async def test_state_mismatch_is_rejected(oidc_gateway):
    server, _ = oidc_gateway
    async with httpx.AsyncClient(base_url=server.base_url) as http:
        start = await http.get("/auth/oidc/login")
        at_idp = await http.get(start.headers["location"])
        tampered = httpx.URL(at_idp.headers["location"]).copy_set_param("state", "not-mine")
        r = await http.get(str(tampered))
        assert r.status_code == 303
        assert "oidc_error=" in r.headers["location"]
        assert (await http.get("/auth/api/me")).json()["username"] is None


async def test_callback_without_flow_cookie_is_rejected(oidc_gateway):
    server, _ = oidc_gateway
    async with httpx.AsyncClient(base_url=server.base_url) as http:
        r = await http.get("/auth/oidc/callback", params={"code": "x", "state": "y"})
        assert r.status_code == 303
        assert "oidc_error=" in r.headers["location"]
        assert (await http.get("/auth/api/me")).json()["username"] is None


async def test_provider_error_response_is_shown(oidc_gateway):
    server, _ = oidc_gateway
    async with httpx.AsyncClient(base_url=server.base_url) as http:
        await http.get("/auth/oidc/login")
        r = await http.get(
            "/auth/oidc/callback",
            params={"error": "access_denied", "error_description": "User said no"},
        )
        assert r.status_code == 303
        assert "User+said+no" in r.headers["location"] or "User%20said%20no" in (
            r.headers["location"]
        )
        assert (await http.get("/auth/api/me")).json()["username"] is None


async def test_id_token_with_bad_signature_is_rejected(oidc_gateway):
    server, idp = oidc_gateway
    idp.sign_with_wrong_key = True
    async with httpx.AsyncClient(base_url=server.base_url) as http:
        r = await drive_login(http, server.base_url)
        assert r.status_code == 303
        assert "oidc_error=" in r.headers["location"]
        assert (await http.get("/auth/api/me")).json()["username"] is None


async def test_id_token_with_wrong_audience_is_rejected(oidc_gateway):
    server, idp = oidc_gateway
    idp.claims_override = {"aud": "some-other-client"}
    async with httpx.AsyncClient(base_url=server.base_url) as http:
        r = await drive_login(http, server.base_url)
        assert "oidc_error=" in r.headers["location"]
        assert (await http.get("/auth/api/me")).json()["username"] is None


async def test_id_token_with_wrong_nonce_is_rejected(oidc_gateway):
    server, idp = oidc_gateway
    idp.claims_override = {"nonce": "not-the-one-we-sent"}
    async with httpx.AsyncClient(base_url=server.base_url) as http:
        r = await drive_login(http, server.base_url)
        assert "oidc_error=" in r.headers["location"]
        assert (await http.get("/auth/api/me")).json()["username"] is None


async def test_expired_id_token_is_rejected(oidc_gateway):
    server, idp = oidc_gateway
    idp.claims_override = {"exp": int(time.time()) - 3600, "iat": int(time.time()) - 7200}
    async with httpx.AsyncClient(base_url=server.base_url) as http:
        r = await drive_login(http, server.base_url)
        assert "oidc_error=" in r.headers["location"]
        assert (await http.get("/auth/api/me")).json()["username"] is None


async def test_missing_id_token_is_rejected(oidc_gateway):
    server, idp = oidc_gateway
    idp.omit_id_token = True
    async with httpx.AsyncClient(base_url=server.base_url) as http:
        r = await drive_login(http, server.base_url)
        assert "oidc_error=" in r.headers["location"]
        assert (await http.get("/auth/api/me")).json()["username"] is None


async def test_issuer_mismatch_in_discovery_is_rejected(run_server, idp):
    idp.issuer_override = "https://evil.example.com"
    port = free_port()
    config = gateway_config(port, oidc=oidc_settings(idp))
    server = run_server(create_app(config), port)
    async with httpx.AsyncClient(base_url=server.base_url) as http:
        r = await http.get("/auth/oidc/login")
        assert r.status_code == 303
        assert "oidc_error=" in r.headers["location"]


# ---------------------------------------------------------------- allow-lists


async def test_allowed_groups_permits_matching_user(run_server, idp):
    port = free_port()
    config = gateway_config(port, oidc=oidc_settings(idp, allowed_groups=["mcp-admins"]))
    server = run_server(create_app(config), port)
    async with httpx.AsyncClient(base_url=server.base_url) as http:
        await drive_login(http, server.base_url)
        assert (await http.get("/auth/api/me")).json()["username"] == "alice"


async def test_allowed_groups_rejects_non_member(run_server, idp):
    port = free_port()
    config = gateway_config(port, oidc=oidc_settings(idp, allowed_groups=["other-team"]))
    server = run_server(create_app(config), port)
    async with httpx.AsyncClient(base_url=server.base_url) as http:
        r = await drive_login(http, server.base_url)
        assert "oidc_error=" in r.headers["location"]
        assert (await http.get("/auth/api/me")).json()["username"] is None


async def test_allowed_users_rejects_unlisted_user(run_server, idp):
    port = free_port()
    config = gateway_config(port, oidc=oidc_settings(idp, allowed_users=["bob"]))
    server = run_server(create_app(config), port)
    async with httpx.AsyncClient(base_url=server.base_url) as http:
        r = await drive_login(http, server.base_url)
        assert "oidc_error=" in r.headers["location"]
        assert (await http.get("/auth/api/me")).json()["username"] is None


# ------------------------------------------------------------- open redirects


@pytest.mark.parametrize(
    "hostile_next",
    ["https://evil.example.com/", "//evil.example.com/", "http://evil.example.com"],
)
async def test_next_cannot_leave_the_gateway(oidc_gateway, hostile_next):
    server, _ = oidc_gateway
    async with httpx.AsyncClient(base_url=server.base_url) as http:
        r = await drive_login(http, server.base_url, next_url=hostile_next)
        assert r.status_code == 303
        assert r.headers["location"] == "/ui/backends"


async def test_next_preserves_the_consent_transaction(oidc_gateway):
    server, _ = oidc_gateway
    async with httpx.AsyncClient(base_url=server.base_url) as http:
        r = await drive_login(http, server.base_url, next_url="/ui/authorize?txn=abc123")
        assert r.headers["location"] == "/ui/authorize?txn=abc123"
