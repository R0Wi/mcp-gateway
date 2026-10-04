"""Browser login via external OpenID Connect providers (standard OIDC + Entra ID).

A real (if minimal) identity provider runs over HTTP next to the gateway:
discovery, authorize, token (with PKCE + client auth checks), JWKS and
userinfo, issuing RS256-signed ID tokens. Tests drive the browser redirects
by hand so every hop -- and every rejection -- is observable.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
import time
from typing import Any
from urllib.parse import parse_qs, unquote_plus, urlencode, urlparse

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import ValidationError

from mcp_gateway.app import create_app
from mcp_gateway.config import GatewayConfig, OIDCProviderConfig
from mcp_gateway.oidc import safe_return_to
from tests.conftest import free_port, gateway_config, pkce_pair, register_client

CLIENT_ID = "gateway-client"
CLIENT_SECRET = "s3cr3t:with/special&chars"
ENTRA_TENANT = "11111111-2222-3333-4444-555555555555"


class FakeIdP:
    """Minimal OpenID provider. ``entra=True`` mimics Entra's multi-tenant
    endpoints: discovery under /<tenant>/v2.0 with a ``{tenantid}`` issuer."""

    def __init__(self, *, entra: bool = False):
        self.entra = entra
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.kid = "key-1"
        self.base = ""
        self.claims: dict[str, Any] = {}
        self.userinfo: dict[str, Any] = {}
        # Test hooks to make the IdP misbehave.
        self.signing_key = self.key
        self.token_overrides: dict[str, Any] = {}
        self.token_requests: list[dict[str, Any]] = []
        self.authorize_requests: list[dict[str, str]] = []
        self._codes: dict[str, dict[str, str]] = {}
        self.app = self._build_app()

    def issuer(self, tenant: str = ENTRA_TENANT) -> str:
        return f"{self.base}/{tenant}/v2.0" if self.entra else self.base

    def _metadata(self) -> dict[str, Any]:
        return {
            "issuer": f"{self.base}/{{tenantid}}/v2.0" if self.entra else self.base,
            "authorization_endpoint": f"{self.base}/authorize",
            "token_endpoint": f"{self.base}/token",
            "jwks_uri": f"{self.base}/jwks",
            "userinfo_endpoint": f"{self.base}/userinfo",
            "response_types_supported": ["code"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
        }

    def _build_app(self) -> FastAPI:
        app = FastAPI()

        @app.get("/.well-known/openid-configuration")
        async def discovery():
            return self._metadata()

        @app.get("/{tenant}/v2.0/.well-known/openid-configuration")
        async def entra_discovery(tenant: str):
            return self._metadata()

        @app.get("/authorize")
        async def authorize(request: Request):
            params = dict(request.query_params)
            self.authorize_requests.append(params)
            code = secrets.token_urlsafe(16)
            self._codes[code] = params
            query = urlencode({"code": code, "state": params["state"]})
            return RedirectResponse(f"{params['redirect_uri']}?{query}", status_code=302)

        @app.post("/token")
        async def token(request: Request):
            form = dict(await request.form())
            self.token_requests.append(form)
            auth = request.headers.get("authorization", "")
            if not auth.startswith("Basic "):
                return JSONResponse({"error": "invalid_client"}, status_code=401)
            user, _, password = base64.b64decode(auth[6:]).decode().partition(":")
            if (unquote_plus(user), unquote_plus(password)) != (CLIENT_ID, CLIENT_SECRET):
                return JSONResponse({"error": "invalid_client"}, status_code=401)
            params = self._codes.pop(form.get("code", ""), None)
            if params is None or params["redirect_uri"] != form.get("redirect_uri"):
                return JSONResponse({"error": "invalid_grant"}, status_code=400)
            challenge = (
                base64.urlsafe_b64encode(
                    hashlib.sha256(form.get("code_verifier", "").encode()).digest()
                )
                .decode()
                .rstrip("=")
            )
            if challenge != params["code_challenge"]:
                return JSONResponse({"error": "invalid_grant"}, status_code=400)
            now = int(time.time())
            claims = {
                "iss": self.issuer(self.claims.get("tid", ENTRA_TENANT)),
                "aud": CLIENT_ID,
                "sub": "user-sub-1",
                "iat": now,
                "exp": now + 300,
                "nonce": params["nonce"],
                **self.claims,
                **self.token_overrides,
            }
            id_token = jwt.encode(
                claims, self.signing_key, algorithm="RS256", headers={"kid": self.kid}
            )
            return {"access_token": "idp-access-token", "token_type": "Bearer",
                    "id_token": id_token}

        @app.get("/jwks")
        async def jwks():
            jwk = jwt.algorithms.RSAAlgorithm.to_jwk(self.key.public_key(), as_dict=True)
            return {"keys": [{**jwk, "kid": self.kid, "use": "sig", "alg": "RS256"}]}

        @app.get("/userinfo")
        async def userinfo(request: Request):
            if request.headers.get("authorization") != "Bearer idp-access-token":
                return JSONResponse({"error": "invalid_token"}, status_code=401)
            return {"sub": "user-sub-1", **self.userinfo}

        return app


@pytest.fixture
def idp(run_server):
    fake = FakeIdP()
    fake.base = run_server(fake.app).base_url
    return fake


@pytest.fixture
def entra_idp(run_server):
    fake = FakeIdP(entra=True)
    fake.base = run_server(fake.app).base_url
    return fake


def oidc_provider(idp: FakeIdP, **overrides) -> dict[str, Any]:
    return {
        "type": "oidc",
        "display_name": "Fake IdP",
        "issuer": idp.base,
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "allowed_users": ["alice@example.com"],
        **overrides,
    }


def entra_provider(idp: FakeIdP, **overrides) -> dict[str, Any]:
    return {
        "type": "entra",
        "tenant_id": "organizations",
        "authority_host": idp.base,
        "allowed_tenants": [ENTRA_TENANT],
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "allowed_roles": ["MCP.User"],
        **overrides,
    }


@pytest.fixture
def start_gateway(run_server):
    def _start(providers: dict[str, dict], **auth_extra) -> str:
        port = free_port()
        app = create_app(gateway_config(port, oidc=providers, **auth_extra))
        return run_server(app, port).base_url

    return _start


async def oidc_login(
    http: httpx.AsyncClient, base: str, provider: str, return_to: str = "/ui/backends"
) -> httpx.Response:
    """Follow gateway -> IdP authorize -> gateway callback; return the callback response."""
    r = await http.get(f"{base}/auth/oidc/{provider}/login", params={"return_to": return_to})
    assert r.status_code == 303, r.text
    r = await http.get(r.headers["location"])  # the IdP's /authorize
    assert r.status_code == 302, r.text
    return await http.get(r.headers["location"])  # back to the gateway's callback


def login_error(response: httpx.Response) -> str | None:
    query = parse_qs(urlparse(response.headers["location"]).query)
    return query.get("login_error", [None])[0]


async def me(http: httpx.AsyncClient, base: str) -> str | None:
    return (await http.get(f"{base}/auth/api/me")).json()["username"]


# --------------------------------------------------------------- happy paths


async def test_oidc_login_completes_mcp_authorization(idp, start_gateway):
    idp.claims = {"email": "Alice@Example.com", "email_verified": True}
    base = start_gateway({"fake": oidc_provider(idp)})

    async with httpx.AsyncClient() as http:
        client_id = await register_client(http, base)
        verifier, challenge = pkce_pair()
        redirect_uri = "http://localhost:1234/callback"
        r = await http.get(
            f"{base}/authorize",
            params={
                "client_id": client_id,
                "response_type": "code",
                "redirect_uri": redirect_uri,
                "state": "st",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "resource": f"{base}/mcp",
            },
        )
        consent_path = urlparse(r.headers["location"])
        return_to = f"{consent_path.path}?{consent_path.query}"
        txn = parse_qs(consent_path.query)["txn"][0]

        r = await oidc_login(http, base, "fake", return_to=return_to)
        assert r.status_code == 303
        assert r.headers["location"] == return_to
        assert await me(http, base) == "Alice@Example.com"

        # The authorization request carried PKCE S256, a nonce and our scopes;
        # the code exchange authenticated with the (form-encoded) client secret.
        sent = idp.authorize_requests[0]
        assert sent["code_challenge_method"] == "S256"
        assert sent["nonce"] and sent["state"]
        assert sent["scope"] == "openid profile email"
        assert sent["redirect_uri"] == f"{base}/auth/oidc/fake/callback"
        assert "client_secret" not in idp.token_requests[0]

        r = await http.post(f"{base}/auth/api/consent", json={"txn_id": txn, "approve": True})
        assert r.status_code == 200, r.text
        code = parse_qs(urlparse(r.json()["redirect_to"]).query)["code"][0]
        r = await http.post(
            f"{base}/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": redirect_uri,
                "client_id": client_id,
                "code_verifier": verifier,
                "resource": f"{base}/mcp",
            },
        )
        assert r.status_code == 200, r.text
        assert r.json()["access_token"]


async def test_login_options_lists_providers(idp, start_gateway, entra_idp):
    base = start_gateway({"fake": oidc_provider(idp), "work": entra_provider(entra_idp)})
    async with httpx.AsyncClient() as http:
        r = await http.get(f"{base}/auth/api/login-options")
    assert r.json() == {
        "password": True,
        "providers": [
            {"name": "fake", "display_name": "Fake IdP", "type": "oidc"},
            {"name": "work", "display_name": "Microsoft", "type": "entra"},
        ],
        "auto_redirect": False,
    }


async def test_oidc_only_gateway_has_no_password_login(idp, run_server):
    port = free_port()
    config = GatewayConfig.model_validate(
        {
            "server": {"public_url": f"http://127.0.0.1:{port}"},
            "auth": {"encryption_key": "k", "oidc": {"fake": oidc_provider(idp)}},
            "storage": {"path": ":memory:"},
        }
    )
    base = run_server(create_app(config), port).base_url
    async with httpx.AsyncClient() as http:
        assert (await http.get(f"{base}/auth/api/login-options")).json()["password"] is False
        r = await http.post(f"{base}/auth/api/login", json={"username": "x", "password": "y"})
        assert r.status_code == 401


async def test_groups_and_nested_roles_claims_admit_users(idp, start_gateway):
    idp.claims = {
        "email": "bob@elsewhere.org",
        "groups": ["staff"],
        "realm_access": {"roles": ["mcp-admin"]},
    }
    base = start_gateway(
        {
            "by-group": oidc_provider(idp, allowed_users=[], allowed_groups=["Staff"]),
            "by-role": oidc_provider(
                idp, allowed_users=[], allowed_roles=["mcp-admin"],
                roles_claim="realm_access.roles",
            ),
            "by-domain": oidc_provider(idp, allowed_users=[], allowed_domains=["ELSEWHERE.org"]),
            "nobody": oidc_provider(idp, allowed_users=[], allowed_groups=["admins"]),
        }
    )
    for provider, expected in [
        ("by-group", "bob@elsewhere.org"),
        ("by-role", "bob@elsewhere.org"),
        ("by-domain", "bob@elsewhere.org"),
        ("nobody", None),
    ]:
        async with httpx.AsyncClient() as http:
            r = await oidc_login(http, base, provider)
            assert await me(http, base) == expected, provider
            if expected is None:
                assert "not allowed" in login_error(r)


async def test_userinfo_fills_in_claims_missing_from_id_token(idp, start_gateway):
    idp.claims = {}
    idp.userinfo = {"email": "alice@example.com", "email_verified": True}
    base = start_gateway({"fake": oidc_provider(idp)})
    async with httpx.AsyncClient() as http:
        await oidc_login(http, base, "fake")
        assert await me(http, base) == "alice@example.com"


async def test_custom_username_claim(idp, start_gateway):
    idp.claims = {"preferred_username": "alice"}
    base = start_gateway(
        {"fake": oidc_provider(idp, username_claim="preferred_username", allowed_users=["alice"])}
    )
    async with httpx.AsyncClient() as http:
        await oidc_login(http, base, "fake")
        assert await me(http, base) == "alice"


# --------------------------------------------------------------- Entra ID


async def test_entra_multi_tenant_login(entra_idp, start_gateway):
    entra_idp.claims = {
        "tid": ENTRA_TENANT,
        "oid": "object-id",
        "preferred_username": "carol@contoso.com",
        "roles": ["MCP.User"],
    }
    base = start_gateway({"entra": entra_provider(entra_idp)})
    async with httpx.AsyncClient() as http:
        r = await oidc_login(http, base, "entra")
        assert login_error(r) is None
        assert await me(http, base) == "carol@contoso.com"
    # Discovery came from the tenant-alias endpoint.
    assert entra_idp.authorize_requests


async def test_entra_rejects_foreign_tenant(entra_idp, start_gateway):
    entra_idp.claims = {
        "tid": "99999999-0000-0000-0000-000000000000",
        "preferred_username": "mallory@fabrikam.com",
        "roles": ["MCP.User"],
    }
    base = start_gateway({"entra": entra_provider(entra_idp)})
    async with httpx.AsyncClient() as http:
        r = await oidc_login(http, base, "entra")
        assert "organization is not allowed" in login_error(r)
        assert await me(http, base) is None


async def test_entra_rejects_issuer_not_matching_tid(entra_idp, start_gateway):
    # A token from tenant A must not pass as tenant B by just claiming tid=B.
    entra_idp.claims = {
        "tid": ENTRA_TENANT,
        "preferred_username": "carol@contoso.com",
        "roles": ["MCP.User"],
    }
    entra_idp.token_overrides = {"iss": f"{entra_idp.base}/other-tenant/v2.0"}
    base = start_gateway({"entra": entra_provider(entra_idp)})
    async with httpx.AsyncClient() as http:
        r = await oidc_login(http, base, "entra")
        assert "unexpected issuer" in login_error(r)
        assert await me(http, base) is None


async def test_entra_requires_role(entra_idp, start_gateway):
    entra_idp.claims = {"tid": ENTRA_TENANT, "preferred_username": "dave@contoso.com"}
    base = start_gateway({"entra": entra_provider(entra_idp)})
    async with httpx.AsyncClient() as http:
        r = await oidc_login(http, base, "entra")
        assert "not allowed" in login_error(r)


# ------------------------------------------------------- token validation


@pytest.mark.parametrize(
    ("tamper", "message"),
    [
        ({"nonce": "attacker-nonce"}, "nonce mismatch"),
        ({"aud": "some-other-client"}, "validation failed"),
        ({"iss": "https://evil.example"}, "unexpected issuer"),
        ({"exp": int(time.time()) - 3600}, "validation failed"),
        ({"azp": "some-other-client"}, "different client"),
    ],
)
async def test_tampered_id_token_is_rejected(idp, start_gateway, tamper, message):
    idp.claims = {"email": "alice@example.com"}
    idp.token_overrides = tamper
    base = start_gateway({"fake": oidc_provider(idp)})
    async with httpx.AsyncClient() as http:
        r = await oidc_login(http, base, "fake")
        assert message in login_error(r)
        assert await me(http, base) is None


async def test_id_token_signed_by_unknown_key_is_rejected(idp, start_gateway):
    idp.claims = {"email": "alice@example.com"}
    idp.signing_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    base = start_gateway({"fake": oidc_provider(idp)})
    async with httpx.AsyncClient() as http:
        r = await oidc_login(http, base, "fake")
        assert "validation failed" in login_error(r)
        assert await me(http, base) is None


async def test_unverified_email_is_rejected(idp, start_gateway):
    idp.claims = {"email": "alice@example.com", "email_verified": False}
    base = start_gateway({"fake": oidc_provider(idp)})
    async with httpx.AsyncClient() as http:
        r = await oidc_login(http, base, "fake")
        assert "not verified" in login_error(r)
        assert await me(http, base) is None


# ------------------------------------------------------------ flow binding


async def test_callback_without_flow_cookie_never_redeems_the_code(idp, start_gateway):
    """Login CSRF: a callback URL carrying someone else's code must not log
    this browser in -- and the code must not even be exchanged."""
    idp.claims = {"email": "alice@example.com"}
    base = start_gateway({"fake": oidc_provider(idp)})
    async with httpx.AsyncClient() as attacker:
        r = await attacker.get(f"{base}/auth/oidc/fake/login")
        r = await attacker.get(r.headers["location"])
        callback_url = r.headers["location"]
    async with httpx.AsyncClient() as victim:
        r = await victim.get(callback_url)
        assert r.status_code == 303
        assert "not started in this browser" in login_error(r)
        assert await me(victim, base) is None
    assert idp.token_requests == []


async def test_state_mismatch_is_rejected(idp, start_gateway):
    idp.claims = {"email": "alice@example.com"}
    base = start_gateway({"fake": oidc_provider(idp)})
    async with httpx.AsyncClient() as http:
        r = await http.get(f"{base}/auth/oidc/fake/login")
        r = await http.get(r.headers["location"])
        callback = urlparse(r.headers["location"])
        query = parse_qs(callback.query)
        r = await http.get(
            f"{base}{callback.path}", params={"code": query["code"][0], "state": "forged"}
        )
        assert "state mismatch" in login_error(r)
        assert await me(http, base) is None
    assert idp.token_requests == []


async def test_flow_cookie_is_bound_to_its_provider(idp, start_gateway):
    idp.claims = {"email": "alice@example.com"}
    base = start_gateway({"a": oidc_provider(idp), "b": oidc_provider(idp)})
    async with httpx.AsyncClient() as http:
        r = await http.get(f"{base}/auth/oidc/a/login")
        r = await http.get(r.headers["location"])
        query = urlparse(r.headers["location"]).query
        r = await http.get(f"{base}/auth/oidc/b/callback?{query}")
        assert "different provider" in login_error(r)
        assert await me(http, base) is None


async def test_provider_error_is_reported(idp, start_gateway):
    base = start_gateway({"fake": oidc_provider(idp)})
    async with httpx.AsyncClient() as http:
        r = await http.get(f"{base}/auth/oidc/fake/login")
        state = parse_qs(urlparse(r.headers["location"]).query)["state"][0]
        r = await http.get(
            f"{base}/auth/oidc/fake/callback",
            params={"error": "access_denied", "error_description": "User cancelled", "state": state},
        )
        assert "User cancelled" in login_error(r)


async def test_open_redirect_via_return_to_is_blocked(idp, start_gateway):
    idp.claims = {"email": "alice@example.com"}
    base = start_gateway({"fake": oidc_provider(idp)})
    async with httpx.AsyncClient() as http:
        r = await oidc_login(http, base, "fake", return_to="https://evil.example/ui/")
        assert r.headers["location"] == "/ui/backends"


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("/ui/authorize?txn=abc", "/ui/authorize?txn=abc"),
        ("/ui", "/ui"),
        ("https://evil.example/ui/", "/ui/backends"),
        ("//evil.example/ui/", "/ui/backends"),
        ("/\\evil.example", "/ui/backends"),
        ("/uix", "/ui/backends"),
        ("/token", "/ui/backends"),
        (None, "/ui/backends"),
    ],
)
def test_safe_return_to(value, expected):
    assert safe_return_to(value) == expected


async def test_unknown_provider_is_404(idp, start_gateway):
    base = start_gateway({"fake": oidc_provider(idp)})
    async with httpx.AsyncClient() as http:
        assert (await http.get(f"{base}/auth/oidc/nope/login")).status_code == 404
        assert (await http.get(f"{base}/auth/oidc/nope/callback")).status_code == 404


async def test_unreachable_provider_reports_error(start_gateway):
    dead = f"http://127.0.0.1:{free_port()}"
    base = start_gateway(
        {"dead": {"issuer": dead, "client_id": CLIENT_ID, "allow_all_users": True}}
    )
    async with httpx.AsyncClient() as http:
        r = await http.get(f"{base}/auth/oidc/dead/login", params={"return_to": "/ui/backends"})
        assert r.status_code == 303
        assert "Could not reach" in login_error(r)


# ------------------------------------------------------------ auto-redirect


def _auth_config(**auth) -> GatewayConfig:
    return GatewayConfig.model_validate(
        {
            "server": {"public_url": "https://gw.example"},
            "auth": {"encryption_key": "k", **auth},
        }
    )


_ONE_PROVIDER = {
    "only": {"issuer": "https://idp.example", "client_id": "c", "allow_all_users": True}
}


async def test_auto_redirect_is_advertised_to_the_ui(idp, run_server):
    port = free_port()
    config = GatewayConfig.model_validate(
        {
            "server": {"public_url": f"http://127.0.0.1:{port}"},
            "auth": {
                "encryption_key": "k",
                "oidc": {"fake": oidc_provider(idp)},
                "oidc_auto_redirect": True,
            },
            "storage": {"path": ":memory:"},
        }
    )
    base = run_server(create_app(config), port).base_url
    async with httpx.AsyncClient() as http:
        options = (await http.get(f"{base}/auth/api/login-options")).json()
    assert options["auto_redirect"] is True
    assert options["password"] is False
    assert [p["name"] for p in options["providers"]] == ["fake"]


def test_auto_redirect_is_off_by_default():
    assert _auth_config(oidc=_ONE_PROVIDER).auth.oidc_auto_redirect is False


@pytest.mark.parametrize(
    "auth",
    [
        # Local users exist: there is a choice to make, so no redirect.
        {"oidc": _ONE_PROVIDER, "users": [{"username": "a", "password": "p"}]},
        # More than one provider: which one?
        {"oidc": {**_ONE_PROVIDER, "other": _ONE_PROVIDER["only"]}},
        # No provider at all.
        {},
    ],
)
def test_auto_redirect_requires_a_single_provider_and_no_users(auth):
    with pytest.raises(ValidationError, match="oidc_auto_redirect requires"):
        _auth_config(oidc_auto_redirect=True, **auth)


# ------------------------------------------------------------ config


def _provider(**fields) -> OIDCProviderConfig:
    return OIDCProviderConfig.model_validate(
        {"client_id": "c", "client_secret": "s", **fields}
    )


@pytest.mark.parametrize(
    ("fields", "message"),
    [
        ({"issuer": "https://idp.example"}, "allow_all_users"),
        ({"allow_all_users": True}, "requires 'issuer'"),
        ({"issuer": "http://idp.example", "allow_all_users": True}, "https://"),
        ({"type": "entra", "allow_all_users": True}, "requires 'tenant_id'"),
        (
            {"type": "entra", "tenant_id": "organizations", "allow_all_users": True},
            "allowed_tenants",
        ),
        (
            {"type": "entra", "tenant_id": "t", "issuer": "https://x", "allow_all_users": True},
            "derives the issuer",
        ),
        (
            {"issuer": "https://idp.example", "tenant_id": "t", "allow_all_users": True},
            "only apply to type 'entra'",
        ),
    ],
)
def test_provider_config_validation(fields, message):
    with pytest.raises(ValidationError, match=message):
        _provider(**fields)


def test_entra_defaults():
    p = _provider(type="entra", tenant_id="contoso.onmicrosoft.com", allowed_roles=["r"])
    assert p.resolved_issuer == "https://login.microsoftonline.com/contoso.onmicrosoft.com/v2.0"
    assert p.resolved_discovery_url.endswith("/v2.0/.well-known/openid-configuration")
    assert p.resolved_username_claim == "preferred_username"
    assert p.resolved_display_name == "Microsoft"


def test_openid_scope_is_always_requested():
    p = _provider(issuer="https://idp.example", scopes=["email"], allow_all_users=True)
    assert p.scopes == ["openid", "email"]


def test_provider_names_are_validated():
    with pytest.raises(ValidationError, match="callback URL"):
        GatewayConfig.model_validate(
            {
                "server": {"public_url": "https://gw.example"},
                "auth": {
                    "encryption_key": "k",
                    "oidc": {"bad/name": {"issuer": "https://idp.example", "client_id": "c",
                                          "allow_all_users": True}},
                },
            }
        )
