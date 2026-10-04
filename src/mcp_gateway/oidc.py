"""Browser login via external OpenID Connect providers (standard OIDC + Entra ID).

The gateway acts as an OIDC relying party for its *own* login page: it is an
alternative to the local username/password accounts, and ends in the same
signed session cookie (``users.SessionManager``). It plays no part in the MCP
OAuth legs -- tokens from the identity provider are used only to establish
who signed in and are then discarded, never stored and never forwarded.

Flow (authorization code + PKCE S256 + nonce, per OIDC Core 3.1):

1. ``/auth/oidc/<name>/login?return_to=/ui/...`` generates state, nonce and a
   PKCE verifier, puts them in a short-lived signed cookie bound to this
   browser, and redirects to the provider.
2. ``/auth/oidc/<name>/callback`` checks ``state`` against that cookie,
   exchanges the code, validates the ID token (signature via the provider's
   JWKS, ``iss``, ``aud``, ``azp``, ``exp``, ``nonce``) and applies the
   provider's ``allowed_*`` rules before a session is created.

Flow state lives in the browser (signed cookie), discovery documents and
JWKS in a per-process cache.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import secrets
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode, urlparse

import httpx
import jwt
from itsdangerous import BadSignature, URLSafeTimedSerializer

from mcp_gateway.config import GatewayConfig, OIDCProviderConfig, require_https_url

logger = logging.getLogger(__name__)

FLOW_COOKIE = "mcp_gateway_oidc"
FLOW_COOKIE_PATH = "/auth/oidc"
# How long a user may spend at the identity provider before the callback.
FLOW_MAX_AGE_SECONDS = 600
DEFAULT_RETURN_TO = "/ui/backends"

METADATA_TTL_SECONDS = 3600
# Minimum interval between JWKS re-fetches triggered by an unknown `kid`, so a
# stream of forged tokens can't turn the gateway into a JWKS request amplifier.
JWKS_REFRESH_MIN_INTERVAL_SECONDS = 60
HTTP_TIMEOUT_SECONDS = 15.0
CLOCK_SKEW_SECONDS = 120

# Asymmetric algorithms only: "none" and the HMAC family are never accepted
# (HS* would validate against the client secret, which is not how either
# Entra or any mainstream provider signs ID tokens).
_ALLOWED_ALGS = frozenset(
    {"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA"}
)


class OIDCError(Exception):
    """A login failure whose message is safe to show to the user."""


@dataclass(frozen=True)
class OIDCIdentity:
    provider: str
    username: str
    subject: str


def safe_return_to(value: str | None) -> str:
    """Only allow same-origin paths into the UI, never an absolute URL (open redirect)."""
    if not value or "\\" in value or any(ord(ch) < 0x20 for ch in value):
        return DEFAULT_RETURN_TO
    parsed = urlparse(value)
    if parsed.scheme or parsed.netloc or value.startswith("//"):
        return DEFAULT_RETURN_TO
    if parsed.path != "/ui" and not parsed.path.startswith("/ui/"):
        return DEFAULT_RETURN_TO
    return value


def _pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(64)
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    )
    return verifier, challenge


def _claim(claims: dict[str, Any], path: str) -> Any:
    """Look up a (possibly dotted, i.e. nested) claim."""
    if path in claims:
        return claims[path]
    node: Any = claims
    for part in path.split("."):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


def _claim_list(claims: dict[str, Any], path: str) -> list[str]:
    value = _claim(claims, path)
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(item) for item in value]
    return []


def _lower_set(values: list[str]) -> set[str]:
    return {v.strip().lower() for v in values}


class OIDCProvider:
    """One configured identity provider: discovery, code exchange, ID token checks."""

    def __init__(self, name: str, config: OIDCProviderConfig, redirect_uri: str):
        self.name = name
        self.config = config
        self.redirect_uri = redirect_uri
        self.display_name = config.resolved_display_name or name
        self._metadata: dict[str, Any] | None = None
        self._metadata_fetched_at = 0.0
        self._jwks: jwt.PyJWKSet | None = None
        self._jwks_fetched_at = 0.0

    # ------------------------------------------------------------ discovery

    async def _get_json(self, url: str) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT_SECONDS) as http:
            response = await http.get(url, headers={"Accept": "application/json"})
        response.raise_for_status()
        data = response.json()
        if not isinstance(data, dict):
            raise TypeError(f"{url} did not return a JSON object")
        return data

    async def metadata(self) -> dict[str, Any]:
        now = time.time()
        if self._metadata is not None and now - self._metadata_fetched_at < METADATA_TTL_SECONDS:
            return self._metadata
        url = self.config.resolved_discovery_url
        logger.debug("Fetching OIDC discovery document for %s from %s", self.name, url)
        try:
            metadata = await self._get_json(url)
        except Exception as exc:
            logger.warning("OIDC discovery for provider %s failed: %r", self.name, exc)
            if self._metadata is not None:
                return self._metadata  # serve stale rather than lock everyone out
            raise OIDCError(f"Could not reach identity provider {self.display_name!r}") from exc
        for field in ("issuer", "authorization_endpoint", "token_endpoint", "jwks_uri"):
            if not isinstance(metadata.get(field), str):
                raise OIDCError(f"Identity provider {self.display_name!r} metadata lacks {field}")
        for field in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
            _require_secure_url(metadata[field], self.display_name)
        # OIDC Discovery 4.3: the document's issuer must be the one we asked.
        # Entra reports its GUID-based issuer even when tenant_id is a domain,
        # and a "{tenantid}" template for the multi-tenant aliases, so it is
        # checked against the token's `tid` claim instead (see _expected_issuer).
        if self.config.type == "oidc" and (
            metadata["issuer"].rstrip("/") != self.config.resolved_issuer
        ):
            logger.error(
                "OIDC provider %s: discovery issuer %r does not match configured issuer %r",
                self.name,
                metadata["issuer"],
                self.config.resolved_issuer,
            )
            raise OIDCError(f"Identity provider {self.display_name!r} is misconfigured")
        self._metadata = metadata
        self._metadata_fetched_at = now
        return metadata

    async def _signing_keys(self, *, refresh: bool = False) -> jwt.PyJWKSet:
        now = time.time()
        stale = now - self._jwks_fetched_at >= METADATA_TTL_SECONDS
        throttled = now - self._jwks_fetched_at < JWKS_REFRESH_MIN_INTERVAL_SECONDS
        if self._jwks is not None and not stale and (not refresh or throttled):
            return self._jwks
        metadata = await self.metadata()
        logger.debug("Fetching JWKS for OIDC provider %s", self.name)
        try:
            jwks = jwt.PyJWKSet.from_dict(await self._get_json(metadata["jwks_uri"]))
        except Exception as exc:
            logger.warning("Fetching JWKS for OIDC provider %s failed: %r", self.name, exc)
            if self._jwks is not None:
                return self._jwks
            raise OIDCError(
                f"Could not load signing keys of identity provider {self.display_name!r}"
            ) from exc
        self._jwks = jwks
        self._jwks_fetched_at = now
        return jwks

    # ----------------------------------------------------------- the flow

    async def authorization_url(self, *, state: str, nonce: str, code_challenge: str) -> str:
        metadata = await self.metadata()
        params = {
            **self.config.extra_authorize_params,
            "response_type": "code",
            "client_id": self.config.client_id,
            "redirect_uri": self.redirect_uri,
            "scope": " ".join(self.config.scopes),
            "state": state,
            "nonce": nonce,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }
        endpoint = metadata["authorization_endpoint"]
        separator = "&" if urlparse(endpoint).query else "?"
        return f"{endpoint}{separator}{urlencode(params)}"

    def _token_auth_method(self, metadata: dict[str, Any]) -> str:
        if self.config.token_endpoint_auth_method:
            return self.config.token_endpoint_auth_method
        if not self.config.client_secret:
            return "none"
        # RFC 8414 default when the field is absent is client_secret_basic.
        supported = metadata.get("token_endpoint_auth_methods_supported") or [
            "client_secret_basic"
        ]
        if "client_secret_basic" in supported:
            return "client_secret_basic"
        return "client_secret_post"

    async def exchange_code(self, code: str, code_verifier: str) -> dict[str, Any]:
        metadata = await self.metadata()
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self.redirect_uri,
            "code_verifier": code_verifier,
        }
        auth: httpx.Auth | None = None
        method = self._token_auth_method(metadata)
        if method == "client_secret_basic":
            assert self.config.client_secret is not None
            # RFC 6749 2.3.1: form-urlencode both parts before Basic-encoding.
            auth = httpx.BasicAuth(
                _form_encode(self.config.client_id), _form_encode(self.config.client_secret)
            )
        else:
            data["client_id"] = self.config.client_id
            if method == "client_secret_post":
                assert self.config.client_secret is not None
                data["client_secret"] = self.config.client_secret
        try:
            async with httpx.AsyncClient(timeout=HTTP_TIMEOUT_SECONDS) as http:
                response = await http.post(
                    metadata["token_endpoint"],
                    data=data,
                    auth=auth,
                    headers={"Accept": "application/json"},
                )
        except httpx.HTTPError as exc:
            logger.warning("OIDC token request to provider %s failed: %r", self.name, exc)
            raise OIDCError(f"Could not reach identity provider {self.display_name!r}") from exc
        try:
            body = response.json()
        except ValueError:
            body = {}
        if response.status_code != 200 or not isinstance(body, dict):
            # The error code/description are the provider's diagnostics (e.g.
            # Entra's AADSTS codes) and carry no secrets; the request did.
            error = body.get("error") if isinstance(body, dict) else None
            description = body.get("error_description") if isinstance(body, dict) else None
            logger.warning(
                "OIDC token exchange with provider %s failed: HTTP %s %s %s",
                self.name,
                response.status_code,
                error or "",
                description or "",
            )
            raise OIDCError(f"Sign-in with {self.display_name} failed (token exchange rejected)")
        return body

    def _expected_issuer(self, metadata: dict[str, Any], claims: dict[str, Any]) -> str:
        issuer = metadata["issuer"]
        if self.config.type == "entra" and "{tenantid}" in issuer:
            tid = claims.get("tid")
            if not isinstance(tid, str) or not tid:
                raise OIDCError("ID token has no tenant (tid) claim")
            issuer = issuer.replace("{tenantid}", tid)
        return issuer

    async def validate_id_token(self, id_token: str, nonce: str) -> dict[str, Any]:
        metadata = await self.metadata()
        try:
            header = jwt.get_unverified_header(id_token)
        except jwt.PyJWTError as exc:
            raise OIDCError("Malformed ID token") from exc
        alg = header.get("alg")
        advertised = metadata.get("id_token_signing_alg_values_supported") or ["RS256"]
        if alg not in _ALLOWED_ALGS or alg not in advertised:
            raise OIDCError(f"ID token signed with unsupported algorithm {alg!r}")

        key = self._find_key(await self._signing_keys(), header.get("kid"))
        if key is None:
            # Providers rotate keys; refresh once (throttled) before giving up.
            key = self._find_key(await self._signing_keys(refresh=True), header.get("kid"))
        if key is None:
            raise OIDCError("ID token signed with an unknown key")

        try:
            claims = jwt.decode(
                id_token,
                key=key.key,
                algorithms=[alg],
                audience=self.config.client_id,
                leeway=CLOCK_SKEW_SECONDS,
                options={
                    "require": ["iss", "aud", "exp", "iat", "sub"],
                    # Checked below: Entra's multi-tenant issuer depends on `tid`.
                    "verify_iss": False,
                },
            )
        except jwt.PyJWTError as exc:
            logger.warning("OIDC provider %s: ID token rejected: %s", self.name, exc)
            raise OIDCError("ID token validation failed") from exc

        if claims.get("iss") != self._expected_issuer(metadata, claims):
            logger.warning(
                "OIDC provider %s: unexpected ID token issuer %r", self.name, claims.get("iss")
            )
            raise OIDCError("ID token was issued by an unexpected issuer")
        # OIDC Core 3.1.3.7 (4, 5): with several audiences, or whenever azp
        # is present, the authorized party must be this client.
        multi_aud = isinstance(claims["aud"], list) and len(claims["aud"]) > 1
        if (multi_aud or "azp" in claims) and claims.get("azp") != self.config.client_id:
            raise OIDCError("ID token was issued to a different client")
        claim_nonce = claims.get("nonce")
        if not isinstance(claim_nonce, str) or not secrets.compare_digest(claim_nonce, nonce):
            raise OIDCError("ID token nonce mismatch")
        return claims

    @staticmethod
    def _find_key(keys: jwt.PyJWKSet, kid: str | None) -> jwt.PyJWK | None:
        candidates = [
            k for k in keys.keys if k.key_type != "oct" and k.public_key_use in (None, "sig")
        ]
        if kid is not None:
            return next((k for k in candidates if k.key_id == kid), None)
        return candidates[0] if len(candidates) == 1 else None

    async def fetch_userinfo(self, access_token: str) -> dict[str, Any]:
        metadata = await self.metadata()
        endpoint = metadata.get("userinfo_endpoint")
        if not isinstance(endpoint, str):
            return {}
        _require_secure_url(endpoint, self.display_name)
        try:
            async with httpx.AsyncClient(timeout=HTTP_TIMEOUT_SECONDS) as http:
                response = await http.get(
                    endpoint,
                    headers={"Authorization": f"Bearer {access_token}", "Accept": "application/json"},
                )
            response.raise_for_status()
            data = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            logger.warning("OIDC userinfo request to provider %s failed: %r", self.name, exc)
            return {}
        return data if isinstance(data, dict) else {}

    async def resolve_claims(self, tokens: dict[str, Any], nonce: str) -> dict[str, Any]:
        """Validated ID token claims, topped up from userinfo when the ID token
        lacks claims the username or authorization rules need."""
        id_token = tokens.get("id_token")
        if not isinstance(id_token, str):
            raise OIDCError(f"{self.display_name} returned no ID token (is 'openid' in scopes?)")
        claims = await self.validate_id_token(id_token, nonce)

        needed = [self.config.resolved_username_claim]
        if self.config.allowed_groups:
            needed.append(self.config.groups_claim)
        if self.config.allowed_roles:
            needed.append(self.config.roles_claim)
        access_token = tokens.get("access_token")
        if (
            self.config.type == "oidc"
            and isinstance(access_token, str)
            and any(_claim(claims, c) is None for c in needed)
        ):
            userinfo = await self.fetch_userinfo(access_token)
            # OIDC Core 5.3.2: userinfo is only usable if its `sub` matches.
            # The ID token's own claims take precedence.
            if userinfo.get("sub") == claims["sub"]:
                claims = {**userinfo, **claims}
        return claims

    def authorize(self, claims: dict[str, Any]) -> OIDCIdentity:
        """Apply the provider's allow rules; returns the identity or raises OIDCError."""
        cfg = self.config
        username_claim = cfg.resolved_username_claim
        username = _claim(claims, username_claim)
        if not isinstance(username, str) or not username.strip():
            logger.warning(
                "OIDC provider %s: claim %r missing from ID token (sub=%s)",
                self.name,
                username_claim,
                claims.get("sub"),
            )
            raise OIDCError(
                f"{self.display_name} did not provide a username ({username_claim!r} claim)"
            )
        username = username.strip()
        # A provider asserting an address it hasn't verified must not be able
        # to claim someone else's email.
        if username_claim == "email" and claims.get("email_verified") is False:
            raise OIDCError(f"Your email address at {self.display_name} is not verified")

        if (
            cfg.type == "entra"
            and cfg.allowed_tenants
            and str(claims.get("tid", "")).lower() not in _lower_set(cfg.allowed_tenants)
        ):
            logger.warning(
                "OIDC provider %s: rejected %r from tenant %s",
                self.name,
                username,
                claims.get("tid"),
            )
            raise OIDCError("Your organization is not allowed to sign in to this gateway")

        if cfg.type == "entra" and cfg.allowed_groups and "groups" not in claims:
            names = claims.get("_claim_names")
            if isinstance(names, dict) and "groups" in names:
                logger.warning(
                    "OIDC provider %s: %r is in too many groups for Entra to list them in "
                    "the token (group overage); use allowed_roles (app roles) instead",
                    self.name,
                    username,
                )

        allowed = cfg.allow_all_users
        lowered = username.lower()
        if not allowed and lowered in _lower_set(cfg.allowed_users):
            allowed = True
        if not allowed and cfg.allowed_domains and "@" in lowered:
            allowed = lowered.rsplit("@", 1)[1] in _lower_set(cfg.allowed_domains)
        if not allowed and cfg.allowed_groups:
            groups = _lower_set(_claim_list(claims, cfg.groups_claim))
            allowed = bool(groups & _lower_set(cfg.allowed_groups))
        if not allowed and cfg.allowed_roles:
            roles = _lower_set(_claim_list(claims, cfg.roles_claim))
            allowed = bool(roles & _lower_set(cfg.allowed_roles))
        if not allowed:
            logger.warning(
                "OIDC provider %s: %r authenticated but is not allowed by any rule",
                self.name,
                username,
            )
            raise OIDCError(f"{username} is not allowed to sign in to this gateway")

        subject = str(claims["sub"])
        if cfg.type == "entra" and claims.get("oid") and claims.get("tid"):
            subject = f"{claims['tid']}/{claims['oid']}"
        return OIDCIdentity(provider=self.name, username=username, subject=subject)


def _form_encode(value: str) -> str:
    return urlencode({"": value})[1:]


def _require_secure_url(url: str, provider: str) -> None:
    try:
        require_https_url(url, "endpoint")
    except ValueError as exc:
        raise OIDCError(f"Identity provider {provider!r} advertises a non-HTTPS endpoint") from exc


class OIDCManager:
    """All configured providers plus the browser-bound flow state."""

    def __init__(self, config: GatewayConfig, secret: str):
        base = config.server.public_url
        self.providers = {
            name: OIDCProvider(name, provider, f"{base}/auth/oidc/{name}/callback")
            for name, provider in config.auth.oidc.items()
        }
        self._serializer = URLSafeTimedSerializer(secret, salt="mcp-gateway-oidc-flow")

    def login_options(self) -> list[dict[str, str]]:
        return [
            {"name": p.name, "display_name": p.display_name, "type": p.config.type}
            for p in self.providers.values()
        ]

    async def start(self, name: str, return_to: str) -> tuple[str, str]:
        """Begin a login: returns (provider authorization URL, flow cookie value)."""
        provider = self.providers[name]
        state = secrets.token_urlsafe(32)
        nonce = secrets.token_urlsafe(32)
        verifier, challenge = _pkce_pair()
        url = await provider.authorization_url(state=state, nonce=nonce, code_challenge=challenge)
        cookie = self._serializer.dumps(
            json.dumps({"p": name, "s": state, "n": nonce, "v": verifier, "r": return_to})
        )
        return url, cookie

    def read_flow(self, cookie_value: str | None) -> dict[str, str] | None:
        if not cookie_value:
            return None
        try:
            flow = json.loads(self._serializer.loads(cookie_value, max_age=FLOW_MAX_AGE_SECONDS))
        except (BadSignature, ValueError):
            return None
        return flow if isinstance(flow, dict) else None

    async def finish(
        self, name: str, flow: dict[str, str], params: dict[str, str]
    ) -> OIDCIdentity:
        """Complete a login from the callback's query parameters."""
        provider = self.providers[name]
        if flow.get("p") != name:
            raise OIDCError("Sign-in was started with a different provider; please try again")
        state = params.get("state") or ""
        if not secrets.compare_digest(state.encode(), str(flow.get("s", "")).encode()):
            raise OIDCError("Sign-in state mismatch; please try again")
        if params.get("error"):
            description = params.get("error_description") or params["error"]
            logger.warning("OIDC provider %s returned an error: %s", name, description)
            raise OIDCError(f"{provider.display_name} reported an error: {description}")
        # RFC 9207: when the provider identifies itself on the callback it
        # must be the one this flow was sent to (mix-up defense).
        iss = params.get("iss")
        if iss is not None:
            expected = (await provider.metadata())["issuer"]
            if "{tenantid}" not in expected and iss != expected:
                raise OIDCError("Authorization response came from an unexpected issuer")
        code = params.get("code")
        if not code:
            raise OIDCError("Missing authorization code")
        tokens = await provider.exchange_code(code, flow["v"])
        claims = await provider.resolve_claims(tokens, flow["n"])
        return provider.authorize(claims)
