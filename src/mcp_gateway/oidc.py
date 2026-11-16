"""External OpenID Connect login for the gateway's browser session.

This is the *client-facing* login leg only: instead of (or alongside) the
local username/password form backed by ``auth.users``, the browser is sent to
an external identity provider and the identity it returns becomes the user of
the gateway session — the same session that then approves MCP clients on the
consent screen.

It is deliberately separate from ``upstream.py``, which makes the gateway an
OAuth *client of upstream MCP servers*; the two never share credentials,
tokens or storage.

What the gateway trusts is the ID token, and only after verifying it:
asymmetric signature against the provider's JWKS, ``iss``/``aud``/``exp``,
and the ``nonce`` bound to this browser's flow. The access token returned
alongside it is never used or stored — the gateway needs an identity, not API
access.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import logging
import secrets
import time
from dataclasses import dataclass, field
from typing import Any

import httpx
import jwt
from itsdangerous import BadSignature, URLSafeTimedSerializer
from jwt import PyJWKSet

from mcp_gateway.config import OIDCConfig

logger = logging.getLogger(__name__)

# Discovery documents and JWKS are cached for this long. A signing key that
# is unknown to the cached JWKS triggers an immediate refetch regardless
# (bounded by _JWKS_MIN_REFETCH_SECONDS), so key rollover is picked up
# without waiting this out.
METADATA_TTL_SECONDS = 3600
_JWKS_MIN_REFETCH_SECONDS = 60

HTTP_TIMEOUT_SECONDS = 15.0

# Asymmetric algorithms only. Symmetric (HS*) ID tokens are signed with the
# client secret, which turns any party holding it into a token minter, and
# "none" is unsigned — neither is accepted no matter what the provider's
# metadata advertises.
ALLOWED_ID_TOKEN_ALGORITHMS = frozenset(
    {"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512"}
)


class OIDCError(Exception):
    """Login through the identity provider could not be completed."""


@dataclass(frozen=True)
class ProviderMetadata:
    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str
    id_token_signing_alg_values_supported: tuple[str, ...] = ()


@dataclass(frozen=True)
class Identity:
    """The verified end user behind a completed login."""

    username: str
    subject: str
    email: str | None = None
    groups: tuple[str, ...] = ()


@dataclass
class PendingLogin:
    """Per-browser state carried across the redirect to the provider."""

    state: str
    code_verifier: str
    nonce: str
    next_url: str
    created_at: float = field(default_factory=time.time)


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def pkce_pair() -> tuple[str, str]:
    """A PKCE ``(code_verifier, code_challenge)`` pair for method S256."""
    verifier = secrets.token_urlsafe(64)
    challenge = _b64url(hashlib.sha256(verifier.encode()).digest())
    return verifier, challenge


class OIDCClient:
    """Authorization-code client (PKCE, S256) against one OIDC provider.

    One instance per gateway; discovery metadata and JWKS are fetched lazily
    on first login and cached, so a provider that is down at startup only
    fails the login attempt rather than the whole gateway.
    """

    def __init__(self, config: OIDCConfig, redirect_uri: str):
        self.config = config
        self.redirect_uri = redirect_uri
        self._lock = asyncio.Lock()
        self._metadata: ProviderMetadata | None = None
        self._metadata_fetched_at = 0.0
        self._jwks: PyJWKSet | None = None
        self._jwks_fetched_at = 0.0

    # ------------------------------------------------------------- discovery

    def _static_metadata(self) -> ProviderMetadata | None:
        cfg = self.config
        if cfg.authorization_endpoint and cfg.token_endpoint and cfg.jwks_uri:
            return ProviderMetadata(
                issuer=cfg.issuer,
                authorization_endpoint=cfg.authorization_endpoint,
                token_endpoint=cfg.token_endpoint,
                jwks_uri=cfg.jwks_uri,
            )
        return None

    async def metadata(self) -> ProviderMetadata:
        static = self._static_metadata()
        if static is not None:
            return static
        async with self._lock:
            fresh = time.time() - self._metadata_fetched_at < METADATA_TTL_SECONDS
            if self._metadata is not None and fresh:
                return self._metadata
            self._metadata = await self._discover()
            self._metadata_fetched_at = time.time()
            return self._metadata

    async def _discover(self) -> ProviderMetadata:
        url = f"{self.config.issuer}/.well-known/openid-configuration"
        logger.debug("Fetching OIDC discovery document from %s", url)
        try:
            async with httpx.AsyncClient(timeout=HTTP_TIMEOUT_SECONDS) as http:
                response = await http.get(url)
                response.raise_for_status()
                doc = response.json()
        except Exception as exc:
            raise OIDCError(f"Could not read OpenID configuration from {url}: {exc}") from exc
        if not isinstance(doc, dict):
            raise OIDCError(f"OpenID configuration at {url} is not a JSON object")

        issuer = doc.get("issuer") or self.config.issuer
        # RFC 8414 §3.3 / OIDC Discovery §4.3: the issuer in the document
        # must match the one we asked about, otherwise a compromised
        # discovery endpoint could point us at an entirely different party's
        # token endpoint while we keep validating against the wrong issuer.
        if str(issuer).rstrip("/") != self.config.issuer:
            raise OIDCError(
                f"OpenID configuration issuer {issuer!r} does not match "
                f"configured issuer {self.config.issuer!r}"
            )
        missing = [
            key
            for key in ("authorization_endpoint", "token_endpoint", "jwks_uri")
            if not doc.get(key)
        ]
        if missing:
            raise OIDCError(
                f"OpenID configuration at {url} is missing: {', '.join(missing)}"
            )
        algs = doc.get("id_token_signing_alg_values_supported") or []
        return ProviderMetadata(
            issuer=self.config.issuer,
            authorization_endpoint=str(doc["authorization_endpoint"]),
            token_endpoint=str(doc["token_endpoint"]),
            jwks_uri=str(doc["jwks_uri"]),
            id_token_signing_alg_values_supported=tuple(str(a) for a in algs),
        )

    # ------------------------------------------------------------- authorize

    async def start_login(self, next_url: str) -> tuple[str, PendingLogin]:
        """Build the provider's authorization URL and the state to carry along."""
        meta = await self.metadata()
        verifier, challenge = pkce_pair()
        pending = PendingLogin(
            state=secrets.token_urlsafe(32),
            code_verifier=verifier,
            nonce=secrets.token_urlsafe(24),
            next_url=next_url,
        )
        params = {
            "response_type": "code",
            "client_id": self.config.client_id,
            "redirect_uri": self.redirect_uri,
            "scope": " ".join(self.config.scopes),
            "state": pending.state,
            "nonce": pending.nonce,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
        url = str(httpx.URL(meta.authorization_endpoint).copy_merge_params(params))
        return url, pending

    # ----------------------------------------------------------- code -> user

    async def complete_login(self, code: str, pending: PendingLogin) -> Identity:
        """Exchange the code and return the verified identity."""
        meta = await self.metadata()
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self.redirect_uri,
            "client_id": self.config.client_id,
            "code_verifier": pending.code_verifier,
        }
        auth: tuple[str, str] | None = None
        if self.config.client_secret:
            # client_secret_basic first, with the secret also in the body for
            # providers that only read it there. Both are RFC 6749 §2.3.1.
            auth = (self.config.client_id, self.config.client_secret)
            data["client_secret"] = self.config.client_secret

        try:
            async with httpx.AsyncClient(timeout=HTTP_TIMEOUT_SECONDS) as http:
                response = await http.post(
                    meta.token_endpoint,
                    data=data,
                    auth=auth,
                    headers={"Accept": "application/json"},
                )
        except Exception as exc:
            raise OIDCError(f"Token request to the identity provider failed: {exc}") from exc

        if response.status_code >= 400:
            # The body can carry the provider's error code; log it, but keep
            # the user-facing message generic.
            logger.warning(
                "OIDC token endpoint returned %s: %s",
                response.status_code,
                response.text[:500],
            )
            raise OIDCError("The identity provider rejected the authorization code")
        try:
            payload = response.json()
        except ValueError as exc:
            raise OIDCError("The identity provider returned a malformed token response") from exc

        id_token = payload.get("id_token")
        if not id_token:
            raise OIDCError("The identity provider returned no ID token")
        claims = await self._verify_id_token(id_token, nonce=pending.nonce, metadata=meta)
        return self._identity_from_claims(claims)

    # ------------------------------------------------------------ id token

    async def _jwk_for(self, kid: str | None, *, jwks_uri: str) -> Any:
        """Signing key for ``kid``, refetching the JWKS if it isn't known yet."""
        jwks = self._jwks
        stale = time.time() - self._jwks_fetched_at > METADATA_TTL_SECONDS
        key = self._lookup_key(jwks, kid)
        if key is not None and not stale:
            return key
        if (
            key is None
            and jwks is not None
            and time.time() - self._jwks_fetched_at < _JWKS_MIN_REFETCH_SECONDS
        ):
            # Unknown kid moments after a fetch: don't let a stream of bogus
            # tokens turn into a stream of requests to the provider.
            raise OIDCError("ID token was signed with an unknown key")
        refreshed = await self._fetch_jwks(jwks_uri)
        key = self._lookup_key(refreshed, kid)
        if key is None:
            raise OIDCError("ID token was signed with an unknown key")
        return key

    @staticmethod
    def _lookup_key(jwks: PyJWKSet | None, kid: str | None) -> Any:
        if jwks is None:
            return None
        for jwk in jwks.keys:
            # A single-key JWKS commonly omits "kid" on both sides.
            if kid is None or jwk.key_id == kid:
                return jwk.key
        return None

    async def _fetch_jwks(self, jwks_uri: str) -> PyJWKSet:
        logger.debug("Fetching OIDC JWKS from %s", jwks_uri)
        try:
            async with httpx.AsyncClient(timeout=HTTP_TIMEOUT_SECONDS) as http:
                response = await http.get(jwks_uri)
                response.raise_for_status()
                # PyJWKSet skips keys whose algorithm PyJWT can't handle, but
                # raises if that leaves nothing usable.
                jwks = PyJWKSet.from_dict(response.json())
        except Exception as exc:
            raise OIDCError(f"Could not read the provider's signing keys: {exc}") from exc
        self._jwks = jwks
        self._jwks_fetched_at = time.time()
        return jwks

    def _allowed_algorithms(self, metadata: ProviderMetadata) -> list[str]:
        advertised = set(metadata.id_token_signing_alg_values_supported)
        if not advertised:
            return sorted(ALLOWED_ID_TOKEN_ALGORITHMS)
        allowed = sorted(advertised & ALLOWED_ID_TOKEN_ALGORITHMS)
        if not allowed:
            raise OIDCError(
                "The identity provider signs ID tokens only with algorithms this "
                f"gateway does not accept: {', '.join(sorted(advertised))}"
            )
        return allowed

    async def _verify_id_token(
        self, id_token: str, *, nonce: str, metadata: ProviderMetadata
    ) -> dict[str, Any]:
        algorithms = self._allowed_algorithms(metadata)
        try:
            header = jwt.get_unverified_header(id_token)
        except jwt.PyJWTError as exc:
            raise OIDCError("The ID token is malformed") from exc
        if header.get("alg") not in algorithms:
            raise OIDCError(f"ID token uses unsupported signing algorithm {header.get('alg')!r}")

        key = await self._jwk_for(header.get("kid"), jwks_uri=metadata.jwks_uri)
        try:
            claims = jwt.decode(
                id_token,
                key=key,
                algorithms=algorithms,
                audience=self.config.client_id,
                issuer=metadata.issuer,
                options={"require": ["exp", "iat", "iss", "aud", "sub"]},
                leeway=60,
            )
        except jwt.PyJWTError as exc:
            logger.warning("ID token verification failed: %s", exc)
            raise OIDCError("The ID token from the identity provider is not valid") from exc

        # OIDC Core §3.1.3.7 step 11: the nonce ties the token to *this*
        # browser's authorization request, so a token obtained elsewhere
        # can't be replayed into this login.
        if not secrets.compare_digest(str(claims.get("nonce") or ""), nonce):
            raise OIDCError("The ID token does not match this login attempt")
        return claims

    # --------------------------------------------------------------- mapping

    def _identity_from_claims(self, claims: dict[str, Any]) -> Identity:
        subject = str(claims["sub"])
        raw_username = claims.get(self.config.username_claim)
        username = str(raw_username) if raw_username else subject
        raw_groups = claims.get(self.config.groups_claim) or []
        if isinstance(raw_groups, str):
            raw_groups = raw_groups.split()
        groups = tuple(str(g) for g in raw_groups) if isinstance(raw_groups, list) else ()
        email = claims.get("email")
        identity = Identity(
            username=username,
            subject=subject,
            email=str(email) if email else None,
            groups=groups,
        )
        self._authorize(identity)
        return identity

    def _authorize(self, identity: Identity) -> None:
        """Apply the configured allow-lists, if any."""
        allowed_users = self.config.allowed_users
        allowed_groups = self.config.allowed_groups
        if allowed_users is None and allowed_groups is None:
            return
        if allowed_users and identity.username in allowed_users:
            return
        if allowed_groups and set(allowed_groups) & set(identity.groups):
            return
        logger.warning(
            "Denying OIDC login for %r: not in auth.oidc.allowed_users/allowed_groups",
            identity.username,
        )
        raise OIDCError("Your account is not allowed to use this gateway")


OIDC_FLOW_COOKIE = "mcp_gateway_oidc_flow"
# How long the browser has to get through the provider's login screen.
FLOW_TTL_SECONDS = 600


class PendingLoginCodec:
    """Carries :class:`PendingLogin` through the redirect in a signed cookie.

    Keeping it in the browser rather than in server memory means the flow
    survives a gateway restart, costs no server state, and — because the
    ``state`` returned by the provider is compared against the copy in *this*
    browser's cookie — the CSRF check is per-browser rather than global.
    """

    def __init__(self, secret: str, max_age_seconds: int = FLOW_TTL_SECONDS):
        self._serializer = URLSafeTimedSerializer(secret, salt="mcp-gateway-oidc-flow")
        self.max_age_seconds = max_age_seconds

    def dumps(self, pending: PendingLogin) -> str:
        return self._serializer.dumps(
            {
                "s": pending.state,
                "v": pending.code_verifier,
                "n": pending.nonce,
                "next": pending.next_url,
            }
        )

    def loads(self, cookie_value: str | None) -> PendingLogin | None:
        if not cookie_value:
            return None
        try:
            payload = self._serializer.loads(cookie_value, max_age=self.max_age_seconds)
        except (BadSignature, ValueError):
            return None
        if not isinstance(payload, dict):
            return None
        try:
            return PendingLogin(
                state=str(payload["s"]),
                code_verifier=str(payload["v"]),
                nonce=str(payload["n"]),
                next_url=str(payload["next"]),
            )
        except KeyError:
            return None
