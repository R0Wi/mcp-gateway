"""Client-facing OAuth 2.1 authorization server for the gateway.

Implements the MCP authorization spec (2025-11-25) for the client leg:

- OAuth 2.1 authorization code flow with mandatory PKCE (S256)
- Dynamic Client Registration (RFC 7591) at /register
- Client ID Metadata Documents (draft-ietf-oauth-client-id-metadata-document)
  for URL-based client IDs, including private_key_jwt client authentication
- Pre-registered ("static") confidential clients from config, for MCP clients
  that support neither DCR nor CIMD (client_secret_basic / client_secret_post)
- Authorization Server Metadata (RFC 8414) with
  ``client_id_metadata_document_supported: true``
- Protected Resource Metadata (RFC 9728) and 401 challenges with
  ``WWW-Authenticate: Bearer resource_metadata="..."``
- Short-lived opaque access tokens and rotating refresh tokens, stored hashed

The interactive part (login + consent) is delegated to a small web UI: the
``authorize`` hook parks the request in a transaction and redirects the
browser to ``/ui/authorize?txn=...``; the UI drives login/consent through the
JSON API in ``web.py`` and finally calls :meth:`GatewayOAuthProvider.complete_authorization`.
"""

from __future__ import annotations

import base64
import binascii
import hmac
import logging
import secrets
import time
from typing import Any
from urllib.parse import parse_qsl, unquote, urlencode

from fastmcp.server.auth.auth import (
    AccessToken as FastMCPAccessToken,
)
from fastmcp.server.auth.auth import (
    OAuthProvider,
    PrivateKeyJWTClientAuthenticator,
    TokenHandler,
)
from fastmcp.server.auth.cimd import CIMDClientManager
from fastmcp.server.auth.oauth_proxy.models import ProxyDCRClient
from mcp.server.auth.handlers.metadata import MetadataHandler
from mcp.server.auth.middleware.client_auth import AuthenticationError
from mcp.server.auth.provider import (
    AuthorizationCode,
    AuthorizationParams,
    AuthorizeError,
    RefreshToken,
    RegistrationError,
    TokenError,
    construct_redirect_uri,
)
from mcp.server.auth.routes import build_metadata, cors_middleware
from mcp.server.auth.settings import ClientRegistrationOptions, RevocationOptions
from mcp.server.streamable_http import MCP_PROTOCOL_VERSION_HEADER
from mcp.server.transport_security import (
    DEFAULT_MAX_REQUEST_BODY_SIZE,
    RequestBodyLimitMiddleware,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from pydantic import AnyUrl
from starlette.middleware.cors import CORSMiddleware
from starlette.requests import Request
from starlette.routing import Route, request_response
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from mcp_gateway.config import GatewayConfig
from mcp_gateway.storage import Storage

logger = logging.getLogger(__name__)

CIMD_REFRESH_SECONDS = 3600


class GatewayClient(ProxyDCRClient):
    """Registered client with lenient scope validation.

    MCP clients frequently request scopes taken from the 401 challenge or the
    protected resource metadata rather than from their own registration
    record. The gateway is a single-identity authorization server, so scopes
    do not gate anything security-relevant; accept whatever is requested
    instead of failing the flow with ``invalid_scope``.
    """

    def validate_scope(self, requested_scope: str | None) -> list[str] | None:
        if requested_scope is None:
            if self.scope:
                return self.scope.split(" ")
            return None
        return requested_scope.split(" ")


def _basic_credentials(request: Request) -> tuple[str, str] | None:
    """Decode an RFC 6749 §2.3.1 ``Authorization: Basic`` header, if present."""
    header = request.headers.get("Authorization", "")
    if not header.startswith("Basic "):
        return None
    try:
        decoded = base64.b64decode(header[6:], validate=True).decode("utf-8")
    except (ValueError, UnicodeDecodeError, binascii.Error):
        return None
    if ":" not in decoded:
        return None
    client_id, client_secret = decoded.split(":", 1)
    return unquote(client_id), unquote(client_secret)


class GatewayClientAuthenticator(PrivateKeyJWTClientAuthenticator):
    """Token endpoint client authentication.

    Static (config-defined) clients are authenticated here, accepting the
    secret via either ``client_secret_basic`` or ``client_secret_post``
    (clients like Gemini Enterprise don't let the operator pick). Everything
    else -- DCR, CIMD, private_key_jwt -- is delegated unchanged.
    """

    def __init__(self, provider: GatewayOAuthProvider, **kwargs: Any):
        super().__init__(provider, **kwargs)
        self._gateway_provider = provider

    async def authenticate_request(self, request: Request) -> OAuthClientInformationFull:
        form_data = await request.form()
        form_client_id = form_data.get("client_id")
        basic = _basic_credentials(request)
        client_id = form_client_id or (basic[0] if basic else None)
        static = (
            self._gateway_provider.get_static_client(str(client_id)) if client_id else None
        )
        if static is None:
            return await super().authenticate_request(request)

        if basic is not None and basic[0] != client_id:
            raise AuthenticationError("Client ID mismatch in Basic auth")
        presented = basic[1] if basic is not None else form_data.get("client_secret")
        if not isinstance(presented, str) or not presented:
            raise AuthenticationError("Client secret is required")
        assert static.client_secret is not None
        if not hmac.compare_digest(static.client_secret.encode(), presented.encode()):
            logger.warning("Invalid client secret presented for static client %s", client_id)
            raise AuthenticationError("Invalid client_secret")
        return static


def _basic_client_id_shim(app: ASGIApp) -> ASGIApp:
    """Copy the client ID from an ``Authorization: Basic`` header into the form.

    RFC 6749 §2.3.1 clients using HTTP Basic often omit ``client_id`` from the
    body, but the SDK's token request models require it. Only urlencoded
    bodies lacking ``client_id`` are rewritten; everything else passes through.
    """

    async def shim(scope: Scope, receive: Receive, send: Send) -> None:
        request = Request(scope)
        basic = _basic_credentials(request)
        content_type = request.headers.get("content-type", "")
        if (
            scope["type"] != "http"
            or basic is None
            or not content_type.startswith("application/x-www-form-urlencoded")
        ):
            await app(scope, receive, send)
            return

        body = b""
        more = True
        while more:
            message = await receive()
            body += message.get("body", b"")
            more = message.get("more_body", False)
        fields = parse_qsl(body.decode("latin-1"), keep_blank_values=True)
        if not any(key == "client_id" for key, _ in fields):
            body = urlencode([*fields, ("client_id", basic[0])]).encode()
            headers = [
                (k, v) for k, v in scope["headers"] if k.lower() != b"content-length"
            ]
            headers.append((b"content-length", str(len(body)).encode()))
            scope = {**scope, "headers": headers}

        sent = False

        async def replay() -> Message:
            nonlocal sent
            if sent:
                return await receive()
            sent = True
            return {"type": "http.request", "body": body, "more_body": False}

        await app(scope, replay, send)

    return shim


class GatewayOAuthProvider(OAuthProvider):
    """A minimal, self-contained OAuth AS backed by SQLite and config-file users."""

    def __init__(self, config: GatewayConfig, storage: Storage):
        public_url = config.server.public_url
        super().__init__(
            base_url=public_url,
            issuer_url=public_url,
            client_registration_options=ClientRegistrationOptions(
                enabled=True,
                valid_scopes=None,  # accept any; scopes are informational here
                default_scopes=list(config.auth.scopes_supported),
            ),
            revocation_options=RevocationOptions(enabled=True),
            required_scopes=None,
        )
        self.config = config
        self.storage = storage
        self._allowed_redirect_patterns = config.auth.allowed_client_redirect_uris
        self.cimd_manager = CIMDClientManager(
            enable_cimd=True,
            default_scope=" ".join(config.auth.scopes_supported),
            allowed_redirect_uri_patterns=self._allowed_redirect_patterns,
        )
        default_scope = " ".join(config.auth.scopes_supported)
        self._static_clients: dict[str, GatewayClient] = {
            c.client_id: GatewayClient(
                client_id=c.client_id,
                client_secret=c.client_secret,
                client_name=c.client_name or c.client_id,
                redirect_uris=[AnyUrl(uri) for uri in c.redirect_uris],
                token_endpoint_auth_method="client_secret_post",
                grant_types=["authorization_code", "refresh_token"],
                response_types=["code"],
                scope=" ".join(c.scopes) if c.scopes else default_scope or None,
                # Exact match against redirect_uris; the DCR/CIMD allow-list
                # patterns don't apply to operator-defined clients.
                allowed_redirect_uri_patterns=None,
            )
            for c in config.auth.static_clients
        }
        if self._static_clients:
            logger.info(
                "Configured %d static OAuth client(s): %s",
                len(self._static_clients),
                ", ".join(self._static_clients),
            )

    # ------------------------------------------------------------------ clients

    def get_static_client(self, client_id: str) -> GatewayClient | None:
        return self._static_clients.get(client_id)

    def _client_from_record(self, record: dict[str, Any]) -> GatewayClient:
        return GatewayClient.model_validate(record)

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        static = self._static_clients.get(client_id)
        if static is not None:
            logger.debug("Resolved static client %s from config", client_id)
            return static

        record = self.storage.get_client(client_id)
        if record is not None:
            client = self._client_from_record(record)
            # Refresh CIMD-backed clients periodically via the cache-aware fetcher.
            if client.cimd_document is not None and (
                client.cimd_fetched_at is None
                or time.time() - client.cimd_fetched_at > CIMD_REFRESH_SECONDS
            ):
                logger.debug("Refreshing stale CIMD client document for %s", client_id)
                refreshed = await self._fetch_cimd_client(client_id)
                if refreshed is not None:
                    return refreshed
            else:
                logger.debug("Loaded cached client %s from storage", client_id)
            return client

        if self.cimd_manager.is_cimd_client_id(client_id):
            logger.debug("Client %s not found in storage; fetching from CIMD", client_id)
            return await self._fetch_cimd_client(client_id)
        
        logger.debug("Client %s is not a CIMD client, return None", client_id)
        return None

    async def _fetch_cimd_client(self, client_id: str) -> GatewayClient | None:
        cimd_client = await self.cimd_manager.get_client(client_id)
        if cimd_client is None:
            return None
        client = GatewayClient.model_validate(cimd_client.model_dump(mode="json"))
        self.storage.save_client(client_id, client.model_dump(mode="json"), is_cimd=True)
        return client

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        if client_info.client_id in self._static_clients:
            # DCR client IDs are random UUIDs, so this should never happen.
            raise RegistrationError(
                error="invalid_client_metadata",
                error_description="client_id collides with a pre-registered client",
            )
        client = GatewayClient.model_validate(client_info.model_dump(mode="json"))
        client.allowed_redirect_uri_patterns = self._allowed_redirect_patterns
        self.storage.save_client(client.client_id, client.model_dump(mode="json"))
        logger.info(
            "Registered new OAuth client %r via DCR (%s)",
            client_info.client_name or client_info.client_id,
            client.client_id,
        )

    # ------------------------------------------------------------------ authorize

    async def authorize(
        self, client: OAuthClientInformationFull, params: AuthorizationParams
    ) -> str:
        txn_id = secrets.token_urlsafe(32)
        client_name = getattr(client, "client_name", None)
        self.storage.save_txn(
            txn_id,
            {
                "client_id": client.client_id,
                "client_name": client_name,
                "redirect_uri": str(params.redirect_uri),
                "redirect_uri_provided_explicitly": params.redirect_uri_provided_explicitly,
                "state": params.state,
                "code_challenge": params.code_challenge,
                "scopes": params.scopes or [],
                "resource": params.resource,
                "created_at": time.time(),
            },
            ttl_seconds=600,
        )
        return f"{str(self.base_url).rstrip('/')}/ui/authorize?txn={txn_id}"

    def describe_txn(self, txn_id: str) -> dict[str, Any] | None:
        """Public transaction info for the login/consent UI."""
        txn = self.storage.get_txn(txn_id)
        if txn is None:
            return None
        from urllib.parse import urlparse

        redirect = urlparse(txn["redirect_uri"])
        return {
            "txn_id": txn_id,
            "client_id": txn["client_id"],
            "client_name": txn.get("client_name"),
            "redirect_uri": txn["redirect_uri"],
            "redirect_host": redirect.hostname or "",
            "is_loopback_redirect": (redirect.hostname or "").lower()
            in {"localhost", "127.0.0.1", "::1"},
            "scopes": txn.get("scopes") or [],
        }

    def complete_authorization(self, txn_id: str, *, subject: str, approve: bool) -> str:
        """Finish a parked authorization request; returns the redirect URL.

        Called by the consent endpoint after the user authenticated and made a
        decision. Generates the authorization code on approval.
        """
        txn = self.storage.get_txn(txn_id)
        if txn is None:
            raise AuthorizeError(
                error="invalid_request", error_description="Unknown or expired transaction"
            )
        self.storage.delete_txn(txn_id)

        if not approve:
            logger.info(
                "Authorization denied by %s for client %s", subject, txn["client_id"]
            )
            return construct_redirect_uri(
                txn["redirect_uri"], error="access_denied", state=txn.get("state")
            )

        logger.info("Authorization approved by %s for client %s", subject, txn["client_id"])
        code = secrets.token_urlsafe(32)
        expires_at = time.time() + self.config.auth.authorization_code_expiry_seconds
        self.storage.save_auth_code(
            code,
            {
                "client_id": txn["client_id"],
                "redirect_uri": txn["redirect_uri"],
                "redirect_uri_provided_explicitly": txn["redirect_uri_provided_explicitly"],
                "code_challenge": txn["code_challenge"],
                "scopes": txn.get("scopes") or [],
                "resource": txn.get("resource"),
                "subject": subject,
                "expires_at": expires_at,
            },
            expires_at=expires_at,
        )
        return construct_redirect_uri(txn["redirect_uri"], code=code, state=txn.get("state"))

    # ------------------------------------------------------------------ codes & tokens

    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> AuthorizationCode | None:
        data = self.storage.get_auth_code(authorization_code)
        if data is None or data["client_id"] != client.client_id:
            return None
        return AuthorizationCode(
            code=authorization_code,
            scopes=data["scopes"],
            expires_at=data["expires_at"],
            client_id=data["client_id"],
            code_challenge=data["code_challenge"],
            redirect_uri=AnyUrl(data["redirect_uri"]),
            redirect_uri_provided_explicitly=data["redirect_uri_provided_explicitly"],
            resource=data.get("resource"),
            subject=data.get("subject"),
        )

    def _issue_tokens(
        self,
        *,
        client_id: str,
        scopes: list[str],
        subject: str | None,
        resource: str | None,
    ) -> OAuthToken:
        access_token = secrets.token_urlsafe(43)
        refresh_token = secrets.token_urlsafe(43)
        now = time.time()
        access_expiry = self.config.auth.access_token_expiry_seconds
        self.storage.save_access_token(
            access_token,
            client_id=client_id,
            scopes=scopes,
            subject=subject,
            resource=resource,
            expires_at=now + access_expiry,
        )
        self.storage.save_refresh_token(
            refresh_token,
            client_id=client_id,
            scopes=scopes,
            subject=subject,
            resource=resource,
            expires_at=now + self.config.auth.refresh_token_expiry_seconds,
        )
        return OAuthToken(
            access_token=access_token,
            token_type="Bearer",
            expires_in=access_expiry,
            scope=" ".join(scopes) if scopes else None,
            refresh_token=refresh_token,
        )

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode
    ) -> OAuthToken:
        # Single-use: consume the code before issuing anything.
        if self.storage.get_auth_code(authorization_code.code) is None:
            raise TokenError(error="invalid_grant", error_description="Authorization code expired")
        self.storage.delete_auth_code(authorization_code.code)
        # A completed authorization exempts this client from the unused-client
        # TTL that reclaims anonymous DCR/CIMD registrations (see storage.py).
        self.storage.mark_client_used(client.client_id)
        logger.info(
            "Issuing access/refresh token pair to client %s (subject=%s)",
            client.client_id,
            authorization_code.subject,
        )
        return self._issue_tokens(
            client_id=client.client_id,
            scopes=authorization_code.scopes,
            subject=authorization_code.subject,
            resource=authorization_code.resource,
        )

    async def load_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: str
    ) -> RefreshToken | None:
        data = self.storage.get_refresh_token(refresh_token)
        if data is None or data["client_id"] != client.client_id:
            return None
        return RefreshToken(
            token=refresh_token,
            client_id=data["client_id"],
            scopes=data["scopes"],
            expires_at=int(data["expires_at"]),
            subject=data.get("subject"),
        )

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: RefreshToken,
        scopes: list[str],
    ) -> OAuthToken:
        data = self.storage.get_refresh_token(refresh_token.token)
        if data is None or data["client_id"] != client.client_id:
            raise TokenError(error="invalid_grant", error_description="Invalid refresh token")
        # Rotation (OAuth 2.1 requirement for public clients): the old refresh
        # token is revoked and a fresh access/refresh pair is issued.
        self.storage.revoke_refresh_token(refresh_token.token)
        effective_scopes = scopes or data["scopes"]
        logger.debug("Rotating refresh token for client %s", client.client_id)
        return self._issue_tokens(
            client_id=client.client_id,
            scopes=effective_scopes,
            subject=data.get("subject"),
            resource=data.get("resource"),
        )

    async def load_access_token(self, token: str) -> FastMCPAccessToken | None:
        data = self.storage.get_access_token(token)
        if data is None:
            return None
        return FastMCPAccessToken(
            token=token,
            client_id=data["client_id"],
            scopes=data["scopes"],
            expires_at=int(data["expires_at"]),
            resource=data.get("resource"),
            subject=data.get("subject"),
            claims={"iss": str(self.issuer_url), "sub": data.get("subject")},
        )

    async def revoke_token(self, token: FastMCPAccessToken | RefreshToken) -> None:
        logger.info("Revoking token for client %s", token.client_id)
        self.storage.delete_access_token(token.token)
        self.storage.revoke_refresh_token(token.token)

    # ------------------------------------------------------------------ routes

    def get_routes(self, mcp_path: str | None = None) -> list[Route]:
        """Standard OAuth routes with CIMD support patched in.

        - AS metadata advertises ``client_id_metadata_document_supported`` and
          the ``private_key_jwt``/``none`` token endpoint auth methods.
        - The token endpoint accepts ``private_key_jwt`` client assertions from
          CIMD clients (validated against the JWKS in their metadata document).
        """
        routes = super().get_routes(mcp_path)
        token_endpoint_url = f"{str(self.base_url).rstrip('/')}/token"
        patched: list[Route] = []
        for route in routes:
            if (
                isinstance(route, Route)
                and route.path == "/token"
                and route.methods is not None
                and "POST" in route.methods
            ):
                authenticator = GatewayClientAuthenticator(
                    provider=self,
                    cimd_manager=self.cimd_manager,
                    token_endpoint_url=token_endpoint_url,
                )
                handler = TokenHandler(provider=self, client_authenticator=authenticator)
                patched.append(
                    Route(
                        path="/token",
                        # Same layering as the SDK's own /token route (CORS ->
                        # body limit -> handler), plus the Basic client_id shim.
                        endpoint=CORSMiddleware(
                            app=RequestBodyLimitMiddleware(
                                _basic_client_id_shim(request_response(handler.handle)),
                                DEFAULT_MAX_REQUEST_BODY_SIZE,
                            ),
                            allow_origins="*",
                            allow_methods=["POST", "OPTIONS"],
                            allow_headers=[MCP_PROTOCOL_VERSION_HEADER],
                        ),
                        methods=["POST", "OPTIONS"],
                    )
                )
            elif isinstance(route, Route) and route.path.startswith(
                "/.well-known/oauth-authorization-server"
            ):
                metadata = build_metadata(
                    self.base_url,
                    self.service_documentation_url,
                    self.client_registration_options or ClientRegistrationOptions(),
                    self.revocation_options or RevocationOptions(),
                )
                metadata.client_id_metadata_document_supported = True
                existing = metadata.token_endpoint_auth_methods_supported or []
                methods = [
                    *existing,
                    *(m for m in ("private_key_jwt", "none") if m not in existing),
                ]
                metadata.token_endpoint_auth_methods_supported = methods
                if self.config.auth.scopes_supported:
                    metadata.scopes_supported = list(self.config.auth.scopes_supported)
                handler = MetadataHandler(metadata)
                patched.append(
                    Route(
                        path=route.path,
                        endpoint=cors_middleware(handler.handle, ["GET", "OPTIONS"]),
                        methods=route.methods or ["GET", "OPTIONS"],
                        name=route.name,
                        include_in_schema=route.include_in_schema,
                    )
                )
                # OIDC Discovery alias (RFC 8414 §5): some clients probe
                # /.well-known/openid-configuration instead of the OAuth path.
                patched.append(
                    Route(
                        path="/.well-known/openid-configuration",
                        endpoint=cors_middleware(handler.handle, ["GET", "OPTIONS"]),
                        methods=["GET", "OPTIONS"],
                    )
                )
            else:
                patched.append(route)
        return patched
