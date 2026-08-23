"""Upstream (gateway -> backend MCP server) authentication and clients.

Supported backend auth methods:

- ``none``    – public servers (e.g. Microsoft Learn docs MCP)
- ``bearer``  – static token injected as ``Authorization: Bearer ...``
- ``headers`` – arbitrary static headers (API keys etc.)
- ``oauth``   – full OAuth 2.1 client per the MCP authorization spec, using
  the official SDK's ``OAuthClientProvider``: protected-resource/AS metadata
  discovery, CIMD (URL-based client ID hosted by the gateway) when the
  upstream AS advertises support, Dynamic Client Registration as fallback,
  PKCE, resource indicators, and automatic token refresh.

OAuth backends are connected interactively once: an admin opens
``/oauth/connect/<backend>`` in a browser (behind gateway login), gets
redirected to the upstream authorization server, and the callback lands on
``/oauth/callback``. Tokens are persisted encrypted in SQLite; afterwards the
flow is fully automatic (refresh included). MCP traffic never triggers an
interactive flow on its own.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from typing import Any
from urllib.parse import parse_qs, urlparse

from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport
from mcp.client.auth import OAuthClientProvider, TokenStorage
from mcp.shared.auth import OAuthClientInformationFull, OAuthClientMetadata, OAuthToken
from pydantic import AnyUrl

from mcp_gateway.config import BackendConfig, GatewayConfig
from mcp_gateway.storage import Storage

logger = logging.getLogger(__name__)

CONNECT_FLOW_TIMEOUT_SECONDS = 300

# Path (relative to the public URL) where the gateway hosts its own Client ID
# Metadata Document for CIMD-capable upstream authorization servers.
CLIENT_METADATA_PATH = "/oauth/client-metadata.json"
UPSTREAM_CALLBACK_PATH = "/oauth/callback"


class NotConnectedError(Exception):
    """OAuth backend has no stored tokens and no interactive flow is running."""


class JsonTokenOAuthClientProvider(OAuthClientProvider):
    """OAuthClientProvider that always asks token endpoints for a JSON response.

    Some authorization servers (notably GitHub's) reply to token requests with
    ``application/x-www-form-urlencoded`` unless the client explicitly sends
    ``Accept: application/json``. The SDK only ever parses JSON, so without
    this header those responses fail to parse even though the exchange itself
    succeeded (an ``access_token=...&token_type=bearer`` body, not an error).
    """

    async def _exchange_token_authorization_code(self, *args: Any, **kwargs: Any):
        request = await super()._exchange_token_authorization_code(*args, **kwargs)
        request.headers["accept"] = "application/json"
        return request

    async def _refresh_token(self, *args: Any, **kwargs: Any):
        request = await super()._refresh_token(*args, **kwargs)
        request.headers["accept"] = "application/json"
        return request


class DbTokenStorage(TokenStorage):
    """SDK TokenStorage backed by the gateway's encrypted SQLite store.

    When the backend has statically configured OAuth client credentials
    (``auth.client_id``, for upstream authorization servers that support
    neither CIMD nor Dynamic Client Registration, e.g. GitHub), those are
    returned as-is and never overwritten by a CIMD/DCR result.
    """

    def __init__(self, storage: Storage, backend: str, static_client_info: OAuthClientInformationFull | None = None):
        self._storage = storage
        self._backend = backend
        self._static_client_info = static_client_info

    async def get_tokens(self) -> OAuthToken | None:
        data = self._storage.get_upstream(self._backend, "tokens")
        return OAuthToken.model_validate(data) if data else None

    async def set_tokens(self, tokens: OAuthToken) -> None:
        self._storage.save_upstream(self._backend, "tokens", tokens.model_dump(mode="json"))

    async def get_client_info(self) -> OAuthClientInformationFull | None:
        if self._static_client_info is not None:
            return self._static_client_info
        data = self._storage.get_upstream(self._backend, "client_info")
        return OAuthClientInformationFull.model_validate(data) if data else None

    async def set_client_info(self, client_info: OAuthClientInformationFull) -> None:
        if self._static_client_info is not None:
            return
        self._storage.save_upstream(
            self._backend, "client_info", client_info.model_dump(mode="json")
        )


class ConnectFlow:
    """State for one interactive backend authorization flow."""

    def __init__(self, backend: str):
        self.backend = backend
        self.authorize_url: asyncio.Future[str] = asyncio.get_event_loop().create_future()
        self.callback: asyncio.Future[tuple[str, str | None]] = (
            asyncio.get_event_loop().create_future()
        )
        self.done: asyncio.Future[str | None] = asyncio.get_event_loop().create_future()
        self.state: str | None = None
        self.created_at = time.time()
        # The background task driving this flow (set once start_connect creates
        # it). Must be cancelled before abandoning the flow: the OAuthClientProvider
        # is cached per backend and its internal lock is held for the task's whole
        # lifetime, so an orphaned task blocks every later connect attempt on that
        # same lock until it naturally times out (up to CONNECT_FLOW_TIMEOUT_SECONDS).
        self.task: asyncio.Task[None] | None = None


class BackendManager:
    """Builds authenticated FastMCP clients for every configured backend and
    orchestrates interactive OAuth connect flows."""

    def __init__(self, config: GatewayConfig, storage: Storage):
        self.config = config
        self.storage = storage
        self._flows_by_backend: dict[str, ConnectFlow] = {}
        self._flows_by_state: dict[str, ConnectFlow] = {}
        self._oauth_providers: dict[str, OAuthClientProvider] = {}

    # ------------------------------------------------------------- client building

    def build_client(self, name: str, backend: BackendConfig) -> Client:
        # Lowercase header names so they take precedence in any case-sensitive
        # merge with per-request headers further down the stack.
        headers = {k.lower(): v for k, v in backend.headers.items()}
        auth: Any = None
        if backend.auth.type == "bearer":
            headers["authorization"] = f"Bearer {backend.auth.token}"
        elif backend.auth.type == "headers":
            headers.update({k.lower(): v for k, v in backend.auth.headers.items()})
        elif backend.auth.type == "oauth":
            auth = self._build_oauth_provider(name, backend)
        transport = StreamableHttpTransport(backend.url, headers=headers or None, auth=auth)
        return Client(transport)

    def _build_oauth_provider(self, name: str, backend: BackendConfig) -> OAuthClientProvider:
        if name in self._oauth_providers:
            return self._oauth_providers[name]

        public_url = self.config.server.public_url
        redirect_uri = f"{public_url}{UPSTREAM_CALLBACK_PATH}"
        scopes = " ".join(backend.auth.scopes) if backend.auth.scopes else None

        static_client_info: OAuthClientInformationFull | None = None
        if backend.auth.client_id:
            # Pre-registered client (e.g. a GitHub OAuth App): the upstream AS
            # supports neither CIMD nor DCR, so use these credentials directly
            # and skip registration entirely.
            static_client_info = OAuthClientInformationFull(
                client_id=backend.auth.client_id,
                client_secret=backend.auth.client_secret,
                redirect_uris=[AnyUrl(redirect_uri)],
                grant_types=["authorization_code", "refresh_token"],
                response_types=["code"],
                token_endpoint_auth_method=(
                    "client_secret_post" if backend.auth.client_secret else "none"
                ),
                scope=scopes,
            )

        client_metadata = OAuthClientMetadata(
            client_name="MCP Gateway",
            redirect_uris=[AnyUrl(redirect_uri)],
            grant_types=["authorization_code", "refresh_token"],
            response_types=["code"],
            token_endpoint_auth_method="none",
            scope=scopes,
        )

        # CIMD: use the gateway's own hosted client metadata document as the
        # client_id when the upstream AS advertises support for it. The SDK
        # falls back to Dynamic Client Registration automatically otherwise.
        client_metadata_url: str | None = None
        if (
            static_client_info is None
            and not backend.auth.prefer_dcr
            and public_url.startswith("https://")
        ):
            client_metadata_url = f"{public_url}{CLIENT_METADATA_PATH}"

        provider = JsonTokenOAuthClientProvider(
            server_url=backend.url,
            client_metadata=client_metadata,
            storage=DbTokenStorage(self.storage, name, static_client_info),
            redirect_handler=self._make_redirect_handler(name),
            callback_handler=self._make_callback_handler(name),
            timeout=CONNECT_FLOW_TIMEOUT_SECONDS,
            client_metadata_url=client_metadata_url,
        )
        self._oauth_providers[name] = provider
        return provider

    def client_metadata_document(self) -> dict[str, Any]:
        """The CIMD document the gateway hosts for upstream authorization servers."""
        public_url = self.config.server.public_url
        return {
            "client_id": f"{public_url}{CLIENT_METADATA_PATH}",
            "client_name": "MCP Gateway",
            "client_uri": public_url,
            "redirect_uris": [f"{public_url}{UPSTREAM_CALLBACK_PATH}"],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none",
        }

    # ------------------------------------------------------------- connect flow

    def _make_redirect_handler(self, backend: str):
        async def redirect_handler(authorization_url: str) -> None:
            flow = self._flows_by_backend.get(backend)
            if flow is None or flow.authorize_url.done():
                # OAuth flow triggered outside an interactive connect session
                # (e.g. plain MCP traffic hitting an unconnected backend).
                raise NotConnectedError(
                    f"Backend '{backend}' requires authorization. "
                    f"Open {self.config.server.public_url}/ui/backends to connect it."
                )
            state = parse_qs(urlparse(authorization_url).query).get("state", [None])[0]
            flow.state = state
            if state is not None:
                self._flows_by_state[state] = flow
            flow.authorize_url.set_result(authorization_url)

        return redirect_handler

    def _make_callback_handler(self, backend: str):
        async def callback_handler() -> tuple[str, str | None]:
            flow = self._flows_by_backend.get(backend)
            if flow is None:
                raise NotConnectedError(f"No active connect flow for backend '{backend}'")
            return await asyncio.wait_for(flow.callback, timeout=CONNECT_FLOW_TIMEOUT_SECONDS)

        return callback_handler

    async def start_connect(self, name: str, client: Client) -> str:
        """Start an interactive OAuth flow; returns the upstream authorization URL.

        Drives the SDK auth machinery by opening an MCP session in a background
        task: the 401 challenge triggers discovery, CIMD/DCR and the redirect
        handler, which hands the authorization URL back to this coroutine.
        """
        backend = self.config.backends.get(name)
        if backend is None or backend.auth.type != "oauth":
            raise ValueError(f"Backend '{name}' is not an OAuth backend")

        old_flow = self._flows_by_backend.pop(name, None)
        if old_flow is not None:
            if old_flow.state:
                self._flows_by_state.pop(old_flow.state, None)
            if old_flow.task is not None and not old_flow.task.done():
                # The old flow's background task holds this backend's OAuth
                # provider lock for its whole lifetime (up to
                # CONNECT_FLOW_TIMEOUT_SECONDS). Cancel and wait for it to
                # actually unwind before starting a new attempt, or the new
                # attempt would silently queue behind that lock and time out
                # without ever sending a request.
                old_flow.task.cancel()
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await old_flow.task

        flow = ConnectFlow(name)
        self._flows_by_backend[name] = flow

        async def drive() -> None:
            try:
                # Force a fresh authorization: an expired/invalid token would
                # otherwise be retried forever without user interaction.
                async with client:
                    await client.ping()
                flow.done.set_result(None)
            except Exception as exc:  # noqa: BLE001 - report to the waiting UI
                if not flow.done.done():
                    flow.done.set_result(f"{type(exc).__name__}: {exc}")
                if not flow.authorize_url.done():
                    flow.authorize_url.set_exception(
                        RuntimeError(f"Authorization failed: {exc}")
                    )

        flow.task = asyncio.create_task(drive())
        try:
            return await asyncio.wait_for(flow.authorize_url, timeout=60)
        except TimeoutError:
            flow.task.cancel()
            raise

    def deliver_callback(self, code: str, state: str | None) -> str | None:
        """Route an upstream authorization callback to the waiting flow.

        Returns the backend name the callback was delivered to, or None.
        """
        flow: ConnectFlow | None = None
        if state is not None:
            flow = self._flows_by_state.pop(state, None)
        if flow is None and len(self._flows_by_backend) == 1:
            # Some servers drop the state parameter; with a single active flow
            # the mapping is unambiguous.
            flow = next(iter(self._flows_by_backend.values()))
        if flow is None or flow.callback.done():
            return None
        flow.callback.set_result((code, state))
        return flow.backend

    async def wait_connect_result(self, name: str) -> str | None:
        """Wait for a running connect flow to finish; returns an error or None."""
        flow = self._flows_by_backend.get(name)
        if flow is None:
            return "No active connect flow"
        try:
            result = await asyncio.wait_for(flow.done, timeout=CONNECT_FLOW_TIMEOUT_SECONDS)
        except TimeoutError:
            result = "Timed out waiting for authorization"
            if flow.task is not None:
                flow.task.cancel()
        finally:
            self._flows_by_backend.pop(name, None)
            if flow.state:
                self._flows_by_state.pop(flow.state, None)
        return result

    def disconnect(self, name: str) -> None:
        """Drop stored upstream credentials for a backend."""
        self.storage.delete_upstream(name)
        provider = self._oauth_providers.get(name)
        if provider is not None:
            provider.context.clear_tokens()
            provider.context.client_info = None
            provider._initialized = False

    # ------------------------------------------------------------- status

    def backend_status(self) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for name, backend in self.config.backends.items():
            entry: dict[str, Any] = {
                "name": name,
                "url": backend.url,
                "enabled": backend.enabled,
                "auth_type": backend.auth.type,
            }
            if backend.auth.type == "oauth":
                tokens = self.storage.get_upstream(name, "tokens")
                client_info = self.storage.get_upstream(name, "client_info")
                entry["connected"] = tokens is not None
                entry["has_refresh_token"] = bool(tokens and tokens.get("refresh_token"))
                if backend.auth.client_id:
                    entry["registration"] = "static"
                elif client_info and str(client_info.get("client_id", "")).startswith("https://"):
                    entry["registration"] = "cimd"
                elif client_info:
                    entry["registration"] = "dcr"
                else:
                    entry["registration"] = None
            else:
                entry["connected"] = True
            out.append(entry)
        return out
