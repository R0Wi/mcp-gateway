"""Absolute-expiry reconstruction across process restarts (see
JsonTokenOAuthClientProvider._initialize).

`OAuthContext.token_expiry_time` -- the timestamp the MCP SDK's
`is_token_valid()` actually checks -- lives in memory only and defaults to
`None` on a fresh `OAuthClientProvider` (i.e. after every gateway restart).
`is_token_valid()` treats `None` as "no known expiry -- still valid", so
without reconstructing it, a genuinely expired access token gets sent as-is
after a restart, the upstream returns 401, and the SDK's 401 handler goes
straight to a full *interactive* re-authorization instead of trying the
refresh token -- even though a perfectly good refresh token is in storage.

`DbTokenStorage` persists the absolute expiry (`expires_at`) inside the
token row itself and hands back an `expires_in` decayed to the token's
remaining lifetime on every read; `_initialize` then just feeds that through
the SDK's own `update_token_expiry` helper.

These tests exercise both real-world GitHub token shapes (see
https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/refreshing-user-access-tokens
and
https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps):

- a GitHub App user access token: expiring, with a refresh token
- a classic GitHub OAuth App token: non-expiring, no refresh token at all

The gateway must work with either.
"""

from __future__ import annotations

import time

import httpx2
import pytest
from mcp.shared.auth import (
    OAuthClientInformationFull,
    OAuthClientMetadata,
    OAuthMetadata,
    OAuthToken,
    ProtectedResourceMetadata,
)
from pydantic import AnyUrl

from mcp_gateway.config import GatewayConfig
from mcp_gateway.storage import Storage
from mcp_gateway.upstream import BackendManager, DbTokenStorage, JsonTokenOAuthClientProvider

# A GitHub App user-to-server token response (refreshing-user-access-tokens
# doc): expires in 8h, ships a refresh token good for ~6 months.
GITHUB_APP_TOKEN_RESPONSE = {
    "access_token": "gho_16C7e42F292c6912E7710c838347Ae178B4a",
    "expires_in": 28800,
    "refresh_token": "ghr_1B4a2e77838347a7E420ce178F2E7c6912E169246c34E1ccbF66C46812d16D5B1A9Dc86A1498",
    "refresh_token_expires_in": 15897600,
    "scope": "repo,gist",
    "token_type": "bearer",
}

# A classic GitHub OAuth App token response, no expiration configured on the
# app (authorizing-oauth-apps doc): no expires_in, no refresh_token at all.
GITHUB_OAUTH_APP_TOKEN_RESPONSE = {
    "access_token": "gho_16C7e42F292c6912E7710c838347Ae178B4a",
    "scope": "repo,gist",
    "token_type": "bearer",
}


def make_provider(storage: Storage, backend: str = "github") -> JsonTokenOAuthClientProvider:
    """A standalone OAuth provider wired to real storage, mirroring what
    BackendManager builds -- but constructed fresh each time, the way a new
    process would after a restart (BackendManager's own provider cache is
    per-process and doesn't survive one either)."""
    return JsonTokenOAuthClientProvider(
        server_url="https://api.githubcopilot.com/mcp/",
        client_metadata=OAuthClientMetadata(
            redirect_uris=[AnyUrl("http://localhost/oauth/callback")],
            grant_types=["authorization_code", "refresh_token"],
            response_types=["code"],
            token_endpoint_auth_method="none",
        ),
        storage=DbTokenStorage(storage, backend),
        redirect_handler=None,
        callback_handler=None,
    )


async def register_client_info(token_storage: DbTokenStorage) -> None:
    """`can_refresh_token()` requires client_info in addition to a stored
    refresh token (the refresh grant needs a client_id) -- set up as it would
    be after a real DCR/CIMD registration or static client_id config."""
    await token_storage.set_client_info(
        OAuthClientInformationFull(
            client_id="test-client-id",
            redirect_uris=[AnyUrl("http://localhost/oauth/callback")],
            grant_types=["authorization_code", "refresh_token"],
            response_types=["code"],
            token_endpoint_auth_method="none",
        )
    )


@pytest.fixture
def storage(tmp_path):
    s = Storage(tmp_path / "t.db", "test-passphrase")
    yield s
    s.close()


def backdate_expiry(storage: Storage, backend: str, expires_at: float) -> None:
    """Rewrite the stored token row's absolute expiry directly, simulating a
    token that (genuinely) expired while the gateway was down -- the way a
    real access token's clock would have run out, not something a test can
    get at through the public TokenStorage interface."""
    data = dict(storage.get_upstream(backend, "tokens"))
    data["expires_at"] = expires_at
    storage.save_upstream(backend, "tokens", data)


async def test_set_tokens_records_absolute_expiry(storage):
    token_storage = DbTokenStorage(storage, "github")

    before = time.time()
    await token_storage.set_tokens(OAuthToken.model_validate(GITHUB_APP_TOKEN_RESPONSE))
    after = time.time()

    raw = storage.get_upstream("github", "tokens")
    assert raw is not None
    expires_at = raw["expires_at"]
    assert before + GITHUB_APP_TOKEN_RESPONSE["expires_in"] <= expires_at
    assert expires_at <= after + GITHUB_APP_TOKEN_RESPONSE["expires_in"]


async def test_get_tokens_returns_decayed_expires_in(storage):
    """`expires_in` is relative to when it was received by definition, so a
    read a while after the write must return a smaller value than what was
    originally issued -- not the original 28800 replayed verbatim."""
    token_storage = DbTokenStorage(storage, "github")
    await token_storage.set_tokens(OAuthToken.model_validate(GITHUB_APP_TOKEN_RESPONSE))

    # Simulate time passing between the write and the read.
    backdate_expiry(storage, "github", time.time() + 100)

    tokens = await token_storage.get_tokens()
    assert tokens is not None
    assert 0 < tokens.expires_in <= 100


async def test_expiring_token_valid_immediately_after_restart(storage):
    """A fresh access token, reloaded by a brand-new provider (a stand-in for
    the process having just restarted), is recognized as still valid --
    instead of merely "unknown expiry, assume valid"."""
    token_storage = DbTokenStorage(storage, "github")
    await token_storage.set_tokens(OAuthToken.model_validate(GITHUB_APP_TOKEN_RESPONSE))

    provider = make_provider(storage)
    await provider._initialize()

    assert provider.context.current_tokens is not None
    assert provider.context.token_expiry_time is not None
    assert provider.context.is_token_valid()


async def test_expired_token_triggers_proactive_refresh_after_restart(storage):
    """The core bug: an access token that actually expired while the process
    was down must be recognized as expired on the next restart, so the SDK's
    *proactive* refresh path fires (using the still-valid refresh token)
    instead of sending a stale token, hitting a 401, and falling into the
    SDK's interactive-only re-authorization."""
    token_storage = DbTokenStorage(storage, "github")
    await token_storage.set_tokens(OAuthToken.model_validate(GITHUB_APP_TOKEN_RESPONSE))
    await register_client_info(token_storage)

    # Back-date the stored expiry well into the past, simulating the gateway
    # having been restarted long after the access token died.
    backdate_expiry(storage, "github", time.time() - 1000)

    provider = make_provider(storage)
    await provider._initialize()

    assert not provider.context.is_token_valid()
    # The refresh token GitHub issued is still good (6-month lifetime) and a
    # refresh should be attempted with it rather than going interactive.
    assert provider.context.can_refresh_token()


async def test_refresh_rotates_expiry(storage):
    """GitHub rotates both the access and refresh token on every refresh
    ('once you use a refresh token, that refresh token and the old user
    access token will no longer work') -- confirm each `set_tokens` call (as
    used by the SDK's refresh handler) re-stamps `expires_at` so expiry
    tracking stays correct across rotations, not just the first grant."""
    token_storage = DbTokenStorage(storage, "github")
    await token_storage.set_tokens(OAuthToken.model_validate(GITHUB_APP_TOKEN_RESPONSE))
    first_expires_at = storage.get_upstream("github", "tokens")["expires_at"]

    rotated = dict(GITHUB_APP_TOKEN_RESPONSE)
    rotated["access_token"] = "gho_rotatedNewAccessToken"
    rotated["refresh_token"] = "ghr_rotatedNewRefreshToken"
    await token_storage.set_tokens(OAuthToken.model_validate(rotated))
    second_expires_at = storage.get_upstream("github", "tokens")["expires_at"]

    assert second_expires_at >= first_expires_at
    tokens = await token_storage.get_tokens()
    assert tokens.access_token == "gho_rotatedNewAccessToken"
    assert tokens.refresh_token == "ghr_rotatedNewRefreshToken"


async def test_non_expiring_classic_oauth_app_token_has_no_expiry(storage):
    """A classic GitHub OAuth App with no expiration configured returns a
    token with neither `expires_in` nor `refresh_token`. The gateway must
    keep working with it indefinitely -- no expiry should be synthesized,
    and no refresh should ever be attempted."""
    token_storage = DbTokenStorage(storage, "github")
    await token_storage.set_tokens(OAuthToken.model_validate(GITHUB_OAUTH_APP_TOKEN_RESPONSE))

    # No expires_in on the token, so no absolute expiry is recorded at all.
    assert "expires_at" not in storage.get_upstream("github", "tokens")

    provider = make_provider(storage)
    await provider._initialize()

    # ...and since there's no expires_in, no absolute expiry is synthesized:
    # the token is treated as valid forever, matching GitHub's own semantics.
    assert provider.context.token_expiry_time is None
    assert provider.context.is_token_valid()
    assert not provider.context.can_refresh_token()


# --- persisted OAuth metadata (wrong-URL refresh after restart) -------------

GITHUB_TOKEN_ENDPOINT = "https://github.com/login/oauth/access_token"


def github_metadata() -> OAuthMetadata:
    return OAuthMetadata(
        issuer="https://github.com/login/oauth",
        authorization_endpoint="https://github.com/login/oauth/authorize",
        token_endpoint=GITHUB_TOKEN_ENDPOINT,
    )


def set_discovered_metadata(provider: JsonTokenOAuthClientProvider) -> None:
    provider.context.oauth_metadata = github_metadata()
    provider.context.auth_server_url = "https://github.com/login/oauth"
    provider.context.protected_resource_metadata = ProtectedResourceMetadata(
        resource="https://api.githubcopilot.com/mcp/",
        authorization_servers=[AnyUrl("https://github.com/login/oauth")],
    )


def json_response(body: dict) -> httpx2.Response:
    return httpx2.Response(200, json=body)


async def test_token_response_persists_auth_metadata(storage):
    provider = make_provider(storage)
    await provider._initialize()
    set_discovered_metadata(provider)

    await provider._handle_token_response(json_response(GITHUB_APP_TOKEN_RESPONSE))

    stored = storage.get_upstream("github", "auth_metadata")
    assert stored["oauth_metadata"]["token_endpoint"] == GITHUB_TOKEN_ENDPOINT
    assert stored["auth_server_url"] == "https://github.com/login/oauth"
    assert stored["protected_resource_metadata"]["resource"] == "https://api.githubcopilot.com/mcp/"


async def test_refresh_response_persists_auth_metadata(storage):
    token_storage = DbTokenStorage(storage, "github")
    await token_storage.set_tokens(OAuthToken.model_validate(GITHUB_APP_TOKEN_RESPONSE))
    provider = make_provider(storage)
    await provider._initialize()
    set_discovered_metadata(provider)

    assert await provider._handle_refresh_response(json_response(GITHUB_APP_TOKEN_RESPONSE)) is True
    stored = storage.get_upstream("github", "auth_metadata")
    assert stored["oauth_metadata"]["token_endpoint"] == GITHUB_TOKEN_ENDPOINT


async def test_failed_refresh_does_not_persist_metadata(storage):
    provider = make_provider(storage)
    await provider._initialize()
    set_discovered_metadata(provider)

    assert await provider._handle_refresh_response(httpx2.Response(404)) is False
    assert storage.get_upstream("github", "auth_metadata") is None


async def test_refresh_after_restart_uses_stored_token_endpoint(storage):
    """Regression: after a restart the proactive refresh used to go to
    <server origin>/token (https://api.githubcopilot.com/token -> 404)."""
    first = make_provider(storage)
    await first._initialize()
    set_discovered_metadata(first)
    await first._handle_token_response(json_response(GITHUB_APP_TOKEN_RESPONSE))
    await register_client_info(first.context.storage)
    backdate_expiry(storage, "github", time.time() - 1000)

    restarted = make_provider(storage)
    await restarted._initialize()

    assert restarted.context.oauth_metadata is not None
    assert restarted.context.auth_server_url == "https://github.com/login/oauth"
    assert restarted.context.protected_resource_metadata is not None
    assert not restarted.context.is_token_valid()
    request = await restarted._refresh_token()
    assert str(request.url) == GITHUB_TOKEN_ENDPOINT
    assert str(request.url) != "https://api.githubcopilot.com/token"


@pytest.mark.parametrize(
    "stored",
    [
        {"oauth_metadata": {"nonsense": True}},
        {"oauth_metadata": github_metadata().model_dump(mode="json"), "auth_server_url": 5},
        {"oauth_metadata": github_metadata().model_dump(mode="json"),
         "protected_resource_metadata": {"bad": 1}},
        {"unexpected": "shape"},
    ],
)
async def test_invalid_stored_metadata_is_ignored(storage, stored):
    storage.save_upstream("github", "auth_metadata", stored)
    provider = make_provider(storage)
    await provider._initialize()
    assert provider.context.oauth_metadata is None
    assert provider.context.protected_resource_metadata is None
    assert provider.context.auth_server_url is None


async def test_disconnect_clears_stored_and_in_memory_metadata(storage):
    config = GatewayConfig.model_validate(
        {
            "server": {"public_url": "http://127.0.0.1:1", "port": 1},
            "auth": {"encryption_key": "test-passphrase", "users": []},
            "storage": {"path": ":memory:"},
            "backends": {
                "github": {
                    "url": "https://api.githubcopilot.com/mcp/",
                    "auth": {"type": "oauth", "client_id": "test-client-id"},
                }
            },
        }
    )
    manager = BackendManager(config, storage)
    provider = manager._build_oauth_provider("github", config.backends["github"])
    await provider._initialize()
    set_discovered_metadata(provider)
    await provider._handle_token_response(json_response(GITHUB_APP_TOKEN_RESPONSE))
    assert storage.get_upstream("github", "auth_metadata") is not None

    manager.disconnect("github")

    assert storage.get_upstream("github", "auth_metadata") is None
    assert provider.context.oauth_metadata is None
    assert provider.context.protected_resource_metadata is None
    assert provider.context.auth_server_url is None
