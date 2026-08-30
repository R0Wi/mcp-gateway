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

import pytest
from mcp.shared.auth import OAuthClientInformationFull, OAuthClientMetadata, OAuthToken
from pydantic import AnyUrl

from mcp_gateway.storage import Storage
from mcp_gateway.upstream import DbTokenStorage, JsonTokenOAuthClientProvider

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


async def test_set_tokens_records_issued_at(storage):
    token_storage = DbTokenStorage(storage, "github")
    assert await token_storage.get_tokens_issued_at() is None

    before = time.time()
    await token_storage.set_tokens(OAuthToken.model_validate(GITHUB_APP_TOKEN_RESPONSE))
    after = time.time()

    issued_at = await token_storage.get_tokens_issued_at()
    assert issued_at is not None
    assert before <= issued_at <= after


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

    # Back-date issuance well past the 8h (28800s) expires_in, simulating the
    # gateway having been restarted long after the access token died.
    storage.save_upstream("github", "token_issued_at", {"issued_at": time.time() - 30000})

    provider = make_provider(storage)
    await provider._initialize()

    assert not provider.context.is_token_valid()
    # The refresh token GitHub issued is still good (6-month lifetime) and a
    # refresh should be attempted with it rather than going interactive.
    assert provider.context.can_refresh_token()


async def test_refresh_rotates_issued_at(storage):
    """GitHub rotates both the access and refresh token on every refresh
    ('once you use a refresh token, that refresh token and the old user
    access token will no longer work') -- confirm each `set_tokens` call
    (as used by the SDK's refresh handler) re-stamps issued_at so expiry
    tracking stays correct across rotations, not just the first grant."""
    token_storage = DbTokenStorage(storage, "github")
    await token_storage.set_tokens(OAuthToken.model_validate(GITHUB_APP_TOKEN_RESPONSE))
    first_issued_at = await token_storage.get_tokens_issued_at()

    rotated = dict(GITHUB_APP_TOKEN_RESPONSE)
    rotated["access_token"] = "gho_rotatedNewAccessToken"
    rotated["refresh_token"] = "ghr_rotatedNewRefreshToken"
    await token_storage.set_tokens(OAuthToken.model_validate(rotated))
    second_issued_at = await token_storage.get_tokens_issued_at()

    assert second_issued_at is not None and second_issued_at >= first_issued_at
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

    # issued_at is still recorded (harmless / for consistency)...
    assert await token_storage.get_tokens_issued_at() is not None

    provider = make_provider(storage)
    await provider._initialize()

    # ...but since there's no expires_in, no absolute expiry is synthesized:
    # the token is treated as valid forever, matching GitHub's own semantics.
    assert provider.context.token_expiry_time is None
    assert provider.context.is_token_valid()
    assert not provider.context.can_refresh_token()
