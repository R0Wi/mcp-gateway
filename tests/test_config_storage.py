"""Unit tests for config loading and encrypted storage."""

from __future__ import annotations

import sqlite3
import time

import pytest

from mcp_gateway.config import GatewayConfig, load_config
from mcp_gateway.storage import Storage
from mcp_gateway.users import SessionManager, verify_user


def test_load_config_with_env_expansion(tmp_path, monkeypatch):
    monkeypatch.setenv("TEST_KEY", "sekrit")
    path = tmp_path / "config.yaml"
    path.write_text(
        """
server:
  public_url: https://mcp.example.com/
auth:
  encryption_key: ${TEST_KEY}
  users:
    - username: admin
      password: ${MISSING_VAR:-fallback}
backends:
  github:
    url: https://api.githubcopilot.com/mcp/
    auth:
      type: oauth
"""
    )
    config = load_config(path)
    assert config.server.public_url == "https://mcp.example.com"  # trailing slash stripped
    assert config.auth.encryption_key == "sekrit"
    assert config.auth.users[0].password == "fallback"
    assert config.backends["github"].auth.type == "oauth"


def test_config_rejects_missing_env(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text(
        """
server:
  public_url: https://x.example
auth:
  encryption_key: ${DEFINITELY_NOT_SET_VAR}
  users: []
"""
    )
    with pytest.raises(ValueError, match="DEFINITELY_NOT_SET_VAR"):
        load_config(path)


def test_config_rejects_user_without_password():
    with pytest.raises(ValueError):
        GatewayConfig.model_validate(
            {
                "server": {"public_url": "https://x.example"},
                "auth": {"encryption_key": "k", "users": [{"username": "a"}]},
            }
        )


def test_config_rejects_bad_backend_name():
    with pytest.raises(ValueError, match="alphanumeric"):
        GatewayConfig.model_validate(
            {
                "server": {"public_url": "https://x.example"},
                "auth": {"encryption_key": "k", "users": [{"username": "a", "password": "p"}]},
                "backends": {"bad name!": {"url": "https://y.example/mcp"}},
            }
        )


def test_storage_encrypts_secrets_at_rest(tmp_path):
    db_path = tmp_path / "test.db"
    storage = Storage(db_path, "passphrase")
    storage.save_client("client-1", {"client_id": "client-1", "client_secret": "super-secret"})
    storage.save_upstream("github", "tokens", {"access_token": "gh-token-xyz"})

    raw = sqlite3.connect(db_path)
    blobs = raw.execute("SELECT data FROM oauth_clients").fetchall()
    blobs += raw.execute("SELECT value FROM upstream_data").fetchall()
    for (blob,) in blobs:
        text = blob.decode() if isinstance(blob, bytes) else str(blob)
        assert "super-secret" not in text
        assert "gh-token-xyz" not in text

    # Round-trips fine through the API.
    assert storage.get_client("client-1")["client_secret"] == "super-secret"
    assert storage.get_upstream("github", "tokens")["access_token"] == "gh-token-xyz"


def test_storage_tokens_stored_hashed(tmp_path):
    storage = Storage(tmp_path / "t.db", "k")
    storage.save_access_token(
        "the-plaintext-token",
        client_id="c",
        scopes=["mcp"],
        subject="admin",
        resource=None,
        expires_at=time.time() + 60,
    )
    raw = sqlite3.connect(tmp_path / "t.db")
    rows = raw.execute("SELECT token_hash FROM access_tokens").fetchall()
    assert rows and all("the-plaintext-token" not in row[0] for row in rows)
    assert storage.get_access_token("the-plaintext-token")["client_id"] == "c"
    assert storage.get_access_token("wrong-token") is None


def test_storage_expiry(tmp_path):
    storage = Storage(tmp_path / "t.db", "k")
    storage.save_access_token(
        "tok", client_id="c", scopes=[], subject=None, resource=None,
        expires_at=time.time() - 1,
    )
    assert storage.get_access_token("tok") is None


def test_verify_user_bcrypt():
    import bcrypt

    from mcp_gateway.config import AuthConfig

    digest = bcrypt.hashpw(b"hunter2", bcrypt.gensalt(rounds=4)).decode()
    auth = AuthConfig.model_validate(
        {
            "encryption_key": "k",
            "users": [{"username": "admin", "password_hash": digest}],
        }
    )
    assert verify_user(auth, "admin", "hunter2")
    assert not verify_user(auth, "admin", "wrong")
    assert not verify_user(auth, "other", "hunter2")


def test_session_roundtrip_and_tamper():
    storage = Storage(":memory:", "test-passphrase")
    sessions = SessionManager("secret", max_age_seconds=60, storage=storage)
    cookie = sessions.create("admin")
    assert sessions.validate(cookie) == "admin"
    assert sessions.validate(cookie + "x") is None
    assert sessions.validate(None) is None
    other = SessionManager("different-secret", max_age_seconds=60, storage=storage)
    assert other.validate(cookie) is None


def test_session_revoked_on_logout():
    storage = Storage(":memory:", "test-passphrase")
    sessions = SessionManager("secret", max_age_seconds=60, storage=storage)
    cookie = sessions.create("admin")
    assert sessions.validate(cookie) == "admin"

    sessions.revoke(cookie)
    assert sessions.validate(cookie) is None, "revoked session must stop validating immediately"

    # Revoking twice, or an unknown/garbage cookie, must not raise.
    sessions.revoke(cookie)
    sessions.revoke("not-a-real-cookie")
    sessions.revoke(None)


def test_session_revocation_is_per_session_not_per_user():
    storage = Storage(":memory:", "test-passphrase")
    sessions = SessionManager("secret", max_age_seconds=60, storage=storage)
    cookie_a = sessions.create("admin")
    cookie_b = sessions.create("admin")
    assert cookie_a != cookie_b, "each login should mint a distinct session"

    sessions.revoke(cookie_a)
    assert sessions.validate(cookie_a) is None
    assert sessions.validate(cookie_b) == "admin", "revoking one session must not affect another"
