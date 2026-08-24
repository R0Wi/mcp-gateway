"""Tests for encryption key handling: file-based key supply, envelope
encryption (DEK wrapped by a KEK), migration of pre-envelope databases, loud
failure on a key mismatch, and the `rotate-key` CLI command.
"""

from __future__ import annotations

import os
import sqlite3
import time

import pytest
from cryptography.fernet import InvalidToken

from mcp_gateway import cli
from mcp_gateway.config import load_config
from mcp_gateway.storage import EncryptionKeyError, Storage

_CONFIG_WITH_OPTIONAL_ENV_KEY = """
server:
  public_url: https://mcp.example.com
auth:
  encryption_key: ${MCP_GATEWAY_ENCRYPTION_KEY:-}
  users:
    - username: admin
      password: hunter2
"""


def test_encryption_key_file_takes_precedence(tmp_path, monkeypatch):
    key_file = tmp_path / "key.txt"
    key_file.write_text("from-the-file\n")  # trailing newline must be stripped
    monkeypatch.setenv("MCP_GATEWAY_ENCRYPTION_KEY", "from-the-env-var")
    monkeypatch.setenv("MCP_GATEWAY_ENCRYPTION_KEY_FILE", str(key_file))

    config_path = tmp_path / "config.yaml"
    config_path.write_text(_CONFIG_WITH_OPTIONAL_ENV_KEY)
    config = load_config(config_path)
    assert config.auth.encryption_key == "from-the-file"


def test_encryption_key_file_alone_is_enough(tmp_path, monkeypatch):
    """No MCP_GATEWAY_ENCRYPTION_KEY needs to be set at all when the _FILE
    variant is used -- and the key must never be copied into this process's
    own environment along the way (readable via /proc/<pid>/environ by
    anything sharing our UID, swept up by crash/APM "environment" capture,
    inherited by every child process -- see _read_encryption_key_file)."""
    monkeypatch.delenv("MCP_GATEWAY_ENCRYPTION_KEY", raising=False)
    key_file = tmp_path / "key.txt"
    key_file.write_text("only-in-the-file")
    monkeypatch.setenv("MCP_GATEWAY_ENCRYPTION_KEY_FILE", str(key_file))

    config_path = tmp_path / "config.yaml"
    config_path.write_text(_CONFIG_WITH_OPTIONAL_ENV_KEY)
    config = load_config(config_path)

    assert config.auth.encryption_key == "only-in-the-file"
    assert "MCP_GATEWAY_ENCRYPTION_KEY" not in os.environ


def test_encryption_key_file_missing_raises(tmp_path, monkeypatch):
    monkeypatch.setenv("MCP_GATEWAY_ENCRYPTION_KEY_FILE", str(tmp_path / "nope.txt"))
    config_path = tmp_path / "config.yaml"
    config_path.write_text(_CONFIG_WITH_OPTIONAL_ENV_KEY)
    with pytest.raises(ValueError, match="MCP_GATEWAY_ENCRYPTION_KEY_FILE"):
        load_config(config_path)


def test_no_key_at_all_raises_a_clear_error(tmp_path, monkeypatch):
    monkeypatch.delenv("MCP_GATEWAY_ENCRYPTION_KEY", raising=False)
    monkeypatch.delenv("MCP_GATEWAY_ENCRYPTION_KEY_FILE", raising=False)
    config_path = tmp_path / "config.yaml"
    config_path.write_text(_CONFIG_WITH_OPTIONAL_ENV_KEY)
    with pytest.raises(ValueError, match="encryption_key"):
        load_config(config_path)


def test_data_is_encrypted_under_a_random_dek_not_the_kek(tmp_path):
    """The DEK, not `encryption_key` itself, must actually decrypt rows --
    otherwise this isn't envelope encryption, it's the old direct scheme."""
    db_path = tmp_path / "t.db"
    storage = Storage(db_path, "the-operator-key")
    storage.save_client("c1", {"secret": "s"})

    raw = sqlite3.connect(db_path)
    (wrapped_dek,) = raw.execute("SELECT value FROM meta WHERE key='dek_wrapped'").fetchone()
    assert wrapped_dek  # a DEK was generated and persisted, wrapped by the KEK

    (blob,) = raw.execute("SELECT data FROM oauth_clients WHERE client_id='c1'").fetchone()
    kek_fernet = storage._kek_fernet("the-operator-key")
    with pytest.raises(InvalidToken):
        kek_fernet.decrypt(blob)  # the row is under the DEK, not the KEK, directly


def test_wrong_key_raises_encryption_key_error(tmp_path):
    db_path = tmp_path / "t.db"
    Storage(db_path, "right-key").close()
    with pytest.raises(EncryptionKeyError):
        Storage(db_path, "wrong-key")


def test_legacy_pre_envelope_database_is_migrated(tmp_path):
    """A database created by the old scheme (rows encrypted directly under
    the KEK, no `dek_wrapped` meta row) must not be orphaned by upgrading:
    existing rows should still decrypt correctly afterwards."""
    db_path = tmp_path / "legacy.db"
    key = "legacy-passphrase"

    # Create the schema (and the salt used below) via a normal Storage, then
    # simulate the pre-envelope-encryption layout by hand: a client row
    # encrypted directly with the KEK, and no `dek_wrapped` meta row.
    storage = Storage(db_path, key)
    kek_fernet = storage._kek_fernet(key)
    storage.close()

    raw = sqlite3.connect(db_path)
    raw.execute(
        "INSERT INTO oauth_clients(client_id, data, is_cimd, created_at) VALUES(?,?,?,?)",
        (
            "legacy-client",
            kek_fernet.encrypt(b'{"client_secret": "legacy-secret"}'),
            0,
            time.time(),
        ),
    )
    raw.execute("DELETE FROM meta WHERE key='dek_wrapped'")
    raw.commit()
    raw.close()

    # Reopening with the same key should migrate the legacy row onto a fresh
    # DEK transparently.
    storage2 = Storage(db_path, key)
    assert storage2.get_client("legacy-client")["client_secret"] == "legacy-secret"

    raw2 = sqlite3.connect(db_path)
    (wrapped_dek,) = raw2.execute("SELECT value FROM meta WHERE key='dek_wrapped'").fetchone()
    assert wrapped_dek
    (migrated_blob,) = raw2.execute(
        "SELECT data FROM oauth_clients WHERE client_id='legacy-client'"
    ).fetchone()
    with pytest.raises(InvalidToken):
        kek_fernet.decrypt(migrated_blob)  # no longer decryptable directly under the KEK
    storage2.close()


def test_pre_last_used_at_database_gets_column_added(tmp_path):
    """A database created before `last_used_at` (and `mark_client_used` /
    the unused-client purge) existed must not crash on reopen: the column
    needs to be added to the existing `oauth_clients` table, since
    `CREATE TABLE IF NOT EXISTS` does not retroactively add columns."""
    db_path = tmp_path / "old.db"

    # Build the old schema by hand: an `oauth_clients` table with no
    # `last_used_at` column, as it looked before that column was added.
    raw = sqlite3.connect(db_path)
    raw.executescript(
        """
        CREATE TABLE oauth_clients (
            client_id TEXT PRIMARY KEY,
            data BLOB NOT NULL,
            is_cimd INTEGER NOT NULL DEFAULT 0,
            created_at REAL NOT NULL
        );
        """
    )
    raw.execute(
        "INSERT INTO oauth_clients(client_id, data, is_cimd, created_at) VALUES(?,?,?,?)",
        ("old-client", b"irrelevant-for-this-test", 0, time.time()),
    )
    raw.commit()
    raw.close()

    storage = Storage(db_path, "some-key")
    try:
        # Column must exist now, and both the write path (mark_client_used)
        # and the read path (purge_expired) must work against it.
        storage.mark_client_used("old-client")
        storage.purge_expired()
    finally:
        storage.close()

    raw2 = sqlite3.connect(db_path)
    columns = {row[1] for row in raw2.execute("PRAGMA table_info(oauth_clients)")}
    assert "last_used_at" in columns
    (last_used_at,) = raw2.execute(
        "SELECT last_used_at FROM oauth_clients WHERE client_id='old-client'"
    ).fetchone()
    assert last_used_at is not None
    raw2.close()


def test_rotate_key_reencrypts_dek_not_rows(tmp_path):
    db_path = tmp_path / "t.db"
    storage = Storage(db_path, "old-key")
    storage.save_client("c1", {"secret": "s1"})
    raw = sqlite3.connect(db_path)
    (before,) = raw.execute("SELECT data FROM oauth_clients WHERE client_id='c1'").fetchone()
    storage.close()

    Storage.rotate_key(db_path, "old-key", "new-key")

    raw2 = sqlite3.connect(db_path)
    (after,) = raw2.execute("SELECT data FROM oauth_clients WHERE client_id='c1'").fetchone()
    assert after == before  # the row itself is untouched; only the wrapped DEK changed

    # Data is readable under the new key, not the old one.
    storage_new = Storage(db_path, "new-key")
    assert storage_new.get_client("c1")["secret"] == "s1"
    storage_new.close()
    with pytest.raises(EncryptionKeyError):
        Storage(db_path, "old-key")


def test_rotate_key_wrong_old_key_raises(tmp_path):
    db_path = tmp_path / "t.db"
    Storage(db_path, "real-key").close()
    with pytest.raises(EncryptionKeyError):
        Storage.rotate_key(db_path, "not-the-real-key", "new-key")


def test_cli_rotate_key_end_to_end(tmp_path, monkeypatch):
    db_path = tmp_path / "gateway.db"
    Storage(db_path, "old-key").close()

    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        f"""
server:
  public_url: https://mcp.example.com
auth:
  encryption_key: unused-for-rotate-key
  users:
    - username: admin
      password: hunter2
storage:
  path: {db_path}
"""
    )
    old_key_file = tmp_path / "old.key"
    new_key_file = tmp_path / "new.key"
    old_key_file.write_text("old-key\n")
    new_key_file.write_text("new-key\n")

    rc = cli.main(
        [
            "rotate-key",
            "-c",
            str(config_path),
            "--old-key-file",
            str(old_key_file),
            "--new-key-file",
            str(new_key_file),
        ]
    )
    assert rc == 0

    storage = Storage(db_path, "new-key")
    storage.close()
    with pytest.raises(EncryptionKeyError):
        Storage(db_path, "old-key")


def test_cli_rotate_key_wrong_old_key(tmp_path, capsys):
    db_path = tmp_path / "gateway.db"
    Storage(db_path, "real-key").close()

    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        f"""
server:
  public_url: https://mcp.example.com
auth:
  encryption_key: unused-for-rotate-key
  users:
    - username: admin
      password: hunter2
storage:
  path: {db_path}
"""
    )
    old_key_file = tmp_path / "old.key"
    new_key_file = tmp_path / "new.key"
    old_key_file.write_text("wrong-key")
    new_key_file.write_text("new-key")

    rc = cli.main(
        [
            "rotate-key",
            "-c",
            str(config_path),
            "--old-key-file",
            str(old_key_file),
            "--new-key-file",
            str(new_key_file),
        ]
    )
    assert rc == 1
    assert "does not match" in capsys.readouterr().err
