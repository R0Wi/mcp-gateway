"""Tests for the Alembic-based schema migrations (mcp_gateway.db_migrations).

`test_key_management.py::test_pre_last_used_at_database_gets_column_added`
covers the concrete bug this replaced (a pre-existing database missing a
later-added column); these tests cover the migration machinery itself.
"""

from __future__ import annotations

import sqlite3

from mcp_gateway import cli
from mcp_gateway.db_migrations import run_migrations, run_migrations_for_path
from mcp_gateway.storage import Storage

_EXPECTED_TABLES = {
    "meta",
    "oauth_clients",
    "auth_codes",
    "access_tokens",
    "refresh_tokens",
    "auth_txns",
    "upstream_data",
    "revoked_sessions",
    "alembic_version",
}


def _tables(conn: sqlite3.Connection) -> set[str]:
    rows = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
    return {row[0] for row in rows}


def test_fresh_database_gets_full_schema_and_head_revision(tmp_path):
    db_path = tmp_path / "fresh.db"
    conn = sqlite3.connect(db_path)
    try:
        run_migrations(conn)
        assert _EXPECTED_TABLES <= _tables(conn)
        (head,) = conn.execute("SELECT version_num FROM alembic_version").fetchone()
        assert head == "0002"
    finally:
        conn.close()


def test_migrations_are_idempotent(tmp_path):
    """Running the migration chain twice against the same database (e.g. a
    server restart, or `mcp-gateway migrate` followed by `mcp-gateway run`)
    must not error or change anything the second time."""
    db_path = tmp_path / "twice.db"
    conn = sqlite3.connect(db_path)
    try:
        run_migrations(conn)
        run_migrations(conn)
        assert _EXPECTED_TABLES <= _tables(conn)
    finally:
        conn.close()


def test_run_migrations_works_against_in_memory_database():
    """`:memory:` only exists for the lifetime of one connection, so this
    only passes if migrations run against the caller's own connection
    rather than a fresh one opened from a path -- see migrations/env.py."""
    conn = sqlite3.connect(":memory:")
    try:
        run_migrations(conn)
        assert _EXPECTED_TABLES <= _tables(conn)
        # the connection must still be open and usable afterwards
        conn.execute("INSERT INTO meta(key, value) VALUES ('k', 'v')")
        conn.commit()
        assert conn.execute("SELECT value FROM meta WHERE key='k'").fetchone() == ("v",)
    finally:
        conn.close()


def test_storage_init_applies_migrations(tmp_path):
    db_path = tmp_path / "via_storage.db"
    storage = Storage(db_path, "some-key")
    storage.close()

    conn = sqlite3.connect(db_path)
    try:
        assert _EXPECTED_TABLES <= _tables(conn)
    finally:
        conn.close()


def test_run_migrations_for_path_creates_parent_dirs(tmp_path):
    db_path = tmp_path / "nested" / "dir" / "gateway.db"
    run_migrations_for_path(db_path)
    assert db_path.exists()

    conn = sqlite3.connect(db_path)
    try:
        assert _EXPECTED_TABLES <= _tables(conn)
    finally:
        conn.close()


def test_cli_migrate_end_to_end(tmp_path, capsys):
    db_path = tmp_path / "gateway.db"
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        f"""
server:
  public_url: https://mcp.example.com
auth:
  encryption_key: unused-for-migrate
  users:
    - username: admin
      password: hunter2
storage:
  path: {db_path}
"""
    )

    rc = cli.main(["migrate", "-c", str(config_path)])
    assert rc == 0
    assert "up to date" in capsys.readouterr().out

    conn = sqlite3.connect(db_path)
    try:
        assert _EXPECTED_TABLES <= _tables(conn)
    finally:
        conn.close()

    # Running it again (e.g. before every `mcp-gateway run`, or a second
    # deploy) must be a no-op, not an error.
    rc = cli.main(["migrate", "-c", str(config_path)])
    assert rc == 0


def test_pre_alembic_database_is_picked_up_without_a_stamp_step(tmp_path):
    """A database from before this project used Alembic at all (no
    `alembic_version` table, but the full old schema already applied by
    hand) must migrate cleanly to head -- not fail because the "create"
    migration's tables already exist."""
    db_path = tmp_path / "legacy.db"
    conn = sqlite3.connect(db_path)
    conn.executescript(
        """
        CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE oauth_clients (
            client_id TEXT PRIMARY KEY,
            data BLOB NOT NULL,
            is_cimd INTEGER NOT NULL DEFAULT 0,
            created_at REAL NOT NULL
        );
        CREATE TABLE auth_codes (
            code_hash TEXT PRIMARY KEY, data TEXT NOT NULL, expires_at REAL NOT NULL
        );
        CREATE TABLE access_tokens (
            token_hash TEXT PRIMARY KEY, client_id TEXT NOT NULL, scopes TEXT NOT NULL,
            subject TEXT, resource TEXT, expires_at REAL NOT NULL
        );
        CREATE TABLE refresh_tokens (
            token_hash TEXT PRIMARY KEY, client_id TEXT NOT NULL, scopes TEXT NOT NULL,
            subject TEXT, resource TEXT, expires_at REAL NOT NULL,
            revoked INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE auth_txns (
            txn_id TEXT PRIMARY KEY, data TEXT NOT NULL, expires_at REAL NOT NULL
        );
        CREATE TABLE upstream_data (
            backend TEXT NOT NULL, key TEXT NOT NULL, value BLOB NOT NULL,
            updated_at REAL NOT NULL, PRIMARY KEY (backend, key)
        );
        """
    )
    conn.commit()
    conn.close()

    conn = sqlite3.connect(db_path)
    try:
        run_migrations(conn)
        assert _EXPECTED_TABLES <= _tables(conn)
        columns = {c[1] for c in conn.execute("PRAGMA table_info(oauth_clients)")}
        assert "last_used_at" in columns
    finally:
        conn.close()
