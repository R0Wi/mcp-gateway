"""SQLite persistence for the gateway.

Secrets are protected at rest:
- OAuth client records and upstream credentials are encrypted with Fernet.
- Access/refresh tokens and authorization codes are stored as SHA-256 hashes;
  the plaintext token never touches the database.

The database is small and access is low-frequency (a personal gateway), so a
single serialized SQLite connection is sufficient.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import secrets
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet, InvalidToken

logger = logging.getLogger(__name__)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS oauth_clients (
    client_id TEXT PRIMARY KEY,
    data BLOB NOT NULL,          -- Fernet-encrypted JSON client record
    is_cimd INTEGER NOT NULL DEFAULT 0,
    created_at REAL NOT NULL,
    last_used_at REAL            -- set when a client completes an authorization
);
CREATE TABLE IF NOT EXISTS auth_codes (
    code_hash TEXT PRIMARY KEY,
    data TEXT NOT NULL,          -- JSON AuthorizationCode payload (no secrets)
    expires_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS access_tokens (
    token_hash TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    scopes TEXT NOT NULL,
    subject TEXT,
    resource TEXT,
    expires_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS refresh_tokens (
    token_hash TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    scopes TEXT NOT NULL,
    subject TEXT,
    resource TEXT,
    expires_at REAL NOT NULL,
    revoked INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS auth_txns (
    txn_id TEXT PRIMARY KEY,
    data TEXT NOT NULL,          -- JSON transaction state
    expires_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS upstream_data (
    backend TEXT NOT NULL,
    key TEXT NOT NULL,           -- 'tokens' | 'client_info'
    value BLOB NOT NULL,         -- Fernet-encrypted JSON
    updated_at REAL NOT NULL,
    PRIMARY KEY (backend, key)
);
CREATE TABLE IF NOT EXISTS revoked_sessions (
    session_id TEXT PRIMARY KEY,
    expires_at REAL NOT NULL     -- the session's own natural expiry; safe to forget after
);
"""

# Anonymous DCR-registered clients that never complete an authorization are
# reclaimed after this long, bounding storage growth from unauthenticated
# /register spam. Clients that *have* authorized (last_used_at is set) are
# never purged by age.
UNUSED_CLIENT_TTL_SECONDS = 24 * 60 * 60


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _derive_fernet_key(secret: str, salt: bytes) -> bytes:
    """Turn an arbitrary passphrase into a Fernet key via scrypt.

    n=2**17 follows current OWASP guidance for password-derived keys; this
    only runs once per process for a passphrase-style (non-Fernet-format)
    encryption_key, so the extra cost is a one-off startup delay. scrypt's
    working set is 128*N*r bytes (~128 MiB at these parameters); OpenSSL's
    default 32 MiB cap would reject that, so raise maxmem accordingly.
    """
    key = hashlib.scrypt(
        secret.encode(), salt=salt, n=2**17, r=8, p=1, dklen=32, maxmem=256 * 1024 * 1024
    )
    return base64.urlsafe_b64encode(key)


class Storage:
    def __init__(self, path: str | Path, encryption_key: str):
        db_path = Path(path)
        if str(db_path) != ":memory:":
            db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self._conn.executescript(_SCHEMA)
        self._conn.commit()
        self._lock = threading.RLock()
        self._fernet = self._init_fernet(encryption_key)

    def _init_fernet(self, encryption_key: str) -> Fernet:
        # Accept a proper Fernet key directly; otherwise treat the value as a
        # passphrase and stretch it with a per-database random salt.
        try:
            return Fernet(encryption_key.encode())
        except (ValueError, TypeError):
            pass
        salt_hex = self._meta_get("kdf_salt")
        if salt_hex is None:
            salt_hex = secrets.token_hex(16)
            self._meta_set("kdf_salt", salt_hex)
        return Fernet(_derive_fernet_key(encryption_key, bytes.fromhex(salt_hex)))

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # -- meta ---------------------------------------------------------------

    def _meta_get(self, key: str) -> str | None:
        with self._lock:
            row = self._conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return row[0] if row else None

    def _meta_set(self, key: str, value: str) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO meta(key,value) VALUES(?,?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, value),
            )
            self._conn.commit()

    def get_or_create_secret(self, name: str, nbytes: int = 32) -> str:
        """Stable random secret persisted (encrypted) in the database."""
        existing = self._meta_get(name)
        if existing is not None:
            try:
                return self._fernet.decrypt(existing.encode()).decode()
            except InvalidToken:
                pass  # encryption key changed; regenerate
        value = secrets.token_urlsafe(nbytes)
        self._meta_set(name, self._fernet.encrypt(value.encode()).decode())
        return value

    # -- encryption helpers ---------------------------------------------------

    def _encrypt_json(self, obj: Any) -> bytes:
        return self._fernet.encrypt(json.dumps(obj).encode())

    def _decrypt_json(self, blob: bytes) -> Any:
        return json.loads(self._fernet.decrypt(blob))

    # -- OAuth clients --------------------------------------------------------

    def save_client(self, client_id: str, record: dict[str, Any], is_cimd: bool = False) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO oauth_clients(client_id, data, is_cimd, created_at) VALUES(?,?,?,?) "
                "ON CONFLICT(client_id) DO UPDATE SET data=excluded.data, is_cimd=excluded.is_cimd",
                (client_id, self._encrypt_json(record), int(is_cimd), time.time()),
            )
            self._conn.commit()

    def get_client(self, client_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT data FROM oauth_clients WHERE client_id=?", (client_id,)
            ).fetchone()
        if row is None:
            return None
        try:
            return self._decrypt_json(row[0])
        except InvalidToken:
            return None  # encryption key changed; treat as unknown client

    def mark_client_used(self, client_id: str) -> None:
        """Record that a client completed an authorization (exempts it from
        the unused-client TTL in :meth:`purge_expired`)."""
        with self._lock:
            self._conn.execute(
                "UPDATE oauth_clients SET last_used_at=? WHERE client_id=?",
                (time.time(), client_id),
            )
            self._conn.commit()

    # -- authorization transactions (pending login/consent) --------------------

    def save_txn(self, txn_id: str, data: dict[str, Any], ttl_seconds: int) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO auth_txns(txn_id, data, expires_at) VALUES(?,?,?)",
                (txn_id, json.dumps(data), time.time() + ttl_seconds),
            )
            self._conn.commit()

    def get_txn(self, txn_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT data, expires_at FROM auth_txns WHERE txn_id=?", (txn_id,)
            ).fetchone()
        if row is None or row[1] < time.time():
            return None
        return json.loads(row[0])

    def delete_txn(self, txn_id: str) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM auth_txns WHERE txn_id=?", (txn_id,))
            self._conn.commit()

    # -- authorization codes ----------------------------------------------------

    def save_auth_code(self, code: str, data: dict[str, Any], expires_at: float) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO auth_codes(code_hash, data, expires_at) VALUES(?,?,?)",
                (token_hash(code), json.dumps(data), expires_at),
            )
            self._conn.commit()

    def get_auth_code(self, code: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT data, expires_at FROM auth_codes WHERE code_hash=?", (token_hash(code),)
            ).fetchone()
        if row is None or row[1] < time.time():
            return None
        return json.loads(row[0])

    def delete_auth_code(self, code: str) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM auth_codes WHERE code_hash=?", (token_hash(code),))
            self._conn.commit()

    # -- access tokens ------------------------------------------------------------

    def save_access_token(
        self,
        token: str,
        *,
        client_id: str,
        scopes: list[str],
        subject: str | None,
        resource: str | None,
        expires_at: float,
    ) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO access_tokens(token_hash, client_id, scopes, subject, resource, expires_at)"
                " VALUES(?,?,?,?,?,?)",
                (token_hash(token), client_id, " ".join(scopes), subject, resource, expires_at),
            )
            self._conn.commit()

    def get_access_token(self, token: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT client_id, scopes, subject, resource, expires_at FROM access_tokens"
                " WHERE token_hash=?",
                (token_hash(token),),
            ).fetchone()
        if row is None or row[4] < time.time():
            return None
        return {
            "client_id": row[0],
            "scopes": row[1].split() if row[1] else [],
            "subject": row[2],
            "resource": row[3],
            "expires_at": row[4],
        }

    def delete_access_token(self, token: str) -> None:
        with self._lock:
            self._conn.execute(
                "DELETE FROM access_tokens WHERE token_hash=?", (token_hash(token),)
            )
            self._conn.commit()

    def delete_access_tokens_for_client(self, client_id: str) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM access_tokens WHERE client_id=?", (client_id,))
            self._conn.commit()

    # -- refresh tokens --------------------------------------------------------------

    def save_refresh_token(
        self,
        token: str,
        *,
        client_id: str,
        scopes: list[str],
        subject: str | None,
        resource: str | None,
        expires_at: float,
    ) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO refresh_tokens(token_hash, client_id, scopes, subject, resource, expires_at)"
                " VALUES(?,?,?,?,?,?)",
                (token_hash(token), client_id, " ".join(scopes), subject, resource, expires_at),
            )
            self._conn.commit()

    def get_refresh_token(self, token: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT client_id, scopes, subject, resource, expires_at, revoked"
                " FROM refresh_tokens WHERE token_hash=?",
                (token_hash(token),),
            ).fetchone()
        if row is None or row[4] < time.time() or row[5]:
            return None
        return {
            "client_id": row[0],
            "scopes": row[1].split() if row[1] else [],
            "subject": row[2],
            "resource": row[3],
            "expires_at": row[4],
        }

    def revoke_refresh_token(self, token: str) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE refresh_tokens SET revoked=1 WHERE token_hash=?", (token_hash(token),)
            )
            self._conn.commit()

    # -- upstream backend credentials ----------------------------------------------

    def save_upstream(self, backend: str, key: str, value: dict[str, Any]) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO upstream_data(backend, key, value, updated_at) VALUES(?,?,?,?) "
                "ON CONFLICT(backend, key) DO UPDATE SET value=excluded.value,"
                " updated_at=excluded.updated_at",
                (backend, key, self._encrypt_json(value), time.time()),
            )
            self._conn.commit()

    def get_upstream(self, backend: str, key: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT value FROM upstream_data WHERE backend=? AND key=?", (backend, key)
            ).fetchone()
        if row is None:
            return None
        try:
            return self._decrypt_json(row[0])
        except InvalidToken:
            return None

    def delete_upstream(self, backend: str, key: str | None = None) -> None:
        with self._lock:
            if key is None:
                self._conn.execute("DELETE FROM upstream_data WHERE backend=?", (backend,))
            else:
                self._conn.execute(
                    "DELETE FROM upstream_data WHERE backend=? AND key=?", (backend, key)
                )
            self._conn.commit()

    # -- browser session revocation (logout) -----------------------------------------

    def revoke_session(self, session_id: str, expires_at: float) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO revoked_sessions(session_id, expires_at) VALUES(?,?) "
                "ON CONFLICT(session_id) DO NOTHING",
                (session_id, expires_at),
            )
            self._conn.commit()

    def is_session_revoked(self, session_id: str) -> bool:
        with self._lock:
            row = self._conn.execute(
                "SELECT 1 FROM revoked_sessions WHERE session_id=?", (session_id,)
            ).fetchone()
        return row is not None

    # -- housekeeping -------------------------------------------------------------------

    def purge_expired(self) -> None:
        now = time.time()
        with self._lock:
            cur = self._conn.execute("DELETE FROM auth_codes WHERE expires_at < ?", (now,))
            deleted = cur.rowcount
            cur = self._conn.execute("DELETE FROM access_tokens WHERE expires_at < ?", (now,))
            deleted += cur.rowcount
            cur = self._conn.execute("DELETE FROM refresh_tokens WHERE expires_at < ?", (now,))
            deleted += cur.rowcount
            cur = self._conn.execute("DELETE FROM auth_txns WHERE expires_at < ?", (now,))
            deleted += cur.rowcount
            cur = self._conn.execute(
                "DELETE FROM revoked_sessions WHERE expires_at < ?", (now,)
            )
            deleted += cur.rowcount
            # Anonymous DCR/CIMD clients that never completed an authorization
            # are reclaimed after UNUSED_CLIENT_TTL_SECONDS; clients that have
            # (last_used_at set) are kept indefinitely.
            cur = self._conn.execute(
                "DELETE FROM oauth_clients WHERE last_used_at IS NULL AND created_at < ?",
                (now - UNUSED_CLIENT_TTL_SECONDS,),
            )
            deleted += cur.rowcount
            self._conn.commit()
        logger.debug("Purged %d expired row(s) from storage", deleted)
