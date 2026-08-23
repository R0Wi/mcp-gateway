"""Local user verification and signed browser sessions."""

from __future__ import annotations

import hmac
import json
import time

import bcrypt
from itsdangerous import BadSignature, URLSafeTimedSerializer

from mcp_gateway.config import AuthConfig

SESSION_COOKIE = "mcp_gateway_session"


def verify_user(auth: AuthConfig, username: str, password: str) -> bool:
    for user in auth.users:
        if not hmac.compare_digest(user.username, username):
            continue
        if user.password_hash is not None:
            try:
                return bcrypt.checkpw(password.encode(), user.password_hash.encode())
            except ValueError:
                return False
        if user.password is not None:
            return hmac.compare_digest(user.password, password)
    # Constant-ish time for unknown users: still run one bcrypt round.
    bcrypt.checkpw(b"invalid", bcrypt.hashpw(b"invalid-user", bcrypt.gensalt(rounds=4)))
    return False


class SessionManager:
    """Signed, time-limited login session cookies (no server-side state)."""

    def __init__(self, secret: str, max_age_seconds: int):
        self._serializer = URLSafeTimedSerializer(secret, salt="mcp-gateway-session")
        self.max_age_seconds = max_age_seconds

    def create(self, username: str) -> str:
        return self._serializer.dumps(json.dumps({"u": username, "t": time.time()}))

    def validate(self, cookie_value: str | None) -> str | None:
        """Return the logged-in username, or None."""
        if not cookie_value:
            return None
        try:
            payload = json.loads(
                self._serializer.loads(cookie_value, max_age=self.max_age_seconds)
            )
            return payload.get("u") or None
        except (BadSignature, ValueError):
            return None
