"""Regression tests for the security review fixes (SECURITY-REVIEW.md).

Each test is named after the finding it guards against a regression of.
"""

from __future__ import annotations

import statistics
import time

import bcrypt
import httpx
import pytest

from mcp_gateway.app import create_app
from mcp_gateway.config import GatewayConfig
from mcp_gateway.users import verify_user
from tests.conftest import free_port, gateway_config, obtain_tokens, register_client

# --------------------------------------------------------------------- M-1 / L-2


def _auth_config(*, hashed: bool, extra_plaintext_user: bool = False):
    from mcp_gateway.config import AuthConfig

    users = [
        {
            "username": "admin",
            **(
                {"password_hash": bcrypt.hashpw(b"correct-horse", bcrypt.gensalt()).decode()}
                if hashed
                else {"password": "correct-horse"}
            ),
        }
    ]
    if extra_plaintext_user:
        users.append({"username": "bob", "password": "hunter2"})
    return AuthConfig.model_validate({"encryption_key": "k", "users": users})


def test_verify_user_correctness():
    auth = _auth_config(hashed=True)
    assert verify_user(auth, "admin", "correct-horse") is True
    assert verify_user(auth, "admin", "wrong") is False
    assert verify_user(auth, "nosuchuser", "correct-horse") is False


def test_verify_user_non_ascii_username_does_not_raise():
    """A non-ASCII username used to raise TypeError in hmac.compare_digest,
    giving an unauthenticated caller a 500 and locking out any user actually
    configured with such a username."""
    auth = _auth_config(hashed=True)
    assert verify_user(auth, "adminé", "correct-horse") is False
    assert verify_user(auth, "noséusername", "x") is False


def test_verify_user_timing_does_not_leak_username_existence():
    """The dummy hash for an unknown/plaintext user must cost the same
    bcrypt work as a real hashed check, or response time leaks which
    usernames exist (measured 270ms gap before the fix, cost 12 vs cost 4)."""
    auth = _auth_config(hashed=True)

    def median_time(username: str, n: int = 5) -> float:
        samples = []
        for _ in range(n):
            t0 = time.perf_counter()
            verify_user(auth, username, "wrong-password")
            samples.append(time.perf_counter() - t0)
        return statistics.median(samples)

    valid = median_time("admin")
    unknown = median_time("nosuchuser")
    # Loose bound (not a tight ms threshold, to stay robust on slow CI):
    # before the fix this ratio was ~2x (270ms vs ~130ms at cost 12 vs a
    # cost-4 dummy), the fix brings both paths to one real bcrypt check each.
    ratio = max(valid, unknown) / max(min(valid, unknown), 1e-6)
    assert ratio < 1.5, f"timing leaks username existence: valid={valid:.3f}s unknown={unknown:.3f}s"


async def test_login_endpoint_rejects_non_ascii_username_cleanly(gateway):
    server, _ = gateway
    async with httpx.AsyncClient(timeout=30) as http:
        r = await http.post(
            f"{server.base_url}/auth/api/login",
            json={"username": "adminé", "password": "x"},
        )
        assert r.status_code == 401


# --------------------------------------------------------------------- H-1


async def test_login_does_not_stall_unrelated_requests(run_server):
    """bcrypt now runs off the event loop; a burst of logins must not stall
    an unrelated endpoint the way synchronous bcrypt.checkpw did (measured
    361x amplification -- 15ms -> 5.4s -- before the fix)."""
    import asyncio

    hashed = bcrypt.hashpw(b"correct-horse", bcrypt.gensalt()).decode()
    port = free_port()
    config = GatewayConfig.model_validate(
        {
            "server": {"public_url": f"http://127.0.0.1:{port}", "port": port},
            "auth": {
                "encryption_key": "test-passphrase",
                "users": [{"username": "admin", "password_hash": hashed}],
            },
            "storage": {"path": ":memory:"},
            "backends": {},
        }
    )
    server = run_server(create_app(config), port)
    base = server.base_url

    async with httpx.AsyncClient(timeout=60) as http:
        t0 = time.perf_counter()
        await http.get(f"{base}/healthz")
        baseline = time.perf_counter() - t0

        flood = [
            asyncio.create_task(
                http.post(f"{base}/auth/api/login", json={"username": "admin", "password": f"x{i}"})
            )
            for i in range(8)
        ]
        await asyncio.sleep(0.05)
        t0 = time.perf_counter()
        r = await http.get(f"{base}/healthz")
        under_load = time.perf_counter() - t0
        await asyncio.gather(*flood, return_exceptions=True)

    assert r.status_code == 200
    # Generous bound: the unrelated request must complete in a small
    # multiple of baseline, not seconds (offloading + rate limiting both
    # contribute; either alone already prevents the multi-second stall).
    assert under_load < max(baseline * 20, 1.0), (
        f"unauthenticated logins stalled an unrelated request: "
        f"baseline={baseline*1000:.0f}ms under_load={under_load*1000:.0f}ms"
    )


async def test_login_rate_limited_per_ip(gateway):
    server, app = gateway
    base = server.base_url
    async with httpx.AsyncClient(timeout=30) as http:
        statuses = []
        for _ in range(app.state.login_limiter.max_requests + 3):
            r = await http.post(
                f"{base}/auth/api/login", json={"username": "admin", "password": "wrong"}
            )
            statuses.append(r.status_code)
        assert 429 in statuses, "no rate limit kicked in after exceeding the login threshold"
        assert statuses[-1] == 429


# --------------------------------------------------------------------- L-3


async def test_logout_revokes_session_immediately(gateway):
    server, _ = gateway
    base = server.base_url
    async with httpx.AsyncClient(timeout=30) as http:
        r = await http.post(f"{base}/auth/api/login", json={"username": "admin", "password": "pw"})
        http.cookies.update(r.cookies)
        r = await http.get(f"{base}/auth/api/me")
        assert r.json()["username"] == "admin"

        saved_cookie = dict(http.cookies)
        r = await http.post(f"{base}/auth/api/logout")
        assert r.status_code == 200

        # Re-attach the (now revoked) cookie manually -- a stolen cookie
        # replayed after logout must not still authenticate.
        replay = httpx.AsyncClient(cookies=saved_cookie, timeout=30)
        async with replay:
            r = await replay.get(f"{base}/auth/api/me")
            assert r.json()["username"] is None


# --------------------------------------------------------------------- M-4 / I-3


async def test_security_headers_present(gateway):
    server, _ = gateway
    base = server.base_url
    async with httpx.AsyncClient(timeout=30) as http:
        r = await http.get(f"{base}/ui/authorize?txn=nonexistent")
        headers = {k.lower(): v for k, v in r.headers.items()}
        assert headers.get("x-frame-options") == "DENY"
        assert "frame-ancestors 'none'" in headers.get("content-security-policy", "")
        assert headers.get("referrer-policy") == "no-referrer"
        assert headers.get("x-content-type-options") == "nosniff"

        r2 = await http.get(f"{base}/auth/api/me")
        assert {k.lower(): v for k, v in r2.headers.items()}.get("cache-control") == "no-store"


# --------------------------------------------------------------------- M-2


async def test_forged_callback_does_not_destroy_admin_connect_flow(run_server):
    upstream_port = free_port()
    upstream = run_server(create_app(gateway_config(upstream_port)), upstream_port)
    port = free_port()
    app = create_app(
        gateway_config(
            port,
            backends={"up": {"url": f"{upstream.base_url}/mcp", "auth": {"type": "oauth"}}},
        )
    )
    gateway = run_server(app, port)
    a = gateway.base_url

    async with httpx.AsyncClient(follow_redirects=False, timeout=30) as admin:
        r = await admin.post(f"{a}/auth/api/login", json={"username": "admin", "password": "pw"})
        admin.cookies.update(r.cookies)
        r = await admin.get(f"{a}/oauth/connect/up")
        assert r.status_code in (302, 307)

        # Anonymous attacker, no session, forged state: must not disturb the
        # admin's pending flow.
        async with httpx.AsyncClient(follow_redirects=False, timeout=30) as attacker:
            ra = await attacker.get(
                f"{a}/oauth/callback", params={"code": "attacker-code", "state": "wrong"}
            )
            assert "Sign+in+required" in ra.headers.get("location", "")

        flow = app.state.backend_manager._flows_by_backend.get("up")
        assert flow is not None and not flow.callback.done(), (
            "an anonymous forged callback consumed the admin's pending connect flow"
        )


async def test_oauth_callback_requires_session(gateway):
    server, _ = gateway
    async with httpx.AsyncClient(follow_redirects=False, timeout=30) as http:
        r = await http.get(
            f"{server.base_url}/oauth/callback", params={"code": "x", "state": "y"}
        )
        assert r.status_code in (302, 307)
        assert "Sign+in+required" in r.headers["location"]


# --------------------------------------------------------------------- M-3


async def test_register_rate_limited_per_ip(gateway):
    server, app = gateway
    base = server.base_url
    async with httpx.AsyncClient(timeout=60) as http:
        statuses = []
        for i in range(app.state.register_limiter.max_requests + 3):
            r = await http.post(
                f"{base}/register",
                json={
                    "client_name": f"c{i}",
                    "redirect_uris": ["http://localhost:1234/callback"],
                    "grant_types": ["authorization_code", "refresh_token"],
                    "response_types": ["code"],
                    "token_endpoint_auth_method": "none",
                },
            )
            statuses.append(r.status_code)
        assert 429 in statuses


async def test_unused_dcr_clients_are_purged_after_ttl(gateway):
    server, app = gateway
    base = server.base_url
    storage = app.state.storage

    async with httpx.AsyncClient(timeout=30) as http:
        unused_client_id = await register_client(http, base)
        used_client_id = await register_client(
            http, base, redirect_uri="http://localhost:5555/callback"
        )
        # Complete a real authorization for `used_client_id` so it is marked used.
        await obtain_tokens(
            http, base, used_client_id, redirect_uri="http://localhost:5555/callback"
        )

    # Backdate both clients' created_at past the unused-client TTL.
    from mcp_gateway.storage import UNUSED_CLIENT_TTL_SECONDS

    old = time.time() - UNUSED_CLIENT_TTL_SECONDS - 10
    storage._conn.execute(
        "UPDATE oauth_clients SET created_at=? WHERE client_id IN (?, ?)",
        (old, unused_client_id, used_client_id),
    )
    storage._conn.commit()

    storage.purge_expired()

    assert storage.get_client(unused_client_id) is None, "never-used client was not reclaimed"
    assert storage.get_client(used_client_id) is not None, (
        "a client that completed an authorization must not be purged by age"
    )


# --------------------------------------------------------------------- L-4 / L-5


def test_mask_error_details_enabled():
    """Internal exception details (backend URLs, HTTP bodies, exception
    types) must not be handed to MCP clients; diagnose from server logs."""
    from mcp_gateway.gateway import build_gateway
    from mcp_gateway.oauth_server import GatewayOAuthProvider
    from mcp_gateway.storage import Storage
    from mcp_gateway.upstream import BackendManager

    port = free_port()
    config = gateway_config(port)
    storage = Storage(":memory:", config.auth.encryption_key)
    provider = GatewayOAuthProvider(config, storage)
    manager = BackendManager(config, storage)

    mcp = build_gateway(config, provider, manager, {})
    assert mcp._mask_error_details is True


def test_forward_incoming_headers_missing_attribute_fails_loudly(monkeypatch):
    """If a future fastmcp release renames/removes forward_incoming_headers,
    the gateway must refuse to start rather than silently re-enabling token
    passthrough to backends.

    fastmcp's own create_proxy() defensively re-sets this attribute on a
    plain Client's StreamableHttpTransport/SSETransport, so a real client
    always has it today -- that's a second line of defense, not this one.
    To exercise *our* check in isolation, create_proxy is stubbed out here
    so only gateway.py's own hasattr check decides the outcome.
    """
    from fastmcp import Client
    from fastmcp.client.transports import StreamableHttpTransport

    import mcp_gateway.gateway as gateway_module
    from mcp_gateway.oauth_server import GatewayOAuthProvider
    from mcp_gateway.storage import Storage
    from mcp_gateway.upstream import BackendManager

    monkeypatch.setattr(gateway_module, "create_proxy", lambda *a, **k: object())

    port = free_port()
    config = gateway_config(
        port, backends={"x": {"url": "http://127.0.0.1:1/mcp", "auth": {"type": "none"}}}
    )
    storage = Storage(":memory:", config.auth.encryption_key)
    provider = GatewayOAuthProvider(config, storage)
    manager = BackendManager(config, storage)

    client = Client(StreamableHttpTransport("http://127.0.0.1:1/mcp"))
    del client.transport.forward_incoming_headers  # simulate a fastmcp API change

    with pytest.raises(RuntimeError, match="forward_incoming_headers"):
        gateway_module.build_gateway(config, provider, manager, {"x": client})
