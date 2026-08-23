from __future__ import annotations

import base64
import hashlib
import secrets
import socket
import threading
import time
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
import uvicorn

from mcp_gateway.app import create_app
from mcp_gateway.config import GatewayConfig


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class LiveServer:
    """A uvicorn server running in a background thread."""

    def __init__(self, app, port: int):
        self.port = port
        self.base_url = f"http://127.0.0.1:{port}"
        self._server = uvicorn.Server(
            uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
        )
        self._thread = threading.Thread(target=self._server.run, daemon=True)

    def start(self) -> LiveServer:
        self._thread.start()
        deadline = time.time() + 10
        while not self._server.started:
            if time.time() > deadline:
                raise RuntimeError("server did not start")
            time.sleep(0.02)
        return self

    def stop(self) -> None:
        self._server.should_exit = True
        self._thread.join(timeout=5)


@pytest.fixture
def run_server():
    servers: list[LiveServer] = []

    def _run(app, port: int | None = None) -> LiveServer:
        server = LiveServer(app, port or free_port()).start()
        servers.append(server)
        return server

    yield _run
    for server in servers:
        server.stop()


def gateway_config(port: int, backends: dict | None = None, **auth_extra) -> GatewayConfig:
    return GatewayConfig.model_validate(
        {
            "server": {"public_url": f"http://127.0.0.1:{port}", "port": port},
            "auth": {
                "encryption_key": "test-passphrase",
                "users": [{"username": "admin", "password": "pw"}],
                **auth_extra,
            },
            "storage": {"path": ":memory:"},
            "backends": backends or {},
        }
    )


@pytest.fixture
def gateway(run_server):
    """A running gateway with no backends; yields (LiveServer, app)."""
    port = free_port()
    app = create_app(gateway_config(port))
    return run_server(app, port), app


def pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(64)
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
        .decode()
        .rstrip("=")
    )
    return verifier, challenge


async def register_client(
    http: httpx.AsyncClient, base: str, redirect_uri: str = "http://localhost:1234/callback"
) -> str:
    r = await http.post(
        f"{base}/register",
        json={
            "client_name": "pytest client",
            "redirect_uris": [redirect_uri],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none",
        },
    )
    assert r.status_code == 201, r.text
    return r.json()["client_id"]


async def obtain_tokens(
    http: httpx.AsyncClient,
    base: str,
    client_id: str,
    redirect_uri: str = "http://localhost:1234/callback",
    username: str = "admin",
    password: str = "pw",
    approve: bool = True,
    scope: str | None = "mcp",
) -> dict:
    """Drive authorize -> login -> consent -> token; returns the token response JSON."""
    verifier, challenge = pkce_pair()
    params = {
        "client_id": client_id,
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "state": "test-state",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "resource": f"{base}/mcp",
    }
    if scope:
        params["scope"] = scope
    r = await http.get(f"{base}/authorize", params=params)
    assert r.status_code in (302, 307), r.text
    txn = parse_qs(urlparse(r.headers["location"]).query)["txn"][0]

    r = await http.post(
        f"{base}/auth/api/login", json={"username": username, "password": password}
    )
    assert r.status_code == 200, r.text
    http.cookies.update(r.cookies)

    r = await http.post(f"{base}/auth/api/consent", json={"txn_id": txn, "approve": approve})
    assert r.status_code == 200, r.text
    redirect_to = r.json()["redirect_to"]
    query = parse_qs(urlparse(redirect_to).query)
    if not approve:
        return {"error": query["error"][0], "state": query.get("state", [None])[0]}
    assert query["state"][0] == "test-state"

    r = await http.post(
        f"{base}/token",
        data={
            "grant_type": "authorization_code",
            "code": query["code"][0],
            "redirect_uri": redirect_uri,
            "client_id": client_id,
            "code_verifier": verifier,
            "resource": f"{base}/mcp",
        },
    )
    assert r.status_code == 200, r.text
    return r.json()
