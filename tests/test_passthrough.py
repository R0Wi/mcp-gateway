"""Opt-in raw-HTTP passthrough (``/backends/<name>/<path>``) to backend routes."""

from __future__ import annotations

import asyncio
import hashlib
import time

import httpx
import pytest
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from mcp_gateway.app import create_app
from tests.conftest import free_port, gateway_config, obtain_tokens, register_client

MIB = 1024 * 1024


class StubBackend:
    """A plain (non-MCP) HTTP backend that records what it received."""

    def __init__(self) -> None:
        self.requests: list[dict] = []
        self.app = Starlette(
            routes=[
                Route("/uploads", self.upload, methods=["POST"]),
                Route("/uploads/{upload_id}", self.delete, methods=["DELETE"]),
                Route("/boom", self.boom, methods=["POST"]),
                Route("/redirect", self.redirect, methods=["POST"]),
            ]
        )

    def _record(self, request: Request, body: bytes) -> dict:
        entry = {
            "method": request.method,
            "path": request.url.path,
            "query": request.url.query,
            "headers": dict(request.headers),
            "size": len(body),
            "sha256": hashlib.sha256(body).hexdigest(),
        }
        self.requests.append(entry)
        return entry

    async def upload(self, request: Request) -> Response:
        entry = self._record(request, await request.body())
        return JSONResponse(
            {"handle": "upload://abc", "size": entry["size"], "sha256": entry["sha256"]},
            status_code=201,
            headers={"set-cookie": "backend=secret", "x-internal": "leak"},
        )

    async def delete(self, request: Request) -> Response:
        self._record(request, await request.body())
        return JSONResponse({"deleted": request.path_params["upload_id"]})

    async def boom(self, request: Request) -> Response:
        self._record(request, await request.body())
        return Response("internal detail: db at 10.0.0.5", status_code=500)

    async def redirect(self, request: Request) -> Response:
        return Response(status_code=302, headers={"location": "http://internal.example/x"})


PASSTHROUGH = [
    {"path": "/uploads", "methods": ["post", "DELETE"], "max_body_bytes": 8 * MIB},
    {"path": "/boom"},
    {"path": "/redirect"},
]


@pytest.fixture
def stub_setup(run_server):
    stub = StubBackend()
    stub_server = run_server(stub.app)
    port = free_port()
    config = gateway_config(
        port,
        backends={
            "stub": {
                "url": f"{stub_server.base_url}/mcp",
                "auth": {"type": "bearer", "token": "upstream-secret"},
                "headers": {"X-Static": "static-value"},
                "passthrough": PASSTHROUGH,
            },
            "plain": {"url": f"{stub_server.base_url}/mcp"},
            "off": {"url": f"{stub_server.base_url}/mcp", "enabled": False,
                    "passthrough": [{"path": "/uploads"}]},
        },
    )
    gateway = run_server(create_app(config), port)
    return gateway, stub, stub_server


async def _token(base: str) -> str:
    async with httpx.AsyncClient() as http:
        client_id = await register_client(http, base)
        return (await obtain_tokens(http, base, client_id))["access_token"]


async def _raw_status(base: str, method: str, path: str, headers: dict[str, str]) -> int:
    """Send a request with `path` byte-for-byte; httpx would normalize '..' away."""
    host, port = base.removeprefix("http://").split(":")
    reader, writer = await asyncio.open_connection(host, int(port))
    lines = [f"{method} {path} HTTP/1.1", f"Host: {host}", "Content-Length: 0",
             "Connection: close", *(f"{k}: {v}" for k, v in headers.items())]
    writer.write(("\r\n".join(lines) + "\r\n\r\n").encode())
    await writer.drain()
    status_line = await reader.readline()
    writer.close()
    return int(status_line.split()[1])


async def _chunks(total: int, size: int = 256 * 1024):
    sent = 0
    while sent < total:
        n = min(size, total - sent)
        yield bytes([sent // size % 256]) * n
        sent += n


async def test_requires_same_bearer_auth_as_mcp(stub_setup):
    gateway, stub, _ = stub_setup
    base = gateway.base_url
    async with httpx.AsyncClient() as http:
        r = await http.post(f"{base}/backends/stub/uploads", content=b"x")
        assert r.status_code == 401
        assert "resource_metadata=" in r.headers["www-authenticate"]
        mcp = await http.post(f"{base}/mcp", content=b"{}")
        assert mcp.status_code == 401
        assert mcp.headers["www-authenticate"] == r.headers["www-authenticate"]

        r = await http.post(
            f"{base}/backends/stub/uploads",
            content=b"x",
            headers={"Authorization": "Bearer not-a-real-token"},
        )
        assert r.status_code == 401
        assert 'error="invalid_token"' in r.headers["www-authenticate"]

        # Unauthenticated requests can't even enumerate routes.
        r = await http.post(f"{base}/backends/nope/whatever")
        assert r.status_code == 401
    assert stub.requests == []


async def test_streams_large_body_with_backend_credential(stub_setup):
    gateway, stub, _ = stub_setup
    base = gateway.base_url
    token = await _token(base)
    total = 5 * MIB + 123
    expected = hashlib.sha256()
    async for chunk in _chunks(total):
        expected.update(chunk)

    async with httpx.AsyncClient(timeout=60) as http:
        r = await http.post(
            f"{base}/backends/stub/uploads?name=cap.pcap",
            content=_chunks(total),  # chunked transfer, no Content-Length
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/vnd.tcpdump.pcap",
                "Cookie": "mcp_gateway_session=should-not-leak",
                "X-Forwarded-For": "1.2.3.4",
                "X-Custom": "dropped",
            },
        )
    assert r.status_code == 201, r.text
    assert r.json() == {"handle": "upload://abc", "size": total, "sha256": expected.hexdigest()}
    # Backend response headers are allowlisted too.
    assert "set-cookie" not in r.headers
    assert "x-internal" not in r.headers

    (seen,) = stub.requests
    assert seen["path"] == "/uploads"
    assert seen["query"] == "name=cap.pcap"
    headers = seen["headers"]
    # The backend sees the gateway's own credential -- never the client token.
    assert headers["authorization"] == "Bearer upstream-secret"
    assert token not in str(headers)
    assert headers["x-static"] == "static-value"
    assert headers["content-type"] == "application/vnd.tcpdump.pcap"
    for leaked in ("cookie", "x-forwarded-for", "x-custom"):
        assert leaked not in headers


async def test_subpath_and_methods(stub_setup):
    gateway, stub, _ = stub_setup
    base = gateway.base_url
    auth = {"Authorization": f"Bearer {await _token(base)}"}
    async with httpx.AsyncClient() as http:
        r = await http.delete(f"{base}/backends/stub/uploads/abc", headers=auth)
        assert r.status_code == 200
        assert r.json() == {"deleted": "abc"}
        assert stub.requests[-1]["method"] == "DELETE"

        r = await http.get(f"{base}/backends/stub/uploads", headers=auth)
        assert r.status_code == 405
        # Subpaths of an allowlisted path reach the backend (here: its own 404).
        r = await http.post(f"{base}/backends/stub/boom/x", headers=auth)
        assert r.status_code == 404
        r = await http.delete(f"{base}/backends/stub/boom", headers=auth)
        assert r.status_code == 405

        for path in (
            "/backends/stub/other",
            "/backends/stub/uploadsX",
            "/backends/stub/uploads/../boom",
            "/backends/stub/uploads/%2E%2E/boom",
            "/backends/stub/uploads%2Fx",
            "/backends/stub//uploads",
            "/backends/stub",
            "/backends/plain/uploads",  # backend without passthrough
            "/backends/off/uploads",  # disabled backend
            "/backends/missing/uploads",
        ):
            assert await _raw_status(base, "POST", path, auth) == 404, path


async def test_body_size_cap(stub_setup):
    gateway, stub, _ = stub_setup
    base = gateway.base_url
    auth = {"Authorization": f"Bearer {await _token(base)}"}
    async with httpx.AsyncClient(timeout=60) as http:
        # Declared Content-Length over the cap: rejected before contacting the backend.
        r = await http.post(
            f"{base}/backends/stub/uploads", content=b"x" * (8 * MIB + 1), headers=auth
        )
        assert r.status_code == 413
        # Chunked body that crosses the cap mid-stream.
        r = await http.post(
            f"{base}/backends/stub/uploads", content=_chunks(9 * MIB), headers=auth
        )
        assert r.status_code == 413
    assert stub.requests == []


async def test_backend_errors_are_masked(stub_setup):
    gateway, _, stub_server = stub_setup
    base = gateway.base_url
    auth = {"Authorization": f"Bearer {await _token(base)}"}
    async with httpx.AsyncClient() as http:
        r = await http.post(f"{base}/backends/stub/boom", content=b"x", headers=auth)
        assert r.status_code == 502
        assert "10.0.0.5" not in r.text
        assert r.json()["error"] == "bad_gateway"

        r = await http.post(f"{base}/backends/stub/redirect", headers=auth)
        assert r.status_code == 302
        assert "location" not in r.headers

        stub_server.stop()
        r = await http.post(f"{base}/backends/stub/uploads", content=b"x", headers=auth)
        assert r.status_code == 502
        assert stub_server.base_url not in r.text


def test_no_passthrough_config_mounts_nothing(gateway):
    _, app = gateway
    assert not any(getattr(r, "path", None) == "/backends" for r in app.routes)


# --------------------------------------------------------------------- OAuth backend


@pytest.fixture
def oauth_chain(run_server):
    """client -> gateway A -(upstream OAuth)-> gateway B -(bearer)-> stub.

    Gateway B's own passthrough route validates the bearer token A sends, so a
    201 from the stub proves A attached a valid upstream OAuth token for B.
    """
    stub = StubBackend()
    stub_server = run_server(stub.app)
    b_port = free_port()
    b = run_server(
        create_app(
            gateway_config(
                b_port,
                backends={
                    "stub": {
                        "url": f"{stub_server.base_url}/mcp",
                        "auth": {"type": "bearer", "token": "b-secret"},
                        "passthrough": [{"path": "/uploads"}],
                    }
                },
            )
        ),
        b_port,
    )
    a_port = free_port()
    a_app = create_app(
        gateway_config(
            a_port,
            backends={
                "up": {
                    "url": f"{b.base_url}/mcp",
                    "auth": {"type": "oauth"},
                    "passthrough": [{"path": "/backends/stub/uploads"}],
                }
            },
        )
    )
    a = run_server(a_app, a_port)
    return a, a_app, b, stub


async def test_oauth_backend_not_connected(oauth_chain):
    a, _, _, stub = oauth_chain
    auth = {"Authorization": f"Bearer {await _token(a.base_url)}"}
    async with httpx.AsyncClient(timeout=15) as http:
        r = await http.post(f"{a.base_url}/backends/up/backends/stub/uploads", content=b"x",
                            headers=auth)
    assert r.status_code == 503
    assert stub.requests == []


async def test_oauth_backend_uses_and_refreshes_upstream_token(oauth_chain):
    a, a_app, b, stub = oauth_chain
    redirect_uri = "http://localhost:1234/callback"
    async with httpx.AsyncClient() as http:
        b_client_id = await register_client(http, b.base_url, redirect_uri)
        b_tokens = await obtain_tokens(http, b.base_url, b_client_id, redirect_uri)
    storage = a_app.state.storage
    storage.save_upstream(
        "up",
        "client_info",
        {
            "client_id": b_client_id,
            "redirect_uris": [redirect_uri],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none",
        },
    )
    # Already expired: the passthrough must refresh it before forwarding.
    storage.save_upstream(
        "up",
        "tokens",
        {**b_tokens, "expires_at": time.time() - 60},
    )

    token = await _token(a.base_url)
    async with httpx.AsyncClient(timeout=30) as http:
        r = await http.post(
            f"{a.base_url}/backends/up/backends/stub/uploads",
            content=b"pcap-bytes",
            headers={"Authorization": f"Bearer {token}"},
        )
    assert r.status_code == 201, r.text
    assert r.json()["size"] == len(b"pcap-bytes")
    assert stub.requests[-1]["headers"]["authorization"] == "Bearer b-secret"

    refreshed = storage.get_upstream("up", "tokens")
    assert refreshed["access_token"] != b_tokens["access_token"]
    assert refreshed["expires_at"] > time.time()
