"""Opt-in raw-HTTP passthrough (``/backends/<name>/<path>``) to backend routes."""

from __future__ import annotations

import asyncio
import hashlib
import logging
import time

import httpx
import pytest
from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport
from fastmcp.exceptions import ToolError
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from mcp_gateway.app import create_app
from mcp_gateway.passthrough import RedactTicketFilter
from tests.conftest import free_port, gateway_config, obtain_tokens, register_client

MIB = 1024 * 1024


class StubBackend:
    """A plain (non-MCP) HTTP backend that records what it received."""

    def __init__(self) -> None:
        self.requests: list[dict] = []
        self.app = Starlette(
            routes=[
                Route("/uploads", self.upload, methods=["POST", "DELETE"]),
                Route("/prefix/uploads", self.upload, methods=["POST"]),
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
        if request.method == "DELETE":
            return JSONResponse({"deleted": True})
        return JSONResponse(
            {"handle": "upload://abc", "size": entry["size"], "sha256": entry["sha256"]},
            status_code=201,
            headers={"set-cookie": "backend=secret", "x-internal": "leak"},
        )

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
            "based": {
                "url": f"{stub_server.base_url}/mcp",
                "passthrough_base_url": f"{stub_server.base_url}/prefix/",
                "passthrough": [{"path": "/uploads"}],
            },
            "off": {"url": f"{stub_server.base_url}/mcp", "enabled": False,
                    "passthrough": [{"path": "/uploads"}]},
        },
    )
    app = create_app(config)
    gateway = run_server(app, port)
    gateway.app = app
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
        r = await http.delete(f"{base}/backends/stub/uploads", headers=auth)
        assert r.status_code == 200
        assert r.json() == {"deleted": True}
        assert stub.requests[-1]["method"] == "DELETE"

        r = await http.get(f"{base}/backends/stub/uploads", headers=auth)
        assert r.status_code == 405
        r = await http.delete(f"{base}/backends/stub/boom", headers=auth)
        assert r.status_code == 405

        for path in (
            "/backends/stub/other",
            "/backends/stub/uploadsX",
            "/backends/stub/uploads/abc",  # exact match only, no prefixes
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


async def test_passthrough_base_url(stub_setup):
    gateway, stub, _ = stub_setup
    base = gateway.base_url
    auth = {"Authorization": f"Bearer {await _token(base)}"}
    async with httpx.AsyncClient() as http:
        r = await http.post(f"{base}/backends/based/uploads", content=b"x", headers=auth)
    assert r.status_code == 201, r.text
    assert stub.requests[-1]["path"] == "/prefix/uploads"


# --------------------------------------------------------------------- upload tickets


def _mcp_client(base: str, token: str) -> Client:
    return Client(
        StreamableHttpTransport(f"{base}/mcp", headers={"Authorization": f"Bearer {token}"}),
        timeout=15,
    )


async def _upload_url(base: str, token: str, **args) -> dict:
    async with _mcp_client(base, token) as client:
        result = await client.call_tool(
            "gateway_create_upload_url", {"backend": "stub", "path": "/uploads", **args}
        )
    return result.structured_content


async def test_upload_url_single_use_without_bearer(stub_setup):
    gateway, stub, _ = stub_setup
    base = gateway.base_url
    token = await _token(base)
    minted = await _upload_url(base, token)
    assert minted["method"] == "POST"
    assert minted["expires_in_seconds"] == 300
    assert minted["max_body_bytes"] == 8 * MIB
    url = minted["url"]
    assert url.startswith(f"{base}/backends/stub/t/")
    ticket = url.rsplit("/", 1)[1]
    # Stored hashed, never in the clear.
    rows = gateway.app.state.storage._conn.execute(
        "SELECT ticket_hash FROM upload_tickets"
    ).fetchall()
    assert len(rows) == 1 and ticket not in rows[0][0]
    total = 2 * MIB

    async with httpx.AsyncClient(timeout=60) as http:
        # A stray probe with the wrong method doesn't burn the URL.
        r = await http.get(url)
        assert r.status_code == 405
        r = await http.post(f"{url}?filename=incident.pcap", content=_chunks(total))
        assert r.status_code == 201, r.text
        assert r.json()["size"] == total
        r = await http.post(url, content=b"again")
        assert r.status_code == 401
        assert r.json()["error"] == "invalid_ticket"

    (seen,) = stub.requests
    assert seen["path"] == "/uploads"
    assert seen["query"] == "filename=incident.pcap"
    assert seen["headers"]["authorization"] == "Bearer upstream-secret"
    assert ticket not in str(seen)


async def test_upload_url_tool_rejects_undeclared_routes(stub_setup):
    gateway, _, _ = stub_setup
    base = gateway.base_url
    token = await _token(base)
    async with _mcp_client(base, token) as client:
        names = {t.name for t in await client.list_tools()}
        assert "gateway_create_upload_url" in names
        for args, match in (
            ({"backend": "nope", "path": "/uploads"}, "Unknown or disabled"),
            ({"backend": "off", "path": "/uploads"}, "Unknown or disabled"),
            ({"backend": "plain", "path": "/uploads"}, "declares no passthrough path"),
            ({"backend": "stub", "path": "/other"}, "declares no passthrough path"),
            ({"backend": "stub", "path": "/uploads", "method": "PUT"}, "not allowed"),
        ):
            with pytest.raises(ToolError, match=match):
                await client.call_tool("gateway_create_upload_url", args)

    # DELETE is declared for /uploads, so a DELETE ticket is fine.
    minted = await _upload_url(base, token, method="delete")
    assert minted["method"] == "DELETE"


async def test_upload_ticket_invalid_expired_or_cross_backend(stub_setup):
    gateway, stub, _ = stub_setup
    base = gateway.base_url
    storage = gateway.app.state.storage
    storage.save_upload_ticket(
        "expired", backend="stub", path="/uploads", method="POST", expires_at=time.time() - 1
    )
    storage.save_upload_ticket(
        "for-stub", backend="stub", path="/uploads", method="POST", expires_at=time.time() + 60
    )
    async with httpx.AsyncClient() as http:
        for path in (
            "/backends/stub/t/does-not-exist",
            "/backends/stub/t/expired",
            "/backends/based/t/for-stub",  # bound to its backend
        ):
            r = await http.post(f"{base}{path}", content=b"x")
            assert r.status_code == 401, path
        # The cross-backend attempt didn't consume it.
        r = await http.post(f"{base}/backends/stub/t/for-stub", content=b"x")
        assert r.status_code == 201
    assert len(stub.requests) == 1


async def test_no_upload_tool_without_passthrough(gateway):
    server, _ = gateway
    async with _mcp_client(server.base_url, await _token(server.base_url)) as client:
        assert [t.name for t in await client.list_tools()] == ["gateway_status"]


def test_access_log_redacts_ticket():
    record = logging.LogRecord(
        "uvicorn.access",
        logging.INFO,
        __file__,
        1,
        '%s - "%s %s HTTP/%s" %d',
        ("127.0.0.1:1234", "POST", "/backends/stub/t/SeCrEt-TiCkEt?filename=a.pcap", "1.1", 201),
        None,
    )
    RedactTicketFilter().filter(record)
    message = record.getMessage()
    assert "SeCrEt-TiCkEt" not in message
    assert "/backends/stub/t/[redacted]?filename=a.pcap" in message
