"""Secrets in a backend URL's query string must never reach the logs."""

from __future__ import annotations

import logging

from fastmcp import FastMCP
from starlette.middleware.base import BaseHTTPMiddleware

from mcp_gateway.app import create_app
from mcp_gateway.diagnostics import strip_query
from mcp_gateway.log_redaction import StripUrlQueryFilter, strip_queries_in_text
from tests.conftest import free_port, gateway_config
from tests.test_aggregation import gateway_mcp_client

SECRET = "s3cr3t-api-key-value"


def make_query_key_backend(seen_keys: list):
    backend = FastMCP(name="query-key-backend")

    @backend.tool
    def echo(text: str) -> str:
        """Echo text back."""
        return f"echo: {text}"

    app = backend.http_app(path="/mcp")

    class RecordQueryKey(BaseHTTPMiddleware):
        async def dispatch(self, request, call_next):
            if request.url.path.startswith("/mcp"):
                seen_keys.append(request.query_params.get("api_key"))
            return await call_next(request)

    app.add_middleware(RecordQueryKey)
    return app


def test_strip_query():
    assert strip_query("http://h:8000/mcp?api_key=x&y=1#frag") == "http://h:8000/mcp"
    assert strip_query("https://h/mcp") == "https://h/mcp"


def test_strip_queries_in_text():
    text = f'GET http://h/a?api_key={SECRET} then "https://h2:1/b?x=1#f" and http://h3/c'
    assert strip_queries_in_text(text) == 'GET http://h/a then "https://h2:1/b" and http://h3/c'


def test_filter_redacts_url_args():
    record = logging.LogRecord(
        "httpx2",
        logging.INFO,
        __file__,
        1,
        'HTTP Request: %s %s "%s %d %s"',
        ("POST", f"http://h:8000/mcp?api_key={SECRET}", "HTTP/1.1", 401, "Unauthorized"),
        None,
    )
    assert StripUrlQueryFilter().filter(record)
    assert record.getMessage() == 'HTTP Request: POST http://h:8000/mcp "HTTP/1.1 401 Unauthorized"'


async def test_backend_url_query_secret_not_logged(run_server, caplog):
    caplog.set_level(logging.INFO)
    seen_keys: list = []
    backend = run_server(make_query_key_backend(seen_keys))

    port = free_port()
    config = gateway_config(
        port,
        backends={
            "keyed": {
                "url": f"{backend.base_url}/mcp?api_key={SECRET}",
                "auth": {"type": "none"},
            }
        },
    )
    gateway_server = run_server(create_app(config), port)

    client = await gateway_mcp_client(gateway_server.base_url)
    async with client:
        result = await client.call_tool("keyed_echo", {"text": "hi"})
        assert result.content[0].text == "echo: hi"

    # The secret is still sent upstream -- only the logs are redacted.
    assert seen_keys and all(k == SECRET for k in seen_keys)

    # Guard against a vacuous pass: both log sites actually fired.
    messages = [r.getMessage() for r in caplog.records]
    assert any(
        r.name == "httpx2" and f"{backend.base_url}/mcp" in r.getMessage() for r in caplog.records
    ), "no httpx2 request line for the backend was logged"
    assert any(m.startswith("Mounted backend keyed (") for m in messages)

    leaked = [f"{r.name}: {r.getMessage()}" for r in caplog.records if SECRET in r.getMessage()]
    assert not leaked, leaked
    assert SECRET not in caplog.text
