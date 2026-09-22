"""server.stateless_http: /mcp works without Mcp-Session-Id round-trips."""

from __future__ import annotations

import json

import httpx

from mcp_gateway.app import create_app
from mcp_gateway.config import GatewayConfig
from tests.conftest import free_port, gateway_config, obtain_tokens, register_client

MCP_HEADERS = {
    "Accept": "application/json, text/event-stream",
    "Content-Type": "application/json",
    "MCP-Protocol-Version": "2025-06-18",
}


def _config(port: int, stateless: bool) -> GatewayConfig:
    config = gateway_config(port)
    config.server.stateless_http = stateless
    return config


def _rpc_result(response: httpx.Response) -> dict:
    """Extract the JSON-RPC message from a JSON or single-event SSE response."""
    if response.headers["content-type"].startswith("application/json"):
        return response.json()
    data = [
        line.removeprefix("data:").strip()
        for line in response.text.splitlines()
        if line.startswith("data:")
    ]
    return json.loads(data[-1])


async def _token(http: httpx.AsyncClient, base: str) -> str:
    client_id = await register_client(http, base)
    return (await obtain_tokens(http, base, client_id))["access_token"]


def test_stateless_http_parses_env_style_strings():
    port = free_port()
    raw = gateway_config(port).model_dump()
    raw["server"]["stateless_http"] = "true"
    assert GatewayConfig.model_validate(raw).server.stateless_http is True
    assert gateway_config(port).server.stateless_http is False


async def test_stateless_mode_needs_no_session_id(run_server):
    port = free_port()
    server = run_server(create_app(_config(port, stateless=True)), port)
    base = server.base_url
    async with httpx.AsyncClient(timeout=10) as http:
        headers = {**MCP_HEADERS, "Authorization": f"Bearer {await _token(http, base)}"}

        r = await http.post(
            f"{base}/mcp",
            headers=headers,
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "pytest", "version": "0"},
                },
            },
        )
        assert r.status_code == 200, r.text
        assert "mcp-session-id" not in r.headers
        assert _rpc_result(r)["result"]["serverInfo"]["name"] == "MCP Gateway"

        # A follow-up call without any session header -- as a relay that
        # strips Mcp-Session-Id would send it -- is served normally.
        r = await http.post(
            f"{base}/mcp",
            headers=headers,
            json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        )
        assert r.status_code == 200, r.text
        assert "mcp-session-id" not in r.headers
        tools = {t["name"] for t in _rpc_result(r)["result"]["tools"]}
        assert "gateway_status" in tools

        # Auth is still enforced per request.
        r = await http.post(
            f"{base}/mcp",
            headers=MCP_HEADERS,
            json={"jsonrpc": "2.0", "id": 3, "method": "tools/list"},
        )
        assert r.status_code == 401


async def test_stateful_mode_rejects_missing_session_id(run_server):
    port = free_port()
    server = run_server(create_app(_config(port, stateless=False)), port)
    base = server.base_url
    async with httpx.AsyncClient(timeout=10) as http:
        headers = {**MCP_HEADERS, "Authorization": f"Bearer {await _token(http, base)}"}
        r = await http.post(
            f"{base}/mcp",
            headers=headers,
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        )
        assert r.status_code == 400, r.text
