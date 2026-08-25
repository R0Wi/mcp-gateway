"""Regression tests for how /ui serves the built single-page app."""

from __future__ import annotations

import re

import httpx


async def test_missing_asset_404s_instead_of_falling_back_to_index(gateway):
    """A stale browser cache -- or a deploy where an old container still
    serves the previous build -- requests a content-hashed asset that no
    longer exists. Returning index.html for it (HTTP 200, text/html) makes
    the browser refuse the module/stylesheet with an opaque MIME-type error
    and renders a blank, unstyled page. It must 404 instead."""
    server, _ = gateway
    async with httpx.AsyncClient(timeout=30) as http:
        r = await http.get(f"{server.base_url}/ui/assets/index-DEADBEEF.js")
        assert r.status_code == 404
        assert "text/html" not in r.headers.get("content-type", "")

        r = await http.get(f"{server.base_url}/ui/favicon-gone.svg")
        assert r.status_code == 404


async def test_unknown_route_still_falls_back_to_index(gateway):
    """Client-side routes have no file extension and must keep serving the
    SPA entry point so deep links work on a hard refresh."""
    server, _ = gateway
    async with httpx.AsyncClient(timeout=30) as http:
        r = await http.get(f"{server.base_url}/ui/backends")
        assert r.status_code == 200
        assert "text/html" in r.headers["content-type"]


async def test_cache_headers(gateway):
    """index.html must be revalidated every time or a stale copy keeps
    pointing at asset names a newer build has already dropped; the hashed
    assets it names can be cached indefinitely."""
    server, _ = gateway
    async with httpx.AsyncClient(timeout=30) as http:
        r = await http.get(f"{server.base_url}/ui/")
        assert r.headers.get("cache-control") == "no-cache"

        asset = re.search(r'/ui/(assets/[^"\']+\.js)', r.text)
        assert asset, "index.html names no hashed JS asset -- is the UI built?"
        r = await http.get(f"{server.base_url}/ui/{asset.group(1)}")
        assert r.status_code == 200
        assert "javascript" in r.headers["content-type"]
        assert r.headers.get("cache-control") == "public, max-age=31536000, immutable"
