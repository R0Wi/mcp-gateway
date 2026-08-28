#!/bin/bash
set -euo pipefail

# Only needed in Claude Code on the web -- a local dev machine already has
# its own browsers and doesn't run our MCP servers in a fresh container.
if [ "${CLAUDE_CODE_REMOTE:-}" != "true" ]; then
  exit 0
fi

# The Playwright MCP server (see .mcp.json) is configured with
# `--browser chromium` so it uses Playwright's own managed Chromium instead
# of requiring a system-installed Google Chrome (which this container
# doesn't have). Make sure that browser is actually present.
#
# `@playwright/mcp` pins its own `playwright`/`playwright-core` version,
# which can (and does) lag or lead the plain `playwright` package's latest
# -- and each version expects a specific, differently-numbered browser
# build. Installing via the bare `playwright` CLI can silently fetch the
# wrong revision. Resolve the version @playwright/mcp@latest actually
# depends on and install a matching browser for it; this is idempotent
# (a no-op if that revision is already cached), and follows whatever
# revision @playwright/mcp needs release to release instead of hardcoding
# a version or a browser path tied to this container.
pw_version="$(npm view @playwright/mcp@latest dependencies.playwright 2>/dev/null || true)"

# Run from outside the repo -- there's no reason to touch this repo's own
# node_modules for a browser download that's unrelated to it. (npx/playwright
# still prints its generic "did you forget npm install?" warning below
# regardless of cwd; it's expected here since this repo doesn't itself
# depend on playwright, and is harmless -- installation still succeeds.)
(
  cd /tmp
  if [ -n "$pw_version" ]; then
    npx --yes "playwright@${pw_version}" install chromium
  else
    # Fallback if the registry lookup above fails for some reason.
    npx --yes playwright install chromium
  fi
)
