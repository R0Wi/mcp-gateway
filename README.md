# MCP Gateway

A lightweight, self-hosted **MCP aggregator gateway**: one public MCP endpoint in front
of any number of protected backend MCP servers, with a **spec-compliant OAuth 2.1
authorization server facing the MCP client** — the piece most existing gateways are
missing.

```
Claude Code / Claude.ai ──OAuth 2.1 (DCR/CIMD + PKCE)──▶ MCP Gateway ──own credentials──▶ GitHub MCP
                                                          │                              ▶ Microsoft Learn MCP
                                                          └── /mcp (Streamable HTTP)      ▶ …more backends
```

Built with **FastAPI + FastMCP**, configured by a **single YAML file**, stores its state
in a single encrypted SQLite database, and ships as one small standalone container —
no reverse proxy required, though you can put one in front of it for TLS.

## Features

**Client-facing (MCP authorization spec, 2025-11-25):**

- OAuth 2.1 authorization code flow with mandatory **PKCE (S256)**
- **Dynamic Client Registration** (RFC 7591) at `/register` — `claude mcp add` works
  with no pre-shared credentials
- **Client ID Metadata Documents (CIMD)** — HTTPS URLs as client IDs, including
  `private_key_jwt` client authentication, advertised via
  `client_id_metadata_document_supported: true`
- **Authorization Server Metadata** (RFC 8414) + OIDC discovery alias
- **Protected Resource Metadata** (RFC 9728); 401 responses carry
  `WWW-Authenticate: Bearer resource_metadata="…"` as Claude's connector requires
- Resource indicators (RFC 8707) accepted and bound to issued tokens
- Short-lived opaque access tokens, **rotating refresh tokens**, single-use
  authorization codes — all stored **hashed**; client records encrypted at rest
- Loopback redirect URIs match **port-agnostically** (Claude Code CLI registers one
  port and authorizes with another); non-loopback URIs require exact registration
- Small **Svelte 5** login + consent UI (single local identity from the config file)

**Backend-facing:**

- `none` — public servers (e.g. Microsoft Learn MCP)
- `bearer` — static token injection (`Authorization: Bearer …`, e.g. PATs)
- `headers` — arbitrary static headers (API keys)
- `oauth` — full OAuth client per the MCP spec: metadata discovery, **CIMD when the
  upstream AS supports it** (the gateway hosts its own client metadata document),
  **DCR fallback**, PKCE, automatic token refresh. Connected once via the browser;
  tokens persisted encrypted (Fernet) in SQLite.
- The client's gateway token is **never** forwarded upstream (no token passthrough,
  as the spec demands); backends only ever see credentials the gateway holds.

**Aggregation:**

- Tools/resources/prompts namespaced per backend: `github_create_issue`,
  `msdocs_microsoft_docs_search`, …
- Live proxying over Streamable HTTP; a down or not-yet-connected backend only
  removes its own tools instead of breaking the gateway
- Built-in `gateway_status` tool

## Quick start

```bash
cp config.example.yaml config.yaml
$EDITOR config.yaml                                   # set public_url, users, backends
cp .env.example .env
$EDITOR .env                                           # set MCP_GATEWAY_ENCRYPTION_KEY (openssl rand -base64 32)
docker compose up -d
```

The gateway runs standalone and listens on `:8000`; `docker compose` picks up
`MCP_GATEWAY_ENCRYPTION_KEY` from `.env` automatically. Put it behind a reverse proxy of
your choice for TLS, or expose the port directly.

Generate a password hash for the config file:

```bash
docker compose run --rm mcp-gateway mcp-gateway hash-password
```

### Connect Claude Code (CLI)

```bash
claude mcp add --transport http gateway https://mcp.example.com/mcp
```

Claude Code discovers the gateway's authorization server, registers itself via DCR (or
uses its CIMD client ID), and opens your browser: log in with a user from
`config.yaml`, approve, done. No tokens to paste.

### Connect Claude.ai / Claude Code web (custom connector)

Add `https://mcp.example.com/mcp` as a custom connector. The browser redirect to
`https://claude.ai/api/mcp/auth_callback` goes through the same login/consent flow.

### Connect OAuth backends

Open `https://mcp.example.com/ui/backends`, sign in, and press **Connect** next to each
OAuth backend (e.g. GitHub MCP). You'll be redirected to the backend's authorization
server once; afterwards the gateway refreshes tokens automatically.

## Configuration

Everything lives in one YAML file (see [`config.example.yaml`](config.example.yaml)).
Values support `${ENV_VAR}` / `${ENV_VAR:-default}` expansion.

```yaml
server:
  public_url: https://mcp.example.com   # behind your reverse proxy

auth:
  encryption_key: ${MCP_GATEWAY_ENCRYPTION_KEY}   # encrypts secrets at rest
  users:
    - username: admin
      password_hash: "$2b$12$…"          # mcp-gateway hash-password
  access_token_expiry_seconds: 3600
  refresh_token_expiry_seconds: 2592000

storage:
  path: /data/gateway.db                 # SQLite; the only state

backends:
  github:                                # → tools namespaced github_*
    url: https://api.githubcopilot.com/mcp/
    auth:
      type: oauth
      # GitHub's authorization server supports neither CIMD nor DCR, so
      # register a GitHub OAuth App and provide its credentials directly:
      client_id: ${GITHUB_OAUTH_CLIENT_ID}
      client_secret: ${GITHUB_OAUTH_CLIENT_SECRET}
  microsoft-docs:                        # → tools namespaced microsoft-docs_*
    url: https://learn.microsoft.com/api/mcp
    auth: { type: none }
  something-with-a-pat:
    url: https://example.com/mcp
    auth: { type: bearer, token: "${SOME_PAT}" }
```

Adding a backend is config-only — no code changes.

### Backend auth reference

| type      | fields                          | behaviour                                                            |
| --------- | ------------------------------- | -------------------------------------------------------------------- |
| `none`    | –                               | no credentials sent                                                   |
| `bearer`  | `token`                         | `Authorization: Bearer <token>` on every request                      |
| `headers` | `headers: {Name: value}`        | static headers (API keys etc.)                                        |
| `oauth`   | `scopes`, `prefer_dcr`, `client_id`, `client_secret` | full OAuth client: CIMD → DCR fallback, PKCE, refresh, encrypted store |

For `oauth` backends the gateway hosts its own Client ID Metadata Document at
`<public_url>/oauth/client-metadata.json` and uses it as its client ID whenever the
upstream AS advertises CIMD support (requires an HTTPS `public_url`); otherwise it
falls back to Dynamic Client Registration. If the upstream AS supports neither (e.g.
GitHub's), set `client_id` (and `client_secret`, if the app is confidential) to use a
pre-registered OAuth client instead — CIMD/DCR are skipped entirely.

## Logging

The gateway logs to stdout/stderr (`docker logs`, `docker compose logs -f`), at `INFO` by
default: startup/shutdown, config summary, login attempts, OAuth authorize/consent/token
issuance, upstream backend connect/disconnect, and backend mount status. `DEBUG` adds
finer-grained detail (client construction, token rotation, CIMD refreshes, storage
housekeeping). No credentials or tokens are ever logged, at any level.

Set the level via the `MCP_GATEWAY_LOG_LEVEL` environment variable (`debug`, `info`,
`warning`, `error`, or `critical`):

```bash
# .env (picked up by docker compose)
MCP_GATEWAY_LOG_LEVEL=debug
```

```bash
# or inline
docker compose run --rm -e MCP_GATEWAY_LOG_LEVEL=debug mcp-gateway
```

`docker-compose.yml` already forwards this variable to the container, defaulting to
`info` when unset.

Outside Docker, `--log-level` on `mcp-gateway run` works the same way and takes
precedence over the env var:

```bash
mcp-gateway run -c config.yaml --log-level debug
```

## Endpoints

| Path                                          | Purpose                                        |
| --------------------------------------------- | ---------------------------------------------- |
| `/mcp`                                        | MCP endpoint (Streamable HTTP)                 |
| `/.well-known/oauth-protected-resource[/mcp]` | RFC 9728 protected resource metadata           |
| `/.well-known/oauth-authorization-server`     | RFC 8414 AS metadata (+ OIDC alias)            |
| `/authorize`, `/token`, `/register`, `/revoke`| OAuth 2.1 endpoints (PKCE, DCR, revocation)    |
| `/ui/authorize`                               | login + consent (Svelte 5)                     |
| `/ui/backends`                                | backend connection status / connect / disconnect |
| `/oauth/client-metadata.json`                 | the gateway's own CIMD document (upstream leg) |
| `/oauth/connect/<backend>`, `/oauth/callback` | upstream OAuth connect flow                    |
| `/healthz`                                    | liveness                                       |

## Security notes

- PKCE (S256) is mandatory; authorization codes are single-use and expire in 5 min.
- Refresh tokens rotate on every use (OAuth 2.1 public-client requirement).
- Access/refresh tokens and auth codes are stored as SHA-256 hashes only.
- Registered client records and upstream credentials are Fernet-encrypted at rest
  (`auth.encryption_key`; passphrases are stretched with scrypt + per-DB salt).
- The consent screen names the client and the exact redirect target, and warns on
  loopback redirects (CIMD localhost-impersonation guidance from the spec).
- Tokens issued to MCP clients are never forwarded to backends, and backend
  credentials never reach MCP clients.
- Sessions are signed (`itsdangerous`), `HttpOnly`, `SameSite=Lax`, `Secure` on HTTPS, and
  are revoked server-side on logout (not just cookie deletion).
- Login and Dynamic Client Registration (`/register`) are rate-limited per source IP;
  password checks run off the event loop so a flood of attempts can't stall the server.
- Anonymous DCR/CIMD client registrations that never complete an authorization are
  reclaimed after 24h; storage doesn't grow unbounded from unauthenticated `/register` traffic.
- Security headers (CSP, `X-Frame-Options: DENY`, `Referrer-Policy`, `X-Content-Type-Options`)
  are set on every response.
- `X-Forwarded-*` headers are trusted only from `server.trusted_proxy_ips` (default:
  loopback). Set this to your reverse proxy's address if you run one — see
  [Configuration](#configuration).
- No credentials are logged.

## Development

```bash
uv venv && uv pip install -e ".[dev]"     # or: pip install -e ".[dev]"
(cd ui && npm install && npm run build)   # build the Svelte UI
pytest                                    # 35 tests incl. full e2e OAuth flows
mcp-gateway run -c config.yaml
```

The test suite spins up real gateways (and a second instance acting as an
OAuth-protected upstream) and drives complete DCR/CIMD + PKCE flows over HTTP.

## Architecture

- `src/mcp_gateway/oauth_server.py` — the client-facing OAuth AS. Builds on the MCP
  SDK's authorization-server handlers and FastMCP's CIMD manager rather than
  hand-rolling protocol code; the gateway adds SQLite persistence, the login/consent
  transaction flow, and token issuance/rotation policy.
- `src/mcp_gateway/upstream.py` — backend clients. OAuth backends use the official
  SDK `OAuthClientProvider` (discovery, CIMD/DCR, refresh) with encrypted SQLite
  token storage and a browser-driven connect flow.
- `src/mcp_gateway/gateway.py` — FastMCP server; each backend is mounted as a live
  proxy under its namespace.
- `src/mcp_gateway/app.py` / `web.py` — FastAPI app: JSON API for the UI, upstream
  callback, CIMD document, static Svelte app; the FastMCP app (MCP endpoint + OAuth
  routes + well-known) is mounted at the root.
- `ui/` — Svelte 5 + Vite SPA (login, consent, backends).

Single-instance by design (SQLite + in-memory connect flows). Runs standalone; put it
behind a reverse proxy of your own if you want TLS termination, and back up one file.
