# Plan: per-user backends, connected during MCP client sign-in

Status: proposed — not implemented.

## Motivation

Today an admin connects each OAuth backend once via `/ui/backends`, and the gateway keeps it
alive with refresh tokens. Three problems with that:

1. **Backend credentials are global.** `DbTokenStorage` keys upstream tokens by backend name
   only, so every gateway user and every MCP client shares one upstream identity (e.g. one
   GitHub account). The gateway is single-user today, but should support several users, each
   with their own, isolated backend accounts.
2. **Connecting is a separate, manual step.** The MCP client has to sign in to the gateway in
   a browser anyway; that is the natural moment to connect the backends too.
3. **A dead backend is silent.** When a backend's refresh token stops working, the backend's
   tools quietly disappear. Nothing records the state (`backend_status()` still says
   `connected: true` because the token row exists), and nothing sends the user back to a
   browser — MCP clients hold 30-day refresh tokens and rarely re-run `/authorize`.

## Decisions

| Topic | Decision |
|---|---|
| Identity | Per-user backend credentials, isolated between gateway users. |
| Sign-in step | During MCP client sign-in, after login and before Approve, go through only the backends that are missing or need re-auth, one at a time; each can be skipped. |
| Stale backend | Immediately invalidate the user's gateway tokens (401 on `/mcp`), so the client re-runs sign-in and the sign-in step. |
| Spec-native alternative | Investigate MCP URL-mode elicitation first (Phase 0). |
| Existing global tokens | Migration assigns them to the user if exactly one is configured; otherwise drops them and logs that users must reconnect. |
| Static-credential backends | Support per-user static credentials (user enters their own API key / token). Operator-configured shared credentials remain available. |
| Background refresh | Out of scope. Stale backends are detected on use. |

## Findings that shape the design

- `fastmcp` 4.2.x `ProxyProvider` / `FastMCPProxy` take a `client_factory` (sync or async)
  invoked **per request**. Inside it, `fastmcp.server.dependencies.get_access_token()` yields
  the caller's token, whose `subject` is the gateway username. So per-user routing needs no
  fork of FastMCP.
- `ProxyProvider` caches component lists (tools, resources, prompts) **across all sessions**,
  300 s by default. With per-user credentials that would show one user's backend tool list to
  another. Per-user backends must use `cache_ttl=0` (or a per-subject cache).
- The MCP SDK ships `UrlElicitationRequiredError` (code `-32042`). FastMCP does not reference
  it anywhere, so it is unknown whether it survives `mask_error_details=True` and the proxy
  path, in either protocol era.
- `access_tokens` and `refresh_tokens` already have a `subject` column, so revoking all of a
  user's gateway tokens is a single `DELETE`/`UPDATE` each.
- The SDK's `OAuthClientProvider` holds an internal lock for a whole interactive flow; one
  provider per `(backend, subject)` also stops one user's connect flow from blocking another's.

## Phases

### Phase 0 — URL-elicitation spike (time-boxed)

Find out whether a tool call can answer "open this URL to (re)connect backend X" instead of
signing the whole client out.

- Raise `UrlElicitationRequiredError` from a proxied tool call and check it reaches the client
  as a JSON-RPC error with code `-32042` and intact `data`, despite `mask_error_details=True`,
  in both the handshake era and `2026-07-28`.
- Check what Claude Code and claude.ai do with it (open the URL? retry?).
- Outcome decides Phase 4: if it works end to end, a stale backend first answers with the
  elicitation, and the 401 becomes the fallback; if not, the 401 is the only mechanism.

### Phase 1 — per-user backend credentials (base for everything else)

- **Migration `0003`** (hand-written, existence-guarded like `0002`): add `subject` to
  `upstream_data` and include it in the uniqueness key. User-specific rows (`tokens`, per-user
  static credentials) carry a subject; gateway-level rows (`client_info` from DCR/CIMD,
  `auth_metadata`) keep `subject = ''` — they are the gateway's own registration with the
  upstream AS and stay shared.
  - Existing `tokens` rows: if exactly one user is configured, assign to them; otherwise
    delete and log a warning that users must reconnect. The migration has no config access,
    so this step runs in startup code (or `mcp-gateway migrate`) after Alembic, not in the
    revision itself.
- **Storage / `DbTokenStorage`**: take `(backend, subject)`; `get/save/delete_upstream` grow a
  subject parameter.
- **`BackendManager`**: cache OAuth providers per `(backend, subject)`; key `ConnectFlow` by
  `(backend, subject)`; `/oauth/callback` additionally checks the session user equals the
  flow's subject. `disconnect`, `backend_status`, `test_connection` become per-user.
- **`gateway.py`**: mount per-user backends with a per-request async factory that resolves the
  subject and returns that user's client, with `cache_ttl=0`. Requests without a subject
  fail closed. Backends with operator-configured shared credentials (`none` / `bearer` /
  `headers`) keep today's single shared client.
- **No-token-passthrough check**: `_require_no_header_forwarding` today inspects one client per
  backend at startup. Extend it to cover clients the factory produces (build them only through
  one helper that always uses `NoForwardStreamableHttpTransport`, and assert on its output).
  Never weaken or remove the check.
- **`BackendInstructionsMiddleware`**: cache per subject for per-user backends.
- **Per-user views**: `/ui/backends`, `gateway_status`, test-connection and disconnect show the
  logged-in user's own state.
- **Cleanup**: on startup, drop per-user rows whose subject is no longer a configured user.

### Phase 2 — stale-state tracking

- Persist per `(backend, subject)`: `connected | needs_reauth (since, reason) | not_connected`.
- Only a **real auth failure** counts: `invalid_grant`, or 401 on the refresh request,
  recorded through the existing `_handle_refresh_response` override, and the 401 → interactive
  path that ends in `redirect_handler` with no flow. A 5xx, a timeout or a network error must
  **not** mark a backend stale (it would sign the user out for an upstream outage). Verify how
  the SDK routes transient refresh failures before relying on `redirect_handler` as a signal.
- For per-user static credentials: a 401/403 from the backend marks it `needs_reauth`.
- Cleared on a successful connect / credential save.
- Shown in `/ui/backends` and `gateway_status`.

### Phase 3 — connect backends during client sign-in

- `describe_txn` (or a new `/auth/api/txn/{id}/backends`) returns the logged-in user's
  backends that are `not_connected` or `needs_reauth`.
- `Authorize.svelte`, after login and before consent, goes through them one at a time:
  - OAuth backend: `/oauth/connect/<b>` → upstream AS → `/oauth/callback` → back to
    `/ui/authorize?txn=…`.
  - Per-user static backend: an inline form for the key/token.
  - Every step has **Skip**; Approve is reachable once each backend is connected or skipped.
- `ConnectFlow` stores `return_txn` **on the server**; the callback redirects there instead of
  `/ui/backends`. Never take the return target from a query parameter (open redirect).
- Extend the transaction TTL (600 s today) on each step, so several upstream logins fit.
- `/ui/backends` stays for connecting backends outside the sign-in flow.

### Phase 4 — forced re-auth (immediate 401)

- When a `(backend, subject)` changes **from healthy to `needs_reauth`**, delete that user's
  access tokens and revoke their refresh tokens. The next `/mcp` request gets 401, the
  client's refresh gets `invalid_grant`, and the client runs a full `/authorize`, which shows
  the stale backend in the Phase 3 sign-in step.
- Revocation fires **only on that change from healthy to stale**. That is what prevents a
  loop: a user who skips the backend gets fresh tokens that stay valid, and a backend that was
  never connected never triggers revocation.
- The tool call that hits the failure is already inside an MCP response and can't become an
  HTTP 401; it returns a clear "backend X needs re-authorization" error — or the URL
  elicitation, if Phase 0 says yes.
- Accepted cost: all of that user's clients are signed out, headless ones included, until the
  user goes through the browser again. Other users are unaffected.

### Phase 5 — per-user static credentials

- Config: a backend opts in, e.g.
  ```yaml
  backends:
    some-api:
      url: https://api.example.com/mcp
      auth:
        type: user_bearer          # or user_headers
        # user_headers: header names the user fills in, e.g. ["X-Api-Key"]
  ```
  Operator-configured `bearer` / `headers` keep working as shared credentials.
- Users enter values in `/ui/backends` or in the sign-in step; stored encrypted in
  `upstream_data` under their subject. Never logged.
- Per-request factory builds the client with that user's headers.

### Phase 6 — tests and docs

- E2E tests over real HTTP, using the existing "second gateway as OAuth upstream" fixture:
  - two users: isolated tokens, isolated tool lists (proxy cache not shared)
  - sign-in step connects a backend; Skip works; transaction TTL extension
  - healthy → stale → 401 → re-auth → working again
  - no loop after Skip
  - a transient upstream error (5xx / timeout) does **not** sign the user out
  - migration: one user → tokens assigned; several users → dropped with warning
  - per-user static credentials round-trip and are never logged
  - `/oauth/callback` rejects a session user different from the flow's subject
- README: multi-user model, sign-in step, forced re-auth behaviour, headless-client caveat.
- CLAUDE.md invariants: no cross-user credential use; no shared proxy component cache for
  per-user backends; the factory is the only way to build per-user backend clients.

## Open risks

- **Headless clients** (scheduled agents, CI) cannot complete an interactive sign-in; forced
  re-auth leaves them without any backend until a human signs in.
- **Detection on use only**: without background refresh, a stale backend is noticed when the
  user next calls one of its tools.
- **Single-instance**: connect flows and the per-subject client/provider caches are in memory,
  consistent with the gateway's single-process design.
- **Memory**: one OAuth provider per `(backend, subject)` — fine for a handful of users.
