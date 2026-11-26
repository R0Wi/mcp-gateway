# Plan: per-user backends, managed in the UI, connected during MCP client sign-in

Status: proposed — not implemented.

## Motivation

Today the operator defines backends in `config.yaml`, an admin connects each OAuth backend
once via `/ui/backends`, and the gateway keeps it alive with refresh tokens. Problems:

1. **Backends and their credentials are global.** `DbTokenStorage` keys upstream tokens by
   backend name only, so every gateway user and every MCP client shares one upstream identity
   (e.g. one GitHub account). The gateway is single-user today, but should support several
   users, each with their own, fully separated backends.
2. **Adding a backend means editing a file and restarting.** Users should define and manage
   their backends themselves, in the UI, without operator involvement or a restart.
3. **Connecting is a separate, manual step.** The MCP client has to sign in to the gateway in a
   browser anyway; that is the natural moment to connect the backends too.
4. **A dead backend is silent.** When a backend's refresh token stops working, its tools quietly
   disappear. Nothing records the state (`backend_status()` still says `connected: true`
   because the token row exists), and nothing sends the user back to a browser — MCP clients
   hold 30-day refresh tokens and rarely re-run `/authorize`.

## Decisions

| Topic | Decision |
|---|---|
| Backend definitions | Live in the database, managed entirely in the UI. Each backend is **private to the user who created it**: nobody else sees it, its credentials, or its tools. |
| Auth types | All of today's types are configured in the UI per backend: `none`, bearer token, custom headers, OAuth (automatic CIMD/DCR, or a pre-registered `client_id`/`client_secret`, scopes, prefer-DCR). |
| `config.yaml` `backends:` | Removed, **no import**. Users re-add their backends in the UI once. Existing upstream tokens are dropped. |
| Changes at runtime | Adding, editing, disabling or deleting a backend takes effect without a restart. |
| Sign-in step | During MCP client sign-in, after login and before Approve, go through only the user's backends that are missing credentials or need re-auth, one at a time; each can be skipped. |
| Stale backend | Immediately invalidate that user's gateway tokens (401 on `/mcp`), so the client re-runs sign-in and the sign-in step. |
| Spec-native alternative | Investigate MCP URL-mode elicitation first (Phase 0). |
| Gateway users | Stay in `config.yaml` for now; managing users in the UI is out of scope. |
| Background refresh | Out of scope. Stale backends are detected on use. |

## Findings that shape the design

- `fastmcp` 4.2.x `ProxyProvider` / `FastMCPProxy` take a `client_factory` (sync or async)
  invoked **per request**. Inside it, `fastmcp.server.dependencies.get_access_token()` yields
  the caller's token, whose `subject` is the gateway username.
- `ProxyProvider` caches component lists (tools, resources, prompts) **across all sessions**,
  300 s by default. Per-user backends must never share that cache between users.
- Today each backend is mounted once at startup (`mcp.mount(proxy, namespace=name)`). With
  per-user, runtime-defined backends, the set of backends — and so the tool list — depends on
  who is calling. That needs one gateway-level provider that resolves the caller's backends per
  request (Phase 0 spike).
- The MCP SDK ships `UrlElicitationRequiredError` (code `-32042`). FastMCP does not reference
  it anywhere, so it is unknown whether it survives `mask_error_details=True` and the proxy
  path, in either protocol era.
- `access_tokens` and `refresh_tokens` already have a `subject` column, so revoking all of a
  user's gateway tokens is a single `DELETE`/`UPDATE` each.
- The SDK's `OAuthClientProvider` holds an internal lock for a whole interactive flow; one
  provider per backend row also stops one user's connect flow from blocking another's.

## Phases

### Phase 0 — spikes (time-boxed)

**a) Per-user dynamic provider.** Prove that one custom FastMCP provider mounted at the root can,
per request:
- resolve the caller's subject, load their enabled backends, and list each backend's tools under
  its namespace prefix (`<name>_<tool>`);
- route `tools/call` (and resources/prompts) to the right backend client;
- pick up a backend added or removed at runtime on the next request, in both protocol eras, and
  send `notifications/tools/list_changed` to that user's sessions where the era supports it;
- keep the component cache per backend row, never shared between users.

If the provider API can't do this cleanly, the fallback is building one `ProxyProvider` per
backend row and filtering visibility per session — less attractive because tool names of other
users' backends would exist on the server.

**b) URL elicitation.** Raise `UrlElicitationRequiredError` from a proxied tool call and check it
reaches the client as a JSON-RPC error with code `-32042` and intact `data`, despite
`mask_error_details=True`, in both eras; check what Claude Code and claude.ai do with it. The
outcome decides Phase 6: if it works end to end, a stale backend first answers with the
elicitation and the 401 becomes the fallback; otherwise the 401 is the only mechanism.

### Phase 1 — backend registry in the database

- **Migration `0003`** (hand-written, existence-guarded like `0002`):
  - new `backends` table: `id`, `owner` (subject), `name` (namespace; unique per owner),
    `url`, `enabled`, `auth_type`, non-secret settings (scopes, prefer-DCR, header names),
    encrypted secrets blob (bearer token, header values, OAuth `client_secret`),
    `created_at`, `updated_at`;
  - `upstream_data` rekeyed from backend name to `backend_id` (`ON DELETE CASCADE`);
    existing rows are deleted, since `config.yaml` backends are not imported.
- **Storage**: CRUD for backends, always scoped by owner — every query takes the subject, so a
  lookup of another user's backend returns "not found", never "forbidden".
- **Validation**: `name` matches `^[a-z0-9][a-z0-9-]{0,31}$`, `gateway` is reserved, URL must
  be `https://` (plain `http://` only when the gateway itself runs on `http://`, i.e. local
  dev); a configurable per-user backend limit (default 50).
- **Config**: drop `backends:` from the config schema and `config.example.yaml`. A config file
  that still has the section logs a warning naming the ignored backends and points to
  `/ui/backends`; it does not fail startup.
- `${ENV_VAR}` expansion no longer applies to backend secrets — they are entered in the UI and
  stored encrypted with the existing envelope encryption (KEK/DEK).
- `mcp-gateway check` no longer validates backends.

### Phase 2 — per-user, runtime routing

- Replace the startup `mount()` loop in `gateway.py` with the Phase 0a provider.
- **`BackendManager`** caches one FastMCP `Client` and, for OAuth, one `OAuthClientProvider`
  per backend row; an edit or delete invalidates (and closes) the cached entries.
- **OAuth**: `DbTokenStorage(backend_id)` holds tokens, `client_info` and `auth_metadata` per
  backend row — with private backends there is nothing left to share between users. The
  gateway's CIMD document and `/oauth/callback` stay single, gateway-wide endpoints.
- **`ConnectFlow`** keyed by backend id; `/oauth/callback` additionally checks the session user
  owns the flow's backend.
- **No-token-passthrough**: every backend client is built by one helper that always uses
  `NoForwardStreamableHttpTransport` and asserts it at build time (replacing the startup-only
  `_require_no_header_forwarding` loop, which has no backends to check any more). The
  `TransportOptions.forward_incoming_headers` existence check stays at startup. Never weaken or
  remove either check.
- **`BackendInstructionsMiddleware`**: cache per backend row; merge only the caller's backends.
- **`gateway_status`** reports the caller's backends only.
- Requests without a subject fail closed (no backends).

### Phase 3 — backend management UI and API

- **JSON API** under `/auth/api/backends` (session required, all owner-scoped): list, create,
  update, delete, enable/disable, test connection, connect/disconnect (existing endpoints move
  from backend name to backend id).
  - Secrets are **write-only**: responses say whether a secret is set, never return it. An
    update with an omitted secret keeps the stored one.
  - Mutating endpoints require `Content-Type: application/json` (no simple-form CSRF), in
    addition to the `SameSite=Lax` session cookie.
  - Delete drops tokens and registration data; best-effort RFC 7009 revocation upstream when
    the AS advertises a revocation endpoint.
- **UI** (`Backends.svelte`): list with status (connected / needs re-auth / not connected /
  disabled); add/edit form with name, URL, enabled, and an auth type selector:
  - *None*
  - *Bearer token* — token field
  - *Custom headers* — name/value rows
  - *OAuth* — automatic (CIMD or DCR, optional scopes, prefer DCR), or pre-registered client
    (`client_id`, `client_secret`, scopes) with the callback URL shown for copying
  - "Test connection" works on unsaved form values before saving.
- **Outbound URL policy (SSRF)**: any user can now make the gateway send requests to an
  arbitrary URL — the backend URL itself, plus OAuth discovery, registration and token URLs it
  learns from metadata. By default, block loopback, link-local (incl. cloud metadata
  `169.254.169.254`), private and unique-local ranges, checked on the **resolved IP at connect
  time** (DNS rebinding), applied to all backend and upstream-OAuth HTTP clients. An operator
  setting in `config.yaml` allows specific hosts/CIDRs (e.g. a Docker network) or turns the
  check off for a single-user deployment.

### Phase 4 — stale-state tracking

- Persist per backend row: `connected | needs_reauth (since, reason) | not_connected`.
- Only a **real auth failure** counts: for OAuth, `invalid_grant` or 401 on the refresh request
  (via the existing `_handle_refresh_response` override) and the 401 → interactive path that
  ends in `redirect_handler` with no flow; for bearer/headers, a 401/403 from the backend. A
  5xx, a timeout or a network error must **not** mark a backend stale (it would sign the user
  out for an upstream outage). Verify how the SDK routes transient refresh failures before
  relying on `redirect_handler` as a signal.
- Cleared on a successful connect or credential update.

### Phase 5 — connect backends during client sign-in

- `describe_txn` (or `/auth/api/txn/{id}/backends`) returns the logged-in user's enabled
  backends that are `not_connected` or `needs_reauth`.
- `Authorize.svelte`, after login and before consent, goes through them one at a time:
  - OAuth: `/oauth/connect/<id>` → upstream AS → `/oauth/callback` → back to
    `/ui/authorize?txn=…`;
  - bearer/headers: an inline form to enter or replace the credential;
  - every step has **Skip**; Approve is reachable once each backend is connected or skipped;
  - a link to add a new backend is out of scope for this page — the sign-in step only fixes
    existing ones.
- `ConnectFlow` stores `return_txn` **on the server**; the callback redirects there instead of
  `/ui/backends`. Never take the return target from a query parameter (open redirect).
- Extend the transaction TTL (600 s today) on each step, so several upstream logins fit.

### Phase 6 — forced re-auth (immediate 401)

- When a backend changes **from healthy to `needs_reauth`**, delete its owner's access tokens
  and revoke their refresh tokens. The next `/mcp` request gets 401, the client's refresh gets
  `invalid_grant`, and the client runs a full `/authorize`, which shows the stale backend in the
  Phase 5 sign-in step.
- Revocation fires **only on that change from healthy to stale**. That prevents a loop: a user
  who skips the backend gets fresh tokens that stay valid, and a backend that was never
  connected never triggers revocation.
- The tool call that hits the failure is already inside an MCP response and can't become an
  HTTP 401; it returns a clear "backend X needs re-authorization" error — or the URL
  elicitation, if Phase 0b says yes.
- Accepted cost: all of that user's clients are signed out, headless ones included, until the
  user goes through the browser again. Other users are unaffected.

### Phase 7 — tests and docs

- **Test fixtures**: `conftest.py` and existing tests define backends through `config.yaml`;
  they move to creating backends through the storage layer or the new API. Expect broad churn
  in the test suite — do it in the same PR as Phase 1/2 so the suite stays green.
- E2E tests over real HTTP, using the existing "second gateway as OAuth upstream" fixture:
  - backend CRUD; secrets never returned by the API or written to logs
  - two users: user A cannot list, read, edit, test, connect, or call user B's backends or
    tools (404, not 403); component caches not shared
  - add a backend at runtime → its tools appear without restart; delete → tools gone, tokens
    and registration deleted
  - each auth type end to end, including pre-registered OAuth client
  - outbound URL policy blocks loopback/private/metadata targets, including via a redirect or
    an OAuth metadata URL, and honours the operator allowlist
  - sign-in step connects a backend; Skip works; transaction TTL extension
  - healthy → stale → 401 → re-auth → working again; no loop after Skip
  - a transient upstream error (5xx / timeout) does **not** sign the user out
  - migration `0003`: old `upstream_data` rows removed, a `config.yaml` with `backends:` starts
    with a warning
- **README**: backends are managed in the UI; multi-user model; sign-in step; forced re-auth and
  the headless-client caveat; outbound URL policy; endpoint table.
- **CLAUDE.md**: replace "Adding a backend is config-only" with the UI model; new invariants —
  every backend query is owner-scoped; no cross-user component cache; backend clients only
  built by the one helper; outbound URL policy applies to every backend-facing HTTP client.

## Open risks

- **Headless clients** (scheduled agents, CI) cannot complete an interactive sign-in; forced
  re-auth leaves them without any backend until a human signs in.
- **Detection on use only**: without background refresh, a stale backend is noticed when the
  user next calls one of its tools.
- **SSRF surface**: user-supplied URLs are the biggest new attack surface; the outbound policy
  must cover OAuth metadata-derived URLs and redirects, not only the backend URL.
- **Breaking upgrade**: existing `config.yaml` backends stop working until re-added in the UI.
- **Single-instance**: connect flows and the per-backend client/provider caches are in memory,
  consistent with the gateway's single-process design.
