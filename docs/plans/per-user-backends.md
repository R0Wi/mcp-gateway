# Plan: per-user backends, managed in the UI, connected during MCP client sign-in

Status: proposed. Everything before `## Phases` is the specification; `## Phases` onward is the
implementation plan.

## Motivation

Today the operator defines backends in `config.yaml`. An admin connects each OAuth backend once via
`/ui/backends`, and the gateway renews the upstream access token with the stored refresh token.
Problems:

1. **All users share one set of backends and one upstream identity.** `config.yaml` can define
   several gateway users (`auth.users` is a list), but `DbTokenStorage` keys upstream tokens by
   backend name only. Every user and every MCP client therefore acts upstream as the same account,
   for example one GitHub account. Each user should have their own backends, credentials and tools.
2. **Adding a backend means editing a file and restarting.** Users should define and manage their own
   backends in the UI, without the operator and without a restart.
3. **Connecting is a separate, manual step.** The MCP client already opens a browser to sign in to
   the gateway. Connecting backends during that same browser visit removes the separate step.
4. **A stale backend gives no signal.** A backend is *stale* when the upstream rejects its credential
   (defined exactly under Decisions). A stale backend's tools drop out of the tool list with no
   error. Nothing records the state: `backend_status()` reports `connected: true` because the token
   row still exists. Nothing sends the user back to a browser either: gateway refresh tokens rotate
   on every use with a fresh lifetime (30 days by default, `refresh_token_expiry_seconds`), so an
   active client may never re-run `/authorize`.

## Goals and non-goals

Goals:

- Each gateway user has private backends. No other gateway user can see, use or change them, their
  credentials, or their tools.
- Users add, edit, disable and delete backends in the UI. Changes apply on the next request, without
  a restart.
- MCP client sign-in offers to connect each of the user's backends that has no credentials or is
  stale.
- A stale backend is recorded as stale, and the user is led back to a browser to fix it.

Non-goals:

- Managing gateway users in the UI. Users stay in `config.yaml`.
- Background refresh of upstream tokens. Staleness is detected when a request reaches the backend.
- Adding a new backend from the sign-in page. The sign-in step only fixes existing backends.
- Running more than one gateway process (see Risks and mitigations).

Scale: a handful of users with up to 50 backends each. All clients, OAuth providers and component
lists are held in memory in one process. A backend row's cached entries are closed when the row is
edited, disabled or deleted.

## Decisions

| Topic | Decision |
|---|---|
| Backend definitions | Stored in the database and managed in the UI. Each backend is **private to the user who created it**: no other gateway user sees it, its credentials, or its tools. |
| Auth types | Every existing type is configurable per backend in the UI: none; bearer token; custom headers; OAuth with automatic registration (Client ID Metadata Document (CIMD) or Dynamic Client Registration (DCR), optional scopes, `prefer_dcr`) or with a pre-registered `client_id` and `client_secret`. |
| `config.yaml` `backends:` | **Removed, with no import.** Users re-add their backends in the UI. Migration `0003` deletes existing upstream tokens. A config file that still has the section starts, with a warning that names the ignored backends. |
| Changes at runtime | Adding, editing, disabling or deleting a backend takes effect on the next request, without a restart. |
| User lifecycle | A backend's `owner` is the gateway username. At startup the gateway deletes the backends, upstream credentials and gateway tokens of every owner no longer in `auth.users`, and logs a warning naming them. Removing a user therefore removes their data, and adding the same username later starts empty. The gateway also rejects a gateway token whose subject is no longer configured. |
| Stale | The upstream rejected the credential itself. For OAuth: the refresh grant returns `invalid_grant` or 401, on a confirming refresh attempt made after the failure. For bearer and header backends: a 401, or a 403 whose `WWW-Authenticate` header carries `error="invalid_token"`. A plain 403, a 5xx, a timeout or a network error is **not** stale. |
| Sign-in step | During MCP client sign-in, after login and before the consent page, the user is offered each of their enabled backends that is stale, or not connected and not skipped before, one at a time. Each can be skipped. A skip is remembered until that backend's settings or credentials change. |
| Response to a stale backend | When a backend changes from connected to stale, the gateway revokes all of that user's gateway tokens. Every client of that user gets 401 on `/mcp` and re-runs sign-in, which offers the stale backend. **Accepted cost:** all of that user's clients are signed out, headless ones included, until the user signs in through a browser again. Other users are unaffected. If the Phase 0b spike shows that URL elicitation or step-up authorization reaches the client, that becomes the first response, and revocation the fallback for clients that do not support it. |
| Background refresh | Out of scope (see Non-goals). |

## Proposed architecture

Components:

- **`backends` table**: one row per backend, holding owner, name, URL, enabled flag, auth type,
  non-secret settings, encrypted secrets, and stale state. Every query takes the owner.
- **Per-user root provider**: one FastMCP provider mounted at the root. On each request it reads the
  caller's subject from the gateway token, loads that user's enabled backend rows, lists each
  backend's components under the `<name>_` prefix, and routes calls to the right backend. A request
  without a subject sees no backends.
- **`BackendManager`**: caches, per backend row, one FastMCP `Client`, one `OAuthClientProvider` for
  OAuth rows, and the row's component list. Editing, disabling or deleting a row closes and drops
  its entries. No cache is keyed by anything wider than one row.
- **Backend client factory**: the one place that builds backend clients and backend-facing HTTP
  clients. It always uses `NoForwardStreamableHttpTransport`, so the MCP client's gateway token is
  never forwarded to a backend, and it applies the outbound URL policy. Every backend-facing HTTP
  request goes through it, including OAuth discovery, registration, token and revocation requests.
- **Stale-state tracking**: `BackendManager` records each auth outcome on the row. The change from
  connected to stale is an atomic update in SQL, and that change triggers token revocation.
- **Sign-in step**: `Authorize.svelte` and the `web.py` JSON API. A `ConnectFlow` (the server-side
  state of one upstream OAuth connect) is keyed by backend id and stores the sign-in transaction to
  return to.

Request flows:

1. **Tool call on `/mcp`**: gateway token → subject → caller's enabled backend rows → the row's
   cached client → upstream.
2. **Client sign-in**: `/authorize` → login → for each offered backend, an upstream connect (or a
   credential form) or Skip → consent → authorization code to the client.

Per-user isolation is enforced in three places: owner-scoped storage queries (another user's backend
is "not found"), per-row caches, and the ownership check on `/oauth/callback`.

If the Phase 0a spike shows the provider API cannot resolve backends per request cleanly, plan B is
one FastMCP sub-server per user. It is built on first request with today's `mount()` code, cached by
subject, and rebuilt when that user's backends change. Filtering one shared server's tools per
session is not acceptable (see Alternatives considered).

## Alternatives considered

| Alternative | Outcome | Reason |
|---|---|---|
| One `ProxyProvider` per backend row on one shared server, with per-session filtering | Rejected | `ProxyProvider`'s component cache is shared across all sessions and filtering is applied afterwards. A filtering bug would expose another user's tools, and every user's tool names would exist on the server, which contradicts the privacy decision. |
| One FastMCP sub-server per user | Plan B for Phase 0a | Reuses today's mount code and isolates caches by construction. Costs memory per active user, and a rebuild drops that user's warm caches. |
| Shared, operator-defined backends with per-user credentials | Rejected | Every new backend still needs the operator and a restart (problem 2). |
| Signal a stale backend only with a tool error, a `gateway_status` flag and a UI badge | Used alongside revocation, not instead of it | An active client may never re-run `/authorize` (problem 4), so a message alone does not reliably get the user back to a browser. |
| URL elicitation or step-up authorization | Under test in Phase 0b | Would reach only the client that touched the stale backend and leave other clients signed in. Depends on client support. |
| Background refresh | Deferred | Would detect staleness before use, but needs a periodic job per backend row and still relies on the sign-in step to fix the backend. |

## Risks and mitigations

| Risk | Impact | Mitigation or acceptance |
|---|---|---|
| SSRF: any user can make the gateway send requests to any URL, including URLs learned from OAuth metadata and redirects | Access to internal services and cloud metadata | Outbound URL policy in the backend client factory. It blocks loopback, link-local, private and unique-local addresses, checked on the IP actually connected to, and the operator can allowlist hosts and networks (Phase 3). Local development against `http://localhost` needs an allowlist entry. |
| One user's tools or credentials reach another user | Privacy breach | Owner-scoped queries, per-row caches, callback ownership check; two-user end-to-end tests (Phase 7). |
| User-entered secrets stored in the database | A stolen database exposes upstream credentials | Existing envelope encryption; secrets are write-only in the API and never logged. |
| The operator cannot see users' backends in the UI | Less oversight of which URLs users register | Accepted. The outbound URL policy bounds what users can reach, and backend URLs are visible in the database and logs. |
| Forced sign-out of all of a user's clients | Headless clients lose access until the user signs in again | Accepted (Decisions). Fires only on the change from connected to stale, and the stale definition excludes transient errors. URL elicitation or step-up authorization comes first if Phase 0b allows. |
| A transient upstream error is taken as stale | Needless sign-out | The stale definition excludes plain 403, 5xx, timeouts and network errors, and OAuth needs a confirming refresh attempt. |
| The MCP client's own authorization timeout | Sign-in fails if several upstream logins take too long | The gateway extends its own transaction on each step. Client-side limits cannot be extended; Phase 0c measures them for Claude Code and claude.ai. Every step can be skipped. |
| Open redirect on the connect callback | Phishing | The return transaction is stored on the server, never taken from a query parameter. |
| Breaking upgrade | Existing backends and upstream tokens are gone. In a multi-user deployment each user re-adds their own copy, which can duplicate upstream registrations | Startup warning naming the ignored backends; upgrade notes in the README. |
| Single process | Connect flows and caches are in memory | Accepted; the gateway is single-instance by design. |

## Findings that shape the design

Checked against fastmcp 4.2.6, MCP SDK 2.3.0, and this repository.

- `ProxyProvider` (`fastmcp/server/providers/proxy.py`) takes a `client_factory` and calls it each
  time it needs a backend connection. During a request, `fastmcp.server.dependencies.get_access_token()`
  returns the caller's token, whose `subject` is the gateway username.
- `ProxyProvider` caches component lists across all sessions, for 300 s by default (`cache_ttl`), and
  applies per-session visibility and auth filtering after the cache lookup.
- Today each backend is mounted once at startup (`gateway.py`, `mcp.mount(proxy, namespace=name)`),
  so every caller sees the same tool list.
- The MCP SDK defines `UrlElicitationRequiredError` with code `-32042`
  (`mcp/shared/exceptions.py`). fastmcp 4.2.6 does not reference it, so it is unknown whether it
  survives `mask_error_details=True` and the proxy path. The gateway serves two MCP protocol eras
  side by side: the sessionless `2026-07-28` revision, and the earlier revisions that open with an
  `initialize` handshake. The spikes must cover both.
- Access tokens are looked up in the database on every request (`load_access_token`), and
  `access_tokens` and `refresh_tokens` both have a `subject` column. Deleting a user's access tokens
  and revoking their refresh tokens takes one statement per table and applies on the next request.
  The column is nullable and has no index; every token issued through sign-in has a subject
  (`complete_authorization`), and migration `0003` adds the index.
- Today a gateway token keeps working after its user is removed from `config.yaml`:
  `load_access_token` does not check that the subject is still configured.
- The SDK's `OAuthClientProvider` holds an internal lock for the whole of an interactive flow. A
  provider shared by several users would make each user's connect flow wait for the others', so
  there is one provider per backend row. Within one user, an abandoned connect flow still blocks
  that backend until `CONNECT_FLOW_TIMEOUT_SECONDS` (300 s), so Skip and leaving the sign-in step
  must cancel the flow.
- The SDK's 401 handler starts an interactive flow without trying the refresh grant
  (see the `_initialize` docstring in `upstream.py`). A request for an interactive flow is therefore
  not proof on its own that a credential is dead.

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

Exit criteria: all four points hold in both protocol eras. If they don't, use plan B, one FastMCP
sub-server per user (see Proposed architecture). Filtering one shared server's tools per session
is not an option (see Alternatives considered).

**b) URL elicitation.** Raise `UrlElicitationRequiredError` from a proxied tool call and check it
reaches the client as a JSON-RPC error with code `-32042` and intact `data`, despite
`mask_error_details=True`, in both eras; check what Claude Code and claude.ai do with it. Also
test step-up authorization: answer a call to a stale backend's tool with HTTP 403
`insufficient_scope` before dispatch, and check whether Claude Code and claude.ai re-run
`/authorize`. The outcome decides Phase 6: if either works end to end, a stale backend first
answers with it and revocation becomes the fallback for clients that don't support it; otherwise
revocation is the only mechanism.

**c) Client tolerance for a long sign-in.** Measure how long Claude Code and claude.ai wait between
redirecting to `/authorize` and receiving the authorization code, and whether that limit allows two
upstream logins inside one sign-in. The result bounds how many backends the Phase 5 step can
usefully offer.

### Phase 1 — backend registry in the database

- **Migration `0003`** (hand-written, existence-guarded like `0002`):
  - new `backends` table: `id`, `owner` (subject), `name` (namespace; unique per owner),
    `url`, `enabled`, `auth_type`, non-secret settings (scopes, prefer-DCR, header names),
    encrypted secrets blob (bearer token, header values, OAuth `client_secret`),
    `created_at`, `updated_at`;
  - `upstream_data` rekeyed from backend name to `backend_id` (`ON DELETE CASCADE`);
    existing rows are deleted, since `config.yaml` backends are not imported;
  - an index on `subject` in `access_tokens` and `refresh_tokens`.
- **User lifecycle**: at startup, delete the backends (and through the cascade their upstream
  credentials) and the gateway tokens of every owner or subject not in `auth.users`, and log a
  warning naming them. `load_access_token` rejects a token whose subject is not a configured user.
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
- **UI** (`Backends.svelte`): list with status (connected / stale / not connected /
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

- Persist per backend row: `connected | stale (since, reason) | not_connected`, plus a
  `skipped` flag for the Phase 5 step.
- Mark a row stale only as the Decisions table defines it:
  - OAuth: on a refresh failure (via the existing `_handle_refresh_response` override), or when
    the 401 → interactive path ends in `redirect_handler` with no flow, make one confirming
    refresh-grant attempt through the same provider. Stale only if that returns `invalid_grant`
    or 401. The SDK's 401 handler skips the refresh grant, so `redirect_handler` alone is not
    proof.
  - Bearer/headers: a 401, or a 403 whose `WWW-Authenticate` header carries
    `error="invalid_token"`.
  - A plain 403, a 5xx, a timeout or a network error never marks a row stale (it would sign the
    user out for an upstream outage).
- The change from `connected` to `stale` is one atomic `UPDATE … WHERE state = 'connected'`, so
  concurrent failures trigger Phase 6 at most once.
- Cleared on a successful connect or credential update; that also clears `skipped`.

### Phase 5 — connect backends during client sign-in

- `describe_txn` (or `/auth/api/txn/{id}/backends`) returns the logged-in user's enabled
  backends that are `stale`, or `not_connected` and not `skipped`. (`describe_txn` describes a
  parked `/authorize` request, the "transaction".)
- `Authorize.svelte`, after login and before consent, goes through them one at a time:
  - OAuth: `/oauth/connect/<id>` → upstream AS → `/oauth/callback` → back to
    `/ui/authorize?txn=…`;
  - bearer/headers: an inline form to enter or replace the credential;
  - every step has **Skip**, which sets the row's `skipped` flag and cancels a running
    `ConnectFlow.task` (otherwise the provider lock blocks that backend for up to 300 s);
    the consent page is reachable once each backend is connected or skipped;
  - a link to add a new backend is out of scope for this page — the sign-in step only fixes
    existing ones.
- `ConnectFlow` stores `return_txn` **on the server**; the callback redirects there instead of
  `/ui/backends`. Never take the return target from a query parameter (open redirect).
- Extend the transaction TTL (600 s today) on each step, so several upstream logins fit.

### Phase 6 — forced re-auth (immediate 401)

- When a backend changes **from `connected` to `stale`**, delete its owner's access tokens
  and revoke their refresh tokens. The next `/mcp` request gets 401, the client's refresh gets
  `invalid_grant`, and the client runs a full `/authorize`, which shows the stale backend in the
  Phase 5 sign-in step.
- Revocation fires **only on that change from `connected` to `stale`**. That prevents a loop: a user
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
  - connected → stale → 401 → re-auth → working again; no loop after Skip
  - a transient upstream error (5xx / timeout) does **not** sign the user out
  - migration `0003`: old `upstream_data` rows removed, a `config.yaml` with `backends:` starts
    with a warning
- **README**: backends are managed in the UI; multi-user model; sign-in step; forced re-auth and
  the headless-client caveat; outbound URL policy; endpoint table.
- **CLAUDE.md**: replace "Adding a backend is config-only" with the UI model; new invariants —
  every backend query is owner-scoped; no cross-user component cache; backend clients only
  built by the one helper; outbound URL policy applies to every backend-facing HTTP client.
