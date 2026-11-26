<!--
Proposed replacement for lines 1–55 of docs/plans/per-user-backends.md
(everything before "## Phases"). Produced by the Stage 7 resolution; see
goldfish_review_report.md for which finding drives each change.
Text marked [K6] depends on the escalated finding K6 and is left out if K6
is not answered.
-->

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
- [K6] Importing existing `config.yaml` backends, and provisioning backends without a browser.

Scale: a handful of users with up to 50 backends each. All clients, OAuth providers and component
lists are held in memory in one process. A backend row's cached entries are closed when the row is
edited, disabled or deleted.

## Decisions

| Topic | Decision |
|---|---|
| Backend definitions | Stored in the database and managed in the UI. Each backend is **private to the user who created it**: no other gateway user sees it, its credentials, or its tools. |
| Auth types | Every existing type is configurable per backend in the UI: none; bearer token; custom headers; OAuth with automatic registration (Client ID Metadata Document (CIMD) or Dynamic Client Registration (DCR), optional scopes, `prefer_dcr`) or with a pre-registered `client_id` and `client_secret`. |
| `config.yaml` `backends:` | **Removed, with no import.** [K6: reason]. Users re-add their backends in the UI. Migration `0003` deletes existing upstream tokens. A config file that still has the section starts, with a warning that names the ignored backends. |
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
| [K6] One-time import of `config.yaml` backends | [K6] | [K6] |

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
| Breaking upgrade | Existing backends and upstream tokens are gone. In a multi-user deployment each user re-adds their own copy, which can duplicate upstream registrations | Startup warning naming the ignored backends; upgrade notes in the README. [K6] |
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
