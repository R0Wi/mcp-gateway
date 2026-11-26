# Stage 5 — Initial Zoom Out: `docs/plans/per-user-backends.md`

Reviewers: `egm-zoom-out` (simplicity and scope), `egm-inventive-catalyst` (false compromises).
Range: full file, lines 1–222. Goldfish context: none.

## Verdict

Not ready to pass. The two reviewers raised 12 findings. After merging the overlaps this report lists 9: 6 Major and 3 Nit. There are no Blockers.

The goal is clear and the motivation is grounded in the code. Both reviewers checked these claims and found them true:

- `backend_status()` reports `connected: true` whenever a token row exists (`upstream.py:660`).
- `access_tokens` and `refresh_tokens` have a `subject` column.
- The transaction TTL is 600 s (`oauth_server.py:171`).

The problems are about shape, not facts:

1. Four separable problems are shipped as one breaking release.
2. The most expensive goal, multi-user, rests on one sentence.
3. The forced sign-out (Phase 6) acts on a signal the plan itself says is unverified.

Neither reviewer could check the FastMCP claims in lines 39–47 (`client_factory` per request; component cache shared across sessions for 300 s), because fastmcp is not installed in the repository. Phase 0a must confirm them.

I checked these code citations myself and they hold:

- `upstream.py:346`: `_drive_interactive_reauth` builds its own `httpx2.AsyncClient(follow_redirects=True)`.
- `upstream.py:408` → `diagnostics.py:95`: every backend transport gets its HTTP client from `traced_http_client_factory`.
- `config.py:85`: `auth.users` is a list.
- `README.md:51,198`: "single local identity", "single-admin deployment".
- `upstream.py:143-149`: the SDK's 401 handler goes straight to an interactive flow and never tries the refresh grant.

---

## Major

### Z1. Forced re-auth signs out every client of the user for one stale backend
Lines 32, 172–185, 214–215. Raised by both reviewers.

**Problem.** When one backend goes stale, Phase 6 revokes all of the user's gateway tokens. The consequences:

- Healthy backends become unusable.
- Headless clients that never touch the stale backend die.
- A stale state found by a cron job's call signs out the user's interactive clients.
- Every client has to run the browser flow again, even after the first one has fixed the backend.

This also makes upstream health control client sessions. That breaks the separation between the two OAuth legs described in `CLAUDE.md`.

The plan already contains softer options and doesn't rank them:

- URL elicitation (Phase 0b).
- A clear tool-call error. The code already produces one ("requires authorization, open /ui/backends", `upstream.py:494-497`), but the user never sees it.

Phase 5 exists mostly to serve Phase 6.

**Suggested change.** Rewrite Phase 6 as a ladder and ship it last:

1. Show `needs_reauth` in `gateway_status` and in the backends list.
2. Return a clear tool-call error that includes the link to `/oauth/connect/<id>`.
3. Use URL elicitation where Phase 0b shows it works.
4. Add **step-up authorization** to the Phase 0b spike. A call to a stale backend's tool gets HTTP 403 `insufficient_scope` before it is dispatched, so only the client that touched that backend re-runs `/authorize`.
5. Use whole-user revocation only if the spike shows none of 1–4 reaches the user. Even then, make it a setting, not hard-wired.

**Cost.** Support for elicitation and step-up varies by client. The tool-call error relies on the model passing it on. The ladder has more paths to test, and it gives less certainty than revocation that the user is sent back to a browser.

### Z2. A destructive action is triggered by an unconfirmed signal
Lines 148–154 combined with 174–176. Raised by the catalyst.

**Problem.** Phase 4 treats one observed failure as proof that a credential is dead. Phase 6 then revokes everything on that signal.

- Line 153 itself says the SDK's handling of transient failures is unverified.
- The SDK goes from a 401 straight to an interactive flow without trying the refresh grant (`upstream.py:143-149`). So "`redirect_handler` called with no flow" can happen while a valid refresh token sits in storage.
- Line 151 counts a **403** as an auth failure for bearer and header backends. GitHub, for example, returns 403 for rate limits and missing permissions. Combined with Phase 6, a rate-limited token signs the user out everywhere.

**Suggested change.**

- Bearer/header backends: count only 401, or a 403 whose `WWW-Authenticate` header has `error="invalid_token"`.
- OAuth backends: before marking a backend `needs_reauth`, make one confirming refresh-grant attempt through the same provider. Mark it stale only on `invalid_grant` or 401.
- Make the healthy → stale change an atomic compare-and-set in SQL, so two concurrent failures can't trigger revocation twice.

### Z3. Four separable problems ship as one breaking change
Lines 5–21, 56–210, and especially 189–191 ("same PR as Phase 1/2"). Raised by zoom-out.

**Problem.** Only motivation points 1 and 2 need the database registry. The other two don't:

- Point 4 (a dead backend is silent) can be fixed on today's config-defined backends with Phase 4 alone.
- Point 3 (connect during sign-in) doesn't need the registry either.

As written, every deployment breaks to deliver all four at once.

**Suggested change.** Re-cut the work into increments that can each ship on their own:

- (a) Stale-state tracking, a truthful `connected` status, and a clear error, on today's backends.
- (b) The sign-in step for backends that are not connected or need re-auth.
- (c) The database registry, the UI, and per-user isolation.
- (d) Forced re-auth, only if Z1's ladder isn't enough.

Mark which increments are optional.

### Z4. The multi-user goal is barely justified, and the motivation misstates today's model
Lines 12–13, 27, 34, 138–144. Raised by zoom-out. The catalyst repeats the same misstatement.

**Problem.** The README describes a single-admin deployment with a single YAML file. The plan justifies multi-user in one clause ("should support several users"). Yet multi-user drives most of the new cost:

- owner scoping on every query
- the per-request dynamic provider
- the cache separation
- the SSRF policy and its allowlist
- per-user limits
- the 404-not-403 rule

Line 13 also says "the gateway is single-user today", which is wrong. `auth.users` is a list (`config.py:85`): several users can already log in, but they share one set of backends and one upstream identity.

**Suggested change.**

- Add a short "Who needs this" paragraph that names the deployment needing separate backends per user.
- Restate problem 1 as "users already exist but share one upstream identity". That is accurate and a stronger argument.
- If no concrete multi-user need exists, scope the plan to UI-managed backends for one owner, keeping an `owner` column as the seam.

### Z5. Backend ownership is keyed by a config username that can change or be reused
Lines 27, 34, 82–89. Raised by zoom-out.

**Problem.** `owner` is the username string from `auth.users`, and users stay in `config.yaml` (line 34). So:

- Removing a user leaves their backends and encrypted credentials orphaned.
- Adding the same username back later, possibly for a different person, silently hands over those backends, upstream tokens and tools.
- Renaming a user loses their backends.

This undercuts "fully separated" (line 13).

**Suggested change.** Add a Decisions row for the user lifecycle. Simplest option: at startup, delete (or disable and log) the backends of owners no longer in `auth.users`, and revoke their gateway tokens. Document that usernames must not be reused.

### Z6. The outbound URL (SSRF) policy has no single enforcement point, and an existing path would bypass it
Lines 138–144, 199–200, 210, 218–219. Raised by both reviewers.

**Problem.** The policy is stated as a rule to apply to "all backend and upstream-OAuth HTTP clients". A rule like that is only as strong as the list of places that remember to apply it. Today there are two places that build HTTP clients:

- `traced_http_client_factory`, which every backend transport uses.
- `_drive_interactive_reauth` (`upstream.py:346`), which builds its own redirect-following client. That client carries OAuth discovery, registration and token traffic, which is the exact surface the plan worries about.

There are also new paths: "test connection" on unsaved values, and RFC 7009 revocation on delete.

Checking "the resolved IP at connect time" also leaves a gap between check and use unless the connection goes to the IP that was checked.

**Suggested change.**

- Implement the policy once, as an httpx2 transport that resolves the host, checks every address, and connects to the checked address (DNS pinning).
- Build every backend-facing client through one factory that extends `traced_http_client_factory`, including `_drive_interactive_reauth`, test-connection and revocation.
- State the invariant "every backend-facing httpx2 client comes from this factory", the same way the plan treats `NoForwardStreamableHttpTransport`.

**Cost.** The pinned-IP connection must keep TLS SNI and the Host header correct. It also adds a dependency on httpx2 internals that an upgrade can break.

---

## Nit

### Z7. Dropping config backends with no import: the cost isn't weighed
Lines 29, 86–87, 93–98, 204, 220. Raised by both reviewers; zoom-out rated it Major.

Every deployment loses its backends and upstream tokens. Two more losses aren't mentioned:

- `${ENV_VAR}` provisioning of backend secrets goes away.
- The new API needs a browser session (line 121), so automated provisioning (IaC, CI) becomes impossible.

Either justify "no import" in the Decisions table, or add a one-time explicit command, for example `mcp-gateway import-backends --owner <user>`. It would create the rows and re-key `upstream_data` instead of deleting it. At minimum, list "no automated provisioning" under Open risks or out of scope.

I rated this Nit rather than Major because the author made "no import" an explicit decision. The finding is that the reasoning and the consequences are missing, not that the decision is wrong.

### Z8. The Phase 0a fallback is fail-open; a third option is worth spiking
Lines 44–47, 60–71. Raised by the catalyst.

The fallback registers every user's tools on one server and filters visibility per session. That fails open: a filtering bug exposes another user's tools.

The third option is a lightweight FastMCP sub-server per user, built on first request from the existing `create_proxy` + `mount(namespace=…)` loop and `BackendInstructionsMiddleware`, cached by subject, and rebuilt when that user's backends change. The root provider only delegates to the caller's sub-server. Judge it on the same four Phase 0a criteria.

**Cost.** Memory grows with the number of active users, a rebuild drops warm caches, and handshake-era sessions need a defined behaviour across a rebuild.

### Z9. Smaller scope and accuracy items
- **Lines 157–170: the sign-in step relies on the client's timeout, not just the gateway's TTL.** Claude Code's loopback listener and claude.ai's connector flow have their own timeouts, which the gateway cannot extend. Consider running each upstream connect in a popup or new tab while `Authorize.svelte` keeps its state. That removes the need for `return_txn` and its open-redirect concern. Either way, name this limit under Open risks.
- **Line 110 ("one helper"):** this helper already exists as `BackendManager.build_client` (`upstream.py:385`). Say "extend `build_client`".
- **Lines 90–92:** the per-user limit "configurable, default 50" is speculative configuration; a constant is enough. The new name regex (lowercase only, at most 32 characters) differs from today's `[a-zA-Z0-9][a-zA-Z0-9_-]*` (`config.py:172`) with no reason given.
- **Lines 128–129, 137:** "test connection on unsaved values" and best-effort upstream RFC 7009 revocation both add new outbound surface for convenience. Consider deferring them.
- **Line 86:** `Storage._migrate_legacy_rows` reads and writes `upstream_data` by the `backend` column (`storage.py:160-171`). Add it to the list of code that changes when the table is re-keyed.
- **Lines 148–170:** Phases 4–5 name functions but not the owner of the stale state. Add one sentence: which component writes `needs_reauth` (the backend manager or the auth hook)?

---

## Choices both reviewers would keep

- Owner-scoped "not found" responses (404, not 403).
- Write-only secrets.
- Keeping both no-token-passthrough checks.
- Keeping background refresh out of scope.
- The single-instance assumption.

## Traceability

| Finding | Zoom-out | Catalyst |
|---|---|---|
| Z1 Forced re-auth blast radius | M3 | 1 |
| Z2 Unconfirmed stale signal / 403 | — | 2 |
| Z3 Bundled breaking change | M1 | — |
| Z4 Multi-user justification / "single-user" misstatement | M2, N4 | (6, premise) |
| Z5 Owner keyed by mutable username | M4 | — |
| Z6 SSRF choke point | M6, N3 (part) | 3 |
| Z7 No import | M5 | 6 |
| Z8 Per-user sub-server option | — | 4 |
| Z9 Smaller items | N1, N2, N3, N5, N6 | 5 |
