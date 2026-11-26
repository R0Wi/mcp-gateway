# Stage 6 — Comprehension Test: `docs/plans/per-user-backends.md`

Reviewer: `egm-comprehension`, which read only the document and no other context.
FeatureRange: lines 1–55. DetailedRange: lines 56–222.

## What this proposes

Backends move out of the operator's `config.yaml` and into the database. Each user defines their own backends in a web UI, and each backend is private to the user who created it. Adding, editing or deleting a backend takes effect without a restart. A single dynamic provider at the root replaces the backends that are mounted once at startup. On every request it works out who is calling and shows only that caller's backends and tools. The tool cache is kept per backend row and is never shared between users.

The gateway records whether each backend is connected, needs re-auth, or is not connected. When an MCP client signs in through the browser, the user is walked through any backends that need credentials, and each one can be skipped. When a working backend stops authenticating, the gateway revokes all of that user's gateway tokens so the client has to sign in again. MCP URL elicitation may replace this if a Phase 0 spike shows it works.

Because any user can now point the gateway at any URL, an outbound URL (SSRF) policy is added. The upgrade is breaking: `config.yaml` backends are not imported, and existing upstream tokens are deleted.

## How the existing system works, per this document

The operator lists backends in `config.yaml`. Each is mounted once at startup under its name as a namespace, so tool names look like `<name>_<tool>`. An admin connects each OAuth backend once through `/ui/backends`, and the gateway keeps it alive with refresh tokens. Upstream tokens are stored in `DbTokenStorage` (the `upstream_data` table), keyed only by backend name, so everyone shares one upstream identity.

The gateway is also an OAuth server for MCP clients. Clients sign in through `/authorize`: a browser login, then a consent ("Approve") page, with a 600 s transaction. They receive access tokens and 30-day refresh tokens, stored in tables that carry a `subject` (the gateway username). Gateway users are defined in `config.yaml`, and the gateway is described as "single-user today". Secrets use envelope encryption (KEK/DEK). When an upstream refresh token dies, the backend's tools vanish silently, and `backend_status()` still reports the backend as connected.

## Findings

There are no Blockers: the reviewer could paraphrase every section. Parts of Phase 4 and Phase 6 it could paraphrase only roughly (findings C3 and C4).

### Major

**C1. Can there be more than one user today, and what happens when a user goes away?** Line 13, line 34 (Decisions, "Gateway users"), line 117 (Phase 2).
The plan's main justification is supporting several users, each with separate backends. Yet it calls the gateway "single-user today" and puts user management out of scope. A reader can't tell any of these:
- whether `config.yaml` can already define several users, so that multi-user works once this plan ships;
- how a user logs in at the "after login" step;
- what happens to a user's backends when that user is removed from `config.yaml` or renamed (`owner` is a username string);
- when a request could arrive without a subject (line 117).

*Cross-reference:* Stage 5 Z4 and Z5. The code shows `auth.users` is already a list, so the "single-user today" wording is factually wrong as well as unclear.

**C2. "Protocol era" is never defined.** Lines 50, 65, 75.
Both the Phase 0a and Phase 0b success criteria depend on "both protocol eras". Line 65 also limits list-change notifications to "where the era supports it". The reader doesn't know which two eras these are or how they differ on the points the spikes test.

**C3. Phase 4's detection mechanism can't be paraphrased.** Lines 149–154.
The phrase "the 401 → interactive path that ends in `redirect_handler` with no flow" relies on three things the document doesn't explain: what `redirect_handler` is, what "no flow" means, and what the `_handle_refresh_response` override currently does. This signal triggers the user-wide sign-out in Phase 6, and line 153 says it is unverified, so the reader can't judge whether the detection is reliable.
*Cross-reference:* Stage 5 Z2.

**C4. Whether Phase 6 still revokes tokens when URL elicitation works is unclear.** Line 33, lines 76–77, lines 174–183.
URL-mode elicitation is never explained: the document doesn't say what the client or user sees, and it gives no spec link. Phase 0b says that if elicitation works, "the 401 becomes the fallback". Phase 6, however, describes revocation as unconditional whenever a backend changes from healthy to stale. The reader can't tell:
- whether tokens are still revoked when elicitation is used;
- what triggers the fallback (for example, a client without elicitation support, or the user ignoring the elicitation).

**C5. The state model is incomplete.** Line 130, line 148, line 160, lines 174–178.
Phase 4 defines three states, but Phase 6 says "healthy", which is never mapped to them. The document also leaves these open:
- What state does an auth-type `none` backend have? It might appear in the sign-in step, or never count as healthy.
- When is a newly created backend `not_connected`, and when is it `connected`?
- How does "disabled" (from the `enabled` flag) combine with the three states?
- How do `backend_status()` (line 20) and `gateway_status` (line 116) relate to the persisted state?

**C6. The no-token-passthrough invariant is stated without what it protects against.** Lines 110–114.
The document says "never weaken or remove either check" but doesn't say what the checks protect: the MCP client's gateway token being forwarded to upstream backends. It names `NoForwardStreamableHttpTransport`, `_require_no_header_forwarding` and `TransportOptions.forward_incoming_headers` without describing them. A new contributor couldn't recognise a violation.

**C7. Phase delivery order is unclear.** Lines 93–95, Phase 3, line 191.
Phase 1 removes `backends:` from the config, but backends can only be created through the UI and API in Phase 3. Line 191 ("same PR as Phase 1/2") suggests each phase is a PR. If so, a build with only Phases 1–2 has no way to add a backend. The document doesn't say which phases must ship together.
*Cross-reference:* Stage 5 Z3.

### Nit

**C8. Several project-specific names are used without a one-line description:**
- `ConnectFlow` (lines 108, 168)
- `describe_txn` and "txn"/"transaction" (lines 159, 163, 170)
- `BackendInstructionsMiddleware` (line 115)
- `upstream_data` (line 86)
- "existence-guarded like `0002`" (line 81)
- the "second gateway as OAuth upstream" fixture (line 192)

**C9. Two acronyms aren't expanded.** CIMD (lines 28, 107, 135) and AS (lines 129, 162). CIMD is a recent MCP-auth term and needs an expansion or a link.

**C10. The local-development URL rule conflicts with the SSRF policy.** Lines 90–92 against lines 138–144.
Phase 1 allows `http://` for local development, but the default SSRF policy blocks loopback and private ranges. So `http://localhost:…` is blocked unless the operator allowlists it. The document should state how the two rules interact.

**C11. "Test connection" is undefined for OAuth backends.** Line 137.
It's unclear what testing an OAuth backend that has no tokens yet means. It could run discovery only, or start a full connect flow.

**C12. Wording and loose ends:**
- "Approve" (line 31) and "consent" (line 161) seem to name the same page; use one term.
- The transaction TTL extension (line 170) gives no amount and no cap.
- "Time-boxed" (line 58) gives no time box.
- "Operator", "admin" and "user" are never defined. One sentence would help: the operator owns gateway users and the SSRF allowlist; users own backends.
