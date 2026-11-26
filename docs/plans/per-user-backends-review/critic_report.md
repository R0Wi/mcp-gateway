# Stage 7 — Critic Review: `docs/plans/per-user-backends.md`

Round 1. Range: FeatureRange, lines 1–55.

| Reviewer | Standard | Status | Raw findings |
|---|---|---|---|
| `egm-design` | feature-spec-standard | completed | 1 Blocker, 7 Major, 4 Nit |
| `egm-structural` | feature-spec-standard | completed | 1 Blocker, 3 Major, 5 Nit |
| `egm-style` | — (persona rules only) | completed | 6 Major, 10 Nit |

Goldfish context: none.

**Isolation note.** The design reviewer's repository-wide grep surfaced lines from the Stage 5/6 reports in `docs/plans/per-user-backends-review/`. The reviewer says it did not open or use them. Its findings that overlap Stage 5 (K4, K5, K6, K7) are each backed by code citations that I checked, so they stand on their own. For later rounds I will tell reviewers not to read that folder.

**Round verdict: not clean.** The round has 1 Blocker and 7 Major findings after deduplication. Under the feature-spec standard the spec fails mainly on missing sections: there is no Alternatives section, no Risks section, and no Architecture section. Several substantive design gaps from Stage 5 also return, now judged against the spec range.

**Code claims I re-checked for this report:**
- `access_tokens.subject` and `refresh_tokens.subject` are nullable, and no migration indexes them (`0001_initial_schema.py:61,73`).
- Refresh rotation issues a new token with a fresh lifetime (`oauth_server.py:340-353`).
- The 30-day value is the configurable default `refresh_token_expiry_seconds` (`config.py:106`).

**Not checkable here:** the fastmcp and MCP SDK claims in lines 39–43 and 48–50, because neither package is installed in this environment.

---

## 🔴 Blocker

### K1. No alternatives are evaluated
`design-1-1`, `structural-1-1` · lines 23–55

**Problem.** The feature-spec standard's Alternatives Rule fails a spec that proposes one path without showing that viable alternatives were rejected for stated reasons.
- The Decisions table states choices with no reasons: no import (line 29), immediate 401 (line 32), no background refresh (line 35).
- The one row that mentions an alternative (line 33) records a task to investigate, not an evaluated option.
- The only real alternative design in the document (one `ProxyProvider` per backend row, lines 69–71) sits in the plan, not the spec.

**Suggested change.** Add `## Alternatives considered` after Decisions, or add a "Why / rejected options" column to the Decisions table. Give each option one concrete reason. At minimum cover:
- **One FastMCP server per user**, chosen by the token's subject. This keeps the existing `mount()` + `ProxyProvider` code, and its caches are isolated without extra work. Compare it with the custom root provider. (Stage 5 Z8 raised the same idea.)
- **The per-row `ProxyProvider` fallback with visibility filtering** (moved from lines 69–71). It fails open, and it contradicts the line 27 guarantee that nobody else sees a user's tools.
- **Shared, operator-defined backends with per-user credentials**, versus fully private backends.
- **A one-time import** of `config.yaml` backends, versus no import.
- **Signalling a stale backend without revoking tokens:** a tool error, a `gateway_status` flag, a UI badge, URL elicitation (pending Phase 0b), or step-up 403. Compare these with the immediate 401.
- **Background refresh**, versus detecting staleness on use.

---

## 🟡 Major

### K2. No risks-and-mitigations section in the spec
`design-1-3`, `structural-1-2` · lines 1–55, and lines 212–222 where the risks sit today

**Problem.** The standard requires the spec to name failure modes, security implications and their mitigations. Today:
- "Open risks" sits after the whole plan and gives no mitigations.
- Line 15 ("without operator involvement") gives every user the power to make the server request arbitrary URLs, which is SSRF. The spec never mentions this; it first appears in Phase 3.
- Security constraints are scattered through the plan: SSRF (line 138), open redirect (line 169), CSRF (line 126), 404-not-403 (line 89), no-token-passthrough (line 110).
- Two items are missing entirely:
  - User-entered secrets now live in the database, where operator-managed env vars used to hold them.
  - Because backends are private (line 27), the operator can no longer see or audit which URLs users have registered.

**Suggested change.** Add `## Risks and mitigations` before `## Phases`, as a table with columns Risk | Impact | Mitigation or "accepted". Include one row for each of:
- SSRF
- cross-user leakage through the component cache
- user secrets stored in the database
- operator oversight of users' backends
- headless-client lockout
- a transient error mistaken for an auth failure
- open redirect on the callback
- the breaking upgrade
- the single-process limit
- the client-side authorization timeout (see K8)

Link each mitigation to its phase.

### K3. No proposed architecture; the core design rests on an unproven spike
`design-1-7`, `structural-1-3` · lines 37–47

**Problem.** The spec never names or connects the new components: the per-request root provider, the `backends` table, the per-row client and provider cache, `ConnectFlow`, the stale-state tracker, and the outbound URL policy. The one architectural statement is buried in a Findings bullet (lines 46–47). Its feasibility is left to Phase 0a, with no exit criteria and no stated plan B that keeps the isolation guarantee.

**Suggested change.** Add `## Proposed architecture` after Decisions, containing:
- a component list;
- two request flows:
  - an `/mcp` tool call: subject → caller's enabled backend rows → per-row cached client → upstream;
  - client sign-in: login → backend connect steps → Approve;
- the cache scopes;
- where isolation is enforced: storage queries, caches, and the callback ownership check.

State the Phase 0a exit criteria. Say whether the visibility-filtered fallback is acceptable given line 27, and name a plan B if it is not.

### K4. A whole-user sign-out is triggered by a stale signal the spec never defines
`design-1-2` · line 32; the definition sits in lines 149–154. Same issue as Stage 5 Z1/Z2.

**Problem.** The most disruptive behaviour in the feature, revoking every token the user holds, depends on a definition of "stale" that lives only in Phase 4. That definition counts a **403** from bearer/header backends. Many servers return 403 for permission or rate limits, not for dead credentials. Line 153 admits that the handling of transient refresh failures is unverified. Concurrent refreshes against an upstream that rotates refresh tokens can also produce a spurious `invalid_grant`.

**Suggested change.** Define "stale" in the Decisions table:
- `invalid_grant` on refresh, or a 401 after a successful refresh;
- not a 403 (unless `WWW-Authenticate` carries `error="invalid_token"`);
- not a transient error.

State the blast radius (every client of that user) next to the decision as an accepted cost, or add a mitigation: a confirming refresh attempt, N consecutive failures, or a setting. Say that one provider per row, serialised by the SDK lock, prevents refresh races.

### K5. "Single-user today" is wrong, and the motivation and upgrade impact follow from that error
`design-1-4`, `structural-1-N1`, `style-1-1` · lines 11–13, line 34. Same issue as Stage 5 Z4 and Stage 6 C1.

**Problem.** Line 11 implies several users, line 13 says there is one, and the code supports several: `config.py:85` declares `users: list[UserConfig]`. The real gap is that all users share one set of backends and one upstream identity. In an existing multi-user deployment, the upgrade:
- removes backends that one admin connected for everyone;
- makes every user re-add and re-connect their own copy;
- duplicates upstream registrations, and possibly upstream accounts.

**Suggested change.** Reword to: "Several gateway users can log in today, but they all share one set of backends and one upstream identity." State the upgrade impact for multi-user deployments under the line 29 decision.

### K6. Removing config backends with no import and no declarative path is not justified
`design-1-5` · line 29. Same issue as Stage 5 Z7.

**Problem.** "Removed, no import" comes with no reason. It removes the only non-interactive way to provision backends (`config.yaml` + `${ENV_VAR}`), because the new API needs a browser session cookie (line 121). Docker and Kubernetes deployments that use secret stores lose backend provisioning entirely.

**Suggested change.** Either justify the removal in the table, or pick one of:
- a one-time import assigned to a named owner;
- an operator path, such as a CLI command or a token-authenticated API, for headless setups.

Record the rejected option under K1.

### K7. Backends are owned by a username, and the user lifecycle is undefined
`design-1-6` · lines 27, 34. Same issue as Stage 5 Z5.

**Problem.** `owner` will be the token subject, which is the bare username from `config.yaml` and can change at any time. As a result:
- Removing a user orphans their backends and encrypted credentials.
- Re-adding the same name for a different person hands that person the previous owner's backends.
- Renaming a user loses their backends.

This breaks the line 27 privacy guarantee.

**Suggested change.** Add a Decisions row that covers:
- purging or quarantining, at startup, the data of owners no longer in `auth.users`;
- whether ownership should key on a stable user id instead of the username;
- that reusing a username never inherits data.

### K8. The sign-in step assumes MCP clients tolerate a long, multi-hop authorization
`design-1-8` · lines 16–17, 31. Related to Stage 5 Z9 (first bullet).

**Problem.** The gateway can extend its own 600 s transaction (`oauth_server.py:171`). It cannot extend the client's limits:
- the loopback callback listener;
- the PKCE/state lifetime;
- popup limits in hosted clients.

Nothing verifies that Claude Code or claude.ai still accept a code after several upstream logins. Separately, a skipped backend that was never connected is offered again on every later sign-in.

**Suggested change.**
- Add the client timeout as a risk (K2), and add a Phase 0 check of real client tolerance for long authorizations.
- Define what happens to skipped backends: prompt only for `needs_reauth` and newly added backends, or remember skips.

### K9. Terms and conditions without one consistent name
`style-1-2`, `style-1-3` · lines 18–19, 31–33, 35. Related to Stage 6 C4/C5.

**Problem.** The same failure is called "dead", "refresh token stops working", "need re-auth" and "stale", and none of them is defined. Line 33 is a task, not a decision, and doesn't say whether elicitation would replace the sign-in step, the token revocation, or both.

**Suggested change.**
- Define "stale" once, where it first appears (this pairs with K4's definition), and use it everywhere.
- Rewrite line 33 as a conditional decision: "If the Phase 0b spike shows `-32042` reaches the client intact, a stale backend first returns a URL elicitation, and revocation becomes the fallback for clients that don't support it; otherwise revocation is the only mechanism."

### K10. Findings mix facts with design conclusions, cite no sources, and use an undefined term
`style-1-4`, `style-1-5`, `style-1-6`, `structural-1-N2`, `structural-1-N4`, `design-1-11` · lines 20–21, 39–54

**Problem.**
- Line 43 ("must never share"), lines 46–47 ("That needs…") and line 54 ("also stops…", where "also" refers back to nothing) are design conclusions placed in a Findings list.
- The fastmcp and SDK claims give no module, version or link.
- "Protocol era" (line 50) is never defined.
- Line 21 ("30-day refresh tokens… rarely re-run `/authorize`") understates the case. The 30 days are a configurable default, and every refresh rotates the token with a fresh lifetime. An active client may therefore never re-run `/authorize`, which supports the motivation more strongly than the current wording.

**Suggested change.**
- Keep each finding factual and give its source: a file:line reference, or a library module and version.
- Move the conclusions into the Architecture section (K3).
- Define the two protocol eras by their revision identifiers.
- Reword line 21: "Refresh tokens rotate on every use with a sliding lifetime (30 days by default), so an active client may never re-run `/authorize`."

**Note on severity:** I merged three style Majors into this one Major because together they are one problem: the Findings section is not a clean evidence base.

---

## 🟢 Nit

- **K11. Goals and non-goals are not separated, and there is no scale target.** Merged from `structural-1-4` (raised as Major) and `design-1-9`.
  - Add `## Goals` / `## Non-goals` between Motivation and Decisions.
  - Move the "out of scope" rows (lines 34, 35, and line 166 from Phase 5) under Non-goals.
  - Add a capacity statement (users × backends, everything held in memory in one process) and a close/eviction policy for idle per-row clients.

  I rated this Nit rather than Major: the content exists and only its placement is wrong, unlike K1 and K2, where content is missing.

- **K12. The lock finding states only the benefit.** (`design-1-10`, lines 53–54) With one provider per row, an abandoned interactive connect blocks that user's other traffic to the same backend for up to `CONNECT_FLOW_TIMEOUT_SECONDS = 300` (`upstream.py:55`). The Skip and abandon paths in the sign-in step must cancel `ConnectFlow.task`.

- **K13. The revocation finding leaves out the facts it depends on.** (`design-1-12`, lines 51–52) Add three points:
  - Access tokens are checked in the database on every request, which is why the 401 is immediate.
  - `subject` is nullable (`0001_initial_schema.py:61,73`), and rows with a NULL subject escape a per-user revocation; handle that case or rule it out.
  - Consider an index on `subject` in migration `0003`.

- **K14. Spec and plan have no visible boundary.** (`structural-1-N3`, `structural-1-N5`)
  - The H1 says "Plan", and the spec sections are H2 siblings of `## Phases`. Add a note under Status that marks where the spec ends.
  - Spell out "(Phase 0)" on lines 33 and 47.
  - Use one sentence style in the Decision cells, and bold only the key constraint.

- **K15. Wording.** (`style-1-7` to `style-1-16`)
  - "proposed — not implemented" says the same thing twice; "proposed" is enough.
  - Replace figurative wording: "keeps it alive", "silent", "quietly disappear", "the natural moment", "anyway".
  - "Nobody else sees it" overstates the guarantee: the operator, who has database access, can. Say "no other gateway user".
  - Expand CIMD and DCR on first use, and write `prefer_dcr` in code format.
  - "Go through" (line 31) is vague, and line 32 has no stated trigger.
  - "Detected on use" (line 35): name the actual trigger.
  - "A single `DELETE`/`UPDATE` each" (line 52): say "one statement per table", and pick DELETE or UPDATE.

---

## Traceability

| Consolidated | design | structural | style | Earlier stages |
|---|---|---|---|---|
| K1 Alternatives | 1-1 | 1-1 | — | Z8 |
| K2 Risks | 1-3 | 1-2 | — | Z6 |
| K3 Architecture | 1-7 | 1-3 | — | — |
| K4 Stale trigger / blast radius | 1-2 | — | — | Z1, Z2, C3 |
| K5 "Single-user" | 1-4 | 1-N1 | 1-1 | Z4, C1 |
| K6 No import | 1-5 | — | — | Z7 |
| K7 User lifecycle | 1-6 | — | — | Z5, C1 |
| K8 Client timeout / skipped backends | 1-8 | — | — | Z9 |
| K9 Terms / line 33 | — | — | 1-2, 1-3 | C4, C5 |
| K10 Findings evidence | 1-11 | 1-N2, 1-N4 | 1-4, 1-5, 1-6 | C2 |
| K11 Goals / scale | 1-9 | 1-4 | — | — |
| K12 Lock | 1-10 | — | — | — |
| K13 Revocation facts | 1-12 | — | — | — |
| K14 Spec/plan boundary | — | 1-N3, 1-N5 | — | — |
| K15 Wording | — | — | 1-7 … 1-16 | C9, C12 |

## Loop state

- **Round 1:** not clean (K1 Blocker; K2–K10 Major).
- **Settled findings:** none yet.
- **Rounds to converge:** 2 consecutive clean rounds; the cap is 5 rounds.
