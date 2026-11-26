# Goldfish Annotated Review Report

Status: resolved. Applied: K1–K5, K7–K15 (auto accept, plan document only). Open: K6 (escalated, awaiting the author). Consistency edits applied to Phases 0, 1, 3–7; "Open risks" removed.

**Target:** `docs/plans/per-user-backends.md` (lines 1–55, FeatureRange). Stage 7, round 1.
**Findings source:** `critic_report.md` (K1–K15).
**Full proposed text for lines 1–55:** [`proposed_spec.md`](proposed_spec.md)

## Before categorising, I checked:

- **Rationale for the decisions.** Neither the commit messages of the two plan commits nor PR #30 (description; no comments) give a reason for any decision. So a reason the document lacks is either one I can derive from the document and the code, or it has to come from you (K6).
- **The library claims the reviewers could not check.** I downloaded fastmcp(-slim) 4.2.6 and MCP SDK 2.3.0 and checked them. All of them hold:
  - `ProxyProvider` is in `fastmcp/server/providers/proxy.py` and calls `self._client_factory()`.
  - `_DEFAULT_CACHE_TTL = 300.0`. The docstring says the cache "is shared across all sessions; per-session visibility and auth filtering are applied after cache lookup".
  - `get_access_token()` is in `fastmcp/server/dependencies.py:674`.
  - `UrlElicitationRequiredError` is in `mcp/shared/exceptions.py:74`, and fastmcp-slim does not reference it.
- **One new fact for K7.** `oauth_server.py:355` (`load_access_token`) does not check that a token's subject is still a configured user. Today a removed user's tokens keep working. Because refresh tokens slide, that can be indefinite.

## Summary

| Category | Findings |
|---|---|
| PROPOSE FIX | K1, K2, K3, K4, K5, K7, K8, K9, K10, K11, K12, K13, K14, K15 |
| ESCALATE | K6 |
| CONTEST | — |
| DECLINE | — |

**Scope note.** Several fixes change what the spec says. The plan text in Phases 0, 1, 4, 5 and 6, and Open risks, would then contradict it. Applying the fixes therefore also includes the small consistency edits to the DetailedRange listed under "Consistency edits outside lines 1–55" at the end. Stage 9 reviews that range in full afterwards.

---

## Prioritized Findings & AI Suggestions

### [Issue 1] K1 [`egm-design`, `egm-structural`] - Severity: Blocker
*   **Affected Scope:** [Lines 23-55](../per-user-backends.md#L23-L55) (Decisions; Findings)
*   **Discrepancy Description:** No alternatives are evaluated. Decisions have no reasons, and the only alternative design sits in the plan (lines 69–71).
*   **Rationale:** The feature-spec standard's Alternatives Rule.
*   ***AI Suggestion:*** PROPOSE FIX
*   ***Justification:*** The finding is accurate.
    *   Four of the alternatives can be given reasons from the document and the verified code:
        *   per-session filtering: rejected, because the `ProxyProvider` cache is shared across sessions;
        *   a per-user sub-server: kept as plan B;
        *   shared backends: rejected, because of problem 2;
        *   a softer signal: used alongside revocation, because of problem 4.
    *   I proposed a reason for deferring background refresh. You can reject it.
    *   The import alternative depends on K6, so its row stays marked [K6] until you answer.
*   ***Proposed Edit:***
    *   Location: new `## Alternatives considered` after `## Proposed architecture`.
    *   Change: the table in `proposed_spec.md` § Alternatives considered. Lines 69–71 of the plan are replaced by a pointer to it (see consistency edits).

### [Issue 2] K2 [`egm-design`, `egm-structural`] - Severity: Major
*   **Affected Scope:** [Lines 1-55](../per-user-backends.md#L1-L55); [Lines 212-222](../per-user-backends.md#L212-L222) (Open risks)
*   **Discrepancy Description:** The spec has no risks-and-mitigations section. SSRF first appears in Phase 3. Two risks are missing entirely: user secrets now stored in the database, and the operator's loss of oversight.
*   **Rationale:** The feature-spec standard requires risks with mitigations.
*   ***AI Suggestion:*** PROPOSE FIX
*   ***Justification:*** The finding is accurate. Every mitigation already exists somewhere in the plan, so the fix gathers them into one place. I wrote the operator-oversight row as "accepted", because it follows from the privacy decision on line 27.
*   ***Proposed Edit:***
    *   Location: new `## Risks and mitigations` before `## Findings that shape the design`. Delete `## Open risks` (lines 212–222), because every item moves into the new table.
    *   Change: the table in `proposed_spec.md` § Risks and mitigations.

### [Issue 3] K3 [`egm-design`, `egm-structural`] - Severity: Major
*   **Affected Scope:** [Lines 37-47](../per-user-backends.md#L37-L47)
*   **Discrepancy Description:** The spec has no architecture section. The core design rests on a spike that has no exit criteria, and its fallback contradicts the privacy decision.
*   **Rationale:** The feature-spec standard requires a Proposed Architecture section.
*   ***AI Suggestion:*** PROPOSE FIX
*   ***Justification:*** The finding is accurate. The proposed text names the components and two request flows, and says where isolation is enforced. It also replaces the fail-open fallback with plan B, a sub-server per user.
    *   **This is a design change, not only an editorial one:** it rejects the original fallback. The reason is in K1's first row.
*   ***Proposed Edit:***
    *   Location: new `## Proposed architecture` after `## Decisions`.
    *   Change: `proposed_spec.md` § Proposed architecture.

### [Issue 4] K4 [`egm-design`] - Severity: Major
*   **Affected Scope:** [Line 32](../per-user-backends.md#L32); [Lines 149-154](../per-user-backends.md#L149-L154)
*   **Discrepancy Description:** A whole-user sign-out is triggered by a stale signal that the spec never defines. The definition in the plan counts a plain 403, and it is unverified.
*   **Rationale:** This is the feature's most disruptive behaviour, and it depends on a heuristic.
*   ***AI Suggestion:*** PROPOSE FIX
*   ***Justification:*** The finding is accurate. The code confirms the SDK's 401 handler skips the refresh grant (see the `_initialize` docstring in `upstream.py`).
    *   I **keep your decision to revoke**. Phase 6 already labels it an "Accepted cost", so I move that statement into the spec.
    *   I tighten the trigger: no plain 403, and a confirming refresh attempt before declaring an OAuth backend stale.
    *   I do not adopt the Stage 5 suggestion to make revocation the last resort. That would reverse a decision you recorded.
*   ***Proposed Edit:***
    *   Location: Decisions rows "Stale" (new) and "Response to a stale backend" (replaces line 32).
    *   Change: as in `proposed_spec.md`. Plan line 151 changes to match (see consistency edits).

### [Issue 5] K5 [`egm-design`, `egm-structural`, `egm-style`] - Severity: Major
*   **Affected Scope:** [Lines 10-13](../per-user-backends.md#L10-L13)
*   **Discrepancy Description:** The plan says "single-user today", which contradicts `config.py:85` (`users: list[UserConfig]`).
*   **Rationale:** The motivation and the upgrade impact both rest on this wrong claim.
*   ***AI Suggestion:*** PROPOSE FIX
*   ***Justification:*** The claim is factually wrong.
*   ***Proposed Edit:***
    *   Location: Motivation item 1.
    *   Change: "**All users share one set of backends and one upstream identity.** `config.yaml` can define several gateway users (`auth.users` is a list), but `DbTokenStorage` keys upstream tokens by backend name only…" Also add the multi-user upgrade impact to the Risks row "Breaking upgrade".

### [Issue 6] K6 [`egm-design`] - Severity: Major
*   **Affected Scope:** [Line 29](../per-user-backends.md#L29)
*   **Discrepancy Description:** Removing config backends with no import, and with no non-browser way to provision them, is not justified.
*   **Rationale:** Declarative deployments (Docker or Kubernetes with secret stores) lose backend provisioning, and every upgrade breaks every deployment.
*   ***AI Suggestion:*** ESCALATE
*   ***Justification:*** The finding is accurate: the document gives no reason. But the reason is your decision, and it is recorded nowhere I can read: not in the commit messages and not on PR #30. Any reason I wrote would be invented. I need one of:
    *   **(a) Keep "no import"** and give the reason in one sentence. "No import" and "no browser-free provisioning" then go under Non-goals.
    *   **(b) Add a one-shot `mcp-gateway import-backends --owner <user>`** CLI command. It reads the deprecated section, creates the rows, and re-keys existing `upstream_data` instead of deleting it. Automatic import stays off.
    *   **(c) Add an operator provisioning path** for headless setups, such as a CLI command or a token-authenticated API.
*   ***Proposed Edit:***
    *   Location: Decisions row `config.yaml backends:`, Non-goals, Alternatives, and the Risks row "Breaking upgrade".
    *   Change: depends on your answer. Until then, every place marked [K6] in `proposed_spec.md` is left out when the fixes are applied, and line 29's current wording stays.

### [Issue 7] K7 [`egm-design`] - Severity: Major
*   **Affected Scope:** [Lines 27, 34](../per-user-backends.md#L27-L34)
*   **Discrepancy Description:** Backends would be owned by a mutable username, and the user lifecycle is undefined. Orphaned backends and username reuse both break isolation.
*   **Rationale:** This undermines the privacy decision.
*   ***AI Suggestion:*** PROPOSE FIX
*   ***Justification:*** The finding is accurate, and the code makes it worse: today a removed user's gateway tokens keep working, because `load_access_token` does not check the subject. The proposal handles it at startup, since a change to `config.yaml` needs a restart anyway:
    *   delete the data of owners who are no longer configured;
    *   reject tokens whose subject is no longer configured.
    *   **Trade-off:** a typo in a username in `config.yaml` deletes that user's backends on the next start. I chose deletion over "disable and keep", because a kept row would be inherited if the name were reused. Tell me if you prefer the other way.
*   ***Proposed Edit:***
    *   Location: new Decisions row "User lifecycle", and a new Findings bullet about `load_access_token`.
    *   Change: as in `proposed_spec.md`. Phase 1 adds the startup cleanup (see consistency edits).

### [Issue 8] K8 [`egm-design`] - Severity: Major
*   **Affected Scope:** [Lines 16-17, 31](../per-user-backends.md#L16-L31)
*   **Discrepancy Description:** The sign-in step assumes the MCP client tolerates a long authorization with several upstream redirects. A skipped, never-connected backend is offered again on every sign-in.
*   **Rationale:** The client's own timeouts can't be extended by the gateway.
*   ***AI Suggestion:*** PROPOSE FIX
*   ***Justification:*** The finding is accurate. Phase 5 extends only the gateway's TTL.
*   ***Proposed Edit:***
    *   Location: Decisions row "Sign-in step" (a skip is remembered until the backend changes), the Risks row "The MCP client's own authorization timeout", and a new Phase 0c spike (see consistency edits).
    *   Change: as in `proposed_spec.md`.

### [Issue 9] K9 [`egm-style`] - Severity: Major
*   **Affected Scope:** [Lines 18-19, 31-33, 35](../per-user-backends.md#L18-L35)
*   **Discrepancy Description:** One condition has four names ("dead", "refresh token stops working", "need re-auth", "stale"). Line 33 is a task, not a decision.
*   **Rationale:** Readers can't tell whether the four names mean different states.
*   ***AI Suggestion:*** PROPOSE FIX
*   ***Justification:*** The finding is accurate.
*   ***Proposed Edit:***
    *   Location: Motivation item 4 defines "stale". Delete the old line 33; its condition moves into "Response to a stale backend": "If the Phase 0b spike shows that URL elicitation or step-up authorization reaches the client, that becomes the first response, and revocation the fallback for clients that do not support it."
    *   Change: as in `proposed_spec.md`.

### [Issue 10] K10 [`egm-design`, `egm-structural`, `egm-style`] - Severity: Major
*   **Affected Scope:** [Lines 20-21, 39-54](../per-user-backends.md#L20-L54)
*   **Discrepancy Description:** The Findings section mixes in conclusions and cites no sources. "Protocol era" is undefined. Line 21 understates how rarely clients return to `/authorize`.
*   **Rationale:** The Findings section is not a clean evidence base.
*   ***AI Suggestion:*** PROPOSE FIX
*   ***Justification:*** The finding is accurate. I verified every library claim against fastmcp 4.2.6 and SDK 2.3.0 (see the top of this report), so the rewritten Findings cite their module paths. "Protocol era" is defined using the two eras that `CLAUDE.md` names. The conclusions move into Architecture.
*   ***Proposed Edit:***
    *   Location: `## Findings that shape the design` (moved to the end of the spec), and Motivation item 4.
    *   Change: as in `proposed_spec.md`.

### [Issue 11] K11 [`egm-design`, `egm-structural`] - Severity: Nit
*   **Affected Scope:** [Lines 5-35](../per-user-backends.md#L5-L35)
*   **Discrepancy Description:** Goals and non-goals aren't separated, and there is no scale target.
*   ***AI Suggestion:*** PROPOSE FIX
*   ***Justification:*** This is cheap to fix, and it gives later stages a scope to check against. The 50-backend figure comes from the plan's own limit (line 92).
*   ***Proposed Edit:***
    *   Location: new `## Goals and non-goals` after Motivation. Remove "Gateway users" (line 34) from the Decisions table; it moves to Non-goals.
    *   Change: as in `proposed_spec.md`.

### [Issue 12] K12 [`egm-design`] - Severity: Nit
*   **Affected Scope:** [Lines 53-54](../per-user-backends.md#L53-L54)
*   **Discrepancy Description:** The lock finding states only the benefit across users, not the 300 s block that one user can hit.
*   ***AI Suggestion:*** PROPOSE FIX
*   ***Justification:*** `upstream.py:55` (`CONNECT_FLOW_TIMEOUT_SECONDS = 300`) and the `ConnectFlow.task` comment at `upstream.py:364-369` confirm it. Skip has to cancel the flow, which changes Phase 5.
*   ***Proposed Edit:***
    *   Location: the lock bullet in Findings.
    *   Change: as in `proposed_spec.md`. Phase 5 adds the cancel (see consistency edits).

### [Issue 13] K13 [`egm-design`] - Severity: Nit
*   **Affected Scope:** [Lines 51-52](../per-user-backends.md#L51-L52)
*   **Discrepancy Description:** The finding omits why revocation takes effect at once (a per-request database lookup), and that `subject` is nullable and has no index.
*   ***AI Suggestion:*** PROPOSE FIX
*   ***Justification:*** Verified at `0001_initial_schema.py:61,73` and `oauth_server.py:355`.
*   ***Proposed Edit:***
    *   Location: the revocation bullet in Findings.
    *   Change: as in `proposed_spec.md`. Phase 1 adds the index (see consistency edits).

### [Issue 14] K14 [`egm-structural`] - Severity: Nit
*   **Affected Scope:** [Lines 1-3, 33, 47](../per-user-backends.md#L1-L47)
*   **Discrepancy Description:** There is no boundary between spec and plan. "(Phase 0)" is used before the reader reaches it. The Decision cells are written in uneven styles.
*   ***AI Suggestion:*** PROPOSE FIX
*   ***Justification:*** The fix is a one-line status note plus the rewrite already proposed.
*   ***Proposed Edit:***
    *   Location: line 3.
    *   Change: "Status: proposed. Everything before `## Phases` is the specification; `## Phases` onward is the implementation plan."

### [Issue 15] K15 [`egm-style`] - Severity: Nit
*   **Affected Scope:** [Lines 3-35](../per-user-backends.md#L3-L35)
*   **Discrepancy Description:** Several wording problems:
    *   redundant status text;
    *   figurative wording;
    *   "nobody else sees it" overstates the guarantee;
    *   unexpanded acronyms;
    *   vague "go through";
    *   "detected on use";
    *   "`DELETE`/`UPDATE` each".
*   ***AI Suggestion:*** PROPOSE FIX
*   ***Justification:*** Each of these is fixed in passing by the rewrite of lines 1–55.
*   ***Proposed Edit:***
    *   Location: throughout lines 1–55.
    *   Change: as in `proposed_spec.md`.

---

## Consistency edits outside lines 1–55

These are applied together with the fixes above, so the plan does not contradict the new spec.

| Where | Change | Driven by |
|---|---|---|
| Phase 0a, lines 69–71 | Replace the fallback paragraph with: "Exit criteria: all four points above hold in both protocol eras. If not, use plan B, one FastMCP sub-server per user (see Proposed architecture); per-session filtering is not an option." | K1, K3 |
| Phase 0b, line 73 | Also test step-up authorization: answer a call to a stale backend's tool with HTTP 403 `insufficient_scope` before dispatch, and check whether Claude Code and claude.ai re-run `/authorize`. | K4, K9 |
| Phase 0, new 0c | **c) Client tolerance for a long sign-in.** Measure how long Claude Code and claude.ai wait between redirecting to `/authorize` and receiving the code, and whether that limit allows two upstream logins. | K8 |
| Phase 1 | Add an index on `access_tokens.subject` and `refresh_tokens.subject`. At startup, delete the backends and tokens of owners not in `auth.users`. `load_access_token` rejects tokens whose subject is not configured. | K7, K13 |
| Phase 4, lines 150–154 | Bearer/headers: "a 401, or a 403 with `WWW-Authenticate: … error="invalid_token"`". OAuth: "one confirming refresh-grant attempt through the same provider; stale only on `invalid_grant` or 401". The change from connected to stale is an atomic update in SQL. | K4 |
| Phase 5, lines 159–167 | List the backends that are stale, or `not_connected` and not skipped. A skip is stored on the row and cleared when the row's settings or credentials change. Skip cancels a running `ConnectFlow.task`. | K8, K12 |
| Open risks, lines 212–222 | Delete; replaced by `## Risks and mitigations`. | K2 |
