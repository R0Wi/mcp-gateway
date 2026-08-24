# Security Review — MCP Gateway

**Date:** 2026-08-24
**Scope:** `src/mcp_gateway/` (all modules), `ui/`, `Dockerfile`, `docker-compose.yml`, `config.example.yaml`
**Version reviewed:** commit on `claude/codebase-security-review-an9lyj`, `fastmcp 3.4.7`, `mcp` SDK as resolved by `pyproject.toml`
**Method:** manual code review of the full source (~1900 LoC Python + Svelte UI), plus executable proof-of-concept tests run against live gateway instances using the repository's own `tests/conftest.py` fixtures. SDK-delegated security controls were verified by reading the installed `fastmcp`/`mcp` sources rather than assumed.

Every finding below marked **Confirmed** was reproduced against a running gateway. Claims that turned out to be **unfounded** are recorded in [Controls verified correct](#controls-verified-correct) — several plausible-looking vulnerabilities are in fact properly defended, and that is worth knowing.

---

## Summary

| # | Severity | Finding | Component |
|---|----------|---------|-----------|
| [H-1](#h-1) | **High** | Unauthenticated request stalls the entire gateway (blocking bcrypt on the event loop, no rate limit) | `web.py`, `users.py` |
| [M-1](#m-1) | **Medium** | Username enumeration via a 270 ms timing oracle | `users.py` |
| [M-2](#m-2) | **Medium** | Any anonymous request can abort an admin's backend OAuth connect flow | `web.py`, `upstream.py` |
| [M-3](#m-3) | **Medium** | Anonymous Dynamic Client Registration grows storage without bound | `oauth_server.py`, `storage.py` |
| [M-4](#m-4) | **Medium** | Consent screen is framable — no clickjacking or hardening headers | `app.py` |
| [L-1](#l-1) | Low | `forwarded_allow_ips="*"` trusts `X-Forwarded-*` from any client | `cli.py` |
| [L-2](#l-2) | Low | Unauthenticated 500 on non-ASCII username; such users can never log in | `users.py` |
| [L-3](#l-3) | Low | Logout does not invalidate the session cookie | `users.py`, `web.py` |
| [L-4](#l-4) | Low | Internal error details returned to MCP clients | `gateway.py` |
| [L-5](#l-5) | Low | Token-passthrough guard fails open if upstream renames an attribute | `gateway.py` |
| [I-1](#i-1) | Info | Scopes are accepted but enforce nothing | `oauth_server.py` |
| [I-2](#i-2) | Info | Plaintext passwords supported in config | `config.py` |
| [I-3](#i-3) | Info | No `Cache-Control: no-store` on authenticated JSON responses | `web.py` |
| [I-4](#i-4) | Info | scrypt KDF parameters below current guidance | `storage.py` |

The design is sound in the places that matter most: token passthrough really is prevented, PKCE is genuinely enforced, redirect URI validation is strict, and secrets are hashed or encrypted at rest. The issues concentrate in **availability** and **operational hardening** of the interactive login/consent surface, which is the one part of the system that is hand-rolled rather than delegated to the MCP SDK.

---

## Findings

<a name="h-1"></a>
### H-1 — Unauthenticated requests stall the entire gateway (High) · Confirmed

**Where:** `src/mcp_gateway/web.py:63-82` (`login`), `src/mcp_gateway/users.py:17-30` (`verify_user`)

`login` is an `async def` handler that calls `bcrypt.checkpw` directly:

```python
@router.post("/login")
async def login(body: LoginRequest, request: Request, response: Response):
    await asyncio.sleep(0.3)
    if not verify_user(config.auth, body.username, body.password):
```

`bcrypt.checkpw` is a **blocking, CPU-bound** call — roughly 250 ms at the default cost factor 12 that `mcp-gateway hash-password` generates. Running it on the event loop thread blocks *every* concurrent task: the MCP endpoint, the OAuth `/token` endpoint, health checks, in-flight backend proxying. The `asyncio.sleep(0.3)` intended to "blunt online guessing" does not serialize anything — it is asynchronous, so all attempts elapse their delay in parallel and then queue up on the CPU.

There is no rate limiting, no account lockout, and no cap on concurrent attempts.

**Reproduction** — 20 anonymous login attempts in flight, measuring an unrelated endpoint:

```
/healthz baseline:       15.1 ms
/healthz under load:   5436.1 ms  (20 anonymous logins in flight)
amplification: 361x
```

A separate run confirms the serialization: 30 concurrent attempts took 8.58 s wall-clock (~3.5 hashes/sec), matching 30 × ~280 ms of serialized CPU rather than the ~1 s that parallel execution would give.

**Impact.** An unauthenticated attacker needing only a few requests per second renders the gateway — including all MCP traffic for legitimate clients — unusable, at negligible cost to themselves. The single-worker `uvicorn.run(app, ...)` deployment in `cli.py` has no second process to absorb this.

**Recommendation.**
1. Move the hash comparison off the event loop: `await anyio.to_thread.run_sync(verify_user, config.auth, body.username, body.password)`.
2. Add real rate limiting keyed on client IP *and* a global concurrency cap (e.g. an `asyncio.Semaphore` of 2–4 around the hashing call), plus exponential backoff or temporary lockout per username.
3. Drop the fixed `asyncio.sleep(0.3)` once M-1 is fixed properly — it costs latency and buys nothing.

---

<a name="m-1"></a>
### M-1 — Username enumeration via timing oracle (Medium) · Confirmed

**Where:** `src/mcp_gateway/users.py:17-30`

The dummy-work path for unknown users runs bcrypt at **cost 4**, while a real user's stored hash is at **cost 12** (what `hash-password` produces) — a 256× difference in work:

```python
    # Constant-ish time for unknown users: still run one bcrypt round.
    bcrypt.checkpw(b"invalid", bcrypt.hashpw(b"invalid-user", bcrypt.gensalt(rounds=4)))
    return False
```

The comment states the correct intent; the parameters defeat it.

**Reproduction** — median of 7 attempts each, wrong password in both cases, against a gateway configured with a cost-12 `password_hash`:

```
VALID username   median:    577.4 ms  (bcrypt cost 12)
UNKNOWN username median:    307.0 ms  (bcrypt cost 4 dummy)
DELTA:                      270.4 ms
```

A 270 ms gap is trivially measurable over a network — no statistical sampling required. The fixed 0.3 s sleep raises both baselines but does not narrow the gap.

**Impact.** An attacker learns which usernames exist before spending effort on passwords. Modest on a single-admin gateway, but it converts a blind attack into a targeted one and pairs directly with H-1's absent rate limiting.

**Recommendation.** Compare against a dummy hash generated **at the same cost as the configured hashes** and computed once at startup, and always iterate the full user list so the number of bcrypt invocations does not depend on the input:

```python
# Computed once at import, at the same cost factor as real hashes.
_DUMMY_HASH = bcrypt.hashpw(b"dummy", bcrypt.gensalt()).decode()

def verify_user(auth: AuthConfig, username: str, password: str) -> bool:
    matched: UserConfig | None = None
    for user in auth.users:
        # Bytes, not str: compare_digest rejects non-ASCII str (see L-2).
        if hmac.compare_digest(user.username.encode(), username.encode()):
            matched = user
            # No early break: keep the loop's cost independent of position.

    if matched is None or matched.password_hash is None:
        # Always spend one full-cost bcrypt so unknown users and plaintext
        # users cost the same as a real hashed-password check.
        bcrypt.checkpw(password.encode(), _DUMMY_HASH.encode())
        if matched is not None and matched.password is not None:
            return hmac.compare_digest(matched.password.encode(), password.encode())
        return False

    try:
        return bcrypt.checkpw(password.encode(), matched.password_hash.encode())
    except ValueError:
        return False
```

This equalises the bcrypt cost across the known/unknown paths and fixes L-2 by encoding
to bytes before `compare_digest`. Combined with H-1, the call belongs in a worker thread.
Note that a deployment mixing plaintext and hashed users still has a small residual gap;
deprecating plaintext passwords (I-2) removes it entirely.

Measured against the sketch above — the gap closes and behaviour is preserved:

```
VALID   username:   270.5 ms
UNKNOWN username:   269.7 ms
DELTA:                0.8 ms          (was 270.4 ms)
correctness: OK (valid login works; non-ASCII username no longer raises)
```

---

<a name="m-2"></a>
### M-2 — Anonymous requests can abort a backend OAuth connect flow (Medium) · Confirmed

**Where:** `src/mcp_gateway/web.py:148-165` (`oauth_callback`), `src/mcp_gateway/upstream.py:323-340` (`deliver_callback`)

`/oauth/callback` performs **no session check** — unlike `/oauth/connect/{name}`, which requires a login. Worse, `deliver_callback` falls back to "the single active flow" whenever the `state` does not resolve:

```python
if flow is None and len(self._flows_by_backend) == 1:
    # Some servers drop the state parameter; with a single active flow
    # the mapping is unambiguous.
    flow = next(iter(self._flows_by_backend.values()))
if flow is None or flow.callback.done():
    ...
flow.callback.set_result((code, state))
```

An unauthenticated request with a bogus `state` therefore reaches the pending flow and consumes its one-shot `callback` future.

**Reproduction** — admin starts a connect; an attacker with no cookies hits the public callback once:

```
GET /oauth/callback?code=attacker-code&state=wrong   ->  307
admin connect result: 'No active connect flow'

OAuthFlowError: State parameter mismatch: wrong != aVa9ax-Rl6W4O5zCxdnCiLinplr55T3OMtqQ_pKqWk0
```

**This is not authorization code injection.** I specifically tested for that, and the MCP SDK defends it correctly: `mcp/client/auth/oauth2.py:361` validates the returned state with `secrets.compare_digest` and aborts, and PKCE binds the code to the gateway's own verifier. The realistic impact is **availability and integrity of the admin workflow**: any anonymous party who can reach the gateway can reliably prevent backends from ever being connected, and the resulting error message (`State parameter mismatch`) points at the wrong culprit, making this hard to diagnose as an attack.

**Recommendation.**
1. Require an authenticated session on `/oauth/callback` — the flow is always initiated from a logged-in browser, so this costs nothing.
2. Remove the "single active flow" fallback, or gate it behind an explicit per-backend opt-in. The MCP SDK always sends `state`; the fallback exists for non-conformant servers and weakens the common case for all of them.
3. On a state mismatch, do **not** consume the flow — leave the future unresolved so the legitimate callback can still arrive.

---

<a name="m-3"></a>
### M-3 — Anonymous DCR grows storage without bound (Medium) · Confirmed

**Where:** `src/mcp_gateway/oauth_server.py:141-149` (`register_client`), `src/mcp_gateway/storage.py:351-363` (`purge_expired`)

`/register` is unauthenticated by design (RFC 7591, and `claude mcp add` depends on it), but registrations are permanent. `purge_expired()` reclaims `auth_codes`, `access_tokens`, `refresh_tokens` and `auth_txns` — it never touches `oauth_clients`. There is no registration cap, no rate limit, and no TTL for clients that never complete an authorization.

**Reproduction:**

```
oauth_clients rows: before=0  after 25 anonymous registrations=25
after purge_expired(): 25  (no client is ever reclaimed)
```

Each row stores a Fernet-encrypted JSON blob containing attacker-controlled fields (`client_name`, `redirect_uris`), so the amplification per request is substantial.

**Impact.** Unauthenticated disk exhaustion against the single SQLite file that holds all gateway state — including the encrypted upstream backend credentials. On the documented Docker deployment this fills the `gateway-data` volume.

**Recommendation.** Purge clients that have never been used for a successful authorization after a short TTL (e.g. 24 h), and delete `is_cimd` rows on their natural refresh cycle since they are re-fetchable. Add a registration rate limit per source IP and an absolute cap on `oauth_clients` rows. Consider recording `last_used_at` to drive eviction.

---

<a name="m-4"></a>
### M-4 — Consent screen is framable; no hardening headers (Medium) · Confirmed

**Where:** `src/mcp_gateway/app.py:52` — the `FastAPI(...)` app adds no security-header middleware.

**Reproduction** — response headers for `/ui/authorize`:

```
{'date': ..., 'server': 'uvicorn', 'content-length': '96', 'content-type': 'application/json'}
```

No `X-Frame-Options`, no `Content-Security-Policy`, no `Referrer-Policy`, no `X-Content-Type-Options`.

**Impact.** `/ui/authorize?txn=…` is the OAuth consent screen with an **Approve** button that grants a client access to every configured backend. With no frame-ancestors restriction, an attacker who can get an authenticated admin to visit their page can frame this screen transparently and clickjack the approval. The attacker controls the `txn` (they initiate the flow with their own DCR-registered client and their own redirect URI), so a single stolen click yields an authorization code for a client they control. The absent `Referrer-Policy` additionally leaks the `txn` identifier via `Referer` to any third-party resource.

The consent UI does display the client name and redirect target and warns on loopback redirects — good design that a framing attack renders invisible.

**Recommendation.** Add a middleware setting, at minimum:

```python
@app.middleware("http")
async def security_headers(request, call_next):
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
    )
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response
```

Verify the CSP against the built Svelte bundle (Vite may need `'unsafe-inline'` for injected styles; prefer a nonce or hash over relaxing the policy).

---

<a name="l-1"></a>
### L-1 — `forwarded_allow_ips="*"` trusts proxy headers from anyone (Low)

**Where:** `src/mcp_gateway/cli.py:100-102`

```python
proxy_headers=True,
forwarded_allow_ips="*",
```

This instructs uvicorn to trust `X-Forwarded-For` / `X-Forwarded-Proto` from **every** peer. The comment assumes a reverse proxy is always present, but `docker-compose.yml` publishes `8000:8000` directly to the host and the README explicitly offers "expose the port directly" as an option. In that configuration any client can set its own apparent source IP (poisoning the `login attempts` audit log this project deliberately writes, and defeating any IP-based rate limiting added for H-1) and can assert `X-Forwarded-Proto: https` on a plaintext connection.

**Recommendation.** Make it configurable — e.g. `server.forwarded_allow_ips` defaulting to the Docker gateway CIDR or `127.0.0.1`, and document that it must name the actual proxy. Never default to `*`.

---

<a name="l-2"></a>
### L-2 — Unauthenticated 500 on non-ASCII username (Low) · Confirmed

**Where:** `src/mcp_gateway/users.py:19`

`hmac.compare_digest` rejects `str` arguments containing non-ASCII characters:

```
POST /auth/api/login {"username": "adminé", ...}  ->  500 Internal Server Error
TypeError: comparing strings with non-ASCII characters is not supported
```

Two consequences: unauthenticated clients can trigger unhandled server errors and stack-trace log noise at will, and — more practically — **any user configured with a non-ASCII username can never authenticate**, since their own correct username raises before any comparison completes.

**Recommendation.** Encode both operands to bytes: `hmac.compare_digest(user.username.encode(), username.encode())`. The M-1 rewrite covers this.

---

<a name="l-3"></a>
### L-3 — Logout does not invalidate the session (Low)

**Where:** `src/mcp_gateway/users.py:33-54`, `src/mcp_gateway/web.py:84-87`

Sessions are stateless `itsdangerous` tokens. `logout` only calls `response.delete_cookie(...)`; the signed token remains valid for the full `login_session_expiry_seconds` (default **8 hours**). A token captured beforehand — from a shared machine, a proxy log, or the `Referer` leak in M-4 — continues to work after the user believes they have signed out. There is also no way to revoke sessions after a password change.

**Recommendation.** Track a server-side session identifier (the `storage` layer already has a `meta` table and a purge routine) and check it in `SessionManager.validate`, or embed a per-user generation counter that a password change or explicit "sign out everywhere" increments.

---

<a name="l-4"></a>
### L-4 — Internal error details returned to MCP clients (Low)

**Where:** `src/mcp_gateway/gateway.py:39` — `mask_error_details=False`

FastMCP will return full exception text to callers. Backend failures surface upstream URLs, HTTP error bodies and internal exception types to any authenticated MCP client; `NotConnectedError` already embeds the gateway's public URL. On a single-admin gateway the trust gap is small, but the setting is a deliberate opt-out of a safe default and will not age well if multi-user support is added.

**Recommendation.** Set `mask_error_details=True` and rely on server-side logging for diagnostics, or make it follow the `--log-level debug` flag.

---

<a name="l-5"></a>
### L-5 — Token-passthrough guard can fail open (Low)

**Where:** `src/mcp_gateway/gateway.py:58-60`

```python
transport = getattr(clients[name], "transport", None)
if hasattr(transport, "forward_incoming_headers"):
    transport.forward_incoming_headers = False
```

The guard enforces the spec's most important prohibition for a gateway — and **it works today** (verified end-to-end, see below). But it is written to silently do nothing if the attribute is ever renamed or moved upstream. `fastmcp/server/providers/proxy.py` sets `forward_incoming_headers = True` in two places, so the default is *on*: a rename in a future `fastmcp 3.x` would re-enable client-token passthrough to every backend with no error and no test failure. The `>=3.4,<4` version range permits exactly that.

**Recommendation.** Fail loudly instead of silently:

```python
if not hasattr(transport, "forward_incoming_headers"):
    raise RuntimeError(
        f"fastmcp transport {type(transport).__name__} has no forward_incoming_headers; "
        "cannot guarantee the no-token-passthrough invariant"
    )
transport.forward_incoming_headers = False
```

and add a regression test asserting the client's gateway token never appears in an upstream request (a recording stub backend makes this straightforward — one is sketched in the review notes for this branch).

---

<a name="i-1"></a>
### I-1 — Scopes enforce nothing (Info)

`GatewayClient.validate_scope` (`oauth_server.py:71-76`) returns whatever is requested, and `exchange_refresh_token` (`oauth_server.py:335`) honours arbitrary scopes on refresh. This is documented and harmless today — the gateway is a single-identity AS where scopes gate nothing, and MCP clients routinely request scopes they never registered. Flagged only so the assumption is not silently inherited: **if per-backend or per-tool authorization is ever added, scopes must not be the mechanism** without first making validation restrictive. A token holder can currently self-grant any scope string.

<a name="i-2"></a>
### I-2 — Plaintext passwords supported in config (Info)

`UserConfig.password` (`config.py:43-59`) accepts a plaintext password as an alternative to `password_hash`. It is clearly marked for local testing and `config.example.yaml` leads with the hashed form, but nothing prevents production use and there is no startup warning. Consider logging a warning at startup when any user is configured with a plaintext password.

<a name="i-3"></a>
### I-3 — No `Cache-Control: no-store` on authenticated responses (Info)

`/auth/api/me`, `/auth/api/txn/{id}` and `/auth/api/backends` return no cache headers. `/auth/api/txn/{id}` discloses client name, redirect URI and scopes to anyone holding the (256-bit random, unguessable) `txn` id, without requiring a session. Add `Cache-Control: no-store` to the authenticated API surface.

<a name="i-4"></a>
### I-4 — scrypt parameters below current guidance (Info)

`storage.py:81-84` uses `n=2**14, r=8, p=1`. OWASP currently recommends `n=2**17` for password-derived keys. The practical risk is low here because the documented input is a 32-byte random key from `openssl rand -base64 32` (which bypasses the KDF entirely via the `Fernet(key)` fast path) — the KDF only applies when an operator supplies a passphrase, which is exactly the low-entropy case where the parameters matter most. Consider raising `n` and noting the one-off startup cost.

---

## Controls verified correct

These were actively probed and hold up. Recording them so future changes do not regress them unknowingly, and so the same ground is not re-covered.

| Control | Verification |
|---|---|
| **No token passthrough to backends** | End-to-end test with a recording stub backend: the client's gateway token never appears upstream; the backend received only the gateway's own `Bearer UPSTREAM-SECRET-TOKEN`. The README's headline claim is accurate. |
| **PKCE (S256) enforcement** | `mcp/server/auth/handlers/token.py:175-183` recomputes the challenge and rejects mismatches; a missing `code_challenge` stored as `None` fails closed. |
| **redirect_uri binding** | Same handler (`:153-170`) rejects a `redirect_uri` that differs between `/authorize` and `/token`. |
| **No open redirect via DCR** | With the default `allowed_client_redirect_uris: null`, `ProxyDCRClient.validate_redirect_uri` requires an **exact** match against registered URIs, allowing only the loopback *port* to vary (`models.py:292-299`). Unsafe schemes (`javascript:`, `data:`, …), userinfo bypasses (`http://localhost@evil.com`) and dot-segment path escapes are all rejected in `redirect_validation.py`. |
| **Upstream authorization code injection** | Defended: `mcp/client/auth/oauth2.py:361` validates `state` with `secrets.compare_digest`, and PKCE binds the code to the gateway's verifier. Confirmed by observing `OAuthFlowError: State parameter mismatch` when a forged callback was injected. (The *availability* consequence is M-2.) |
| **Token revocation ownership** | `mcp/server/auth/handlers/revoke.py` authenticates the client and checks `token.client_id == client.client_id` before revoking — one client cannot revoke another's tokens. |
| **Path traversal in `/ui/{rest:path}`** | `web.py:182-188` calls `.resolve()` *before* `is_relative_to(STATIC_DIR.resolve())`. Both `../` traversal and the pathlib absolute-path join quirk (`/ui//etc/passwd`) are correctly blocked. |
| **XSS in the UI** | Svelte auto-escapes all `{...}` interpolation and the codebase uses no `{@html}`. The `?error=` / `?connected=` query parameters reflected in `Backends.svelte` are inert. |
| **CSRF on `/auth/api/consent`** | Adequately mitigated: the cookie is `SameSite=Lax` (blocking cross-site POST), and the endpoint rejects CORS-safelisted content types — a `text/plain` body was refused, so a no-preflight cross-origin POST cannot reach it. Verified by test. Note FastMCP's own consent flow carries an explicit `csrf_token`; adding one here would be defense in depth, not a fix for a live hole. |
| **Secrets at rest** | Access/refresh tokens and auth codes stored as SHA-256 hashes only; client records and upstream credentials Fernet-encrypted; a changed encryption key degrades safely to "unknown client" rather than erroring. |
| **Authorization code hygiene** | Single-use (consumed before token issuance), 5-minute expiry, bound to `client_id`. Refresh tokens rotate on use and the old one is marked revoked. |
| **Container posture** | Runs as non-root uid 10001; `.dockerignore` and `.gitignore` both exclude `config.yaml`, `.env` and `*.db`. |

One gap worth noting within an otherwise-correct control: refresh token rotation revokes the presented token but does **not** implement reuse detection. OAuth 2.1 recommends that replay of an already-rotated refresh token invalidate the entire token family, since replay signals theft. Today the replay simply fails, leaving the thief's freshly-issued token valid. Worth adding alongside M-3's storage work.

---

## Suggested remediation order

1. **H-1** — offload bcrypt to a thread and add rate limiting. Highest impact, smallest change.
2. **M-4** — add the security-headers middleware. A few lines, closes the clickjacking path to consent.
3. **M-1 + L-2** — rewrite `verify_user` once; both are the same function.
4. **M-2** — require a session on `/oauth/callback` and drop the stateless fallback.
5. **M-3** — add client TTL/eviction to `purge_expired`, plus a registration cap.
6. **L-1, L-3, L-4, L-5** — hardening, sequence as convenient. L-5 is cheap and protects the system's most important invariant.

---

## Notes on method and limits

- Findings were reproduced with `pytest` tests driving live `uvicorn` gateway instances via the repository's `tests/conftest.py` fixtures. The PoC tests were run from a scratch directory and deliberately **not** committed; the L-5 recommendation includes the one that is worth keeping as a permanent regression test.
- Timing measurements were taken over loopback on a shared container; absolute numbers will vary, but the 270 ms gap in M-1 stems from a 256× bcrypt cost difference and is structural, not environmental.
- The existing suite (35 tests) passes and covers the OAuth flows well. It contains **no negative or abuse-case tests** — no assertions that malformed input is rejected, that unauthenticated callers are refused, or that the no-passthrough invariant holds. That gap is why L-5 can regress silently, and is the highest-value addition to the suite.
- Not covered: dependency CVE scanning, the `ui/` npm dependency tree, TLS configuration (deliberately delegated to a reverse proxy), and the security of the upstream backends themselves.
