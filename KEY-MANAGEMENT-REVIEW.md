# Key Management for the Encrypted SQLite Store

**Date:** 2026-08-24
**Scope:** how `MCP_GATEWAY_ENCRYPTION_KEY` is supplied, stored, and used to protect
`data/gateway.db` — not a general security review (see `SECURITY-REVIEW.md` for that;
this document is based on this branch, which already includes that review's fixes).
**Trigger:** a follow-up question after the security review — "the SQLite values are
encrypted with a key from an env var; is that best practice, and can we do better?"

This is a discussion document, not a set of applied fixes. It ends with concrete,
prioritized recommendations, but no code has been changed.

---

## Short answer

Supplying the key via an environment variable is a **reasonable, common baseline** for
a project explicitly scoped as a self-hosted, single-instance "personal gateway" — it's
better than a hardcoded key or an unencrypted database, and it keeps the deployment
story to "set one env var." It is **not**, however, what a security-conscious production
deployment would consider best practice for a secret of this sensitivity, for two
independent reasons:

1. **Env vars are a comparatively leaky container for secrets** — better options exist
   at roughly the same implementation cost (see [What's leakier about env vars](#whats-leakier-about-env-vars-specifically)).
2. **The scheme has no key rotation, and no separation between the key an operator
   manages and the key that actually encrypts data** — envelope encryption is the
   standard fix, and it's what most "best practice" guidance is actually pointing at
   when it says "manage your keys properly."

Neither gap is really about *where the key comes from*, though — see the next section.

This branch already tightened one adjacent knob (`SECURITY-REVIEW.md` finding I-4:
the scrypt cost factor for passphrase-style keys was raised from `n=2**14` to
`n=2**17`, matching current OWASP guidance). That's a real, useful improvement to how
hard a *stolen passphrase* is to brute-force — but it doesn't touch either of the two
gaps below, which are about the key that's actually in use, not about how expensive it
is to guess one.

---

## The fundamental limit: key and ciphertext share a trust boundary

Before recommending anything, it's worth being precise about what encrypting the
SQLite values actually buys, because no amount of key-handling hardening changes it.

`Storage` (`src/mcp_gateway/storage.py`) uses the `encryption_key` to build a `Fernet`
instance directly in the gateway process, and that same process is what needs to
decrypt `upstream_data` on every proxied MCP call (to attach a backend's bearer token
or refresh its OAuth tokens) and `oauth_clients` on every `/authorize` and `/token`
request. That means:

- The key **must** be available, in plaintext, in the memory of the exact process that
  can also read `gateway.db` off disk. There is no way to encrypt data "at rest" here
  without the runtime holding the key — this isn't a design flaw, it's what "encrypt at
  rest, decrypt on use" means for a service that has to use the data continuously.
- Consequently: **anyone with code execution inside the running container can read
  everything**, key included — `docker exec`, a container escape, a supply-chain
  compromise of a dependency, or a vulnerability in the gateway itself all bypass the
  encryption entirely, the same way they would bypass a KMS-backed scheme too, unless
  decryption happens in a separate trust domain the compromised process must call out
  to (an HSM or remote KMS that never releases the raw key — see
  [What we're deliberately not recommending](#what-were-deliberately-not-recommending)).

So the actual value of at-rest encryption here is narrower than "protects the
database," and worth naming explicitly: it protects against someone or something that
can obtain **the database file without the running process** — a stolen or
mis-permissioned backup, a snapshot of the Docker volume, a copy of `gateway.db`
attached to a bug report, a misconfigured bucket sync, a second party with read access
to the volume mount but not to the container. Every recommendation below is in service
of keeping the key *out* of that same blast radius, not of defending against a fully
compromised gateway process (which, by construction, can't be defended against by any
change to how the key is stored).

---

## What's leakier about env vars specifically

Compared to a file-based secret (a Docker/Compose `secrets:` mount, a Kubernetes
`Secret` volume, a Vault Agent sidecar writing to a `tmpfs` path), a plain environment
variable:

- Shows up verbatim in `docker inspect <container>` and in `docker compose config`
  output, both of which are things people paste into GitHub issues, Slack, or CI logs
  without thinking about it.
- Is readable by anything with `/proc/<pid>/environ` access for the same UID — any
  other process that ends up running as the `gateway` user (a shell someone opens for
  debugging, a sidecar sharing the PID namespace) can read it, not just the gateway
  binary.
- Is inherited by every child process the gateway ever spawns, and shows up in most
  crash-reporting / APM integrations' default "environment" capture unless explicitly
  scrubbed — a risk that grows, not shrinks, as the project adds instrumentation later.
- Is easy to leave sitting in shell history or a `.bash_profile` from manual
  `export MCP_GATEWAY_ENCRYPTION_KEY=...` during ad-hoc debugging, even though the
  documented flow (`.env`, gitignored, loaded by `docker compose`) avoids that.

None of this is exotic — it's the standard reasoning behind "prefer files/secret
volumes over env vars for anything you'd call a credential," and it applies here
exactly as much as it would to a database password or an API key.

---

## Two gaps that are about the *scheme*, not the transport

### No key rotation

`_init_fernet` (`storage.py:118`) builds the Fernet key directly from
`encryption_key` (or from a passphrase stretched with scrypt — see the next point). If
the operator ever needs to rotate `encryption_key` — because it leaked, because of a
compliance requirement, because an employee with access left — there is currently no
supported path to do that:

```python
def get_client(self, client_id: str) -> dict[str, Any] | None:
    ...
    try:
        return self._decrypt_json(row[0])
    except InvalidToken:
        return None  # encryption key changed; treat as unknown client
```

Changing `encryption_key` today doesn't rotate anything — it **silently orphans every
existing encrypted row**. `get_client`/`get_upstream` catch `InvalidToken` and just
return `None`, so a key change looks like "all registered clients and all connected
backends vanished," not like an error. Nothing in the codebase or README currently
warns an operator about this before they do it. (This branch's L-3 fix added a similar
"invalidate cleanly, on purpose" mechanism for browser *sessions* — `revoke_session`/
`is_session_revoked` in `storage.py` — but that's a deliberate, explicit revocation
path; nothing analogous exists for the *data* encryption key, where the equivalent
event — a key change — currently happens by accident of `InvalidToken` rather than by
a designed rotation flow.)

### No separation between the operator's key and the data's key

Right now the operator-supplied `encryption_key` (or a key derived from it) is used
*directly* as the Fernet key for every row. Standard practice for a system that expects
to rotate keys is **envelope encryption**: generate a random Data Encryption Key (DEK)
once, encrypt all the actual data with the DEK, and encrypt only the small DEK itself
with the operator's Key Encryption Key (KEK). Rotating the KEK then means re-wrapping
one ~32-byte value, not re-encrypting the whole database.

Interestingly, the codebase already has half of this pattern — `get_or_create_secret`
generates a random value and stores it encrypted with the KEK-derived Fernet key:

```python
def get_or_create_secret(self, name: str, nbytes: int = 32) -> str:
    """Stable random secret persisted (encrypted) in the database."""
    existing = self._meta_get(name)
    if existing is not None:
        try:
            return self._fernet.decrypt(existing.encode()).decode()
        except InvalidToken:
            pass  # encryption key changed; regenerate
    value = secrets.token_urlsafe(nbytes)
    self._meta_set(name, self._fernet.encrypt(value.encode()).decode())
    return value
```

— but this is used today only for the session-signing secret, and even there, an
`InvalidToken` on a key change just **silently regenerates** the secret (invalidating
every open browser session, on top of — after this branch's L-3 fix — the *explicit*
per-session revocation logout now performs) rather than being treated as the rotation
signal it actually is. Applying the same "random value, wrapped by the KEK" shape to
the *data* encryption key too — rather than using the KEK-derived key directly — is
what turns "change `encryption_key`" from a destructive operation into a rotation the
gateway can support with a small, explicit migration.

---

## Recommendations

Ordered by (impact protecting the key) ÷ (implementation effort), given this project's
explicit scope as a small, single-admin, self-hosted service — not by generic
"enterprise security checklist" importance.

### 1. Accept the key from a file, not just an env var

Add an alternative config field, e.g. `auth.encryption_key_file`, read once at startup
(strip trailing whitespace/newline) with the same fallback logic `_init_fernet`
already has (try as a raw Fernet key, else treat as a passphrase). This is a small,
additive change — `encryption_key` keeps working exactly as it does today — but it lets
an operator plug in whatever they already use for secrets without any gateway code
change on their side:

- **Docker Compose `secrets:`** — mounted at `/run/secrets/<name>`, 0400, not visible
  in `docker inspect`. A drop-in replacement for the current
  `environment: {MCP_GATEWAY_ENCRYPTION_KEY: ...}` in `docker-compose.yml`.
- **Kubernetes `Secret` volumes** — same shape, works the same way.
- **Vault Agent / External Secrets Operator / cloud KMS sidecars** — these virtually
  all work by writing the resolved secret to a file on a `tmpfs`, specifically so the
  target application doesn't need bespoke SDK integration. A file-based config option
  is the one thing that makes the gateway compatible with *all* of them for free.

This is the highest-value, lowest-effort item here: it doesn't ask the gateway to
integrate with any specific secrets manager, it just stops requiring the one transport
(env var) that's incompatible with the file-based convention nearly every secrets
manager uses.

### 2. Add envelope encryption + a `rotate-key` command

Generate a random DEK on first run (via the existing `get_or_create_secret` pattern,
generalized), use it — not the KEK-derived key — for all `_encrypt_json`/`_decrypt_json`
calls, and add:

```
mcp-gateway rotate-key --old-key-file OLD --new-key-file NEW
```

which decrypts the wrapped DEK with `OLD` and re-encrypts it with `NEW`: an O(1)
operation regardless of how many rows the database has, and no data is at risk of
being silently orphaned. This turns key rotation from "not supported, and changing the
key destroys data without warning" into a documented, safe operation — arguably more
impactful for real-world security posture than the transport question in
recommendation 1, since a key that's known to have leaked but can't be rotated safely
tends to just... not get rotated.

### 3. Fail loudly, not silently, on a key mismatch

Independent of envelope encryption: today, a wrong/changed key makes clients and
backend connections quietly disappear (`InvalidToken` → `None`). At minimum, log an
explicit `ERROR` the first time a decrypt fails after startup ("stored data could not
be decrypted with the configured encryption_key — has the key changed? see
[rotation docs]"), so this surfaces as an operational alert rather than a confusing
"why are my backends showing as disconnected" bug report.

### 4. Document Compose `secrets:` as the recommended pattern today

Even before (1) exists in code, `docker-compose.yml` and the README's Quick Start
currently point operators at `environment:`, which is the leakier of the two options
Compose itself supports. Worth a documentation note now regardless of whether (1) ships:
Compose can inject a secret as a file into the container at a fixed path without any
gateway support, if the gateway is told to read a file at that path — which is exactly
what (1) would add.

### 5. Treat the volume/disk as a second, complementary layer — not a replacement

Application-level encryption (what this gateway does) and disk/volume-level encryption
(LUKS, an encrypted EBS volume, etc.) protect against *different* things and are worth
having both, not one instead of the other:

- Disk encryption protects the data when the physical disk or volume is stolen or
  decommissioned **while the key is not available** — but once the volume is mounted
  and the OS is running, disk encryption is transparent and offers no protection
  against reading the raw `gateway.db` file.
- Application-level Fernet encryption protects the specific fields even when the file
  itself leaks *while mounted* — a backup copied to the wrong bucket, a volume snapshot
  shared with the wrong team, a support bundle — precisely the scenarios named above.

Recommend operators encrypt the underlying volume as well, as defense in depth, but
this is orthogonal to anything in the gateway's code and doesn't need to block on it.

### 6. Document a key-loss runbook

Given (2)/(3) don't exist yet: state plainly, next to the `MCP_GATEWAY_ENCRYPTION_KEY`
instructions in the README, that losing the key means losing every registered OAuth
client and every connected backend's tokens irrecoverably (clients will need to
re-register via DCR, backends will need reconnecting) — and recommend operators back
the key up the same way they'd back up any other irreplaceable credential (a password
manager, a sealed secret in their org's vault), not just rely on `.env` on the host.

---

## What we're deliberately *not* recommending

**A pluggable KMS/HSM backend** (AWS KMS, GCP KMS, Vault Transit, etc.) where the raw
key never enters the gateway's memory at all, and every encrypt/decrypt is a network
call to the external service. This is the natural "final" step in key management for a
production multi-tenant system, and it's the only option that actually changes the
[trust-boundary](#the-fundamental-limit-key-and-ciphertext-share-a-trust-boundary)
argument above (a compromised gateway process still can't read historical data itself,
only decrypt *the tokens it currently needs* through the KMS call, and every call is
auditable/revocable at the KMS).

It's a legitimate next step if this project's scope grows toward multi-tenant or
larger organizational deployments, but for the stated scope — *"a lightweight,
self-hosted... personal gateway"* (README) with a single admin and a SQLite file
described as "the only state" — it adds meaningful operational complexity (network
dependency for every token decrypt, cloud-provider-specific integration code, credentials
to reach the KMS which just becomes the new "key to protect") for a threat model this
project isn't targeting. Recommendations 1–3 get most of the realistic benefit at a
fraction of the cost; this is worth revisiting only if the project's positioning
changes.

Similarly not recommended right now: migrating from field-level Fernet encryption to
whole-database encryption via **SQLCipher**. It would reduce the amount of custom
code doing the encrypt/decrypt bookkeeping, but the current implementation already
uses a standard, well-audited primitive (`cryptography`'s `Fernet`) rather than
hand-rolled crypto, so the marginal safety benefit is small relative to the cost of
swapping the storage layer.

---

## Summary

| # | Recommendation | Effort | Addresses |
|---|---|---|---|
| 1 | Accept the key from a file (`encryption_key_file`), not just an env var | Small | env-var leak surface |
| 2 | Envelope encryption (DEK wrapped by KEK) + `mcp-gateway rotate-key` | Medium | no rotation path |
| 3 | Log loudly (not silently) on a decrypt failure after startup | Small | silent data loss on key mismatch |
| 4 | Document/offer Compose `secrets:` instead of `environment:` | Small (docs only, today) | env-var leak surface |
| 5 | Recommend volume/disk encryption as defense in depth | None (docs only) | different threat (offline theft) |
| 6 | Document a key-loss runbook | Small (docs only) | operational risk, unowned today |
| — | KMS/HSM backend, SQLCipher migration | Large | out of scope for this project's stated size today |

None of this is a response to a live vulnerability — the current scheme (Fernet,
scrypt-stretched passphrase at `n=2**17` as of this branch's I-4 fix, hashed tokens, no
plaintext secrets logged) is sound for what it claims to do. The gaps above are about
**operational maturity of key handling** (rotation, blast radius of the key's storage
location) rather than a flaw in the cryptography itself, and recommendations 1, 3, and
4 in particular are cheap enough that there's little reason not to just do them.
