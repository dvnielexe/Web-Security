# Module 3: Password Storage & Hashing — Cheatsheet

## Core Theme

> **Hashing ≠ Encryption. Salting ≠ Slow. Each defense solves one specific problem — evaluate each independently before calling storage "secure."**

Mental model: **shredder, not safe.** Encryption is reversible by design (a safe — get the original back with the key). Hashing is irreversible (a shredder — prove equality without ever reconstructing the original). Passwords must never be reversible.

## Why Encryption Is Worse Than Even Plaintext-with-Access-Controls

- Encryption preserves full plaintext-equivalent blast radius (every password recoverable) **while creating false confidence it's "secure."**
- Compromise of ONE key = compromise of ALL passwords, instantly, in recoverable form.
- Real finding name: **"Passwords Stored Using Reversible Encryption Instead of One-Way Hashing"** — treat as critical severity, same as plaintext storage.

## Required Properties of a Password Hash

| Property | Meaning | Why it matters for passwords |
|---|---|---|
| One-way / pre-image resistant | Can't reverse output→input | Stolen hash ≠ recovered password |
| Deterministic | Same input → same output always | Server can re-check on next login |
| Collision-resistant | Hard to find two inputs, same output | Prevents forging a "matching" password |
| **Slow / computationally expensive** | Deliberately costly per attempt | **The critical property for passwords specifically** |

## Why MD5/SHA-256 Are Wrong for Passwords (Precise Reasoning)

- They are NOT "broken" as hash functions (SHA-256 is not cryptographically broken) — they are simply **too fast**.
- Speed is a FEATURE for file integrity checks (no one is guessing the input). Speed is **the vulnerability itself** for passwords (attacker doesn't have the input, is guessing it offline, billions of guesses/sec possible on fast hashes with GPU/ASIC).
- **Imprecise report language to avoid:** "MD5 is cryptographically broken, therefore bad for passwords" — the collision weakness isn't why it's wrong here; the speed is.

## Salting

**What it defeats:**
- Cross-user pattern leakage (identical passwords → identical hashes, revealing shared passwords across a breached DB without cracking anything)
- Rainbow table / precomputation attacks (attacker can't reuse one precomputed table across many databases)

**What it does NOT defeat (critical distinction):**
- **Per-target brute-force speed.** A salt does nothing to slow down an attacker guessing repeatedly against ONE specific user's hash — `hash(guess + known_salt)` is computed exactly as fast as `hash(guess)` if the underlying algorithm is fast.
- Salt solves *reuse/precomputation*. Algorithm choice solves *per-guess cost*. **Both are required, independently — neither substitutes for the other.**

**Salt requirements:** random, unique per password, need NOT be secret (fine to store in plaintext next to the hash) — but must be unique. A **static/shared salt across all users is functionally a fake salt** — it collapses back to the "identical password → identical hash" problem and is crackable in bulk (crack ONE hash, derive the shared salt, apply to the rest of the database).

## Purpose-Built Password Hashing Algorithms

| Algorithm | Mechanism | Notes |
|---|---|---|
| bcrypt | Blowfish-based, deliberately slow, tunable work factor | Still acceptable; longest battle-tested; less memory-hard |
| scrypt | Slow + memory-hard | Improvement over bcrypt |
| **Argon2id** | Slow + memory-hard + resists GPU/ASIC parallelization | Current best practice; won Password Hashing Competition |

- All three **handle salting internally/automatically** — don't roll your own salt logic.
- **Memory-hardness** is the key evolution: GPUs/ASICs excel at parallelizing fast, low-memory computation. Forcing each guess to consume RAM makes parallel scaling far more expensive (more cores ≠ cheap when each core also needs proportional memory).
- Neither bcrypt nor Argon2 is "strictly better" on every axis — bcrypt has longer track record/fewer implementation bugs; Argon2 has stronger structural resistance to modern parallel-cracking hardware.

## Common Developer Mistakes

- Reversible encryption instead of hashing
- Fast general-purpose hash (MD5/SHA-1/SHA-256/512) with no work-factor concept
- Rolling your own "slow-down" scheme (manual iteration loops) instead of vetted algorithms
- Static/shared/hardcoded salt instead of per-password random salt
- Silent password truncation (some bcrypt implementations ignore bytes beyond 72 — test edge-case long passwords)
- Logging plaintext passwords anywhere before the hash boundary
- "We use bcrypt" with cost parameters configured absurdly low (e.g., iteration count of 1) — technically correct algorithm, none of the actual protection

## Black-Box Detection Methodology (no source/DB access)

**Timing signal for algorithm speed:**
1. Take multiple repeated samples of login response time — never trust a single measurement (network jitter/server load noise)
2. Compare against a non-computational baseline endpoint (simple GET) on the same app
3. Look for a **consistent, reproducible delta**: tens–hundreds of ms → likely slow/memory-hard algorithm; negligible delta → likely fast hash
4. **Confounders to rule out before concluding:** rate-limiting/artificial delay padding, CDN/WAF caching (check `cf-cache-status`, `X-Cache` headers), result caching on repeated identical requests

**Distinguishing competing explanations for an unexpected observation (general discipline):**
- Treat every observation as a **hypothesis, not a finding**
- Ask explicitly: what exact property does this prove, vs. what am I assuming?
- Design ONE targeted test that can confirm or falsify it before writing the conclusion
- Example: "app emails a plaintext temp password on reset" does NOT by itself prove reversible storage — it's equally consistent with "generates new random password, hashes it, overwrites old hash, emails the new plaintext once." **Test to distinguish:** try logging in with the ORIGINAL password after receiving the temp one. If original still works → reversible storage confirmed. If original no longer works → safe pattern (new credential generated, no reversibility). These are TWO SEPARATE FINDINGS (storage reversibility vs. insecure credential delivery via email) — don't conflate them in a report.

## Secure Design Principles

- One-way hashing only, never reversible encryption
- Argon2id preferred; bcrypt/scrypt acceptable; nothing else
- Salt: random, unique per password, doesn't need to be secret, must be unique
- Use library-handled salting, don't roll your own
- Tune cost parameters to current hardware — this is a moving target requiring periodic revisiting
- Never log plaintext passwords before the hash boundary

## Common Misconceptions

- "It's hashed, so it's secure" → hashed with what algorithm, what cost factor, salted how?
- "We use a salt" → shared/static salts provide none of salting's real benefit
- "MD5/SHA-256 are broken, that's why they're bad for passwords" → imprecise; they're not broken as hash functions, they're simply too fast for this use case
- "bcrypt is outdated, must use Argon2" → bcrypt remains acceptable; Argon2 is preferred, not mandatory
- "Emailing a plaintext temp password proves reversible storage" → does NOT — could be a freshly generated credential; requires a follow-up test (see above) to confirm

## Variations & Edge Cases

- **Pepper**: additional secret value (unlike salt — kept secret, stored outside the DB, e.g. HSM/env config) added to hash input; defense-in-depth if DB alone is breached
- **Password truncation bugs**: test long passwords for silent truncation (bcrypt 72-byte limit in some implementations)
- **Legacy migration**: apps moving MD5→bcrypt often re-hash opportunistically on next login rather than forcing mass resets — recognize this as a valid interim state, not automatically a flaw

## Reporting Reference

- **Reversible encryption / plaintext-equivalent storage**
  - OWASP: A02:2021 – Cryptographic Failures
  - CWE-257 (Storing Passwords in a Recoverable Format), CWE-321 (Use of Hard-coded Cryptographic Key) if key is embedded
- **Fast/weak hash algorithm (MD5/SHA-256, no work factor)**
  - OWASP: A02:2021 – Cryptographic Failures
  - CWE-916 (Use of Password Hash With Insufficient Computational Effort)
- **Static/shared/missing salt**
  - CWE-759 (Use of a One-Way Hash without a Salt), CWE-760 (Use of a One-Way Hash with a Predictable Salt)
- **Insecure credential delivery (plaintext password via email)**
  - CWE-522 (Insufficiently Protected Credentials)
  - Report SEPARATELY from any storage-reversibility claim unless independently confirmed

## Key Test to Remember
Black-box "is this reversible storage or just bad delivery?" → after a plaintext-password reset email, try logging in with the OLD password. Still works = reversible storage. Doesn't work = safe generate-and-replace pattern (separate, lesser finding: insecure delivery only).