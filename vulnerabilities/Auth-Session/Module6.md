# Module 6: HTTP Statelessness & Why Sessions Exist — Cheatsheet

## Core Theme

> **HTTP has zero memory between requests. Sessions are a workaround, not a native feature. The session ID is a lookup key (name tag) — the actual identity data lives in server-side storage (notebook). Confusing the two, or trusting anything that crosses from notebook to client and back, is the root of most session vulnerabilities.**

## Mental Model: Name Tag & Notebook

- HTTP = talking to someone with total amnesia between every sentence
- Session ID (name tag) = a lookup key handed to the client, meaningless on its own
- Server-side session store (notebook) = where the actual truth about identity/role/permissions lives
- The name tag does not make the server remember you — it's a pointer into a record the server already wrote

## Two Fundamentally Different Session Architectures

| | Server-side (opaque reference) sessions | Client-side (self-contained) tokens (JWT, Module 9) |
|---|---|---|
| What the "name tag" contains | Meaningless random ID | The actual identity data, cryptographically signed |
| Where truth lives | Server-side notebook (DB/Redis/memory) | On the token itself |
| Revocation | Trivial — erase the notebook entry, ID instantly worthless | Architecturally hard — no notebook entry to erase, valid until natural expiry |
| Server-side lookup required? | Yes, every request | No — that's the entire point |

**Core tradeoff to carry forward:** server-side sessions trade a lookup cost for easy revocation; client-side tokens trade easy revocation for no-lookup speed. Neither is "more secure" in the abstract — they have opposite failure modes.

## Session ID Requirements (Same Math as Module 5 Reset Tokens — Amplified)

- **128+ bits of entropy, CSPRNG-generated, opaque** — no usability excuse exists (never human-typed, lives in a cookie).
- **Longer-lived than reset tokens (hours/days/weeks vs. minutes)** → the attacker's brute-force time budget is LARGER, making entropy even more critical here, not less.
- Formula from Module 5 applies directly: `keyspace ÷ achievable guesses within valid lifetime = attack feasibility`.
- **Entropy has a practical ceiling** — 128 bits is already infeasible to brute-force with any realistic resource budget. 256 bits is not meaningfully more secure in practice; don't flag "only 128 bits" as a finding once past this threshold.
- **Deterministic generation from guessable inputs is a critical flaw regardless of output length** — e.g., `md5(timestamp + email)` produces 128-bit-looking output, but if inputs are guessable/enumerable, attacker recomputes rather than brute-forces. Output length is a red herring if input space is small. (Same lesson as Module 3's static-salt MD5 and Module 5's 26^6 keyspace — always check the actual attacker-facing search space, not the output format.)

## Repeated Transmission = Expanded Attack Surface (vs. Reset Tokens)

- Reset token: transmitted once, ideally invalidated immediately after use — one narrow interception window.
- Session ID: retransmitted on **every single request**, for the entire session lifetime (potentially days) — many independent interception opportunities, attacker only needs to succeed once.
- **This is the first-principles justification for the `Secure` cookie flag** (mandatory HTTPS-only transmission) — full cookie attribute coverage in Module 7.

## Full Session Lifecycle (Preview — Full Detail in Module 8)

```
Creation → Transmission (repeated) → Validation (every request) → Expiration/Invalidation
```
- Creation needs high entropy
- Transmission needs a secure channel, repeatedly
- Validation = the notebook lookup — must also correctly determine AUTHORIZATION, not just "does this session exist" (Module 1 callback)
- Expiration/Invalidation = where Module 5's "sessions survive password change" gap lives

## The Recurring Failure Pattern: Treating Client Data as Notebook Content

**The vulnerability class, precisely named:** server derives an authorization decision from a client-supplied value (hidden field, custom header, round-tripped response data) instead of re-deriving it from the server-side session lookup.

- Module 1's `user_id` in order lookup, Module 1's `X-User-Role` header, Module 2's `user_id` in email-change, and Module 6's `role` sent back as `X-Client-Role` are **all the same underlying bug**, appearing in different forms.
- **Critical insight: a secure session mechanism only guarantees AUTHENTICATION is sound.** It says nothing about whether every individual authorization decision actually sources from that mechanism, versus quietly sourced from something client-controlled sitting alongside it.
- **Even data the server itself originally sent is untrustworthy once round-tripped.** The moment data crosses from notebook → client, it must be treated as untrusted the instant it returns, regardless of origin. "I sent it to you" is not "I can trust it coming back."
- **Why this bug is common and usually unintentional:** typically introduced as a performance optimization ("save the backend a lookup") by someone thinking about UI convenience, not security — collapsing the distinction between "data for rendering" and "data for authorization decisions." Useful framing for reports: this is a boundary-confusion bug, not negligence — frame it that way to help fixes land faster.

## Common Developer Mistakes

- Low-entropy/predictable session IDs (sequential, timestamp-based, weak PRNG, or deterministic hash of guessable inputs)
- Session ID transmitted via URL parameter instead of cookie (inherits Module 5's Referer/history/log exposure)
- Session ID never rotated after login (→ session fixation, see below)
- Missing `Secure` flag
- Trusting client-supplied authorization data (role/permission fields/headers) instead of deriving purely from server-side lookup

## Detection Methodology

- Check session ID entropy/format — random opaque string vs. patterned (sequential/timestamp/short)?
- Check if session ID ever appears in a URL instead of purely a cookie
- Check `Secure` flag presence (test: force an HTTP connection, does the cookie transmit?)
- **Critical test:** find every request carrying authorization-relevant data (role, tier, permissions) OUTSIDE the session cookie — hidden fields, custom headers, JSON fields — tamper with it, check if server behavior changes independent of actual session-lookup truth
- **Session fixation test (derived from first principles, not memorized):**
  - Can you set/fix a known session ID before a victim authenticates?
  - Does login fail to rotate the session ID (same ID pre- and post-auth)?
  - After logout, is the session truly invalidated server-side, or still usable?

## Missing `Secure` Flag on an HTTPS-Only App — Still a Real Finding

Even with HTTPS-everywhere + HSTS and no HTTP endpoints: **`Secure` is an independent, protocol-level enforcement layer, not redundant with HSTS.** Without it, cookie confidentiality depends entirely on *perfect, permanent* infrastructure correctness (no regression, no future misconfigured subdomain, no TLS-terminating proxy forwarding plaintext internally, no accidental HTTP debug endpoint). Report as **defense-in-depth / missing security control**, typically Low-to-Medium severity given current low exploitability — NOT "no impact." Correct framing: *"cookie confidentiality currently depends on infrastructure-level correctness rather than the protocol itself."*

## Secure Design Principles

- Session ID: 128+ bits entropy, CSPRNG, opaque, no embedded meaning
- Session ID lives in a cookie only, never a URL
- `Secure` flag mandatory regardless of perceived redundancy with HTTPS-only deployment
- Authorization data always re-derived server-side from session lookup on every request — never accepted from any client-supplied or round-tripped value
- Treat any value that leaves server control as untrusted the instant it returns, regardless of who originally issued it

## Common Misconceptions

- "The session ID is the identity" → it's a lookup key; identity lives server-side
- "The server sent me this value, so it's safe to send back" → the round-trip itself breaks trust; origin doesn't matter
- "A secure session mechanism = the whole authz system is secure" → session security only guarantees authentication; every authorization decision must independently source from the server
- "128 bits vs 256 bits entropy matters a lot" → both are already past the practical brute-force feasibility ceiling
- "HSTS + HTTPS-only means `Secure` flag is redundant" → it's an independent safety net for infrastructure regression, not a redundant control

## Variations & Edge Cases

- **Stateless sessions (JWT)** — inverts this entire model (data on the tag, no notebook); full tradeoff analysis in Module 9
- **Distributed session storage** — notebook becomes a shared store (Redis/DB) for load-balanced clusters; introduces consistency/latency considerations, not inherently a security flaw
- **Session tokens in localStorage/sessionStorage** (SPA pattern) — avoids some cookie-based CSRF concerns but trades in XSS-readability risk — tension explored further in Module 7

## Reporting Reference

- **Session fixation (no rotation on login)**
  - OWASP: A07:2021 – Identification and Authentication Failures
  - CWE-384 (Session Fixation)
- **Predictable/low-entropy session ID**
  - CWE-330 (Use of Insufficiently Random Values), CWE-331 (Insufficient Entropy)
- **Client-controlled authorization data (role/permission from header/field, not session lookup)**
  - CWE-602 (Client-Side Enforcement of Server-Side Security), CWE-639 (Authorization Bypass Through User-Controlled Key)
- **Missing `Secure` flag**
  - CWE-614 (Sensitive Cookie Without 'Secure' Attribute) — Low-Medium, frame as defense-in-depth gap even on HTTPS-only apps

## Key Test to Remember
First-principles session fixation test: does the session ID value change between pre-auth and post-auth states? Same value throughout = no rotation = attacker-fixed session IDs can become authenticated sessions the moment a victim logs in using them.