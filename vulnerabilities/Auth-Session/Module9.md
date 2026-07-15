# Module 9: JWT Fundamentals - Cheatsheet

## Core Theme
A JWT is a self-contained, signed name tag that carries identity data on its face, instead of pointing to a server-side notebook. The signature guarantees integrity and authenticity ONLY - never confidentiality. This single architectural choice explains nearly every JWT vulnerability and the entire revocation tradeoff.

## Mental Model
Server-side session = name tag pointing to a notebook entry (Module 6).
JWT = a notarized, wax-sealed letter that carries the actual claims on its face - the seal (signature) proves it's genuine and unaltered, but anyone can read every word on the letter without ever having the seal-stamp.

## Structure
`header.payload.signature` - three Base64URL-encoded segments.
- Header: `{"alg": "HS256", "typ": "JWT"}` - declares signing algorithm
- Payload: the actual claims (user_id, role, exp, etc.)
- Signature: `HMAC-SHA256(base64(header)+"."+base64(payload), secret)` - the wax seal

**Critical: Base64 is encoding, not encryption.** Trivially, instantly reversible by anyone, no key required. Anyone who sees a JWT can read its full payload in seconds via jwt.io or any text editor.

## What the Signature Does and Does NOT Protect
- Protects: integrity (content unaltered since signing) and authenticity (produced by the real key holder)
- Does NOT protect: confidentiality. Never assume payload contents are hidden from anyone who possesses the token.

## Never Trust the `alg` Header - Algorithm Pinning

The `alg` field is attacker-controlled data traveling alongside the token. If the server dispatches its verification logic based on what the token CLAIMS about itself, two classic attacks follow:

**`alg: none` attack:** attacker edits payload freely (e.g., role: user -> admin), sets header to `{"alg":"none"}`, drops the signature entirely. A naive verifier sees `alg: none`, skips verification, accepts the forged token. Full privilege escalation, zero cryptography needed.

**RS256 -> HS256 algorithm confusion:** RS256 uses a private key to sign, public key to verify (often legitimately published, e.g. JWKS endpoint). Attacker changes `alg` to HS256 (symmetric - same key signs AND verifies) and signs using the known PUBLIC key as the HMAC secret. A vulnerable server, tricked by the `alg` field, uses that same public key as the symmetric secret for verification - accepts the forgery. No brute-forcing needed; the "secret" was legitimately public all along.

**Fix - algorithm pinning:** server independently decides, from its OWN configuration, exactly one acceptable algorithm and key - never dispatches based on the token's own `alg` claim. Best practice: instantiate the verifier locked to one specific algorithm/key so no other code path can even consider an alternate `alg` value (not just an `if` check, which can have subtle bugs - case sensitivity, alg name variants).

## Payload Data Mistakes (Confidentiality)

Common sensitive data wrongly placed in JWT payloads:
- PII (name, email, phone, address) "for convenience"
- Internal system details (sequential internal user IDs -> enumeration + business intel leak just from decoding, no attack needed)
- Business-sensitive data (subscription tier, account balance, pricing tier)
- Secondary secrets (API keys, internal service tokens embedded for downstream convenience) - most severe version

## Signing Secret Compromise: Categorically Worse Than Password Compromise

Cracking one user's password = one account compromised (Module 3).
Cracking the JWT signing secret (weak/guessable HS256 secret, brute-forceable offline from just one captured token) = forge ANY claim for ANY user, indefinitely, until manual key rotation - a full authentication bypass for the entire application, not a single-account incident. Treat signing keys with "root of trust" severity, not "just another password."

## The Revocation Gap (Direct Consequence of No Notebook)

Session flow: verify cookie -> LOOK UP current, live state in the notebook.
JWT flow: verify signature -> trust claims AS FROZEN AT SIGNING TIME. No lookup occurs at all - that's the entire design point.

**Result:** revocation is structurally impossible short of natural expiration. Ban a user, change their role, fire them - every JWT issued before that moment remains fully valid and accepted until its `exp` passes, regardless of what the server's database now says.

**Consequence for design:** token lifetime is the ONLY lever bounding exposure, since there's no other revocation control. Rule: **token lifetime should be inversely proportional to the severity of what it authorizes** - minutes for high-privilege actions (fund transfers), hours/longer tolerable for low-stakes ones (viewing a public profile).

## Reporting the Revocation Gap (Not a "Bug" - The Model Working As Designed)

Test: ban/demote a user server-side, confirm their still-unexpired JWT continues to work. This is a real, reportable structural finding - frame severity by what the token authorizes (High: admin/financial actions; Medium: standard user actions; Lower: minimal-scope, non-sensitive data).

**Do NOT just recommend "add revocation checks" vaguely** - name concrete mechanisms, each with a stated tradeoff:
1. **Server-side blocklist/denylist** checked every request - most direct, but reintroduces the per-request lookup cost JWTs were chosen to avoid
2. **Short-lived access token + refresh token pattern** (Module 10) - industry-standard middle ground; one deliberate, bounded checkpoint instead of every-request checking
3. **Token version / security-stamp claim** - server increments a version number on security-relevant events (ban, password change, role change); JWT carries the version at issuance; verification does one lightweight version-number lookup, far cheaper than a full session record

## Coverage Gap: A Secure JWT Implementation Protects Nothing It Isn't Actually Checked Against

Classic pattern: JWT signature verification is flawless everywhere it's used, but a SEPARATE endpoint trusts a raw client-supplied parameter (e.g., `GET /api/pricing?user_id=1024`) with NO JWT check at all. This is not a JWT vulnerability - it's Module 1's original IDOR pattern wearing a new costume. **A well-built control says nothing about its coverage** - every endpoint must independently enforce verification; nothing about JWTs existing elsewhere in the app implies protection here.

## Common Developer Mistakes
- Trusting the `alg` header instead of server-side pinning
- Sensitive/business data in the payload (forgetting encoding != encryption)
- Excessively long expiration with no compensating revocation mechanism
- No `exp` claim at all (valid forever by design)
- Weak/guessable HMAC secrets (offline brute-forceable from one captured token)
- Treating JWT presence as proof of CURRENT account state without supplementary checks for high-stakes actions
- Individual endpoints skipping JWT verification entirely while other endpoints correctly enforce it

## Detection Methodology
- Decode any issued JWT (no key needed) - inspect for sensitive data, sequential/enumerable IDs, detailed role/permission structures
- Attempt `alg: none` + stripped signature - does the server still accept it?
- If RS256 + discoverable public key (JWKS endpoint, app binary, docs) - attempt algorithm confusion (alg -> HS256, sign with the public key as HMAC secret)
- Check `exp` presence and whether duration is proportionate to what's authorized
- Offline brute-force/dictionary attack against HMAC secret from a captured valid token (within authorized scope only)
- Ban/demote a user server-side, test if their still-unexpired JWT keeps working - demonstrates the structural revocation gap without any forgery
- Map every endpoint reachable with a valid session/JWT and confirm EACH ONE independently enforces verification - don't assume coverage from one well-tested endpoint

## Secure Design Principles
- Never trust the `alg` header - pin algorithm and key server-side
- Treat payload as fully public/readable - no PII, secrets, or business-sensitive data
- Always include and enforce `exp` - no indefinitely valid JWT
- Token lifetime inversely proportional to authorization severity
- Strong, high-entropy HS256 secrets, or prefer RS256/ES256 with proper key management
- Deliberately reintroduce bounded statefulness where revocation matters (blocklist / refresh-token / version-stamp) - pick based on cost/exposure tradeoff
- Every endpoint independently enforces JWT verification

## Common Misconceptions
- "JWTs are inherently more secure than sessions" - different tradeoffs (revocation ease vs. lookup-free scale), neither universally superior
- "Base64 provides some security" - encoding, not encryption, trivially reversible
- "Signature verification protects the whole app" - only protects the token's own integrity; unrelated unchecked endpoints remain fully exposed
- "The revocation gap is just how JWTs work, not a valid finding" - it IS a real, reportable structural gap requiring a concrete architectural mitigation

## Session vs JWT: Default Recommendation
- **Banking / high-control needs -> server-side sessions.** Revocation must be immediate and total; trivial notebook-erasure beats any JWT mitigation.
- **Public API, millions of low-stakes read requests/sec -> JWTs.** Lookup-free verification scales; exposure window is boundable via short expiration since individual request stakes are low.
- Core tradeoff to state in any design discussion: **revocability vs. lookup-free scalability.**
- In practice, most large systems hybridize: short-lived JWT for the scale-sensitive access path + server-tracked refresh token for the control-sensitive revocation path (Module 10).

## Variations & Edge Cases
- **JWE (JSON Web Encryption)** - genuinely encrypted JWT variant, addresses confidentiality directly; far less common than signed-only JWS in practice
- **`kid` (Key ID) header injection** - if not validated against an allowlist, enables SQLi/path traversal/key-confusion attacks; same root cause as the `alg` trust problem, more advanced
- **JWT in localStorage** (SPA pattern) - sidesteps cookie-based CSRF but trades in XSS-readability risk (Module 7 tension, resurfacing)

## Reporting Reference
- **`alg: none` / algorithm confusion accepted**
  - CWE-347 (Improper Verification of Cryptographic Signature)
  - OWASP: A02:2021 - Cryptographic Failures
- **Sensitive data in JWT payload**
  - CWE-200 (Exposure of Sensitive Information)
- **No/weak `exp`, excessive lifetime with no revocation mitigation**
  - CWE-613 (Insufficient Session Expiration)
- **Weak/guessable HMAC signing secret**
  - CWE-326 (Inadequate Encryption Strength), CWE-321 (Hard-coded key, if applicable)
- **Endpoint bypassing JWT verification entirely (IDOR via unchecked parameter)**
  - CWE-639 (Authorization Bypass Through User-Controlled Key), OWASP A01:2021

## Key Test to Remember
For any token-based system: "What decisions is the server making based on this token, and is any of that data either (a) attacker-controlled and not independently re-validated, or (b) sensitive and assumed-hidden when it's actually fully readable?" Then separately: does EVERY endpoint that should require this token actually check it?