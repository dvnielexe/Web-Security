# Module 2: Login & Registration Workflows — Cheatsheet

## Core Theme

> **Trust established at registration propagates silently into every downstream feature. Verification isn't a formality — it's the only step that converts a claim into a credential.**

Registration = passport office (decides how much proof is required to issue identity).
Login = border check (verifies the passport matches the person, right now).
A weak passport office makes every downstream border check meaningless.

## Registration Workflow (Standard Pipeline)

```
1. Client submits { email, password, [fields] }
2. Server validates input (format, password policy) — server-side, never trust client-side only
3. Server checks if identity already exists
4. Server creates account record — SHOULD be in "unverified" state
5. Server hashes + stores password (Module 3)
6. Server sends verification mechanism (email link / OTP)
7. User completes verification → account becomes "active"/"trusted"
```

**Critical design rule:** Between step 4 and step 7, the account must be **functionally inert** — no login, no invite-targeting, no directory visibility, no API access — until verification completes. If ANY feature trusts the email field before verification, that feature has silently reopened the trust boundary registration was supposed to close.

## Claim vs. Credential

- **Claim** = an assertion with no proof behind it (e.g., an email field in a registration form)
- **Credential** = an assertion backed by proof of control (e.g., a clicked verification link, a correct password)

**Rule:** If any system feature treats a claim as if it were a credential, that is the vulnerability — regardless of how far from the registration form that feature lives (invites, directories, password reset, SSO domain trust).

## Enumeration — Full Vector List (not just error messages)

Enumeration is a **category** of side-channel from asymmetry between "exists" and "doesn't exist" code paths. Check ALL of these, not just the obvious one:

| Vector | Mechanism |
|---|---|
| Response body / error text | "Invalid password" vs "Invalid username" |
| HTTP status code | 200 vs 409 Conflict on registration |
| Timing | Hash comparison skipped entirely if account not found (asymmetric work) |
| Rate limiting / lockout behavior | Valid accounts lock out after N attempts; invalid accounts never do |
| Response size / structure | Subtly different payload shape |
| Cache headers | Different cache-control on found vs not-found |
| Secondary features | "Resend verification" behaving differently for real vs fake addresses |

**Downstream impact of enumeration:** doesn't just enable social engineering — it converts a blind brute-force/credential-stuffing attack into a **targeted** one, since attacker traffic is now concentrated only on confirmed-valid accounts (also makes attack traffic less anomalous to detection systems).

## Login Workflow — Timing Oracle

```
1. Look up account by email
2. Hash submitted password, compare to stored hash
3. Match → issue session
4. No match → failure
```

**Vulnerable pattern:** if account not found, server short-circuits and skips step 2 entirely → faster response → timing side-channel reveals account existence even with identical error text.

**Fix:** always perform equivalent computational work regardless of outcome (e.g., compare against a dummy hash when account doesn't exist) + constant-time comparison. Don't rely on artificial delay alone — padding can still be measurably inconsistent.

## Common Developer Mistakes

- Full account usability before email verification (claim treated as credential)
- Asymmetric responses across valid/invalid identity claims (any vector above)
- No rate limiting on login/registration (enables brute-force + mass enumeration)
- Weak/absent password policy (Module 3)
- Client-side-only validation, no server-side re-check
- Logging plaintext passwords in request logs / error traces / analytics
- Registration silently merging/overwriting existing unverified account (subtle takeover path)
- Sensitive feature endpoints not independently re-checking verification status (assuming login-gate is enough)

## Detection Methodology

- **Response diffing**: valid vs invalid identity claims — body, status code, headers, timing, cache-control, lockout behavior
- **Verification boundary test**: does an unverified account have ANY functional capability? Test `/me` or `/current_user` immediately after registration — does it expose a verification flag, or does it return a fully authenticated profile with no distinction?
- **Cross-feature trust test**: once you find an unverified-but-usable session, test 2-3 sensitive endpoints directly (profile edit, messaging, invites, directory) — don't assume the login gate protects everything downstream
- **Rate limit differentiation test**: is limiting identity-aware (leaks existence) or global?

## Secure Design Principles

- Verification gates trust everywhere, not just login
- Symmetric responses across ALL identity-claim outcomes (status, body, timing, rate-limit, headers)
- Generic confirmation messaging: "if this email exists, a link has been sent" — regardless of actual existence
- Server-side re-validation always
- Rate limit by IP **and** by identity claim (single-axis limiting is bypassable)

## Common Misconceptions

- "We fixed enumeration, our error message is generic now" → doesn't cover timing/status code/lockout vectors
- "Verification email = just a security feature" → it's a trust boundary; anything downstream that ignores it makes the feature decorative
- "Registration/login are isolated from the rest of the app" → trust minted here propagates into unrelated features silently (directories, invites, sharing)

## Variations & Edge Cases

- **Social login (OAuth)**: identity provider handles verification implicitly, but apps sometimes still create a local unverified record first — reopens the same gap
- **Invite-only registration**: does the app verify the invitee actually controls the invited email, or just that they clicked a link?
- **Username-based (no email) registration**: uniqueness-checking itself becomes the primary enumeration surface

## Reporting Reference

- **Premature session issuance for unverified accounts**
  - OWASP: A07:2021 – Identification and Authentication Failures
  - CWE-287 (Improper Authentication), CWE-306 (Missing Authentication for Critical Function)
- **User enumeration (any vector)**
  - OWASP: A07:2021
  - CWE-203 (Observable Discrepancy)
- **Unverified claim treated as trusted downstream (directory/invite exposure)**
  - OWASP: A01:2021 – Broken Access Control (if it exposes/affects other users' data or access)
  - CWE-284 (Improper Access Control)

## Report Title Template
`[Mechanism] Allows [Consequence] via [Root Cause]`
e.g., *"Unverified Email Registration Allows Arbitrary Attacker-Controlled Entries in Workspace Directory (Enables Enumeration & Impersonation)"*

## Key Test to Determine Severity Ceiling
After obtaining ANY session (verified or not), hit the current-user/`/me` endpoint first:
- Fully populated profile, no verification state visible → architecture never distinguishes verified/unverified → high/critical
- `verified: false` flag returned → test whether *individual* sensitive endpoints re-check that flag before ruling out severity — don't stop at the first gate