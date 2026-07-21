# Module 13: Token & MFA Vulnerabilities - Cheatsheet

## Core Theme
This module consolidates Module 9 (JWT) and Module 4 (MFA) into concrete exploitation and detection methodology, plus Remember Me as the intersection point of both. The recurring pattern: every header field, every "convenience" feature, and every long-lived credential is a place where a control that works correctly elsewhere can be silently routed around.

## JWT: kid Header Injection (New Beyond Module 9)
Same trust-boundary violation as `alg` (Module 9), different downstream vulnerability class. If the server uses the attacker-controlled `kid` header to directly construct a file path (`readFile("/keys/" + kid + ".pem")`) or an unparameterized query, this opens PATH TRAVERSAL or SQL INJECTION - completely outside the JWT spec itself.

**Concrete exploitation example:** `kid = "../../../../dev/null"` -> server reads an empty file -> attacker signs a forged HS256 token using an empty string as the HMAC key -> signatures match, instant forgery, no cracking needed.

**Fix:** `kid` must only be used to look up a value from a strict, pre-defined server-side allowlist - never used to directly build a file path or query string.

**Generalizable lesson:** every JWT header field is attacker-controlled data, exactly like `alg`. Don't just check `alg` handling - check ALL header fields for the same trust violation.

## Clock Skew Tolerance Silently Extends Token Lifetime
Server logic: `now <= exp + skew`. A "15-minute" token with a 10-minute skew tolerance is really valid ~25 minutes (66% longer than intended).

**Why this matters specifically for short-lived tokens:** the whole design philosophy of short expiration (Module 9) assumes the stated duration IS the real exposure window. Generous skew silently invalidates that risk calculation - the security team believes exposure is bounded to X minutes when it's actually X+skew.

**Detection:** capture a token, replay at increasing intervals past stated `exp`, find where rejection actually starts - compare that effective tolerance against the intended lifetime as a percentage.

## MFA Bypass - Concrete Black-Box Tests

1. **Downgrade actions:** attempt to disable MFA, change recovery phone/email, view/regenerate backup codes using ONLY the password - test the WHOLE family of downgrade actions, not just "disable MFA" alone
2. **Real-time phishing relay:** capture TOTP via relay proxy, replay immediately against real site - NOTE: operating actual phishing relay infrastructure crosses into "building attacker tooling," requires explicit program clearance beyond normal scope; often reported as a theoretical/architectural finding (TOTP lacks origin-binding) rather than physically demonstrated
3. **Push fatigue:** confirm the TECHNICAL ABILITY to trigger unlimited rapid push prompts (no rate limit/cooldown/number-matching) - you're proving the app-level control is absent, not that a human will actually fall for it (which you can't ethically force)
4. **TOTP rate limiting:** script rapid sequential code submissions within one 30-second window - binary outcome, self-contained, no chaining needed

## Remember Me Vulnerabilities

**Core violation:** Remember Me silently re-authenticating without MFA re-invocation is structurally IDENTICAL to Module 4's password-reset-bypasses-MFA finding - both are cases where the app has two paths to "authenticated" and only one enforces the second factor. Remember Me is arguably worse: it's a STANDING silent side door requiring zero active attacker effort - just persistence/physical access to a device over time (shared computers, stolen laptops, browser sync/backups).

**Precise framing:** Remember Me itself isn't the vulnerability (it's a legitimate convenience feature) - the vulnerability is that it's treated as EQUIVALENT IN STRENGTH to a freshly-completed MFA login, when its actual security model (a bearer cookie persisting for weeks) is categorically weaker. The account's TRUE security floor becomes "whoever has access to this specific cookie," not "whoever has password + MFA device" (same lesson as Module 4's WebAuthn-fallback discussion).

**Device-binding gap as a SEPARATE, distinct finding:** if the token isn't bound to the originating device at all, this is also a "feature doesn't match its own stated scope" / deceptive design issue - independent of the MFA-bypass finding. A user checking "Remember Me on THIS device" makes different risk decisions (shared library computer vs. personal laptop) based on a security boundary claim that doesn't actually exist in the implementation. Report both findings separately.

**General testing habit from this:** whenever a feature's name/UI copy makes an implicit security claim ("on this device," "only visible to your team," "private by default"), test whether the implementation actually honors THAT SPECIFIC claim - not just whether the feature works generally.

## Refresh Tokens ARE the Real Security Boundary (Critical Insight)

In a short-lived-access-token architecture, if the refresh token has the SAME long lifetime as Remember Me (e.g., 90 days), no device binding, no MFA re-check, and no server-side revocation - **the refresh token becomes the real credential.** The 5-minute access token expiration becomes meaningless theater, since the refresh mechanism will simply mint a new one indefinitely.

**Full layered fix (not just one change):**
1. Device binding (partial fix - ties refresh token to originating device fingerprint)
2. Server-side revocation capability for refresh tokens specifically (the more fundamental fix - ties to Module 8: without this, detecting compromise gives no way to ACT on it before natural expiration)
3. Shorter refresh token lifetime, decoupled from the Remember Me cookie's own lifetime
4. Periodic forced MFA re-check on refresh (e.g., every 7 days even within an active Remember Me period) - bounds the maximum MFA-free window regardless of activity

**Generalizable lesson:** test the refresh mechanism with the SAME rigor as primary login - functionally, it IS the primary login, running silently in the background.

## Bypass vs. Abuse - Applying Module 11's Distinction Precisely

Remember Me MFA-bypass is a **bypass-category finding**, not abuse. Test: is a control functioning correctly and being weaponized against a third party (abuse - like lockout-DoS)? Or is a control simply never being invoked because an alternate path avoids it entirely (bypass - like reset-skips-MFA)? Remember Me never invokes MFA at all via this path - it doesn't turn a working MFA control into a weapon against anyone. Structurally identical to: reset-skips-MFA (Module 4), remember-me-survives-logout (Module 8). Don't hedge toward "both" - commit to the precise category; it sharpens which diagnostic question you ask next time ("is there an alternate path around this?" vs. "can this correctly-working thing be weaponized against someone else?").

## Common Developer Mistakes
- `kid` used to construct file paths/queries directly instead of allowlist lookup
- Generous clock skew undermining intended short-lived-token exposure window
- MFA downgrade actions (not just disable) accepting only the password
- Push MFA with no rate limit/cooldown/number-matching
- No independent rate limiting on TOTP submission
- Remember Me granting full auth without MFA re-invocation
- Remember Me tokens with no device-binding, replayable from anywhere
- Refresh tokens with Remember-Me-equivalent lifetime, no device binding, no revocation, no periodic MFA re-check

## Detection Methodology
1. `kid` injection: path traversal / SQLi payloads in the kid header value
2. Clock skew: replay token at increasing intervals past exp, find actual tolerance
3. MFA downgrade: attempt disable/recovery-change/backup-code-view with password only - test the whole family
4. Push fatigue: confirm unlimited rapid push capability (no rate limit/cooldown/number-matching)
5. TOTP rate limit: rapid sequential submissions within one 30s window
6. Remember Me MFA-bypass: enable Remember Me, clear session, retain Remember Me cookie, return - is MFA re-prompted?
7. Remember Me device-binding: replay the cookie from a genuinely different device/IP - still works?
8. Refresh token rigor: test refresh token lifetime, device-binding, revocation, and periodic MFA re-check with the same depth as primary login testing

## Secure Design Principles
- kid validated only against a strict server-side allowlist
- Minimal, documented clock skew tolerance
- Every downgrade action requires proof equal to what it removes
- Push MFA: number-matching + rate-limit/cooldown
- TOTP submission rate-limited independently from login
- Remember Me: device-bound, independently revocable, shorter-lived than pure convenience requires, periodic forced MFA re-check
- Refresh tokens tested with primary-login-level rigor - they are the real security boundary
- Feature naming/UI must accurately reflect actual technical scope

## Common Misconceptions
- "Short access token expiration = secure system" - only if refresh mechanism has independently meaningful constraints
- "kid is just a lookup hint" - it's attacker-controlled input like any JWT header field
- "Clock skew tolerance is harmless" - silently extends real exposure beyond stated exp
- "Remember Me is just UX, not a security control" - it's a full alternate auth path requiring primary-login-level testing rigor
- "Named 'on this device' means device-scoped" - naming is not implementation; test actual behavior independently

## Reporting Reference
- kid header injection (path traversal/SQLi): CWE-22 (Path Traversal) or CWE-89 (SQL Injection), root-caused as CWE-345 (Insufficient Verification of Data Authenticity)
- Excessive clock skew tolerance: CWE-613 (Insufficient Session Expiration), framed as exposure-window violation
- MFA downgrade with password only: CWE-306 (Missing Authentication for Critical Function)
- Push MFA fatigue (no rate limit/number-matching): CWE-307
- Remember Me bypassing MFA: CWE-287 (Improper Authentication) - frame as bypass, structurally identical to reset-skips-MFA
- Remember Me lacking device-binding (deceptive scope): frame narratively as "implementation doesn't match stated feature scope" - report as its own distinct finding alongside the MFA-bypass issue
- Refresh token as unbounded standing credential: CWE-613, CWE-287 - frame as "refresh token IS the real security boundary and lacks the constraints the architecture depends on"

## Key Test to Remember
For any "skip re-authentication" convenience feature (Remember Me, trusted device, saved session): does it skip re-typing a password, or does it skip MFA entirely? These are very different risk profiles - test explicitly which one is actually happening, and test the underlying refresh/persistence mechanism with the same rigor as the primary login flow.