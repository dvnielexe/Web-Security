# Module 12: Authentication Vulnerabilities II - Cheatsheet
## Password Reset Flaws, Session Fixation, Hijacking, Predictable IDs, Insecure Cookie Config

## Core Theme
Module 11 attacked the front door. This module attacks the badge already in someone's hand - either by stealing a real one (hijacking) or by pre-establishing a fake one before the victim authenticates (fixation). Two root categories, each with its own methodology.

## The Two Root Categories
1. **Session hijacking (theft)** - attacker steals an existing, valid session ID after the user has logged in
2. **Session fixation (pre-establishment)** - attacker sets or predicts a session ID BEFORE login, then waits for the victim to authenticate using it

## Session Fixation - Full Attack Chain
```
1. Attacker gets a session ID from the target site pre-auth: "abc123"
2. Attacker forces this exact ID onto the victim's browser
3. Victim authenticates using "abc123" without realizing it was attacker-supplied
4. Server binds identity to "abc123" WITHOUT rotating it
5. Attacker, still holding "abc123", is now authenticated as the victim
```

**Three delivery mechanisms (any one enables the attack, given the precondition below):**
1. **URL-based fixation** - app accepts session ID via query/path parameter (e.g., legacy `?PHPSESSID=`); attacker crafts a link with a chosen ID, victim clicks it
2. **Cookie injection via XSS** - `document.cookie = "session=abc123"` from ANY origin sharing the cookie's Domain scope (including a lower-security subdomain - Module 7 callback)
3. **Network-level injection** - same-network attacker (public WiFi) intercepts a plaintext HTTP response (missing `Secure`/no HSTS) and injects their own `Set-Cookie` header before it reaches the victim - requires NO other application vulnerability at all, a standalone network-position attack

**THE single precondition that determines success regardless of delivery method:** does the server rotate/regenerate the session ID upon successful login? If yes, ALL three delivery mechanisms become irrelevant - the fixed ID is discarded the instant auth succeeds. This is a single choke-point control that closes an entire vulnerability class.

**Detection:** capture session ID pre-login, authenticate, compare. Identical value = vulnerable, regardless of which delivery mechanism you can practically demonstrate in your specific engagement.

## Session Hijacking - Six Independent Theft Vectors (Umbrella Term)

| Vector | Root cause | Module |
|---|---|---|
| XSS reading document.cookie | Missing HttpOnly | 7 |
| Network interception (MITM/sniffing) | Missing Secure, no HSTS | 6, 7 |
| Session ID in URL/logs/Referer | ID transmitted outside cookie | 5, 6 |
| Predictable/brute-forceable session ID | Insufficient entropy | 6 |
| Cross-subdomain exposure | Overly broad Domain scope + weak subdomain | 7 |
| Session ID reflected in API response body | Server-side data exposure | 7 |

**Critical: ruling out one vector does NOT rule out the others.** Test each independently.

**Prioritization insight:** cookie-attribute check (HttpOnly/Secure presence on the very first login response) is the cheapest, zero-search-required signal AND tells you which other rows are worth pursuing (e.g., missing HttpOnly = worth actively hunting for XSS specifically to weaponize it). API-reflection check has higher payoff-if-found (immediate complete takeover, zero further conditions) but requires searching multiple endpoints. Strong methodology does cookie-attributes first (unlocks what to check next), then the reflection sweep.

## Session Rotation Must Cover Privilege Change, Not Just Login (Module 8 Callback)

Same missing-behavior shape as fixation, different trigger: if the session ID isn't rotated when a user's privilege level changes mid-session (promotion to admin without re-login), any attacker already holding that user's PRE-promotion session ID silently inherits the new privileges.

**Report naming:** "Session Fixation via Privilege Escalation" / "Missing Session Regeneration on Authorization Level Change."

**Severity framing - be honest about the prerequisite:** this is NOT a standalone zero-click bug - it requires the attacker to already hold a valid pre-promotion session ID via some other means (any of the six hijacking vectors above, shared/kiosk device, insider access). State this compounding prerequisite explicitly in severity justification rather than implying instant universal exploitability.

**Universal principle:** any increase in trust level must invalidate the old session artifact and issue a new one - old trust artifacts must never silently inherit new privileges.

## Impersonation / "Login As User" Features - A Distinct Risk Category

If impersonation is implemented as a FLAG on the support agent's EXISTING session (`impersonating_user_id: X`) rather than a genuinely separate, scoped session:

- **Not just a rotation issue - this is identity-source confusion.** A session is meant to represent one identity at a time; making identity a switchable property creates authorization-confusion bugs, distinct from classic fixation/hijacking.
- **Audit ambiguity (often the most severe consequence in regulated industries):** every logged action during impersonation may attribute the AGENT's actions to the VICTIM user. This is a compliance/forensic-integrity failure, not just a security bug - if the agent does something malicious or makes a costly error, the audit trail says the user did it.
- **Compounded replay risk:** since impersonation isn't a separately-scoped session, ANY of the six hijacking vectors succeeding against the agent's session during an active impersonation window hands the attacker full victim access with zero additional steps - AND the resulting malicious actions get logged as the victim's own actions, giving the attacker unusually effective cover.
- **Residual state leakage:** stale impersonation flags/context bleeding into the agent's normal session after impersonation ends.

**Correct secure design:** impersonation mints a genuinely SEPARATE, distinctly-scoped session/token - short hard expiration, cryptographically tagged with BOTH the agent's real identity and the target's identity as independent claims, logged as its own distinct session type. Ending impersonation fully TERMINATES that session (not a flag-flip) - the agent's original session is never touched and never carries impersonation risk.

**Schema fix for both audit ambiguity AND hijacking detection:** store `actor_user_id` (who really is authenticated - the agent) and `effective_user_id` (whose account/permissions are being used) as SEPARATE fields on every session/activity record. Benefits: audit clarity (always know who acted vs. on whose behalf), AND hijacking detection (a session tied to one actor suddenly appearing from a new device/IP while still acting as a given effective_user becomes automatically traceable/suspicious).

## Common Developer Mistakes
- No session rotation on login (fixation's single point of failure)
- No session rotation on privilege change (same gap, different trigger)
- Missing HttpOnly/Secure/narrow Domain (independently exploitable, Module 7)
- Insufficient session ID entropy or deterministic generation
- Session ID accepted via URL parameter "for compatibility"
- Raw session ID reflected in any API response body
- OAuth/login callback appending the freshly-issued session ID as a URL parameter "for mobile compatibility" - exposes the highest-value, freshest token at the worst possible moment via URL-exposure vectors (Referer/history/logs - Module 5/7), even when the cookie itself is properly HttpOnly/Secure
- Impersonation features implemented as a flag on an existing session instead of a separately-scoped session

## Detection Methodology (Consolidated)
1. Fixation test: session ID pre-login vs. post-login - identical = vulnerable
2. Privilege-change rotation test: session ID before vs. after a privilege change - identical = vulnerable
3. Cookie attribute sweep: HttpOnly/Secure/SameSite/Domain on the first authenticated response
4. API/response body sweep: raw session ID appearing anywhere outside Set-Cookie
5. Entropy/predictability check across multiple collected session IDs
6. Cross-subdomain mapping: enumerate subdomains sharing Domain scope, assess each for independent vulnerabilities (esp. XSS)
7. Check OAuth/SSO callback flows specifically for session ID or auth code appended to redirect URLs
8. For any impersonation/support-access feature: test whether it mints a separate session or flags an existing one; check audit logs for actor vs. effective identity separation

## Secure Design Principles
- Rotate session ID on every trust-boundary crossing: login, logout, AND privilege change
- Full cookie attribute hardening as non-negotiable baseline
- Never accept session ID via URL parameter
- Never reflect raw session ID in API responses
- High-entropy, CSPRNG session ID generation
- Impersonation/support-access requires a distinctly-scoped session with actor_user_id + effective_user_id recorded separately in every log, and full termination (not flag-flip) on end

## Common Misconceptions
- "Session fixation requires XSS" - false; URL-param acceptance and network-level injection are equally valid, unrelated to any XSS bug
- "We rotate on login, so fixation is handled" - must also rotate on privilege change
- "Hijacking is one vulnerability" - umbrella of six independent vectors; ruling out one doesn't rule out others
- "Impersonation features are just a privilege-change rotation issue" - identity-as-switchable-flag creates audit/compliance failures and authorization-source confusion beyond session lifecycle

## Reporting Reference
- Session fixation (any delivery mechanism): CWE-384 (Session Fixation)
- Missing rotation on privilege change: CWE-384 / CWE-613, framed as "Session Fixation via Privilege Escalation"
- Session ID via URL parameter: CWE-598 (Use of GET Request Method With Sensitive Query Strings)
- Impersonation feature lacking separate session scoping: CWE-266 (Incorrect Privilege Assignment), plus a distinct audit-integrity finding (not a standard CWE - frame narratively as compliance/forensic risk)

## Key Test to Remember
Session ID captured before and after ANY trust-boundary-crossing action (login, privilege change) - if identical, the app is vulnerable to fixation-style exploitation regardless of which specific delivery mechanism you can practically demonstrate.