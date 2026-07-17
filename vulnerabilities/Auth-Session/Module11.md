# Module 11: Authentication Vulnerabilities I - Cheatsheet
## Enumeration, Weak Policies, Default Creds, Brute-Force, Credential Stuffing

## Core Theme
All five attacks in this module test the login endpoint's ability to withstand volume and knowledge-based guessing. Rate limiting is the single universal control that blunts all five simultaneously - but it is a mitigating control, not a fix, and it has real, specific blind spots (distributed attacks, weaponizable side effects) that must be tested independently.

## The Universal Control: Rate Limiting
Every attack here (enumeration, weak-policy exploitation, default creds, brute-force, credential stuffing) requires MANY requests against the login endpoint. Rate limiting constrains the one resource all five depend on: request volume over time. But it raises cost, it doesn't close the underlying weakness - distinguish "reduces exploitability" from "closes the vulnerability" in every report.

## Enumeration (Full Recap + Extension)
Vectors: error text, status code, timing, lockout/rate-limit differential, response size, cache headers (Module 2).
**Extension for this module:** not just login/registration/reset - ANY endpoint accepting username/email as a lookup key (profile pictures, public display names, API existence checks) can leak existence.

## Weak Password Policies: Composition Rules vs. Real Entropy
"8 chars, 1 uppercase, 1 number, 1 symbol" produces a FALSE sense of security. Real-world human pattern: capitalize first letter, append required digit+symbol at the end (`Password1!`, `Summer2024!`) - a pattern baked into every major cracking wordlist/rule-set (e.g., Hashcat rule files). A policy-compliant 10-char password following this pattern can be far easier to crack than a rule-violating random 16-char lowercase passphrase.

**Standard to cite by name: NIST 800-63B** - shifted guidance away from composition rules toward: length as the primary strength signal, checking against known-breached password corpuses (e.g., Have I Been Pwned API), and removing forced periodic rotation (which produces predictable incremental patterns: Password1! -> Password2!).

## Default Credentials: Why They Persist
Root organizational cause: **no enforced ownership** after initial setup. Primary customer-facing logins get constant attention (business depends on them, daily use surfaces issues). Admin panels, staging environments, IoT devices, internal tools are built once and implicitly become "someone else's problem" - nothing about daily operations forces anyone to revisit them.
**Testing implication:** subdomain enumeration/asset discovery specifically targets these "unowned, forgotten" systems precisely because the organizational blind spot is structural and predictable across almost every org.

## Brute-Force: Algorithm Strength vs. Online Attack Reality
Strong hashing (Argon2id, ~200ms/guess) protects against OFFLINE brute-force (attacker limited by their own compute, one machine = fixed guesses/sec). It provides **zero protection against ONLINE brute-force** if the endpoint has no rate limiting - attacker isn't compute-bound, they're request-bound, and nothing stops parallel/concurrent requests or distributed-IP requests from spinning up many simultaneous hash computations on the SERVER's infrastructure.

**Generalizable lesson:** algorithm-level defenses and request-level defenses (rate limiting) protect against two INDEPENDENT attacker positions (offline compute-bound vs. online request-bound) - neither substitutes for the other. Same shape as Module 3's salt-vs-algorithm distinction, one level up the stack.

## Credential Stuffing: Root Cause vs. Responsibility
Higher success rate than blind brute-force because attacker has REAL, pre-validated username/password pairs from unrelated breaches, exploiting human password reuse.

**Precise attribution (important for reports):** root cause is EXTERNAL to the tested application (another company's breach + human reuse behavior) - this application cannot be "at fault" for that data existing. BUT the tested application fully controls whether that external risk translates into successful takeover HERE: rate limiting, CAPTCHA/proof-of-work after suspicious volume, breach-list checking at registration/password-change, device/IP reputation, and MFA (most complete single defense - neutralizes even a perfectly correct stolen pair).

**Report framing:** "Credential stuffing succeeds because of externally-sourced breach data and reuse behavior - outside this app's control. However, the app's own lack of [specific control] determines whether that external risk becomes account takeover here." Correctly separates origin from remediation responsibility.

## Distributed Credential Stuffing Defeats Both Rate Limiting AND Lockout Simultaneously
Scenario: 50 breached pairs, 50 residential proxy IPs, 1 attempt per IP. Per-IP rate limiting never triggers (1 attempt/IP stays under any reasonable threshold). Per-account lockout never triggers (each account only sees 1 attempt). **Both controls operate on a single axis (one IP or one account) - distributed stuffing defeats both axes simultaneously by design, staying invisible at either vantage point.**

**Required control category - behavioral/risk-based authentication:** changes the unit of analysis from "this IP" or "this account" to the AGGREGATE PATTERN across the whole endpoint (many accounts, many rotating IPs, all succeeding on first try = glaringly obvious in aggregate, invisible per-unit). Concrete mechanisms: device fingerprinting, IP reputation (proxy/VPN/datacenter detection), impossible-travel detection, step-up auth triggers. Industry category: bot management / account-takeover-prevention services - architecturally distinct from generic rate limiting, not a stricter version of it.

**Report implication:** confirming rate limiting + lockout are correctly configured is NOT sufficient to conclude stuffing risk is addressed.

## Account Lockout as a Weaponizable DoS Vector (Control Working AS DESIGNED)
If lockout triggers on N failed attempts with no restriction on WHO can trigger them: attacker only needs the VICTIM's email (often guessable/public - company email formats), deliberately fails login N times, locks out a legitimate user who did nothing wrong. **No password guessing needed at all.**

**Why this is a distinct category from every other finding in this module:** every other vulnerability involves an attacker getting PAST a weak/missing control. This one is the control **succeeding at its exact designed function**, and that correct functioning IS the attack surface. Victims: the legitimate user AND the business (real-world impact: executed at scale during a sales event, or targeted at specific known employees/executives as harassment/disruption).

**Fix (not "remove lockout" - reopens brute-force):** progressive delays instead of hard lockout, CAPTCHA after N failures instead of full block, IP/device-based throttling COMBINED WITH (not instead of) account-based throttling.

**General pattern to check for:** any "punish after N failures" control shape can potentially be weaponized against the very user it protects.

## Bypass-Thinking vs. Abuse-Thinking (Why Lockout-DoS Is Easy to Miss)
- Passes obvious tests: control works as intended, looks secure at a glance
- Testers default to "can I get around this?" not "can I weaponize this?"
- Impact is indirect: denies access to OTHERS rather than granting the attacker access - less intuitive to spot
- Threat model mismatch: control evaluated against one attacker model (brute-force) but not against another (DoS via the control itself)
**Practice going forward:** explicitly ask both bypass AND abuse questions for every control encountered.

## Common Developer Mistakes
- No rate limiting on login/registration/reset
- Composition-based password policy instead of length/breach-list-based (NIST 800-63B misalignment)
- Default credentials on non-primary systems (admin panels, staging, IoT) surviving via lack of ownership
- Relying on strong hashing alone as if it stops online brute-force
- No MFA, or MFA not enforced on every password-accepting path (legacy API, remember-device, password reset)
- No breach-list checking at registration/password-change
- Hard lockout with no compensating control, enabling DoS-via-lockout

## Detection Methodology
- Full enumeration sweep across login, registration, AND password reset
- Password policy test: attempt registration with known breached passwords - rejected via breach-list or only composition-checked?
- Default credential sweep on any discovered admin panel/internal tool/IoT interface
- Rate limit test: sequential AND parallel/concurrent AND distributed-IP requests separately
- Credential stuffing simulation: check for MFA/breach-list/behavioral detection as backstops beyond raw rate limiting
- Lockout weaponization test: deliberately fail a known valid account's login N times from a controlled test account - does it lock the victim, with no compensating control?

## Secure Design Principles
- Rate limiting on login, registration, password reset - both per-IP AND per-account (neither alone is sufficient)
- Length/breach-list-based password policy (NIST 800-63B)
- No default credentials anywhere - mandatory first-login rotation + ownership/inventory tracking for internal/staging/IoT
- MFA as the most complete credential-stuffing defense, enforced on every password-accepting path
- Progressive delays/CAPTCHA instead of hard lockout
- Behavioral/risk-based authentication for aggregate pattern detection against distributed stuffing

## Common Misconceptions
- "Strong hashing protects against brute-force" - only offline; online is a volume problem needing rate limiting
- "Complex password requirements = strong passwords" - composition rules often produce predictable patterns; length + breach-checking are the real signals
- "Rate limiting solves credential stuffing" - solves single-source volume only; distributed stuffing needs behavioral detection
- "Credential stuffing is the breached company's fault, not ours" - root cause is external, but translation into takeover is within the tested app's control
- "Account lockout is purely protective" - can be weaponized as a DoS vector if not designed with that tradeoff in mind

## Variations & Edge Cases
- CAPTCHA bypass/farming services - real attackers pay third-party solving services; CAPTCHA is a speed bump against well-resourced attackers, not an absolute barrier
- Slow-drip enumeration - staying just under rate-limit thresholds indefinitely still eventually enumerates a full user base; rate limiting raises cost/time, doesn't make it impossible
- Password spraying - inverse of brute-force: ONE common password against MANY accounts, specifically staying under per-account lockout thresholds while covering a large attack surface

## Reporting Reference
- No rate limiting on auth endpoints: CWE-307 (Improper Restriction of Excessive Authentication Attempts)
- Weak/composition-only password policy: CWE-521 (Weak Password Requirements)
- Default credentials: CWE-1392 (Use of Default Credentials), CWE-798
- Credential stuffing susceptibility (no MFA/breach-list/behavioral defense): CWE-307, OWASP A07:2021
- Account lockout DoS weaponization: CWE-400 (Uncontrolled Resource Consumption) framed as availability impact via a security control's intended behavior

## Key Test to Remember
For every control found: ask both "can I bypass this?" AND "can I weaponize this against someone else?" The second question catches an entire category of findings (lockout-as-DoS) that the first question will never surface, because the control is working exactly as designed.