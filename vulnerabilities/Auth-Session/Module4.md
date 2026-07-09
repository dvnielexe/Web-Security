# Module 4: Multi-Factor Authentication — Cheatsheet

## Core Theme

> **MFA's value = compromising two independent proofs simultaneously is harder than compromising one. But "different category" alone isn't sufficient — what matters is whether the second factor's proof is bound to something an attacker can't relay (origin/session), and whether an alternate path exists that reaches the same outcome without ever passing through the control.**

## The Reusable Diagnostic Question (Reflection Q1, corrected)

Not "does this have any weakness" (too broad, true of everything). The actual sharp question:

> **"Is this proof something only the legitimate party can produce at the moment of use — or is it a value that, once observed, can be copied and replayed by anyone who captured it?"**

- TOTP/SMS codes = **values** — copyable, relayable by a human or proxy in real time
- WebAuthn/FIDO2 = a **live cryptographic operation bound to origin** — not a value that can be captured and reused elsewhere; the browser enforces the origin check at the protocol level

## The Recurring Pattern (Reflection Q2, corrected)

Not "weakest link" (implies one component is weak in isolation — usually untrue; TOTP's crypto is fine, WebAuthn's fallback crypto is fine). The actual pattern seen repeatedly this module:

> **"For every strong control, ask: is there an alternate path that reaches the same outcome without passing through it?"**

Examples of this exact shape recurring: password reset bypassing MFA entirely (separate door); WebAuthn fallback to email-OTP becoming a permanent parallel path; MFA-disable requiring only the password (one keyholder overriding both).

## Why "Different Category" ≠ Phishing-Resistant

Real-time phishing proxy captures password AND TOTP code the instant they're typed, relays both to the real site before the code expires. Server sees a normal, valid login. TOTP defeats *slow/offline* replay (code expires) but does NOT defeat *real-time relay* — the code isn't bound to session or origin.

**Phishing-resistant = cryptographically bound to origin (WebAuthn/FIDO2).** Registered for `real-bank.com`, will not produce a valid signature for `real-bnak.com` even if the user is fully visually fooled — enforced by protocol, not user judgment.

## MFA Mechanism Comparison

| Mechanism | Category | Phishing-resistant? | Primary weakness |
|---|---|---|---|
| SMS OTP | Something you have (weak) | No | SIM swap, SS7 interception, real-time relay |
| TOTP | Something you have | No | Real-time relay, seed/secret theft |
| Push notification | Something you have | No | MFA fatigue / prompt bombing (human-factors attack, not crypto) |
| Hardware key (WebAuthn/FIDO2) | Something you have | **Yes** | Physical theft (still needs local presence/PIN) |
| Biometric | Something you are | Yes (when paired with WebAuthn) | Usually a local unlock for a stored key, not a remote comparison |

## MFA Fatigue / Prompt Bombing

A **human-factors attack, not a cryptographic one.** Attacker with password triggers repeated push prompts until a tired/annoyed user taps "approve." No algorithm fix — fix is **interaction design**: require number-matching (user types a number shown on login screen into the phone prompt) instead of a bare approve/deny tap.

## TOTP Shared Secret: The Asymmetry With Passwords

- A stolen **password** is self-healing — user rotates it, old one stops working immediately.
- A stolen **TOTP shared secret** produces a second, fully valid, server-indistinguishable authenticator — no natural "rotate" action exists, exposure is typically silent (info disclosure bug, not a phishing page the user notices), so compromise is **durable and often permanent** until someone thinks to force re-enrollment.
- **Conclusion: MFA secret compromise can be as severe as password compromise** — cuts against the default assumption that 2nd-factor secrets are inherently "safer" to leak.

**Secure handling of the raw secret (setup/QR code display):**
- Single-use/short-lived display — inaccessible after initial viewing or after a short window (same principle as Module 2's "don't leave a high-value artifact retrievable after its single legitimate use")
- Require fresh re-authentication immediately before displaying; never a bookmarkable/cacheable static URL
- **Never re-displayed after setup, by anyone** — including support/admin. Lost authenticator → full re-enrollment (new secret, old invalidated), never "here's your original secret again"

## The Keyholder Principle (Downgrade/Trust-Transfer Actions)

> **Any action that reduces account security posture must require proof equal to or greater than what it removes.**

Applies to: disabling MFA, changing recovery phone/email, viewing/regenerating backup codes, re-enrolling a new authenticator, WebAuthn→fallback-factor downgrades.

**Universal test:** find every endpoint that modifies or removes a security control → check if it requires proof equal to what it's removing. "Disable 2FA requires only the password" = one keyholder overriding both — the second factor was only ever enforced on the happy path, never on the attacker path.

## 6-Digit TOTP Code Length: Not the Real Control

- 1,000,000 possible codes, 30-second window — sounds protective in isolation.
- **Without rate limiting**, an attacker at ~10-50 req/sec can exhaust the entire keyspace within a single 30-second window — the time-bound property is irrelevant to this attack, it just resets the clock for the next attempt.
- **Rate limiting (3-5 attempts before lockout/backoff) is the actual control carrying the security weight**, not code length. Code length is only "safe" *conditional on* rate limiting existing.
- **General methodology takeaway:** whenever a control's stated security margin depends on a hidden assumption ("attacker can only try a few times"), test that assumption directly — don't trust the nominal math.

## Common Developer Mistakes

- MFA treated as replacing the need for a strong password policy
- SMS as the *only* MFA option (no phishing resistance, SIM-swap risk)
- Push notifications with no number-matching/context (MFA fatigue exposure)
- MFA disable/downgrade requiring only the password
- Backup/recovery codes not rate-limited or not invalidated as a full set once one is used
- "Remember this device" tokens that never expire or can be forged via cookie/header manipulation
- Re-displaying the raw TOTP secret on request instead of forcing full re-enrollment
- **Password reset flow that re-authenticates the user without re-invoking MFA** (very common real-world finding — password reset often built by a different team/sprint, MFA requirement never re-threaded through it)

## Detection Methodology

- Can MFA be disabled/downgraded using only the primary factor?
- Does password reset / any recovery flow bypass MFA entirely and grant a session directly?
- Are backup codes rate-limited, single-use, invalidated as a set after use?
- Is "remember this device" securely generated, expiring, non-forgeable?
- Is TOTP time-drift tolerance excessively generous?
- **Is there rate limiting specifically on the MFA code submission step**, separate from password rate limiting?
- For any fallback/recovery factor: is it permanent, or does the app force/prompt return to the stronger original factor?
- For any fallback: is there friction asymmetry — easy to invoke fallback, no friction to restore strong factor?

## Real-World Attack Chain Pattern (Password Reset Bypassing MFA)

Attacker compromises email → triggers password reset → sets new password via emailed link → app logs in directly, MFA never invoked → full account takeover despite MFA being "enabled" and correctly implemented elsewhere.

**Reframe for reports:** *"MFA isn't protecting the account — the email inbox is."* Lead reports with the sentence that names the real security boundary, not just the step list.

## Secure Design Principles

- Second-factor strength = origin/session-bound (WebAuthn) vs. portable/relayable secret (TOTP/SMS)
- Downgrade actions require proof ≥ what they remove (keyholder principle)
- Password reset must re-invoke MFA before granting a session
- Rate limit the 2FA submission endpoint independently
- Raw MFA secrets: write-once, never re-displayed; exposure = forced full re-enrollment
- Offer phishing-resistant options (WebAuthn/FIDO2) where possible
- Push MFA requires number-matching, not bare approve/deny

## Common Misconceptions

- "MFA makes an account unhackable" → defeats credential stuffing/simple theft; does NOT defeat real-time phishing relay, session/token theft, or any flow that bypasses MFA invocation
- "Different factor category = phishing-resistant" → false; only origin/session-bound proofs are
- "6-digit codes are strong because 1M possibilities" → only true conditional on rate limiting
- "MFA secret compromise is less severe than password compromise" → often the reverse — static, silently exposed, rarely rotated

## Variations & Edge Cases

- "Remember this device" = long-lived MFA bypass — test expiration, revocability, forgeability
- Backup/recovery codes = a designed legitimate bypass path — must be equally rigorously protected (rate-limited, single-use, fully invalidated as a set)
- Account recovery via support/helpdesk = common out-of-band bypass skipping the entire technical MFA implementation via social engineering the support team — often the actual weakest path in an otherwise strong system
- **Fallback factors (e.g., WebAuthn → email OTP) are not inherently flawed** — the flaw is if the fallback becomes a silent, permanent, equal-standing alternative rather than a temporary bridge back to the original guarantee. Any fallback path effectively defines the account's TRUE minimum security floor — report the honest floor, not the advertised strongest factor.

## Reporting Reference

- **MFA disable/downgrade requires only primary factor**
  - OWASP: A07:2021 – Identification and Authentication Failures
  - CWE-306 (Missing Authentication for Critical Function)
- **Password reset bypasses MFA**
  - OWASP: A07:2021
  - CWE-287 (Improper Authentication)
- **No rate limiting on MFA code submission**
  - CWE-307 (Improper Restriction of Excessive Authentication Attempts)
- **TOTP/MFA secret exposure via insecure setup display**
  - CWE-522 (Insufficiently Protected Credentials)
- **Permanent insecure fallback undermining stronger factor**
  - CWE-287 / CWE-305 (Authentication Bypass by Alternate Path or Channel) — this CWE name literally matches the recurring pattern of this module

## Key Universal Test
For every strong control found in an app: **is there an alternate path that reaches the same outcome without passing through it?** (password reset vs. MFA; fallback factor vs. primary factor; disable-endpoint vs. enable-endpoint). This single question predicts most real-world MFA bypass findings.