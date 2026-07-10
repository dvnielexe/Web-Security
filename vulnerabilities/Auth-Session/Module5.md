# Module 5: Password Reset & Account Recovery — Cheatsheet

## Core Theme

> **Password reset proves inbox continuity, not identity.** It's a secondary path to the same trust level as login — and every secondary path is, by definition, a place where the primary defenses (password strength, MFA) don't apply unless deliberately re-threaded through it.

## The Unifying Question for This Whole Module

> **"When this control fires, does it actually revoke/re-check everything that was true before it — or does it just add a new fact on top of old, unexamined trust?"**

Catches: MFA not re-invoked on reset (old "password=identity" assumption stays trusted), sessions surviving password change (old session stays trusted, new password just added), verification not gating downstream features (old "account exists" assumption stays trusted).

## Why Email Works for Reset (Despite Being "Just Another Account")

- Email is fundamentally a **password-protected account, same as the one being reset** — using it as proof relocates the "something you know" problem to a different provider rather than escaping it.
- Real value: it's a channel **established and verified at registration, separate in time from the current login attempt.** Reset proves "continuity of access to a previously-verified channel" — NOT identity.
- Consequence: your app's account security has an **implicit dependency on a system you don't control** (the user's email provider's security). The recovery path is frequently the true security floor of an account (same lesson as Module 4's WebAuthn-fallback).

## Standard Reset Flow (Full Pipeline)

```
1. User submits email
2. Server responds UNIFORMLY regardless of existence (Module 2)
3. Server generates high-entropy random token
4. Server stores token (hashed) + user ID + expiration
5. Email sent: https://app.com/reset?token=<token>
6. User clicks, submits new password
7. Server validates: exists, matches user, not expired, not used
8. Valid → password updated, token invalidated (single-use)
9. ALL other active sessions invalidated
10. Notification email sent ("your password was changed")
```

## Token Entropy: Exponential vs. Linear (Critical Distinction)

- **Entropy/keyspace (token length/charset) = exponential lever.** Each added character multiplies keyspace by the charset size.
- **Expiration window + rate limiting = linear levers.** Each unit removed subtracts a fixed, small number of attempts.
- **Exponential dominates linear, almost always.** Example: 6→12 char token (same 26-letter charset) = ~309,000,000x keyspace increase. Cutting expiration 60min→5min = only 12x reduction in attempts. Not remotely comparable.
- **Practical formula:** `keyspace ÷ achievable guesses within valid window (given real rate limiting) = attack feasibility`. Always compute both sides before judging "is this long enough."
- **Standard:** 128+ bits of entropy for reset tokens (32+ random chars, mixed case+digits, or UUID-based) — rate limiting and expiration are complementary, never a substitute for adequate entropy.

## Why TOTP Can Be Short But Reset Tokens Can't

- TOTP must be **human-typed**, under time pressure, into a small field — hard usability ceiling forces shortness. Since it can't rely on entropy, its real security comes almost entirely from linear controls (30s window + strict rate limiting — Module 4).
- Reset tokens are **embedded in a URL, clicked not typed** — zero usability cost to making them enormous. No excuse exists for a short reset token.
- **Testing heuristic:** any short, low-entropy secret you find — ask if there's a genuine human-typing constraint forcing shortness. If it's URL/header/hidden-field only (machine-consumed), shortness is very hard to justify regardless of other mitigations.

## Session Persistence After Password Change

- A session, once minted, is a **completely independent trust artifact** from the password that created it — nothing automatically ties its validity back to current password state.
- If sessions aren't explicitly invalidated on password change: **"change your password to regain control" becomes theater** — attacker's pre-existing session survives untouched; they no longer even need the password.
- Must be deliberately coded — "change password" and "session management" are often built as separate features sharing a user record, with the requirement never threaded between them (same team/sprint gap pattern as Module 4's MFA-reset issue).

## URL-Embedded Tokens: The Referer/Logging Exposure Class

Token in URL (`?token=abc123`) — because it must be clickable from an email (can't easily make an email link fire a POST) — creates exposure via:
- `Referer` header leak to any third-party resource (image/font/analytics) loaded on the reset landing page
- Browser history
- Server/proxy/CDN logs at every hop
- Caching layers

**Mitigation (not "avoid URLs" — often impractical):** landing page immediately extracts token client-side on load, exchanges it via API call, redirects to a clean URL with token stripped — minimizing the window the raw token sits exposed.

## Common Developer Mistakes

- Low-entropy tokens (exponential vs linear confusion)
- Long expiration with no compensating rate limit
- Tokens not invalidated after single use
- **Sessions not invalidated on password change**
- No "password changed" notification email
- Referer/log leak via third-party resources on reset landing page
- Reset re-authenticates without re-invoking MFA (Module 4)
- Predictable tokens (sequential IDs, timestamps, weak PRNG instead of CSPRNG)
- Unvalidated `redirect_url` parameter in the reset flow (open redirect in a maximum-trust context)

## Detection Methodology

- Calculate actual token entropy; check if shortness is justified by a real usability (human-typing) constraint
- Rate limit test on BOTH request endpoint and confirmation endpoint separately
- Replay test: submit the same token twice
- Expired-token test: server-side enforcement, not just client-side form hiding
- **Session survival test** (highest signal-per-effort — see below): login device A, reset password device B, check if device A's session still works
- MFA re-invocation test post-reset
- Third-party resource check on reset landing page (Referer leak surface)
- Notification email check — sent? actionable ("wasn't you?")
- Walk EVERY response branch, not just the "headline" mechanism: valid email+valid token, valid email+invalid token, invalid email+any token, expired token, reused token — each can leak differently (e.g., enumeration hiding in the wrong-token-vs-nonexistent-account response diff)

## Prioritization Under Time Pressure (Practical Exercise Insight)

**Prefer checks that are:**
(a) cheap to execute (few requests)
(b) binary/unambiguous outcome (clear pass/fail)
(c) don't require chaining with another unconfirmed weakness to matter

**Session invalidation test wins on all three** — two requests, clear yes/no, and if it fails, severity is severe regardless of how perfect everything else in the flow is (no dependency chain needed, unlike token entropy which needs rate-limiting-absence to actually be exploitable).

## Context Determines Severity, Not Bug Class Alone

An open redirect (or any "generically low severity" bug — verbose error, minor info leak) is NOT a fixed-severity finding. **Severity is a function of the flow it's embedded in.** Same unvalidated `redirect_url` on a "share article" feature = low severity. Same parameter inside a password-reset flow, at the moment of maximum manufactured user trust ("I just clicked a real email, just reset my password, I trust this app right now") = high-severity credential-harvesting primitive — described precisely as **"phishing with a built-in trust preloader."** Always ask what flow a bug is reachable from before finalizing severity.

## Secure Design Principles

- Treat reset-email possession as inbox continuity proof, not identity — design defenses accordingly
- 128+ bit token entropy — no usability excuse for shortness
- Short expiration as complementary control, not primary
- Rate limit request AND confirmation endpoints independently
- Server-side single-use enforcement
- Invalidate ALL other sessions on password change
- Re-invoke MFA post-reset before granting session
- Send "password changed" notification with "wasn't you?" path
- Allowlist redirect destinations — never accept unvalidated redirect targets in reset flow
- Strip/exchange token from URL immediately on landing page load

## Common Misconceptions

- "Email-based reset is inherently secure, it's industry standard" → only as strong as the email account itself; a practical tradeoff, not a theoretically ideal solution
- "Short tokens are fine if they expire quickly" → entropy is exponential, expiration is linear; entropy dominates absent a real usability constraint
- "Changing password logs the attacker out" → false unless session invalidation is explicit
- "Open redirects are low severity by default" → severity is entirely context/flow-dependent

## Variations & Edge Cases

- **Security questions** (mother's maiden name) — largely deprecated; answers often publicly discoverable
- **SMS-based reset** — inherits Module 4's SIM-swap/SS7 weaknesses, applied to recovery instead of MFA
- **Support/helpdesk recovery** — out-of-band bypass relying on human judgment; often the actual weakest path
- **Magic link login** (no password, ever) — makes email account security the account's ENTIRE, PERMANENT security floor, not just during recovery

## Reporting Reference

- **Low-entropy/predictable reset token**
  - OWASP: A07:2021 – Identification and Authentication Failures
  - CWE-640 (Weak Password Recovery Mechanism), CWE-330 (Insufficiently Random Values)
- **Sessions not invalidated on password change**
  - CWE-613 (Insufficient Session Expiration)
- **Reset bypasses MFA**
  - CWE-287 (Improper Authentication)
- **Account/email enumeration via reset flow response differences**
  - CWE-203 (Observable Discrepancy) — Medium severity typically (recon-enabling, not direct-access-enabling)
- **Open redirect in reset flow**
  - CWE-601 (URL Redirection to Untrusted Site) — severity Medium→High depending on context (auth flow = high end)
- **Token exposure via Referer/logs**
  - CWE-598 (Use of GET Request Method With Sensitive Query Strings)

## Key Test to Remember
Cheapest, highest-signal black-box test for any reset flow: **login on device A → trigger reset from device B → check if device A's session still works.** Binary outcome, no dependency chain, severe if it fails.