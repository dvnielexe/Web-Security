# Module 1: Identity, Authentication & Authorization — Cheatsheet

## Core Definitions

| Concept | Question It Answers | Example Mechanism |
|---|---|---|
| **Identity** | Who do you claim to be? | Username, email, user ID |
| **Authentication (AuthN)** | Can you prove that claim? | Password, MFA, biometric, certificate, session token |
| **Authorization (AuthZ)** | What are you allowed to do? | Roles, permissions, ACLs, ownership checks |

**Mental model:** Nightclub bouncer (AuthN checks ID at the door, once) + wristband (session, a stand-in for AuthN) + room access policy (AuthZ, checked at every door).

## The Single Most Important Rule

> **Authentication succeeding tells you nothing about what should happen next.**

A system can have flawless authentication (strong hashing, MFA, hardware tokens) and catastrophic authorization (no ownership checks at all) — simultaneously. The two controls are **independent**. One does not "affect" or "strengthen" the other. Report them as separate vulnerability classes.

## Diagnostic Method (use this on every scenario)

Ask these **in order**, never collapsed into one judgment:

1. **Where does the identity claim in this request come from?**
   (server-side session state vs. client-controlled body/header/param/token)
2. **Is that claim actually verified/proven, or just trusted?**
   → If NOT proven / client can forge it → likely **AuthN failure** (broken trust anchor)
3. **If proven, is the resulting identity then checked against the resource/action being accessed?**
   → If NOT checked → **AuthZ failure** (IDOR / BOLA / broken access control)

**Common reflex to resist:** defaulting to "AuthN" any time the word "identity" or "impersonation" appears. Ask instead: *was authentication itself ever fooled, or was a correctly-authenticated identity simply not checked against the target of the action?*

## Classification Reference Table

| Scenario Pattern | Root Cause | Correct Classification | NOT This |
|---|---|---|---|
| Session cookie valid, but object ID in URL/body isn't checked against owner | Missing ownership check | AuthZ (IDOR / BOLA) | AuthN failure |
| `user_id` taken from client-supplied body instead of session | Missing ownership check on write | AuthZ (IDOR / BOLA) | AuthN / impersonation |
| Role/permission read from client-controlled header (`X-User-Role`) | Trust anchor re-anchored to attacker-controlled data | AuthN failure (broken trust anchor) — looks like AuthZ in code but functions as an AuthN bypass | Simple AuthZ bug |
| JWT payload editable client-side, no signature verification | Proof mechanism itself doesn't verify the claim | AuthN failure | AuthZ |
| Username enumeration via different error messages | Identity-claim validity leaked pre-authentication | Information Disclosure (weakens AuthN resistance to attack) | AuthN failure itself |
| Weak/predictable/reusable password reset token | Reset token IS the AuthN mechanism for that action | AuthN failure | AuthZ |
| `isAdmin` fetched fresh from DB server-side every request, not client-editable | Correct trust anchor | Secure — no vuln | N/A |
| Uniform response time + uniform response shape on login | No side-channel leak | Secure — no vuln | N/A |

## Key Distinctions to Never Blur

- **"Identity" in the scenario text ≠ automatically an AuthN issue.** Check if authentication was actually bypassed, or if a correctly-proven identity was just never checked against the action.
- **A client-controlled trust anchor (header, editable token, unsigned JWT) is worse than a missing check** — it doesn't just skip one authorization decision, it invalidates every decision built on top of it.
- **Reset tokens, MFA codes, and session tokens are all AuthN mechanisms** for their respective actions — weaknesses in them are AuthN failures, not AuthZ.
- **Ownership/ACL checks on already-authenticated requests are AuthZ** — this is where IDOR lives.

## Reporting Reference

- **IDOR / Broken Object Level Authorization**
  - OWASP: **A01:2021 – Broken Access Control**
  - CWE: **CWE-639** – Authorization Bypass Through User-Controlled Key
  - Also relevant: **CWE-284** (Improper Access Control), **CWE-863** (Incorrect Authorization)
- **Broken/bypassable authentication (client-controlled trust anchor, unsigned tokens)**
  - OWASP: **A07:2021 – Identification and Authentication Failures**
  - CWE: **CWE-287** (Improper Authentication), **CWE-347** (Improper Verification of Cryptographic Signature) for unsigned JWTs
- **Username enumeration**
  - OWASP: **A07:2021 – Identification and Authentication Failures**
  - CWE: **CWE-203** (Observable Discrepancy)
- **Weak/predictable/reusable reset tokens**
  - OWASP: **A07:2021 – Identification and Authentication Failures**
  - CWE: **CWE-640** (Weak Password Recovery Mechanism), **CWE-330** (Use of Insufficiently Random Values)

## Report Title Template

`[Vuln Class] in [Endpoint/Feature] — [Impact]`
e.g., *"IDOR in Email Change Endpoint Allows Account Takeover via user_id Parameter Tampering"*

## Self-Check Questions for Future Modules

- Was authentication itself ever fooled, or just skipped-around?
- Where does the value being checked come from — server state or client input?
- Am I naming the vulnerability by its mechanism, or by which word sounds more serious?