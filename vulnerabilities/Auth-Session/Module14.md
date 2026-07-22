# Module 14: Detection Methodology & Testing Framework - Cheatsheet
## The Capstone: One Repeatable Sequence for Any Target

## Core Theme
Fourteen modules of scattered knowledge compressed into ONE question, applied continuously: "Where is trust created, how is it carried, and where does it actually die?" Most critical bugs aren't inside a control - they're in the SEAMS between controls (login->session, session->token, token->revocation). Test the seams, not just the controls.

## The Four-Phase Architecture

**Phase 1: Identity Establishment** (Modules 1-5)
What it is: how the app proves someone is who they claim to be, and how that proof is protected.
- AuthN/AuthZ separation - is every decision correctly sourced from the right one?
- Registration/login enumeration sweep (error text, timing, status code, lockout differential)
- Password policy (breach-list check vs. composition-only - NIST 800-63B)
- MFA presence, factor category, phishing-resistance (origin-bound vs. portable value)
- Password reset flow (token entropy, single-use, redirect_uri validation)
- Every downgrade action (MFA disable, recovery-contact change) requires proof >= what's removed

**Phase 2: Session Integrity** (Modules 6-8)
What it is: how proven trust is carried forward across stateless HTTP requests.
- Session ID entropy + transport (cookie vs URL)
- Cookie attribute sweep: HttpOnly, Secure, SameSite, Domain scope
- Idle timeout + absolute timeout measurement (both required, different threat models)
- Logout invalidation test (replay old session post-logout)
- Server-initiated revocation capability

**Phase 3: Token Trust** (Modules 9-10, if JWT/OAuth present)
What it is: self-contained, signed trust-carrying, and delegated third-party authorization.
- alg/kid header trust test (never let attacker-controlled header dictate verification logic)
- Payload confidentiality check (encoding != encryption)
- exp/aud/iss validation completeness + clock skew tolerance
- OAuth: redirect_uri strict validation, PKCE strength, confused-deputy check (bare access token used as login?)

**Phase 4: Trust Transitions & Cross-Boundary State** (synthesis of Modules 8, 12, 13)
What it is: what happens when trust MOVES, changes, or is supposed to stop - across mechanisms and over time. Tested LAST because it's inherently comparative - requires phases 1-3 already characterized.
- Privilege change: does session/token rotate on BOTH promotion and revocation?
- Remember Me / refresh token: same rigor as primary login - device-bound? Revocable? Periodic MFA re-check?
- Multi-mechanism consistency: when session + JWT + refresh token coexist, which is the ACTUAL authority, and does every endpoint check the SAME one?
- Stale/dormant session test: repeat Phase 2/3 tests using an OLD, untouched session, not just a fresh one - fresh sessions are consistent by default; gaps hide in stale ones (exactly an attacker's profile)
- Impersonation/support-access: separately-scoped session? actor_user_id vs effective_user_id in logs?

**Applied throughout ALL phases, to every control found - two lenses:**
- Bypass lens: "Is there an alternate path that reaches the same outcome without passing through this control?"
- Abuse lens: "Can this correctly-functioning control be weaponized against someone else?"

## Why Phase 4 Comes Last (Not a Separate Category, But a Dependency)
You can't test "does trust survive a transition" until you've characterized what trust looks like on both sides of that transition. This is also why the most sophisticated findings across the whole curriculum (Module 8's revocation gap, Module 12's impersonation audit ambiguity, Module 13's refresh-token-as-real-boundary) all appeared late - cross-boundary reasoning is the highest-order skill, built on everything beneath it.

## Prioritization Rule: Concentrated Trust = Concentrated Testing Priority
If Phase 1 reveals a missing control (e.g., no MFA at all), this does NOT shrink Phase 4 scope - it CONCENTRATES it. Without MFA, the entire security weight of the account rests on a single mechanism (session/token), so every transition boundary touching THAT mechanism now carries the full weight that would otherwise be distributed across two independent factors. Whatever carries the most concentrated trust in a given system is where transition-boundary gaps matter most.

## Why Ordered, Dependency-Aware Testing Beats a Flat Checklist
1. **Follows dependency, not categories** - tests what depends on what (Identity -> Session -> Token -> Transitions), so you don't validate controls sitting on already-broken trust
2. **Exposes chaining paths** - flat lists find isolated bugs; ordered testing finds the actual chain that matters in practice ("weak reset -> session survives -> refresh token persists = full takeover") - only visible when tested in flow
3. **Identifies the TRUE trust boundary** - apps often have multiple "auth systems" (session vs JWT vs refresh token); a checklist might test all of them but miss which one ACTUALLY governs access and which one fails to revoke
4. **Impact-weighted discovery** - a Phase 1 break tells you immediately that later findings may be secondary or amplifiers rather than root issues; a flat checklist gives equal weight to everything, forcing the triager to do synthesis work the tester should have done
5. **Systematically tests the seams** - most critical bugs live BETWEEN controls (login->session, session->token, token->revocation), not inside any single one; a flat checklist structurally never asks "what happens between these?"

## Phase Assignment vs. Testing Order Are Separate Decisions
A control's phase describes what it fundamentally IS. Testing order is a separate, practical decision about risk and dependency. Example: password reset is fundamentally a Phase 1 (Identity Establishment) mechanism, but the REASON to test it early is a Phase-4-style insight arriving early ("is this an alternate path around the primary login/MFA control?"). Recognizing when phase-identity and testing-priority diverge is itself an advanced methodology skill.

## The Complete Executable Checklist

```
PHASE 1 - IDENTITY ESTABLISHMENT
[ ] Register an account, sweep for enumeration (error/timing/status/lockout diffs)
[ ] Test password policy (breach-list vs composition-only)
[ ] Test MFA presence, factor type, phishing-resistance
[ ] Test password reset (token entropy, single-use, redirect_uri validation)
[ ] Test every downgrade action requires proof >= what's removed

PHASE 2 - SESSION INTEGRITY
[ ] Capture session ID pre/post login - rotation check (fixation test)
[ ] Cookie attribute sweep (HttpOnly/Secure/SameSite/Domain)
[ ] Idle timeout + absolute timeout measurement
[ ] Logout invalidation test (replay old session post-logout)
[ ] Server-initiated revocation capability check

PHASE 3 - TOKEN TRUST (if JWT/OAuth present)
[ ] alg/kid header trust test
[ ] Payload sensitive-data check
[ ] exp/aud/iss validation completeness + clock skew test
[ ] redirect_uri + PKCE test (if OAuth present)

PHASE 4 - TRUST TRANSITIONS (apply LAST, using findings from 1-3)
[ ] Privilege change: rotation on promotion AND revocation?
[ ] Remember Me / refresh token: primary-login-level rigor
[ ] Multi-mechanism consistency: single actual authority, checked uniformly everywhere?
[ ] Stale/dormant session test (not just your fresh session)
[ ] Impersonation/support-access: separate session? actor vs effective identity logged?

THROUGHOUT: apply bypass lens + abuse lens to every control found in every phase.
```

## Master Vocabulary Index (Quick Reference Across All 14 Modules)
- Identity vs AuthN vs AuthZ (M1) | Claim vs credential (M2) | Hashing vs encryption, salt vs algorithm (M3)
- Factor categories, origin-binding vs portable value (M4) | Inbox continuity vs identity, exponential vs linear entropy levers (M5)
- Name tag vs notebook (M6) | HttpOnly/Secure/SameSite/Domain (M7) | Idle vs absolute timeout, revocation gap (M8)
- Self-contained signed token, algorithm pinning, revocation-lifetime tradeoff (M9) | Confused deputy, PKCE, aud/iss validation (M10)
- Bypass-thinking vs abuse-thinking, universal control (rate limiting) (M11) | Fixation vs hijacking, actor vs effective identity (M12)
- kid injection, clock skew, refresh-token-as-real-boundary (M13) | Four-phase trust-flow methodology (M14)

## The One Question That Replaces Fourteen Modules of Recall
**"Where is trust created, how is it carried, and where does it actually die?"**
Trace this question through every target, every control, every feature - and the specific vulnerability names (IDOR, fixation, confused deputy, kid injection) become labels you attach AFTER finding the gap, not a checklist you search FOR.