# Module 8: Session Lifecycle - Cheatsheet

## Core Theme
A session isn't static - it's born, lives through privilege changes, and is supposed to die under specific conditions. The universal test: after a trust-changing action, what other places still hold equivalent trust - and can I keep using them?

## Lifecycle Stages
1. Creation - session ID generated, notebook entry written
2. Active use - validated every request
3. Privilege change - role/permissions change mid-session
4. Idle timeout - no activity for N minutes -> expire
5. Absolute timeout - expires after N hours regardless of activity
6. Explicit logout - user-initiated termination
7. Server-side revocation - admin/security force-terminates a session

## Idle vs Absolute Timeout
Idle timeout = physical proximity threat (walked away). Absolute timeout = temporal drift threat (too much time passed to still trust original auth event). Neither substitutes for the other.

## Logout Client-Side Illusion
If logout only clears the cookie but doesn't erase the server-side notebook entry, logout is theater - the session stays fully live. Same shape as Module 5's "reset doesn't invalidate other sessions."

## Privilege Change Asymmetry
Promotion lag = harmless UX annoyance. Revocation lag = live security exposure (user just flagged untrustworthy retains access during cache-propagation window). Fix: revocation should force full session invalidation, not rely on cache timing.

## Server-Initiated Revocation
Without it, security teams can detect compromise but not contain it - attacker's session keeps working through password resets and MFA enforcement. This forfeits the core architectural advantage server-side sessions have over stateless tokens (the server owns the notebook and can kill any name tag). Most commonly entirely-skipped stage because it's invisible until an actual incident.

## Multi-Layer State Consistency
When session validity is checked in more than one place (DB + cache/CDN), a "logout all devices" action may only update the DB while request-time checks read a stale cache. Passes testing against your own hot session; fails against dormant/stale sessions - exactly an attacker's profile.

## Common Developer Mistakes
- Only idle or only absolute timeout, not both
- Logout clears cookie only, not server-side entry
- Revocation relies on cache propagation
- No server-initiated revocation capability at all
- "Remember me" tokens not covered by same revocation rigor as primary session
- Batch jobs as sole enforcement for security-critical state changes

## Detection Methodology
- Test idle and absolute timeout durations directly
- Log out, replay captured session ID - still honored?
- Downgrade a session's privilege via admin action, test immediate residual access
- Check for ANY admin capability to force-terminate a user's sessions
- Test "remember me" token independence from logout
- Use two sessions: revoke one via "logout all," test if the OTHER session (stale/cache-differentiated) still works

## Secure Design Principles
- Implement both idle and absolute timeout
- Logout invalidates server-side notebook entry
- Revocation forces full session invalidation, not cache-dependent
- Maintain server-initiated revocation for incident response
- Verify security actions against every layer where validity is cached
- Remember-me and other alt-auth paths get equal revocation rigor

## Common Misconceptions
- "Timeouts exist so lifecycle is handled" - idle and absolute solve different problems
- "Logout clearing cookie is enough" - no effect on server-side notebook unless coded
- "Revoke checked on every request = safe" - only if every layer re-checks live state, not cache
- "We tested logout and it worked" - tested a fresh/hot session; failures appear on stale sessions

## Reporting Reference
- No server-side invalidation on logout: CWE-613
- No absolute timeout: CWE-613
- Revocation not immediate (cache-dependent): CWE-613, CWE-284
- No server-initiated revocation: CWE-613 - frame as forfeiting server-side session architecture's core advantage
- Remember-me bypassing logout: CWE-613

## Key Test
"After this action changes trust, what other places still hold equivalent trust - and can I keep using them?" Apply to every trust-changing action for the rest of your testing career.