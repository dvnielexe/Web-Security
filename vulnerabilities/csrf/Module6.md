# CSRF Module 06 — CSRF Defenses Layer by Layer
> **Curriculum:** CSRF Mastery for Ethical Hacking & Bug Bounty  
> **Module:** 06 of 12  
> **Topic:** Synchronizer Tokens, Double-Submit Cookies, SameSite, Origin/Referer Validation, Custom Headers, Defense-in-Depth  
> **Level:** Intermediate-Advanced — analyzes every major CSRF defense as a trust assertion with its failure modes

---

## Table of Contents
- [CSRF Module 06 — CSRF Defenses Layer by Layer](#csrf-module-06--csrf-defenses-layer-by-layer)
  - [Table of Contents](#table-of-contents)
  - [1. The Defense Landscape — Three Levels](#1-the-defense-landscape--three-levels)
  - [2. Defense 1 — Synchronizer Token Pattern](#2-defense-1--synchronizer-token-pattern)
    - [Mechanism](#mechanism)
    - [Why It Works](#why-it-works)
  - [3. CSRF Token Required Properties](#3-csrf-token-required-properties)
  - [4. Per-Session vs Per-Request Token Models](#4-per-session-vs-per-request-token-models)
  - [5. Common CSRF Token Implementation Mistakes](#5-common-csrf-token-implementation-mistakes)
  - [6. Defense 2 — Double-Submit Cookie Pattern](#6-defense-2--double-submit-cookie-pattern)
    - [Mechanism](#mechanism-1)
    - [Why It Works (Theory)](#why-it-works-theory)
    - [Critical Weakness](#critical-weakness)
  - [7. Double-Submit Weakness — Subdomain Cookie Injection](#7-double-submit-weakness--subdomain-cookie-injection)
    - [Why Signed Double-Submit Prevents This](#why-signed-double-submit-prevents-this)
  - [8. Signed Double-Submit Cookie](#8-signed-double-submit-cookie)
  - [9. Defense 3 — Origin Header Validation](#9-defense-3--origin-header-validation)
    - [How It Works](#how-it-works)
    - [When Origin Is Present](#when-origin-is-present)
    - [The Absent Origin Problem](#the-absent-origin-problem)
    - [Origin Validation Failure Modes](#origin-validation-failure-modes)
  - [10. Defense 4 — Referer Header Validation](#10-defense-4--referer-header-validation)
    - [Implementation](#implementation)
    - [Scenarios Where Referer Is Absent or Wrong](#scenarios-where-referer-is-absent-or-wrong)
    - [The Referer Validation Dilemma](#the-referer-validation-dilemma)
  - [11. Origin vs Referer Comparison](#11-origin-vs-referer-comparison)
  - [12. Defense 5 — SameSite Cookie Attribute](#12-defense-5--samesite-cookie-attribute)
    - [SameSite as a Defense Layer](#samesite-as-a-defense-layer)
    - [SameSite Failure Modes (Defense Layer Analysis)](#samesite-failure-modes-defense-layer-analysis)
  - [13. Defense 6 — Custom Request Header](#13-defense-6--custom-request-header)
    - [Mechanism](#mechanism-2)
    - [Why It Works](#why-it-works-1)
    - [Limitations](#limitations)
  - [14. XSS Interaction — When All Defenses Collapse](#14-xss-interaction--when-all-defenses-collapse)
    - [How XSS Defeats Each Defense](#how-xss-defeats-each-defense)
    - [The Common Failure Mode](#the-common-failure-mode)
    - [Implication for Defense Design](#implication-for-defense-design)
  - [15. Defense Independence — The Common Failure Mode](#15-defense-independence--the-common-failure-mode)
  - [16. The Correct Defense-in-Depth Layering Model](#16-the-correct-defense-in-depth-layering-model)
  - [17. Re-Authentication as a Design-Level Defense](#17-re-authentication-as-a-design-level-defense)
  - [18. Key Terminology Reference](#18-key-terminology-reference)
  - [19. Common Misconceptions](#19-common-misconceptions)
    - [❌ "Three CSRF defense layers are always independent"](#-three-csrf-defense-layers-are-always-independent)
    - [❌ "Double-submit cookie is as strong as synchronizer token"](#-double-submit-cookie-is-as-strong-as-synchronizer-token)
    - [❌ "Validating Referer is sufficient for CSRF protection"](#-validating-referer-is-sufficient-for-csrf-protection)
    - [❌ "If CSRF token is present in the form, the application is protected"](#-if-csrf-token-is-present-in-the-form-the-application-is-protected)
    - [❌ "SameSite=Strict provides complete CSRF protection without tokens"](#-samesitestrict-provides-complete-csrf-protection-without-tokens)
    - [❌ "Origin: null is always safe to reject"](#-origin-null-is-always-safe-to-reject)
    - [❌ "The CSRF token can be stored in a cookie"](#-the-csrf-token-can-be-stored-in-a-cookie)
  - [20. Bug Bounty Reference](#20-bug-bounty-reference)
    - [Defense Evaluation Checklist](#defense-evaluation-checklist)
    - [Reporting CSRF Defense Weaknesses](#reporting-csrf-defense-weaknesses)
  - [21. Module 6 Summary — What You Must Know Cold](#21-module-6-summary--what-you-must-know-cold)

---

## 1. The Defense Landscape — Three Levels

CSRF defenses operate at three distinct levels. Each level has different failure modes. Genuine defense-in-depth layers across levels, not within one level.

```
┌──────────────────────────────────────────────────────────────────┐
│                      DEFENSE LEVELS                              │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  BROWSER LEVEL                                                   │
│  └── SameSite cookie attribute                                   │
│      Enforced by browser, attacker cannot override               │
│      Application configures; browser enforces                    │
│      Failure mode: misconfiguration, subdomain attack, GET gap   │
│                                                                  │
│  TRANSPORT LEVEL                                                 │
│  ├── Origin header validation                                    │
│  └── Referer header validation                                   │
│      Server checks where request came from                       │
│      Reliable when present; unreliable when absent               │
│      Failure mode: header absent, same-origin XSS                │
│                                                                  │
│  APPLICATION LEVEL                                               │
│  ├── CSRF token (synchronizer token pattern)                     │
│  ├── Double-submit cookie pattern                                │
│  └── Custom request header requirement                           │
│      Server generates and validates unforgeable secret           │
│      Primary defense — does not rely solely on browser behavior  │
│      Failure mode: weak token, XSS extraction, implementation    │
│                                                                  │
│  DESIGN LEVEL                                                    │
│  └── Re-authentication for critical actions                      │
│      Requires victim's credential — cannot be forged             │
│      Failure mode: none (CSRF cannot supply victim's password)   │
│      Cost: UX friction                                           │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

---

## 2. Defense 1 — Synchronizer Token Pattern

The primary CSRF defense. Every other defense is supplementary.

### Mechanism

```
ON PAGE RENDER (server side):
  1. Generate cryptographically random token
     token = secrets.token_urlsafe(32)   # Python
     token = crypto.randomBytes(32).toString('hex')  # Node.js

  2. Store in server-side session tied to user
     session["csrf_token"] = token

  3. Embed in every state-changing form
     <input type="hidden" name="csrf_token" value="{{ token }}">

  4. OR for AJAX: inject into meta tag, read via JS
     <meta name="csrf-token" content="{{ token }}">

     // Client JS reads and sends in header
     const token = document.querySelector('meta[name="csrf-token"]').content;
     fetch('/api/action', {
       headers: { 'X-CSRF-Token': token },
       credentials: 'include'
     });

ON REQUEST VALIDATION (server side):
  1. Extract from request body or header
     received = request.POST.get("csrf_token")
     OR
     received = request.headers.get("X-CSRF-Token")

  2. Extract expected from session
     expected = session.get("csrf_token")

  3. Constant-time comparison
     if not hmac.compare_digest(received or "", expected or ""):
         return HttpResponse(403)

  4. Optionally: rotate token (per-request model)
```

### Why It Works

```
CSRF attack requires:
  A forged request carrying a valid CSRF token

Attacker cannot obtain the token because:
  ✗ Token embedded in server-generated HTML
  ✗ SOP prevents cross-origin page reads
  ✗ Token is random — cannot be guessed
  ✗ Token is session-bound — cannot be reused from another session

Server sees:
  Session cookie → proves WHO (identity)
  CSRF token     → proves WHERE (request came from server's own page)
  Together they answer: authenticated AND intentional
```

---

## 3. CSRF Token Required Properties

```
┌─────────────────────────────────────────────────────────────────┐
│              CSRF TOKEN — REQUIRED PROPERTIES                   │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  PROPERTY 1 — Cryptographic Randomness                          │
│  Use:   secrets.token_urlsafe(), crypto.randomBytes(),          │
│         SecureRandom, os.urandom()                              │
│  Never: Math.random(), time-based, sequential counters          │
│  Why:   Predictable tokens are guessable                        │
│                                                                 │
│  PROPERTY 2 — Sufficient Entropy                                │
│  Minimum: 128 bits (16 bytes)                                   │
│  Recommended: 256 bits (32 bytes)                               │
│  Why:   Prevents brute-force within session lifetime            │
│                                                                 │
│  PROPERTY 3 — Session Binding                                   │
│  Stored in server-side session, keyed to user's session         │
│  Validated against the session cookie in the same request       │
│  Why:   Prevents cross-user token reuse                         │
│  Mistake: token stored globally, not per-session                │
│                                                                 │
│  PROPERTY 4 — Server-Side Validation                            │
│  Comparison on server, not client                               │
│  Why:   Client-side checks are bypassable entirely              │
│                                                                 │
│  PROPERTY 5 — Constant-Time Comparison                          │
│  Use:   hmac.compare_digest() or equivalent                     │
│  Never: == or === (timing side-channel)                         │
│  Why:   Character-by-char comparison leaks token info           │
│                                                                 │
│  PROPERTY 6 — Correct Transmission Channel                      │
│  MUST be in:     request body OR custom request header          │
│  MUST NOT be in: cookie (auto-sent → no CSRF protection)        │
│  MUST NOT be in: URL parameter (Referer leakage, logs)          │
│  Why:   Cookie transmission defeats entire purpose               │
│                                                                 │
│  PROPERTY 7 — Expiration                                        │
│  Tied to session lifetime minimum                               │
│  Per-request tokens expire on use                               │
│  Why:   Limits replay window                                    │
│                                                                 │
│  PROPERTY 8 — Invalidation on Logout                            │
│  Session destroyed → token invalidated                          │
│  Why:   Post-logout token replay prevented                      │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## 4. Per-Session vs Per-Request Token Models

```
PER-SESSION TOKEN MODEL:
┌────────────────────────────────────────────────────────────┐
│ One token generated at login                               │
│ Same token used for all forms in the session               │
│ Invalidated on logout                                      │
│                                                            │
│ Implementation:                                            │
│   session["csrf"] = generate_token()  # on login          │
│   # Reuse for every form render                            │
│   # Validate: request.body["csrf"] == session["csrf"]      │
│                                                            │
│ Pros: Simple; back button works; no race conditions        │
│ Cons: Token leaked once = valid for entire session         │
│ Use:  Most traditional web applications                    │
└────────────────────────────────────────────────────────────┘

PER-REQUEST TOKEN MODEL:
┌────────────────────────────────────────────────────────────┐
│ New token generated each time a form is rendered           │
│ Previous token invalidated when new one is issued          │
│                                                            │
│ Implementation:                                            │
│   # On every form render:                                  │
│   token = generate_token()                                 │
│   session["csrf"] = token                                  │
│   render_form(csrf_token=token)                            │
│                                                            │
│   # On validation:                                         │
│   validate and immediately rotate                          │
│                                                            │
│ Pros: Leaked token has very short validity                 │
│ Cons: Back button breaks; race conditions in parallel tabs │
│ Use:  High-security single-action flows                    │
└────────────────────────────────────────────────────────────┘
```

---

## 5. Common CSRF Token Implementation Mistakes

```
MISTAKE 1 — Token not tied to session
  Server generates token, returns to client
  Does NOT store in session
  Validates only that token is present in request
  
  Attack: Attacker generates any value, submits it → accepted
  Fix: Store token in server-side session; validate against session

MISTAKE 2 — Token stored in cookie
  Set-Cookie: csrf_token=xK9mP2...   ← auto-sent by browser
  Form: <input name="csrf" value="xK9mP2...">
  Server: validates cookie == body
  
  Attack: Both values sent automatically by browser
          This is Double-Submit pattern (not Synchronizer)
          → Vulnerable to subdomain cookie injection
  Fix: Store token server-side in session, not in cookie

MISTAKE 3 — Token in URL parameter
  GET /form?csrf_token=xK9mP2...
  
  Attack surface:
    Token in browser history
    Token in Referer header sent to third parties
    Token in server access logs
    Token cached by browser/proxy
  Fix: Token in body or custom header only

MISTAKE 4 — Non-constant-time comparison
  if request.body["csrf"] == session["csrf"]:  ← timing attack
  
  Fix: if hmac.compare_digest(received, expected):

MISTAKE 5 — Same token across all users
  GLOBAL_TOKEN = generate_once()  # application startup
  All users share same token
  
  Attack: Attacker reads their own token, uses it against victim
  Fix: Per-session token generation

MISTAKE 6 — Token not validated on all methods
  Token validated on POST but not PUT/PATCH/DELETE
  
  Attack: Use PUT/DELETE to bypass validation
  Fix: Validate on ALL state-changing methods

MISTAKE 7 — Token not invalidated on logout
  User logs out → session destroyed → token still accepted
  
  Attack: Observe token, logout, use token post-logout
  Fix: Invalidate all tokens on logout/session destruction

MISTAKE 8 — Empty/null token accepted
  if request.body.get("csrf") == session.get("csrf"):
  # Both return None → None == None → True
  
  Fix: Explicitly reject empty/null/missing tokens
```

---

## 6. Defense 2 — Double-Submit Cookie Pattern

Alternative to synchronizer tokens for stateless applications (no server-side session store).

### Mechanism

```
ON LOGIN / SESSION START:
  1. Generate random value
     csrf_value = secrets.token_urlsafe(32)

  2. Set in cookie (accessible to JS — NOT HttpOnly)
     Set-Cookie: csrf=xK9mP2...; SameSite=Strict; Secure

  3. Embed same value in forms
     <input type="hidden" name="csrf_token" value="xK9mP2...">

  4. OR JS reads cookie and sends in header
     const csrfToken = getCookie('csrf');
     fetch('/api/action', {
       headers: { 'X-CSRF-Token': csrfToken },
       credentials: 'include'
     });

ON VALIDATION:
  cookie_value = request.cookies.get("csrf")
  body_value   = request.POST.get("csrf_token")
  
  if not hmac.compare_digest(cookie_value, body_value):
      return 403
```

### Why It Works (Theory)

```
Attacker's forged form:
  Cookie:     browser auto-sends csrf=xK9mP2... (attacker cannot READ this)
  Body value: attacker must supply matching value
  
  Attacker cannot read the cookie (SOP + browser enforcement)
  Cannot supply matching body value
  → Request rejected
```

### Critical Weakness

Double-submit relies on the attacker not knowing the cookie value. If the attacker can control the cookie value, both sides of the comparison are attacker-controlled.

---

## 7. Double-Submit Weakness — Subdomain Cookie Injection

```
ATTACK CHAIN:

Step 1: Attacker gains control of old.victim.com
        (subdomain takeover, XSS on subdomain, compromised subdomain)

Step 2: Attacker serves page from old.victim.com that sets cookie:
        Set-Cookie: csrf=ATTACKER_CHOSEN_VALUE; Domain=victim.com; Path=/
        
        Note: Subdomains CAN set cookies for parent domain
        This cookie now applies to app.victim.com

Step 3: Victim visits old.victim.com
        Browser receives and stores:
        csrf=ATTACKER_CHOSEN_VALUE for domain victim.com

Step 4: Attacker triggers forged request to app.victim.com
        Forged body: csrf_token=ATTACKER_CHOSEN_VALUE
        Cookie sent: csrf=ATTACKER_CHOSEN_VALUE (from injection)

Step 5: Server validates:
        cookie value:  ATTACKER_CHOSEN_VALUE
        body value:    ATTACKER_CHOSEN_VALUE
        ✓ Match → request ACCEPTED

Step 6: CSRF succeeds — double-submit completely bypassed

ROOT CAUSE:
  The CSRF cookie and the body token are both client-controlled
  The server is comparing two values the attacker can set
  The defense assumes attacker cannot control the cookie — subdomain breaks this
```

### Why Signed Double-Submit Prevents This

Even with subdomain cookie injection, the attacker cannot forge a valid HMAC signature without the server's secret key.

---

## 8. Signed Double-Submit Cookie

Adds HMAC signature to cookie value, making injected cookies invalid.

```python
import hmac
import hashlib
import secrets

SECRET_KEY = b"server_secret_key_never_expose"

# GENERATING THE TOKEN (server side)
def generate_csrf_cookie():
    value = secrets.token_urlsafe(32)
    signature = hmac.new(
        SECRET_KEY,
        value.encode(),
        hashlib.sha256
    ).hexdigest()
    return f"{value}.{signature}"

# Cookie: csrf=<value>.<hmac_signature>; SameSite=Strict; Secure
# Form:   <input name="csrf_token" value="<value>"> (unsigned value only)

# VALIDATING (server side)
def validate_signed_double_submit(request):
    cookie = request.cookies.get("csrf", "")
    body_value = request.POST.get("csrf_token", "")
    
    if "." not in cookie:
        return False
    
    value, signature = cookie.rsplit(".", 1)
    
    # Validate signature (proves cookie wasn't injected/tampered)
    expected_sig = hmac.new(
        SECRET_KEY,
        value.encode(),
        hashlib.sha256
    ).hexdigest()
    
    if not hmac.compare_digest(signature, expected_sig):
        return False  # Cookie signature invalid — injection attempt
    
    # Validate body matches cookie value
    if not hmac.compare_digest(value, body_value):
        return False
    
    return True
```

```
WHY THIS DEFEATS SUBDOMAIN INJECTION:
  Attacker injects: csrf=EVIL_VALUE.FAKE_SIGNATURE
  Server validates signature: hmac(SECRET_KEY, EVIL_VALUE) ≠ FAKE_SIGNATURE
  → REJECTED even though attacker controlled the cookie
  
  Attacker cannot forge valid HMAC without SECRET_KEY
  SECRET_KEY never leaves server
```

---

## 9. Defense 3 — Origin Header Validation

Modern browsers automatically include `Origin` header on cross-origin requests.

### How It Works

```python
ALLOWED_ORIGINS = {
    "https://app.victim.com",
    "https://www.victim.com"
}

def validate_origin(request):
    origin = request.headers.get("Origin")
    
    if origin is None:
        # Origin absent — allow (don't break same-origin and non-browser requests)
        # Rely on other defenses
        return True
    
    if origin not in ALLOWED_ORIGINS:
        return False  # Cross-origin request from unlisted origin
    
    return True
```

### When Origin Is Present

```
Origin IS sent (browser adds automatically):
  ✓ Cross-origin POST requests
  ✓ Cross-origin requests via fetch() with CORS
  ✓ Cross-origin form submissions
  ✓ Most modern cross-origin browser requests

Origin IS NOT sent:
  ✗ Same-origin requests (usually absent)
  ✗ GET navigation requests in some browsers
  ✗ Non-browser clients (curl, mobile SDKs)
  ✗ Some browser extensions
  ✗ Direct navigation (bookmark, address bar)
  ✗ Requests from within PDF viewers
```

### The Absent Origin Problem

```
TWO IMPERFECT OPTIONS:

Option A — Reject absent Origin:
  ✓ Stops attacker who can suppress Origin
  ✗ Breaks same-origin requests, mobile apps, non-browser clients
  → Too strict for most real applications

Option B — Allow absent Origin:
  ✓ Legitimate clients unaffected
  ✗ Attacker in environments where Origin is absent can bypass
  → Acceptable IF other defenses are in place

RECOMMENDED:
  Reject if Origin present AND not in allowlist
  Allow if Origin absent (rely on CSRF token as primary defense)
  Never blindly reflect Origin in CORS headers
```

### Origin Validation Failure Modes

```
1. Same-origin XSS:
   Request from victim.com XSS → Origin: https://victim.com → passes

2. Older browser:
   Does not send Origin → absent → server allows

3. Wildcard allowlist:
   if "victim.com" in origin:  ← allows evil-victim.com, victim.com.evil.com
   Fix: exact match only, not substring

4. Null origin:
   Sandboxed iframes send Origin: null
   Some servers allowlist null → attacker uses sandboxed iframe PoC:
     <iframe sandbox="allow-scripts allow-forms"
             srcdoc='<form action="target" method="POST">
                     <script>document.forms[0].submit()</script>
                     </form>'>
     </iframe>
```

---

## 10. Defense 4 — Referer Header Validation

Contains the full URL of the referring page. Weaker than Origin but widely supported.

### Implementation

```python
from urllib.parse import urlparse

ALLOWED_HOSTS = {"victim.com", "www.victim.com", "app.victim.com"}

def validate_referer(request):
    referer = request.headers.get("Referer")
    
    if not referer:
        # Missing Referer — allow (too many legitimate cases)
        return True
    
    try:
        parsed = urlparse(referer)
        # Check host matches allowed list (exact match)
        if parsed.netloc not in ALLOWED_HOSTS:
            return False
    except Exception:
        return False
    
    return True
```

### Scenarios Where Referer Is Absent or Wrong

```
LEGITIMATE SCENARIOS (Referer absent/wrong — must not break these):

1. HTTPS → HTTP transition
   User on https://victim.com navigates to http://victim.com/page
   Browser strips Referer to prevent HTTPS URL leakage over HTTP

2. Meta referrer policy
   <meta name="referrer" content="no-referrer">
   <meta name="referrer" content="origin">  (sends only origin, not path)
   <a href="..." referrerpolicy="no-referrer">

3. Privacy browsers / settings
   Brave, Firefox Enhanced Tracking Protection, Tor Browser
   Strip or spoof Referer by default

4. Browser extensions
   Ad blockers, privacy tools commonly strip Referer

5. Direct navigation
   User types URL, uses bookmark, opens link from email client, IDE
   No referring page → no Referer

6. Corporate proxies
   Enterprise environments often strip Referer before forwarding

7. Non-browser clients
   Mobile apps, curl, API clients
   Do not send Referer unless explicitly coded to do so

ATTACK SCENARIOS (Referer wrong — should catch these):
8. Cross-origin form submission from evil.com
   Referer: https://evil.com/attack.html → reject

ATTACKER SUPPRESSION:
9. Attacker's page includes:
   <meta name="referrer" content="no-referrer">
   No Referer sent → server allows (if missing Referer is allowed)
   → This is why Referer is not a primary defense
```

### The Referer Validation Dilemma

```
Strict (reject missing):
  ✓ Attacker cannot suppress Referer to bypass
  ✗ Breaks scenarios 1-7 above (real users)

Permissive (allow missing):
  ✓ Legitimate users unaffected
  ✗ Attacker suppresses Referer → bypasses check

Neither is fully satisfactory.
Referer is defense-in-depth only — never primary defense.
Primary defense must be CSRF token.
```

---

## 11. Origin vs Referer Comparison

```
┌──────────────────┬───────────────────────────┬───────────────────────────┐
│ Property         │ Origin                    │ Referer                   │
├──────────────────┼───────────────────────────┼───────────────────────────┤
│ Contains         │ Protocol + domain + port  │ Full URL (path + query)   │
├──────────────────┼───────────────────────────┼───────────────────────────┤
│ Privacy risk     │ Low (no path exposed)     │ High (full URL in logs)   │
├──────────────────┼───────────────────────────┼───────────────────────────┤
│ Suppressible     │ Harder to suppress        │ Easily suppressed         │
│ by attacker      │                           │ via meta referrer policy  │
├──────────────────┼───────────────────────────┼───────────────────────────┤
│ Forgeable        │ No (browser sets)         │ No (browser sets)         │
│ by attacker      │                           │ but easily suppressed     │
├──────────────────┼───────────────────────────┼───────────────────────────┤
│ Sent on GET nav  │ Not always                │ Usually (unless stripped) │
├──────────────────┼───────────────────────────┼───────────────────────────┤
│ Sent on POST     │ Yes (cross-origin)        │ Yes (usually)             │
├──────────────────┼───────────────────────────┼───────────────────────────┤
│ Absent scenarios │ Same-origin, non-browser, │ Many (see Section 10)     │
│                  │ direct nav, old browsers  │                           │
├──────────────────┼───────────────────────────┼───────────────────────────┤
│ CSRF defense use │ Primary supplementary     │ Last resort / fallback    │
├──────────────────┼───────────────────────────┼───────────────────────────┤
│ Recommended      │ YES — use as supplement   │ Avoid as sole check       │
│                  │ to CSRF token             │ Use as fallback only      │
└──────────────────┴───────────────────────────┴───────────────────────────┘
```

---

## 12. Defense 5 — SameSite Cookie Attribute

Full reference in Module 2. Summary as defense layer:

### SameSite as a Defense Layer

```
WHAT SAMESITE PROVIDES:
  Browser-enforced control on cross-site cookie sending
  Attacker on evil.com cannot override this
  Works at browser level, independent of application logic

WHAT SAMESITE DOES NOT PROVIDE:
  Protection against same-site attacks (XSS on victim.com)
  Protection against subdomain attacks (same-site ≠ same-origin)
  Application-level intent verification
  Protection if misconfigured, absent, or on old browsers
```

### SameSite Failure Modes (Defense Layer Analysis)

```
FAILURE 1 — Misconfiguration
  SameSite=None (deliberate or accidental)
  → Full cross-site cookie sending restored
  → Complete bypass

FAILURE 2 — Absent attribute on older browsers
  Pre-2020 browsers: absent = SameSite=None behavior
  Chrome 2020+: absent = SameSite=Lax (with timing window)
  → Cannot rely on browser defaults

FAILURE 3 — Subdomain compromise
  SameSite considers subdomains as same-site
  Attacker on sub.victim.com → same-site → cookies sent
  → Subdomain takeover defeats SameSite

FAILURE 4 — GET state-changing endpoints
  SameSite=Lax exception: cross-site GET navigation sends cookie
  Any state-changing GET endpoint is exploitable under Lax

FAILURE 5 — Lax+POST timing window
  Cookies without explicit SameSite: 2-min POST window in Chrome
  → POST CSRF possible immediately after login

FAILURE 6 — Same-origin XSS
  XSS on victim.com → request is same-origin → SameSite irrelevant
  Session cookie sent on all same-origin requests

FAILURE 7 — Browser support
  Older browsers, some mobile browsers ignore SameSite
  → Cannot be sole defense for diverse user base
```

---

## 13. Defense 6 — Custom Request Header

For AJAX-heavy applications. Requires a custom header that HTML forms cannot produce.

### Mechanism

```javascript
// Client side — add to every AJAX request
fetch('/api/transfer', {
  method: 'POST',
  credentials: 'include',
  headers: {
    'X-Requested-With': 'XMLHttpRequest',
    // OR application-specific:
    'X-CSRF-Protection': '1',
    'X-App-Name': 'MyApp'
  },
  body: JSON.stringify({ to: 'bob', amount: 100 })
});
```

```python
# Server side — validate header presence
def validate_custom_header(request):
    if request.headers.get('X-Requested-With') != 'XMLHttpRequest':
        return HttpResponse(403)
```

### Why It Works

```
HTML <form> submissions:
  Cannot set custom headers (browser restriction)
  Content-Type limited to form-compatible types
  → Forged form submission lacks custom header → rejected

fetch() cross-origin with custom header:
  Triggers CORS preflight (OPTIONS request)
  Server must explicitly allow origin + header
  Without permissive CORS: preflight rejected → request blocked
  → Forged fetch() blocked by CORS
```

### Limitations

```
✗ Only protects AJAX endpoints
✗ Does not protect HTML form submission endpoints
✗ CORS misconfiguration defeats this entirely
✗ Same-origin XSS can set any header freely
✓ Good supplementary defense for pure API endpoints
✓ Pairs well with CSRF token for defense-in-depth
```

---

## 14. XSS Interaction — When All Defenses Collapse

XSS on the same origin defeats every CSRF defense simultaneously. This is the single most important security relationship between attack classes.

### How XSS Defeats Each Defense

```javascript
// Attacker XSS payload running on victim.com

// STEP 1: Extract CSRF token
const resp = await fetch('/settings', { credentials: 'include' });
const html = await resp.text();
const token = html.match(/name="csrf_token" value="([^"]+)"/)[1];

// STEP 2: Forge authenticated request with valid token
await fetch('/settings/change-email', {
  method: 'POST',
  credentials: 'include',
  headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  body: `email=attacker@evil.com&csrf_token=${token}`
});

// WHY EACH DEFENSE FAILS:
//
// CSRF TOKEN: XSS reads it directly from DOM (same-origin)
//
// SAMESITE: XSS runs on victim.com → request is same-site
//           SameSite restriction does not apply
//           Session cookie sent automatically
//
// ORIGIN:   Request origin = https://victim.com
//           Passes allowlist check perfectly
//
// REFERER:  Referer = https://victim.com/search?q=...
//           Passes domain check perfectly
//
// CUSTOM HEADER: Same-origin JS can set any header freely
//               X-Requested-With: XMLHttpRequest → passes
```

### The Common Failure Mode

```
XSS is the common failure mode for ALL CSRF defenses:

  CSRF Token      → XSS reads token from DOM
  SameSite        → XSS is same-site, restriction bypassed
  Origin header   → Request from victim.com, check passes
  Referer header  → Request from victim.com, check passes
  Custom header   → Same-origin JS sets it freely

Only re-authentication survives:
  Even XSS cannot supply the victim's password or OTP
  Re-auth at critical actions remains effective
```

### Implication for Defense Design

```
XSS and CSRF defenses must be evaluated together:
  Strong CSRF token + XSS on same origin = weak CSRF protection
  Strong CSRF token + no XSS = strong CSRF protection

Additional mitigations:
  Content Security Policy (CSP):
    Restricts which scripts can execute
    Blocks inline script (prevents most XSS payload injection)
    Does not eliminate XSS but reduces CSRF token extraction risk
  
  HttpOnly on session cookie:
    Protects session from XSS theft
    Does not prevent XSS from making authenticated requests
    Does not protect CSRF token (CSRF token usually not HttpOnly)
```

---

## 15. Defense Independence — The Common Failure Mode

The claim "three independent layers" requires scrutiny.

```
INDEPENDENT layers have DIFFERENT failure modes:
  If Layer A fails, Layer B still protects

NON-INDEPENDENT layers share a failure mode:
  One event causes multiple layers to fail simultaneously

ANALYSIS OF THE THREE LAYERS:

Layer 1 — CSRF Token        Failure mode: XSS, weak implementation
Layer 2 — SameSite          Failure mode: XSS (same-site bypass), misconfiguration
Layer 3 — Origin/Referer    Failure mode: XSS (same-origin passes checks)

SHARED FAILURE MODE: Same-origin XSS defeats all three simultaneously.

TRUE independence would require each layer to have
a completely different failure mode.

WHAT GENUINE INDEPENDENCE LOOKS LIKE:
  CSRF Token (app level)   — fails to XSS
  SameSite (browser level) — fails to misconfiguration/subdomain
  Re-auth (design level)   — fails to nothing (CSRF cannot supply password)
  
  Re-auth has a different failure mode than XSS — genuinely independent layer
```

---

## 16. The Correct Defense-in-Depth Layering Model

```
┌──────────────────────────────────────────────────────────────────┐
│              CORRECT DEFENSE-IN-DEPTH MODEL                      │
├────────────────┬─────────────────────────┬───────────────────────┤
│ Layer          │ What It Prevents         │ Failure Mode          │
├────────────────┼─────────────────────────┼───────────────────────┤
│ CSRF Token     │ Forged requests from     │ XSS, weak token,      │
│ (primary)      │ external origins         │ implementation error  │
├────────────────┼─────────────────────────┼───────────────────────┤
│ SameSite=Lax   │ Cross-site cookie        │ Misconfiguration,     │
│ or Strict      │ attachment on most       │ subdomain attack,     │
│ (browser)      │ cross-site requests      │ GET state changes     │
├────────────────┼─────────────────────────┼───────────────────────┤
│ Origin Header  │ Identifiable cross-site  │ Absent header,        │
│ Validation     │ requests                 │ same-origin XSS       │
│ (transport)    │                          │                       │
├────────────────┼─────────────────────────┼───────────────────────┤
│ Referer        │ Identifiable cross-site  │ Suppressible,         │
│ Validation     │ requests (fallback)      │ many legitimate       │
│ (transport)    │                          │ absent scenarios      │
├────────────────┼─────────────────────────┼───────────────────────┤
│ Re-auth        │ Critical irreversible    │ None for CSRF         │
│ (design)       │ actions                  │ (UX cost only)        │
└────────────────┴─────────────────────────┴───────────────────────┘

MINIMUM RECOMMENDED STACK:
  ✓ CSRF Token (synchronizer pattern, session-bound)
  ✓ SameSite=Lax explicitly set on session cookie
  ✓ Origin header validation as supplement

FOR HIGH-SECURITY APPLICATIONS:
  ✓ All of the above
  ✓ SameSite=Strict for session cookie
  ✓ Re-authentication for critical actions
  ✓ CSP to limit XSS impact on token extraction
  ✓ Signed double-submit cookie for stateless services
```

---

## 17. Re-Authentication as a Design-Level Defense

The only CSRF defense that survives same-origin XSS.

```
IMPLEMENTATION:
  Before executing irreversible/high-impact actions:
    Require: current_password, OTP, TOTP code, or hardware key

  // Server side
  def delete_account(request):
      if not verify_password(request.user, request.POST["password"]):
          return HttpResponse(403, "Authentication required")
      # Only reaches here if password verified
      perform_deletion(request.user)

WHY CSRF CANNOT BYPASS THIS:
  CSRF causes the browser to send a request
  The request is blind — attacker cannot supply the victim's password
  The victim's password is not available in any cookie or header
  CSRF cannot interact with re-auth prompts

WHY XSS CANNOT EASILY BYPASS THIS:
  XSS could show a fake re-auth prompt and capture the password
  BUT: this requires significant additional XSS complexity
  AND: phishing detection, user awareness may catch it
  Re-auth significantly raises the attack complexity even under XSS

WHEN TO REQUIRE RE-AUTH:
  ✓ Account deletion
  ✓ Email address change
  ✓ Password change
  ✓ Two-factor authentication enrollment or removal
  ✓ Adding payment methods
  ✓ Large financial transactions
  ✓ Admin privilege grants
  ✓ OAuth application authorization with wide scope
```

---

## 18. Key Terminology Reference

| Term | Definition |
|------|------------|
| **Synchronizer Token Pattern** | Server generates session-bound random token, embeds in forms, validates on submission |
| **Double-Submit Cookie** | CSRF defense using matching values in cookie and request body/header |
| **Signed Double-Submit** | Double-submit variant where cookie value is HMAC-signed to prevent injection |
| **Origin Header** | Browser-set header containing protocol+domain+port of requesting origin |
| **Referer Header** | Browser-set header containing full URL of referring page |
| **Constant-Time Comparison** | Token comparison that takes equal time regardless of match point (prevents timing attacks) |
| **Subdomain Cookie Injection** | Attack where attacker-controlled subdomain sets cookies for parent domain |
| **Per-Session Token** | One CSRF token for the lifetime of a user session |
| **Per-Request Token** | New CSRF token generated for every form render, previous token invalidated |
| **Custom Header Defense** | Requiring a non-standard header that HTML forms cannot produce cross-origin |
| **Defense-in-Depth** | Layering multiple independent security controls so failure of one doesn't expose system |
| **Common Failure Mode** | Single event (e.g., XSS) that defeats multiple defense layers simultaneously |
| **Re-authentication** | Requiring credential verification before executing high-impact actions |
| **CSP** | Content Security Policy — HTTP header restricting script execution sources |
| **HMAC** | Hash-based Message Authentication Code — used to sign tokens to prevent tampering |
| **Timing Attack** | Side-channel attack exploiting time differences in comparison operations |

---

## 19. Common Misconceptions

### ❌ "Three CSRF defense layers are always independent"
**Wrong.** Same-origin XSS defeats CSRF tokens, SameSite, Origin validation, and Referer validation simultaneously. Layers sharing a common failure mode are not independent. Only re-authentication at the design level is genuinely independent.

### ❌ "Double-submit cookie is as strong as synchronizer token"
**Wrong.** Double-submit compares two client-side values. Subdomain cookie injection lets an attacker control both values. Synchronizer tokens store the expected value server-side where the attacker cannot reach it.

### ❌ "Validating Referer is sufficient for CSRF protection"
**Wrong.** Referer is suppressible, absent in many legitimate scenarios, and bypassed by any same-origin XSS. Never use Referer as a primary or sole CSRF defense.

### ❌ "If CSRF token is present in the form, the application is protected"
**Wrong.** The token must be correctly generated (cryptographically random), stored (server-side, session-bound), transmitted (body or header, not cookie or URL), and validated (server-side, constant-time). A token that fails any of these properties provides little or no protection.

### ❌ "SameSite=Strict provides complete CSRF protection without tokens"
**Wrong.** SameSite=Strict blocks cross-site requests but not same-site XSS. An XSS on any page of the application bypasses SameSite entirely. Tokens are still required for defense-in-depth.

### ❌ "Origin: null is always safe to reject"
**Wrong.** Legitimate sandboxed iframes send `Origin: null`. Rejecting null breaks these use cases. However, allowing null can be dangerous if attackers use sandboxed iframes as CSRF vectors. Handle explicitly with awareness of both sides.

### ❌ "The CSRF token can be stored in a cookie"
**Wrong.** Cookies are sent automatically by the browser — this is the root cause of CSRF. Storing the CSRF token in a cookie means it travels without any additional proof of intent, defeating the purpose. Token must be in body or custom header.

---

## 20. Bug Bounty Reference

### Defense Evaluation Checklist

When reviewing an application's CSRF defenses:

```
CSRF TOKEN CHECK:
  □ Is a token present in state-changing requests?
  □ Is it in the body or a custom header (not cookie, not URL)?
  □ Remove the token — does the server reject? (TEST: token not validated)
  □ Send empty token — does the server reject? (TEST: presence not value)
  □ Send random value — does the server reject? (TEST: not validated vs session)
  □ Use another user's token — does the server reject? (TEST: session binding)
  □ Switch method to GET, remove token — does it work? (TEST: method exemption)
  □ Change Content-Type — does token validation still run?

DOUBLE-SUBMIT CHECK:
  □ Is CSRF value in a cookie AND in the body?
  □ Is the cookie HttpOnly? (if yes: JS can't read it — may be synchronizer)
  □ Can you set the cookie from a subdomain?
  □ Does a signed variant exist? (try tampering with cookie value)

SAMESITE CHECK:
  □ What SameSite value is set on session cookie?
  □ Is it explicit or relying on browser default?
  □ Are any state-changing endpoints reachable via GET?

ORIGIN/REFERER CHECK:
  □ Send request with Origin: https://evil.com — rejected?
  □ Send request without Origin — rejected or allowed?
  □ Send request with Origin: null — allowed? (sandboxed iframe vector)
  □ Send request with Referer stripped — allowed?
  □ Send request with Referer: https://evil.com — rejected?

XSS INTERACTION:
  □ Does any XSS exist on the same origin?
  □ If yes: all CSRF defenses should be considered potentially bypassed
  □ Note in report: XSS + CSRF = complete account takeover chain
```

### Reporting CSRF Defense Weaknesses

```markdown
## CSRF Defense Bypass via [Mechanism]

### Vulnerability
The application implements CSRF protection via [token/double-submit/Origin check]
but the implementation is bypassable because [specific weakness].

### Weakness Detail
[Specific property that fails — e.g., token not session-bound, 
double-submit cookie injectable via subdomain, Origin not validated]

### Exploit Scenario
[Step-by-step chain to bypass the defense and execute a forged request]

### Impact
[Specific action achievable; severity based on that action]

### Remediation
[Specific fix for the identified weakness]
```

---

## 21. Module 6 Summary — What You Must Know Cold

```
DEFENSE LEVELS:
✓ Browser level: SameSite — attacker cannot override, browser enforces
✓ Transport level: Origin/Referer — server checks request source header
✓ Application level: CSRF token — server generates and validates secret
✓ Design level: Re-auth — cannot be bypassed by CSRF alone

SYNCHRONIZER TOKEN:
✓ Must be: cryptographically random, 128+ bits, session-bound
✓ Must be: validated server-side with constant-time comparison
✓ Must travel in: body or custom header (NEVER cookie, NEVER URL)
✓ Must be: invalidated on logout
✓ Common mistakes: not session-bound, empty accepted, stored in cookie

DOUBLE-SUBMIT COOKIE:
✓ Compares cookie value to body value
✓ Weakness: subdomain cookie injection → attacker controls both values
✓ Fix: signed double-submit (HMAC) → injection cannot forge valid signature
✓ Weaker than synchronizer token; use when no server-side session store

ORIGIN HEADER:
✓ Reject if present and not allowlisted
✓ Allow if absent (don't break legitimate requests)
✓ Fails to: absent header (old browsers, non-browser), same-origin XSS
✓ Better than Referer; use as supplement to CSRF token

REFERER HEADER:
✓ Suppressible, absent in many legitimate scenarios
✓ Defense-in-depth only; never primary defense
✓ Allow missing Referer to avoid breaking legitimate users

XSS INTERACTION:
✓ Same-origin XSS defeats ALL CSRF defenses simultaneously:
  Token → readable from DOM
  SameSite → same-site request, bypass
  Origin/Referer → request from victim.com, passes checks
✓ Only re-authentication survives same-origin XSS
✓ Fix XSS first; CSRF defenses are secondary to XSS elimination

DEFENSE-IN-DEPTH:
✓ Minimum: CSRF token + SameSite=Lax + Origin validation
✓ High security: + SameSite=Strict + Re-auth for critical actions + CSP
✓ Layers sharing a failure mode (XSS) are not truly independent
✓ Re-auth is the only genuinely independent layer
```

---

*Next: Module 07 — Defeating the Defenses*  
*Token leakage via XSS, token leakage via Referer, subdomain attacks,*
*SameSite=Lax bypass scenarios, CORS misconfiguration interaction, and login CSRF chains*