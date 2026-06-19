# CSRF Module 02 — Cookies, Sessions & Authentication State
> **Curriculum:** CSRF Mastery for Ethical Hacking & Bug Bounty  
> **Module:** 02 of 12  
> **Topic:** Cookie Attributes, Session Lifecycle, SameSite Deep Dive, Auth Mechanism Comparison  
> **Level:** Foundational-Intermediate — builds directly on Module 01 trust model

---

## Table of Contents
- [CSRF Module 02 — Cookies, Sessions \& Authentication State](#csrf-module-02--cookies-sessions--authentication-state)
  - [Table of Contents](#table-of-contents)
  - [1. What "Logged In" Means to a Browser](#1-what-logged-in-means-to-a-browser)
  - [2. Session Lifecycle — Full Flow](#2-session-lifecycle--full-flow)
  - [3. Cookie Attributes — Complete Reference](#3-cookie-attributes--complete-reference)
    - [Attribute Summary Table](#attribute-summary-table)
    - [`HttpOnly` — Detailed](#httponly--detailed)
    - [`Secure` — Detailed](#secure--detailed)
    - [`Domain` — Detailed](#domain--detailed)
    - [`Path` — Detailed](#path--detailed)
    - [`Max-Age` / `Expires` — Detailed](#max-age--expires--detailed)
  - [4. SameSite Deep Dive — The Three Values](#4-samesite-deep-dive--the-three-values)
    - [`SameSite=Strict`](#samesitestrict)
    - [`SameSite=Lax`](#samesitelax)
    - [`SameSite=None`](#samesitenone)
  - [5. Same-Site vs Same-Origin — Critical Distinction](#5-same-site-vs-same-origin--critical-distinction)
  - [6. The SameSite=Lax Exception — Precise Rules](#6-the-samesitelax-exception--precise-rules)
    - [What Triggers the Exception (Cookie IS Sent)](#what-triggers-the-exception-cookie-is-sent)
    - [What Does NOT Trigger the Exception (Cookie NOT Sent)](#what-does-not-trigger-the-exception-cookie-not-sent)
    - [The GET Form Edge Case](#the-get-form-edge-case)
  - [7. The Lax+POST Timing Window](#7-the-laxpost-timing-window)
  - [8. Why HttpOnly Does Not Prevent CSRF](#8-why-httponly-does-not-prevent-csrf)
  - [9. Why Secure Does Not Prevent CSRF](#9-why-secure-does-not-prevent-csrf)
  - [10. CSRF Token — Why It Works Mechanically](#10-csrf-token--why-it-works-mechanically)
    - [The Core Property](#the-core-property)
    - [Implementation Flow](#implementation-flow)
    - [Why the Forged Request Fails](#why-the-forged-request-fails)
    - [What the Token Proves](#what-the-token-proves)
  - [11. Authentication Mechanisms Compared](#11-authentication-mechanisms-compared)
    - [Cookie-Based Sessions](#cookie-based-sessions)
    - [JWT in Cookie](#jwt-in-cookie)
    - [JWT in localStorage + Authorization Header](#jwt-in-localstorage--authorization-header)
    - [Hybrid — HttpOnly Cookie + CSRF Token](#hybrid--httponly-cookie--csrf-token)
    - [Comparison Table](#comparison-table)
  - [12. JWT — Format vs Delivery Mechanism](#12-jwt--format-vs-delivery-mechanism)
  - [13. What the Server Must Check](#13-what-the-server-must-check)
    - [Option A — CSRF Token (Synchronizer Token Pattern)](#option-a--csrf-token-synchronizer-token-pattern)
    - [Option B — Origin Header Validation](#option-b--origin-header-validation)
    - [Option C — Referer Header Validation](#option-c--referer-header-validation)
    - [Option D — Custom Request Header](#option-d--custom-request-header)
  - [14. The Layered Defense Model](#14-the-layered-defense-model)
  - [15. State-Changing GET Requests — The Lax Blind Spot](#15-state-changing-get-requests--the-lax-blind-spot)
    - [What Triggers the Lax Exception](#what-triggers-the-lax-exception)
    - [The Defense](#the-defense)
  - [16. Key Terminology Reference](#16-key-terminology-reference)
  - [17. Common Misconceptions](#17-common-misconceptions)
    - [❌ "HttpOnly prevents CSRF"](#-httponly-prevents-csrf)
    - [❌ "Secure prevents CSRF"](#-secure-prevents-csrf)
    - [❌ "JWTs prevent CSRF"](#-jwts-prevent-csrf)
    - [❌ "SameSite=Lax fully prevents CSRF"](#-samesitelax-fully-prevents-csrf)
    - [❌ "SameSite=Strict is always the right choice"](#-samesitestrict-is-always-the-right-choice)
    - [❌ "Checking the Referer header is sufficient"](#-checking-the-referer-header-is-sufficient)
    - [❌ "If I use CSRF tokens I don't need SameSite"](#-if-i-use-csrf-tokens-i-dont-need-samesite)
    - [❌ "localStorage tokens are always better than cookies"](#-localstorage-tokens-are-always-better-than-cookies)
  - [18. Bug Bounty Relevance](#18-bug-bounty-relevance)
    - [Reconnaissance Checklist — Cookie Attributes](#reconnaissance-checklist--cookie-attributes)
    - [Identifying CSRF Surface](#identifying-csrf-surface)
    - [Report Severity by Action](#report-severity-by-action)
  - [19. Module 2 Summary — What You Must Know Cold](#19-module-2-summary--what-you-must-know-cold)

---

## 1. What "Logged In" Means to a Browser

From the browser's perspective, being "logged in" is a purely mechanical state:

> The browser holds a cookie whose domain matches the target server, and the server accepts that cookie's value as proof of identity.

The browser has no concept of:
- Whether the current page is trustworthy
- Whether the user intended the current request
- Whether the request was triggered by the user or by attacker-planted HTML

This is not a bug. It is the definition of how cookie-based authentication works.

```
"Logged in" from browser's perspective:
  cookie_jar["bank.com"]["session"] = "abc123"  ← that's it

"Authenticated" from server's perspective:
  session_store["abc123"] exists and is not expired  ← that's it

Neither checks intent. CSRF abuses this gap.
```

---

## 2. Session Lifecycle — Full Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                     SESSION LIFECYCLE                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  1. User submits credentials                                    │
│     POST /login { username: "alice", password: "..." }          │
│                      ↓                                          │
│  2. Server validates credentials                                │
│                      ↓                                          │
│  3. Server creates session record                               │
│     session_store["abc123"] = {                                 │
│         user_id:    42,                                         │
│         created_at: 1700000000,                                 │
│         expires_at: 1700086400,                                 │
│         csrf_token: "xK9mP2qL..."  ← if implemented            │
│     }                                                           │
│                      ↓                                          │
│  4. Server sends Set-Cookie header                              │
│     Set-Cookie: session=abc123; HttpOnly; Secure; SameSite=Lax  │
│                      ↓                                          │
│  5. Browser stores cookie                                       │
│     cookie_jar["bank.com"]["session"] = "abc123"                │
│                      ↓                                          │
│  6. Every subsequent request to bank.com:                       │
│     Browser auto-attaches → Cookie: session=abc123              │
│                      ↓                                          │
│  7. Server looks up session_store["abc123"]                     │
│     → finds user 42 → request treated as authenticated          │
│                                                                 │
│  CSRF EXPLOITS STEP 6 — the automatic attachment                │
└─────────────────────────────────────────────────────────────────┘
```

---

## 3. Cookie Attributes — Complete Reference

### Attribute Summary Table

| Attribute | What It Does | Prevents CSRF? | Prevents XSS Token Theft? |
|-----------|-------------|----------------|--------------------------|
| `HttpOnly` | Blocks JS from reading cookie | ❌ No | ✅ Yes |
| `Secure` | HTTPS-only transmission | ❌ No | ❌ No |
| `SameSite=Strict` | Never sent cross-site | ✅ Yes (complete) | ❌ No |
| `SameSite=Lax` | Sent only on cross-site top-level GET | ✅ Partial | ❌ No |
| `SameSite=None` | Always sent cross-site | ❌ No | ❌ No |
| `Domain` | Scope to domain + subdomains | ❌ No (widens attack surface) | ❌ No |
| `Path` | Scope to path prefix | ❌ No | ❌ No |
| `Max-Age`/`Expires` | Controls lifetime | ❌ No (indirect) | ❌ No |

### `HttpOnly` — Detailed

```http
Set-Cookie: session=abc123; HttpOnly
```

**Purpose:** XSS mitigation — prevents `document.cookie` from reading the value.

**CSRF relevance:** None. The browser still attaches the cookie to every matching request automatically. CSRF does not need to read the cookie — it relies on the browser's transport layer to send it.

```
XSS attack (without HttpOnly):
  JavaScript reads document.cookie → steals "session=abc123" → sends to attacker server

CSRF attack (regardless of HttpOnly):
  Attacker page causes request to bank.com → browser attaches cookie automatically
  Attacker never reads the cookie value → doesn't need to
```

### `Secure` — Detailed

```http
Set-Cookie: session=abc123; Secure
```

**Purpose:** Prevents cookie transmission over unencrypted HTTP — stops passive network sniffing.

**CSRF relevance:** None. The forged CSRF request travels over HTTPS just like a legitimate one. TLS encrypts the transport; it does not verify that the user intended the request.

### `Domain` — Detailed

```http
Set-Cookie: session=abc123; Domain=bank.com
```

**Without Domain:** Cookie sent only to the exact host (`bank.com` only).

**With Domain:** Cookie sent to `bank.com` AND all subdomains (`api.bank.com`, `mail.bank.com`, `dev.bank.com`).

**CSRF relevance:**
- Widens the set of origins that receive the cookie
- If attacker controls any subdomain, they may exploit cookie scope
- Critical for Double-Submit Cookie attacks (Module 6) — subdomain control can poison the cookie

**Best practice:** Omit the `Domain` attribute unless subdomain sharing is explicitly required.

### `Path` — Detailed

```http
Set-Cookie: session=abc123; Path=/app
```

**Purpose:** Scopes cookie delivery to URL paths beginning with `/app`.

**CSRF relevance:** Minimal. An attacker targeting `/app/transfer` can craft requests to that exact path. `Path` is not a security boundary.

### `Max-Age` / `Expires` — Detailed

```http
Set-Cookie: session=abc123; Max-Age=3600
Set-Cookie: session=abc123; Expires=Thu, 01 Jan 2026 00:00:00 GMT
```

**Without these:** Session cookie — deleted when browser closes (but not always, due to session restore features).

**With these:** Persistent cookie — survives browser restarts until expiry.

**CSRF relevance:** Longer-lived cookies extend the CSRF attack window. A persistent session cookie from a banking site may remain valid for days or weeks, giving an attacker more time to exploit it.

---

## 4. SameSite Deep Dive — The Three Values

`SameSite` is the only cookie attribute that directly addresses CSRF. It controls whether the browser sends the cookie on cross-site requests.

### `SameSite=Strict`

```http
Set-Cookie: session=abc123; SameSite=Strict
```

**Rule:** Cookie is NEVER sent on any cross-site request — including navigations, subresources, and form submissions.

```
Scenario                                              Cookie Sent?
─────────────────────────────────────────────────────────────────
User on bank.com clicks link to bank.com/dashboard   ✅ Yes (same-site)
User clicks link in email to bank.com/dashboard      ❌ No  (cross-site navigation)
evil.com auto-submits POST to bank.com               ❌ No  (cross-site POST)
evil.com loads <img src="bank.com/action">           ❌ No  (cross-site subresource)
Google search result link to bank.com                ❌ No  (cross-site navigation)
```

**CSRF protection:** Complete. No cross-site request of any kind carries the cookie.

**Usability cost:** High. Users following links from emails, search engines, other sites arrive at the application as if logged out. For most consumer-facing applications this is unacceptable UX.

**Appropriate for:** Admin panels, high-security internal tools, step-up authentication flows, any context where users are expected to navigate directly.

### `SameSite=Lax`

```http
Set-Cookie: session=abc123; SameSite=Lax
```

**Rule:** Cookie is sent on cross-site requests ONLY when BOTH conditions are met:
1. HTTP method is GET
2. Request is a top-level navigation (changes the browser URL bar)

```
Scenario                                              Cookie Sent?
─────────────────────────────────────────────────────────────────
User clicks <a href="bank.com/page">                 ✅ Yes (top-level GET)
Browser follows 302 redirect to bank.com             ✅ Yes (top-level GET)
window.location.href = "bank.com/action"             ✅ Yes (top-level GET)
<meta http-equiv="refresh" to bank.com>              ✅ Yes (top-level GET)
evil.com auto-submits POST form to bank.com          ❌ No  (cross-site POST)
evil.com loads <img src="bank.com/action">           ❌ No  (subresource, not top-level)
evil.com uses fetch("bank.com/action")               ❌ No  (not top-level navigation)
evil.com loads <iframe src="bank.com/action">        ❌ No  (not top-level navigation)
```

**CSRF protection:** Strong against POST-based CSRF. Partial — GET-based CSRF via top-level navigation still works.

**Usability:** Good. Users can follow links from emails and search engines and arrive logged in.

**Chrome default (2020+):** Cookies without explicit `SameSite` attribute are treated as `Lax`.

### `SameSite=None`

```http
Set-Cookie: session=abc123; SameSite=None; Secure
```

**Rule:** Cookie sent on ALL cross-site requests — pre-2020 default behavior.

**Requires:** Must be paired with `Secure` attribute (browser enforced).

**CSRF implication:** Full ambient authority restored. Application is responsible for all CSRF protection.

**Legitimate uses:** Third-party embedded widgets, payment processors, cross-domain SSO, OAuth flows, advertising/analytics that need cross-site cookie access.

---

## 5. Same-Site vs Same-Origin — Critical Distinction

These terms are frequently confused. They define different boundaries.

```
SAME-ORIGIN: protocol + domain + port must ALL match
──────────────────────────────────────────────────────
https://bank.com:443   →  https://bank.com:443      ✅ same-origin
https://bank.com:443   →  http://bank.com:443       ❌ different protocol
https://bank.com:443   →  https://bank.com:8443     ❌ different port
https://bank.com:443   →  https://api.bank.com:443  ❌ different subdomain

SAME-SITE: registrable domain (eTLD+1) must match
──────────────────────────────────────────────────────
https://bank.com        →  https://bank.com         ✅ same-site
https://app.bank.com    →  https://api.bank.com     ✅ same-site (both bank.com)
https://bank.com        →  https://evil.com         ❌ cross-site
https://bank.co.uk      →  https://evil.co.uk       ❌ cross-site (eTLD is .co.uk)
```

**Security implication:** `SameSite` is a coarser boundary than same-origin. A subdomain of the same registered domain is still "same-site" and will receive cookies even with `SameSite=Strict`. This matters for subdomain takeover attacks.

```
If attacker controls sub.bank.com:
  sub.bank.com is same-site as bank.com
  SameSite=Strict does NOT protect against attacks from sub.bank.com
  The cookie is sent on requests from sub.bank.com to bank.com
```

---

## 6. The SameSite=Lax Exception — Precise Rules

The Lax exception is the most important nuance for CSRF testing.

### What Triggers the Exception (Cookie IS Sent)

```
✅ <a href="https://bank.com/action">link</a>  — user clicks
✅ window.location.href = "https://bank.com/action"  — JS redirect
✅ window.location.replace("https://bank.com/action")
✅ <meta http-equiv="refresh" content="0; url=https://bank.com/action">
✅ HTTP 301/302/303/307 redirect chain ending at bank.com via GET
✅ Browser address bar navigation
✅ Bookmark click
```

### What Does NOT Trigger the Exception (Cookie NOT Sent)

```
❌ <img src="https://bank.com/action">          — subresource
❌ <iframe src="https://bank.com/action">       — subresource
❌ <script src="https://bank.com/action">       — subresource
❌ fetch("https://bank.com/action")             — not top-level
❌ XMLHttpRequest to bank.com                   — not top-level
❌ <form method="POST" action="bank.com">       — POST method
❌ <form method="GET" action="bank.com">        — GET form IS top-level...
```

### The GET Form Edge Case

```html
<form method="GET" action="https://bank.com/action">
  <input type="hidden" name="to" value="attacker">
  <input type="submit">
</form>
```

A GET form submission IS a top-level navigation — the browser navigates to the form's action URL with parameters in the query string. Under `SameSite=Lax`, the cookie IS sent.

This means GET-based CSRF via form is viable under Lax, just like `<a href>` links.

---

## 7. The Lax+POST Timing Window

Chrome introduced a temporary exception for cookies without an explicit `SameSite` attribute:

```
Cookie set without SameSite attribute in Chrome:

  First 2 minutes after cookie creation:
    → Behaves like SameSite=None for top-level cross-site POST
    → POST form submissions from other sites DO send the cookie

  After 2 minutes:
    → Enforces SameSite=Lax behavior
    → POST form submissions from other sites do NOT send the cookie
```

**Why it exists:** Backward compatibility for OAuth and SSO flows that rely on cross-site POST redirects.

**Attack scenario:**
```
1. Attacker forces victim to log in (Login CSRF — Module 5)
2. Immediately (within 2 minutes) triggers the forged action
3. The new session cookie is still in the Lax+POST window
4. POST-based CSRF succeeds despite Lax default
```

**Testing note:** If a target application uses cookies without explicit `SameSite` and you can control the login timing, test within the 2-minute window.

---

## 8. Why HttpOnly Does Not Prevent CSRF

This is the single most common CSRF misconception. Full mechanical breakdown:

```
WHAT HTTPONLY DOES:
  document.cookie returns ""  ← JavaScript cannot read the cookie

WHAT CSRF REQUIRES:
  Browser transport layer sends Cookie: session=abc123 header
  ← This happens BEFORE JavaScript runs
  ← HttpOnly has no effect on this layer

CSRF FLOW WITH HTTPONLY COOKIE:
  1. evil.com page loads
  2. HTML triggers request to bank.com (img tag, form, etc.)
  3. Browser transport layer checks cookie jar for bank.com cookies
  4. Finds session=abc123 (HttpOnly flag is irrelevant here)
  5. Attaches Cookie: session=abc123 to the request
  6. Request sent — bank.com never told about HttpOnly
  7. Server validates session → executes action

HttpOnly is an XSS defense. It is not a CSRF defense.
```

---

## 9. Why Secure Does Not Prevent CSRF

```
WHAT SECURE DOES:
  Cookie only transmitted over HTTPS connections
  Prevents passive interception on HTTP networks

WHY IT DOESN'T STOP CSRF:
  The forged request travels over HTTPS — same as legitimate requests
  Secure only controls the transport protocol
  It does not control who initiated the request
  It does not verify user intent

ANALOGY:
  Secure = armored car (protects the package in transit)
  CSRF   = the attacker already put the wrong package in the car
  The armored car delivers the wrong package securely
```

---

## 10. CSRF Token — Why It Works Mechanically

### The Core Property

A CSRF token works because it is a **secret value that the legitimate page has but the attacker cannot obtain**.

```
Why the attacker cannot obtain it:
  1. Token is embedded in the HTML of bank.com's pages
  2. Cross-origin pages cannot read bank.com's HTML (Same-Origin Policy)
  3. Token is random and unpredictable — cannot be guessed
  4. Token is tied to the session — cannot be reused across sessions
```

### Implementation Flow

```
SERVER SIDE (on page render):
  csrf_token = generate_random_token()  // e.g., "xK9mP2qL7rN3..."
  session_store["abc123"]["csrf_token"] = csrf_token
  embed in HTML:
    <input type="hidden" name="csrf_token" value="xK9mP2qL7rN3...">

CLIENT SIDE (legitimate form submission):
  POST /transfer
  Cookie: session=abc123          ← browser attaches automatically
  Body: to=bob&amount=100&csrf_token=xK9mP2qL7rN3...  ← page includes

SERVER SIDE (validation):
  expected = session_store["abc123"]["csrf_token"]
  received = request.body["csrf_token"]
  if expected == received:
      proceed()
  else:
      reject(403)
```

### Why the Forged Request Fails

```
ATTACKER'S FORGED FORM:
  <form action="https://bank.com/transfer" method="POST">
    <input name="to" value="attacker">
    <input name="csrf_token" value="???">  ← CANNOT fill this in
  </form>

Attacker cannot obtain the token because:
  ✗ Cannot read bank.com pages (SOP blocks cross-origin reads)
  ✗ Cannot read bank.com cookies (SOP + HttpOnly)
  ✗ Cannot guess the token (cryptographically random)
  ✗ Cannot reuse another user's token (tied to victim's session)

Result: Server receives request with missing or invalid token → 403 Rejected
```

### What the Token Proves

```
Session cookie proves:  WHO you are (identity)
CSRF token proves:      WHERE the request came from (the page server generated)

Together they answer:
  "Is this user authenticated?"  → session cookie
  "Did this request originate from our application?"  → CSRF token
```

---

## 11. Authentication Mechanisms Compared

### Cookie-Based Sessions

```
Flow:
  Login → server sets session cookie → browser auto-sends on every request

CSRF vulnerability:  YES — ambient authority
XSS token exposure:  LOW — HttpOnly prevents cookie read
Implementation:      Server-side session store required
Logout:              Server invalidates session record
```

### JWT in Cookie

```
Flow:
  Login → server sets JWT in cookie → browser auto-sends on every request

CSRF vulnerability:  YES — still ambient authority (cookie = auto-send)
XSS token exposure:  LOW — if HttpOnly
Implementation:      Stateless — no session store needed
Critical mistake:    Developers think "JWT = no CSRF" — WRONG
                     JWT is a token FORMAT, not a delivery MECHANISM
                     Cookie delivery = CSRF vulnerability regardless of format
```

### JWT in localStorage + Authorization Header

```
Flow:
  Login → JS stores JWT in localStorage → JS reads it and sets Authorization header

CSRF vulnerability:  NO
  Reason 1: Cross-origin pages cannot read another origin's localStorage (SOP)
  Reason 2: Cross-origin pages cannot set Authorization header on forged requests
  Reason 3: <form> and <img> have no mechanism to set custom headers

XSS token exposure:  HIGH — JS can read localStorage → XSS steals the JWT
Implementation:      JS must explicitly attach token on every request
Logout:              Client must delete localStorage entry (server cannot force)
```

### Hybrid — HttpOnly Cookie + CSRF Token

```
Flow:
  Login → server sets HttpOnly session cookie
        → server generates CSRF token
        → token embedded in HTML / returned in non-HttpOnly cookie
        → JS reads token → includes in requests

CSRF vulnerability:  VERY LOW — requires valid token
XSS token exposure:  MEDIUM — CSRF token readable, but session cookie protected
Implementation:      Most robust pattern for traditional web apps
```

### Comparison Table

```
┌──────────────────────────┬────────────┬──────────────┬────────────────┐
│ Mechanism                │ CSRF Risk  │ XSS Token    │ Notes          │
│                          │            │ Exposure     │                │
├──────────────────────────┼────────────┼──────────────┼────────────────┤
│ Cookie (no attrs)        │ HIGH       │ HIGH         │ Worst case     │
│ Cookie + HttpOnly        │ HIGH       │ LOW          │ XSS protected  │
│ Cookie + SameSite=Strict │ NONE       │ LOW          │ UX cost        │
│ Cookie + SameSite=Lax    │ LOW        │ LOW          │ GET gap exists │
│ Cookie + CSRF token      │ VERY LOW   │ MEDIUM       │ Best for SPAs  │
│ JWT in cookie            │ HIGH       │ LOW*         │ Common mistake │
│ JWT in localStorage      │ NONE       │ HIGH         │ XSS risk       │
│ JWT header + SameSite    │ NONE       │ LOW          │ Modern SPAs    │
└──────────────────────────┴────────────┴──────────────┴────────────────┘
* If HttpOnly
```

---

## 12. JWT — Format vs Delivery Mechanism

This distinction prevents one of the most common developer mistakes.

```
JWT = JSON Web Token
    = A TOKEN FORMAT (encoded, optionally signed, optionally encrypted)
    = Contains claims: { user_id: 42, exp: 1700086400, role: "admin" }

JWT is NOT a security mechanism for CSRF on its own.
JWT is NOT inherently more secure than session IDs for CSRF purposes.

WHAT MATTERS FOR CSRF: HOW THE TOKEN IS DELIVERED AND SENT

JWT in cookie:
  → Browser sends automatically on every matching request
  → CSRF VULNERABLE (same as session cookie)

JWT in localStorage + Authorization header:
  → Application JS must explicitly read and attach
  → CSRF SAFE (attacker cannot replicate this)

JWT in sessionStorage + Authorization header:
  → Same as localStorage for CSRF purposes
  → CSRF SAFE
  → Cleared on tab close (shorter window than localStorage)
```

**Common developer mistake:**
```
Developer: "We switched to JWTs, so we removed CSRF protection."
Reality:   They stored the JWT in a cookie.
Result:    Full CSRF vulnerability, no protection.
```

---

## 13. What the Server Must Check

For CSRF resistance, the server needs to verify that the request originated from a page it generated — not just that the user is authenticated.

### Option A — CSRF Token (Synchronizer Token Pattern)
```
Check: Does the token in the request body match the token in the session?
Strength: Strong — token is unforgeable without reading the page
Weakness: Token must be correctly generated, stored, and validated
```

### Option B — Origin Header Validation
```
Check: Does the Origin header match an expected value?
Header: Origin: https://bank.com
Strength: Modern browsers send this on cross-origin requests
Weakness: Absent on same-origin requests, some legacy browsers, some contexts
Rule: Reject if Origin present and not allowlisted; allow if absent (cautiously)
```

### Option C — Referer Header Validation
```
Check: Does the Referer header match an expected domain?
Header: Referer: https://bank.com/transfer-form
Strength: Available in most browsers
Weakness: Frequently stripped (HTTPS→HTTP, privacy tools, referrerpolicy meta tag)
          Can be suppressed by attacker: <meta name="referrer" content="no-referrer">
Rule: Never rely on Referer alone
```

### Option D — Custom Request Header
```
Check: Is a custom header (e.g., X-Requested-With: XMLHttpRequest) present?
Strength: Cross-origin pages cannot set custom headers on simple requests
Weakness: Only works for AJAX requests; forms cannot set custom headers
          CORS misconfiguration can defeat this
```

---

## 14. The Layered Defense Model

No single control is sufficient. Defense in depth:

```
LAYER 1 — SameSite Cookie Attribute
  → Controls when browser attaches cookie on cross-site requests
  → Eliminates condition 2 (ambient authority) for covered request types
  → Gap: Lax allows GET navigations; None provides no protection

LAYER 2 — CSRF Token (Synchronizer Token)
  → Verifies request originated from server-generated page
  → Eliminates condition 3 (no intent verification)
  → Gap: XSS can extract token from DOM

LAYER 3 — Origin/Referer Header Validation
  → Server-side check on request source
  → Defense-in-depth against token bypass scenarios
  → Gap: Headers can be absent or stripped

LAYER 4 — Re-authentication for Sensitive Actions
  → Eliminates condition 1 (active session) for critical operations
  → Password confirmation, MFA step for: account deletion, password change,
    large transfers, admin actions
  → Cannot be bypassed by CSRF alone

RECOMMENDED MINIMUM:
  SameSite=Lax + CSRF Token + Origin validation
  For high-security: SameSite=Strict + CSRF Token + re-auth for critical actions
```

---

## 15. State-Changing GET Requests — The Lax Blind Spot

`SameSite=Lax` has one explicit exception: cross-site top-level GET navigation. If an application performs state changes via GET, `Lax` does not protect it.

### What Triggers the Lax Exception

```html
<!-- All of these send SameSite=Lax cookies on cross-site GET -->

<!-- Link click (user interaction) -->
<a href="https://bank.com/delete-account?confirm=yes">Click here</a>

<!-- JS redirect (no user interaction needed) -->
<script>window.location.href = "https://bank.com/delete-account?confirm=yes";</script>

<!-- Meta refresh (no user interaction needed) -->
<meta http-equiv="refresh" content="0; url=https://bank.com/delete-account?confirm=yes">

<!-- GET form submission (top-level navigation) -->
<form method="GET" action="https://bank.com/delete-account">
  <input name="confirm" value="yes">
  <input type="submit">
</form>
```

### The Defense

GET requests must NEVER perform state-changing actions. This is both:
1. An HTTP specification requirement (GET must be idempotent/safe)
2. A CSRF security requirement (Lax does not protect GET-based state changes)

```
Safe GET:     GET /account/details        → returns data, changes nothing
Unsafe GET:   GET /account/delete?id=123  → deletes data ← CSRF vulnerable under Lax
```

---

## 16. Key Terminology Reference

| Term | Definition |
|------|------------|
| **Session Cookie** | Cookie holding session identifier; sent automatically by browser |
| **HttpOnly** | Cookie attribute preventing JavaScript read access; does NOT prevent CSRF |
| **Secure** | Cookie attribute limiting transmission to HTTPS; does NOT prevent CSRF |
| **SameSite** | Cookie attribute controlling cross-site sending behavior; primary CSRF cookie defense |
| **SameSite=Strict** | Cookie never sent on cross-site requests; complete CSRF protection, high UX cost |
| **SameSite=Lax** | Cookie sent only on cross-site top-level GET navigation; partial CSRF protection |
| **SameSite=None** | Cookie sent on all cross-site requests; no CSRF protection; requires Secure |
| **Same-Site** | Requests where registrable domain (eTLD+1) matches; coarser than same-origin |
| **Same-Origin** | Requests where protocol + domain + port all match; stricter than same-site |
| **eTLD+1** | Effective top-level domain + one label (e.g., bank.com from app.bank.com) |
| **CSRF Token** | Random secret embedded in forms; proves request came from server-generated page |
| **Synchronizer Token Pattern** | Server stores token in session; embeds in HTML; validates on submit |
| **Ambient Authority** | Credentials automatically included in requests (cookies) without explicit attachment |
| **Lax+POST Window** | 2-minute Chrome exception allowing cross-site POST for cookies without SameSite |
| **JWT** | JSON Web Token — a token FORMAT, not a delivery mechanism |
| **Authorization Header** | HTTP header requiring explicit JS attachment; not sent by browser automatically |
| **Top-Level Navigation** | Request that changes the browser URL bar; Lax exception applies |
| **Subresource Request** | Request for embedded content (img, script, iframe); not a top-level navigation |

---

## 17. Common Misconceptions

### ❌ "HttpOnly prevents CSRF"
**Wrong.** HttpOnly prevents XSS from reading the cookie. CSRF does not read the cookie — the browser's transport layer sends it automatically. HttpOnly is irrelevant to CSRF.

### ❌ "Secure prevents CSRF"
**Wrong.** Secure controls transport protocol. The forged request travels over HTTPS — just like a legitimate one. Encrypted forgery is still forgery.

### ❌ "JWTs prevent CSRF"
**Wrong.** JWT is a token format. If stored in a cookie, it is sent automatically — full CSRF vulnerability. JWT in localStorage with Authorization header is CSRF-safe, but that's because of the delivery mechanism, not the JWT format itself.

### ❌ "SameSite=Lax fully prevents CSRF"
**Wrong.** Lax has a deliberate exception: cross-site top-level GET navigation. If any state-changing endpoint responds to GET, Lax does not protect it. Lax also has the Lax+POST 2-minute timing window.

### ❌ "SameSite=Strict is always the right choice"
**Wrong.** Strict breaks legitimate cross-site navigation — users following links from emails or search engines arrive logged out. Strict is appropriate for high-security contexts, not general consumer applications.

### ❌ "Checking the Referer header is sufficient"
**Wrong.** Referer is frequently absent (HTTPS→HTTP transitions, privacy tools, referrerpolicy meta tags, browser settings). An application that rejects missing Referer breaks legitimate requests. An application that allows missing Referer is bypassable. Referer is defense-in-depth, not primary defense.

### ❌ "If I use CSRF tokens I don't need SameSite"
**Wrong.** Defense in depth. CSRF tokens can be leaked via XSS. SameSite provides a browser-level layer that doesn't depend on application-level token management. Use both.

### ❌ "localStorage tokens are always better than cookies"
**Wrong.** localStorage tokens are CSRF-safe but XSS-vulnerable. HttpOnly cookies are XSS-protected for the token but CSRF-vulnerable without SameSite/CSRF tokens. Each model has tradeoffs. The hybrid (HttpOnly cookie + CSRF token) is typically best for traditional web apps.

---

## 18. Bug Bounty Relevance

### Reconnaissance Checklist — Cookie Attributes

When testing a target, check every `Set-Cookie` header:

```
1. Is SameSite set? Which value?
   → None = full CSRF surface
   → Lax  = GET-based state changes may be vulnerable
   → Strict = very limited CSRF surface (check subdomain issues)
   → Absent (legacy browser) = full CSRF surface

2. Is HttpOnly set?
   → Absent = XSS can steal session token
   → Present = session protected from XSS (but CSRF still possible)

3. Is Secure set?
   → Absent on sensitive app = session may leak over HTTP

4. What is the Domain scope?
   → Domain=example.com = all subdomains receive cookie
   → Check for subdomain takeover opportunities

5. What is the Max-Age/Expires?
   → Long-lived = wider CSRF attack window
   → No expiry = session cookie, closed on browser close
```

### Identifying CSRF Surface

```
Look for state-changing endpoints:
  POST /api/user/change-email
  POST /api/account/delete
  POST /api/transfer
  GET  /admin/delete-user?id=X    ← GET + state change = Lax bypass candidate
  POST /api/admin/add-role

Check request structure:
  Is there a CSRF token in the body or headers?
  Is there an X-Requested-With header?
  Is there an Origin or Referer validation (check response to missing/wrong values)?

If SameSite=None or absent: test all state-changing endpoints
If SameSite=Lax: test GET-based state-changing endpoints
If no CSRF token: likely vulnerable regardless of SameSite (defense in depth gap)
```

### Report Severity by Action

| Action | Severity |
|--------|----------|
| Change email / password (account takeover path) | Critical |
| Add attacker as admin / privilege escalation | Critical |
| Financial transaction (transfer, payment) | Critical/High |
| Account deletion | High |
| Add/remove authorized users | High |
| Data deletion (files, records) | High |
| Change security settings (2FA, recovery email) | High |
| Social actions (post, follow, share) | Medium |
| Preference changes (notification settings) | Low |

---

## 19. Module 2 Summary — What You Must Know Cold

```
COOKIE ATTRIBUTES:
✓ HttpOnly = XSS defense only; does NOT prevent CSRF
✓ Secure = transport defense only; does NOT prevent CSRF
✓ SameSite = the only cookie attribute that directly addresses CSRF
✓ Domain without explicit setting = safer (exact host only)

SAMESITE VALUES:
✓ Strict = never cross-site; complete CSRF protection; high UX cost
✓ Lax    = only cross-site top-level GET; strong CSRF protection with GET gap
✓ None   = always cross-site; no CSRF protection; requires Secure
✓ Absent (Chrome 2020+) = treated as Lax

LAX EXCEPTION:
✓ Cookie IS sent on cross-site GET if it is a top-level navigation
✓ This includes: link clicks, JS redirects, meta refresh, GET form submissions
✓ This EXCLUDES: img/iframe/fetch subresource requests
✓ State-changing GETs are therefore vulnerable under Lax

SESSIONS:
✓ Server stores session data; browser holds only the session ID in cookie
✓ Server checks: is this session ID valid? (identity)
✓ Server does NOT check by default: did the user intend this? (legitimacy)

JWT:
✓ JWT is a token FORMAT, not a security mechanism for CSRF
✓ JWT in cookie = CSRF vulnerable (ambient authority)
✓ JWT in localStorage + Authorization header = CSRF safe
✓ "We use JWTs" is NOT a CSRF defense unless the delivery mechanism is correct

CSRF TOKEN MECHANICS:
✓ Works because it is unforgeable: attacker cannot read the server-generated page
✓ Proves WHERE the request came from, not just WHO sent it
✓ Must be: random, per-session (or per-request), validated server-side

DEFENSE LAYERS:
✓ SameSite → controls browser cookie attachment (browser layer)
✓ CSRF token → verifies request origin (application layer)
✓ Origin/Referer → server-side header check (defense-in-depth)
✓ Re-authentication → eliminates active session for sensitive actions (design layer)
✓ Best practice: use at least two layers
```

---

*Next: Module 03 — The Anatomy of a CSRF Attack*  
*The three required conditions in detail, attacker control surface, what the server cannot distinguish, forged request construction, and impact scoping*