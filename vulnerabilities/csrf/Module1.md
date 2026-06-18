# CSRF Module 01 — The Trust Problem
> **Curriculum:** CSRF Mastery for Ethical Hacking & Bug Bounty  
> **Module:** 01 of 12  
> **Topic:** Browser Trust Model, Ambient Authority, and the Root Cause of CSRF  
> **Level:** Foundational — every later module builds on this

---

## Table of Contents
1. [What CSRF Actually Is](#1-what-csrf-actually-is)
2. [The Web's Original Trust Model](#2-the-webs-original-trust-model)
3. [Ambient Authority — The Core Problem](#3-ambient-authority--the-core-problem)
4. [How Browsers Handle Cookies](#4-how-browsers-handle-cookies)
5. [Authentication vs Request Legitimacy](#5-authentication-vs-request-legitimacy)
6. [The Three Required Conditions for CSRF](#6-the-three-required-conditions-for-csrf)
7. [How HTML Triggers Requests Without JavaScript](#7-how-html-triggers-requests-without-javascript)
8. [What the Server Sees vs What Actually Happened](#8-what-the-server-sees-vs-what-actually-happened)
9. [The Analytical Framework — Four Questions](#9-the-analytical-framework--four-questions)
10. [Who Is At Fault — Design vs Implementation](#10-who-is-at-fault--design-vs-implementation)
11. [Same-Origin Policy and Why It Doesn't Stop CSRF](#11-same-origin-policy-and-why-it-doesnt-stop-csrf)
12. [CSRF vs Related Attacks — Conceptual Boundaries](#12-csrf-vs-related-attacks--conceptual-boundaries)
13. [Key Terminology Reference](#13-key-terminology-reference)
14. [Common Misconceptions](#14-common-misconceptions)
15. [Mental Models Summary](#15-mental-models-summary)
16. [Bug Bounty Relevance](#16-bug-bounty-relevance)

---

## 1. What CSRF Actually Is

**Cross-Site Request Forgery (CSRF)** is an attack that causes an authenticated user's browser to send an unintended request to a web application — using the user's credentials — without the user's knowledge or consent.

### The One-Sentence Definition
> CSRF tricks the browser into borrowing the user's credentials to perform an action the user never intended.

### What CSRF Is NOT
- It is **not** credential theft — the attacker never sees the cookie or password
- It is **not** a session hijacking attack — the attacker never obtains the session token
- It is **not** about breaking encryption or bypassing TLS
- It is **not** a server-side vulnerability in isolation — it is a consequence of browser behavior combined with server-side trust assumptions

### What CSRF IS
- An abuse of the browser's automatic credential-attachment behavior
- An exploitation of the server's failure to distinguish intended from forged requests
- A trust relationship abuse between the browser and the server
- An **ambient authority** exploit

---

## 2. The Web's Original Trust Model

The web was designed with a simple assumption:

> **If a browser sends a cookie with a request, the cookie holder is the legitimate user.**

This made sense in 1994 when:
- Web pages were static documents
- Users browsed one site at a time
- Third-party content embedding didn't exist
- Cross-site navigation was simple hyperlinking

### How The Web Changed
The web evolved into an **adversarial content platform**:
- Pages embed third-party images, scripts, iframes, and widgets
- Advertisements load from foreign origins
- Social sharing buttons make cross-origin requests
- One browser tab can contain content from dozens of origins

The trust model never caught up. For decades, cookies were still attached automatically to **every matching request** regardless of which page triggered it.

### The Design Consequence
```
Original assumption:  request → browser → server
                      [user initiated] [trusted]

Reality:              evil.com page → browser → bank.com server
                      [attacker planted] [still trusted by server]
```

---

## 3. Ambient Authority — The Core Problem

**Ambient authority** means credentials are automatically included in requests without any explicit action from the user or application code.

### Contrast: Explicit vs Ambient Authority

| Model | How Credentials Are Sent | CSRF Risk |
|-------|--------------------------|-----------|
| **Ambient** (cookies) | Browser attaches automatically based on destination domain | HIGH — any page can trigger credentialed requests |
| **Explicit** (Authorization header) | Application code must actively include the token | LOW — cross-origin pages cannot read/attach headers |
| **Explicit** (localStorage token in header) | JS must read token and set header on every request | LOW — cross-origin JS cannot access another origin's localStorage |

### Why Ambient Authority Enables CSRF
```
Ambient authority means:
  1. User logs into bank.com → session cookie stored in browser
  2. User visits evil.com → browser holds the bank.com cookie
  3. evil.com causes a request to bank.com → browser AUTOMATICALLY attaches the cookie
  4. Server sees a valid session → trusts the request
  5. Action executes — user never intended it
```

The browser is not malfunctioning. It is operating exactly as designed. That is what makes this hard.

---

## 4. How Browsers Handle Cookies

Understanding cookie attachment is critical — this is the mechanism CSRF exploits.

### Cookie Attachment Decision (Browser Side)

When a browser is about to send an HTTP request, it asks:
> "Do I have any cookies whose domain and path match this request's destination?"

If yes → cookies are attached. **The origin of the page that triggered the request is irrelevant to this decision.**

```
Browser cookie jar:
  ┌─────────────────────────────────┐
  │ bank.com | session=abc123       │  ← stored when user logged in
  │ evil.com | tracker=xyz          │
  └─────────────────────────────────┘

Request triggered by evil.com to bank.com/transfer:
  Destination: bank.com ✓ → attach bank.com cookies
  Origin of trigger: evil.com → IRRELEVANT to cookie attachment
```

### Key Cookie Attributes (Preview — Full Coverage in Module 2)

| Attribute | What It Does | CSRF Relevance |
|-----------|-------------|----------------|
| `HttpOnly` | Blocks JS from reading the cookie | Does NOT prevent CSRF — cookie still auto-sent |
| `Secure` | Only sent over HTTPS | Does NOT prevent CSRF — only affects protocol |
| `SameSite` | Controls cross-site sending behavior | PRIMARY modern CSRF defense |
| `Domain` | Which domains receive the cookie | Relevant to subdomain CSRF attacks |
| `Path` | Which paths receive the cookie | Minor relevance |

> **Critical Insight:** `HttpOnly` is widely misunderstood. It prevents XSS from *reading* the cookie. It does absolutely nothing to prevent CSRF because CSRF doesn't need to read the cookie — the browser sends it automatically.

---

## 5. Authentication vs Request Legitimacy

This is the most important conceptual distinction in CSRF.

### Two Separate Questions

| Question | What It Establishes | How Cookies Answer It |
|----------|--------------------|-----------------------|
| **Is this user authenticated?** | Identity — who they are | ✅ Yes — valid session cookie proves authentication |
| **Did this user intend this request?** | Legitimacy — whether they meant it | ❌ No — cookie presence says nothing about intent |

### The Server's False Assumption
Servers were historically designed to check authentication (question 1) and then proceed. They assumed that if a request is authenticated, it must be legitimate. CSRF breaks that assumption.

```
Server logic (vulnerable):
  if (session_cookie.valid) {
      execute_action()   ← no intent check
  }

Server logic (CSRF-resistant):
  if (session_cookie.valid && request_has_proof_of_intent()) {
      execute_action()   ← intent verified separately
  }
```

### Analogy
Think of authentication as proving you have a house key. Request legitimacy is proving you actually walked to the door yourself and put the key in — not that someone else grabbed your hand while you were distracted and opened the door for them.

---

## 6. The Three Required Conditions for CSRF

Every CSRF vulnerability requires all three. Remove any one and the attack fails.

```
┌─────────────────────────────────────────────────────┐
│           THREE CONDITIONS FOR CSRF                 │
├─────────────────────────────────────────────────────┤
│                                                     │
│  1. ACTIVE SESSION                                  │
│     The victim has a valid authenticated session    │
│     (a credentialed cookie exists in the browser)  │
│                                                     │
│  2. AUTOMATIC CREDENTIAL ATTACHMENT                 │
│     The browser will send the credential without   │
│     any user action (ambient authority)             │
│                                                     │
│  3. NO INTENT VERIFICATION                          │
│     The server cannot distinguish an intentional   │
│     request from a forged one                       │
│                                                     │
└─────────────────────────────────────────────────────┘
```

### Mapping Defenses to Conditions

| Condition | Defense That Eliminates It |
|-----------|---------------------------|
| Active session | Short session timeouts, re-authentication for sensitive actions |
| Automatic credential attachment | `SameSite=Strict` cookies (browser stops attaching cross-site) |
| No intent verification | CSRF tokens, Origin/Referer validation, custom headers |

---

## 7. How HTML Triggers Requests Without JavaScript

CSRF does not require JavaScript. HTML alone can cause browsers to make authenticated requests automatically on page load.

### GET Requests — Trivially Triggered

```html
<!-- Image tag — fires immediately on page parse, no user interaction -->
<img src="https://bank.com/transfer?to=attacker&amount=5000" style="display:none">

<!-- Script src — fires on page load -->
<script src="https://bank.com/logout"></script>

<!-- Link prefetch — browser may pre-fetch -->
<link rel="prefetch" href="https://bank.com/delete-account">

<!-- iframe — loads target URL automatically -->
<iframe src="https://bank.com/transfer?to=attacker&amount=5000" style="display:none"></iframe>
```

> ⚠️ GET-based CSRF is only exploitable when the server performs state-changing actions on GET requests — which violates HTTP semantics but is common in poorly designed applications.

### POST Requests — Auto-Submit Form

```html
<!-- Entire attack delivered as HTML, no JavaScript needed for submission trigger -->
<html>
  <body onload="document.forms[0].submit()">
    <form action="https://bank.com/transfer" method="POST" style="display:none">
      <input type="hidden" name="to"     value="attacker_account">
      <input type="hidden" name="amount" value="10000">
      <input type="hidden" name="currency" value="USD">
    </form>
  </body>
</html>
```

When the victim loads this page:
1. Browser parses HTML
2. `body onload` fires
3. Form is submitted to `bank.com`
4. Browser attaches `bank.com` session cookie
5. Server receives a fully authenticated POST request

### With JavaScript (More Flexible)

```javascript
// JavaScript version — same effect, more control
window.onload = function() {
  var form = document.createElement('form');
  form.action = 'https://bank.com/transfer';
  form.method = 'POST';

  var fields = { to: 'attacker', amount: '10000' };
  for (var name in fields) {
    var input = document.createElement('input');
    input.type = 'hidden';
    input.name = name;
    input.value = fields[name];
    form.appendChild(input);
  }

  document.body.appendChild(form);
  form.submit();
};
```

### What the Browser Cannot Do (Attacker Limitation)
```
The attacker CAN:
  ✓ Cause the browser to SEND a request to any origin
  ✓ Include cookies automatically (ambient authority)
  ✓ Set form field values
  ✓ Choose HTTP method (GET, POST via form)

The attacker CANNOT:
  ✗ Read the response (blocked by Same-Origin Policy)
  ✗ Set arbitrary request headers on cross-origin requests
  ✗ Read the victim's cookies directly
  ✗ Access the victim's session token value
```

> This limitation is important: CSRF is a **blind attack**. The attacker cannot read the server's response. They can only cause side effects (state changes). This limits CSRF to write operations, not data exfiltration.

---

## 8. What the Server Sees vs What Actually Happened

This table shows the server's view of a CSRF request versus reality.

| Property | What Server Sees | What Actually Happened |
|----------|-----------------|----------------------|
| Session cookie | Valid, belongs to victim | Browser attached it automatically |
| User identity | Correctly identified victim | Correct, but irrelevant — intent is what matters |
| Request method | POST (or GET) | Triggered by attacker's HTML |
| Request parameters | Exactly as crafted | Set by attacker, not user |
| IP address | Victim's IP | Correct — victim's browser made the request |
| TLS/HTTPS | Valid | Encryption doesn't help — request is "legitimate" at network level |
| Origin header | May or may not be present | Present in modern browsers on cross-origin requests |
| Referer header | May point to evil.com | Often stripped or suppressed |

### The Server's Impossible Position (Without Defenses)
Without explicit intent verification, the server literally cannot tell the difference between:
- A user clicking "Transfer $10,000" on `bank.com`
- An attacker's page causing that same request to be sent

Both produce identical HTTP requests at the server's network interface.

---

## 9. The Analytical Framework — Four Questions

Use these for every CSRF scenario analysis. Apply them before looking for vulnerabilities.

```
┌──────────────────────────────────────────────────────────────┐
│              CSRF ANALYTICAL FRAMEWORK                       │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  Q1: Who does the server think made this request?           │
│      → Identity: which user account                         │
│                                                              │
│  Q2: How does the server know that?                         │
│      → Evidence: session cookie, JWT in cookie, etc.        │
│                                                              │
│  Q3: Could someone else cause that same evidence            │
│      to be present?                                         │
│      → Forgability: can the attacker make the browser        │
│        produce an identical-looking request?                 │
│                                                              │
│  Q4: What would the server need to check that an            │
│      attacker cannot forge?                                  │
│      → Defense: what proof of intent is unforgeable?        │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

**CSRF exists in the gap between Q2 and Q3.**

If the answer to Q3 is "yes" and the server only checks Q1/Q2 evidence, CSRF is possible.

---

## 10. Who Is At Fault — Design vs Implementation

### The Distributed Responsibility Model

```
┌─────────────────┬────────────────────────────────────────────┐
│ Party           │ Responsibility                             │
├─────────────────┼────────────────────────────────────────────┤
│ Web Design      │ Created ambient authority via cookie model │
│                 │ Did not anticipate adversarial cross-site  │
│                 │ content at scale                           │
├─────────────────┼────────────────────────────────────────────┤
│ Browser Vendors │ Historically sent cookies unconditionally  │
│                 │ Now fixing with SameSite default changes   │
├─────────────────┼────────────────────────────────────────────┤
│ Application     │ Failed to add compensating controls        │
│ Developers      │ Conflated authentication with legitimacy   │
│                 │ Did not implement intent verification       │
├─────────────────┼────────────────────────────────────────────┤
│ Framework       │ Historically did not enforce CSRF tokens   │
│ Authors         │ Modern frameworks now include by default   │
└─────────────────┴────────────────────────────────────────────┘
```

### The Historical Shift
- **Pre-2016:** Full burden on individual applications; most got it wrong
- **2016:** `SameSite` cookie attribute introduced (Chrome)
- **2020:** Chrome changed `SameSite` default from `None` to `Lax`
- **Present:** Browsers partially mitigate CSRF; applications still must implement defenses for full protection

---

## 11. Same-Origin Policy and Why It Doesn't Stop CSRF

### What Same-Origin Policy (SOP) Does
SOP prevents a page from one origin from **reading** content from another origin.

```
Origin = protocol + domain + port
https://bank.com:443  ≠  https://evil.com:443

evil.com JavaScript CANNOT:
  ✗ Read bank.com's cookies
  ✗ Read bank.com's localStorage
  ✗ Read bank.com's HTTP responses
  ✗ Access bank.com's DOM
```

### What SOP Does NOT Do
SOP does **not** prevent a page from **sending** requests to another origin.

```
evil.com JavaScript CAN:
  ✓ Submit a form to bank.com
  ✓ Load an image from bank.com
  ✓ Create an iframe pointing to bank.com
  ✓ Make a fetch() to bank.com (with some CORS restrictions)
```

### Why SOP Was Designed This Way
The web is built on cross-origin resource *loading*. Every page loads images, fonts, scripts from CDNs. If SOP blocked all cross-origin requests, the web would break. SOP only blocks *reading* responses, not *sending* requests.

### The SOP/CSRF Relationship
```
SOP prevents:   attacker reading the response
CSRF exploits:  attacker causing the request to be sent

SOP and CSRF operate on different parts of the request lifecycle.
SOP does not address CSRF at all.
```

---

## 12. CSRF vs Related Attacks — Conceptual Boundaries

| Attack | What It Abuses | Attacker Gets | Requires |
|--------|---------------|---------------|----------|
| **CSRF** | Ambient authority (cookies) | Action performed as victim | Victim to load attacker page |
| **XSS** | Reflected/stored script execution | Code execution in victim's browser | Injection point in target app |
| **Clickjacking** | UI deception | Victim clicks attacker-chosen target | Iframe embedding allowed |
| **Session Hijacking** | Cookie theft | Actual session token | XSS or network interception |
| **SSRF** | Server trust in user-supplied URLs | Server makes requests to internal systems | User-controllable URL input |

### CSRF + XSS Interaction (Preview)
XSS can defeat CSRF defenses by:
1. Reading the CSRF token from the page (XSS can read same-origin content)
2. Including it in a forged request
3. Effectively bypassing the token defense

> If your app has XSS, your CSRF tokens may be worthless. This is covered in Module 7.

---

## 13. Key Terminology Reference

| Term | Definition |
|------|------------|
| **CSRF** | Cross-Site Request Forgery — forged authenticated request from external origin |
| **Ambient Authority** | Credentials automatically included in requests without explicit attachment |
| **Session Cookie** | Cookie storing authentication state, sent automatically by browser |
| **Same-Origin Policy (SOP)** | Browser rule preventing cross-origin response reading; does not prevent sending |
| **Origin** | Protocol + domain + port (e.g., `https://bank.com:443`) |
| **Cross-Site** | A request where the page origin differs from the request destination |
| **Cross-Origin** | More specific: protocol, domain, or port differs between trigger and destination |
| **Intent Verification** | Server-side mechanism to confirm the user consciously initiated the request |
| **Forgeable** | Evidence an attacker can cause to appear without user cooperation |
| **Unforgeable** | Evidence an attacker cannot produce (e.g., a secret token only the server and page share) |
| **State-Changing Action** | Server operation that modifies data (transfer, delete, change password) — CSRF target |
| **Idempotent** | Operation safe to repeat (most GETs) — lower CSRF risk if truly read-only |
| **CSRF Token** | Secret value included in requests to prove the request originated from the legitimate page |
| **SameSite** | Cookie attribute controlling whether cookie is sent on cross-site requests |
| **Double-Submit Cookie** | CSRF defense using matching values in cookie and request parameter |

---

## 14. Common Misconceptions

### ❌ "HTTPS prevents CSRF"
**Wrong.** TLS encrypts the transport. The request itself is still forged — it's just encrypted forgery. The server decrypts a perfectly valid but unintended request.

### ❌ "POST requests are safe from CSRF"
**Wrong.** HTML forms support POST. An auto-submitting form on `evil.com` sends a fully credentialed POST request. The method provides no CSRF protection.

### ❌ "HttpOnly cookies prevent CSRF"
**Wrong.** `HttpOnly` prevents JavaScript from reading the cookie. CSRF does not need to read the cookie — the browser sends it automatically. `HttpOnly` is irrelevant to CSRF.

### ❌ "CSRF steals your session"
**Wrong.** The attacker never obtains your session token. They cause your browser to use it on their behalf. The session is borrowed, not stolen.

### ❌ "Same-Origin Policy prevents CSRF"
**Wrong.** SOP prevents reading responses. CSRF abuses the sending of requests. They address different parts of the HTTP lifecycle.

### ❌ "If there's no JavaScript on the attacker's page, CSRF can't happen"
**Wrong.** HTML tags (`<img>`, `<form>`, `<iframe>`) trigger requests without any JavaScript. The `body onload` auto-submit form requires no JavaScript for the submission itself.

### ❌ "CSRF only works on GET requests"
**Wrong.** GET-based CSRF is trivially easy, but POST-based CSRF works via auto-submitting forms.

### ❌ "Checking the Referer header is enough"
**Partially wrong.** Referer can be suppressed (HTTPS→HTTP, privacy tools, `referrerpolicy` meta tag). Relying solely on Referer creates exploitable gaps. More in Module 6.

---

## 15. Mental Models Summary

### Mental Model 1 — The Puppet Model
```
Attacker = Puppeteer
User's Browser = Puppet
User's Session Cookie = The strings
Bank Server = Audience that can't see the strings

The puppeteer makes the puppet perform actions.
The audience sees only the puppet acting.
```

### Mental Model 2 — The Trust Triangle
```
         TRUST
   Browser ←──────── Server
      │                 ↑
      │ forges          │ trusts
      │                 │
   evil.com ────────────┘
   (attacker)

The server trusts the browser.
The attacker exploits that trust by controlling the browser's actions.
```

### Mental Model 3 — The Request Lifecycle
```
1. User logs into bank.com
   → Browser stores: { "bank.com": "session=abc123" }

2. User visits evil.com
   → Page contains: <img src="https://bank.com/transfer?to=attacker&amount=5000">

3. Browser parses <img> tag
   → Destination: bank.com
   → Cookie jar check: bank.com cookie found
   → Browser sends: GET /transfer?to=attacker&amount=5000
                    Cookie: session=abc123

4. bank.com server receives request
   → Checks: session=abc123 → valid, belongs to victim
   → Executes: transfer $5000 to attacker

5. Attacker wins. Victim never knew.
```

### Mental Model 4 — The Gap Model
```
What the server checks:    [ Authentication ] ✓
What CSRF abuses:          [ ←── this gap ──→ ] 
What the server ignores:   [ Intent/Origin   ] ✗
```

---

## 16. Bug Bounty Relevance

### What to Look For in Reconnaissance
- State-changing endpoints that use cookies for authentication
- Applications that rely entirely on session cookies (not Authorization headers)
- Older applications that may predate SameSite defaults
- Mobile application backends that disable CSRF protections

### CSRF Severity Factors (for Report Writing)
| Impact | Severity |
|--------|----------|
| Account takeover (change email/password) | Critical |
| Financial transactions (transfer, purchase) | Critical/High |
| Privilege escalation (add admin role) | High |
| Data deletion (delete account, files) | High |
| Social actions (post, follow, message) | Medium |
| Low-impact settings changes | Low |

### Triage Signals — Is CSRF Even Possible Here?
Before testing, check:
1. Does the endpoint perform a state-changing action? (If read-only, no CSRF impact)
2. Does the application use session cookies? (If JWT in Authorization header, no CSRF)
3. Is `SameSite=Strict` or `SameSite=Lax` set on the session cookie? (Partial mitigation)
4. Is there a CSRF token in requests? (May be bypassable — check Module 7)
5. Does the server validate the `Origin` or `Referer` header? (May be bypassable)

### Deliverable for Bug Reports
```
Title:      CSRF in [endpoint] allows [action] as authenticated user
Severity:   [based on impact table above]
Component:  [specific endpoint, e.g., POST /api/user/change-email]

Reproduction:
1. Victim logs into [target]
2. Victim visits attacker-controlled page containing [PoC HTML]
3. Request is sent to [endpoint] with victim's session
4. [Action] is performed without victim's knowledge

Impact:
An attacker who can cause a victim to visit a malicious page
can [specific impact]. No victim interaction beyond page visit required.

PoC:
[minimal HTML payload — form or img tag]

Remediation:
Implement synchronizer CSRF tokens / SameSite=Strict cookie attribute
```

---

## Module 1 Summary — What You Must Know Cold

```
✓ CSRF borrows credentials, it does not steal them
✓ The browser attaches cookies based on DESTINATION, not SOURCE of request
✓ HttpOnly does NOT prevent CSRF
✓ HTTPS does NOT prevent CSRF
✓ POST does NOT prevent CSRF
✓ Same-Origin Policy does NOT prevent CSRF (it addresses reading, not sending)
✓ CSRF requires: active session + ambient authority + no intent verification
✓ HTML alone (no JS) can trigger CSRF via <img>, <form onload>, <iframe>
✓ CSRF is a blind attack — attacker cannot read the response
✓ Authentication ≠ Legitimacy — servers must verify both
✓ The four questions: who / how server knows / can attacker replicate / what's unforgeable
```

---

*Next: Module 02 — Cookies, Sessions & Authentication State*  
*Deep dive into cookie attributes, session lifecycle, and how SameSite changes the game*