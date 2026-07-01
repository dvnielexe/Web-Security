# CSRF Module 11 — Secure Design Reviews
> **Curriculum:** CSRF Mastery for Ethical Hacking & Bug Bounty  
> **Module:** 11 of 12  
> **Topic:** Trust Boundary Mapping, Architecture Review, Secure Design Principles, Defense-in-Depth Composition  
> **Level:** Advanced — security architect perspective on CSRF across multi-service architectures

---

## Table of Contents
- [CSRF Module 11 — Secure Design Reviews](#csrf-module-11--secure-design-reviews)
  - [Table of Contents](#table-of-contents)
  - [1. The Security Architect's Mindset](#1-the-security-architects-mindset)
  - [2. Trust Boundary Mapping — The First Step](#2-trust-boundary-mapping--the-first-step)
    - [Trust Map Template](#trust-map-template)
    - [Example: Fintech Architecture Trust Map](#example-fintech-architecture-trust-map)
  - [3. Same-Site vs Same-Origin in Multi-Service Architecture](#3-same-site-vs-same-origin-in-multi-service-architecture)
  - [4. Evaluating CSRF Defense Stacks](#4-evaluating-csrf-defense-stacks)
    - [How to Evaluate Any Defense Combination](#how-to-evaluate-any-defense-combination)
    - [Example: API Defense Stack Analysis](#example-api-defense-stack-analysis)
  - [5. The CORS Allowlist as a Trust Extension](#5-the-cors-allowlist-as-a-trust-extension)
    - [The legacy.fintech.com Problem](#the-legacyfintechcom-problem)
  - [6. WAF as a CSRF Defense — Why It Fails](#6-waf-as-a-csrf-defense--why-it-fails)
    - [The Fundamental Problem](#the-fundamental-problem)
    - [Conditions for WAF to Provide Partial Value](#conditions-for-waf-to-provide-partial-value)
  - [7. The Shared Domain Risk — WordPress and Third-Party Services](#7-the-shared-domain-risk--wordpress-and-third-party-services)
    - [Why Shared Registered Domain Creates CSRF Risk](#why-shared-registered-domain-creates-csrf-risk)
    - [The Blind CSRF via Same-Site Attack](#the-blind-csrf-via-same-site-attack)
    - [Mitigations](#mitigations)
  - [8. SameSite=Strict — What It Actually Protects](#8-samesitestrict--what-it-actually-protects)
    - [The Common Misconception](#the-common-misconception)
    - [What Genuinely Protects the Admin Panel](#what-genuinely-protects-the-admin-panel)
  - [9. Custom Header Defense — Scope and Limits in Architecture](#9-custom-header-defense--scope-and-limits-in-architecture)
    - [X-Requested-With and Similar Headers](#x-requested-with-and-similar-headers)
  - [10. Admin Panel Security — Complete Design](#10-admin-panel-security--complete-design)
    - [Threat Model for Admin Panel](#threat-model-for-admin-panel)
    - [Complete Admin Panel Secure Design](#complete-admin-panel-secure-design)
  - [11. CORS Allowlist — Entry Approval Framework](#11-cors-allowlist--entry-approval-framework)
  - [12. Moving to a Separate Registered Domain](#12-moving-to-a-separate-registered-domain)
    - [What Changes When Admin Moves to admin.fintech-internal.com](#what-changes-when-admin-moves-to-adminfintech-internalcom)
  - [13. Complete Defense-in-Depth Stack for API + SPA + Mobile](#13-complete-defense-in-depth-stack-for-api--spa--mobile)
  - [14. Secure Design Principles for CSRF](#14-secure-design-principles-for-csrf)
    - [Principle 1 — The Weakest Link](#principle-1--the-weakest-link)
    - [Principle 2 — Defense Independence](#principle-2--defense-independence)
    - [Principle 3 — Explicit Over Implicit](#principle-3--explicit-over-implicit)
    - [Principle 4 — Blast Radius Minimization](#principle-4--blast-radius-minimization)
    - [Principle 5 — Secure by Default](#principle-5--secure-by-default)
  - [15. Architecture Review Checklist](#15-architecture-review-checklist)
    - [Phase 1 — Trust Boundary Mapping](#phase-1--trust-boundary-mapping)
    - [Phase 2 — Defense Evaluation](#phase-2--defense-evaluation)
    - [Phase 3 — Scenario Testing](#phase-3--scenario-testing)
    - [Phase 4 — Recommendations Prioritization](#phase-4--recommendations-prioritization)
  - [16. Key Terminology Reference](#16-key-terminology-reference)
  - [17. Common Misconceptions](#17-common-misconceptions)
    - [❌ "SameSite=Strict means the admin panel is safe from any same-site subdomains"](#-samesitestrict-means-the-admin-panel-is-safe-from-any-same-site-subdomains)
    - [❌ "CORS allowlist prevents CSRF from same-site subdomains"](#-cors-allowlist-prevents-csrf-from-same-site-subdomains)
    - [❌ "WAF protection is equivalent to application-level CSRF controls"](#-waf-protection-is-equivalent-to-application-level-csrf-controls)
    - [❌ "Moving a service to a subdomain isolates it from CSRF attacks on other subdomains"](#-moving-a-service-to-a-subdomain-isolates-it-from-csrf-attacks-on-other-subdomains)
    - [❌ "X-Requested-With header requirement prevents CSRF from same-site attackers"](#-x-requested-with-header-requirement-prevents-csrf-from-same-site-attackers)
    - [❌ "CORS allowlist only needs to include origins that make API requests"](#-cors-allowlist-only-needs-to-include-origins-that-make-api-requests)
  - [18. Bug Bounty Reference — Architectural Findings](#18-bug-bounty-reference--architectural-findings)
    - [High-Value Architectural CSRF Findings](#high-value-architectural-csrf-findings)
    - [Report Template — Architectural CSRF Finding](#report-template--architectural-csrf-finding)
  - [19. Module 11 Summary — What You Must Know Cold](#19-module-11-summary--what-you-must-know-cold)

---

## 1. The Security Architect's Mindset

```
VULNERABILITY FINDER asks:
  "Is this endpoint exploitable?"
  → Find endpoint → test for token → missing → report

SECURITY ARCHITECT asks:
  "What is the trust model?"
  "Where are the boundaries?"
  "What assumptions are being made?"
  "Which assumptions can be violated?"
  "What is the blast radius of each violation?"
  "Which controls are genuinely independent?"
  "What is the minimum viable attack chain?"

For CSRF specifically, the architect's six questions:

  1. What credentials travel automatically?
     (Which cookies, which domains, which SameSite values)

  2. Which origins are trusted, and why?
     (CORS allowlist entries, subdomain relationships)

  3. What happens if any trusted origin is compromised?
     (XSS, RCE, subdomain takeover on trusted origin)

  4. What is the blast radius of each trust relationship?
     (Can trusted origin reach admin panel? financial API? all users?)

  5. Which controls share failure modes?
     (If XSS defeats CORS and SameSite simultaneously: not independent)

  6. What is the minimum viable attack chain?
     (Fewest steps from external attacker to worst-case impact)
```

---

## 2. Trust Boundary Mapping — The First Step

Before evaluating any control, map every trust relationship in the architecture.

### Trust Map Template

```
For each origin in the system, document:
  □ What can it read? (CORS allowlist membership)
  □ What cookies are sent to it? (SameSite + registered domain)
  □ What user content does it accept? (XSS surface)
  □ What authentication model does it use?
  □ What is its security posture relative to other origins?

For each pair of origins, document:
  □ Same-origin? (identical protocol + host + port)
  □ Same-site? (same eTLD+1 — e.g., both example.com)
  □ Cross-site? (different registered domains)
  □ In each other's CORS allowlist?
```

### Example: Fintech Architecture Trust Map

```
REGISTERED DOMAIN: fintech.com
All subdomains share same-site relationship with each other.

┌──────────────────────┬────────────────────────────────────────────────┐
│ Origin               │ Trust Relationships                            │
├──────────────────────┼────────────────────────────────────────────────┤
│ app.fintech.com      │ In API CORS allowlist                          │
│ (React SPA)          │ Same-site with ALL fintech.com subdomains      │
│                      │ Session cookie auto-sent from here to API      │
├──────────────────────┼────────────────────────────────────────────────┤
│ api.fintech.com      │ Sets session cookie (SameSite=Lax)             │
│ (DRF API)            │ CORS allowlist: app + legacy                   │
│                      │ Receives same-site requests from ALL subdomains│
├──────────────────────┼────────────────────────────────────────────────┤
│ admin.fintech.com    │ Separate admin_session (SameSite=Strict)       │
│ (Django admin)       │ SAME-SITE with marketing, legacy, app          │
│                      │ SameSite=Strict does NOT isolate from subdomains│
├──────────────────────┼────────────────────────────────────────────────┤
│ legacy.fintech.com   │ IN API CORS allowlist (HIGH RISK)              │
│ (PHP legacy)         │ Can make credentialed API requests + read resp  │
│                      │ Same-site → session cookie sent to API          │
│                      │ Security posture: weaker than API              │
├──────────────────────┼────────────────────────────────────────────────┤
│ marketing.fintech.com│ NOT in API CORS allowlist                      │
│ (WordPress)          │ Same-site → session cookie STILL sent to API   │
│                      │ User-submitted content → XSS surface           │
│                      │ Blind CSRF via same-site possible              │
└──────────────────────┴────────────────────────────────────────────────┘

CRITICAL INSIGHT:
  CORS controls cross-origin RESPONSE READING
  CORS does NOT prevent cross-origin REQUEST SENDING from same-site origins
  SameSite controls cookie attachment — applies to ALL same-site subdomains
  Every fintech.com subdomain can send credentialed API requests
  CORS only controls whether that origin can READ the API response
```

---

## 3. Same-Site vs Same-Origin in Multi-Service Architecture

This distinction determines which defense layer applies and what the attack surface is.

```
SAME-ORIGIN: protocol + host + port all identical
  https://api.fintech.com  ↔  https://api.fintech.com  = same-origin
  https://api.fintech.com  ↔  https://app.fintech.com  = cross-origin

SAME-SITE: eTLD+1 matches
  https://api.fintech.com  ↔  https://app.fintech.com  = same-site
  https://api.fintech.com  ↔  https://legacy.fintech.com = same-site
  https://api.fintech.com  ↔  https://evil.com          = cross-site

SECURITY IMPLICATIONS:

SameSite cookie attribute:
  Controls sending based on SITE relationship
  Does NOT distinguish between subdomains of the same site
  SameSite=Strict: blocks cross-site, allows same-site (all subdomains)
  SameSite=Lax:    blocks cross-site POST, allows same-site all methods

CORS:
  Controls based on ORIGIN relationship
  Applies between different subdomains (cross-origin, same-site)
  Does NOT apply within same origin
  CORS allowlist = who can read your responses cross-origin

WHAT DEFENDS AGAINST WHAT:

                    evil.com     legacy.fintech.com   app.fintech.com
                    (cross-site) (cross-origin,        (cross-origin,
                                 same-site)            same-site)
SameSite=Lax       ✓ Blocks     ✗ Does not block      ✗ Does not block
CORS allowlist     ✓ Blocks     ✓ Blocks (if not       ✓ Allows (if in
                   reads        in allowlist)          allowlist)
CSRF Token         ✓ Blocks     ✓ Blocks (if no XSS)  ✓ Blocks (if no XSS)
Re-authentication  ✓ Blocks     ✓ Blocks               ✓ Blocks

Only CSRF tokens and re-auth protect against same-site subdomain attacks.
SameSite is useless against subdomains of the same registered domain.
```

---

## 4. Evaluating CSRF Defense Stacks

### How to Evaluate Any Defense Combination

```
For each defense in the stack, ask:
  1. What attack vector does this block?
  2. What is its trust assumption?
  3. What breaks that assumption?
  4. Does breaking it also break other defenses? (shared failure mode)

For the stack as a whole:
  5. What attacks does NO single defense block?
  6. What is the minimum viable bypass?
  7. Do any two defenses have genuinely different failure modes?
```

### Example: API Defense Stack Analysis

```
Stack: SameSite=Lax + CORS allowlist + Content-Type: application/json

DEFENSE 1: SameSite=Lax
  Blocks: Cross-site POST from evil.com
  Assumption: Attacker cannot trigger same-site requests
  Broken by: XSS on any fintech.com subdomain
             Subdomain takeover on any fintech.com subdomain

DEFENSE 2: CORS Allowlist (app + legacy)
  Blocks: Response reading from unlisted origins
  Assumption: Listed origins are trustworthy
  Broken by: XSS or RCE on legacy.fintech.com
             Both defenses 1 and 2 broken simultaneously by this

DEFENSE 3: Content-Type: application/json
  Blocks: HTML form CSRF (forms can't produce JSON)
  Assumption: Attacker cannot produce application/json from browser
  Broken by: text/plain with JSON body (bypasses preflight + CT check)
             Same-site XSS with fetch() (can set Content-Type freely)

SHARED FAILURE MODE:
  XSS on legacy.fintech.com breaks ALL THREE simultaneously:
    SameSite: legacy is same-site → cookie sent
    CORS: legacy is in allowlist → response readable
    Content-Type: JS fetch can set application/json freely

CONCLUSION:
  This stack provides zero genuine independence
  A single compromise (legacy XSS) defeats the entire stack
  Missing control: explicit CSRF token (different failure mode)
```

---

## 5. The CORS Allowlist as a Trust Extension

Every CORS allowlist entry extends your security boundary to include that origin.

```
CORS Allowlist Principle:
  "Adding origin X to your CORS allowlist means:
   IF origin X is compromised,
   the attacker has full credentialed access to your API
   (both sending requests and reading responses)"

Allowlist entry approval questions:
  □ Does this origin actually need to READ API responses?
     (If only writing: same-site request sends cookie without CORS)
     (CORS allowlist only needed for response reading)
  □ What is the security posture of this origin?
  □ Does it accept user-submitted content? (XSS surface)
  □ Who controls it? (internal vs third-party)
  □ Can it be taken over? (subdomain takeover risk)
  □ What is the blast radius if it is compromised?

The weakest origin in your CORS allowlist
sets the upper bound on your API security.
```

### The legacy.fintech.com Problem

```
legacy.fintech.com is in the CORS allowlist.

This means:
  If legacy has XSS → attacker can make credentialed API calls + read responses
  If legacy has RCE → same
  If legacy has auth bypass → same

Legacy PHP characteristics (typical):
  Older codebase → more likely to have XSS vulnerabilities
  Less security-conscious development era
  Possibly fewer dependency updates
  Less likely to have CSP, modern security headers

Consequence:
  api.fintech.com's CSRF posture = legacy.fintech.com's security posture
  Two services with different security levels, but one trust boundary

Fix options:
  Option A: Remove from CORS allowlist
    → Legacy makes backend-to-backend API calls instead
    → No browser cookie involvement in legacy→API calls
    → XSS on legacy cannot forge browser-credentialed API requests

  Option B: Accept and compensate
    → Harden legacy to same standard as API
    → Add CSRF tokens to API (independent of CORS)
    → Monitor for unusual cross-origin patterns
```

---

## 6. WAF as a CSRF Defense — Why It Fails

### The Fundamental Problem

```
WAF operates at: network/HTTP layer (signatures, rules, patterns)
CSRF operates via: legitimate browser behavior (valid cookies, normal requests)

A CSRF attack is indistinguishable from a legitimate request at the WAF:

Legitimate request:
  POST /transfer HTTP/1.1
  Cookie: session=abc123
  Content-Type: application/json
  Origin: https://app.fintech.com
  Body: {"to":"bob","amount":100}

CSRF attack (from compromised legacy.fintech.com):
  POST /transfer HTTP/1.1
  Cookie: session=abc123         ← same valid cookie
  Content-Type: application/json ← same content type
  Origin: https://legacy.fintech.com ← allowlisted origin
  Body: {"to":"attacker","amount":10000}

WAF analysis:
  Valid session: ✓
  Valid Content-Type: ✓
  Allowed origin: ✓
  No SQL injection: ✓
  No XSS payload: ✓
  No attack signature: ✓
  → PASS (request is indistinguishable from legitimate)

Intent verification requires application-level knowledge.
WAF has no access to session state or user intent.
```

### Conditions for WAF to Provide Partial Value

```
WAF CAN partially help if configured to:
  1. Validate CSRF token presence AND value
     (requires WAF to understand application token format and session store)
  2. Validate Origin/Referer against strict allowlist
     (partially effective — misses absent headers, same-site requests)
  3. Rate limit request patterns
     (detection, not prevention)

Questions to ask before accepting WAF as CSRF defense:
  □ Which specific WAF rule covers CSRF?
  □ Does it validate token VALUE or just presence?
  □ Is the rule applied to ALL state-changing endpoints?
  □ Does it cover same-site requests (or only cross-site)?
  □ What happens if Origin header is absent?
  □ Who updates WAF rules when API endpoints change?
  □ Is there a bypass path (direct IP access, staging environment)?
  □ Does it cover the legacy service specifically?

VERDICT:
  "Protected by WAF" is not an acceptable CSRF defense claim
  without specific answers to all of the above.
  Legacy service needs application-level CSRF controls.
  WAF is defense-in-depth at best.
```

---

## 7. The Shared Domain Risk — WordPress and Third-Party Services

### Why Shared Registered Domain Creates CSRF Risk

```
marketing.fintech.com (WordPress):
  Same registered domain (fintech.com) as:
    api.fintech.com
    admin.fintech.com
    legacy.fintech.com

  Therefore: SAME-SITE with all of them

WordPress risk factors:
  User-submitted blog comments → stored XSS surface
  Plugin ecosystem → historically large XSS source
  Older/unpatched WordPress → known vulnerabilities
  Less security-hardened than custom applications

XSS on marketing.fintech.com gives attacker:
  Code execution in victim's browser on marketing.fintech.com context
  Ability to make same-site requests to api.fintech.com, admin.fintech.com
  Session cookies sent automatically (same-site, SameSite=Lax/Strict)
  For SameSite=Lax: both cookies sent on same-site requests
  For SameSite=Strict: admin_session ALSO sent (same-site, not cross-site)
```

### The Blind CSRF via Same-Site Attack

```
XSS on marketing.fintech.com:

fetch("https://api.fintech.com/transfer", {
  method: "POST",
  credentials: "include",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ to: "attacker", amount: 5000 })
});

Is marketing.fintech.com in CORS allowlist? NO
→ CORS preflight: rejected (marketing not in allowlist)
→ fetch() response: BLOCKED (can't read response)

BUT:
  The preflight only blocks the response from being read
  The actual POST request IS sent before CORS check
  Wait — actually for preflighted requests, browser sends OPTIONS first
  If OPTIONS rejected: actual POST not sent
  → This specific attack blocked at CORS preflight level

HOWEVER: for simple requests (no preflight):
  <form enctype="text/plain" action="https://api.fintech.com/transfer">
  This IS sent even without CORS allowlist
  Session cookie attached (same-site)
  If server parses text/plain as JSON: CSRF succeeds

AND: Same-site fetch() with simple content type:
  fetch() with application/x-www-form-urlencoded (simple request)
  No preflight required
  Cookie sent (same-site)
  If API accepts this content type: CSRF succeeds
  
KEY NUANCE:
  Preflighted requests (application/json) from non-allowlisted origins:
    OPTIONS sent, rejected, actual request NOT sent
  Simple requests from non-allowlisted origins:
    Sent directly, response blocked, but ACTION EXECUTES
  This is why CSRF tokens matter even with CORS
```

### Mitigations

```
IMMEDIATE:
  □ Content Security Policy on marketing.fintech.com
    → Limits what XSS can do even if injected
  □ Comment sanitization (WordPress wp_kses or equivalent)
  □ WordPress updates + plugin audit
  □ Disable unnecessary plugins (reduce attack surface)

ARCHITECTURAL:
  □ Move marketing to separate registered domain
    marketing-fintech.com instead of marketing.fintech.com
    → Now cross-site with api, admin, legacy
    → XSS on marketing cannot reach API/admin via same-site
    → SameSite=Lax/Strict now genuinely protects other services

  □ Add CSRF tokens to API (blocks simple request attacks)
    → Even if XSS gets request through, no valid token
```

---

## 8. SameSite=Strict — What It Actually Protects

### The Common Misconception

```
Developer belief:
  "SameSite=Strict on admin session means admin panel is safe from
   CSRF attacks originating anywhere outside the admin panel itself"

Reality:
  SameSite=Strict blocks: CROSS-SITE requests
  A cross-site request = request from a DIFFERENT registered domain

  marketing.fintech.com → admin.fintech.com:
    Are these cross-site? NO — both fintech.com
    Are they same-site? YES
    Does SameSite=Strict block the cookie? NO — same-site = allowed

SameSite=Strict protects against:
  ✓ evil.com attempting to trigger admin actions
  ✓ Any domain outside fintech.com
  ✓ Email links, Google searches, external redirects

SameSite=Strict does NOT protect against:
  ✗ XSS on marketing.fintech.com
  ✗ XSS on legacy.fintech.com
  ✗ XSS on app.fintech.com
  ✗ Any fintech.com subdomain
  ✗ Same-origin XSS on admin.fintech.com itself
```

### What Genuinely Protects the Admin Panel

```
Against external attackers (evil.com):
  SameSite=Strict ✓ (blocks cookie cross-site)
  CsrfViewMiddleware ✓ (validates token)
  Both together: strong protection

Against same-site attackers (fintech.com subdomains):
  SameSite=Strict ✗ (does not restrict same-site)
  CsrfViewMiddleware ✓ (if CSRF token not leakable via XSS)
  Re-authentication ✓✓ (cannot be bypassed even with same-site XSS)

Against same-origin XSS (admin.fintech.com itself):
  SameSite=Strict ✗
  CsrfViewMiddleware ✗ (XSS reads token from DOM)
  Re-authentication ✓✓ (XSS cannot supply admin password)
```

---

## 9. Custom Header Defense — Scope and Limits in Architecture

### X-Requested-With and Similar Headers

```
Mechanism:
  Custom headers (X-Requested-With: XMLHttpRequest, X-App-Client: spa-v2)
  Trigger CORS preflight on cross-origin requests
  HTML forms cannot set custom headers
  → Cross-origin form CSRF blocked

What it protects against:
  ✓ HTML form CSRF from evil.com
  ✓ Cross-origin fetch() from evil.com (CORS preflight check)

What it does NOT protect against:
  ✗ Same-site XSS (JavaScript can set any header freely)
    XSS on legacy.fintech.com:
      fetch("https://api.fintech.com/transfer", {
        headers: { "X-Requested-With": "XMLHttpRequest" }
      });
      → Header set, same-site, cookie sent → attack succeeds
  
  ✗ Same-origin attacks (no CORS restriction)
  
  ✗ CORS misconfiguration (if attacker origin is allowed)

VERDICT for legacy PHP service:
  X-Requested-With is a supplementary defense, not a primary fix
  Does not prove user intent (attacker can set it from same-site position)
  Legacy service needs actual CSRF token validation
  Custom header = raises bar for external attackers only
```

---

## 10. Admin Panel Security — Complete Design

### Threat Model for Admin Panel

```
Threats:
  1. External attacker (evil.com) → CSRF forging admin action
  2. Same-site XSS (fintech.com subdomains) → same-site CSRF
  3. Same-origin XSS (admin.fintech.com) → token extraction + CSRF
  4. Session theft → unauthorized admin access
  5. Phishing → admin credentials stolen

Controls by threat:

Threat 1 (External):
  SameSite=Strict ✓ blocks cross-site cookie
  CsrfViewMiddleware ✓ validates token
  → Well protected

Threat 2 (Same-site XSS):
  SameSite=Strict ✗ does not restrict same-site
  CsrfViewMiddleware ✓ if token not obtainable cross-origin
  CORS on admin: must not allow marketing/legacy subdomains
  Re-authentication ✓✓ cannot be bypassed

Threat 3 (Same-origin XSS):
  All cookie-level defenses ✗
  CsrfViewMiddleware ✗ XSS reads token from DOM
  Re-authentication ✓✓ only surviving control

Threat 4 (Session theft):
  HttpOnly ✓ prevents JS read
  Secure ✓ HTTPS only
  Short session timeout ✓

Threat 5 (Phishing):
  MFA ✓ second factor required
  Hardware keys ✓✓ phishing-resistant
```

### Complete Admin Panel Secure Design

```python
# settings.py
MIDDLEWARE = [
    'django.middleware.csrf.CsrfViewMiddleware',  # never comment out
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    # ...
]

SESSION_COOKIE_SAMESITE = 'Strict'
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_AGE = 3600  # 1 hour — short timeout for admin

# views.py — re-authentication for critical actions
from django.contrib.auth import authenticate
from django.views.decorators.csrf import csrf_protect
from django.contrib.auth.decorators import login_required, user_passes_test

@login_required
@user_passes_test(lambda u: u.is_superuser)
def delete_all_users(request):
    if request.method == 'POST':
        # CSRF token already validated by CsrfViewMiddleware
        
        # Re-authentication: admin must confirm with password
        password = request.POST.get('confirm_password', '')
        user = authenticate(
            username=request.user.username,
            password=password
        )
        if user is None:
            return HttpResponse('Authentication required', status=403)
        
        # Both CSRF token and password verified
        # Safe to proceed with irreversible action
        User.objects.exclude(pk=request.user.pk).delete()
        
        # Audit log entry
        AuditLog.objects.create(
            actor=request.user,
            action='DELETE_ALL_USERS',
            ip=request.META.get('REMOTE_ADDR')
        )
        return JsonResponse({'status': 'completed'})
```

---

## 11. CORS Allowlist — Entry Approval Framework

Before adding any origin to a CORS allowlist, answer all of these:

```
QUESTION 1: Does this origin actually need to READ responses?
  If it only needs to send requests (write operations):
    Same-site: session cookie already sent without CORS
    CORS allowlist not needed
  If it needs to read responses (API data):
    CORS allowlist entry justified
    But all other questions still apply

QUESTION 2: What is this origin's security posture?
  Does it accept user-submitted content? (XSS surface)
  Is it kept up to date? (patch cadence)
  Does it have CSP, XSS protections?
  Is it developed with security review?

QUESTION 3: Who controls this origin?
  Internal team → known security practices
  Third-party → unknown practices, may change ownership
  Shared infrastructure → multiple teams with different standards

QUESTION 4: Can this origin be taken over?
  Does it point to an external resource? (subdomain takeover risk)
  Is it on a platform with takeover history? (Heroku, S3, Netlify)

QUESTION 5: What is the blast radius if this origin is compromised?
  Can attacker read all user data?
  Can attacker execute financial transactions?
  Can attacker escalate to admin?

QUESTION 6: Is there a safer alternative?
  Backend-to-backend API calls (no browser cookie involvement)
  Separate authentication for that origin
  Scoped API access (read-only token for that origin)

DECISION MATRIX:
  All answers acceptable → Add to allowlist with documented justification
  Any answer unacceptable → Explore alternatives first
  Unknown answers → Treat as unacceptable until answered
```

---

## 12. Moving to a Separate Registered Domain

### What Changes When Admin Moves to admin.fintech-internal.com

```
BEFORE (admin.fintech.com):
  Same-site with marketing.fintech.com
  Same-site with legacy.fintech.com
  XSS on marketing/legacy → same-site request to admin → cookie sent
  SameSite=Strict: does not protect against same-site subdomains

AFTER (admin.fintech-internal.com):
  Different registered domain from fintech.com
  Cross-site with marketing.fintech.com ✓
  Cross-site with legacy.fintech.com ✓
  Cross-site with app.fintech.com ✓

  XSS on marketing.fintech.com → admin.fintech-internal.com:
    Cross-site request → SameSite=Strict DOES block the cookie
    → Admin session cookie NOT sent
    → Attack fails at cookie level

GENUINE PROTECTION GAINED:
  SameSite=Strict now actually isolates admin from fintech.com subdomains
  Compromise of any fintech.com subdomain cannot reach admin via browser cookies

RESIDUAL RISKS THAT REMAIN:
  □ Same-origin XSS on admin.fintech-internal.com itself
    → Full control of admin panel
    → Re-authentication still required
  □ Admin credential phishing
    → MFA mitigates
  □ Session theft via non-XSS vectors
    → HttpOnly + Secure + short timeout
  □ Network-level attacks (if HTTPS not enforced)
    → HSTS + Secure cookie
```

---

## 13. Complete Defense-in-Depth Stack for API + SPA + Mobile

```
┌────────────────────────────────────────────────────────────────────────┐
│         COMPLETE CSRF DEFENSE STACK: POST /api/transfer                │
│         Supports: React SPA (session cookie) + Mobile (JWT Bearer)     │
├─────────────────────────┬──────────────────────┬───────────────────────┤
│ Layer                   │ Protects Against     │ Failure Mode          │
├─────────────────────────┼──────────────────────┼───────────────────────┤
│ SameSite=Lax on         │ Cross-site POST CSRF │ Misconfiguration      │
│ session cookie          │ from evil.com        │ Browser differences   │
│                         │                      │ Same-site subdomains  │
├─────────────────────────┼──────────────────────┼───────────────────────┤
│ Strict CORS allowlist   │ Untrusted cross-     │ Trusted origin        │
│ (app.fintech.com only)  │ origin response      │ compromised           │
│                         │ reading              │ CORS misconfiguration │
├─────────────────────────┼──────────────────────┼───────────────────────┤
│ Content-Type:           │ HTML form CSRF       │ text/plain JSON body  │
│ application/json        │ (forms can't produce │ Server loose parsing  │
│ validation              │ JSON)                │ Same-site XSS bypass  │
├─────────────────────────┼──────────────────────┼───────────────────────┤
│ CSRF token in           │ Forged authenticated │ XSS token extraction  │
│ X-CSRF-Token header     │ requests (web SPA)   │ Token leakage via URL │
│ (web users only)        │                      │ Presence-only check   │
├─────────────────────────┼──────────────────────┼───────────────────────┤
│ Origin header           │ Cross-origin         │ Absent header         │
│ validation              │ requests from        │ Trusted origin bad    │
│ (server-side)           │ unlisted origins     │ Substring matching    │
├─────────────────────────┼──────────────────────┼───────────────────────┤
│ Re-authentication       │ All CSRF even with   │ None for CSRF         │
│ (large transfers only)  │ bypassed token       │ UX friction           │
├─────────────────────────┼──────────────────────┼───────────────────────┤
│ Mobile: Bearer JWT in   │ Traditional CSRF     │ Token theft via XSS   │
│ Authorization header    │ (no ambient auth)    │ (if in mobile web)    │
│ stored in memory        │                      │ Insecure storage      │
├─────────────────────────┼──────────────────────┼───────────────────────┤
│ Logging & monitoring    │ Detect abuse         │ Detection only        │
│ (anomaly detection)     │ patterns             │ Not prevention        │
└─────────────────────────┴──────────────────────┴───────────────────────┘

KEY DESIGN DECISIONS:
  Web SPA: session cookie (ambient) + CSRF token (explicit intent proof)
  Mobile:  JWT in Authorization header only (no cookies = no ambient authority)
  Mobile never uses credentials: include or sets cookies
  CSRF token requirement: only applies to cookie-authenticated requests
  Token stored: in memory or readable cookie (not localStorage)
```

---

## 14. Secure Design Principles for CSRF

### Principle 1 — The Weakest Link

```
CSRF posture = security of the weakest trusted origin

Every CORS allowlist entry: extends trust boundary
Every same-site subdomain: implicit trust (SameSite cannot isolate)
Every subdomain with weaker security: potential pivot point

Design implication:
  Audit all same-site subdomains before relying on SameSite
  Audit all CORS allowlist entries before relying on CORS
  High-security components should use separate registered domains
  Any subdomain with user content = XSS surface = CSRF pivot
```

### Principle 2 — Defense Independence

```
Independent defenses must have DIFFERENT failure modes.

Example — NOT independent:
  CORS allowlist + SameSite: SAME failure mode (same-site subdomain XSS)
  Both defeated simultaneously by XSS on legacy.fintech.com

Example — GENUINELY independent:
  CSRF token: fails to same-origin XSS extracting token
  Re-authentication: fails to... nothing via CSRF
  Different failure modes → genuine independence
  
Test for independence:
  "If attack X defeats defense A, does it also defeat defense B?"
  If yes: same failure mode → not independent
  If no: different failure modes → genuine independence
```

### Principle 3 — Explicit Over Implicit

```
Implicit controls (fragile):
  "CORS prevents CSRF" — only for cross-origin, not same-site
  "SameSite=Strict protects admin" — only for cross-site, not same-site subdomains
  "WAF protects legacy" — WAF cannot distinguish intent
  "We use JWTs" — only if delivered via header, not cookie

Explicit controls (reliable):
  CSRF token: explicitly validates intent on every request
  Re-authentication: explicitly confirms identity for sensitive action
  Signed double-submit: explicitly unforgeable without server secret
  Origin allowlist: explicitly lists trusted origins by name

Design principle:
  Security should not depend on what you think a defense does
  It should depend on what the defense explicitly verifies
```

### Principle 4 — Blast Radius Minimization

```
Design trust relationships to minimize compromise impact.

High blast radius (dangerous):
  Legacy service in CORS allowlist → legacy XSS = full API access for all users
  Marketing on same domain → WP XSS = admin panel attack surface

Low blast radius (better):
  Legacy uses backend-to-backend API calls → XSS on legacy ≠ API access
  Marketing on separate domain → XSS on marketing ≠ fintech.com cookie access
  Admin on separate domain → compromise of app doesn't reach admin

Blast radius reduction techniques:
  Separate registered domains for different security zones
  Backend-to-backend calls instead of browser-mediated cross-origin calls
  Scoped API tokens with minimal permissions
  Re-authentication limits blast radius even for authenticated sessions
```

### Principle 5 — Secure by Default

```
Every new endpoint, service, or feature must be secure without opt-in.

Dangerous defaults in the fintech architecture:
  DRF views: CSRF enforced by SessionAuthentication
             BUT only if CsrfViewMiddleware is active
             Easy to accidentally disable globally
  WordPress: User content requires explicit sanitization
             Default WP comment config insufficient
  CORS: Easy to add origins to allowlist without security review

Secure by default means:
  New API endpoints: require CSRF token automatically (middleware, not decorator)
  New admin actions: require re-auth by default (base class enforces it)
  New CORS entries: require documented security review before addition
  New subdomains: not automatically trusted; must be explicitly assessed
  New content inputs: sanitized by default; unsafe must be explicitly allowed
```

---

## 15. Architecture Review Checklist

### Phase 1 — Trust Boundary Mapping

```
□ List all origins (protocol + host + port) in the system
□ Identify registered domain for each
□ Map same-site relationships (group by eTLD+1)
□ List all CORS allowlist entries for each service
□ Identify all cookie names, their SameSite values, which origins they reach
□ Identify all services accepting user-submitted content (XSS surfaces)
□ Identify all external/third-party services in the same registered domain
```

### Phase 2 — Defense Evaluation

```
□ For each state-changing endpoint:
  □ What authentication mechanism? (cookie vs header)
  □ Is there a CSRF token? Is it session-bound? Is value validated?
  □ Is there Origin/Referer validation?
  □ What SameSite value on session cookie?
  □ Any method override support? (_method parameter, X-HTTP-Method-Override)
  □ State-changing GET endpoints?

□ For each trust relationship (CORS allowlist entry):
  □ Does the origin need response reading? (or just sending)
  □ Security posture of the origin?
  □ Blast radius of that origin's compromise?
  □ Alternative (backend-to-backend) possible?

□ For admin/privileged actions:
  □ Re-authentication on critical/irreversible actions?
  □ Audit logging?
  □ Session timeout appropriate?
  □ MFA enabled?
```

### Phase 3 — Scenario Testing

```
□ Attacker on evil.com — can they trigger any state change?
□ XSS on lowest-security same-site subdomain — can they reach high-security API?
□ Legacy/third-party service compromise — blast radius?
□ Marketing site XSS — can they reach admin panel?
□ Same-origin XSS on highest-security service — what survives?
□ Subdomain takeover on any *.domain.com — what trust do they inherit?
□ What is the minimum viable attack chain for: account takeover / financial loss / admin access?
```

### Phase 4 — Recommendations Prioritization

```
CRITICAL (block before launch):
  □ Any missing CSRF token on financial/ATO-path endpoint
  □ Any CORS origin reflection (ACAO reflects request Origin)
  □ Any state-changing GET endpoint
  □ Legacy service with "WAF as CSRF defense" claim

HIGH (first post-launch sprint):
  □ Re-authentication missing on critical admin actions
  □ CORS allowlist entries with weaker security posture
  □ User-submitted content on same registered domain as high-security services
  □ Missing CSP on XSS-surface subdomains

MEDIUM (security hardening roadmap):
  □ Moving marketing/lower-security services to separate registered domains
  □ Converting legacy service to backend-to-backend API calls
  □ Subdomain monitoring for dangling CNAMEs
  □ Per-request CSRF token rotation for highest-sensitivity endpoints
```

---

## 16. Key Terminology Reference

| Term | Definition |
|------|------------|
| **Trust boundary** | The line between origins/systems that trust each other and those that don't |
| **Trust extension** | Adding an origin to CORS allowlist; that origin's compromise now affects you |
| **Blast radius** | The scope of impact if a given trust relationship or component is compromised |
| **Weakest link** | The least-secure origin in your trust chain; sets the upper bound on security |
| **Same-site attack** | CSRF attack originating from a different subdomain of the same registered domain |
| **Blind CSRF** | CSRF where the action executes but the attacker cannot read the response |
| **Defense independence** | Two controls are independent if compromising one does not compromise the other |
| **Secure by default** | Architecture where new components are protected without requiring explicit opt-in |
| **Backend-to-backend** | Server-to-server API calls with no browser cookie involvement; no ambient authority |
| **Re-authentication** | Requiring credential confirmation before executing high-impact actions |
| **Audit log** | Record of privileged actions including actor, action, timestamp, IP |
| **Shared failure mode** | Two defenses that are both defeated by the same attack vector |
| **eTLD+1** | Effective top-level domain + one label; the registrable domain unit for same-site |
| **Dangling CNAME** | DNS CNAME pointing to unclaimed external resource; enables subdomain takeover |
| **Content-based isolation** | Separating high-security and user-content services to different registered domains |

---

## 17. Common Misconceptions

### ❌ "SameSite=Strict means the admin panel is safe from any same-site subdomains"
**Wrong.** SameSite=Strict prevents cross-site cookie sending. Subdomains of the same registered domain are same-site. XSS on any `fintech.com` subdomain can make credentialed requests to `admin.fintech.com` with the admin session cookie attached, bypassing SameSite=Strict entirely.

### ❌ "CORS allowlist prevents CSRF from same-site subdomains"
**Wrong.** CORS controls whether a cross-origin origin can READ responses. It does not prevent same-site requests from carrying cookies. An origin not in the CORS allowlist can still send same-site requests with session cookies — it just cannot read the response (blind CSRF).

### ❌ "WAF protection is equivalent to application-level CSRF controls"
**Wrong.** WAFs cannot distinguish legitimate from forged requests because both carry valid session cookies and look identical at the HTTP level. WAFs can only apply intent validation if specifically configured to validate CSRF tokens — which requires deep application-level understanding that most WAF rules don't have.

### ❌ "Moving a service to a subdomain isolates it from CSRF attacks on other subdomains"
**Wrong.** Subdomains of the same registered domain are same-site. The only way to achieve genuine isolation is to use a completely different registered domain (e.g., `admin.fintech-internal.com` instead of `admin.fintech.com`).

### ❌ "X-Requested-With header requirement prevents CSRF from same-site attackers"
**Wrong.** Same-site JavaScript (from XSS on any fintech.com subdomain) can freely set X-Requested-With and any other custom header on cross-origin but same-site requests. Custom header checks only stop attackers from different registered domains (where CORS preflight applies).

### ❌ "CORS allowlist only needs to include origins that make API requests"
**Wrong.** CORS allowlist entries should only include origins that need to READ API responses. If an origin only needs to send requests (and already can via same-site cookie attachment), adding it to the CORS allowlist unnecessarily extends the trust boundary and increases blast radius.

---

## 18. Bug Bounty Reference — Architectural Findings

### High-Value Architectural CSRF Findings

```
FINDING 1: Over-permissive CORS allowlist
  What to look for: Origins in CORS allowlist with weaker security
  How to test: Identify allowlisted origins → test for XSS on them
               → forge API requests from XSS position
  Severity: High/Critical (depends on API actions available)
  Report framing: "XSS on [allowlisted origin] enables full API CSRF bypass"

FINDING 2: User-submitted content on same registered domain as sensitive API
  What to look for: WordPress, forums, comment systems on same eTLD+1
  How to test: Find XSS in user content → forge requests to sensitive API
  Severity: High/Critical
  Report framing: "XSS on [content site] enables same-site CSRF on [API]"

FINDING 3: SameSite=Strict admin panel with same-site subdomains
  What to look for: Admin cookie with Strict + weaker subdomains on same domain
  How to test: XSS on weaker subdomain → forge admin requests
  Severity: Critical (admin compromise)
  Report framing: "SameSite=Strict does not protect admin from same-site XSS"

FINDING 4: WAF as sole CSRF defense
  What to look for: No application-level CSRF tokens on legacy/older services
  How to test: Send forged requests → check if WAF passes them
  Severity: High/Critical
  Report framing: "Legacy service CSRF unprotected — WAF insufficient"

FINDING 5: Missing re-authentication on admin critical actions
  What to look for: Admin delete/escalate/configure actions without password prompt
  How to test: CSRF on admin action → does it execute without password?
  Severity: High (amplifies other CSRF findings)
  Report framing: "Admin [action] lacks re-authentication — CSRF enables [impact]"
```

### Report Template — Architectural CSRF Finding

```markdown
## Title
Architectural CSRF Risk: [Specific Finding] Enables [Impact]

## Severity
[Critical/High] — [One-line justification]

## Architecture Gap
[Description of the trust relationship or design decision creating the risk]

## Attack Chain
1. Attacker [initial position/action]
2. [Step exploiting the architectural gap]
3. [Resulting credentialed access]
4. [Final impact]

## Why Existing Defenses Are Insufficient
[SameSite/CORS/WAF defense X does not protect against this because...]

## Blast Radius
[What an attacker can access/do if the chain succeeds]

## Recommended Fix
Priority 1 (immediate): [Architectural change that breaks chain earliest]
Priority 2 (hardening): [Defense-in-depth additions]

## Proof of Concept
[Minimal demonstration showing the architectural gap]
```

---

## 19. Module 11 Summary — What You Must Know Cold

```
TRUST BOUNDARY MAPPING:
✓ Map all origins, their same-site relationships, CORS allowlist memberships
✓ Every CORS allowlist entry extends your security boundary
✓ Every same-site subdomain is an implicit trust relationship
✓ Security posture of the weakest trusted origin = your API's security posture

SAMESITE AND SUBDOMAINS:
✓ SameSite (any value) does NOT isolate subdomains from each other
✓ SameSite=Strict blocks cross-site only (different registered domains)
✓ marketing.fintech.com XSS → admin.fintech.com: same-site, Strict doesn't block
✓ True isolation requires separate registered domains

CORS AND CSRF:
✓ CORS controls response reading, not request sending for same-site origins
✓ Non-allowlisted origin can still send same-site requests (blind CSRF possible)
✓ CORS allowlist entry = trust extension = that origin's compromise affects you
✓ Add origins to allowlist only when they need to READ responses

WAF:
✓ WAF cannot distinguish legitimate from forged requests
✓ "Protected by WAF" is not an acceptable CSRF defense without specifics
✓ WAF is defense-in-depth at best; application-level controls required

ADMIN PANELS:
✓ SameSite=Strict + CSRF token: strong against external attackers
✓ Same-site subdomain XSS defeats both (same-site → cookie sent, XSS → token read)
✓ Re-authentication on critical actions: only control that survives same-site XSS
✓ Moving admin to separate registered domain: makes SameSite=Strict genuinely work

DEFENSE INDEPENDENCE:
✓ Two controls independent only if they have different failure modes
✓ CORS + SameSite: same failure mode (same-site subdomain XSS)
✓ CSRF token + re-auth: different failure modes (genuinely independent)
✓ Re-authentication survives everything — only control with no CSRF bypass

SECURE DESIGN:
✓ Separate security zones to separate registered domains
✓ Use backend-to-backend for service-to-service calls (removes browser cookie involvement)
✓ Audit CORS allowlist entries — justify each one with security review
✓ Re-auth by default for all irreversible/privileged actions
✓ User-submitted content on same domain = XSS surface = CSRF pivot point
```

---

*Next: Module 12 — Cumulative Assessment & Cheatsheet*  
*Full synthesis quiz across all 11 modules, GitHub-ready master cheatsheet,*
*complete detection checklist, and bug bounty report templates*