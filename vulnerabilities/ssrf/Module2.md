# Module 2 — Basic SSRF

> Finding and confirming HTTP-based SSRF: discovery methodology, injection points, and PoC construction.

---

## Table of Contents

- [Module 2 — Basic SSRF](#module-2--basic-ssrf)
  - [Table of Contents](#table-of-contents)
  - [Core Concept](#core-concept)
  - [Mental Model](#mental-model)
  - [Common Injection Points](#common-injection-points)
  - [The Loopback Trust Assumption](#the-loopback-trust-assumption)
  - [Discovery Methodology](#discovery-methodology)
  - [PoC Construction — Correct Ordering](#poc-construction--correct-ordering)
  - [Proving Server-Side Origin](#proving-server-side-origin)
  - [Headless Browser Fetchers — Special Case](#headless-browser-fetchers--special-case)
  - [Secure Coding — First Real Fix Attempt](#secure-coding--first-real-fix-attempt)
  - [Common Mistakes](#common-mistakes)
  - [Variations and Edge Cases](#variations-and-edge-cases)
  - [Terminology Reference](#terminology-reference)
  - [Common Misconceptions](#common-misconceptions)
  - [Summary](#summary)

---

## Core Concept

Basic SSRF discovery reduces to one recurring question:

> **"Does the server ever fetch a URL, or part of a URL, that I influence?"**

Everything else — target selection, payload choice, severity — is downstream of finding that entry point.

---

## Mental Model

Every "server fetches a URL" feature is a **remote-controlled arm attached to the server**. The arm works exactly as designed — your job is to grab the controller (the URL parameter) and point it somewhere the developer never intended. The arm has no opinion about `https://api.partner.com/logo.png` vs. `http://127.0.0.1:6379` — it just fetches.

---

## Common Injection Points

| Feature | Why It Fetches | Typical Parameter |
|---|---|---|
| Webhook registration | Server calls back to a URL on events | `callback_url`, `webhook_url` |
| "Import from URL" | Server downloads content on your behalf | `import_url`, `source_url` |
| Avatar/image-by-URL upload | Server fetches and stores/resizes an image | `image_url`, `avatar_url` |
| PDF/document generation | Server renders a page (often headless browser) at a URL | `url`, `page_url` |
| Link preview / unfurling | Server fetches metadata from a link | `link`, `preview_url` |
| SSO / OAuth metadata config | Server fetches IdP metadata from configurable endpoint | `metadata_url`, `idp_url` |
| "Print this page" / HTML-to-PDF | Same rendering-engine mechanism as above | `html_url` |

Grep client code / API docs for parameter names: `url`, `uri`, `link`, `path`, `dest`, `callback`, `webhook`, `src`, `feed`, `endpoint`.

---

## The Loopback Trust Assumption

Services bound to `127.0.0.1` (e.g., Redis on `6379`) often **skip authentication entirely**, relying on a positional trust model: *"only trusted local processes can reach this interface."*

SSRF breaks this because the connection now **originates from the trusted server itself** — the loopback-bound service has no way to distinguish a legitimate local process from the web server acting on an attacker's behalf. This is a **positional trust failure, not an authentication bypass** — the service was never authenticating in the first place.

**Key nuance:** raw TCP services (Redis, Memcached) don't parse HTTP framing and don't check `Host` headers — they simply read whatever bytes arrive on the connection. This is the seed of Module 5's protocol smuggling (gopher:// exists specifically to deliver raw protocol bytes past an HTTP-oriented client).

---

## Discovery Methodology

1. **Map every feature touching an external URL** — grep for parameter names above.
2. **Test with an out-of-network canary first** (a domain/listener you control, e.g. `webhook.site`). This confirms the server fetches attacker-controlled URLs *before* you touch internal targets.
3. **Escalate to loopback** — `http://127.0.0.1`, `http://localhost`, common internal ports (`80, 443, 6379, 8080, 3306, 9200, 27017`).
4. **Observe response differences** — status code, response time, error content, body length. These distinguish "port open, service responded" from "closed/filtered" — the foundation of blind/semi-blind detection (Module 3).

---

## PoC Construction — Correct Ordering

```
Step 1: Confirm the server fetches ANY external URL you control
        → canary hit on your listener

Step 2: Extract maximum information from that one canary hit
        → check User-Agent, check whether content is REFLECTED
          back to you (full-response) or merely fetched (blind)
        → e.g., for a PDF generator: put distinctive text on your
          canary page, check if it appears in the output PDF

Step 3: Escalate to loopback, now knowing blind vs. full-response
        → success criteria differs: rendered internal content
          vs. timing/error signal only

Step 4: Escalate to full internal range / metadata
        → only once loopback reachability is confirmed
```

**Do not repeat identical canary requests** — each step should extract new information. Two identical confirmation hits waste methodology and weaken report clarity.

---

## Proving Server-Side Origin

Evidence that the **server**, not a client-side redirect or your own browser, made the request:

- **Timing correlation** — listener hit occurs within milliseconds of your action on the app (most reliable signal)
- **Source IP** — request originates from the target company's infrastructure, not a residential/random IP
- **User-Agent** — supporting signal only:
  - `python-requests/...`, `Go-http-client/...` → simple backend HTTP client
  - `Mozilla/5.0 ... HeadlessChrome/...` → **still server-side** — a headless browser rendering engine, not proof of "not SSRF"

UA alone is not proof of origin — a headless renderer looks like a real browser. Timing + source IP are the real proof.

---

## Headless Browser Fetchers — Special Case

PDF generators, screenshot tools, and "print this page" features often use a headless browser (Chromium via Puppeteer/Playwright, wkhtmltopdf, etc.) rather than a simple HTTP client.

**This changes what "full-response SSRF" looks like:**

| Fetcher Type | What You Get Back | Best For |
|---|---|---|
| Simple HTTP client (`requests.get`) | Raw response bytes, if the developer chooses to return them | Raw-data targets — e.g. plaintext JSON credentials from metadata endpoints |
| Headless browser / renderer | A **rendered representation** (image/PDF) of what the engine could display | HTML-rendering targets — internal dashboards, admin panels |

**Caveat:** a renderer shows what it can *draw*. Response headers and raw non-HTML data (e.g., plaintext credential JSON from a metadata endpoint) generally **will not appear** in a rendered PDF/screenshot — there's nothing for the engine to render. Prefer testing raw-data targets against non-rendering fetchers where possible, and HTML targets against rendering fetchers.

---

## Secure Coding — First Real Fix Attempt

```python
# Weak — Module 1 pattern, string-based blocklist
if parsed.hostname not in ['localhost', '127.0.0.1']:
    ...

# Improved — validates the RESOLVED IP, not the hostname string
import ipaddress, socket

def is_safe_url(url):
    parsed = urlparse(url)
    if parsed.scheme not in ('http', 'https'):
        return False
    try:
        resolved_ip = socket.gethostbyname(parsed.hostname)
    except socket.gaierror:
        return False
    ip = ipaddress.ip_address(resolved_ip)
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
        return False
    return True
```

**Still incomplete:** doesn't pin the resolved IP for the actual outbound connection (TOCTOU gap → DNS rebinding, Module 6) and doesn't handle redirects. This is a checkpoint fix, not a final one — full hardening arrives after Module 6.

---

## Common Mistakes

1. Checking the hostname **string** instead of the **resolved IP** (the #1 real-world root cause).
2. Blocking only `localhost`/`127.0.0.1` literally — missing `0.0.0.0`, other loopback forms, IPv6 `::1`.
3. Skipping the external-canary confirmation step and jumping straight to internal targets — produces false negatives when a request is blocked, since you never proved the server fetches attacker URLs at all.
4. Treating "no data returned" as "not vulnerable" — a timing/error difference alone can already prove internal reachability (bridges into blind SSRF, Module 3).
5. Repeating identical canary tests instead of extracting new information (blind vs. full-response) at each step.

---

## Variations and Edge Cases

- **Same domain, different port**: `http://target.com:6379` — bypasses naive "must match our domain" checks while hitting an internal service exposed via port.
- **IPv6 loopback**: `http://[::1]` — missed by IPv4-only blocklists.
- **URL userinfo confusion**: `http://trusted.com@127.0.0.1/` — parser-dependent; some read `trusted.com` as host, others correctly resolve `127.0.0.1`. (Full parser-confusion depth: Module 6.)

---

## Terminology Reference

| Term | Definition |
|---|---|
| **Canary** | An external, attacker-controlled URL/listener used to confirm outbound fetch behavior before testing internal targets |
| **Positional trust** | Security model relying on network position (e.g., "bound to loopback") instead of authentication |
| **TOCTOU** | Time-of-check to time-of-use — a gap between validating a value and using it, exploitable when the value can change in between |
| **Headless browser** | A browser engine (e.g., Chromium) run without a UI, often used server-side for rendering/PDF/screenshot generation |

---

## Common Misconceptions

1. **"A browser-like User-Agent on my listener means it's not SSRF."** False — headless renderers are still server-side and produce browser-like UAs.
2. **"Headless-browser fetchers always give better full-response SSRF."** Only for HTML-rendering targets — raw-data targets (e.g., metadata JSON) often render as nothing.
3. **"If loopback is blocked, testing is done."** False — port variation, IPv6, and userinfo confusion can still bypass a naive check (Module 6 will formalize this).

---

## Summary

Basic SSRF discovery is a repeatable methodology, not guesswork: map URL-fetching features → confirm with an external canary → extract maximum signal from that confirmation (blind vs. full-response, fetcher type) → escalate deliberately to loopback and beyond. Loopback-bound services are exploitable specifically because they rely on positional trust rather than authentication, and SSRF supplies exactly the "trusted position" they assumed was unreachable from outside. Fetcher type (simple HTTP client vs. headless renderer) determines what evidence is actually retrievable, and should guide which internal targets you prioritize.