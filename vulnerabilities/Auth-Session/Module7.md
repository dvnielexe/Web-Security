# Module 7: Cookies & Session Attributes — Cheatsheet

## Core Theme

> **Every cookie attribute defends against exactly ONE specific mechanism. None of them protect application logic. "This control is present" ≠ "this attack surface is closed." Always ask: what specific attack does this stop, and what paths remain completely untouched?**

## Mental Model
Cookie = sealed envelope (contents = session ID, from Module 6) + handling instructions on the outside (attributes = who can open it, which routes it travels, when delivery is refused).

## `HttpOnly`

**What it does:** Cookie inaccessible to JavaScript via `document.cookie` or any client-side script API. Still transmitted normally in HTTP requests.

**What it does NOT do:** Does not fix XSS. Does not stop an attacker with JS execution from:
- Performing any action the logged-in user can perform, in real time — browser auto-attaches the cookie to any request the malicious script fires (`fetch`/`XHR`); `HttpOnly` blocks *readability*, not *automatic transmission*
- Reading/exfiltrating anything rendered on the page
- Capturing keystrokes/form input, injecting fake overlays
- Reading anti-CSRF tokens directly out of the DOM if present there

**Report framing:** Never write "XSS is mitigated because cookies are HttpOnly." Correct: "session cookie theft via this vector is prevented, but the underlying XSS still permits full in-session action execution" — score severity close to what it'd be without HttpOnly; live action execution is often as damaging as offline replay, sometimes more so (instant, no further attacker effort needed).

## `Secure`

**What it does:** Cookie withheld entirely on any plaintext HTTP request; only ever sent over HTTPS.

**What it does NOT do:** Protect the page itself, or anything the user submits on a downgraded/SSL-stripped connection. In an SSL-stripping attack, `Secure` prevents cookie theft specifically — but the attacker still fully controls the plaintext page, can harvest credentials typed into it, manipulate forms, etc.

**Complementary control: HSTS** (`Strict-Transport-Security`) — browser never even attempts an HTTP connection to the domain again, auto-upgrades before sending anything, including the first request. `Secure` alone leaves the plaintext-page attack surface wide open; HSTS closes reachability of that plaintext page. **Defense-in-depth, not redundant** (same principle from Module 6).

## `SameSite`

| Value | Behavior |
|---|---|
| `Strict` | Never sent cross-site, even top-level navigation (clicking an email link) |
| `Lax` (modern default) | Sent on top-level navigation; NOT on cross-site subrequests (JS-submitted forms, image loads, iframes) |
| `None` | Sent on all cross-site requests (requires `Secure` alongside it) |

**Why `Lax`, not `Strict`, is the sensible default:** `Strict` breaks legitimate flows — clicking a link from email/search/chat while logged in would land the user looking logged-out (cookie withheld on that first cross-site navigation), forcing a jarring re-login. Also breaks OAuth/SSO return flows and magic-link logins. `Lax` still blocks the most damaging silent CSRF (auto-submitting cross-site forms/fetches) while preserving "click a link, land already logged in."

**Critical limitation — do not rely on `SameSite` alone:** does NOT cover state-changing `GET` endpoints (e.g., `GET /transfer?amount=X` triggered via `<img>` tag) or older/non-compliant clients. Pair with CSRF tokens for state-changing requests — same conclusion your CSRF curriculum already reached, now understood at the mechanism level.

## `Domain` Scope

Setting `Domain=.company.com` (leading dot) shares the cookie across **all subdomains**, not just the intended one. Creates a trust dependency on the security of every subdomain — including ones you may not control to the same standard (marketing CMS, staging, support tickets).

**Attack chain:** weak subdomain (e.g., outdated CMS) has XSS → attacker gets script execution in `blog.company.com` origin → session cookie for `app.company.com` (scoped to parent domain) is present and either readable (no HttpOnly) or auto-attached to authenticated requests (even with HttpOnly) → attacker rides or steals the session → server's notebook lookup treats attacker as victim.

**Fix:** scope `Domain` as narrowly as possible — omit entirely (defaults to exact host-only match) or restrict to the specific subdomain. Cross-subdomain sharing should be a deliberate, justified decision, never a default/oversight.

**Parallel principle:** same shape as Module 4's "your account security depends on your email provider's security" — except the dependency here is on your OWN organization's weakest subdomain, often more overlooked because it feels "internal."

## Client-Writable Cookies Carrying Authorization-Relevant Data

Example: non-HttpOnly `user_prefs` cookie storing `{"role": "admin"}` "just for UI convenience." Same root failure as Module 6 (client-controlled data trusted for authz), but with a critical escalation:

**No attacker or XSS required at all.** Any authenticated user can open dev tools, directly edit the cookie value, reload — instant self-service privilege escalation if ANY server endpoint trusts that field instead of deriving role from the session lookup. Client-writable storage isn't just XSS-adjacent risk — it's a **direct self-service escalation vector** since attacker and victim are the same person.

**Fix:** never place authorization-relevant data in client-readable/writable storage (cookies without HttpOnly, localStorage, sessionStorage) — regardless of "just for UI" framing.

## Server Reflecting the Raw Session ID (e.g., `/api/session-info` returning it in JSON)

Completely bypasses `HttpOnly` — not by reading `document.cookie`, but because the **server hands the secret over directly** as response data. Worse than a typical HttpOnly-bypass-via-XSS because **no XSS is required at all** — this is a standing, permanent vulnerability requiring only that someone notice the endpoint exists.

**One-liner:** if the server ever reflects the session ID as data, it nullifies HttpOnly and hands the attacker the name tag directly.

**Fix:** remove raw session ID from any API response body entirely, full stop — "HttpOnly is already set" is not a valid remediation here.

## The Unifying Concept Behind Both `user_prefs` and `/api/session-info`

Both are the same Module 6 violation in different forms: **the client is either given write access to something authorization logic might later trust, or given read access to the notebook's actual secret content.** Cookie attributes (HttpOnly/Secure/SameSite) govern browser-level transport of the cookie — they have ZERO authority over what the server chooses to put in a response body or trust as input. "Cookie is perfectly configured" ≠ "application is secure" — attributes close browser-transport paths only, never application-logic paths.

## Detection Methodology

- Inspect `Set-Cookie` headers directly for every session-relevant cookie: `HttpOnly`, `Secure`, `SameSite`, `Domain`/`Path` scope
- Test `HttpOnly` empirically via any JS execution context (console or confirmed XSS) — confirm absence from readable cookie set, don't assume
- Test `Secure` by forcing an HTTP request (if any HTTP listener exists) and checking if the cookie is sent
- Test `SameSite` empirically: craft a cross-site form/fetch, observe actual attachment behavior — don't trust the stated policy
- Map full `Domain` scope: enumerate other subdomains under the same parent, assess their relative security posture (use recon/subdomain enumeration tooling)
- Check every API response body for raw session ID or other secret-bearing "notebook" values inadvertently exposed as data

## Common Developer Mistakes

- Missing `HttpOnly` (session cookie readable, any XSS → instant session theft)
- Missing `Secure` (compounds with missing HSTS)
- `SameSite=None` set broadly without genuine cross-site need
- Relying on `SameSite=Lax` alone as complete CSRF defense
- Overly broad `Domain` scope (parent domain instead of specific subdomain)
- Authorization-relevant data in non-HttpOnly cookies or other client-writable storage
- API endpoints reflecting the raw session ID as response data

## Secure Design Principles

- `HttpOnly` on every session/auth cookie, no exceptions (even knowing it doesn't fully neutralize XSS)
- `Secure` on every cookie, always
- `SameSite=Lax` default; `Strict` for especially sensitive cookies/actions; never sole CSRF defense — pair with tokens
- `Domain` scoped as narrowly as possible
- Never place authz-relevant data in client-readable/writable storage
- Never reflect the raw session ID/secret in any API response body

## Common Misconceptions

- "HttpOnly stops XSS" → stops one exfiltration technique only; live in-session action execution remains fully possible
- "Secure means the connection is always encrypted" → only withholds the cookie on plaintext; page/submitted-data exposure remains without HSTS
- "SameSite=Lax is enough CSRF protection" → doesn't cover state-changing GET, older clients; pair with tokens
- "It's just a UI preferences cookie, not security-relevant" → any value a downstream check might trust becomes security-relevant
- "All three flags set = fully immune to theft/misuse" → False. They harden the name tag; they don't fix application logic, XSS, or server-side data leaks

## Variations & Edge Cases

- **`__Host-`/`__Secure-` cookie name prefixes** — browser-enforced guarantees baked into the name itself (`__Host-` requires Secure, no Domain attribute, Path=/); browser rejects the cookie outright on violation — stronger enforcement than attributes alone
- **CSRF token cookies deliberately NOT HttpOnly** — legitimate exception: double-submit cookie pattern requires JS to read the token and attach it to requests; security comes from same-origin-only read access (attacker sites can't read it), not from hiding it from your own JS. Don't over-apply HttpOnly blindly.
- **Cookie size/count limits** — practical constraint, not security-relevant

## Reporting Reference

- **Missing HttpOnly on session cookie**
  - CWE-1004 (Sensitive Cookie Without HttpOnly Flag)
- **Missing Secure flag**
  - CWE-614 (Sensitive Cookie Without 'Secure' Attribute)
- **Overly broad Domain scope / cross-subdomain cookie exposure**
  - CWE-284 (Improper Access Control) — contextualize with affected subdomain's security posture
- **Authorization data in client-writable cookie**
  - CWE-602 (Client-Side Enforcement of Server-Side Security), CWE-639
- **Session ID reflected in API response body**
  - CWE-522 (Insufficiently Protected Credentials) — treat as High, no XSS prerequisite needed for exploitation

## Key Test to Remember
For any cookie-attribute finding: state explicitly what mechanism it closes AND what remains fully open. "HttpOnly is set" answers "can XSS read the cookie?" — it does not answer "can XSS still act as the user?" Always answer both.