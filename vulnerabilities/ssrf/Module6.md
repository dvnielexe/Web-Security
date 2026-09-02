# Module 6 — Filter Bypass Techniques

> Thinking like a parser: how the same destination can be represented in dozens of forms that defeat string-based validation.

---

## Table of Contents

- [Module 6 — Filter Bypass Techniques](#module-6--filter-bypass-techniques)
  - [Table of Contents](#table-of-contents)
  - [Core Concept](#core-concept)
  - [Mental Model](#mental-model)
  - [IP Encoding Catalog](#ip-encoding-catalog)
  - [The Strict-Validator vs. Permissive-Connector Gap](#the-strict-validator-vs-permissive-connector-gap)
  - [DNS-Based Bypasses](#dns-based-bypasses)
  - [URL Parser Confusion](#url-parser-confusion)
  - [Redirect-Based Bypasses](#redirect-based-bypasses)
  - [Scheme Confusion](#scheme-confusion)
  - [Case Variation and Fragment Abuse](#case-variation-and-fragment-abuse)
  - [Localhost Aliases — Consolidated Reference](#localhost-aliases--consolidated-reference)
  - [Bypass Methodology — Audit Checklist](#bypass-methodology--audit-checklist)
  - [Common Mistakes](#common-mistakes)
  - [Terminology Reference](#terminology-reference)
  - [Common Misconceptions](#common-misconceptions)
  - [The Unifying Defensive Principle](#the-unifying-defensive-principle)
  - [Summary](#summary)

---

## Core Concept

Every technique in this module exploits the same root cause: **a validator checks one specific textual representation of a destination, while the resolver/parser/connector that actually acts on the URL accepts many other representations that resolve to the exact same place.** Blocklists fail because the input space of equivalent representations is far larger than any developer enumerates.

---

## Mental Model

> A blocklist author thinks like a person reading an address. A bypass technique thinks like the machine parsing it.

`127.0.0.1` and `0x7f000001` look obviously different to a human. To a network stack, they're the same 32-bit integer in different notation. Validity of any given representation is **parser-dependent, not universal** — a check written against one canonical form says nothing about how a different (but equally valid) form will be interpreted downstream.

---

## IP Encoding Catalog

| Encoding | Example (127.0.0.1) | Why It Works |
|---|---|---|
| Decimal (integer) | `2130706433` | 4 octets as one 32-bit number |
| Octal | `0177.0.0.1` / `017700000001` | Leading `0` triggers octal interpretation |
| Hexadecimal | `0x7f000001` | `0x` prefix triggers hex interpretation |
| Dotted-hex per octet | `0x7f.0x0.0x0.0x1` | Mixed notation, some parsers accept per-octet hex |
| Octet dropping (short form) | `127.1` → `127.0.0.1` | Missing octets zero-expanded by some resolvers |
| IPv6-mapped IPv4 | `::ffff:127.0.0.1` | IPv4-in-IPv6 notation, missed by IPv4-only blocklists |
| IPv6 loopback | `::1` | Different address family entirely |

---

## The Strict-Validator vs. Permissive-Connector Gap

The general "resolve to canonical form, then validate" principle only holds if **the validating library and the connecting library parse identically**. In practice they often don't:

- Python's `ipaddress.ip_address()` is **strict** — rejects `2130706433` / `0x7f000001` outright (`ValueError`)
- The OS resolver / underlying HTTP client's connection logic (often libc `inet_aton`-style) is **permissive** — silently accepts decimal/octal/hex and normalizes to the real IP before connecting

**Exploitable gap:** if validation throws on a malformed-looking string and the developer assumes "rejected," but a *different* code path (or a redirect target, or the raw hostname handed straight to the connecting function) receives that same string, the permissive connector resolves and connects anyway.

**Audit question:** is the exact same parser/resolution path used for validation also used for the actual connection, and is the validated destination guaranteed to be the one that gets connected to?

---

## DNS-Based Bypasses

- **A record pointing at an internal IP**: attacker's own domain resolves directly to `127.0.0.1` — defeats any check that only inspects the hostname *string* ("is it literally `localhost`?") without resolving it.
- **CNAME chains**: some validators check only the first hop and don't fully follow CNAME chains before the actual connection does.

---

## URL Parser Confusion

URL parsing is inconsistent across libraries — the same string can be interpreted differently by a validator vs. the actual connecting client.

```
http://trusted.com@127.0.0.1/
http://127.0.0.1#trusted.com/
```

In `http://trusted.com@127.0.0.1/`, `trusted.com` is **userinfo** (username), not the host — the real host is `127.0.0.1`. A naive regex/substring validator looking for "a domain-looking string" sees `trusted.com` and approves; the spec-compliant HTTP client correctly parses `127.0.0.1` as the host and connects there. **The validator and the connector disagree about what "the host" means for the identical string** — the same root pattern as the IP-parsing gap above, manifesting in URL syntax.

---

## Redirect-Based Bypasses

Validate `http://safe-looking-domain.com` (passes every check) → that server responds `302 Location: http://127.0.0.1/`. If the fetching code follows redirects (`allow_redirects=True`), **validation only ever inspected the first URL** — the redirect target is never re-validated. Requires only an attacker-controlled domain or an open redirect on some external server.

---

## Scheme Confusion

Any validation checking `url.startswith("http")` is defeated by `httpx://`, `HTTP://` (case), or a scheme the validator's substring check doesn't anticipate — including the `gopher://`/`file://`/`dict://` schemes covered mechanically in Module 5.

---

## Case Variation and Fragment Abuse

- **Case variation**: `HTTP://127.0.0.1/`, `LOCALHOST` — case-sensitive equality checks (`hostname == 'localhost'`) miss these; DNS/HTTP are case-insensitive at the protocol level.
- **Fragment abuse**: `http://127.0.0.1#@trusted.com/` — fragments (`#...`) are never sent to the server in the actual request, but a naive validator string-searching the full URL for "trusted.com" may see it and approve, unaware the fragment is invisible to the real connection.

---

## Localhost Aliases — Consolidated Reference

| Alias | Form |
|---|---|
| `127.0.0.1` | Standard |
| `0.0.0.0` | "This host" — often routes to loopback |
| `0x7f000001` | Hex |
| `2130706433` | Decimal integer |
| `0177.0.0.1` | Octal |
| `127.1` | Short form |
| `::1` | IPv6 loopback |
| `::ffff:127.0.0.1` | IPv4-mapped IPv6 |
| `localhost.` | Trailing dot — some resolvers strip it, string-equality checks may not match |

---

## Bypass Methodology — Audit Checklist

Run against any blocklist-based defense:

1. Does it validate the **string**, or the **resolved value**? (String → bypassable via any encoding.)
2. Is the validating parser the **same library/strictness** as the connecting parser? (Different → exploit the gap.)
3. Does it **re-validate after redirects**? (No → redirect bypass.)
4. Does it restrict **scheme explicitly**, or just check a prefix? (Prefix → scheme confusion.)
5. Is the comparison **case-sensitive**? (Yes → case variation bypass.)
6. Does it account for **userinfo/fragment syntax** per the URL spec, or substring-search the raw string? (Substring search → parser confusion.)

---

## Common Mistakes

1. Testing a filter only against the canonical form (`127.0.0.1`, `localhost`) and declaring it solid.
2. Using a strict validator and assuming a thrown exception means the value can never reach the connector via any code path.
3. Enabling `allow_redirects=True` without re-validating each hop.
4. Writing a regex-based host extractor instead of using a spec-compliant URL parser, missing userinfo/fragment distinctions.

---

## Terminology Reference

| Term | Definition |
|---|---|
| **Canonicalization** | Converting a value to one standard form before comparison/validation |
| **Userinfo** | The `user[:password]@` portion of a URL, preceding the actual host |
| **Open redirect** | A server endpoint that redirects to an attacker-controlled URL, usable as a bypass hop |
| **Substring/regex validator** | A naive filter that pattern-matches parts of a raw string instead of using a proper URL/IP parser |

---

## Common Misconceptions

1. **"Blocking `127.0.0.1` and `localhost` covers loopback."** False — at least seven other equivalent representations exist (see catalog above).
2. **"If my IP validator rejects a malformed string, the app is safe."** False if a different code path or the connector itself parses that same string more permissively.
3. **"A domain in the URL string is the host."** False — userinfo (`user@host`) and fragments (`#...`) can contain domain-looking text that is never treated as the host by a spec-compliant parser.
4. **"Redirect-following is a UX feature with no security implication."** False — it silently reopens the entire validation surface at each hop unless re-validated.

---

## The Unifying Defensive Principle

Every bypass category in this module shares one root cause: **a gap between what was validated and what was actually connected to.** The single principle that defeats all of them at once:

> Parse and resolve the complete URL using the same semantics as the actual network client, validate the resulting destination against an explicit policy, and enforce that policy at connection time — including on every redirect hop — without ever reinterpreting the destination later via a different, more permissive code path.

This is a preview of Module 9's full hardened implementation, but the principle itself is the entire lesson of this module distilled to one sentence.

---

## Summary

Filter bypass techniques exist because IP addresses and URLs have far more valid textual representations than any blocklist author enumerates — decimal, octal, hex, IPv6-mapped forms for IPs; userinfo, fragments, and case variation for URLs; unrevalidated redirect chains and unrestricted schemes on top of that. The consistent root cause across every category is a mismatch between the parser doing validation and the parser doing the actual connection. Defeating all of them simultaneously doesn't require enumerating each encoding — it requires closing the validation/connection gap itself: same parsing semantics, resolved-value validation, and enforcement at connection time on every hop.