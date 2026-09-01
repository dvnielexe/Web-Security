# Module 5 — Protocol Smuggling & Advanced Vectors

> Moving past HTTP-only targets: gopher://, dict://, file://, DNS rebinding, and raw-protocol exploitation against Redis, Memcached, and SMTP.

---

## Table of Contents

- [Module 5 — Protocol Smuggling \& Advanced Vectors](#module-5--protocol-smuggling--advanced-vectors)
  - [Table of Contents](#table-of-contents)
  - [Core Concept](#core-concept)
  - [Mental Model](#mental-model)
  - [Why Plain http:// Fails Against Redis](#why-plain-http-fails-against-redis)
  - [gopher:// Syntax and Mechanics](#gopher-syntax-and-mechanics)
  - [gopher:// Client Support — Critical Limitation](#gopher-client-support--critical-limitation)
  - [dict:// — Port Scanning and Banner Grabbing](#dict--port-scanning-and-banner-grabbing)
  - [file:// — Local File Read](#file--local-file-read)
  - [Why file:// Reaches Full-Response So Easily](#why-file-reaches-full-response-so-easily)
  - [DNS Rebinding — The TOCTOU Attack](#dns-rebinding--the-toctou-attack)
  - [HTTP Request Smuggling via SSRF](#http-request-smuggling-via-ssrf)
  - [SSRF to Redis/Memcached — Concrete Impact](#ssrf-to-redismemcached--concrete-impact)
  - [SSRF to Internal SMTP](#ssrf-to-internal-smtp)
  - [Detection Methodology](#detection-methodology)
  - [Defense \& Secure Coding](#defense--secure-coding)
  - [Common Mistakes](#common-mistakes)
  - [Variations and Edge Cases](#variations-and-edge-cases)
  - [Terminology Reference](#terminology-reference)
  - [Common Misconceptions](#common-misconceptions)
  - [Prioritization Guidance](#prioritization-guidance)
  - [Summary](#summary)

---

## Core Concept

Protocol smuggling exploits targets that don't speak HTTP at all — Redis, Memcached, SMTP — by controlling the **raw byte stream** sent to a socket, rather than relying on an HTTP client's auto-generated request format. These services read whatever bytes arrive and interpret them as their own native protocol, with zero awareness that "HTTP" was ever involved.

---

## Mental Model

> An HTTP client is a courier who hands over an envelope and says "please read this letter." Redis, SMTP, Memcached don't know what a "letter" is supposed to look like — they just read whatever's inside as a sequence of commands, line by line.

`gopher://` lets the attacker control exactly what goes inside that envelope, byte for byte, instead of the SSRF client generating a standard HTTP request around a URL fragment.

---

## Why Plain http:// Fails Against Redis

A normal `http://` SSRF only gives the attacker control over the **URL path** — the HTTP client library still generates the full request format (`GET /path HTTP/1.1\r\nHost: ...\r\n\r\n`) around it. `GET` happens to be a valid Redis command, so Redis attempts to interpret it — then chokes on `/path HTTP/1.1` as garbage arguments. Command fails; the missing piece is **full control over the raw byte sequence**, not just a URL fragment plugged into a client-generated template.

---

## gopher:// Syntax and Mechanics

```
gopher://target-host:port/_<URL-encoded-raw-bytes>
```

The `_` immediately after the port tells the gopher-handling client: everything after this is a raw data blob to send verbatim to the socket.

```
gopher://127.0.0.1:6379/_SET%20webshell%20%22malicious_value%22%0d%0a
```

Decoded: `SET webshell "malicious_value"\r\n` — sent as raw bytes, no HTTP wrapper. Redis parses it as a legitimate RESP command.

---

## gopher:// Client Support — Critical Limitation

Support is **client-dependent**, not universal:
- Python's `requests` does **not** support gopher by default
- PHP's `curl` extension historically did — this is why gopher-based SSRF-to-RCE chains are heavily associated with PHP applications in bug bounty writeups
- Many modern HTTP clients have dropped or never added gopher support specifically because of its abuse potential

**Confirm before building a payload:** craft a gopher URL whose "raw bytes" form a minimal valid HTTP request (`gopher://your-listener:80/_GET%20/canary%20HTTP/1.0%0d%0a%0d%0a`) and check your listener. A hit confirms the library forwards raw bytes as instructed; an immediate error (e.g. "unsupported scheme") means the path is dead — don't invest in RESP payload crafting first.

---

## dict:// — Port Scanning and Banner Grabbing

```
dict://internal-host:port/
```

Simpler than gopher — makes a raw connection to any port, often surfacing connection success/failure more distinctly than a plain `http://` request. Frequently used purely as a **port scanner disguised as a URL scheme**, feeding into Module 3's timing/error differential technique.

---

## file:// — Local File Read

```
file:///etc/passwd
file:///var/www/html/config.php
file:///proc/self/environ
```

If the URL-fetching library resolves `file://` (many do unless explicitly disabled), this is a **direct local filesystem read on the vulnerable server** — not a network request to another host at all. Often the most severe and most commonly overlooked vector, since attention gravitates toward gopher/dict as "the advanced stuff."

---

## Why file:// Reaches Full-Response So Easily

The features most likely to be `file://`-vulnerable (image-by-URL fetchers, PDF generators, "import from URL") are built to **take the fetched content and hand it back to the user** as their entire purpose. When pointed at `file:///etc/passwd`, the feature returns file contents by design — no additional exfil trick needed, because response-forwarding was already the intended behavior. Contrast with Redis-via-gopher, where the feature was never meant to show anything back, making those chains blind by nature and requiring separate confirmation.

---

## DNS Rebinding — The TOCTOU Attack

```python
resolved_ip = socket.gethostbyname(parsed.hostname)  # validation happens HERE
# ... time passes ...
requests.get(url)  # actual connection happens HERE, re-resolves DNS independently
```

Attacker controls DNS for their own domain with a very low TTL: first lookup (validation time) returns a safe public IP; second lookup (connection time, moments later) returns `127.0.0.1` or an internal IP.

```
T0: validate "attacker-domain.com" → 1.2.3.4 (public, passes check)
T1: connect to "attacker-domain.com" → re-resolves → 127.0.0.1 (attack)
```

**Common incomplete fix:** validating the resolved IP but passing the original **hostname string** (not the validated IP) to the actual request call. The validation and the connection perform two independent DNS lookups with a time gap between them — validating an IP you then discard achieves nothing. A correct fix must force the connection to use the exact validated IP (connection pinning), full implementation in Module 9.

---

## HTTP Request Smuggling via SSRF

If the SSRF-vulnerable server sits behind a reverse proxy/load balancer, and raw CRLF sequences can be injected into the forged request (via gopher-style raw byte control, or a reflected header value), a **second, hidden HTTP request** can be smuggled inside what the proxy treats as one request — potentially poisoning the connection for the next user or bypassing proxy-level access controls. SSRF's specific angle: it originates the smuggled traffic *from inside* the trusted network segment, which some smuggling defenses don't anticipate.

---

## SSRF to Redis/Memcached — Concrete Impact

- **Data manipulation**: `SET`/`DEL` on arbitrary keys — if the app trusts Redis-cached session tokens, feature flags, or auth decisions, application logic can be manipulated
- **Redis → RCE chain**: with `CONFIG SET dir` / `CONFIG SET dbfilename` permissions (common in under-hardened deployments), crafted `SET` + `SAVE` commands can write a malicious file to disk (webshell into a web-served directory, or an SSH `authorized_keys` file) — the well-known "Redis RCE via SSRF" chain
- **Memcached**: similar raw-protocol abuse, reading/writing cache keys, sometimes exposing session data or cached credentials

---

## SSRF to Internal SMTP

`gopher://` (sometimes even tolerant `http://`) pointed at an internal SMTP port (25/587) can smuggle raw SMTP commands (`MAIL FROM`, `RCPT TO`, `DATA`) — enabling internal email spoofing (mail appearing to originate from a trusted internal relay, bypassing spoofing checks that only apply to internet-facing mail flow) or further downstream command injection in vulnerable configurations.

---

## Detection Methodology

1. **Test scheme support explicitly** — try `file://`, `gopher://`, `dict://` alongside `http://`/`https://` on every confirmed injection point.
2. **Confirm gopher with a self-hosted listener first** before investing in RESP payload crafting.
3. **For DNS rebinding**, use a rebinding-capable authoritative DNS server with scriptable low-TTL responses — don't try to manually race the timing.
4. **For Redis**, a successful blind `SET` needs a follow-up confirmation read — via a second SSRF request against Redis-backed observable behavior, or by chaining to RCE where success becomes self-evident.

---

## Defense & Secure Coding

- **Scheme allowlisting at the client-library level** — explicitly restrict to `http`/`https` only, rejecting `file://`, `gopher://`, `dict://`, `ftp://` at the library configuration layer.
- **DNS pinning** — resolve once, validate, and force the actual connection to use that exact validated IP; never let the HTTP client independently re-resolve at connection time.
- **Network segmentation as defense-in-depth, not sole control** — Redis/Memcached/internal SMTP should require authentication regardless of network position (`requirepass`, protected mode) rather than relying purely on "it's internal" (the same positional-trust failure from Module 2).

---

## Common Mistakes

1. Assuming a client that blocks `http://127.0.0.1` also blocks `gopher://127.0.0.1` — different scheme, different validation code path.
2. Validating IP but passing the original hostname to the connection call — the DNS rebinding TOCTOU gap.
3. Assuming Redis/Memcached are "safe because internal" without checking if auth is actually configured.
4. Building a full gopher/RESP payload before confirming the library even processes the gopher scheme.

---

## Variations and Edge Cases

- **Gopher URL-encoding quirks**: some libraries double-decode or mangle `%0d%0a` differently — payload construction sometimes needs trial-and-error per library/version.
- **`php://filter` chains**: PHP-native fetching code can be vulnerable to language-specific wrapper schemes beyond the "standard" set covered here.
- **Partial DNS rebinding defenses**: some frameworks pin DNS for a single request but not across a redirect chain — a redirect can trigger fresh resolution, reopening the rebinding window mid-chain.

---

## Terminology Reference

| Term | Definition |
|---|---|
| **Protocol smuggling** | Using raw byte control (e.g. via gopher://) to send a non-HTTP protocol's native commands to a target that doesn't speak HTTP |
| **RESP** | Redis Serialization Protocol — Redis's plaintext, line-based command format |
| **DNS pinning** | Forcing a connection to use a specific, already-validated IP rather than re-resolving the hostname |
| **CRLF injection** | Injecting `\r\n` sequences to smuggle additional protocol-level content into a request |

---

## Common Misconceptions

1. **"If http:// SSRF to an internal port is blocked, the port is safe."** False — scheme-specific bypasses (gopher, dict, file) follow entirely different validation code paths.
2. **"Gopher-based attacks work against any URL-fetching SSRF."** False — gopher support is client-library dependent and must be confirmed first.
3. **"Validating a resolved IP prevents DNS rebinding."** False unless the validated IP is what's actually used for the connection — validating and discarding achieves nothing.
4. **"Internal services don't need authentication."** False — this positional-trust assumption is exactly what SSRF exploits; Redis/Memcached should require auth regardless of network position.

---

## Prioritization Guidance

When testing a newly confirmed SSRF with unknown internals, prioritize by effort-to-payoff, not theoretical severity:

1. **`file://` first** — lowest effort, potentially immediate full-response local file read.
2. **gopher/raw-protocol testing second** — high value, but conditional on the fetcher supporting the scheme and knowledge of what's listening internally.
3. **DNS rebinding last** — powerful against poorly implemented validation, but requires the most setup (attacker-controlled DNS infrastructure) and depends on a specific TOCTOU implementation flaw rather than being broadly applicable.

---

## Summary

Protocol smuggling moves SSRF exploitation beyond "the target speaks HTTP" by controlling raw bytes sent to a socket — gopher:// for arbitrary raw-protocol commands (Redis, Memcached, SMTP), dict:// for lightweight port scanning, and file:// for direct local filesystem read. file:// tends toward full-response almost automatically because the vulnerable features were already designed to return fetched content. DNS rebinding exploits the time gap between hostname validation and actual connection, defeated only by pinning the connection to the exact validated IP. None of these techniques are universally available — client library scheme support must be confirmed before investing in payload construction, and prioritization should favor low-effort, high-certainty wins (file://) before conditional, setup-heavy techniques (DNS rebinding).