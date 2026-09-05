# Module 9 — Defense in Depth

> Assembling every incomplete fix from Modules 1–8 into a complete, layered defense — and understanding why no single layer is ever sufficient alone.

---

## Table of Contents

- [Module 9 — Defense in Depth](#module-9--defense-in-depth)
  - [Table of Contents](#table-of-contents)
  - [Core Concept](#core-concept)
  - [Mental Model](#mental-model)
  - [Why Perfect Input Validation Still Isn't Sufficient Alone](#why-perfect-input-validation-still-isnt-sufficient-alone)
  - [Layer 1 — Allowlist, Properly Implemented](#layer-1--allowlist-properly-implemented)
  - [Layer 2 — DNS Pinning and Manual Redirect Validation](#layer-2--dns-pinning-and-manual-redirect-validation)
  - [Layer 3 — Network-Level Segmentation](#layer-3--network-level-segmentation)
  - [Layer 4 — IMDSv2 Enforcement at the Platform Level](#layer-4--imdsv2-enforcement-at-the-platform-level)
  - [Layer 5 — Monitoring and Detection](#layer-5--monitoring-and-detection)
  - [Secure Coding Patterns by Language](#secure-coding-patterns-by-language)
  - [Code Review Methodology for SSRF](#code-review-methodology-for-ssrf)
  - [Terminology Reference](#terminology-reference)
  - [Common Misconceptions](#common-misconceptions)
  - [Curriculum Capstone](#curriculum-capstone)
  - [Summary](#summary)

---

## Core Concept

Every "improved" defense across this curriculum (Module 2's resolved-IP check, Module 5's DNS pinning gap, Module 6's blocklist attempts) was eventually shown to have a remaining gap. This module assembles the complete layered defense, where each layer covers what the others might miss.

---

## Mental Model

> A single defense is a single point of failure. Defense in depth is a series of doors, each locked with a different key, such that defeating one door doesn't grant access — it just reveals the next door.

---

## Why Perfect Input Validation Still Isn't Sufficient Alone

Even flawless validation logic only defends **the one code path it's actually called on**. It fails to address:

- A developer adding a new fetch code path later and forgetting to call the validator
- A third-party library update silently changing DNS resolution behavior underneath it
- A different vulnerability class entirely (XXE, SVG upload, GraphQL federated resolver) triggering a fetch through infrastructure nobody thought to route through the validator
- The validator correctly restricting the wrong boundary (e.g., blocking internal IPs but not realizing link-local addresses need separate handling — Module 1's exact lesson)

**Core argument for defense in depth:** input validation depends on every future developer remembering to invoke it correctly, forever, across every current and future code path — an organizational reliability problem, not just a code correctness problem. Network segmentation, platform-level enforcement, and monitoring work **even when someone forgets to call the validator**.

---

## Layer 1 — Allowlist, Properly Implemented

```python
import ipaddress, socket
from urllib.parse import urlparse

ALLOWED_HOSTS = {"api.trusted-partner.com", "cdn.ourcompany.com"}

def is_safe_url(url: str) -> tuple[bool, str]:
    parsed = urlparse(url)

    if parsed.scheme not in ("https",):
        return False, "scheme not allowed"

    if parsed.hostname not in ALLOWED_HOSTS:
        return False, "host not in allowlist"

    try:
        resolved_ip = socket.gethostbyname(parsed.hostname)
    except socket.gaierror:
        return False, "DNS resolution failed"

    ip = ipaddress.ip_address(resolved_ip)
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
        return False, "resolves to disallowed IP range"

    return True, resolved_ip
```

**Why resolved-IP validation still matters even with a tight hostname allowlist:** a fully trusted hostname's DNS is still mutable — the partner's DNS could be compromised, misconfigured, or briefly point elsewhere during infrastructure migration. The security boundary is the resolved address, not the name — the same "validate the resolved value, not the string" principle from Module 6, applied even to already-allowlisted inputs.

---

## Layer 2 — DNS Pinning and Manual Redirect Validation

```python
import requests

def fetch_pinned(url: str) -> requests.Response:
    is_safe, result = is_safe_url(url)
    if not is_safe:
        raise ValueError(f"Blocked: {result}")

    validated_ip = result
    parsed = urlparse(url)

    pinned_url = url.replace(parsed.hostname, validated_ip, 1)
    return requests.get(
        pinned_url,
        headers={"Host": parsed.hostname},  # preserves vhost/TLS-SNI correctness
        verify=True,
        allow_redirects=False,  # never follow automatically
    )
```

`Host` header is preserved because the TCP connection goes to the resolved IP, but the header tells the receiving server which virtual host/resource is actually being requested — pinning the connection doesn't mean discarding the hostname entirely.

**Manual redirect validation** — never let the HTTP client's built-in redirect-following run automatically, since that bypasses validation on every hop after the first:

```python
def fetch_with_validated_redirects(url: str, max_redirects: int = 3) -> requests.Response:
    current_url = url
    for _ in range(max_redirects):
        is_safe, result = is_safe_url(current_url)
        if not is_safe:
            raise ValueError(f"Blocked at hop: {result}")

        response = fetch_pinned(current_url)

        if response.status_code in (301, 302, 303, 307, 308):
            current_url = response.headers["Location"]
            continue  # re-validate this new URL before following it
        else:
            return response

    raise ValueError("Too many redirects")
```

Include a `max_redirects` cap to prevent resource exhaustion from an attacker-controlled redirect loop.

---

## Layer 3 — Network-Level Segmentation

Exists specifically for the "developer forgot to call the validator" scenario:

- **Egress firewall rules** at host/container level — explicitly deny outbound traffic to RFC 1918 ranges, loopback, and `169.254.169.254` from workloads with no legitimate need to reach them, enforced by infrastructure regardless of application code.
- **Dedicated "fetcher" service pattern** — route ALL URL-fetching functionality through one isolated internal service with its own tightly restricted egress, so even a completely new, unvalidated code path in the main application can't directly reach internal targets.

---

## Layer 4 — IMDSv2 Enforcement at the Platform Level

Enforce `HttpTokens: required` on every instance (disabling IMDSv1 entirely) as **infrastructure policy**, not dependent on any application code being correct — a single platform-level setting protecting against every application-level SSRF bug simultaneously, high-leverage precisely because it doesn't rely on developers remembering anything.

---

## Layer 5 — Monitoring and Detection

Assume something eventually gets through:

- **Log and alert on outbound requests** to private IP ranges, `169.254.169.254`, or unexpected schemes (`gopher://`, `file://`) — these should almost never occur legitimately, making them high-signal.
- **Rate-limit and alert on repeated failed/blocked fetch attempts** from a single user/session — consistent with active SSRF probing (the discovery methodology from Module 2, visible defender-side as anomalous behavior).

---

## Secure Coding Patterns by Language

| Language/Framework | Key Pattern |
|---|---|
| Python | Validate resolved IP + pin connection; avoid `requests` following redirects blindly |
| Node.js | Libraries like `ssrf-req-filter`, or equivalent IP validation before `axios`/`fetch`; Node's DNS resolution is also rebinding-susceptible |
| Java | Disable `XMLInputFactory` external entity processing by default; validate `URL`/`URLConnection` targets before `openConnection()` |
| PHP | Explicitly restrict `curl`'s allowed protocols via `CURLOPT_PROTOCOLS` — closes Module 5's PHP-specific gopher risk |
| Go | Custom `net.Dialer.Control` to validate resolved IPs before the connection completes — relatively clean dial-time DNS pinning |

---

## Code Review Methodology for SSRF

1. Grep for outbound request functions (`requests.get`, `axios`, `fetch`, `curl_exec`, `URLConnection`, XML parser instantiation).
2. For each, trace backward: is any part of the destination attacker-influenced (directly or indirectly — webhook config, XML content, GraphQL argument, SVG upload)?
3. If yes — does validation check the resolved IP, or just the string?
4. Is the validated value what's actually used for the connection, or could the original string reach the connector via a different path?
5. Are redirects followed automatically, or manually re-validated per hop?
6. Is scheme restricted to an explicit allowlist, or just prefix/substring-checked?
7. Does network-level segmentation exist as a backstop in case this specific validation has a bug?

---

## Terminology Reference

| Term | Definition |
|---|---|
| **Defense in depth** | Layering independent controls so that defeating one doesn't grant full access |
| **Connection pinning** | Forcing a network connection to use a specific, already-validated IP address |
| **Fetcher service pattern** | Routing all URL-fetching functionality through one isolated, restricted-egress internal service |
| **High-signal alert** | A monitored event with very low legitimate-traffic false-positive rate, e.g. any request to `169.254.169.254` |

---

## Common Misconceptions

1. **"A well-implemented validation function is our entire SSRF defense."** False — it's a single control dependent on every future developer invoking it correctly across every current and future code path; defense in depth compensates for inevitable gaps.
2. **"Allowlisting the hostname makes resolved-IP validation redundant."** False — DNS for an allowlisted hostname can still be compromised, misconfigured, or migrate unexpectedly.
3. **"Turning `allow_redirects` back on is fine once the initial URL is validated."** False — each redirect hop needs the full validation + resolution + pinning process independently.
4. **"IMDSv2 enforcement makes application-level SSRF defenses unnecessary."** False — layers address different failure modes; platform-level enforcement is a backstop, not a substitute for reducing SSRF surface in application code.

---

## Curriculum Capstone

XSS abuses a victim's browser to perform an unintended action; SSRF abuses **the server itself** to make network requests the attacker shouldn't control. Because the server sits inside trust boundaries a browser never could, SSRF can reach resources that are invisible or inaccessible from the public internet — internal APIs, cloud metadata, loopback-bound services. The core lesson across all nine modules: stop thinking about SSRF as "a `url` parameter" and instead recognize **any attacker-controlled input that can cause the server to initiate a network connection** — webhooks, XML documents, SVG uploads, GraphQL arguments, and inputs not yet invented.

---

## Summary

No single SSRF defense is sufficient alone, because each addresses a different failure mode: allowlisting closes the "any string works" problem, resolved-IP validation closes the DNS-mutability problem, connection pinning and manual redirect validation close the TOCTOU gap, network segmentation and IMDSv2 enforcement provide platform-level backstops independent of application code correctness, and monitoring catches whatever still gets through. The unifying discipline, carried from Module 1 through this final module: treat SSRF as an architectural risk inherent to any feature where attacker-controlled input can cause a server-side network request — not a single bug to patch once and forget.