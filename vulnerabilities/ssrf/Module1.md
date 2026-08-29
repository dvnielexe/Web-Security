# Module 1 — SSRF Foundations

> Server-Side Request Forgery: the attacker doesn't send the malicious request — they convince a trusted server to send it for them.

---

## Table of Contents

- [Module 1 — SSRF Foundations](#module-1--ssrf-foundations)
  - [Table of Contents](#table-of-contents)
  - [Core Definition](#core-definition)
  - [Mental Model](#mental-model)
  - [SSRF vs XSS — Trust Boundary Comparison](#ssrf-vs-xss--trust-boundary-comparison)
  - [Why It Exists (Technical Root Causes)](#why-it-exists-technical-root-causes)
  - [The "No Internal Network" Myth](#the-no-internal-network-myth)
  - [Anatomy of a Weak Defense (Case Study)](#anatomy-of-a-weak-defense-case-study)
  - [Five Constraints a Real Fix Must Cover](#five-constraints-a-real-fix-must-cover)
  - [Detection Methodology (Preview)](#detection-methodology-preview)
  - [Secure Design Principles](#secure-design-principles)
  - [Terminology Reference](#terminology-reference)
  - [Common Misconceptions](#common-misconceptions)
  - [Bug Bounty Reference](#bug-bounty-reference)
  - [Summary](#summary)

---

## Core Definition

**SSRF (Server-Side Request Forgery)** occurs when an attacker can induce a server-side application to make HTTP (or other protocol) requests to an unintended destination — including internal services, cloud metadata endpoints, or arbitrary external hosts — by controlling all or part of a URL the server fetches on the attacker's behalf.

**CWE Reference:** CWE-918 (Server-Side Request Forgery)

---

## Mental Model

> **A browser is a guest with a keycard. A server is staff with a master key standing inside the building.**
>
> XSS steals the guest's keycard — you can act as the victim, within the victim's existing access.
> SSRF hands you the staff member's legs and says "walk wherever you want, I'll tell you where."

The danger of SSRF isn't payload sophistication — SSRF payloads are often just a URL. The danger is **inherited network position**. Firewalls, VPC boundaries, and "internal-only" trust assumptions are drawn around *the server*, not around *the browser*. Controlling what URL the server fetches means you inherit whatever position that server sits in.

---

## SSRF vs XSS — Trust Boundary Comparison

| | XSS | SSRF |
|---|---|---|
| Who makes the forged request | Victim's **browser** | **The server itself** |
| What trust is abused | Victim's session / cookies | Server's **network position** |
| Where the request lands | Back at the target app, in victim's context | Anywhere the server can route to — internal APIs, cloud metadata, localhost services, other VPC hosts |
| Attacker's leverage | "I can act as the victim" | "I can make the trusted machine act as me, from inside the perimeter" |
| Typical payload complexity | Context-aware script/markup | Often just a crafted URL |

---

## Why It Exists (Technical Root Causes)

1. **HTTP client libraries have no concept of "untrusted origin."** `requests.get(user_input)`, `axios.get(userUrl)`, etc. will resolve and connect to `169.254.169.254` exactly as readily as `https://api.stripe.com`. The library doesn't know or care where the string came from.
2. **DNS resolution happens at request-time, not validation-time.** A hostname that passes a check can resolve to something entirely different by the time the actual connection is made (seed concept for DNS rebinding — Module 6).
3. **Outbound traffic is under-inspected relative to inbound traffic.** Enormous effort goes into WAFs, input validation, and auth on the *inbound* path. The *outbound* path — "what is my server allowed to talk to" — is often unexamined, because historically the server wasn't thought of as an attacker-controlled traffic origin.

**The general pattern that creates SSRF surface:** any feature where "user input → server issues an HTTP request using it" exists. Webhook validators, "import from URL," PDF/image generators fetching a source, link preview generators, SSO metadata fetchers — structurally identical attack surface, repeated across dozens of feature categories.

---

## The "No Internal Network" Myth

Claim: *"Our server has strict egress rules and can't reach the internal VPC, so we're not vulnerable to SSRF."*

**False.** Egress restrictions reduce risk but don't eliminate it. Two categories of target persist regardless of VPC segmentation:

1. **The server's own network identity.** It can still make requests as a trusted backend origin — hitting external services/partner APIs that allowlist by IP, or the cloud provider's own control-plane APIs.
2. **Local-to-the-instance resources**, which exist at a lower layer than VPC routing:
   - **Loopback services** (`127.0.0.1` / same-host ports)
   - **Cloud metadata endpoints** — `169.254.169.254` is a **link-local** address, always reachable from the instance itself, independent of VPC firewall rules (full depth in Module 4)

Credentials obtained from a metadata endpoint don't just leak "internal info" — they let the attacker impersonate **the server's actual cloud identity** to the provider's own API. That's a fundamentally larger blast radius than a leaked internal admin panel, and it's why "well-segmented" networks were still catastrophically breached via SSRF (see: Capital One 2019, Module 4).

---

## Anatomy of a Weak Defense (Case Study)

```python
# Looks like a security check. Isn't one.
def validate_webhook(url):
    if url.startswith("http://") or url.startswith("https://"):
        response = requests.get(url, timeout=5)
        return response.status_code == 200
```

This validates the **shape** of the input (scheme prefix) and constrains **nothing** that actually matters:

- ❌ Destination (host/IP) — unconstrained
- ❌ DNS resolution — unchecked, and re-resolved at request time
- ❌ Redirects — none followed here, but nothing prevents chaining
- ❌ Ports/services — unconstrained
- ❌ Response handling — blindly trusted

**Second example — blocklist with multiple compounding gaps:**

```python
@app.route('/fetch-avatar')
def fetch_avatar():
    url = request.args.get('image_url')
    parsed = urlparse(url)
    if parsed.hostname not in ['localhost', '127.0.0.1']:
        img_data = requests.get(url, allow_redirects=True, timeout=10).content
        return Response(img_data, mimetype='image/png')
    return "Blocked", 403
```

Flaws:
- Blocklist only matches two exact strings — misses `127.0.0.2`, decimal/octal/hex IP encodings, IPv6 `::1`, private ranges (`10.x`, `172.16.x`, `192.168.x`), and any hostname that merely *resolves* to those ranges
- `parsed.hostname` is validated as a **string**, not the resolved IP — DNS can point anywhere by connection time
- `allow_redirects=True` means an initial "safe" URL can 302 to an internal target after the check passes
- No metadata-endpoint (`169.254.169.254`) blocking
- No port restriction — any internal service on any port is reachable
- Response is returned directly to the attacker — this is **full-response SSRF**, usable as a live proxy for internal reconnaissance/data exfiltration
- Enables port scanning / service discovery via response timing and content differences

---

## Five Constraints a Real Fix Must Cover

| Constraint | What Fails Without It |
|---|---|
| **Destination validation** | Blocklists miss encodings; only resolved-IP allowlisting is reliable |
| **DNS resolution control** | String-based hostname checks bypassed by DNS rebinding |
| **Redirect handling** | Server-side redirects bypass pre-request validation entirely |
| **Port/service restriction** | Internal services on non-standard ports remain reachable |
| **Response exposure control** | Determines blind vs semi-blind vs full-response severity |

---

## Detection Methodology (Preview)

Full methodology arrives in Module 2–3, but the starting question for any feature is:

> **"Does the server ever fetch a URL, or part of a URL, that I influence?"**

Common injection points to scan for: webhook/callback URL fields, "import from link" features, file/image/avatar-by-URL upload, PDF/document generation from a URL, link unfurling/preview, SSO/OAuth metadata URL config, XML external entity references (XXE-as-SSRF), API integrations where the user supplies an endpoint.

---

## Secure Design Principles

- **Allowlist resolved IPs, never blocklist hostnames.** The input space of "bad" hosts is unbounded; the set of "known-good" destinations is small and enumerable.
- **Validate after DNS resolution, and re-validate on redirect** (pin the resolved IP, don't just check the hostname string once).
- **Disable or tightly control redirect-following** on server-initiated fetches.
- **Enforce metadata protections at the platform level** — e.g., IMDSv2 token requirement (AWS), not just application-layer filtering.
- **Segment "URL-fetching" capability itself** — route these requests through an isolated proxy/service with its own restricted egress, so even a full bypass has a contained blast radius.
- **Never return raw response bodies/status directly to the requesting user** where avoidable — this is what turns blind SSRF into full-response SSRF.

---

## Terminology Reference

| Term | Definition |
|---|---|
| **SSRF** | Server-Side Request Forgery — server induced to make attacker-influenced requests |
| **Blind SSRF** | No response/data returned to attacker; detected out-of-band (Module 3) |
| **Full-response SSRF** | Response body/data returned directly to attacker |
| **Link-local address** | Address valid only on a local network segment, not routed — e.g. `169.254.169.254` |
| **Confused deputy** | A privileged program tricked into misusing its authority on behalf of an attacker |
| **DNS rebinding** | Changing what a hostname resolves to between validation-time and request-time |
| **IMDS** | Instance Metadata Service (cloud provider's per-instance metadata/credential endpoint) |

---

## Common Misconceptions

1. **"Strict egress rules = SSRF-safe."** False — link-local metadata and loopback services remain reachable (see above).
2. **"Scheme checking (http/https only) is a meaningful control."** False — it constrains the wrapper, not the destination.
3. **"Blind SSRF is low severity because there's no visible output."** False — blind SSRF can still reach metadata endpoints, trigger internal actions, or enable port scanning via timing; severity is about *reachability*, not *visibility* (full treatment in Module 3).
4. **"SSRF is basically just an internal-network problem."** False — internal reconnaissance is only one branch; metadata-endpoint credential theft often has larger, cloud-account-wide impact.

---

## Bug Bounty Reference

- **Capital One (2019):** SSRF against a misconfigured WAF allowed metadata-endpoint credential theft, leading to S3 bucket access and a breach of ~100M+ customer records — the canonical case for "SSRF → cloud credential theft → mass data breach." (Full case study in Module 4.)

---

## Summary

SSRF abuses the **server's network position**, not a victim's session — the direct structural counterpart to how XSS abuses a browser's session. The core developer failure is **validating input shape (scheme, string hostname) instead of resolved destination**. "No internal network access" is not a safety guarantee, because link-local metadata and loopback resources sit outside normal VPC routing entirely. Any real defense must control destination, DNS resolution, redirects, ports, and response exposure — all five, since a partial fix leaves the remaining surface fully exploitable.