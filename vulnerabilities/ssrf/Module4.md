# Module 4 — Cloud Metadata Endpoints

> Where SSRF stops being "internal recon" and becomes direct cloud account compromise.

---

## Table of Contents

- [Module 4 — Cloud Metadata Endpoints](#module-4--cloud-metadata-endpoints)
  - [Table of Contents](#table-of-contents)
  - [Core Concept](#core-concept)
  - [Mental Model](#mental-model)
  - [The Metadata Address and IMDSv1](#the-metadata-address-and-imdsv1)
  - [Why IMDSv1 Is the Easiest High-Value Target](#why-imdsv1-is-the-easiest-high-value-target)
  - [Real-World Example — Capital One](#real-world-example--capital-one)
  - [IMDSv2 — The URL-vs-Method/Headers Gap](#imdsv2--the-url-vs-methodheaders-gap)
  - [GCP and Azure — Static Header Model](#gcp-and-azure--static-header-model)
  - [Static Header vs. Stateful Token — Relative Strength](#static-header-vs-stateful-token--relative-strength)
  - [Data Exposed Beyond Credentials](#data-exposed-beyond-credentials)
  - [Exfiltrating Metadata via Blind SSRF](#exfiltrating-metadata-via-blind-ssrf)
  - [Detection Methodology](#detection-methodology)
  - [Exploitation Logic — Full Chain](#exploitation-logic--full-chain)
  - [Defense \& Secure Coding](#defense--secure-coding)
  - [Common Mistakes](#common-mistakes)
  - [Diagnosing a Blank/Failed Result](#diagnosing-a-blankfailed-result)
  - [Terminology Reference](#terminology-reference)
  - [Common Misconceptions](#common-misconceptions)
  - [Summary](#summary)

---

## Core Concept

Cloud metadata endpoints are internal-only-by-design services that hand out instance identity data — and, critically, temporary cloud credentials — to anything that can reach them, with the reachability itself treated as sufficient proof of legitimacy. SSRF that reaches this address converts a web bug into direct cloud account compromise.

---

## Mental Model

> Position *is* authentication. The metadata endpoint's entire security model is: "if you can reach this address, you must be the instance itself — here are its credentials, no login required."

The precondition for this entire attack category: the SSRF-vulnerable code must run somewhere with network-level access to its own metadata service — true by default for most VM, container, and even many serverless workloads. **Any confirmed SSRF should immediately be tested against `169.254.169.254`** before anything else, since it converts a "meh, internal recon" finding into potential critical severity.

---

## The Metadata Address and IMDSv1

`169.254.169.254` — identical across AWS, GCP, and Azure. A deliberately reserved **link-local** address (RFC 3927), non-routable outside the local link — which is exactly why it evades normal "internal network" firewall rules (ties back to Module 1's link-local reasoning).

**AWS IMDSv1** (plain, unauthenticated):

```
GET http://169.254.169.254/latest/meta-data/
GET http://169.254.169.254/latest/meta-data/iam/security-credentials/
GET http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>
```

The final request returns `AccessKeyId`, `SecretAccessKey`, `SessionToken` — a live, valid temporary AWS credential for the instance's attached IAM role. No authentication required.

---

## Why IMDSv1 Is the Easiest High-Value Target

Most SSRF primitives are **"URL-in, GET-out"** — the attacker controls the destination string; method and headers are hardcoded by the developer. IMDSv1 requires *nothing* beyond a plain GET — no custom headers, no special method, no protocol trickery. This is the lowest capability bar of any high-value internal target (compare to Redis via gopher://, Module 5, which requires raw protocol smuggling).

---

## Real-World Example — Capital One

**Chain:** misconfigured WAF (itself an EC2 instance with an overly permissive IAM role) had an SSRF vulnerability → attacker reached the WAF instance's own IMDSv1 endpoint → stole IAM credentials → credentials permitted S3 list/read → ~100M customer records exposed.

The underlying SSRF was not sophisticated. Severity came entirely from **what the stolen credentials could reach** — the reachability argument, not the bug's technical complexity.

---

## IMDSv2 — The URL-vs-Method/Headers Gap

```
# Step 1: obtain a token — requires PUT + custom header
PUT http://169.254.169.254/latest/api/token
Headers: X-aws-ec2-metadata-token-ttl-seconds: 21600

# Step 2: use the token
GET http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>
Headers: X-aws-ec2-metadata-token: <token-from-step-1>
```

**Key gap:** "control a URL" ≠ "control an HTTP method + headers." IMDSv2 doesn't try to block the destination (impossible — it must remain reachable from the instance). It moves the requirement from "control a URL" to **"control a multi-step, stateful HTTP interaction with a specific header"** — which most basic SSRF primitives cannot do.

**IMDSv2 is not unbypassable.** It raises the bar for *basic* SSRF specifically. It does not stop:
- SSRF via a feature that already does full request forwarding (method/headers as part of legitimate function)
- Certain redirect chains or request-smuggling primitives (edge cases)
- Instances that still have **IMDSv1 enabled** (opt-out historically, not always disabled by default)

**Correct framing:** "IMDSv2 raises the capability bar; whether this SSRF clears that bar depends on exactly what the vulnerable code lets me control" — a testable question, not an assumption.

---

## GCP and Azure — Static Header Model

| Provider | Metadata Address | Required Header | Basic-SSRF Defense |
|---|---|---|---|
| AWS (IMDSv1) | `169.254.169.254` | None | None |
| AWS (IMDSv2) | `169.254.169.254` | `X-aws-ec2-metadata-token` (via PUT) | Multi-step + custom header |
| GCP | `.../computeMetadata/v1/` | `Metadata-Flavor: Google` | Custom header required |
| Azure | `.../metadata/instance` | `Metadata: true` | Custom header required |

---

## Static Header vs. Stateful Token — Relative Strength

A **single static, known-value header** blocks pure URL-only SSRF, but is trivially reproducible the moment an SSRF primitive gives *any* header control (webhook configs, proxy features, some XXE constructions) — the attacker just hardcodes the known name/value.

A **stateful token** (IMDSv2) requires the primitive to support an entire **request-response-reuse sequence**: PUT → capture response → reuse value in a second request. Most SSRF primitives that can add a static header still can't do multi-request state management.

**Conclusion:** GCP/Azure's single-header model is real defense-in-depth against basic SSRF, but weaker than IMDSv2 specifically against SSRF primitives with header-injection capability.

---

## Data Exposed Beyond Credentials

- **Instance identity** (instance ID, region, AMI ID) — fingerprinting/recon
- **User-data scripts** (`/latest/user-data`) — frequently contain **hardcoded secrets, DB passwords, startup config**, often more directly damaging than IAM credentials, and sometimes not behind the same IMDSv2-style protection
- **Network configuration** — internal IPs, security group info
- **IAM role name**, and full credentials if unprotected

---

## Exfiltrating Metadata via Blind SSRF

A single blind SSRF request **cannot by itself** exfiltrate credential content via DNS — it has no mechanism to read a response and re-encode it into a second request's hostname. Requires a **chaining primitive**:

1. A second bug (e.g., SSTI) that captures the fetched response into a variable, then builds a second outbound request using that variable as a subdomain (`{stolen_key}.attacker-canary.com`)
2. A feature that legitimately chains "fetch a URL, then use the response to build another URL"
3. Redirect-based chaining, where the target 302-redirects using content it just fetched

**Without chaining:** blind SSRF into metadata proves reachability only — still a strong severity argument (Module 3), but not literal credential exfiltration. Defensible framing: *"I couldn't extract the credential itself, but proved this endpoint is reachable and [unauthenticated / returns 200] — an attacker with a slightly more capable primitive could fully exfiltrate."*

---

## Detection Methodology

1. Confirm target is cloud-hosted (response headers, IP ranges — or just test, it costs nothing).
2. Test IMDSv1 first — plain GET to `/latest/meta-data/`.
3. If blocked, check whether the SSRF primitive supports method/header control before assuming full failure — note explicitly rather than guessing.
4. Check `/latest/user-data` separately — may not share the same protection as IAM credentials.
5. If blind, use OOB (Module 3) to prove reachability to the metadata address specifically — a stronger argument than generic internal-IP reachability, since the target is nameable and universally high-value.

---

## Exploitation Logic — Full Chain

```
SSRF confirmed
    ↓
Cloud-hosted? → yes
    ↓
GET /latest/meta-data/iam/security-credentials/<role>
    ↓
   200 + creds → IMDSv1, full compromise, use stolen creds against AWS API
    ↓
   Blocked → check if primitive supports PUT+header
   → yes: attempt IMDSv2 flow
   → no: document reachability only, argue severity via reachability framing
```

---

## Defense & Secure Coding

- **Enforce IMDSv2 exclusively** (`HttpTokens: required`) — default policy, not opt-in.
- **IAM role least-privilege** — scope roles so credential theft doesn't equal total access (Capital One's severity was amplified by an overly broad WAF-instance role).
- **Network-level blocking as defense-in-depth** — block `169.254.169.254` at egress/iptables for workloads with no legitimate need to reach it, beyond relying on IMDSv2 alone.
- **Avoid secrets in user-data** — treat it as reachable by anything on the box, not just SSRF.

---

## Common Mistakes

1. Not testing metadata reachability on a confirmed SSRF at all — treating it as "just internal recon."
2. Assuming IMDSv2 fully closes the issue without checking what the specific primitive can actually control.
3. Stopping after one failed IMDSv1 request without checking user-data or provider-specific alternate endpoints.
4. (Defender-side) attaching overly broad IAM roles to internet-facing instances — raises the severity of any downstream SSRF finding.

---

## Diagnosing a Blank/Failed Result

A blank PDF/response when targeting metadata via a headless-browser fetcher has **at least two distinct causes** — don't default to "not vulnerable":

1. **Rendering limitation** — raw JSON/plaintext often won't display in a rendered PDF. Test with an internal **plaintext-returning** target vs. an internal **HTML-returning** target: if plaintext also renders blank but HTML renders fine, the fetch likely succeeded — you just can't see JSON output.
2. **Fetch actually failed** — e.g., IMDSv2 requires PUT-first and a GET-only primitive received a 401; this can look identical to "succeeded but unrenderable" from the outside. Distinguish via generation logs/errors, or a second injection point that returns raw text instead of rendering, before concluding either way.

---

## Terminology Reference

| Term | Definition |
|---|---|
| **IMDS** | Instance Metadata Service — per-instance cloud metadata/credential endpoint |
| **Link-local address** | Address valid only on the local network segment, non-routable — e.g. `169.254.169.254` |
| **IMDSv1 / IMDSv2** | AWS's unauthenticated vs. token-authenticated metadata service versions |
| **User-data** | Instance boot/config script, often containing embedded secrets |

---

## Common Misconceptions

1. **"IMDSv2 makes metadata theft impossible."** False — it raises the capability bar for basic URL-only SSRF; primitives with method/header control or full request forwarding can still complete the flow.
2. **"A single required header is as strong as a stateful token."** False — a static header is trivially reproducible with any header-injection capability; a stateful token requires multi-request state management, a much higher bar.
3. **"Blind SSRF into metadata can't be exploited without full response visibility."** Partially false — reachability alone is often sufficient for a strong severity argument, and chaining primitives can sometimes achieve full exfiltration.
4. **"A blank result means the metadata fetch failed."** False — it may mean the fetch succeeded but the fetcher (e.g., headless renderer) couldn't display the content type returned.

---

## Summary

Cloud metadata endpoints convert SSRF from a network-position problem into direct credential theft, because reachability alone is treated as authentication. IMDSv1's plain-GET design makes it the lowest-capability-bar high-value target in the entire curriculum. IMDSv2 and GCP/Azure's header requirements defend against the common "URL-in, GET-out" SSRF shape by requiring method/header control the attacker's primitive usually lacks — but none of these are absolute; the real question is always what the specific SSRF primitive can control. Cloud metadata reachability is an especially strong severity argument because the target is standardized and consistently high-value across virtually every cloud-hosted target, unlike generic internal-network reachability.