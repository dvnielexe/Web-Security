# Module 3 — Blind SSRF

> No response, no error, no visible signal — detecting and proving SSRF entirely through out-of-band side effects.

---

## Table of Contents

- [Module 3 — Blind SSRF](#module-3--blind-ssrf)
  - [Table of Contents](#table-of-contents)
  - [Core Concept](#core-concept)
  - [Mental Model](#mental-model)
  - [Why Blind SSRF Still Produces Signal](#why-blind-ssrf-still-produces-signal)
  - [Blind vs. Semi-Blind vs. Full-Response](#blind-vs-semi-blind-vs-full-response)
  - [Out-of-Band Detection Tooling](#out-of-band-detection-tooling)
  - [Detection Methodology](#detection-methodology)
  - [The False-Positive Trap](#the-false-positive-trap)
  - [Semi-Blind Port Scanning via Timing](#semi-blind-port-scanning-via-timing)
  - [Defense — Eliminating the Oracle](#defense--eliminating-the-oracle)
  - [Common Mistakes](#common-mistakes)
  - [Variations and Edge Cases](#variations-and-edge-cases)
  - [Terminology Reference](#terminology-reference)
  - [Common Misconceptions](#common-misconceptions)
  - [Bug Bounty Reporting Note](#bug-bounty-reporting-note)
  - [Summary](#summary)

---

## Core Concept

Blind SSRF: the vulnerable feature fetches an attacker-controlled URL, but returns **no differentiable signal** in the HTTP response — no body content, no distinguishing status code, no timing difference. Detection requires shifting from "read the response" to "detect out-of-band side effects" of the fetch itself.

---

## Mental Model

> **Full-response SSRF is shouting into a room and hearing an echo. Blind SSRF is shouting into a room with no echo — but the room still exists, and things inside it still moved.**

Stop looking at the HTTP response. Look for side effects on a **different channel** than the one the vulnerable request travels on — DNS lookups, timing deltas, secondary listeners on another protocol entirely.

---

## Why Blind SSRF Still Produces Signal

Even when the app discards the response, the underlying network operations still physically occur:

1. **DNS resolution** happens first, regardless of what the app does with the result afterward
2. **TCP connection attempt** — timing varies measurably based on open/closed/filtered port state
3. **Wait for response or timeout** — differs by target reachability

None of these require the app to show you anything — they are side effects of the network stack itself.

**Why DNS is the most reliable OOB channel:** DNS resolution is treated as infrastructure-level, not application-level, so it's rarely subject to the same outbound firewall rigor as HTTP/TCP. Even in networks with aggressive egress filtering, DNS usually still has to work — otherwise nothing on the network could resolve any hostname at all. If the HTTP fetch itself gets blocked, the DNS lookup that precedes it often still fires.

---

## Blind vs. Semi-Blind vs. Full-Response

| Type | What You Get Back | How You Detect It | Example |
|---|---|---|---|
| **Full-response** | Complete response body/data | Directly in the HTTP response | Image proxy returning fetched bytes |
| **Semi-blind** | No data, but a differential signal (status, timing, error type) | Response-side inference, no OOB needed | Webhook validator returning `400` for unreachable, `200` for reachable |
| **Blind** | Nothing differentiable at all | Out-of-band only (DNS/HTTP hit on external listener) | Webhook validator always returns `200 OK` regardless of outcome |

Severity should be judged by **reachability** (what the fetch can touch), not **visibility** (what you can see in the response). This distinction is the core rebuttal to "it's blind, so it's low impact."

---

## Out-of-Band Detection Tooling

- **Burp Collaborator** / **interactsh** (open-source equivalent): generates a unique, disposable subdomain (e.g. `x7f3k2.oast.site`) and logs every DNS query, HTTP hit, or SMTP connection it receives, from any source, over any protocol.
- **Uniqueness matters**: use a distinct payload domain per test case — reusing one domain across multiple injection points makes hits impossible to attribute.

---

## Detection Methodology

1. Generate a unique OOB payload domain per test case.
2. Insert it into the suspected injection point.
3. Trigger the vulnerable feature.
4. Poll the OOB log for:
   - **DNS query** → minimum confirmation ("something resolved this hostname")
   - **HTTP hit** → stronger proof — confirms the full fetch happened
   - **Timestamp correlation** → hit occurs shortly after the trigger action, not at a random unrelated time

---

## The False-Positive Trap

A lone DNS hit is **necessary but not sufficient** proof. Corporate **secure email gateways** (Proofpoint, Mimecast, etc.) often pre-fetch/detonate URLs found in email content before delivery — if your OOB payload ever lands in an email field (share-via-email, password reset links), the gateway itself generates unrelated DNS/HTTP hits.

**Mitigation:** require **timestamp correlation with your specific trigger action**, and ideally confirm the hit's **source IP falls within the target's known infrastructure range**. "I saw a hit" is weak; "I saw the hit, correlated to my action, from the target's IP range" is report-ready.

---

## Semi-Blind Port Scanning via Timing

With semi-blind SSRF, the application's response timing/status becomes a self-contained port-scanning oracle — no OOB infrastructure required:

| Port State | Behavior | App's Response |
|---|---|---|
| **Closed** | Connection refused immediately | Fast error (~ms), often distinct message |
| **Filtered** | No response, hangs until timeout | Slow — full timeout duration before error |
| **Open, non-HTTP service** | Connects, but doesn't speak HTTP | Different timing/error, connection succeeded |
| **Open, HTTP service** | Full HTTP round-trip | Fastest "success," distinguishable content-length/status |

This lets an attacker build a **complete internal port map** — hosts, open ports, likely services — purely from timing buckets and error differences, with zero response body content. This is why "no data leak" ≠ "low severity": it's a reconnaissance oracle, and recon is frequently step one of a longer attack chain.

---

## Defense — Eliminating the Oracle

Beyond Module 2's destination validation, blind-SSRF-specific defense requires **normalizing every response path**:

```python
def fetch_safely(url):
    if not is_safe_url(url):
        raise ValueError("Blocked")
    try:
        resp = requests.get(url, timeout=5)
        return {"status": "processed"}   # identical shape regardless of outcome
    except requests.RequestException:
        return {"status": "processed"}   # do NOT leak timeout vs refused vs success
```

**Key principle:** if the fetch can't be fully prevented, eliminate the attacker's ability to *learn* from it. Every code path — success, timeout, connection refused, DNS failure — must return **identical content in identical time**. This is a mitigation of the semi-blind timing oracle, not a fix for the underlying fetch — the request still reaches internal hosts, but the attacker can no longer distinguish outcomes via the response channel.

A common **incomplete fix**: normalizing status codes/body but leaving timing untouched — a 10-second timeout vs. a 50ms connection-refused is still a fully exploitable oracle even with identical response bodies.

---

## Common Mistakes

1. Treating a single DNS hit as confirmed SSRF without timestamp correlation or ruling out scanners/gateways.
2. Reusing the same OOB payload domain across multiple test cases, breaking attribution.
3. Normalizing status/body but not timing — leaves the timing oracle fully intact.
4. Dismissing blind SSRF as inherently low severity — severity is about reachability, not visibility.
5. Assuming "no hit within a minute" means "not vulnerable" — second-order/delayed blind SSRF (e.g., scheduled report generators) can fire hours later.

---

## Variations and Edge Cases

- **Multi-protocol OOB**: Collaborator-style tools catch hits over DNS, HTTP, and SMTP — useful for non-HTTP fetch mechanisms (Module 5).
- **Second-order blind SSRF**: payload is stored and fetched later (e.g., scheduled jobs) — expect delayed OOB hits, don't assume immediate silence means no vulnerability.
- **Partial blind**: status/body normalized, but a side channel still leaks — e.g., differing `Content-Length` on an otherwise identical error page, or cache-timing differences.

---

## Terminology Reference

| Term | Definition |
|---|---|
| **Out-of-band (OOB) detection** | Confirming a vulnerability via a side channel (DNS, secondary HTTP listener) rather than the direct response |
| **Semi-blind SSRF** | No data returned, but differential signal (timing/status/error) allows inference |
| **Oracle** | Any observable signal (timing, status, error type) an attacker can use to infer internal state |
| **Second-order SSRF** | Payload is stored and the vulnerable fetch occurs later, asynchronously from submission |

---

## Common Misconceptions

1. **"A DNS hit alone proves SSRF."** False — email gateways and other scanners can cause unrelated DNS resolution; timestamp correlation is required.
2. **"Blind means low severity."** False — reachability (what the fetch can touch, e.g. cloud metadata) determines severity, not whether a response is visible.
3. **"Normalizing the response body is enough to kill the oracle."** False — timing differences alone remain a fully functional side channel if untouched.
4. **"No signal within seconds means not vulnerable."** False for second-order/asynchronous SSRF — delayed hits are still valid confirmation.

---

## Bug Bounty Reporting Note

To preempt the common triager objection *"this is low severity, no data was exposed"*: the report must argue **reachability, not data exposure**. Demonstrate that the same injection point that fired your OOB payload could equally be pointed at a high-value internal target (cloud metadata, internal admin service) — the absence of data in the PoC doesn't imply absence of reachable impact. Include: exact vulnerable parameter, OOB domain used, timestamp correlation, source IP verification, and an explicit statement of what else is reachable via the same primitive.

---

## Summary

Blind SSRF shifts detection from response-reading to side-effect detection — DNS resolution, TCP timing, and OOB listener hits all occur regardless of what the application shows you. DNS is the most reliable OOB channel because it's rarely subject to the same egress filtering as HTTP/TCP. Semi-blind SSRF turns response timing into a self-contained port-scanning oracle. The core defense specific to this category is eliminating that oracle — normalizing every response path in both content and timing — since full destination blocking (Module 2) isn't always achievable. Severity arguments must center on reachability, not visibility, to preempt "low impact" triager pushback.