# Module 8 — Exploitation & Bug Bounty Methodology

> Converting technical findings into credible, well-scoped, paid reports — the gap between "found a real bug" and "got it triaged correctly."

---

## Table of Contents

- [Module 8 — Exploitation \& Bug Bounty Methodology](#module-8--exploitation--bug-bounty-methodology)
  - [Table of Contents](#table-of-contents)
  - [Core Concept](#core-concept)
  - [Mental Model](#mental-model)
  - [The Impact Ladder](#the-impact-ladder)
  - [Chaining SSRF with Other Vulnerabilities](#chaining-ssrf-with-other-vulnerabilities)
  - [Report Structure](#report-structure)
  - [Preemptive Severity Justification](#preemptive-severity-justification)
  - [Demonstrating Impact Safely](#demonstrating-impact-safely)
  - [Common Triager Objections and Responses](#common-triager-objections-and-responses)
  - [Severity Assessment via CVSS](#severity-assessment-via-cvss)
  - [Real-World Pattern Recognition](#real-world-pattern-recognition)
  - [Full Workflow Synthesis](#full-workflow-synthesis)
  - [Terminology Reference](#terminology-reference)
  - [Common Misconceptions](#common-misconceptions)
  - [The Core Takeaway](#the-core-takeaway)
  - [Summary](#summary)

---

## Core Concept

Technical correctness and getting paid for a finding are different skills. This module converts the technical range from Modules 1–7 into severity reasoning, vulnerability chaining, and report-writing that survives a skeptical, time-pressured triager.

---

## Mental Model

> A triager reads dozens of reports a day, most low-effort or exaggerated. Your report competes for limited attention and trust. Every sentence either builds credibility or spends it.

Shift from "did I find a real bug" (already answerable) to **"will a skeptical, time-pressured reader believe this is real and understand why it matters, in the first 30 seconds."**

---

## The Impact Ladder

```
1. Port scan / internal reconnaissance   (semi-blind timing/error signal)
2. Internal service access               (reach an internal API/dashboard)
3. Internal data exposure                (read data from that service)
4. Credential theft                      (cloud metadata, file:// config reads)
5. Remote code execution                 (Redis/gopher chain, or credential
                                           reuse to pivot further)
```

**Testing obligation:** climb as far as responsibly possible before reporting — not stop at the first rung reached. On any confirmed SSRF against a cloud-hosted target, test metadata reachability before writing anything up; stopping at "port scan confirmed" hands the triager an easy excuse to downgrade ("just internal recon").

---

## Chaining SSRF with Other Vulnerabilities

SSRF is often the connective tissue between otherwise-separate weaknesses:

- **SSRF + SSTI** — SSTI processes a fetched response, turning blind metadata reachability into full credential exfiltration.
- **SSRF + open redirect** — a redirect on the target's own domain can bypass an allowlist that only checks "is this URL on our domain."
- **SSRF + stored XXE** — a document uploaded once, processed repeatedly (recurring report generator), turns a one-time upload into a repeatedly-firing primitive.
- **SSRF + IDOR** — a predictable/enumerable ID on stored fetch results lets you view other users' triggered fetches.

**Why SSRF+IDOR matters for reporting specifically:** it converts a *theoretical* internal-infrastructure argument into a *concrete, non-hypothetical* cross-user data exposure — far easier for a triager to accept than "an attacker could reach X, which could expose Y." Concrete impact beats theoretical impact in triage, every time.

---

## Report Structure

1. **Summary** — one or two sentences: what's vulnerable, what it allows, at what severity.
2. **Vulnerable endpoint/parameter** — exact URL, exact parameter name.
3. **Steps to reproduce** — numbered, copy-pasteable, minimal.
4. **Proof of impact** — the highest rung actually climbed, not just initial confirmation.
5. **Root cause analysis** — briefly explain *why* it's exploitable (e.g., "`image_url` fetched via `requests.get()` without destination validation") — demonstrates understanding, not just a working payload.
6. **Suggested remediation** — specific ("resolved-IP allowlisting + disable redirect-following"), not generic ("please fix SSRF").
7. **Severity justification** — explicitly state the CVSS-relevant factors or program's own criteria; don't assume the triager connects the dots.

---

## Preemptive Severity Justification

Structure for the "it's blind, no data was exposed" objection — state the limitation, pivot to what's proven, explicitly state the conclusion:

> "Although the SSRF is blind and I could not directly retrieve the metadata response, I confirmed that the vulnerable server can reach the cloud instance metadata service. This demonstrates server-side access to a privileged internal endpoint that may expose instance credentials; therefore, the impact is greater than simple internal port scanning, even though credential extraction was not demonstrated."

Do the triager's severity reasoning *for* them — a busy triager rewards reports that make their job easy.

---

## Demonstrating Impact Safely

**Never complete an actual RCE/data-destruction/service-disruption exploit**, even when technically capable within scope. Authorization to test means authorization to *prove* the vulnerability exists, not to fully exploit it as a real attacker would — completed exploitation risks real damage and is typically out-of-scope conduct.

**Proof-of-capability is sufficient; proof-of-completed-attack is not required and is risky.** Example (Redis/gopher chain):

1. Demonstrate `CONFIG SET dir` / `CONFIG SET dbfilename` succeed, confirmed via a follow-up `CONFIG GET`.
2. Write to a non-destructive, clearly-marked test location — never the actual web root, never `authorized_keys`.
3. Describe remaining steps in prose, not executed: *"An attacker could subsequently redirect dir/dbfilename to the web-served directory and write a webshell via SAVE, achieving RCE. I did not perform this final step to avoid modifying production systems."*

Stopping short and stating so explicitly reads as professionalism, strengthening report credibility rather than weakening it — and is the ethically correct line regardless of triager reaction.

---

## Common Triager Objections and Responses

| Objection | Response Strategy |
|---|---|
| "Just internal recon, no real impact" | Climb the impact ladder first; if capped at rung 1-2, argue reachability-based severity explicitly |
| "Blind SSRF, no data exposed" | Preemptive phrasing: state limitation → pivot to proof → state conclusion |
| "Requires internal attacker position" | Clarify your access was entirely external/unauthenticated — the SSRF itself grants the internal position |
| "Duplicate of existing report" | Clean timestamped PoC, be ready to show independent discovery methodology |
| "Known/accepted risk" | Verify it's genuinely documented policy, not deflection — ask for the specific reference |
| "Low severity, needs rare authenticated role" | Disclose the precondition proactively in the report — builds credibility rather than inviting suspicion |

---

## Severity Assessment via CVSS

- **Attack Vector (Network)** — SSRF is almost always network-vector, remotely triggerable.
- **Attack Complexity** — a basic URL-parameter SSRF is Low complexity; a DNS-rebinding-dependent chain is Higher complexity, which can *reduce* score despite feeling more advanced.
- **Privileges Required** — unauthenticated entry points score higher than ones requiring a logged-in account.
- **Confidentiality/Integrity/Availability Impact** — credential theft = confidentiality; Redis SET/DEL on trusted cache data = integrity; internal DoS vector = availability.

**Why simple exploits can score higher than sophisticated ones:** CVSS measures risk to the organization — how easily *any* attacker, of *any* skill level, can reproduce the impact — not researcher sophistication. A one-request unauthenticated IMDSv1 GET is reproducible by literally anyone who finds the parameter; a DNS-rebinding chain requires attacker-controlled DNS infrastructure and precise timing. The organization's risk is higher from the simple one, even though the complex one is more impressive to demonstrate.

---

## Real-World Pattern Recognition

Recurring high-yield patterns across public bug bounty writeups:

- **Webhook-URL SSRF into cloud metadata** — one of the most repeated patterns; webhook features are common, under-scrutinized ("just a callback"), and frequently miss destination validation.
- **PDF/screenshot-generator SSRF** — repeatedly found in "export to PDF"/"share as image" features, often chained with SVG/headless-browser techniques (Module 7).
- **URL-preview/unfurling SSRF** — chat/messaging platforms auto-generating link previews; the feature's entire purpose is "fetch a URL a user pasted," a textbook Module 2 injection point often missed because it feels minor.

**Common thread:** the highest-yield targets are features whose entire purpose is fetching attacker-influenceable URLs, especially ones treated as low-risk "convenience" features by developers.

---

## Full Workflow Synthesis

```
1. Confirm SSRF (Module 2 canary methodology)
2. Determine blind/semi-blind/full-response (Module 3)
3. Climb the impact ladder as far as responsibly possible:
   port scan → internal access → data exposure → credential theft →
   [STOP before actual RCE — demonstrate capability, not completion]
4. Check for chaining opportunities (SSTI, IDOR, open redirect, stored XXE)
5. Write report: summary → endpoint → repro steps → proof of impact →
   root cause → remediation → explicit severity justification
6. Preempt the specific objection your finding is most vulnerable to
```

---

## Terminology Reference

| Term | Definition |
|---|---|
| **Impact ladder** | Ordered escalation from port scanning through RCE, used to structure testing and reporting |
| **Triage** | The program's process of reviewing, validating, and scoring a submitted report |
| **CVSS** | Common Vulnerability Scoring System — standardized severity scoring based on exploitability and impact factors |
| **Proof-of-capability** | Demonstrating an exploit primitive works without completing the full harmful action |

---

## Common Misconceptions

1. **"A more sophisticated exploit chain always scores higher."** False — CVSS often scores low-complexity, low-precondition exploits higher, since they're reproducible by any attacker.
2. **"If I can't extract data, I shouldn't report it."** False — reachability-based severity arguments are valid and often accepted, especially with the correct preemptive framing.
3. **"Demonstrating full RCE strengthens a report."** False — actual completed exploitation is typically out-of-scope and risky; capability proof plus explicit stopping is the professional and credible approach.
4. **"Getting reports dismissed means the finding wasn't real."** Often false — many dismissals are communication failures (unclear proof of impact, no severity justification) rather than technical invalidity.

---

## The Core Takeaway

Once technical fundamentals are solid (as they now are across Modules 1–7), the bottleneck for actual bounty payouts is rarely "can I find the bug" — it's "can I write the report so a busy, skeptical human believes and values it." A disproportionate share of practice time going forward should go toward **writing practice reports for findings already understood technically**, not chasing more exotic techniques.

---

## Summary

Bug bounty success requires converting technical findings into credible, well-scoped reports: climb the impact ladder before writing anything up, look for chaining opportunities that turn theoretical impact into concrete impact, structure the report to preempt the specific objection your finding is most vulnerable to, and understand that CVSS rewards ease-of-reproduction over researcher sophistication. Demonstrate capability, never complete harmful exploitation, and do the triager's severity reasoning for them rather than leaving it as an exercise for a skeptical, time-pressured reader.