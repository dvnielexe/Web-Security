# Module 7 — SSRF in Modern Applications

> The same primitive, wearing different clothes: webhooks, XXE, GraphQL, microservices, and Kubernetes as SSRF injection surfaces.

---

## Table of Contents

- [Module 7 — SSRF in Modern Applications](#module-7--ssrf-in-modern-applications)
  - [Table of Contents](#table-of-contents)
  - [Core Concept](#core-concept)
  - [Mental Model](#mental-model)
  - [Webhook Systems — Async Amplification](#webhook-systems--async-amplification)
  - [Image Processors — File-Upload SSRF via SVG](#image-processors--file-upload-ssrf-via-svg)
  - [XML Parsers — XXE as an SSRF Variant](#xml-parsers--xxe-as-an-ssrf-variant)
  - [Headless Browsers as a General Category](#headless-browsers-as-a-general-category)
  - [GraphQL as an SSRF Vector](#graphql-as-an-ssrf-vector)
  - [SSRF in Microservice Architectures](#ssrf-in-microservice-architectures)
  - [Cloud Function SSRF](#cloud-function-ssrf)
  - [Kubernetes Internal Network Exposure](#kubernetes-internal-network-exposure)
  - [Detection Methodology](#detection-methodology)
  - [Defense \& Secure Coding](#defense--secure-coding)
  - [Common Mistakes](#common-mistakes)
  - [Terminology Reference](#terminology-reference)
  - [Common Misconceptions](#common-misconceptions)
  - [The Core Habit of Mind](#the-core-habit-of-mind)
  - [Summary](#summary)

---

## Core Concept

The vulnerability class doesn't change from Modules 1–6 — the **shape of the injection point** does. Modern architectures introduce entry points (webhooks, XML documents, GraphQL resolvers, service mesh calls) that nobody thinks of as "URL fetchers," but functionally are.

---

## Mental Model

> You've learned to recognize one silhouette: "a text field labeled `url`." This module teaches you to recognize the same silhouette wearing different clothes — a webhook config, an XML document, a GraphQL query, a service mesh call — where nobody labeled anything `url`, but the mechanic is identical.

For every new feature type, ask the same Module 2 question: **does this feature cause a server to make a network request based on something I can influence?** — even when it doesn't look like a URL field.

---

## Webhook Systems — Async Amplification

Webhook delivery is typically asynchronous with **retries** (exponential backoff over hours). This gives an attacker:
- **Multiple independent confirmation windows** — a missed OOB hit on the first delivery attempt doesn't mean the vulnerability is gone; a later retry can still confirm it.
- **Amplification** — if the payload targets a slow/resource-constrained internal service, automatic retries turn the webhook system into a built-in repeated-attack-delivery mechanism with no further action from the attacker.

**Testing implication:** don't declare "not vulnerable" after a single missed hit — check for retry behavior over an extended window.

---

## Image Processors — File-Upload SSRF via SVG

Some image processors parse the file format itself rather than just fetching-and-displaying. SVG can contain embedded external references:

```xml
<svg xmlns="http://www.w3.org/2000/svg">
  <image href="http://169.254.169.254/latest/meta-data/" />
</svg>
```

If the server-side rasterization library resolves the `href`, this is SSRF **through a file upload**, not a URL parameter — a different injection surface than Module 2's table, same underlying mechanic.

---

## XML Parsers — XXE as an SSRF Variant

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/role-name">
]>
<foo>&xxe;</foo>
```

**Mapping to the core primitive:** the XML parser itself becomes the vulnerable HTTP-client-equivalent component. The `SYSTEM` identifier plays the exact role of "the URL parameter" from Module 2's injection-point table — attacker-controlled input (the XML document) causes a server-side fetch, disguised as ordinary document parsing.

XXE-as-SSRF is not a separate vulnerability class — it inherits every technique from Modules 2–6 (blind detection via OOB, metadata targeting, filter bypass on entity sanitization). Any XML-accepting endpoint is a candidate: SOAP APIs, RSS/Atom parsers, DOCX/ODT uploads (XML internally).

---

## Headless Browsers as a General Category

Beyond PDF generation: screenshot services, "preview my website" tools, scraping/monitoring services, SEO/social-crawler simulators. Because headless browsers **execute JavaScript**, a target page's own JS can make further requests from inside the renderer's network context — **client-side-triggered SSRF from inside the server-side renderer**, beyond whatever the attacker directly controls in the initial URL.

---

## GraphQL as an SSRF Vector

**Discovery methodology shift:** REST SSRF hunting is traffic analysis (grep parameter names in requests). GraphQL SSRF hunting is **schema analysis**, because there's no fixed set of endpoints/parameter names to grep.

1. **Get the schema** — via introspection (`__schema`, `__type`) if enabled; otherwise partial reconstruction via fuzzing.
2. **Scan every field argument for fetch-shaped semantics** — not just literal `url` args, but `fetchExternalProfile(url:)`, `avatarSource(path:)`, `importFrom(endpoint:)`, `syncWithService(webhookEndpoint:)`.
3. **Pay special attention to federated/nested resolvers** — a resolver may silently call a completely different internal microservice to populate a field, invisible from the query itself. This is the richest SSRF surface in this module, since the fetch is an implementation detail hidden from the caller.
4. **Test each candidate the same way as Module 2** — external canary first, then escalate.

One sentence: **REST SSRF hunting is traffic analysis; GraphQL SSRF hunting is schema analysis.**

---

## SSRF in Microservice Architectures

Service-to-service calls often have minimal/no authentication, relying on positional trust ("if you're on this network/mesh, you're trusted") — the same assumption behind Redis's loopback trust (Modules 2/5).

**Transitive trust exploitation:** Service A trusts the internal network → Service B trusts Service A → Service C trusts Service B, often with weak or absent authentication because each hop is "internal." Compromising ONE public-facing service via SSRF can expose dozens or hundreds of otherwise-inaccessible services — SSRF becomes a **network pivot into the mesh**, not a single-hop information leak, because the attacker borrows each hop's existing trust relationship with the next.

---

## Cloud Function SSRF

Serverless functions (Lambda, GCP Cloud Functions, Azure Functions) are often assumed "stateless and isolated," but still run with an attached execution role/service account. The classic `169.254.169.254` IMDS pattern doesn't always apply directly (e.g., Lambda injects credentials via environment variables instead), but the **pattern is identical to Module 4**: ephemeral compute + automatically-vended credentials + insufficient isolation from attacker-influenced request handling. Mechanism differs per provider; risk category is the same.

---

## Kubernetes Internal Network Exposure

- **Kubernetes API server** — often reachable at `https://kubernetes.default.svc` from within a pod; pods frequently have a service account token auto-mounted at `/var/run/secrets/kubernetes.io/serviceaccount/token`. SSRF reaching the API server extends blast radius to potential **cluster-level API access**.
- **Underlying cloud provider node metadata** (`169.254.169.254`) is often *also* reachable from within a pod unless explicitly blocked at the CNI/network-policy layer — Module 4's entire risk category persists underneath Kubernetes' own internal API surface.

---

## Detection Methodology

1. **Webhooks**: OOB listener test, but check retry windows before ruling out.
2. **File uploads (SVG/DOCX/etc.)**: test embedded external references per the file format's own mechanism, not just HTTP parameters.
3. **XML-accepting endpoints**: test XXE-style entity injection regardless of whether the endpoint "looks like" it does networking.
4. **GraphQL**: pull the schema (introspection), scan for fetch-semantic field names, prioritize federated/nested resolvers.
5. **Microservices/Kubernetes**: once ANY SSRF is confirmed, explicitly test reachability to the Kubernetes API server and node metadata endpoint — the highest-value target may be several trust-hops from the initially vulnerable service.

---

## Defense & Secure Coding

- **Disable external entity resolution by default** in XML parsers (DOCTYPE/external entity processing off by default, not opt-in hardening).
- **Sandbox/restrict headless browser network access** — separate egress rules from the main application, since renderers execute arbitrary JS from fetched pages.
- **Disable GraphQL introspection in production** — reduces recon ease, not a complete fix.
- **Zero-trust service mesh authentication** — mTLS/service-to-service tokens for every internal call, closing the "A trusts network, B trusts A" chain directly.
- **CNI-layer network policies** blocking pod-to-metadata traffic, in addition to IMDSv2-style protections, for workloads with no legitimate need to reach node metadata.

---

## Common Mistakes

1. Only testing URL-parameter-shaped injection points, missing file-upload-based (SVG/XML) SSRF entirely.
2. Declaring webhook SSRF unconfirmed after a single missed OOB hit without accounting for retries.
3. Testing GraphQL like REST — grepping request bodies for `url` instead of reading the schema.
4. Stopping at the first confirmed internal service in a microservice environment without testing onward reachability to higher-value mesh-wide targets.
5. Assuming serverless/cloud functions are "isolated" and skipping credential/metadata exposure testing.

---

## Terminology Reference

| Term | Definition |
|---|---|
| **XXE (XML External Entity)** | Exploiting XML parser entity resolution to trigger server-side requests/file reads |
| **Federated resolver** | A GraphQL resolver that fetches data from a different backend service to populate part of a query response |
| **Service mesh** | Infrastructure layer managing service-to-service communication, often with implicit network-position trust |
| **CNI (Container Network Interface)** | The plugin layer controlling pod networking and network policy enforcement in Kubernetes |

---

## Common Misconceptions

1. **"SSRF only happens through URL parameters."** False — file uploads (SVG), XML documents, and GraphQL arguments are equally valid injection points.
2. **"XXE and SSRF are unrelated vulnerability classes."** False — XXE with a `SYSTEM` identifier is SSRF delivered through XML parsing.
3. **"Microservices are more secure because attackers can't reach them directly."** False — SSRF provides indirect reachability, and positional trust between services often means weak/absent authentication once reached.
4. **"Serverless functions are isolated from credential theft risk."** False — the metadata/credential-vending mechanism differs by provider, but the underlying risk category (Module 4) still applies.

---

## The Core Habit of Mind

Stop searching for a syntax pattern (`url=`). For every attacker-controlled input, ask: **"Can processing this input cause the server to make a network request?"** This reframes discovery from pattern-matching parameter names to reasoning about server-side behavior — the single most transferable habit from this module, applicable to injection points not yet invented.

---

## Summary

Every "new" injection point in this module — webhooks, SVG uploads, XXE, GraphQL, microservices, Kubernetes — is the same Module 1 primitive (attacker-controlled input → server-side network request) delivered through an unfamiliar shape. Webhook retries turn blind confirmation into a forgiving, multi-window process. XXE makes the XML parser itself the vulnerable fetcher. GraphQL requires schema analysis instead of traffic analysis. Microservice and Kubernetes environments dramatically amplify blast radius through transitive positional trust. The unifying discipline across all of them: ask whether processing attacker-controlled input causes a network request — not whether a field happens to be named `url`.