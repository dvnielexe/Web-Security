# Module 1: XSS Foundations 🛡️

Welcome. This module builds Cross-Site Scripting (XSS) expertise from the ground up, focusing on deep understanding and browser internals rather than just payload memorization. 

Designed for those with intermediate HTML/JS knowledge and basic security awareness.

---

## 📑 Table of Contents
- [Module 1: XSS Foundations 🛡️](#module-1-xss-foundations-️)
  - [📑 Table of Contents](#-table-of-contents)
  - [1. Concept Overview](#1-concept-overview)
  - [2. Mental Model — The Trust Betrayal](#2-mental-model--the-trust-betrayal)
  - [3. Technical Breakdown — Why XSS Happens](#3-technical-breakdown--why-xss-happens)
  - [4. The Three Types of XSS — Critical Distinction](#4-the-three-types-of-xss--critical-distinction)
  - [5. The Injection Mental Model — Contexts](#5-the-injection-mental-model--contexts)
  - [6. Why It Matters — Real Consequences](#6-why-it-matters--real-consequences)
  - [7. . Common Developer Mistakes That Cause XSS](#7--common-developer-mistakes-that-cause-xss)
  - [8. Detection Methodology — How Attackers Find It](#8-detection-methodology--how-attackers-find-it)
  - [9. Knowledge Check](#9-knowledge-check)

---

## 1. Concept Overview

**Cross-Site Scripting (XSS)** is a vulnerability that allows an attacker to inject and execute malicious JavaScript inside a victim's browser, in the context of a trusted website.

> **Key Takeaway:** The word "scripting" is the key. The attacker doesn't break into the server. They don't crack passwords. They make the browser run *their code* as if the trusted website wrote it. 

---

## 2. Mental Model — The Trust Betrayal

Before any exploitation, you need to understand what trust really means in the browser. 

The core insight of the browser trust model is this: **the browser cannot distinguish between JavaScript that the server intentionally sent and JavaScript that an attacker smuggled in.** Once code is inside the HTML document of `example.com`, the browser treats it as fully trusted by `example.com`.

This is not a browser bug; it's the web's design. The security model assumes the server only sends trustworthy content. XSS exploits the gap between that assumption and reality.

---

## 3. Technical Breakdown — Why XSS Happens

**The Root Cause:** User-controlled input reaches a rendering context (HTML, JavaScript, CSS, URL) without being correctly escaped or sanitized for that specific context.

When a server builds an HTML string like `"<h1>Hello " + name + "</h1>"`, and the `name` variable contains `<script>alert(1)</script>`, the browser receives perfectly valid HTML. The browser's parser has no way of knowing that the `<script>` tag originated from user input rather than the developer's source code.

---

## 4. The Three Types of XSS — Critical Distinction

Understanding the delivery mechanism is crucial for both exploitation and defense.

| Type | How the Payload Arrives | Server Visibility | Typical Execution Flow |
| :--- | :--- | :--- | :--- |
| **Reflected** (Non-Persistent) | Delivered via the immediate HTTP request (URL parameters, headers, forms). | **High.** Passes through the server and reflects in the HTTP response. | Attacker tricks victim into clicking link ➔ Server reflects payload ➔ Browser executes it. |
| **Stored** (Persistent) | Delivered previously and saved on the server (database, files, comments). | **Moderate.** Server stores the payload as data, serving it to future users. | Attacker saves payload to server ➔ Victim visits page ➔ Server serves payload ➔ Browser executes it. |
| **DOM-based** | Delivered via client-side scripts modifying the DOM dynamically. | **Zero.** Often resides in URL fragments (`#`), which are never sent to the server. | Victim clicks link ➔ Server sends clean page ➔ Client-side JS reads malicious fragment ➔ Browser executes it. |

> **⚠️ Note on DOM XSS:** Because the payload never reaches the server, backend firewalls (WAFs) and server logs are completely blind to it.

---

## 5. The Injection Mental Model — Contexts

Every injection is about **context**. The same input string can be harmless or lethal depending on where it lands in the HTML document.

```text
┌──────────────────────────────────────────────────────────────┐
│  HTML document                                               │
│                                                              │
│  <div>  ← HTML element context                               │
│     Hello [user input here]  ← text content context          │
│  </div>                                                      │
│                                                              │
│  <img src="[user input here]">  ← attribute context          │
│                                                              │
│  <script>                                                    │
│     var name = "[user input here]";  ← JS string context     │
│  </script>                                                   │
│                                                              │
│  <a href="[user input here]">  ← URL context                 │
│                                                              │
│  <style>                                                     │
│     color: [user input here];  ← CSS context                 │
│  </style>                                                    │
└──────────────────────────────────────────────────────────────┘
```

---

## 6. Why It Matters — Real Consequences

XSS is far more than an **alert(1)** pop-up. Real-world impacts include:

- Account Takeover: Stealing document.cookie session tokens to bypass authentication entirely.

- Credential Harvesting: Rewriting a login form's action attribute to route submitted passwords to an attacker-controlled server.

- Worm Propagation: Stored XSS that automatically re-posts itself (e.g., the infamous 2005 MySpace Samy worm).

- Admin Compromise: Targeting higher-privilege users (like support admins) to gain full application control.

- CSRF Bypass: Reading CSRF tokens directly from the DOM to forge authenticated requests.

---

## 7. . Common Developer Mistakes That Cause XSS

- Trusting input type, not encoding output: Validating that a name only contains letters is a business rule, not an XSS defense.

- Encoding in the wrong context: HTML-encoding a value that lands inside a JavaScript string block.

- Using innerHTML unsafely: Assigning any user data to innerHTML invokes the HTML parser, opening the door for execution.

- Trusting HTTP headers: Assuming headers like Referer or User-Agent are safe to render (they are fully attacker-controlled).

- Sanitizing on input instead of output: What matters is how the data is rendered. A string safe in one context can be dangerous in another.

---

## 8. Detection Methodology — How Attackers Find It

- Map Inputs: Identify URL parameters, form fields, headers, cookies, and JSON body fields.

- Trace Reflections: Submit a unique string (e.g., xss_probe_7734) and search the HTTP response to see where and how it returns.

- Identify Context: Does the probe land inside a tag, an attribute, a JS string, or raw HTML?

- Test Injection: Craft a payload specific to breaking out of that exact context.

- Check Filters: Observe how the application transforms the input and attempt bypasses.

---

## 9. Knowledge Check
Reflection Questions

    Q: A developer runs strip_tags() before storing data, which is later rendered inside <script>var data = "___";</script>. Is there a risk?

        A: Yes. strip_tags() protects the HTML context, but the data is rendering in a JS context. An attacker can break out with "; alert(1); // without using a single HTML tag.

    Q: Data is only reflected on a 404 Not Found page. Is this low risk?

        A: No. Attackers don't wait for users to type payloads. They craft a malicious link to the 404 page and deliver it via phishing.

    Q: Why is DOM XSS harder to detect?

        A: 1. Server-side defenses are blind to it (payload stays in the browser). 2. Finding it requires tracing asynchronous JavaScript execution flow from "Sources" to "Sinks".


Claude chat: DT