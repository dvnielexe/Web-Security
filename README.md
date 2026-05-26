<div align="center">

# 🔐 Web Security Notes

> A living notebook on web application security — vulnerabilities, methodology, tooling, and resources compiled as I work toward bug bounty and beyond.

![Status](https://img.shields.io/badge/status-active-brightgreen)
![Focus](https://img.shields.io/badge/focus-web%20security-blueviolet)
![Level](https://img.shields.io/badge/level-intermediate-orange)

</div>

---

## 👤 About This Repo

This is my personal knowledge base for web security — built as I go through labs, CTFs, bug bounty programs, and research. It's written in my own words, structured for quick reference, and updated regularly.

If you find it useful, great. If you spot something wrong or missing, feel free to open an issue or PR.

> **Stack I work with:** Kali Linux · Burp Suite Pro · VS Code · Docker

---

## 📁 Structure

```
web-security-notes/
├── vulnerabilities/
│   ├── xss
│   ├── sqli
│   ├── idor
│   ├── ssrf
│   ├── xxe
│   ├── csrf
│   ├── open-redirect
│   ├── broken-auth
│   ├── business-logic
│   └── api-security
├── methodology/
│   ├── recon
│   ├── enumeration
│   ├── exploitation
│   ├── chaining
│   └── reporting
├── tools/
│   ├── burp-suite
│   ├── recon-tools
│   └── automation
└── resources
```

---

## 🐛 Vulnerabilities

| Vulnerability | Category | Severity | Notes |
|---|---|---|---|
| [Cross-Site Scripting (XSS)](./vulnerabilities/xss.md) | Client-side | Medium–High | Reflected, Stored, DOM |
| [SQL Injection](./vulnerabilities/sqli.md) | Injection | High–Critical | In-band, Blind, OOB |
| [IDOR](./vulnerabilities/idor.md) | Access Control | Medium–High | Object reference manipulation |
| [SSRF](./vulnerabilities/ssrf.md) | Server-side | High–Critical | Internal service access |
| [XXE](./vulnerabilities/xxe.md) | Injection | Medium–High | XML external entity |
| [CSRF](./vulnerabilities/csrf.md) | Client-side | Medium | State-changing requests |
| [Open Redirect](./vulnerabilities/open-redirect.md) | Validation | Low–Medium | Useful in chains |
| [Broken Auth](./vulnerabilities/broken-auth.md) | Auth | High–Critical | Session, JWT, OAuth flaws |
| [Business Logic](./vulnerabilities/business-logic.md) | Logic | Varies | App-specific, high value |
| [API Security](./vulnerabilities/api-security.md) | API | Varies | REST, GraphQL, mass assignment |

---

## 🧭 Methodology

My general approach when testing a target.

### Recon

```
Target
 ├── Passive
 │    ├── Subdomain enum     → subfinder, amass, crt.sh
 │    ├── Historical URLs    → waybackurls, gau
 │    ├── Tech fingerprint   → Wappalyzer, whatweb
 │    └── GitHub dorking     → secrets, endpoints, config files
 │
 └── Active
      ├── Live host check    → httpx
      ├── Port scanning      → nmap
      ├── Dir/param fuzzing  → ffuf, feroxbuster
      ├── JS recon           → LinkFinder, SecretFinder
      └── Vuln scanning      → nuclei
```

### Testing Flow

1. **Map the attack surface** — all endpoints, parameters, file uploads, auth flows
2. **Identify entry points** — user-controlled input, headers, cookies, JSON/XML bodies
3. **Apply vuln-specific methodology** — follow checklist per category
4. **Attempt chaining** — escalate low-severity findings into higher-impact chains
5. **Document everything** — even dead ends; useful for reporting context

### Chaining Examples

| Chain | Result |
|---|---|
| Open Redirect → OAuth state bypass | Account takeover |
| Self-XSS → CSRF | Stored XSS exploitable by others |
| SSRF → Internal metadata | Cloud credential theft |
| IDOR + Broken auth | Privilege escalation |

---

## 🛠️ Tools

### Core

| Tool | Purpose | Link |
|---|---|---|
| Burp Suite Pro | Intercept, scan, fuzz | [portswigger.net](https://portswigger.net) |
| ffuf | Fast web fuzzer | [github.com/ffuf/ffuf](https://github.com/ffuf/ffuf) |
| Nuclei | Template-based scanner | [github.com/projectdiscovery/nuclei](https://github.com/projectdiscovery/nuclei) |
| httpx | HTTP probe / live check | [github.com/projectdiscovery/httpx](https://github.com/projectdiscovery/httpx) |
| Subfinder | Subdomain discovery | [github.com/projectdiscovery/subfinder](https://github.com/projectdiscovery/subfinder) |

### Recon

| Tool | Purpose |
|---|---|
| Amass | Deep subdomain enumeration |
| GAU | Fetch known URLs from multiple sources |
| Waybackurls | Pull historical URLs from Wayback Machine |
| LinkFinder | Extract endpoints from JS files |
| SecretFinder | Find secrets/API keys in JS |
| gf | grep patterns for interesting params |

### Automation & Pipelines

```bash
# Basic recon pipeline
subfinder -d target.com -silent | httpx -silent | nuclei -t exposures/

# Parameter discovery
gau target.com | gf xss | qsreplace '"><script>alert(1)</script>'

# JS endpoint extraction
katana -u https://target.com -jc | grep "\.js" | xargs -I{} linkfinder -i {} -o cli
```

---

## 📝 Writeups

| Target | Vuln | Difficulty | Link |
|---|---|---|---|
| PortSwigger Labs | Various | Easy–Expert | [writeups/portswigger/](./writeups/) |
| HackTheBox | Various | Medium–Hard | [writeups/htb/](./writeups/) |
| CTF challenges | Various | Varies | [writeups/ctf/](./writeups/) |

*Writeups added as I complete them.*

---

## 📚 Resources

### Learning Platforms

- [PortSwigger Web Academy](https://portswigger.net/web-security) — best free web security labs, period
- [HackTheBox](https://hackthebox.com) — machines and web challenges
- [TryHackMe](https://tryhackme.com) — guided learning paths
- [PentesterLab](https://pentesterlab.com) — vuln-specific exercises

### Bug Bounty

- [HackerOne Hacktivity](https://hackerone.com/hacktivity) — disclosed real-world reports (read daily)
- [AllAboutBugBounty](https://github.com/daffainfo/AllAboutBugBounty) — per-vuln cheatsheets
- [HowToHunt](https://github.com/KathanP19/HowToHunt) — methodology per vuln type
- [Bug Hunter's Methodology (TBHM)](https://github.com/jhaddix/tbhm) — Jason Haddix's framework

### References

- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
- [HackTricks](https://book.hacktricks.xyz)
- [PortSwigger Research](https://portswigger.net/research)

### Channels & People to Follow

- **Nahamsec** — bug bounty methodology, community
- **STÖK** — hunter mindset, recon deep dives
- **LiveOverflow** — low-level + web, excellent explanations
- **John Hammond** — CTF walkthroughs
- **Intigriti** — monthly XSS challenges

---

## 📈 Progress Tracker

| Milestone | Status |
|---|---|
| OWASP Top 10 — all labs completed | 🔄 In progress |
| Burp Suite Certified Practitioner | ⏳ Planned |
| First HackerOne report submitted | ⏳ Planned |
| First bounty paid | ⏳ Planned |
| 10 accepted reports | ⏳ Planned |

---

## ⚖️ Legal & Ethics

Everything in this repo is for **educational purposes and authorized testing only**.

- Only test systems you have explicit permission to test
- Follow platform rules and program scopes when doing bug bounty
- Never access, modify, or exfiltrate real user data
- Responsible disclosure always

---

<div align="center">

*Built with curiosity. Updated with every new thing I break.*

</div>
