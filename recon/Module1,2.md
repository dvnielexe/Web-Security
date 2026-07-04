# Bug Bounty Recon — Master Cheatsheet
### Web Application Reconnaissance: Foundations through Passive Recon

> **Curriculum progress:** Modules 1–2 complete
> **Last updated:** 2025-06-10
> **Environment:** Windows + WSL2 (Ubuntu 22.04)

---

## Table of Contents

1. [The Recon Mental Model](#1-the-recon-mental-model)
2. [Scope Rules — Non-Negotiable](#2-scope-rules--non-negotiable)
3. [Lab Setup](#3-lab-setup)
4. [Folder Structure and Note-Taking](#4-folder-structure-and-note-taking)
5. [DNS — Commands and Record Types](#5-dns--commands-and-record-types)
6. [WHOIS — Domain and IP Intelligence](#6-whois--domain-and-ip-intelligence)
7. [Certificate Transparency Logs](#7-certificate-transparency-logs)
8. [subfinder — Passive Subdomain Enumeration](#8-subfinder--passive-subdomain-enumeration)
9. [ASN and IP Range Mapping](#9-asn-and-ip-range-mapping)
10. [Shodan — Passive Infrastructure Recon](#10-shodan--passive-infrastructure-recon)
11. [Cloud and CDN Handling](#11-cloud-and-cdn-handling)
12. [Merging and Deduplicating Output](#12-merging-and-deduplicating-output)
13. [Triage and Prioritization](#13-triage-and-prioritization)
14. [The Full Passive Recon Workflow](#14-the-full-passive-recon-workflow)
15. [Tool Reference Card](#15-tool-reference-card)
16. [Common Mistakes Reference](#16-common-mistakes-reference)
17. [Key Vocabulary](#17-key-vocabulary)

---

## 1. The Recon Mental Model

### The five-layer stack

Everything in recon maps to one of five layers. Always start at Layer 1.

```
┌──────────────────────────────────────┐
│  5. SURFACE ANALYSIS                 │  Endpoints, params, JS, forms
├──────────────────────────────────────┤
│  4. LIVE HOST VERIFICATION           │  HTTP probing, screenshots
├──────────────────────────────────────┤
│  3. ASSET DISCOVERY                  │  Subdomains, DNS, certificates
├──────────────────────────────────────┤
│  2. ORGANIZATION MAPPING             │  WHOIS, ASN, acquisitions
├──────────────────────────────────────┤
│  1. SCOPE & RULES                    │  Program policy, in/out of scope
└──────────────────────────────────────┘
```

### Passive vs. active — the line

| Type | You send packets to | Examples |
|------|-------------------|---------|
| Passive | Third-party databases only | crt.sh, WHOIS, Shodan |
| Light active | Target's DNS resolvers | DNS resolution, live host check |
| Active | Target's servers directly | HTTP probing, port scanning |

### Core mental model

You are mapping a city using only public records, satellite images, and tax filings. You do not knock on doors yet.

Recon quality determines bug bounty results. Hunters who find the most critical bugs find the *right targets* — not the most hardened production endpoints, but the forgotten staging server with no WAF and debug mode on.

---

## 2. Scope Rules — Non-Negotiable

### What scope defines

- **In-scope assets:** what you are permitted to test
- **Out-of-scope assets:** explicitly forbidden — never touch these
- **Rules of engagement:** rate limits, forbidden techniques, disclosure procedures

### The infrastructure ownership rule

> A bug bounty program can only grant permission for assets **they own and control.**

If a subdomain resolves to a CDN or third-party service, that third party never consented to testing. You may not probe their infrastructure, regardless of what the scope wildcard says.

```
mail.example.com → CNAME → example.mailchimp.com

You can assess: mail.example.com       ✅ (in scope via wildcard)
You cannot probe: example.mailchimp.com ❌ (Mailchimp's infrastructure)
```

### Wildcard scope — what it means

`*.example.com` = you are permitted to look for vulnerabilities on subdomains of example.com.
It does **not** mean unlimited access or authorization for any technique.

### Scope intake workflow

| Step | Action |
|------|--------|
| 1 | Read the **entire** policy page, not just the scope table |
| 2 | Copy in-scope and out-of-scope lists into `scope.txt` |
| 3 | Resolve ambiguities conservatively — if unsure, assume out of scope |
| 4 | Flag third-party services — WHOIS the resolved IP to check ownership |
| 5 | Re-read scope as your asset map grows |

### Common scope mistakes

- Testing interesting-looking assets without verifying scope first
- Assuming wildcard means unlimited access
- Testing assets that resolve to third-party IPs (CDNs, SaaS platforms)
- Forgetting that scope can change — re-read periodically on long engagements

---

## 3. Lab Setup

### WSL2 installation

```powershell
# Windows PowerShell (admin)
wsl --install -d Ubuntu-22.04
```

### Essential packages

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y git curl wget python3 python3-pip \
  dnsutils whois nmap jq tmux ripgrep unzip build-essential
```

### Go installation (required for modern recon tools)

```bash
wget https://go.dev/dl/go1.22.3.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.22.3.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.bashrc
source ~/.bashrc

# Verify
go version
```

### Tool installation reference

```bash
# subfinder
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# asnmap
go install github.com/projectdiscovery/asnmap/cmd/asnmap@latest

# Shodan CLI
pip install shodan --break-system-packages
shodan init YOUR_API_KEY
```

---

## 4. Folder Structure and Note-Taking

### Standard folder structure

```
~/recon/
├── targets/
│   └── <program-name>/
│       ├── scope.txt               ← copy from program page
│       ├── domains/
│       │   ├── ct_subdomains.txt   ← from crt.sh
│       │   ├── subfinder.txt       ← from subfinder
│       │   ├── all_subdomains.txt  ← merged master list
│       │   └── dns/
│       ├── http/
│       │   ├── probed.json
│       │   └── screenshots/
│       ├── endpoints/
│       │   ├── js_endpoints.txt
│       │   └── params.txt
│       ├── notes.md
│       └── findings/
│           └── potential/
├── tools/
├── wordlists/
└── scripts/
```

```bash
# Create base structure
mkdir -p ~/recon/{targets,tools,wordlists,scripts}
```

### notes.md template

```markdown
# Target: <Program Name>
**Program:** <Platform URL>
**Scope read:** YYYY-MM-DD
**Last updated:** YYYY-MM-DD

## Scope
### In scope
- *.example.com

### Out of scope
- blog.example.com

## Discoveries

### <subdomain>
- Discovery source: crt.sh / subfinder / Shodan
- Resolves to: <IP>
- IP owner: <target ASN / Cloudflare / AWS>
- Open ports (Shodan): <ports>
- Software: <name and version>
- Priority: High / Medium / Low / Skip
- Reason: <one sentence>
- Next action: <specific>
- Date: YYYY-MM-DD

## Questions / Ambiguities
- Is X in scope? Not listed. Assume no until confirmed.

## Dead Ends
- careers.example.com — hosted on Greenhouse (third party), skip

## Commands Run
YYYY-MM-DD HH:MM — subfinder -d example.com -o domains/subfinder.txt
```

### What good notes contain

- Exact commands with timestamps
- What each discovery resolves to (IP, CNAME, third party confirmed)
- Decision and reason for each asset (test / skip / ambiguous)
- Dead ends — so you never revisit them
- Open questions and how they were resolved

---

## 5. DNS — Commands and Record Types

### Record types and recon value

| Record | Stores | Why it matters |
|--------|--------|---------------|
| `A` | IPv4 address | What server does this name point to? |
| `AAAA` | IPv6 address | Same for IPv6 |
| `CNAME` | Alias to another domain | Reveals CDNs, third parties — critical for takeover recon |
| `MX` | Mail servers | Email infrastructure, often bypasses CDN |
| `NS` | Nameservers | Zone control — shared NS signals shared ownership |
| `TXT` | Arbitrary text | SPF/DKIM, verification tokens, occasionally secrets |
| `SOA` | Zone authority | Can reveal internal hostnames and admin emails |

### Essential dig commands

```bash
# A record
dig example.com A

# All records
dig example.com ANY

# Specific record type
dig example.com NS
dig example.com MX
dig example.com TXT
dig example.com CNAME

# Query a specific resolver
dig @8.8.8.8 example.com A
dig @1.1.1.1 example.com A

# Reverse lookup — IP to hostname
dig -x 93.184.216.34

# Short output only
dig +short example.com A

# Trace full resolution path
dig +trace example.com
```

### DNS signals to look for

- **TXT records:** SPF `include:` statements list all mail providers. Verification tokens reveal what services the org uses. Occasionally contain leaked API keys or internal data.
- **CNAME chains:** Pointing to third-party services — foundational for subdomain takeover identification (Module 3).
- **NS delegation:** NS records differing from the parent zone indicate a separately managed subdomain zone.
- **MX records:** Reveal self-hosted vs. provider-based email. MX servers often bypass CDNs and reveal direct IPs.

### DNS common mistakes

- Only querying A records — always pull TXT, MX, NS, CNAME
- Not timestamping queries — DNS changes, you need to know when you saw what
- Trusting cached responses — if something seems wrong, try multiple resolvers
- Treating DNS as a formality — subdomain takeovers and misconfigurations live here

---

## 6. WHOIS — Domain and IP Intelligence

### Command syntax

```bash
# Domain WHOIS
whois example.com

# IP WHOIS — who owns this IP block?
whois 93.184.216.34

# Grep for key fields
whois example.com | grep -iE "name|org|email|server|date"
```

### Fields and their recon value

| Field | What to do with it |
|-------|-------------------|
| `Registrant Org` | Search for all domains registered by this org (reverse WHOIS) |
| `Registrant Email` | Pivot — find other domains registered with same email |
| `Name Servers` | Shared custom NS = shared ownership |
| `Creation Date` | Very new = staging/test. Very old = potentially forgotten |
| `Updated Date` | Recent = infrastructure change |
| `Expiry Date` | Near-expiry = possibly abandoned asset |

### Reverse WHOIS tools

| Tool | URL | Cost |
|------|-----|------|
| ViewDNS | https://viewdns.info/reversewhois/ | Free |
| WhoisXML API | https://whoisxmlapi.com | Paid |
| DomainTools | https://domaintools.com | Expensive |

### Nameserver pivoting

```bash
# Two domains sharing custom nameservers = same owner
dig example.com NS
dig example-payments.com NS
# If both return ns1.example-internal.com → same organization
```

---

## 7. Certificate Transparency Logs

### What it is

Every SSL/TLS certificate issued since 2015 must be logged in a public Certificate Transparency log. Every subdomain that has received an HTTPS cert is permanently and publicly recorded.

### crt.sh commands

```bash
# Browser
https://crt.sh/?q=%.example.com

# CLI — fetch, parse, deduplicate, clean
curl -s "https://crt.sh/?q=%.example.com&output=json" \
  | jq -r '.[].name_value' \
  | sed 's/\*\.//g' \
  | sort -u \
  | grep -v "^$" \
  > ~/recon/targets/example/domains/ct_subdomains.txt

# Count results
wc -l ct_subdomains.txt
```

### What to check in raw CT output

- **SAN certificates:** One cert can cover multiple domains. Inspect full SAN list for bonus subdomain discoveries.
- **Wildcard certs:** `*.example.com` in CT output signals a subdomain zone exists — the wildcard itself isn't actionable, but any accompanying SANs are.
- **Historical subdomains:** CT logs go back years. Subdomains no longer in DNS may still be live hosts.

### CT output — noise vs. signal

| Signal | Noise |
|--------|-------|
| `dev.example.com` | `*.example.com` (wildcard entry) |
| `internal-tools.example.com` | Entries with spaces or special characters |
| `legacy-api.example.com` | Domains not ending in target root (SAN cross-contamination) |

### CT sources

| Source | Notes |
|--------|-------|
| crt.sh | Primary — free, JSON API |
| Censys | Free account — richer, rate-limited |
| CertSpotter | Real-time monitoring |
| subfinder | Aggregates CT + many other sources |

---

## 8. subfinder — Passive Subdomain Enumeration

### Install and verify

```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
subfinder -version
```

### Core commands

```bash
# Standard run
subfinder -d example.com -o subfinder.txt

# Silent — output only, no banner
subfinder -d example.com -silent

# Verbose — see which sources return results
subfinder -d example.com -v

# Multiple domains from file
subfinder -dL domains.txt -silent -o all_subdomains.txt

# Increase threads
subfinder -d example.com -t 50 -silent
```

### API key configuration

`~/.config/subfinder/provider-config.yaml`:

```yaml
virustotal:
  - YOUR_VT_KEY
shodan:
  - YOUR_SHODAN_KEY
censys:
  - YOUR_CENSYS_ID:YOUR_CENSYS_SECRET
```

Free keys worth getting: VirusTotal, Shodan, Censys.

### What subfinder sources add over crt.sh alone

- VirusTotal passive DNS — historical resolution data
- Shodan hostnames — from banner and cert scanning
- HackerTarget, URLScan, AlienVault OTX
- Typically 10–30% more coverage than CT logs alone

### Limitations

- Entirely passive — will miss subdomains with no historical DNS or cert record
- Does not verify whether discovered subdomains are live (Module 3)
- Source quality varies — some aggregators have stale data

---

## 9. ASN and IP Range Mapping

### What an ASN is

An Autonomous System Number (ASN) identifies a network operated by a single organization. Finding the target's ASN gives you every IP range they own.

### Finding an ASN

```bash
# WHOIS on a known target IP
whois 93.184.216.34 | grep -iE "as|origin|org"

# asnmap — domain to ASN
asnmap -d example.com
asnmap -d example.com -silent   # CIDR output only

# Hurricane Electric web UI
https://bgp.he.net/              # search company name or domain

# RADb query
whois -h whois.radb.net -- '-i origin AS12345' | grep "route:"
```

### Extracting IP ranges from an ASN

```bash
# asnmap
asnmap -a AS15169 -silent

# Hurricane Electric
https://bgp.he.net/AS15169#_prefixes
```

### Cross-referencing subdomains and ASNs

```bash
# Resolve subdomain
dig +short api.example.com
# Returns: 203.0.113.45

# Check IP ownership
whois 203.0.113.45 | grep -iE "org|netname|owner"
# Returns target org name = target-owned
# Returns "Cloudflare" = CDN, not target infrastructure
```

### Known CDN and cloud ASNs

| Provider | ASN |
|----------|-----|
| Cloudflare | AS13335 |
| AWS | AS16509 |
| Google Cloud | AS15169 |
| Azure | AS8075 |
| Fastly | AS54113 |
| Akamai | AS20940 |

---

## 10. Shodan — Passive Infrastructure Recon

### Setup

```bash
pip install shodan --break-system-packages
shodan init YOUR_API_KEY
shodan info    # verify
```

### Core queries

```bash
# By hostname
shodan search hostname:example.com

# By organization
shodan search org:"Example Corp"

# By IP
shodan host 93.184.216.34

# By CIDR range
shodan search net:203.0.113.0/24

# By SSL certificate — HIGH VALUE
shodan search ssl:"example.com"
shodan search ssl.cert.subject.cn:example.com
```

### Web UI queries (no API key required for basic search)

```
hostname:example.com
org:"Example Corp"
ssl:"example.com"
ssl.cert.subject.cn:example.com
product:"Apache Tomcat"
http.title:"Example Corp"
```

### The ssl: query — why it matters

`ssl:"example.com"` finds any server whose TLS cert mentions the target's domain. Reveals:

- Servers on non-standard ports (8080, 8443, 9090)
- Origin servers hiding behind Cloudflare or other CDNs
- Internal infrastructure accidentally internet-exposed
- Development and staging servers with real production certs

### What a Shodan result tells you

```
IP: 203.0.113.45
Ports: 22, 80, 443, 8080
Banner (8080): Apache Tomcat/7.0.47
Cert CN: staging.example.com
Org: Example Corp
ASN: AS64512
Last seen: 2025-06-01
```

Reading this: target-owned IP (their ASN), old Tomcat on non-standard port, cert confirms it serves a staging subdomain.

### Shodan limitations

- Data may be weeks or months old — not real time
- Coverage varies by IP range
- Free tier: limited queries, no historical data
- Does not exploit — observation only

---

## 11. Cloud and CDN Handling

### Identify CDN vs. direct IPs

```bash
# Resolve and check ownership
dig +short api.example.com
whois <returned IP> | grep -iE "org|netname"
```

### What the ownership result means

| IP owner | Your approach |
|----------|--------------|
| Target's own ASN | Infrastructure target — enumerate services, ports, software |
| Cloudflare / Fastly | Application-layer target — focus on endpoints, auth, business logic |
| AWS / GCP / Azure | May still be target's cloud infra — check via org/account context |
| Known third-party SaaS | Not a testing target — record and skip |

### Finding origin IPs behind CDNs

| Technique | How |
|-----------|-----|
| Historical DNS | viewdns.info/iphistory or SecurityTrails — pre-CDN A records |
| Shodan ssl: | `ssl:"example.com"` — origin may have matching cert |
| MX records | `dig example.com MX` — mail often bypasses CDN |
| HTTP headers | `X-Real-IP`, `X-Origin-Server`, `CF-Connecting-IP` misconfigs |
| Favicon hash | Shodan can match favicons across IPs |

```bash
# Historical DNS lookup
https://viewdns.info/iphistory/?domain=example.com

# MX bypass
dig example.com MX
whois $(dig +short example.com MX | awk '{print $2}' | head -1)
```

---

## 12. Merging and Deduplicating Output

```bash
# Merge two files
cat ct_subdomains.txt subfinder.txt | sort -u > all_subdomains.txt

# Merge all .txt files in directory
cat ~/recon/targets/example/domains/*.txt | sort -u > all_subdomains.txt

# Remove wildcard entries
grep -v "^\*\." all_subdomains.txt > clean_subdomains.txt

# Remove blank lines
sed '/^$/d' all_subdomains.txt > clean_subdomains.txt

# Filter to target root only
grep "\.example\.com$" all_subdomains.txt > filtered.txt

# Count
wc -l all_subdomains.txt
```

---

## 13. Triage and Prioritization

### Priority tiers

| Tier | Criteria | Action |
|------|----------|--------|
| **High** | Target ASN, no CDN, non-production naming, old software | Enumerate immediately |
| **Medium** | CDN-fronted, interesting naming, non-standard ports | Enumerate after high |
| **Low** | Standard production assets, marketing sites | Enumerate later |
| **Skip** | Confirmed third-party infra, out of scope | Document and ignore |

### Signals that raise priority

- **Naming:** `legacy`, `internal`, `admin`, `dev`, `staging`, `test`, `old`, `backup`, `mgmt`, `api`
- **No CDN:** resolves directly to target ASN
- **Non-standard ports:** 8080, 8443, 9090, 3000, 4000, 9200
- **Old software:** Tomcat 7.x, Apache 2.2, PHP 5.x, Nginx < 1.14
- **Recent cert on subdomain not in current DNS**

---

## 14. The Full Passive Recon Workflow

```
1. Read scope → scope.txt
         │
         ▼
2. WHOIS root domain
   → org name, email, NS
   → reverse WHOIS if visible
         │
         ▼
3. Certificate Transparency
   → crt.sh curl + jq → ct_subdomains.txt
   → subfinder run → subfinder.txt
   → merge → all_subdomains.txt
         │
         ▼
4. ASN mapping
   → asnmap / bgp.he.net
   → extract CIDR ranges
   → WHOIS resolved IPs — confirm ownership
         │
         ▼
5. Shodan
   → org:"Target" + ssl:"target.com"
   → note open ports, banners, software versions
         │
         ▼
6. Merge and deduplicate all sources
   → sort -u → master subdomain list
   → filter wildcards and garbage
         │
         ▼
7. Triage
   → assign High / Medium / Low / Skip
   → document each with reason and next action
         │
         ▼
8. Update notes.md
   → timestamped findings, decisions, dead ends
```

---

## 15. Tool Reference Card

| Tool | Purpose | Install | Key command |
|------|---------|---------|-------------|
| `dig` | DNS queries | `apt install dnsutils` | `dig example.com ANY` |
| `whois` | Domain and IP registration data | `apt install whois` | `whois example.com` |
| `curl` + `jq` | CT log queries and JSON parsing | `apt install curl jq` | `curl -s "https://crt.sh/?q=%.example.com&output=json" \| jq -r '.[].name_value'` |
| `subfinder` | Passive subdomain enumeration | `go install ...subfinder@latest` | `subfinder -d example.com -silent` |
| `asnmap` | Domain to ASN and CIDR mapping | `go install ...asnmap@latest` | `asnmap -d example.com -silent` |
| `shodan` | Internet-wide service scanning database | `pip install shodan` | `shodan search ssl:"example.com"` |
| `sort` | Deduplication and sorting | built-in | `sort -u file.txt` |
| `grep` | Filtering output | built-in | `grep "\.example\.com$" file.txt` |
| `sed` | Text transformation | built-in | `sed 's/\*\.//g' file.txt` |
| `wc` | Line counting | built-in | `wc -l file.txt` |

### Useful web resources

| Resource | URL | Use |
|----------|-----|-----|
| crt.sh | https://crt.sh | CT log query |
| ViewDNS | https://viewdns.info | Reverse WHOIS, IP history, DNS tools |
| BGP Hurricane Electric | https://bgp.he.net | ASN lookup, IP range mapping |
| Shodan web | https://shodan.io | Infrastructure search |
| Censys | https://search.censys.io | Certificate and infrastructure search |
| CertSpotter | https://sslmate.com/certspotter | Real-time CT monitoring |

---

## 16. Common Mistakes Reference

| Mistake | Why it matters | Correct approach |
|---------|---------------|-----------------|
| Skipping scope check | Can get you banned or in legal trouble | Always read full policy before any action |
| Testing third-party IPs | You're testing Cloudflare, not the target | Always WHOIS the resolved IP first |
| Only querying A records | Miss MX, TXT, NS, CNAME intelligence | Pull all record types as standard |
| Only using one subdomain source | Miss 30%+ of assets | Combine crt.sh + subfinder at minimum |
| Treating all subdomains equally | Wastes time on low-value assets | Triage before enumerating |
| Skipping the ssl: Shodan query | Miss origin servers and non-standard ports | Always run ssl:"target.com" on Shodan |
| Port-scanning CDN IPs | Testing Cloudflare infrastructure | Identify CDN fronting, pivot to app layer |
| Not recording commands | Lose reproducibility | Timestamp every command in notes.md |
| Using Shodan results as ground truth | Data may be weeks old | Verify with live probing (Module 3) |
| Probing for CVEs during passive recon | Active exploitation before scope/timing confirmed | Record version, research, probe later |

---

## 17. Key Vocabulary

| Term | Definition |
|------|-----------|
| **ASN** | Autonomous System Number — identifies all IP ranges operated by one organization |
| **CIDR** | Classless Inter-Domain Routing — IP range notation, e.g. `203.0.113.0/24` |
| **CNAME** | Canonical Name — DNS alias record pointing one domain to another |
| **CT log** | Certificate Transparency log — public ledger of all issued TLS certificates |
| **CDN** | Content Delivery Network — proxy infrastructure (Cloudflare, Fastly, Akamai) |
| **Passive recon** | Intelligence gathering with zero packets sent to the target |
| **Reverse WHOIS** | Finding all domains registered by a specific org name or email address |
| **SAN** | Subject Alternative Name — TLS cert field listing all domains a cert covers |
| **Scope** | Legal boundary of testing defined by the bug bounty program |
| **Subdomain takeover** | Claiming a subdomain whose CNAME points to a deleted/unclaimed third-party resource |
| **WAF** | Web Application Firewall — typically deployed at CDN layer, bypassed by direct IP |
| **WHOIS** | Protocol returning registration metadata for domains and IP blocks |
| **Wildcard DNS** | `*.example.com` — matches any subdomain of example.com |
| **Zone transfer** | DNS mechanism to replicate a zone — misconfigured servers leak all DNS records |

---

*Part of a structured bug bounty reconnaissance curriculum. Legal, authorized targets only.*
*Updated after each module. Always check for the latest version.*