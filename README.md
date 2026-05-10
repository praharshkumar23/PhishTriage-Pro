# 🎯 PhishTriage Pro

> **Not just detection. Full phishing incident workflow.**
>
> *Detects the phishing link in 30 seconds. Gives the L1 analyst everything they need to respond in 60.*

[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://python.org)
[![Streamlit](https://img.shields.io/badge/built%20with-Streamlit-red)](https://streamlit.io)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![SOC Ready](https://img.shields.io/badge/SOC-L1%20Ready-green)](#)

---

## 🚨 The Real Problem

Most phishing tools stop at a verdict. In a real SOC, that is where the work begins.

After every phishing alert, an L1 analyst manually:

| Task | Time without PhishTriage |
|------|--------------------------|
| Write IOC list (URL, domain, IP, hash) | 10–15 min |
| Map to MITRE ATT&CK | 5–10 min |
| Look up IP reputation | 5–10 min |
| Check OTX for threat actor context | 5–10 min |
| Write Splunk or KQL hunt query | 15–20 min |
| Prepare firewall block rule | 5 min |
| Write shift handoff note | 20–30 min |
| Check 40+ user-reported phishing emails | 60–90 min |
| Log false positive reason | Rarely done |

**Total: 2–3 hours per incident, every shift. PhishTriage significantly reduces repetitive investigation time.**

---

## 🌐 The Core Problem: New IPs and Domains

The hardest phishing to catch is from attackers using **brand new infrastructure** — IP registered yesterday, domain 2 hours old, not on any blocklist yet.

PhishTriage's multi-source approach handles this:

| Source | What it catches | Why it matters for new threats |
|--------|----------------|-------------------------------|
| **urlscan.io** | Screenshot, redirect chain, all loaded IPs, DOM hash | Sees what the page actually does — attacker can't hide redirects |
| **AbuseIPDB** | IP abuse confidence 0–100% | Attacker buys new domain but uses the same hosting IP — IP may already be flagged |
| **AlienVault OTX** | Researcher pulses, threat actor groups, malware families | Community may already have a pulse about that IP range even if domain is new |
| **Google Safe Browsing** | SOCIAL_ENGINEERING list, updated from Chrome reports | Chrome users hit it → Google flags it fast, sometimes within hours |
| **Local Heuristics** | Brand-in-subdomain, IP-as-host, homoglyph, HTTP on login page | Catches attacker tricks that APIs miss — works with zero API keys |

If 3 or more sources flag the URL → tool marks it MALICIOUS with confidence %.

---

## ⚡ All 6 Features

### Feature 1 — Instant Investigation Pack
Paste URL → get in one click:
- IOC list (URL, domain, IP, path, hash)
- MITRE ATT&CK mapping + follow-on chain
- Incident timeline (T+0 to T+7 min)
- Block rules for proxy, DNS, firewall, email gateway
- Splunk SPL + Sentinel KQL preview

### Feature 2 — Multi-Source Threat Intel
Runs 4 APIs + local heuristics in sequence. Handles brand-new IPs/domains.
Aggregate verdict with confidence %. Each source explains what it found and why.

### Feature 3 — Shift Handoff Report
One form → one note → paste into Jira / ServiceNow / Teams / Slack.
Includes MITRE chain, users clicked, status, next action. Done in 90 seconds.

### Feature 4 — Bulk Email Header Triage
Paste 50 emails → sorted by risk score. 🔴 HIGH first. Skip the 🟢 LOW.
Checks SPF/DKIM/DMARC, Reply-To mismatch, brand spoofing, urgency keywords.

### Feature 5 — False Positive Explainer + Pattern Memory
Log why an alert is FP. Tool tracks repeat closures. If same indicator is FP 3+ times → suggests suppression rule. Builds a team FP database over time.

### Feature 6 — Context-Aware SIEM Query Generator
Paste URL → get 6 ready-to-run queries (Splunk proxy, DNS, email + KQL network, email, endpoint) + block rule. No Googling, no asking seniors.

---

## 🛠️ Tools & APIs

| Tool | Purpose | Cost |
|------|---------|------|
| Python 3.9+ | Core language | Free |
| Streamlit | Web UI | Free |
| `requests` | API calls | Free |
| `socket` stdlib | Live DNS resolution | Free |
| `urllib.parse` stdlib | URL parsing | Free |
| `re` stdlib | Email header parsing | Free |
| **urlscan.io API** | Page scan, screenshot, redirects | Free 5,000/month |
| **AbuseIPDB API** | IP reputation, abuse score | Free 1,000/day |
| **AlienVault OTX API** | Domain/IP threat intel, actor groups | Free unlimited |
| **Google Safe Browsing API** | Phishing/malware real-time list | Free 10,000/day |

**All four APIs have free tiers. Total monthly cost: $0.**

---

## 🚀 How to Run — Step by Step

### Step 1 — Clone the repo
```bash
git clone https://github.com/praharshkumar23/PhishTriage.git
cd PhishTriage
```

### Step 2 — Create virtual environment
```bash
# Windows
python -m venv venv
venv\Scripts\activate

# macOS / Linux
python3 -m venv venv
source venv/bin/activate
```

### Step 3 — Install dependencies
```bash
pip install -r requirements.txt
```
Only installs `streamlit` and `requests`. Everything else is Python stdlib.

### Step 4 — Set up API keys (optional but recommended)
```bash
cp .env.example .env
```
Open `.env` and add your keys. All four API keys are free:

| API | Where to get the free key |
|-----|--------------------------|
| urlscan.io | https://urlscan.io/user/signup |
| AbuseIPDB | https://www.abuseipdb.com/register |
| AlienVault OTX | https://otx.alienvault.com → Settings → API Key |
| Google Safe Browsing | https://console.cloud.google.com → Enable Safe Browsing API |

The tool works without any keys — local heuristics always run.

### Step 5 — Load environment variables
```bash
# Linux / macOS
export $(grep -v '^#' .env | xargs)

# Windows PowerShell
Get-Content .env | ForEach-Object { if ($_ -notmatch '^#') { $k,$v = $_ -split '=',2; [System.Environment]::SetEnvironmentVariable($k,$v) } }
```

### Step 6 — Run the app
```bash
streamlit run app.py
```

Opens at: **http://localhost:8501**

### Step 7 — Test with sample data
- `samples/sample_headers.txt` — paste into Bulk Triage tab
- `samples/sample_incident.json` — use values to test Handoff tab

---

## 🏢 L1 SOC Daily Use — Real Scenarios

### You get an alert: suspicious link in HR email
1. Open PhishTriage → Tab 1 (Investigation Pack)
2. Paste URL → Generate Pack
3. IOC list, MITRE map, block rule ready in 3 seconds
4. Copy Splunk query → run in your SIEM → find who clicked
5. Tab 2 (Threat Intel) → Run Full Intel → check if IP is known bad
6. Escalate or contain based on aggregate verdict

### Shift ends in 10 minutes, open incident needs handoff
1. Tab 3 (Shift Handoff)
2. Fill 6 fields, click Generate
3. Copy formatted note into Jira/ServiceNow
4. Done in 90 seconds instead of 30 minutes

### 42 phishing emails in the user-reported queue
1. Tab 4 (Bulk Triage)
2. Paste all headers → Triage All
3. Work 🔴 HIGH ones first
4. Quick-close 🟢 LOW without manual review
5. Total time: 10–15 min instead of 90 min

### Closing an alert as false positive
1. Tab 5 (False Positive)
2. Log indicator + reason
3. If same indicator appears 3+ times → tool surfaces it for suppression
4. Your team builds a FP database over time

### New phishing URL, domain registered today, not on any blocklist
1. Tab 2 (Threat Intel)
2. Paste URL → Run Full Intel
3. Local heuristics catch: free TLD + brand keyword in domain + HTTP on login page = HIGH
4. AbuseIPDB shows the hosting IP has 78% abuse confidence from past attacks
5. OTX shows 2 pulses referencing same IP range
6. Even with zero VT hits, you have strong evidence to escalate

---

## 🗂️ Project Structure

```
PhishTriage_Pro/
├── app.py                        ← Main Streamlit app (6 tabs)
├── requirements.txt              ← streamlit, requests
├── .env.example                  ← API key template
│
├── modules/
│   ├── offline_fallback.py   # Heuristic-only scoring when APIs fail
│   ├── suppression.py        # Allowlist & suppression logic
│   ├── campaign_correlation.py # Cluster IOCs into campaigns
│   ├── threat_intel.py       # API enrichment layer
│   ├── fp_memory.py          # False positive memory store
│   ├── handoff_engine.py     # Shift handoff report generator
│   ├── siem_queries.py       # KQL/SPL query generation
│   └── mitre_engine.py       # MITRE ATT&CK mapping
│
├── data/
│   ├── allowlist.json        # Editable list of suppressed domains
│   └── ioc_cache.json        # Cached known-bad domains (offline use)
│   ├── ioc_engine.py             ← IOC extraction, DNS, domain flagging
│   ├── mitre_engine.py           ← MITRE ATT&CK mapping
│   ├── siem_queries.py           ← Splunk SPL + KQL generator
│   ├── handoff_engine.py         ← Shift handoff builder
│   ├── bulk_triage.py            ← Email header scorer
│   ├── fp_memory.py              ← FP logging and pattern DB
│   └── threat_intel.py           ← 4 APIs + local heuristic engine
│
├── data/
│   └── fp_patterns.json          ← Persistent FP database
│
└── samples/
    ├── sample_headers.txt
    └── sample_incident.json
```

---

## 📐 MITRE ATT&CK Coverage

| Attack Type | Technique | Tactic | Follow-on |
|-------------|-----------|--------|-----------|
| Phishing Link | T1566.002 | Initial Access | T1078 — Valid Accounts |
| Phishing Attachment | T1566.001 | Initial Access | T1204 — User Execution |
| Credential Harvest | T1056.003 | Collection, Credential Access | T1078 — Valid Accounts |

---


---

## ⚠️ Limitations

PhishTriage Pro is a triage and investigation assistant, not an automatic decision engine.

- It does not replace analyst judgment.
- API results can timeout or rate-limit.
- Heuristic scoring can produce false positives.
- New attacker infrastructure can still evade detection.
- Low confidence does not mean safe.

The tool is designed to reduce manual work and surface good leads fast, not to make final closure decisions.

---

## 🧠 Why the Scoring Is More Realistic

Each signal is not treated the same. Strong sources should matter more than weak ones.

### Suggested weight model

| Signal | Weight | Why |
|--------|--------|-----|
| Google Safe Browsing hit | 40 | Direct phishing/malware signal |
| urlscan malicious verdict | 30 | Strong behavioral scan result |
| AbuseIPDB abuse score 70+ | 25 | Bad hosting infrastructure |
| OTX pulse count 3+ | 20 | Community threat context |
| IP-as-hostname | 20 | Common attacker trick |
| Free TLD + brand spoofing | 15 | Cheap infrastructure abuse |
| Reply-To mismatch | 15 | Very common in phishing |
| SPF/DKIM/DMARC fail | 10–15 | Email authenticity issue |
| Suspicious urgency words | 5 | Weak alone, useful with others |

This makes the tool harder to fool than a simple yes/no ruleset.

---



## 🛡️ Allowlist & Suppression

To reduce alert fatigue, PhishTriage Pro supports suppression rules:
- **Internal Domains:** Ignore company-owned domains and subdomains.
- **Scanner/Service Accounts:** Automatically ignore known security scanner traffic.
- **Known-Good Services:** Pre-approved SaaS, HR portals, or IT helpdesk links.
- **Analyst Overrides:** If an analyst flags a domain as "safe" once, it is cached to prevent future alerts.

## 🔌 Offline Fallback Mode

If APIs are unavailable (timeout, rate limits, or internet outage), the tool automatically switches to:
- **Local Heuristic Scoring:** All domain-based checks remain functional.
- **Cached Reputation:** Uses local cache of previously seen malicious IOCs.
- **Basic Forensic Extraction:** Header parsing and metadata extraction still work.

This ensures that even during a network disruption, the analyst can still perform initial triage.

## 🔗 Campaign Correlation

A single IOC is not enough. Phishing almost always comes as a campaign.

PhishTriage Pro should correlate these signals:
- Same sender infrastructure
- Same IP range
- Same ASN / hosting provider
- Same favicon hash
- Same redirect chain
- Same brand spoofing pattern
- Same subject style
- Same attachment hash

If 3 or more line up, the tool should mark it as the same campaign and group the incidents together.

---

## 🛡️ False Positive Controls

To avoid over-scoring legitimate traffic, the tool should support:
- Internal domain allowlists
- Scanner allowlists
- Reputation decay for old benign indicators
- Known business portal exceptions
- Department-specific baselines
- Analyst override comments

This is important because a real SOC gets a lot of noisy alerts from internal tools, marketing links, and security scanners.

---

## 🧩 Better Real-SOC Workflow

A good L1 flow looks like this:
1. User reports suspicious email.
2. Analyst pastes URL or headers into PhishTriage Pro.
3. Tool scores the message and runs enrichment.
4. Analyst reviews strong signals first.
5. If malicious, block and escalate.
6. If false positive, log the reason.
7. If repeated pattern, create suppression or tuning request.
8. Handoff summary goes to L2 or next shift.

That is the real value of the project.



## 🧮 Scoring Example

This is how a URL should score in a more realistic way:

| Signal | Example | Weight |
|--------|---------|--------|
| Google Safe Browsing hit | direct phishing match | 40 |
| urlscan malicious verdict | page behavior looks bad | 30 |
| AbuseIPDB confidence 70+ | bad hosting IP | 25 |
| OTX pulse count 3+ | community threat context | 20 |
| free TLD + brand spoofing | `amaz0n-verify.tk` | 15 |
| Reply-To mismatch | sender trick | 15 |
| SPF/DKIM/DMARC fail | email authenticity issue | 10–15 |
| urgency words | `verify now` | 5 |

The idea is simple: strong sources should outweigh weak hints.
A few weak indicators should not automatically create a malicious verdict.

## 📌 Resume Bullet

> Built **PhishTriage Pro**, an open-source SOC phishing incident workflow tool (Python + Streamlit) integrating 4 threat intel APIs (urlscan.io, AbuseIPDB, AlienVault OTX, Google Safe Browsing) plus local heuristic analysis to detect malicious URLs even when brand-new. Auto-generates IOC packs, MITRE ATT&CK mappings, Splunk SPL + Sentinel KQL hunt queries, shift handoff reports, bulk email triage, and a false-positive pattern database — reducing analyst response time from 2+ hours to under 2 minutes.

---

## 👤 Author

**Praharsh Kumar** — SOC Analyst  
[GitHub](https://github.com/praharshkumar23) | [LinkedIn](https://linkedin.com/in/praharshkumar23)

*Built for educational and defensive security research purposes.*
