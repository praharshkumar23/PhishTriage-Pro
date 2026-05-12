import json, os
from datetime import datetime
from urllib.parse import urlparse

def generate_escalation_pack(scan_data: dict, analyst: str = "Praharsh Kumar",
                               escalate_to: str = "L2 Analyst",
                               incident_id: str = "INC-2026-0000") -> str:
    """
    Auto-generate a rich escalation pack from real scan data.
    Includes: timeline, all API results, IOCs, verdict, recommended actions.
    Ready to paste into Jira/ServiceNow or send to L2.
    """
    ts     = datetime.now().strftime("%Y-%m-%d %H:%M IST")
    url    = scan_data.get("url", "Not provided")
    score  = scan_data.get("score", 0)
    verdict = scan_data.get("verdict", "UNKNOWN")
    mode   = scan_data.get("mode", "offline")
    flags  = scan_data.get("flags", [])

    # Extract domain/IP
    try:
        parsed = urlparse(url if url.startswith("http") else "https://" + url)
        domain = parsed.netloc.replace("www.", "").split(":")[0]
    except:
        domain = "Unknown"

    # Severity mapping
    if score >= 70:
        severity = "🔴 HIGH"
        sla      = "Respond within 1 hour"
        action   = "Block immediately, notify security team, initiate IR process"
    elif score >= 40:
        severity = "🟡 MEDIUM"
        sla      = "Respond within 4 hours"
        action   = "Investigate further, monitor for user interaction"
    else:
        severity = "🟢 LOW"
        sla      = "Respond within 24 hours"
        action   = "Log and monitor, likely benign"

    api_results = scan_data.get("api_results", {})
    vt   = api_results.get("virustotal", {})
    ab   = api_results.get("abuseipdb", {})
    otx  = api_results.get("otx", {})
    gsb  = api_results.get("gsb", {})
    seen = scan_data.get("seen_before", {})

    pack = f"""# 🚨 SOC Escalation Pack — {incident_id}

---

## Incident Overview
| Field | Value |
|---|---|
| **Incident ID** | {incident_id} |
| **Generated** | {ts} |
| **Analyst (L1)** | {analyst} |
| **Escalate To** | {escalate_to} |
| **Severity** | {severity} |
| **SLA** | {sla} |

---

## Verdict
> **{verdict} — {score}/100**
> Mode: `{mode}`
> {action}

---

## IOCs Extracted
| Type | Value |
|---|---|
| URL | `{url}` |
| Domain | `{domain}` |
| Score | {score}/100 |
| Attack Vector | Phishing Link |

---

## Detection Signals
"""
    for f in flags:
        pack += f"- {f}
"

    pack += f"""
---

## API Intelligence
### VirusTotal
"""
    if vt.get("available"):
        pack += f"- Malicious engines: **{vt.get('malicious',0)}/{vt.get('total',0)}**
"
        pack += f"- Suspicious: {vt.get('suspicious',0)}
"
        pack += f"- Harmless: {vt.get('harmless',0)}
"
    else:
        pack += f"- {vt.get('error', 'Not available')}
"

    pack += "
### AbuseIPDB
"
    if ab.get("available"):
        pack += f"- Abuse confidence: **{ab.get('abuse_confidence',0)}%**
"
        pack += f"- Total reports: {ab.get('total_reports',0)}
"
        pack += f"- Country/ISP: {ab.get('country','?')} / {ab.get('isp','?')}
"
        pack += f"- Tor node: {'YES ⚠️' if ab.get('is_tor') else 'No'}
"
    else:
        pack += f"- {ab.get('error', 'Not available (domain-based URL, no IP)')}
"

    pack += "
### AlienVault OTX
"
    if otx.get("available"):
        pack += f"- Domain pulses: **{otx.get('domain_pulses',0)}**
"
        pack += f"- IP pulses: {otx.get('ip_pulses',0)}
"
        pack += f"- Verdict: {otx.get('verdict','?')}
"
        if otx.get("tags"):
            pack += f"- Tags: {', '.join(otx.get('tags',[]))}
"
    else:
        pack += f"- {otx.get('error', 'Not available')}
"

    pack += "
### Google Safe Browsing
"
    if gsb.get("available"):
        threats = gsb.get("threats", [])
        pack += f"- {'🔴 Flagged: ' + ', '.join(threats) if threats else '🟢 Not flagged'}
"
    else:
        pack += f"- {gsb.get('error', 'Not available')}
"

    pack += f"""
---

## Prior History
"""
    if seen.get("seen"):
        pack += f"⚠️ **{seen.get('message','')}**
"
        pack += f"- Total prior matches: {seen.get('total_matches',0)}
"
        pack += f"- Malicious hits: {seen.get('malicious_hits',0)}
"
    else:
        pack += "🟢 First time seeing this URL — no prior history.
"

    pack += f"""
---

## Recommended Actions
- [ ] Block `{domain}` at web proxy and DNS filter
- [ ] Search email logs: who else received a link to this domain?
- [ ] Search EDR logs for click events to `{domain}`
- [ ] Force password reset for any user who clicked
- [ ] Add to SIEM blocklist (see SIEM Queries tab)
- [ ] Update ticket with user impact assessment
- [ ] Notify manager if {score} >= 70 (HIGH severity)

---

## What L1 Already Checked
- [x] Static heuristic analysis — Score: {score}/100
- [x] Domain extracted and IOCs noted
- {'[x]' if vt.get('available') else '[ ]'} VirusTotal {'— ' + str(vt.get('malicious',0)) + ' engines flagged' if vt.get('available') else '— API key needed'}
- {'[x]' if ab.get('available') else '[ ]'} AbuseIPDB {'— ' + str(ab.get('abuse_confidence',0)) + '% confidence' if ab.get('available') else '— No IP in URL'}
- {'[x]' if otx.get('available') else '[ ]'} AlienVault OTX {'— ' + str(otx.get('domain_pulses',0)) + ' pulses' if otx.get('available') else '— API key needed'}
- {'[x]' if gsb.get('available') else '[ ]'} Google Safe Browsing {'— ' + str(gsb.get('verdict','')) if gsb.get('available') else '— API key needed'}
- [x] Prior history checked — {'MATCH FOUND' if seen.get('seen') else 'No prior hits'}

---

*Generated by PhishTriage Pro | Built by Praharsh Kumar*
*This report is auto-generated. Always verify before taking action.*
"""
    return pack
