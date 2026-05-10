
# ── Offline Fallback + Allowlist Support ──────────────────────────────────
try:
    from modules.offline_fallback import offline_score
    from modules.suppression import is_allowlisted, get_allowlist
    OFFLINE_AVAILABLE = True
except ImportError:
    OFFLINE_AVAILABLE = False
#!/usr/bin/env python3
"""
PhishTriage Pro — SOC Phishing Incident Workflow Tool
Author: Praharsh Kumar
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "modules"))

import json
import streamlit as st
from datetime import datetime

from ioc_engine     import build_ioc_list, extract_domain, resolve_ip, get_domain_age_flag
from mitre_engine   import get_mitre_mapping, get_mitre_chain
from siem_queries   import generate_all
from handoff_engine import generate_handoff
from bulk_triage    import triage_all
from fp_memory      import log_fp, get_fp_history, get_all_fp, FP_REASONS
from threat_intel   import run_full_intel, check_heuristics
from campaign_correlation import simple_campaign_cluster
from suppression import is_allowlisted

st.set_page_config(page_title="PhishTriage Pro", page_icon="🎯", layout="wide",
                   initial_sidebar_state="expanded")

st.markdown("""
<style>
  [data-testid="stSidebar"] { background: #0d1117; }
  .block-container { padding-top: 1.2rem; }
  code { font-size: 0.78rem !important; }
  .ioc-row {
    background: #161b22; border-left: 3px solid #f85149;
    border-radius: 4px; padding: 6px 12px; margin-bottom: 4px;
    font-family: monospace; font-size: 0.82rem;
  }
  .intel-card {
    background: #161b22; border: 1px solid #30363d;
    border-radius: 8px; padding: 12px 16px; margin-bottom: 8px;
  }
  .timeline-row {
    background: #161b22; border-left: 3px solid #388bfd;
    border-radius: 4px; padding: 6px 12px; margin-bottom: 4px; font-size: 0.82rem;
  }
  .verdict-box {
    border-radius: 8px; padding: 12px 18px;
    font-size: 1.05rem; font-weight: 600; margin-bottom: 10px;
  }
</style>
""", unsafe_allow_html=True)

# ── Sidebar ───────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("## 🎯 PhishTriage Pro")
    st.markdown("*Full SOC phishing incident workflow*")
    st.markdown("*Built by Praharsh Kumar*")
    st.markdown("---")
    st.markdown("""
**Tabs:**
1. 🔍 Investigation Pack
2. 🌐 Threat Intel (4 APIs)
3. 📋 Shift Handoff
4. 📧 Bulk Triage
5. ❌ False Positive
6. 🔎 SIEM Queries
""")
    st.markdown("---")
    keys_set = []
    for k in ["URLSCAN_API_KEY","ABUSEIPDB_API_KEY","OTX_API_KEY","GOOGLE_SAFE_BROWSING_KEY"]:
        if os.getenv(k): keys_set.append(k.split("_")[0])
    if keys_set:
        st.success(f"✅ APIs active: {', '.join(keys_set)}")
    else:
        st.warning("⚠️ No API keys set. Add to .env to enable live threat intel.")
    st.metric("FP Patterns Logged", len(get_all_fp()))
    st.markdown("---")
    st.markdown("[GitHub](https://github.com/praharshkumar23) | [LinkedIn](https://linkedin.com/in/praharshkumar23)")

st.markdown("# 🎯 PhishTriage Pro")
st.markdown("*Not just detection. Full phishing incident workflow.*")
st.markdown("---")

tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
    "🔍 Investigation Pack",
    "🌐 Threat Intel",
    "📋 Shift Handoff",
    "📧 Bulk Triage",
    "❌ False Positive",
    "🔎 SIEM Queries",
])

# ══════════════════════════════════════════════════════════════════════════════
# TAB 1 — INVESTIGATION PACK
# ══════════════════════════════════════════════════════════════════════════════
with tab1:
    st.markdown("### 🔍 Instant Investigation Pack")
    st.caption("Paste a flagged URL → get IOCs, MITRE mapping, block rules, SIEM queries, and timeline in one click.")
    st.markdown("---")

    c1, c2 = st.columns([3, 1])
    with c1:
        inv_url = st.text_input("Flagged URL", placeholder="http://amaz0n-verify.tk/login", key="inv_url")
    with c2:
        attack_type = st.selectbox("Attack type",
                                    ["phishing-link","phishing-attachment","credential-harvest"],
                                    key="atk")

    c3, c4, c5 = st.columns(3)
    inc_id       = c3.text_input("Incident ID", value=f"INC-{datetime.now().year}-0042", key="inc1")
    analyst      = c4.text_input("Analyst", value="Praharsh Kumar", key="an1")
    att_hash     = c5.text_input("Attachment hash (optional)", placeholder="SHA256…", key="ah")

    if st.button("⚡ Generate Investigation Pack", type="primary", use_container_width=True):
        if not inv_url:
            st.warning("Paste a URL first.")
        else:
            domain  = extract_domain(inv_url)
            ip      = resolve_ip(domain)
            iocs    = build_ioc_list(inv_url, att_hash or None)
            mitre   = get_mitre_mapping(attack_type)
            queries = generate_all(inv_url)
            heur    = check_heuristics(inv_url, domain)

            # Banner
            if heur["score"] >= 50:
                st.error(f"🚨 HIGH RISK — {heur['verdict']} | Domain: `{domain}`")
            else:
                st.warning(f"⚠️ UNDER INVESTIGATION — `{domain}`")

            st.markdown("---")
            st.markdown("#### 📌 IOC List")
            for ioc in iocs:
                icon = "🔴" if ioc["confidence"] == "High" else "🟡"
                st.markdown(
                    f'<div class="ioc-row">{icon} <b>{ioc["type"]}</b> &nbsp;|&nbsp; '
                    f'{ioc["value"]} &nbsp;|&nbsp; <span style="color:#8b949e">{ioc["note"]}</span></div>',
                    unsafe_allow_html=True)
            st.markdown(f"**Domain flag:** {get_domain_age_flag(domain)}")
            st.download_button("⬇️ Export IOC List",
                               "\n".join([f"{i['type']}: {i['value']}" for i in iocs]),
                               file_name=f"iocs_{inc_id}.txt")

            st.markdown("---")
            st.markdown("#### 🛡️ MITRE ATT&CK")
            m1, m2, m3 = st.columns(3)
            m1.metric("Technique", mitre["technique_id"])
            m2.metric("Tactic", mitre["tactic"])
            m3.metric("Follow-on", mitre["follow_on_id"])
            st.info(f"**{mitre['technique_id']} — {mitre['technique_name']}**  \n"
                    f"{mitre['description']}  \n"
                    f"**Follow-on risk:** {mitre['follow_on_id']} — {mitre['follow_on_name']}")

            st.markdown("---")
            st.markdown("#### 🕐 Incident Timeline")
            for t, ev in [
                ("T+0m","User reported suspicious link to SOC"),
                ("T+1m",f"URL queued: {inv_url}"),
                ("T+2m",f"Domain extracted: {domain}"),
                ("T+3m",f"IP resolved: {ip}"),
                ("T+4m",f"IOCs compiled — {len(iocs)} indicators"),
                ("T+5m",f"MITRE mapped: {mitre['technique_id']} → {mitre['follow_on_id']}"),
                ("T+6m","SIEM queries generated"),
                ("T+7m",f"Block rule ready | Analyst: {analyst}"),
            ]:
                st.markdown(
                    f'<div class="timeline-row"><b style="color:#388bfd">{t}</b> &nbsp;→&nbsp; {ev}</div>',
                    unsafe_allow_html=True)

            st.markdown("---")
            st.markdown("#### 🔒 Block Rules")
            st.code(queries["block_rule"], language="bash")

            st.markdown("---")
            st.markdown("#### 🔎 Quick SIEM Preview")
            q1, q2 = st.columns(2)
            q1.markdown("**Splunk SPL — Proxy Hunt**")
            q1.code(queries["splunk_proxy"], language="splunk")
            q2.markdown("**Sentinel KQL — Network**")
            q2.code(queries["kql_network"], language="sql")

            st.success(f"✅ Pack generated — {inc_id}")


# ══════════════════════════════════════════════════════════════════════════════
# TAB 2 — THREAT INTEL (4 APIs + local heuristics)
# ══════════════════════════════════════════════════════════════════════════════
with tab2:
    st.markdown("### 🌐 Multi-Source Threat Intel")
    st.caption(
        "Runs 4 independent APIs in sequence + local heuristic checks. "
        "Even if a domain is brand new and not on any blocklist, heuristics + OTX pulses often catch it."
    )

    # API status table
    with st.expander("📋 API Status & Free Tier Info", expanded=False):
        st.markdown("""
| API | What it checks | Free tier | Cost |
|-----|---------------|-----------|------|
| **urlscan.io** | Full page scan, screenshot, redirect chain, DOM, all loaded IPs | 5,000 scans/month | Free |
| **AbuseIPDB** | IP reputation, abuse confidence score, country, ISP, Tor exit | 1,000/day | Free |
| **AlienVault OTX** | Domain + IP pulses, threat actor groups, malware families | Unlimited | Free |
| **Google Safe Browsing** | Phishing + malware + social engineering real-time list | 10,000/day | Free |
| **Local Heuristics** | Homoglyph, subdomain chain, IP-as-host, brand spoofing, TLD | Unlimited | Always free |

All API keys go in `.env` file. See `.env.example`. Tool works without them — local heuristics always run.
""")

    st.markdown("---")
    ti_url = st.text_input("URL or domain to investigate", placeholder="http://amaz0n-verify.tk/login", key="ti_url")

    if st.button("🌐 Run Full Threat Intel", type="primary", use_container_width=True):
        if not ti_url:
            st.warning("Enter a URL first.")
        else:
            domain = extract_domain(ti_url)
            ip     = resolve_ip(domain)
            st.info(f"Checking: `{domain}` → IP: `{ip}`")

            with st.spinner("Running checks across all sources…"):
                results = run_full_intel(ti_url, ip, domain)

            agg = results["aggregate"]
            verdict_color = ("#f85149" if "MALICIOUS" in agg["overall_verdict"]
                             else "#d29922" if "SUSPICIOUS" in agg["overall_verdict"]
                             else "#3fb950")
            st.markdown(
                f'<div class="verdict-box" style="background:{verdict_color}22;border:1px solid {verdict_color}">'
                f'{agg["overall_verdict"]}<br>'
                f'<span style="font-size:0.8rem;font-weight:400">'
                f'{agg["high_signals"]}/{agg["total_checks"]} sources flagged | Confidence: {agg["confidence"]}'
                f'</span></div>',
                unsafe_allow_html=True)

            st.markdown("---")

            # ── urlscan.io ────────────────────────────────────────────────────
            r_us = results["urlscan"]
            with st.expander("🔍 urlscan.io — Page Scan & Screenshot", expanded=True):
                if r_us.get("error"):
                    st.warning(f"⚠️ {r_us['error']}")
                    st.markdown("""
**What this would show with an API key:**
- Full screenshot of the phishing page so you can see what victims see
- Every IP and domain the page loads (catches hidden trackers, C2 callbacks)
- Redirect chain — attackers chain: legit site → link shortener → attacker server
- DOM hash — compare to known phishing kits (same kit = same actor)
- Verdict score from urlscan's own ML model
- **Get your free key at: https://urlscan.io/user/signup**
""")
                elif r_us.get("available"):
                    m = "🔴 MALICIOUS" if r_us["malicious"] else "🟢 Not flagged"
                    st.metric("Verdict", m)
                    if r_us.get("screenshot"):
                        st.markdown(f"[📸 View Screenshot]({r_us['screenshot']})")
                    if r_us.get("ips"):
                        st.markdown(f"**IPs loaded by page:** {', '.join(r_us['ips'])}")

            # ── AbuseIPDB ─────────────────────────────────────────────────────
            r_ab = results["abuseipdb"]
            with st.expander("🛡️ AbuseIPDB — IP Reputation Check", expanded=True):
                if r_ab.get("error"):
                    st.warning(f"⚠️ {r_ab['error']}")
                    st.markdown("""
**What this would show with an API key:**
- Abuse confidence score 0–100% (80%+ = almost certainly malicious)
- Country and ISP hosting the phishing server
- Total abuse reports in last 90 days
- Whether IP is a Tor exit node (attackers use Tor for anonymity)
- Usage type: datacenter / residential / VPN / hosting

**Key insight for L1:** Attacker uses brand-new domain, but their hosting IP
has a 94% abuse confidence score → escalate immediately even if domain looks clean.

**Get your free key at: https://www.abuseipdb.com/register**
""")
                elif r_ab.get("available"):
                    conf = r_ab["abuse_confidence"]
                    a1,a2,a3,a4 = st.columns(4)
                    a1.metric("Abuse Confidence", f"{conf}%",
                               delta="HIGH RISK" if conf >= 70 else "MEDIUM" if conf >= 30 else "LOW")
                    a2.metric("Country", r_ab["country"])
                    a3.metric("Total Reports", r_ab["total_reports"])
                    a4.metric("Tor Exit Node", "YES ⚠️" if r_ab["is_tor"] else "No")
                    st.caption(f"ISP: {r_ab['isp']} | Last reported: {r_ab['last_reported']}")

            # ── OTX ──────────────────────────────────────────────────────────
            r_otx = results["otx"]
            with st.expander("📡 AlienVault OTX — Community Threat Intel", expanded=True):
                if r_otx.get("error"):
                    st.warning(f"⚠️ {r_otx['error']}")
                    st.markdown("""
**What this would show with an API key (it is FREE and unlimited):**
- Number of community threat intel pulses referencing this domain/IP
- Which threat actor groups have been linked to this infrastructure
- Malware families associated with this domain
- MITRE ATT&CK tags from researcher-authored pulses
- Context like "this domain is part of a BEC campaign targeting healthcare"

**This is the only free tool that gives you human-authored context — not just a score.**

**Get your free key at: https://otx.alienvault.com → create account → API key in settings**
""")
                elif r_otx.get("available"):
                    o1, o2 = st.columns(2)
                    o1.metric("Domain Pulses", r_otx["domain_pulses"])
                    o2.metric("IP Pulses", r_otx["ip_pulses"])
                    st.metric("OTX Verdict", r_otx["verdict"])
                    if r_otx["tags"]:
                        st.markdown(f"**Tags:** {' | '.join(r_otx['tags'])}")
                    if r_otx["malware_families"]:
                        st.markdown(f"**Malware families:** {', '.join(r_otx['malware_families'])}")

            # ── Google Safe Browsing ──────────────────────────────────────────
            r_gsb = results["gsb"]
            with st.expander("🔒 Google Safe Browsing — Phishing/Malware List", expanded=True):
                if r_gsb.get("error"):
                    st.warning(f"⚠️ {r_gsb['error']}")
                    st.markdown("""
**What this would show with an API key:**
- Whether URL is on Google's real-time SOCIAL_ENGINEERING list
  (credential harvesting, fake login pages)
- MALWARE — page serves drive-by malware
- UNWANTED_SOFTWARE — PUA / adware delivery
- Updates in near real-time from Chrome browser reports + Google crawlers

**Key insight:** A URL that is 3 hours old may not be on any community list yet,
but if Chrome users have visited it and reported it, Google flags it fast.

**Get your FREE key at: https://console.cloud.google.com → Safe Browsing API → free 10k/day**
""")
                elif r_gsb.get("available"):
                    st.metric("Google Verdict", r_gsb["verdict"])
                    if r_gsb["threats"]:
                        for t in r_gsb["threats"]:
                            st.error(f"🔴 Flagged as: {t}")

            # ── Local Heuristics ──────────────────────────────────────────────
            r_h = results["heuristics"]
            with st.expander("⚙️ Local Heuristics — No API Needed (Always Runs)", expanded=True):
                st.metric("Heuristic Score", f"{r_h['score']}/100 — {r_h['verdict']}")
                for flag in r_h["flags"]:
                    st.markdown(f"- {flag}")
                st.caption("Catches: IP-as-hostname, brand in subdomain, suspicious TLD, "
                           "HTTP on login page, deep subdomain chains, homoglyph domains, URL shorteners.")

            with st.expander("🧩 Campaign Correlation — Is this part of a bigger wave?", expanded=True):
                cc = simple_campaign_cluster(ti_url)
                c1, c2 = st.columns(2)
                c1.metric("Cluster Score", f"{cc['score']}/100")
                c2.metric("Cluster ID", cc['cluster_id'])
                st.markdown(f"**Domain:** `{cc['domain']}`")
                st.markdown("**Signals seen:**")
                for s in cc['signals']:
                    st.markdown(f"- {s}")
                st.info(cc['same_campaign_hint'])


# ══════════════════════════════════════════════════════════════════════════════
# TAB 3 — SHIFT HANDOFF
# ══════════════════════════════════════════════════════════════════════════════
with tab3:
    st.markdown("### 📋 Shift Handoff Report")
    st.caption("Fill the fields. One click gives you a note to paste into Jira/ServiceNow/Teams.")
    st.markdown("---")
    hc1, hc2 = st.columns(2)
    with hc1:
        h_inc  = st.text_input("Incident ID", value="INC-2026-0042", key="h_inc")
        h_url  = st.text_input("URL", placeholder="http://amaz0n-verify.tk/login", key="h_url")
        h_tgt  = st.number_input("Users targeted", 0, value=45, key="h_tgt")
        h_dept = st.text_input("Department", value="HR department", key="h_dept")
    with hc2:
        h_clk    = st.text_area("Users who clicked (one per line)",
                                 value="john@company.com\nsarah@company.com\nmark@company.com",
                                 height=95, key="h_clk")
        h_status = st.selectbox("Status", ["Open","In Progress","Contained","Closed"], key="h_st")
        h_assign = st.text_input("Assign to", value="L2 Analyst", key="h_ass")
    h_next = st.text_area("Next action", value="Check lateral movement on john@ machine. Review auth logs.", height=60, key="h_nxt")
    h_atk  = st.selectbox("Attack type (MITRE chain)", ["phishing-link","phishing-attachment","credential-harvest"], key="h_atk")

    if st.button("📋 Generate Handoff Note", type="primary", use_container_width=True):
        if not h_url:
            st.warning("Enter the URL.")
        else:
            clicked  = [l.strip() for l in h_clk.split("\n") if l.strip()]
            note     = generate_handoff(h_inc, h_url, h_tgt, h_dept, clicked,
                                        h_status, h_next, get_mitre_chain(h_atk), h_assign)
            st.code(note, language="text")
            st.download_button("⬇️ Download Handoff", note, file_name=f"handoff_{h_inc}.txt")
            st.success("Ready. Copy into your ticketing system.")


# ══════════════════════════════════════════════════════════════════════════════
# TAB 4 — BULK EMAIL TRIAGE
# ══════════════════════════════════════════════════════════════════════════════
with tab4:
    st.markdown("### 📧 Bulk Email Header Triage")
    st.caption("Paste multiple emails (separated by ---). Highest risk first. Skip the greens.")
    default = """From: Amazon Billing <notice@amaz0n-verify.tk>
Reply-To: reset@amaz0n-verify.tk
Subject: Urgent: verify your password now
Received-SPF: fail
https://amaz0n-verify.tk/login

---

From: HR Team <hr@company.com>
Reply-To: hr@company.com
Subject: Policy update for all employees

---

From: Microsoft Security <alert@microsoft-login-support.xyz>
Reply-To: noreply@microsoft-login-support.xyz
Subject: Unusual sign-in detected — action required
DKIM=fail
https://microsoft-login-support.xyz/signin"""
    bulk_in = st.text_area("Paste emails here", value=default, height=260, key="bi")

    if st.button("📧 Triage All Emails", type="primary", use_container_width=True):
        if not bulk_in.strip():
            st.warning("Paste some emails first.")
        else:
            res = triage_all(bulk_in)
            high = sum(1 for r in res if "🔴" in r["priority"])
            med  = sum(1 for r in res if "🟡" in r["priority"])
            low  = sum(1 for r in res if "🟢" in r["priority"])
            st.markdown(f"**{len(res)} email(s) scored:** 🔴 {high} High &nbsp; 🟡 {med} Medium &nbsp; 🟢 {low} Low")
            st.markdown("---")
            for r in res:
                with st.expander(f"{r['priority']} — Risk: {r['risk_score']}/100 — {r['email_num']} — From: {r['from'][:50] or 'Unknown'}"):
                    e1, e2 = st.columns(2)
                    e1.write(f"**From:** {r['from']}")
                    e1.write(f"**Reply-To:** {r['reply_to'] or 'Same as From'}")
                    e1.write(f"**Subject:** {r['subject']}")
                    e2.metric("Risk Score", f"{r['risk_score']}/100")
                    if r["reasons"]:
                        st.markdown("**Why this score:**")
                        for reason in r["reasons"]: st.markdown(f"- {reason}")
                    if r["urls"]:
                        st.markdown("**URLs found:**")
                        for u in r["urls"]: st.code(u)


# ══════════════════════════════════════════════════════════════════════════════
# TAB 5 — FALSE POSITIVE
# ══════════════════════════════════════════════════════════════════════════════
with tab5:
    st.markdown("### ❌ False Positive Explainer")
    st.caption("43% of phishing alerts are FP. Log why — and stop investigating the same thing next week.")
    fp1, fp2 = st.columns(2)
    with fp1:
        fp_inc  = st.text_input("Incident ID", value="INC-2026-0049", key="fp_inc")
        fp_ind  = st.text_input("Indicator (URL, domain, IP, or hash)", key="fp_ind",
                                 placeholder="scanner.company.internal")
        fp_an   = st.text_input("Analyst", value="Praharsh Kumar", key="fp_an")
    with fp2:
        fp_r    = st.selectbox("FP Reason", FP_REASONS, key="fp_r")
        fp_n    = st.text_area("Notes", height=95, key="fp_n")

    if st.button("💾 Log False Positive", type="primary", use_container_width=True):
        if not fp_ind:
            st.warning("Enter the indicator.")
        else:
            rec  = log_fp(fp_inc, fp_ind, fp_r, fp_an, fp_n)
            hist = get_fp_history(fp_ind)
            st.success(f"✅ Logged. This indicator has been closed as FP **{len(hist)} time(s)**.")
            if len(hist) >= 3:
                st.error(f"⚠️ REPEATED FP — `{fp_ind}` closed {len(hist)} times. Recommend a suppression rule.")
            st.json(rec)

    st.markdown("---")
    st.markdown("#### 📂 FP Pattern Database (last 10)")
    all_fp = get_all_fp()
    if all_fp:
        for e in reversed(all_fp[-10:]):
            st.markdown(f"- **{e['timestamp']}** | `{e['indicator']}` | {e['reason']} | "
                        f"Analyst: {e['analyst']} | Times: **{e['repeat_count']}**")
    else:
        st.info("No false positives logged yet.")


# ══════════════════════════════════════════════════════════════════════════════
# TAB 6 — SIEM QUERIES
# ══════════════════════════════════════════════════════════════════════════════
with tab6:
    st.markdown("### 🔎 Context-Aware SIEM Query Generator")
    st.caption("Paste a URL or domain. Get 6 ready-to-run queries + block rule. No Googling.")
    siem_url = st.text_input("URL or domain", placeholder="http://amaz0n-verify.tk", key="siem_url")

    if st.button("🔎 Generate SIEM Queries", type="primary", use_container_width=True):
        if not siem_url:
            st.warning("Enter a URL or domain.")
        else:
            from ioc_engine import extract_domain as _ed
            q = generate_all(siem_url)
            st.info(f"Queries generated for domain: `{_ed(siem_url)}`")
            st.markdown("---")
            st.markdown("#### Splunk SPL")
            s1, s2 = st.columns(2)
            s1.markdown("**Proxy Hunt**");  s1.code(q["splunk_proxy"], language="splunk")
            s1.download_button("⬇️ Proxy SPL", q["splunk_proxy"], file_name="proxy.spl")
            s2.markdown("**DNS Hunt**");    s2.code(q["splunk_dns"],   language="splunk")
            s2.download_button("⬇️ DNS SPL", q["splunk_dns"],   file_name="dns.spl")
            st.code(q["splunk_email"], language="splunk"); st.download_button("⬇️ Email SPL", q["splunk_email"], file_name="email.spl")
            st.markdown("---")
            st.markdown("#### Microsoft Sentinel KQL")
            k1, k2 = st.columns(2)
            k1.markdown("**Network Events**");   k1.code(q["kql_network"],   language="sql")
            k1.download_button("⬇️ KQL Net",  q["kql_network"],   file_name="net.kql")
            k2.markdown("**Email Events**");     k2.code(q["kql_email"],     language="sql")
            k2.download_button("⬇️ KQL Email", q["kql_email"],     file_name="email.kql")
            st.code(q["kql_endpoint"], language="sql"); st.download_button("⬇️ KQL Endpoint", q["kql_endpoint"], file_name="endpoint.kql")
            st.markdown("---")
            st.markdown("#### 🔒 Block Rule")
            st.code(q["block_rule"], language="bash")
            st.download_button("⬇️ Block Rule", q["block_rule"], file_name="block_rule.txt")

st.markdown("---")
st.markdown("<div style='text-align:center;color:#484f58;font-size:0.78rem'>"
            "PhishTriage Pro v2.0 — Built by Praharsh Kumar | "
            "<a href='https://github.com/praharshkumar23' style='color:#388bfd'>GitHub</a></div>",
            unsafe_allow_html=True)
with st.sidebar:
    st.markdown("### ⚙️ Settings")
    offline_mode = st.toggle("Force Offline Mode (API unavailable)", value=False)
    st.markdown("### 🛡️ Allowlisted Domains")
    if OFFLINE_AVAILABLE:
        for d in get_allowlist()[:5]:
            st.caption(f"✅ {d}")
        st.caption("Edit `data/allowlist.json` to manage.")
    st.markdown("---")
