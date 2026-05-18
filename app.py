import streamlit as st
import json, os, sys
from datetime import datetime
from urllib.parse import urlparse

sys.path.insert(0, os.path.dirname(__file__))

st.set_page_config(
    page_title="PhishTriage Pro",
    page_icon="🎯",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.markdown("""
<style>
html, body, [class*="css"] { font-family: 'Inter', sans-serif; }
.block-container { padding-top: 1.2rem; padding-bottom: 1rem; }
.soc-header {
    background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
    border: 1px solid #334155;
    border-radius: 12px;
    padding: 18px 24px;
    margin-bottom: 18px;
    display: flex;
    align-items: center;
    gap: 14px;
}
.soc-header h1 { font-size: 1.7rem; font-weight: 700; color: #f1f5f9; margin: 0; }
.soc-header p { color: #94a3b8; font-size: 0.85rem; margin: 4px 0 0 0; }
.verdict-malicious, .verdict-suspicious, .verdict-safe {
    border-radius: 12px; padding: 18px 20px; margin: 12px 0;
    border: 1px solid;
}
.verdict-malicious { background: linear-gradient(135deg, #450a0a, #7f1d1d); border-color: #ef4444; }
.verdict-suspicious { background: linear-gradient(135deg, #431407, #78350f); border-color: #f97316; }
.verdict-safe { background: linear-gradient(135deg, #052e16, #14532d); border-color: #22c55e; }
.verdict-title { font-size: 1.35rem; font-weight: 700; color: #f1f5f9; }
.verdict-score { font-size: 2.3rem; font-weight: 800; }
.verdict-action { color: #cbd5e1; font-size: 0.9rem; margin-top: 6px; }
.signal-card {
    background: #1e293b; border: 1px solid #334155; border-radius: 10px;
    padding: 14px 16px; margin: 6px 0;
}
.signal-hit { border-left: 3px solid #ef4444; }
.signal-ok { border-left: 3px solid #22c55e; }
.signal-warn { border-left: 3px solid #f97316; }
.signal-label { font-size: 0.78rem; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.05em; }
.signal-value { font-size: 1rem; font-weight: 600; color: #f1f5f9; margin-top: 2px; }
.score-bar-wrap { background: #0f172a; border-radius: 8px; height: 12px; margin: 6px 0; }
.score-bar-fill { height: 12px; border-radius: 8px; transition: width 0.4s; }
.ioc-pill {
    display: inline-block; background: #1e293b; border: 1px solid #475569;
    border-radius: 6px; padding: 3px 10px; font-size: 0.78rem; font-family: monospace;
    color: #e2e8f0; margin: 3px 3px 3px 0;
}
.ioc-pill-red { border-color: #ef4444; color: #fca5a5; }
.sec-head {
    font-size: 0.72rem; font-weight: 700; color: #64748b; text-transform: uppercase;
    letter-spacing: 0.1em; margin: 18px 0 8px 0; border-bottom: 1px solid #1e293b; padding-bottom: 4px;
}
section[data-testid="stSidebar"] { background: #0f172a !important; border-right: 1px solid #1e293b; }
</style>
""", unsafe_allow_html=True)

def _try_import(module, pkg=None):
    try:
        import importlib
        return importlib.import_module(module), None
    except Exception:
        return None, pkg or module

threat_intel_mod, _ = _try_import("modules.threat_intel")
handoff_mod, _ = _try_import("modules.handoff_engine")
siem_mod, _ = _try_import("modules.siem_queries")
campaign_mod, _ = _try_import("modules.campaign_correlation")
seen_before_mod, _ = _try_import("modules.seen_before")
escalation_mod, _ = _try_import("modules.escalation_pack")
campaign_det_mod, _ = _try_import("modules.campaign_detector")
suppression_mod, _ = _try_import("modules.suppression")
offline_mod, _ = _try_import("modules.offline_fallback")

DEFAULTS = {"inv_url": "", "ti_url": "", "siem_url": "", "ho_url": "", "fp_url": "", "att_hash": ""}
for k, v in DEFAULTS.items():
    if k not in st.session_state:
        st.session_state[k] = v

def check_allowlist(url):
    return suppression_mod.is_allowlisted(url) if suppression_mod else False

def run_offline(url):
    return offline_mod.offline_score(url) if offline_mod else None

def run_threat_intel(url):
    if not threat_intel_mod:
        return None, None
    try:
        import socket
        parsed = urlparse(url if url.startswith("http") else "https://" + url)
        domain = parsed.netloc.replace("www.", "").split(":")[0]
        try:
            ip = socket.gethostbyname(domain)
        except Exception:
            ip = "Could not resolve"
        return threat_intel_mod.run_full_intel(url, ip, domain), threat_intel_mod.check_heuristics(url, domain)
    except Exception as e:
        return {"error": str(e)}, {}

def run_seen_before(url):
    if not seen_before_mod:
        return None
    try:
        return seen_before_mod.seen_before(url)
    except Exception as e:
        return {"seen": False, "message": f"Check failed: {e}"}

def run_campaign_detect(url):
    if not campaign_det_mod:
        return None
    try:
        return campaign_det_mod.detect_campaign(url)
    except Exception as e:
        return {"campaign_detected": False, "message": f"Detection failed: {e}"}

def run_heatmap():
    if not campaign_det_mod:
        return None
    try:
        return campaign_det_mod.get_campaign_heatmap()
    except Exception:
        return None

def run_escalation_pack(scan_data, analyst, escalate_to, incident_id):
    if not escalation_mod:
        return None
    try:
        return escalation_mod.generate_escalation_pack(scan_data, analyst, escalate_to, incident_id)
    except Exception as e:
        return f"Escalation pack error: {e}"

def load_scan_history():
    try:
        p = "scan_history.json"
        return json.load(open(p)) if os.path.exists(p) else []
    except Exception:
        return []

def save_scan(url, result):
    history = load_scan_history()
    history.append({"ts": datetime.now().strftime("%Y-%m-%d %H:%M"), "url": url, "score": result.get("score", 0), "verdict": result.get("verdict", "UNKNOWN"), "mode": result.get("mode", "online")})
    json.dump(history, open("scan_history.json", "w"), indent=2)

with st.sidebar:
    st.markdown("### 🎯 PhishTriage Pro")
    st.caption("Simple phishing triage")
    st.caption("Built by **Praharsh Kumar**")
    st.divider()

    def _sidebar_key(name):
        try:
            v = st.secrets.get(name, "")
            if v: return v
        except Exception:
            pass
        return os.getenv(name, "")

    vt_key = _sidebar_key("VIRUSTOTAL_API_KEY")
    ab_key = _sidebar_key("ABUSEIPDB_API_KEY")
    ot_key = _sidebar_key("OTX_API_KEY")
    gs_key = _sidebar_key("GOOGLE_SAFE_BROWSING_KEY")
    us_key = _sidebar_key("URLSCAN_API_KEY")

    st.markdown("**API Status:**")
    st.markdown(f"{'🟢' if vt_key else '🔴'} VirusTotal")
    st.markdown(f"{'🟢' if ab_key else '🔴'} AbuseIPDB")
    st.markdown(f"{'🟢' if ot_key else '🔴'} OTX")
    st.markdown(f"{'🟢' if gs_key else '🔴'} Safe Browsing")
    st.markdown(f"{'🟢' if us_key else '🔴'} urlscan.io")

    st.divider()
    hist = load_scan_history()
    st.markdown("**Session Stats:**")
    c1, c2 = st.columns(2)
    c1.metric("Scanned", len(hist))
    c2.metric("Malicious", sum(1 for h in hist if "MALICIOUS" in str(h.get("verdict", ""))))

st.markdown("""
<div class="soc-header">
  <span style="font-size:2.1rem">🎯</span>
  <div>
    <h1>PhishTriage Pro</h1>
    <p>Simple phishing incident workflow.</p>
  </div>
</div>
""", unsafe_allow_html=True)

tab_inv, tab_ti, tab_ho, tab_bulk, tab_fp, tab_siem = st.tabs([
    "🔍 Investigation Pack", "🌐 Threat Intel", "📋 Shift Handoff", "📊 Bulk Triage", "❌ False Positive", "🔎 SIEM Queries"
])

with tab_inv:
    st.markdown("## 🔍 Investigation Pack")
    st.caption("Paste a URL and get a short triage summary.")
    st.divider()

    c1, c2, c3 = st.columns([3, 1, 1])
    with c1:
        inv_url = st.text_input("Flagged URL", placeholder="http://member15.example.com/login", key="inv_url")
    with c2:
        atk_type = st.selectbox("Attack type", ["phishing-link", "credential-harvest", "malware-dl", "BEC", "smishing"], key="atk_type")
    with c3:
        scan_mode = st.selectbox("Scan mode", ["Live", "Offline", "Both"], key="scan_mode")

    c4, c5 = st.columns(2)
    with c4:
        inc_id = st.text_input("Incident ID", value=f"INC-2026-{str(len(load_scan_history())+42).zfill(4)}", key="inc_id")
    with c5:
        analyst = st.text_input("Analyst", value="Praharsh Kumar", key="analyst")

    gen_btn = st.button("Run Investigation", type="primary", use_container_width=True, key="gen_inv")

    if gen_btn and inv_url:
        if check_allowlist(inv_url):
            st.warning(f"⚠️ `{inv_url}` is allowlisted.")
            st.stop()
        use_api = scan_mode in ["Live", "Both"]
        use_offline = scan_mode in ["Offline", "Both"]
        with st.spinner("Running checks..."):
            offline_result = run_offline(inv_url) if use_offline else None
            ti_result, heuristics = run_threat_intel(inv_url) if use_api else (None, None)
            seen_result = run_seen_before(inv_url)
            campaign_det = run_campaign_detect(inv_url)

        agg = (ti_result or {}).get("aggregate", {})
        vt = (ti_result or {}).get("virustotal", {}) if isinstance((ti_result or {}).get("virustotal", {}), dict) else {}
        vt_m = vt.get("malicious", 0) or agg.get("vt_malicious", 0)
        vt_t = vt.get("total", 0) or agg.get("vt_total", 0)

        if use_api and ti_result and not ti_result.get("error"):
            h_score = heuristics.get("score", 0) if heuristics else 0
            score = min(h_score + agg.get("high_signals", 0) * 15, 100)
            flags = heuristics.get("flags", []) if heuristics else []
            mode_label = f"ONLINE — {agg.get('high_signals', 0)} API hits"
        elif use_offline and offline_result:
            score = offline_result.get("score", 0)
            flags = offline_result.get("flags", [])
            mode_label = "OFFLINE"
        else:
            score, flags, mode_label = 0, [], "ERROR"

        if vt_t > 0:
            if vt_m >= 10: score = max(score, 85)
            elif vt_m >= 3: score = max(score, 72)
            elif vt_m >= 1: score = max(score, 42)

        verdict = "MALICIOUS" if score >= 70 else "SUSPICIOUS" if score >= 40 else "LOW RISK"
        css = "verdict-malicious" if score >= 70 else "verdict-suspicious" if score >= 40 else "verdict-safe"
        icon = "🚨" if score >= 70 else "⚠️" if score >= 40 else "✅"
        color = "#ef4444" if score >= 70 else "#f97316" if score >= 40 else "#22c55e"

        st.markdown(f"""
<div class="{css}">
  <div style="display:flex; justify-content:space-between; align-items:center;">
    <div>
      <div class="verdict-title">{icon} {verdict}</div>
      <div class="verdict-action">Incident: <b>{inc_id}</b> | Analyst: <b>{analyst}</b> | Mode: <code>{mode_label}</code></div>
    </div>
    <div class="verdict-score" style="color:{color}">{score}/100</div>
  </div>
</div>
""", unsafe_allow_html=True)

        a, b, c, d = st.columns(4)
        a.metric("VirusTotal", f"{vt_m}/{vt_t}")
        b.metric("API hits", agg.get("high_signals", 0))
        c.metric("Heuristic", f"{heuristics.get('score', 0) if heuristics else 0}/100")
        d.metric("Mode", mode_label)

        st.markdown("### Key findings")
        if flags:
            for f in flags[:5]:
                st.markdown(f"- {f}")
        else:
            st.markdown("- No heuristic flags detected")

        st.markdown("### Seen before")
        if seen_result and seen_result.get("seen"):
            st.warning(seen_result.get("message", "Previously seen"))
        else:
            st.success("First time seen")

        st.markdown("### Indicators")
        parsed = urlparse(inv_url if inv_url.startswith("http") else "https://" + inv_url)
        domain = parsed.netloc.replace("www.", "")
        for k, v in {"URL": inv_url, "Domain": domain or "—", "Attack type": atk_type, "Incident": inc_id, "Analyst": analyst}.items():
            st.write(f"**{k}:** {v}")

        save_scan(inv_url, {"score": score, "verdict": verdict, "mode": mode_label})

with tab_ti:
    st.markdown("## 🌐 Threat Intel")
    st.caption("Check URL with live threat intel sources.")
    st.divider()

    ti_url = st.text_input("URL to enrich", placeholder="https://suspicious-domain.xyz", key="ti_url")
    c1, c2 = st.columns([5, 1])
    with c1:
        ti_btn = st.button("Run Threat Intel", type="primary", use_container_width=True, key="ti_btn")
    with c2:
        ti_clr = st.button("🗑️ Clear", use_container_width=True, key="ti_clr")
    if ti_clr:
        st.session_state.pop("ti_url", None)
        st.rerun()

    if ti_btn and ti_url:
        if check_allowlist(ti_url):
            st.warning("⚠️ Domain is allowlisted — suppressed.")
        else:
            with st.spinner("Querying threat intel APIs..."):
                ti_result, heuristics = run_threat_intel(ti_url)
                offline_result = run_offline(ti_url)

            vt = (ti_result or {}).get("virustotal", {}) if isinstance((ti_result or {}).get("virustotal", {}), dict) else {}
            us = (ti_result or {}).get("urlscan", {}) if isinstance((ti_result or {}).get("urlscan", {}), dict) else {}
            ab = (ti_result or {}).get("abuseipdb", {}) if isinstance((ti_result or {}).get("abuseipdb", {}), dict) else {}
            ot = (ti_result or {}).get("otx", {}) if isinstance((ti_result or {}).get("otx", {}), dict) else {}
            agg = (ti_result or {}).get("aggregate", {})
            vt_m = vt.get("malicious", 0) or agg.get("vt_malicious", 0)
            vt_t = vt.get("total", 0) or agg.get("vt_total", 0)

            if vt_t > 0 and vt_m >= 1:
                st.error(f"VirusTotal: {vt_m}/{vt_t} vendors flagged this URL as malicious.")
            else:
                st.success("No strong VirusTotal hits found.")

            m1, m2, m3, m4 = st.columns(4)
            m1.metric("VirusTotal", f"{vt_m}/{vt_t}")
            m2.metric("urlscan.io", "Available" if us.get("available") else "Not available")
            m3.metric("AbuseIPDB", str(ab.get("abuse_confidence", "—")))
            m4.metric("OTX", str(ot.get("domain_pulses", 0) + ot.get("ip_pulses", 0)))

            st.markdown("### Heuristics")
            if heuristics and heuristics.get("flags"):
                for flag in heuristics.get("flags", [])[:6]:
                    st.markdown(f"- {flag}")
            else:
                st.markdown("- No heuristic flags detected")

            if offline_result:
                st.caption(f"Offline score: {offline_result.get('score', 0)}/100 | {offline_result.get('verdict', '—')}")

with tab_ho:
    st.markdown("## 📋 Shift Handoff Generator")
    st.caption("End of shift? Generate a short summary.")
    st.divider()

    ho_url = st.text_input("Primary incident URL", key="ho_url")
    ho_inc = st.text_input("Incident ID", value="INC-2026-0042", key="ho_inc")
    ho_ana = st.text_input("Your name", value="Praharsh Kumar", key="ho_ana")
    ho_next = st.text_input("Handoff to", key="ho_next")
    ho_notes = st.text_area("Analyst notes", height=100, key="ho_notes")
    ho_status = st.selectbox("Status", ["Open", "In Progress", "Escalated to L2", "Closed — FP", "Closed — Resolved"], key="ho_status")
    ho_btn = st.button("Generate Handoff", type="primary", key="ho_btn")

    if ho_btn:
        if handoff_mod and ho_url:
            try:
                result = handoff_mod.generate_handoff(url=ho_url, incident_id=ho_inc, analyst=ho_ana, next_analyst=ho_next, notes=ho_notes, status=ho_status)
                st.code(result, language="markdown")
                st.download_button("⬇️ Download Handoff (.md)", result, f"handoff_{ho_inc}.md", "text/markdown")
            except Exception as e:
                st.error(f"Handoff engine error: {e}")

with tab_bulk:
    st.markdown("## 📊 Bulk Triage")
    st.caption("Upload a CSV with a `url` column.")
    st.divider()
    uploaded = st.file_uploader("Upload CSV", type=["csv"])
    if uploaded:
        import pandas as pd
        df = pd.read_csv(uploaded)
        if "url" not in df.columns:
            st.error("CSV must have a `url` column")
        else:
            st.write(f"Found **{len(df)}** URLs")
            if st.button("Run Bulk Triage", type="primary", key="bulk_btn"):
                results = []
                prog = st.progress(0)
                urls_list = df["url"].dropna().tolist()
                for i, u in enumerate(urls_list):
                    r = run_offline(str(u).strip())
                    results.append({"url": u, "score": r.get("score", 0) if r else 0, "verdict": r.get("verdict", "ERROR") if r else "ERROR"})
                    prog.progress((i+1)/len(urls_list))
                out = pd.DataFrame(results)
                st.dataframe(out, use_container_width=True)
                st.download_button("⬇️ Download Results", out.to_csv(index=False), "bulk_triage_results.csv", "text/csv")

with tab_fp:
    st.markdown("## ❌ False Positive Logger")
    st.caption("Mark a scan as FP and allowlist it.")
    st.divider()
    fp_url = st.text_input("URL that was a false positive", key="fp_url")
    fp_reason = st.selectbox("Reason", ["Internal tool / portal", "Security awareness simulation", "Marketing email", "SaaS vendor link", "New domain but legitimate", "Other"], key="fp_reason")
    fp_notes = st.text_area("Notes", key="fp_notes", height=80)
    fp_add = st.checkbox("Add to allowlist", key="fp_add")
    fp_btn = st.button("Log False Positive", type="primary", key="fp_btn")
    if fp_btn and fp_url:
        if fp_add and suppression_mod:
            try:
                al_path = "data/allowlist.json"
                al = json.load(open(al_path)) if os.path.exists(al_path) else {"domains": []}
                dom = urlparse(fp_url if fp_url.startswith("http") else "https://" + fp_url).netloc.replace("www.", "")
                if dom and dom not in al["domains"]:
                    al["domains"].append(dom)
                    os.makedirs("data", exist_ok=True)
                    json.dump(al, open(al_path, "w"), indent=2)
                    st.success(f"✅ `{dom}` added to allowlist.")
            except Exception as e:
                st.warning(f"Could not update allowlist: {e}")

with tab_siem:
    st.markdown("## 🔎 SIEM Query Generator")
    st.caption("Generate KQL and SPL from a URL or domain.")
    st.divider()
    siem_url = st.text_input("URL or domain", key="siem_url")
    siem_type = st.selectbox("SIEM", ["Microsoft Sentinel (KQL)", "Splunk (SPL)", "Both"], key="siem_type")
    c1, c2 = st.columns([5, 1])
    with c1:
        siem_btn = st.button("Generate Queries", type="primary", use_container_width=True, key="siem_btn")
    with c2:
        siem_clr = st.button("🗑️ Clear", use_container_width=True, key="siem_clr")
    if siem_clr:
        st.session_state.pop("siem_url", None)
        st.rerun()
    if siem_btn and siem_url:
        dom = urlparse(siem_url if siem_url.startswith("http") else "https://" + siem_url).netloc.replace("www.", "")
        if siem_type in ["Microsoft Sentinel (KQL)", "Both"]:
            kql = f"""EmailEvents
| where Timestamp > ago(7d)
| where Urls has "{dom}"
| project Timestamp, SenderFromAddress, RecipientEmailAddress, Subject, Urls

UrlClickEvents
| where Timestamp > ago(7d)
| where Url has "{dom}"
| project Timestamp, AccountUpn, Url, ActionType, IPAddress

DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteUrl has "{dom}"
| project Timestamp, DeviceName, InitiatingProcessFileName, RemoteUrl, RemoteIP"""
            st.code(kql, language="sql")
            st.download_button("⬇️ Download KQL", kql, f"query_{dom}.kql", "text/plain")
        if siem_type in ["Splunk (SPL)", "Both"]:
            spl = f"""index=email_logs earliest=-7d
| search url="*{dom}*"
| table _time, src_user, recipient, subject, url

index=proxy earliest=-7d
| search url="*{dom}*"
| table _time, src_ip, user, url, action, http_status

index=endpoint earliest=-7d
| search dest_host="*{dom}*"
| table _time, host, process, dest_host, dest_ip"""
            st.code(spl, language="bash")
            st.download_button("⬇️ Download SPL", spl, f"query_{dom}.spl", "text/plain")

with st.sidebar:
    st.divider()
    st.markdown("### 📜 Recent Scans")
    hist = load_scan_history()
    if not hist:
        st.caption("No scans yet.")
    else:
        for h in reversed(hist[-8:]):
            verdict = h.get("verdict", "UNKNOWN")
            score = h.get("score", 0)
            short = h.get("url", "")[:35] + ("..." if len(h.get("url","")) > 35 else "")
            color = "🔴" if "MALICIOUS" in verdict else "🟡" if "SUSPICIOUS" in verdict else "🟢"
            st.markdown(f"{color} `{score}/100` — {short}")
            st.caption(h.get("ts", ""))
        if st.button("🗑️ Clear History", key="clr_hist"):
            json.dump([], open("scan_history.json", "w"))
            st.rerun()

st.divider()
with st.expander("📜 Full Scan History", expanded=False):
    hist = load_scan_history()
    if not hist:
        st.info("No scans recorded yet.")
    else:
        import pandas as pd
        df_hist = pd.DataFrame(list(reversed(hist)))
        df_hist.columns = [c.upper() for c in df_hist.columns]
        st.dataframe(df_hist, use_container_width=True, hide_index=True)
        st.download_button("⬇️ Export History CSV", df_hist.to_csv(index=False), "scan_history.csv", "text/csv")
