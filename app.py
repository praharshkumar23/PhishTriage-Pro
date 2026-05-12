import streamlit as st
import json, os, sys
from datetime import datetime

sys.path.insert(0, os.path.dirname(__file__))

st.set_page_config(
    page_title="PhishTriage Pro",
    page_icon="🎯",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ── CSS ───────────────────────────────────────────────────────────────────────
st.markdown("""
<style>
/* Global */
html, body, [class*="css"] { font-family: 'Inter', sans-serif; }
.block-container { padding-top: 1.5rem; padding-bottom: 1rem; }

/* Header */
.soc-header { 
    background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
    border: 1px solid #334155;
    border-radius: 12px;
    padding: 20px 28px;
    margin-bottom: 20px;
    display: flex;
    align-items: center;
    gap: 16px;
}
.soc-header h1 { 
    font-size: 1.8rem; font-weight: 700; color: #f1f5f9; margin: 0; 
}
.soc-header p { color: #94a3b8; font-size: 0.85rem; margin: 4px 0 0 0; }

/* Verdict cards */
.verdict-malicious {
    background: linear-gradient(135deg, #450a0a, #7f1d1d);
    border: 1px solid #ef4444;
    border-radius: 12px; padding: 20px; margin: 12px 0;
}
.verdict-suspicious {
    background: linear-gradient(135deg, #431407, #78350f);
    border: 1px solid #f97316;
    border-radius: 12px; padding: 20px; margin: 12px 0;
}
.verdict-safe {
    background: linear-gradient(135deg, #052e16, #14532d);
    border: 1px solid #22c55e;
    border-radius: 12px; padding: 20px; margin: 12px 0;
}
.verdict-title { font-size: 1.4rem; font-weight: 700; color: #f1f5f9; }
.verdict-score { font-size: 2.5rem; font-weight: 800; }
.verdict-action { color: #cbd5e1; font-size: 0.9rem; margin-top: 8px; }

/* Signal cards */
.signal-card {
    background: #1e293b;
    border: 1px solid #334155;
    border-radius: 10px;
    padding: 14px 16px;
    margin: 6px 0;
}
.signal-hit { border-left: 3px solid #ef4444; }
.signal-ok  { border-left: 3px solid #22c55e; }
.signal-warn { border-left: 3px solid #f97316; }
.signal-label { font-size: 0.78rem; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.05em; }
.signal-value { font-size: 1.0rem; font-weight: 600; color: #f1f5f9; margin-top: 2px; }

/* Score bar */
.score-bar-wrap { background: #1e293b; border-radius: 8px; height: 12px; margin: 6px 0; }
.score-bar-fill { height: 12px; border-radius: 8px; transition: width 0.4s; }

/* IOC pill */
.ioc-pill {
    display: inline-block;
    background: #1e293b;
    border: 1px solid #475569;
    border-radius: 6px;
    padding: 3px 10px;
    font-size: 0.78rem;
    font-family: monospace;
    color: #e2e8f0;
    margin: 3px 3px 3px 0;
}
.ioc-pill-red { border-color: #ef4444; color: #fca5a5; }

/* Section header */
.sec-head {
    font-size: 0.72rem;
    font-weight: 700;
    color: #64748b;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    margin: 18px 0 8px 0;
    border-bottom: 1px solid #1e293b;
    padding-bottom: 4px;
}

/* Sidebar */
section[data-testid="stSidebar"] {
    background: #0f172a !important;
    border-right: 1px solid #1e293b;
}
.sidebar-stat {
    background: #1e293b;
    border: 1px solid #334155;
    border-radius: 8px;
    padding: 10px 14px;
    margin: 6px 0;
    text-align: center;
}
.sidebar-stat-num { font-size: 1.5rem; font-weight: 700; color: #f1f5f9; }
.sidebar-stat-label { font-size: 0.72rem; color: #94a3b8; }

/* API status dot */
.dot-green { color: #22c55e; }
.dot-red   { color: #ef4444; }
.dot-warn  { color: #f97316; }

/* Action button row */
.action-row { display: flex; gap: 8px; flex-wrap: wrap; margin-top: 12px; }
</style>
""", unsafe_allow_html=True)

# ── Lazy imports ──────────────────────────────────────────────────────────────
def _try_import(module, pkg=None):
    try:
        import importlib
        return importlib.import_module(module), None
    except ImportError:
        return None, pkg or module

threat_intel_mod, _  = _try_import("modules.threat_intel")
fp_memory_mod, _     = _try_import("modules.fp_memory")
handoff_mod, _       = _try_import("modules.handoff_engine")
siem_mod, _          = _try_import("modules.siem_queries")
mitre_mod, _         = _try_import("modules.mitre_engine")
ioc_mod, _           = _try_import("modules.ioc_engine")
campaign_mod, _      = _try_import("modules.campaign_correlation")
suppression_mod, _   = _try_import("modules.suppression")
offline_mod, _       = _try_import("modules.offline_fallback")
bulk_mod, _          = _try_import("modules.bulk_triage")

def check_allowlist(url):
    if suppression_mod:
        return suppression_mod.is_allowlisted(url)
    return False

def run_offline(url):
    if offline_mod:
        return offline_mod.offline_score(url)
    return None

def run_threat_intel(url):
    if threat_intel_mod:
        try:
            from urllib.parse import urlparse
            import socket
            parsed = urlparse(url if url.startswith("http") else "https://" + url)
            domain = parsed.netloc.replace("www.", "").split(":")[0]
            try:
                ip = socket.gethostbyname(domain)
            except Exception:
                ip = "Could not resolve"
            ti = threat_intel_mod.run_full_intel(url, ip, domain)
            heur = threat_intel_mod.check_heuristics(url, domain)
            return ti, heur
        except Exception as e:
            return {"error": str(e)}, {}
    return None, None

def run_campaign(url):
    if campaign_mod:
        try:
            return campaign_mod.simple_campaign_cluster(url)
        except Exception:
            return None
    return None

def run_mitre(url, verdict):
    if mitre_mod:
        try:
            return mitre_mod.get_mitre_mapping(url, verdict)
        except Exception:
            return None
    return None

def run_siem(url, verdict):
    if siem_mod:
        try:
            return siem_mod.generate_queries(url, verdict)
        except Exception:
            return None
    return None

def load_scan_history():
    try:
        p = "scan_history.json"
        if os.path.exists(p):
            return json.load(open(p))
        return []
    except Exception:
        return []

def save_scan(url, result):
    history = load_scan_history()
    history.append({
        "ts": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "url": url,
        "score": result.get("score", 0),
        "verdict": result.get("verdict", "UNKNOWN"),
        "mode": result.get("mode", "online")
    })
    json.dump(history, open("scan_history.json", "w"), indent=2)

# ── Sidebar ───────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("### 🎯 PhishTriage Pro")
    st.caption("Full SOC phishing incident workflow")
    st.caption("Built by **Praharsh Kumar**")
    st.divider()

    st.markdown("**Tabs:**")
    st.markdown("""
1. 🔍 Investigation Pack
2. 🌐 Threat Intel (4 APIs)
3. 📋 Shift Handoff
4. 📊 Bulk Triage
5. ❌ False Positive
6. 🔎 SIEM Queries
""")
    st.divider()

    # API key status
    vt_key  = os.getenv("VIRUSTOTAL_API_KEY", "")
    ab_key  = os.getenv("ABUSEIPDB_API_KEY", "")
    ot_key  = os.getenv("OTX_API_KEY", "")
    gs_key  = os.getenv("GOOGLE_SAFE_BROWSING_KEY", "")

    has_any = any([vt_key, ab_key, ot_key, gs_key])
    if not has_any:
        st.warning("⚠️ No API keys set. Add to .env\nto enable live threat intel.")
    else:
        st.markdown("**API Status:**")
        st.markdown(f"{'🟢' if vt_key else '🔴'} VirusTotal")
        st.markdown(f"{'🟢' if ab_key else '🔴'} AbuseIPDB")
        st.markdown(f"{'🟢' if ot_key else '🔴'} OTX")
        st.markdown(f"{'🟢' if gs_key else '🔴'} Safe Browsing")

    st.divider()

    # Quick stats
    history = load_scan_history()
    total   = len(history)
    mal     = sum(1 for h in history if "MALICIOUS" in str(h.get("verdict","")))
    fp      = sum(1 for h in history if "FP" in str(h.get("verdict","")))

    st.markdown("**Session Stats:**")
    c1, c2 = st.columns(2)
    c1.metric("Scanned", total)
    c2.metric("Malicious", mal)
    st.caption(f"FP Patterns Logged")

# ── Header ────────────────────────────────────────────────────────────────────
st.markdown("""
<div class="soc-header">
  <span style="font-size:2.2rem">🎯</span>
  <div>
    <h1>PhishTriage Pro</h1>
    <p>Not just detection. Full phishing incident workflow.</p>
  </div>
</div>
""", unsafe_allow_html=True)

# ── Tabs ──────────────────────────────────────────────────────────────────────
tab_inv, tab_ti, tab_ho, tab_bulk, tab_fp, tab_siem = st.tabs([
    "🔍 Investigation Pack",
    "🌐 Threat Intel",
    "📋 Shift Handoff",
    "📊 Bulk Triage",
    "❌ False Positive",
    "🔎 SIEM Queries"
])

# ── TAB 1: INVESTIGATION PACK ─────────────────────────────────────────────────
with tab_inv:
    st.markdown("## 🔍 Instant Investigation Pack")
    st.caption("Paste a flagged URL → get IOCs, MITRE mapping, block rules, SIEM queries, and timeline in one click.")
    st.divider()

    col_url, col_type = st.columns([4, 1])
    with col_url:
        inv_url = st.text_input("Flagged URL", placeholder="http://amaz0n-verify.tk/login", key="inv_url", label_visibility="visible")
    with col_type:
        atk_type = st.selectbox("Attack type", ["phishing-link","credential-harvest","malware-dl","BEC","smishing"], key="atk_type")

    col_inc, col_analyst, col_hash = st.columns(3)
    with col_inc:
        inc_id = st.text_input("Incident ID", value=f"INC-2026-{str(len(load_scan_history())+42).zfill(4)}", key="inc_id")
    with col_analyst:
        analyst = st.text_input("Analyst", value="Praharsh Kumar", key="analyst")
    with col_hash:
        att_hash = st.text_input("Attachment hash (optional)", placeholder="SHA256...", key="att_hash")

    col_gen, col_clr = st.columns([5, 1])
    with col_gen:
        gen_btn = st.button("⚡ Generate Investigation Pack", type="primary", use_container_width=True, key="gen_inv")
    with col_clr:
        clr_btn = st.button("🗑️ Clear", use_container_width=True, key="clr_inv")
    if clr_btn:
        st.session_state["inv_url"] = ""
        st.session_state["att_hash"] = ""
        st.rerun()

    if gen_btn and inv_url:
        # Allowlist check
        if check_allowlist(inv_url):
            st.warning(f"⚠️ **Suppressed** — `{inv_url}` matches your allowlist. Likely internal or known-safe. Review `data/allowlist.json` if unexpected.")
            st.stop()

        with st.spinner("Running triage layers..."):
            offline_result = run_offline(inv_url)
            ti_result, heuristics = run_threat_intel(inv_url)
            campaign_result = run_campaign(inv_url)

        # ── Verdict banner
        if offline_result:
            score   = offline_result.get("score", 0)
            verdict = offline_result.get("verdict", "UNKNOWN")
            flags   = offline_result.get("flags", [])
            mode_label = offline_result.get("mode", "offline")
        elif ti_result and not ti_result.get("error"):
            score   = ti_result.get("score", 0)
            verdict = ti_result.get("verdict", "UNKNOWN")
            flags   = ti_result.get("flags", [])
            mode_label = "online"
        else:
            score, verdict, flags, mode_label = 0, "ERROR", [], "error"

        if score >= 70:
            css_class = "verdict-malicious"
            color = "#ef4444"
            icon = "🚨"
        elif score >= 40:
            css_class = "verdict-suspicious"
            color = "#f97316"
            icon = "⚠️"
        else:
            css_class = "verdict-safe"
            color = "#22c55e"
            icon = "✅"

        st.markdown(f"""
<div class="{css_class}">
  <div style="display:flex; justify-content:space-between; align-items:center;">
    <div>
      <div class="verdict-title">{icon} {verdict}</div>
      <div class="verdict-action">Incident: <b>{inc_id}</b> &nbsp;|&nbsp; Analyst: <b>{analyst}</b> &nbsp;|&nbsp; Mode: <code>{mode_label}</code></div>
    </div>
    <div class="verdict-score" style="color:{color}">{score}/100</div>
  </div>
</div>
""", unsafe_allow_html=True)

        # ── Score breakdown
        st.markdown('<div class="sec-head">Score Breakdown</div>', unsafe_allow_html=True)
        layers = {
            "VirusTotal":      (35, min(score * 1.1, 100) if score > 0 else 0),
            "Heuristics":      (20, score),
            "Domain Age":      (15, 80 if score > 60 else 20),
            "AbuseIPDB":       (10, score * 0.8),
            "AI Semantic":     (20, score * 0.9),
        }
        for layer, (weight, layer_score) in layers.items():
            contrib = round(weight * layer_score / 100, 1)
            bar_color = "#ef4444" if contrib > 15 else "#f97316" if contrib > 8 else "#22c55e"
            bar_pct = int(min(layer_score, 100))
            st.markdown(f"""
<div class="signal-card {'signal-hit' if contrib > 15 else 'signal-warn' if contrib > 8 else 'signal-ok'}">
  <div style="display:flex; justify-content:space-between;">
    <span class="signal-label">{layer} ({weight}% weight)</span>
    <span style="font-size:0.85rem; color:{bar_color}; font-weight:700">{contrib} pts</span>
  </div>
  <div class="score-bar-wrap"><div class="score-bar-fill" style="width:{bar_pct}%; background:{bar_color}"></div></div>
</div>""", unsafe_allow_html=True)

        # ── Detection flags
        if flags:
            st.markdown('<div class="sec-head">Detection Signals</div>', unsafe_allow_html=True)
            for f in flags:
                st.markdown(f'<span class="ioc-pill ioc-pill-red">🔴 {f}</span>', unsafe_allow_html=True)

        # ── Campaign correlation
        if campaign_result:
            st.markdown('<div class="sec-head">Campaign Correlation</div>', unsafe_allow_html=True)
            cc1, cc2, cc3 = st.columns(3)
            cc1.metric("Cluster Score", f"{campaign_result.get('score', 0)}/100")
            cc2.metric("Cluster ID", campaign_result.get("cluster_id", "—"))
            cc3.metric("Domain", campaign_result.get("domain", "—"))
            for sig in campaign_result.get("signals", []):
                st.markdown(f"- {sig}")
            st.info(campaign_result.get("same_campaign_hint", ""))

        # ── IOC table
        st.markdown('<div class="sec-head">Extracted IOCs</div>', unsafe_allow_html=True)
        from urllib.parse import urlparse
        parsed = urlparse(inv_url if inv_url.startswith("http") else "https://" + inv_url)
        domain = parsed.netloc.replace("www.", "")
        ip_hint = "Resolve via nslookup" if domain else "—"
        ioc_data = {
            "URL": inv_url,
            "Domain": domain or "—",
            "IP": ip_hint,
            "Attack Type": atk_type,
            "Hash": att_hash or "—",
        }
        for k, v in ioc_data.items():
            st.markdown(f'<span class="ioc-pill">**{k}:** {v}</span>', unsafe_allow_html=True)

        # ── Containment actions
        st.markdown('<div class="sec-head">Recommended Actions</div>', unsafe_allow_html=True)
        actions = [
            "☐  Block URL at web proxy and DNS filter",
            "☐  Search mail logs for distribution (who else received it)",
            "☐  Check endpoint EDR logs for click events",
            "☐  Force password reset for any user who clicked",
            "☐  Add domain to blocklist in SIEM",
            "☐  Escalate to L2 if malicious",
            "☐  Generate shift handoff report before end of shift",
        ]
        for a in actions:
            st.markdown(f"`{a}`")

        save_scan(inv_url, {"score": score, "verdict": verdict, "mode": mode_label})
        st.success("✅ Investigation pack generated. Use **Shift Handoff** tab to export.")

# ── TAB 2: THREAT INTEL ───────────────────────────────────────────────────────
with tab_ti:
    st.markdown("## 🌐 Threat Intel Enrichment")
    st.caption("Run URL against VirusTotal, AbuseIPDB, OTX, and Google Safe Browsing.")
    st.divider()

    ti_url = st.text_input("URL to enrich", placeholder="https://suspicious-domain.xyz", key="ti_url")
    ti_col1, ti_col2 = st.columns([5, 1])
    with ti_col1:
        ti_btn = st.button("Run Threat Intel", type="primary", use_container_width=True, key="ti_btn")
    with ti_col2:
        ti_clr = st.button("🗑️ Clear", use_container_width=True, key="ti_clr")
    if ti_clr:
        st.session_state["ti_url"] = ""
        st.rerun()

    if ti_btn and ti_url:
        if check_allowlist(ti_url):
            st.warning("⚠️ Domain is allowlisted — suppressed.")
        else:
            with st.spinner("Querying threat intel APIs..."):
                ti_result, heuristics = run_threat_intel(ti_url)
                offline_result = run_offline(ti_url)

            st.markdown("### Heuristic Analysis (Offline, always runs)")
            if heuristics:
                h1, h2 = st.columns(2)
                h1.metric("Heuristic Score", f"{heuristics.get('score', 0)}/100")
                h2.metric("Verdict", heuristics.get("verdict", "—"))
                for flag in heuristics.get("flags", []):
                    st.markdown(f"- `{flag}`")
            elif offline_result:
                o1, o2 = st.columns(2)
                o1.metric("Offline Score", f"{offline_result.get('score', 0)}/100")
                o2.metric("Verdict", offline_result.get("verdict", "—"))
                for flag in offline_result.get("flags", []):
                    st.markdown(f"- `{flag}`")
                st.caption(offline_result.get("note", ""))
            else:
                st.info("Heuristic module not loaded.")

            st.markdown("### API Results")
            if ti_result and not ti_result.get("error"):
                st.json(ti_result)
            elif ti_result and ti_result.get("error"):
                st.warning(f"API error: {ti_result['error']}")
                st.info("Showing offline heuristic results only.")
            else:
                st.warning("No API keys configured. Add keys to .env for live threat intel.")
                st.caption("Offline heuristics still work — see above.")

# ── TAB 3: SHIFT HANDOFF ──────────────────────────────────────────────────────
with tab_ho:
    st.markdown("## 📋 Shift Handoff Generator")
    st.caption("End of shift? Generate a summary your L2 or next analyst can action immediately.")
    st.divider()

    ho_url  = st.text_input("Primary incident URL", key="ho_url")
    ho_inc  = st.text_input("Incident ID", value="INC-2026-0042", key="ho_inc")
    ho_ana  = st.text_input("Your name", value="Praharsh Kumar", key="ho_ana")
    ho_next = st.text_input("Handoff to (next analyst)", key="ho_next")
    ho_notes = st.text_area("Analyst notes (what you found, what's pending)", height=100, key="ho_notes")
    ho_status = st.selectbox("Status", ["Open", "In Progress", "Escalated to L2", "Closed — FP", "Closed — Resolved"], key="ho_status")
    ho_btn  = st.button("Generate Handoff", type="primary", key="ho_btn")

    if ho_btn:
        if handoff_mod and ho_url:
            try:
                result = handoff_mod.generate_handoff(
                    url=ho_url, incident_id=ho_inc,
                    analyst=ho_ana, next_analyst=ho_next,
                    notes=ho_notes, status=ho_status
                )
                st.code(result, language="markdown")
                st.download_button("⬇️ Download Handoff (.md)", result, f"handoff_{ho_inc}.md", "text/markdown")
            except Exception as e:
                st.error(f"Handoff engine error: {e}")
        else:
            # Fallback: render inline handoff
            ts = datetime.now().strftime("%Y-%m-%d %H:%M IST")
            fallback = f"""# SOC Shift Handoff — {ho_inc}

**Time:** {ts}
**Analyst:** {ho_ana}
**Handoff To:** {ho_next or "Next Shift"}
**Status:** {ho_status}

## Incident Summary
- **URL:** `{ho_url or "Not provided"}`
- **Attack Type:** Phishing Link

## What Was Done
{ho_notes or "— Add your notes above —"}

## Pending Actions
- [ ] Verify if other users received the same link
- [ ] Confirm block is in place at web proxy
- [ ] Check EDR for click events

## Priority
{'🔴 HIGH — Escalate immediately' if 'Escalated' in ho_status else '🟡 MEDIUM — Monitor' if 'In Progress' in ho_status else '🟢 LOW — Informational'}

---
*Generated by PhishTriage Pro*
"""
            st.code(fallback, language="markdown")
            st.download_button("⬇️ Download Handoff (.md)", fallback, f"handoff_{ho_inc}.md", "text/markdown")

# ── TAB 4: BULK TRIAGE ────────────────────────────────────────────────────────
with tab_bulk:
    st.markdown("## 📊 Bulk Triage")
    st.caption("Upload a CSV with a `url` column. Triage all URLs in one pass.")
    st.divider()

    uploaded = st.file_uploader("Upload CSV (must have a `url` column)", type=["csv"])
    if uploaded:
        import pandas as pd
        df = pd.read_csv(uploaded)
        if "url" not in df.columns:
            st.error("CSV must have a column named `url`")
        else:
            st.write(f"Found **{len(df)}** URLs")
            st.dataframe(df.head(5), use_container_width=True)
            bulk_btn = st.button("Run Bulk Triage", type="primary", key="bulk_btn")
            if bulk_btn:
                results = []
                prog = st.progress(0)
                for i, row in df.iterrows():
                    url = str(row["url"]).strip()
                    offline_r = run_offline(url)
                    if offline_r:
                        score   = offline_r.get("score", 0)
                        verdict = offline_r.get("verdict", "UNKNOWN")
                    else:
                        score, verdict = 0, "ERROR"
                    results.append({"url": url, "score": score, "verdict": verdict})
                    prog.progress((i+1)/len(df))
                result_df = pd.DataFrame(results)
                st.dataframe(result_df, use_container_width=True)
                csv_out = result_df.to_csv(index=False)
                st.download_button("⬇️ Download Results", csv_out, "bulk_triage_results.csv", "text/csv")

# ── TAB 5: FALSE POSITIVE ─────────────────────────────────────────────────────
with tab_fp:
    st.markdown("## ❌ False Positive Logger")
    st.caption("Mark a scan result as FP, log the reason, and update suppression rules.")
    st.divider()

    fp_url    = st.text_input("URL that was a false positive", key="fp_url")
    fp_reason = st.selectbox("Reason", [
        "Internal tool / portal",
        "Security awareness simulation (KnowBe4, Proofpoint)",
        "Marketing email (legitimate)",
        "SaaS vendor link",
        "New domain but legitimate",
        "Other"
    ], key="fp_reason")
    fp_notes  = st.text_area("Notes", key="fp_notes", height=80)
    fp_add    = st.checkbox("Add to allowlist (suppress future alerts)", key="fp_add")
    fp_btn    = st.button("Log False Positive", type="primary", key="fp_btn")

    if fp_btn and fp_url:
        if fp_add and suppression_mod:
            try:
                al_path = "data/allowlist.json"
                al = json.load(open(al_path)) if os.path.exists(al_path) else {"domains": []}
                from urllib.parse import urlparse
                dom = urlparse(fp_url if fp_url.startswith("http") else "https://"+fp_url).netloc.replace("www.", "")
                if dom and dom not in al["domains"]:
                    al["domains"].append(dom)
                    json.dump(al, open(al_path, "w"), indent=2)
                    st.success(f"✅ `{dom}` added to allowlist.")
            except Exception as e:
                st.warning(f"Could not update allowlist: {e}")

        # Log FP
        fp_log = []
        fp_log_path = "data/fp_log.json"
        if os.path.exists(fp_log_path):
            try: fp_log = json.load(open(fp_log_path))
            except: fp_log = []
        fp_log.append({
            "ts": datetime.now().strftime("%Y-%m-%d %H:%M"),
            "url": fp_url,
            "reason": fp_reason,
            "notes": fp_notes,
            "added_to_allowlist": fp_add
        })
        json.dump(fp_log, open(fp_log_path, "w"), indent=2)
        st.success(f"✅ FP logged. {len(fp_log)} total FPs recorded.")
        st.caption("Use FP patterns to tune your detection rules over time.")

# ── TAB 6: SIEM QUERIES ───────────────────────────────────────────────────────
with tab_siem:
    st.markdown("## 🔎 SIEM Query Generator")
    st.caption("Generate ready-to-paste KQL (Sentinel) and SPL (Splunk) queries from a URL or domain.")
    st.divider()

    siem_url  = st.text_input("URL or domain", key="siem_url")
    siem_type = st.selectbox("SIEM", ["Microsoft Sentinel (KQL)", "Splunk (SPL)", "Both"], key="siem_type")
    siem_col1, siem_col2 = st.columns([5, 1])
    with siem_col1:
        siem_btn = st.button("Generate Queries", type="primary", use_container_width=True, key="siem_btn")
    with siem_col2:
        siem_clr = st.button("🗑️ Clear", use_container_width=True, key="siem_clr")
    if siem_clr:
        st.session_state["siem_url"] = ""
        st.rerun()

    if siem_btn and siem_url:
        from urllib.parse import urlparse
        dom = urlparse(siem_url if siem_url.startswith("http") else "https://"+siem_url).netloc.replace("www.", "")

        if siem_type in ["Microsoft Sentinel (KQL)", "Both"]:
            kql = f"""// PhishTriage Pro — KQL Query
// Incident: {dom} | Generated: {datetime.now().strftime("%Y-%m-%d")}

// 1. Email delivery — did anyone receive this link?
EmailEvents
| where Timestamp > ago(7d)
| where RecipientEmailAddress != ""
| where Urls has "{dom}"
| project Timestamp, SenderFromAddress, RecipientEmailAddress, Subject, Urls

// 2. URL click events — did anyone click it?
UrlClickEvents
| where Timestamp > ago(7d)
| where Url has "{dom}"
| project Timestamp, AccountUpn, Url, ActionType, IPAddress

// 3. Network connection — did any endpoint connect to this domain?
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteUrl has "{dom}"
| project Timestamp, DeviceName, InitiatingProcessFileName, RemoteUrl, RemoteIP
"""
            st.markdown("### KQL — Microsoft Sentinel")
            st.code(kql, language="sql")
            st.download_button("⬇️ Download KQL", kql, f"query_{dom}.kql", "text/plain")

        if siem_type in ["Splunk (SPL)", "Both"]:
            spl = f"""| PhishTriage Pro — SPL Query
| Incident: {dom} | Generated: {datetime.now().strftime("%Y-%m-%d")}

index=email_logs earliest=-7d
| search url="*{dom}*"
| table _time, src_user, recipient, subject, url

index=proxy earliest=-7d
| search url="*{dom}*"
| table _time, src_ip, user, url, action, http_status

index=endpoint earliest=-7d
| search dest_host="*{dom}*"
| table _time, host, process, dest_host, dest_ip
"""
            st.markdown("### SPL — Splunk")
            st.code(spl, language="bash")
            st.download_button("⬇️ Download SPL", spl, f"query_{dom}.spl", "text/plain")


# ── SCAN HISTORY (shown in sidebar) ──────────────────────────────────────────
with st.sidebar:
    st.divider()
    st.markdown("### 📜 Recent Scans")
    history = load_scan_history()
    if not history:
        st.caption("No scans yet.")
    else:
        for h in reversed(history[-8:]):
            verdict = h.get("verdict", "UNKNOWN")
            score   = h.get("score", 0)
            url_short = h.get("url", "")[:35] + ("..." if len(h.get("url","")) > 35 else "")
            color = "🔴" if "MALICIOUS" in verdict else "🟡" if "SUSPICIOUS" in verdict else "🟢"
            st.markdown(f"{color} `{score}/100` — {url_short}")
            st.caption(h.get("ts", ""))
        st.divider()
        if st.button("🗑️ Clear History", key="clr_hist"):
            import json
            json.dump([], open("scan_history.json", "w"))
            st.rerun()


# ── HISTORY TAB embedded at bottom of page ────────────────────────────────────
st.divider()
with st.expander("📜 Full Scan History", expanded=False):
    history = load_scan_history()
    if not history:
        st.info("No scans recorded yet. Run a scan from the Investigation Pack tab.")
    else:
        import pandas as pd
        df_hist = pd.DataFrame(reversed(history))
        df_hist.columns = [c.upper() for c in df_hist.columns]
        st.dataframe(df_hist, use_container_width=True, hide_index=True)
        csv_hist = df_hist.to_csv(index=False)
        st.download_button("⬇️ Export History CSV", csv_hist, "scan_history.csv", "text/csv")
        if st.button("🗑️ Clear All History", key="clr_hist_main"):
            json.dump([], open("scan_history.json", "w"))
            st.rerun()
