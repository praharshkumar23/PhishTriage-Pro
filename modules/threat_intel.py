"""
Threat Intel Engine — PhishTriage Pro
APIs: VirusTotal, AbuseIPDB, AlienVault OTX, Google Safe Browsing, urlscan.io
"""

import os, re, json, socket, time, requests
from urllib.parse import urlparse
from datetime import datetime

TIMEOUT = 8

def _key(name: str) -> str:
    try:
        import streamlit as st
        val = st.secrets.get(name, "")
        if val: return val
    except Exception:
        pass
    return os.getenv(name, "")


# ─────────────────────────────────────────────────────────────────────────────
# 1. VIRUSTOTAL  ← NEW (replaces missing VT check)
# ─────────────────────────────────────────────────────────────────────────────
def check_virustotal(url: str) -> dict:
    result = {
        "source": "VirusTotal", "available": False, "error": None,
        "malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0,
        "total": 0, "verdict": "Unknown", "scan_url": None,
    }
    key = _key("VIRUSTOTAL_API_KEY")
    if not key:
        result["error"] = "VIRUSTOTAL_API_KEY not set in Streamlit Secrets"
        return result
    try:
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        headers = {"x-apikey": key}
        r = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers, timeout=TIMEOUT
        )
        if r.status_code == 404:
            # URL not in VT cache — submit it
            r2 = requests.post(
                "https://www.virustotal.com/api/v3/urls",
                headers=headers, data={"url": url}, timeout=TIMEOUT
            )
            if r2.status_code not in (200, 201):
                result["error"] = f"VT submit failed: HTTP {r2.status_code}"
                return result
            # Wait briefly and retry once
            time.sleep(5)
            r = requests.get(
                f"https://www.virustotal.com/api/v3/urls/{url_id}",
                headers=headers, timeout=TIMEOUT
            )
        if r.status_code != 200:
            result["error"] = f"HTTP {r.status_code}"
            return result

        stats = (r.json()
                  .get("data", {})
                  .get("attributes", {})
                  .get("last_analysis_stats", {}))
        mal  = stats.get("malicious", 0)
        sus  = stats.get("suspicious", 0)
        har  = stats.get("harmless", 0)
        und  = stats.get("undetected", 0)
        tot  = mal + sus + har + und

        result["available"]  = True
        result["malicious"]  = mal
        result["suspicious"] = sus
        result["harmless"]   = har
        result["undetected"] = und
        result["total"]      = tot
        result["scan_url"]   = f"https://www.virustotal.com/gui/url/{url_id}"
        result["verdict"]    = (
            f"🔴 MALICIOUS — {mal}/{tot} vendors" if mal >= 3 else
            f"🟡 SUSPICIOUS — {mal}/{tot} vendors flagged" if mal >= 1 else
            f"🟢 Clean — 0/{tot} vendors flagged"
        )
    except Exception as e:
        result["error"] = str(e)
    return result


# ─────────────────────────────────────────────────────────────────────────────
# 2. URLSCAN.IO
# ─────────────────────────────────────────────────────────────────────────────
def check_urlscan(url: str) -> dict:
    result = {"source": "urlscan.io", "available": False, "error": None,
              "verdict": None, "malicious": None, "screenshot": None,
              "ips": [], "redirects": [], "dom_hash": None, "scan_id": None}
    key = _key("URLSCAN_API_KEY")
    if not key:
        result["error"] = "URLSCAN_API_KEY not set in Streamlit Secrets"
        return result
    try:
        headers = {"API-Key": key, "Content-Type": "application/json"}
        payload = {"url": url, "visibility": "private"}
        r = requests.post("https://urlscan.io/api/v1/scan/",
                          headers=headers, json=payload, timeout=TIMEOUT)
        if r.status_code not in (200, 201):
            result["error"] = f"Submit failed: HTTP {r.status_code}"
            return result
        scan_id = r.json().get("uuid", "")
        result["scan_id"] = scan_id
        time.sleep(10)
        r2 = requests.get(f"https://urlscan.io/api/v1/result/{scan_id}/",
                          headers=headers, timeout=TIMEOUT)
        if r2.status_code != 200:
            result["error"] = f"Result fetch failed: HTTP {r2.status_code}"
            return result
        data = r2.json()
        verdicts = data.get("verdicts", {}).get("overall", {})
        result["available"]  = True
        result["malicious"]  = verdicts.get("malicious", False)
        result["verdict"]    = verdicts.get("score", 0)
        result["screenshot"] = f"https://urlscan.io/screenshots/{scan_id}.png"
        page = data.get("page", {})
        result["ips"] = list({ip for ip in [page.get("ip")] if ip})
    except Exception as e:
        result["error"] = str(e)
    return result


# ─────────────────────────────────────────────────────────────────────────────
# 3. ABUSEIPDB
# ─────────────────────────────────────────────────────────────────────────────
def check_abuseipdb(ip: str) -> dict:
    result = {"source": "AbuseIPDB", "available": False, "error": None,
              "ip": ip, "abuse_confidence": None, "country": None,
              "isp": None, "total_reports": None, "last_reported": None,
              "is_tor": False, "usage_type": None}
    key = _key("ABUSEIPDB_API_KEY")
    if not key:
        result["error"] = "ABUSEIPDB_API_KEY not set in Streamlit Secrets"
        return result
    if ip in ("Could not resolve", "", "127.0.0.1"):
        result["error"] = "Invalid or unresolvable IP"
        return result
    try:
        headers = {"Key": key, "Accept": "application/json"}
        params  = {"ipAddress": ip, "maxAgeInDays": 90}
        r = requests.get("https://api.abuseipdb.com/api/v2/check",
                         headers=headers, params=params, timeout=TIMEOUT)
        if r.status_code != 200:
            result["error"] = f"HTTP {r.status_code}"
            return result
        d = r.json().get("data", {})
        result["available"]        = True
        result["abuse_confidence"] = d.get("abuseConfidenceScore", 0)
        result["country"]          = d.get("countryCode", "Unknown")
        result["isp"]              = d.get("isp", "Unknown")
        result["total_reports"]    = d.get("totalReports", 0)
        result["last_reported"]    = d.get("lastReportedAt", "Never")
        result["is_tor"]           = d.get("isTor", False)
        result["usage_type"]       = d.get("usageType", "Unknown")
    except Exception as e:
        result["error"] = str(e)
    return result


# ─────────────────────────────────────────────────────────────────────────────
# 4. ALIENVAULT OTX
# ─────────────────────────────────────────────────────────────────────────────
def check_otx(domain: str, ip: str = None) -> dict:
    result = {"source": "AlienVault OTX", "available": False, "error": None,
              "domain_pulses": 0, "ip_pulses": 0, "threat_actors": [],
              "malware_families": [], "tags": [], "verdict": "Unknown"}
    key = _key("OTX_API_KEY")
    if not key:
        result["error"] = "OTX_API_KEY not set in Streamlit Secrets"
        return result
    headers = {"X-OTX-API-KEY": key}
    try:
        r = requests.get(
            f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general",
            headers=headers, timeout=TIMEOUT)
        if r.status_code == 200:
            d = r.json()
            result["available"]     = True
            result["domain_pulses"] = d.get("pulse_info", {}).get("count", 0)
            pulses = d.get("pulse_info", {}).get("pulses", [])
            for p in pulses[:5]:
                result["tags"].extend(p.get("tags", []))
                result["malware_families"].extend(p.get("malware_families", []))
            result["tags"] = list(set(result["tags"]))[:8]
        if ip and ip not in ("Could not resolve", "", "127.0.0.1"):
            r2 = requests.get(
                f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
                headers=headers, timeout=TIMEOUT)
            if r2.status_code == 200:
                result["ip_pulses"] = r2.json().get("pulse_info", {}).get("count", 0)
        total = result["domain_pulses"] + result["ip_pulses"]
        result["verdict"] = ("🔴 Malicious" if total >= 3 else
                             "🟡 Suspicious" if total >= 1 else "🟢 No known threats")
    except Exception as e:
        result["error"] = str(e)
    return result


# ─────────────────────────────────────────────────────────────────────────────
# 5. GOOGLE SAFE BROWSING
# ─────────────────────────────────────────────────────────────────────────────
def check_google_safe_browsing(url: str) -> dict:
    result = {"source": "Google Safe Browsing", "available": False,
              "error": None, "threats": [], "verdict": "Not flagged"}
    key = _key("GOOGLE_SAFE_BROWSING_KEY")
    if not key:
        result["error"] = "GOOGLE_SAFE_BROWSING_KEY not set in Streamlit Secrets"
        return result
    try:
        payload = {
            "client": {"clientId": "phishtriage", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING",
                                "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }
        r = requests.post(
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={key}",
            json=payload, timeout=TIMEOUT)
        if r.status_code != 200:
            result["error"] = f"HTTP {r.status_code}"
            return result
        result["available"] = True
        matches = r.json().get("matches", [])
        result["threats"] = [m.get("threatType") for m in matches]
        result["verdict"] = ("🔴 " + ", ".join(result["threats"])
                              if result["threats"] else "🟢 Not flagged by Google")
    except Exception as e:
        result["error"] = str(e)
    return result


# ─────────────────────────────────────────────────────────────────────────────
# 6. OFFLINE HEURISTICS (always runs, no key needed)
# ─────────────────────────────────────────────────────────────────────────────
def check_heuristics(url: str, domain: str) -> dict:
    flags  = []
    score  = 0
    parsed = urlparse(url if url.startswith("http") else "https://" + url)
    parts  = domain.split(".")

    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain):
        flags.append("🔴 IP address used as hostname — evasion tactic")
        score += 30

    if url.startswith("http://") and any(w in url.lower()
       for w in ["login","verify","password","signin","account","secure","bank","pay"]):
        flags.append("🔴 HTTP (not HTTPS) on a sensitive-keyword page")
        score += 20

    if len(parts) >= 5:
        flags.append(f"🟡 Deep subdomain chain ({len(parts)} levels)")
        score += 15

    brands = ["paypal","amazon","microsoft","google","apple","netflix","bank","office365"]
    root   = ".".join(parts[-2:])
    for b in brands:
        if b in domain and b not in root:
            flags.append(f"🔴 Brand '{b}' in subdomain but not root domain — spoofing")
            score += 25
            break

    try:
        domain.encode("ascii")
    except UnicodeEncodeError:
        flags.append("🔴 Non-ASCII characters in domain — possible homoglyph attack")
        score += 30

    shorteners = ["bit.ly","t.co","tinyurl","ow.ly","rb.gy","is.gd"]
    for s in shorteners:
        if s in domain:
            flags.append(f"🟡 URL shortener: {s} — hiding final destination")
            score += 15
            break

    free_tlds = [".tk",".ml",".ga",".cf",".gq",".pw",".top",".xyz",".click",".live"]
    for tld in free_tlds:
        if domain.endswith(tld):
            flags.append(f"🔴 Free/cheap TLD: {tld} — extremely common in phishing")
            score += 20
            break

    typosquats = [r"amaz[o0]n", r"g[o0]{2}gle", r"paypa[l1]", r"micr[o0]s[o0]ft",
                  r"app[l1]e", r"netf[l1]ix", r"faceb[o0]{2}k"]
    for pat in typosquats:
        if re.search(pat, domain):
            flags.append(f"🔴 Typosquatting pattern detected: {domain}")
            score += 30
            break

    phish_kw = ["login","verify","secure","account","update","confirm","suspend","unlock"]
    found_kw = [w for w in phish_kw if w in url.lower()]
    if found_kw:
        flags.append(f"🟡 Phishing keywords: {', '.join(found_kw)}")
        score += len(found_kw) * 5

    if not flags:
        flags.append("🟢 No heuristic flags detected")

    score = min(score, 100)
    verdict = "🔴 MALICIOUS" if score >= 70 else "🟡 SUSPICIOUS" if score >= 40 else "🟢 LOW RISK"
    return {
        "source": "Local Heuristics (no API)",
        "available": True,
        "flags": flags,
        "score": score,
        "verdict": verdict,
    }


# ─────────────────────────────────────────────────────────────────────────────
# UNIFIED RUN
# ─────────────────────────────────────────────────────────────────────────────
def run_full_intel(url: str, ip: str, domain: str) -> dict:
    results = {
        "virustotal": check_virustotal(url),
        "urlscan":    check_urlscan(url),
        "abuseipdb":  check_abuseipdb(ip),
        "otx":        check_otx(domain, ip),
        "gsb":        check_google_safe_browsing(url),
        "heuristics": check_heuristics(url, domain),
    }

    vt   = results["virustotal"]
    vt_m = vt.get("malicious", 0) if vt.get("available") else 0
    vt_t = vt.get("total", 0) if vt.get("available") else 0

    high_signals = 0
    if vt_m >= 1:                                                        high_signals += 1
    if results["urlscan"].get("malicious"):                              high_signals += 1
    if (results["abuseipdb"].get("abuse_confidence") or 0) >= 50:       high_signals += 1
    if "Malicious" in str(results["otx"].get("verdict", "")):           high_signals += 1
    if results["gsb"].get("threats"):                                    high_signals += 1
    if (results["heuristics"].get("score") or 0) >= 50:                 high_signals += 1

    results["aggregate"] = {
        "high_signals":    high_signals,
        "total_checks":    6,
        "vt_malicious":    vt_m,
        "vt_total":        vt_t,
        "overall_verdict": (
            "🔴 MALICIOUS — Multiple sources confirm threat" if high_signals >= 3 else
            "🟡 SUSPICIOUS — Some signals, investigate further" if high_signals >= 1 else
            "🟢 LOW RISK — No strong signals"
        ),
        "confidence": f"{min(high_signals * 17, 100)}%",
    }
    return results
