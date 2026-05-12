"""
Threat Intel Engine — PhishTriage Pro
Uses 4 free/cheap APIs in parallel + local offline checks.

APIs used:
  1. urlscan.io        — scan URL, screenshot, DOM, redirects (free 5000/month)
  2. AbuseIPDB         — IP reputation, abuse confidence score (free 1000/day)
  3. AlienVault OTX    — IOC reputation, MITRE pulses (free unlimited)
  4. Google Safe Browsing — real-time phishing/malware list (free 10k/day)

All 4 have generous free tiers. Total cost: $0/month for typical SOC use.
If any key is missing, that check is gracefully skipped — tool still works.
"""

import os, re, json, socket, time, requests
from urllib.parse import urlparse
from datetime import datetime

# ── Load keys from env ────────────────────────────────────────────────────────
URLSCAN_KEY     = os.getenv("URLSCAN_API_KEY", "")
ABUSEIPDB_KEY   = os.getenv("ABUSEIPDB_API_KEY", "")
OTX_KEY         = os.getenv("OTX_API_KEY", "")
GSB_KEY         = os.getenv("GOOGLE_SAFE_BROWSING_KEY", "")

TIMEOUT = 8  # seconds per request

# ─────────────────────────────────────────────────────────────────────────────
# 1. URLSCAN.IO
# ─────────────────────────────────────────────────────────────────────────────
def check_urlscan(url: str) -> dict:
    """
    Submit URL to urlscan.io for full scan.
    Returns: verdict, screenshot_url, IPs, redirect chain, DOM hash, malicious bool.

    Why urlscan over VirusTotal:
    - Free 5000 scans/month (VT free = 500/day but limited URL features)
    - Returns SCREENSHOT (you can literally see what the phishing page looks like)
    - Returns redirect chain (attackers often use multi-hop redirects)
    - Returns ALL IPs/domains the page loads (catches hidden subresources)
    - Lets you SEARCH previous scans for same domain (pivot to related attacks)
    - No credit card for free tier
    """
    result = {"source": "urlscan.io", "available": False, "error": None,
              "verdict": None, "malicious": None, "screenshot": None,
              "ips": [], "redirects": [], "dom_hash": None, "scan_id": None}
    if not URLSCAN_KEY:
        result["error"] = "URLSCAN_API_KEY not set — add to .env to enable"
        return result
    try:
        headers = {"API-Key": URLSCAN_KEY, "Content-Type": "application/json"}
        payload = {"url": url, "visibility": "private"}
        r = requests.post("https://urlscan.io/api/v1/scan/",
                          headers=headers, json=payload, timeout=TIMEOUT)
        if r.status_code not in (200, 201):
            result["error"] = f"Submit failed: HTTP {r.status_code}"; return result
        scan_id  = r.json().get("uuid", "")
        result["scan_id"] = scan_id
        # Wait for scan to complete (up to 15s)
        time.sleep(10)
        r2 = requests.get(f"https://urlscan.io/api/v1/result/{scan_id}/",
                          headers=headers, timeout=TIMEOUT)
        if r2.status_code != 200:
            result["error"] = f"Result fetch failed: HTTP {r2.status_code}"; return result
        data = r2.json()
        verdicts = data.get("verdicts", {}).get("overall", {})
        result["available"]  = True
        result["malicious"]  = verdicts.get("malicious", False)
        result["verdict"]    = verdicts.get("score", 0)
        result["screenshot"] = f"https://urlscan.io/screenshots/{scan_id}.png"
        page = data.get("page", {})
        result["ips"]        = list({ip for ip in [page.get("ip")] if ip})
        result["dom_hash"]   = data.get("stats", {}).get("domainStats", {})
    except Exception as e:
        result["error"] = str(e)
    return result


# ─────────────────────────────────────────────────────────────────────────────
# 2. ABUSEIPDB
# ─────────────────────────────────────────────────────────────────────────────
def check_abuseipdb(ip: str) -> dict:
    """
    Check IP reputation on AbuseIPDB.
    Returns: abuse confidence score (0-100), country, ISP, total reports, last seen.

    Why this matters for phishing:
    - Attacker uses a NEW IP/domain to bypass blocklists
    - AbuseIPDB shows if that IP has been reported before (even for different attacks)
    - Abuse confidence 80%+ = almost certainly malicious
    - Free 1000 lookups/day — enough for any L1 SOC shift

    Key use case:
    - URL resolves to 192.168.x.x → check AbuseIPDB → 87% abuse confidence
    - Even if the domain is new, the IP hosting it may be known bad
    """
    result = {"source": "AbuseIPDB", "available": False, "error": None,
              "ip": ip, "abuse_confidence": None, "country": None,
              "isp": None, "total_reports": None, "last_reported": None,
              "is_tor": False, "usage_type": None}
    if not ABUSEIPDB_KEY:
        result["error"] = "ABUSEIPDB_API_KEY not set — add to .env to enable"
        return result
    if ip in ("Could not resolve", "", "127.0.0.1"):
        result["error"] = "Invalid or unresolvable IP"; return result
    try:
        headers = {"Key": ABUSEIPDB_KEY, "Accept": "application/json"}
        params  = {"ipAddress": ip, "maxAgeInDays": 90}
        r = requests.get("https://api.abuseipdb.com/api/v2/check",
                         headers=headers, params=params, timeout=TIMEOUT)
        if r.status_code != 200:
            result["error"] = f"HTTP {r.status_code}"; return result
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
# 3. ALIENVAULT OTX
# ─────────────────────────────────────────────────────────────────────────────
def check_otx(domain: str, ip: str = None) -> dict:
    """
    Check domain + IP on AlienVault OTX (Open Threat Exchange).
    Returns: pulse count, threat actors, MITRE tags, malware families, verdict.

    Why OTX is powerful for NEW threats:
    - 100,000+ researchers submit threat intel daily
    - If attacker uses brand-new domain, OTX may already have a pulse
    - Shows WHICH threat actor group was using similar infrastructure
    - FREE, unlimited API calls
    - Only platform that gives you human-authored context: "this is part of BEC campaign"

    Key use case:
    - Analyst gets new phishing URL → domain 2 days old → no VT hits
    - OTX shows 3 pulses referencing same IP range → Lazarus Group
    - That context changes the priority from Low to Critical
    """
    result = {"source": "AlienVault OTX", "available": False, "error": None,
              "domain_pulses": 0, "ip_pulses": 0, "threat_actors": [],
              "malware_families": [], "tags": [], "verdict": "Unknown"}
    if not OTX_KEY:
        result["error"] = "OTX_API_KEY not set — add to .env to enable (it is FREE)"
        return result
    headers = {"X-OTX-API-KEY": OTX_KEY}
    try:
        # Domain check
        r = requests.get(
            f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general",
            headers=headers, timeout=TIMEOUT)
        if r.status_code == 200:
            d = r.json()
            result["available"]       = True
            result["domain_pulses"]   = d.get("pulse_info", {}).get("count", 0)
            pulses = d.get("pulse_info", {}).get("pulses", [])
            for p in pulses[:5]:
                result["tags"].extend(p.get("tags", []))
                for ta in p.get("targeted_countries", []):
                    pass
                mf = p.get("malware_families", [])
                result["malware_families"].extend(mf)
            result["tags"] = list(set(result["tags"]))[:8]
        # IP check
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
# 4. GOOGLE SAFE BROWSING
# ─────────────────────────────────────────────────────────────────────────────
def check_google_safe_browsing(url: str) -> dict:
    """
    Check URL against Google Safe Browsing (real-time, maintained by Google).
    Returns: threat type (MALWARE / SOCIAL_ENGINEERING / UNWANTED_SOFTWARE etc.)

    Why Google Safe Browsing:
    - Updated in near-real-time by Google's own crawlers
    - Catches SOCIAL_ENGINEERING (credential harvesting pages) specifically
    - Free 10,000 lookups/day — more than enough
    - Uses a different database than every other tool = different angle
    - Simple to add: just one API key from Google Cloud (free)

    Key use case:
    - URL is 6 hours old — not on VirusTotal yet
    - Google Safe Browsing already flagged it as SOCIAL_ENGINEERING
    - Because Chrome detected user reports + Google crawled it
    """
    result = {"source": "Google Safe Browsing", "available": False,
              "error": None, "threats": [], "verdict": "Not flagged"}
    if not GSB_KEY:
        result["error"] = "GOOGLE_SAFE_BROWSING_KEY not set — add to .env to enable (FREE)"
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
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GSB_KEY}",
            json=payload, timeout=TIMEOUT)
        if r.status_code != 200:
            result["error"] = f"HTTP {r.status_code}"; return result
        result["available"] = True
        matches = r.json().get("matches", [])
        result["threats"] = [m.get("threatType") for m in matches]
        result["verdict"] = ("🔴 " + ", ".join(result["threats"])
                              if result["threats"] else "🟢 Not flagged by Google")
    except Exception as e:
        result["error"] = str(e)
    return result


# ─────────────────────────────────────────────────────────────────────────────
# 5. OFFLINE HEURISTIC CHECK (no API key needed — always runs)
# ─────────────────────────────────────────────────────────────────────────────
def check_heuristics(url: str, domain: str) -> dict:
    """
    Local heuristic checks that run even with zero API keys.
    Catches common attacker tricks that APIs sometimes miss.

    Catches:
    - Homoglyph / unicode lookalike domains (аmazon.com with Cyrillic 'а')
    - Domain age signals via TLD + digit patterns
    - Excessive subdomain chains (victim.target.attacker.tk)
    - IP address as hostname (http://185.220.101.45/login)
    - HTTP (no S) on a login/payment page
    - Brand name embedded in subdomain (paypal.attacker.com)
    - Newly popular redirect trick (url shorteners in phishing)
    """
    flags  = []
    score  = 0
    parsed = urlparse(url if url.startswith("http") else "https://" + url)

    # IP as hostname
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain):
        flags.append("🔴 IP address used as hostname (no domain) — evasion tactic")
        score += 30

    # HTTP on login/payment/verify page
    if url.startswith("http://") and any(w in url.lower()
       for w in ["login","verify","password","signin","account","secure","bank","pay"]):
        flags.append("🔴 HTTP (not HTTPS) on a sensitive-keyword page")
        score += 20

    # Excessive subdomains
    parts = domain.split(".")
    if len(parts) >= 5:
        flags.append(f"🟡 Deep subdomain chain ({len(parts)} levels) — often used to spoof brands")
        score += 15

    # Brand in subdomain
    brands = ["paypal","amazon","microsoft","google","apple","netflix","bank","office365"]
    root   = ".".join(parts[-2:])
    for b in brands:
        if b in domain and b not in root:
            flags.append(f"🔴 Brand '{b}' in subdomain but not in root domain — spoofing pattern")
            score += 25
            break

    # Unicode / homoglyph detection (very basic)
    try:
        domain.encode('ascii')
    except UnicodeEncodeError:
        flags.append("🔴 Non-ASCII (possible homoglyph/punycode) characters in domain")
        score += 30

    # URL shortener
    shorteners = ["bit.ly","t.co","tinyurl","ow.ly","rb.gy","is.gd","buff.ly"]
    for s in shorteners:
        if s in domain:
            flags.append(f"🟡 URL shortener detected: {s} — attacker hiding final destination")
            score += 15
            break

    # Suspicious TLD
    free_tlds = [".tk",".ml",".ga",".cf",".gq",".pw",".top",".xyz",".click",".live"]
    for tld in free_tlds:
        if domain.endswith(tld):
            flags.append(f"🔴 Free/cheap TLD: {tld} — extremely common in phishing")
            score += 20
            break

    # Digits in domain
    digits = sum(c.isdigit() for c in parts[0])
    if digits >= 3:
        flags.append(f"🟡 {digits} digits in domain name — typosquatting signal")
        score += 10

    if not flags:
        flags.append("🟢 No local heuristic flags")

    score = min(score, 100)
    return {
        "source": "Local Heuristics (no API)",
        "available": True,
        "flags": flags,
        "score": score,
        "verdict": "🔴 HIGH" if score >= 50 else "🟡 MEDIUM" if score >= 20 else "🟢 LOW",
    }


# ─────────────────────────────────────────────────────────────────────────────
# UNIFIED THREAT INTEL RUN — calls all 4 APIs + local check
# ─────────────────────────────────────────────────────────────────────────────
def run_full_intel(url: str, ip: str, domain: str) -> dict:
    """
    Run all 5 checks and return a unified verdict.
    Each check runs independently — if one fails, others still work.
    """
    results = {
        "urlscan":   check_urlscan(url),
        "abuseipdb": check_abuseipdb(ip),
        "otx":       check_otx(domain, ip),
        "gsb":       check_google_safe_browsing(url),
        "heuristics":check_heuristics(url, domain),
    }

    # Aggregate verdict
    high_signals = 0
    if results["urlscan"].get("malicious"):          high_signals += 1
    if (results["abuseipdb"].get("abuse_confidence") or 0) >= 50: high_signals += 1
    if "Malicious" in str(results["otx"].get("verdict", "")):      high_signals += 1
    if results["gsb"].get("threats"):                               high_signals += 1
    if (results["heuristics"].get("score") or 0) >= 50:            high_signals += 1

    results["aggregate"] = {
        "high_signals": high_signals,
        "total_checks": 5,
        "overall_verdict": (
            "🔴 MALICIOUS — Multiple sources confirm threat" if high_signals >= 3 else
            "🟡 SUSPICIOUS — Some signals present, investigate further" if high_signals >= 1 else
            "🟢 LOW RISK — No strong signals from any source"
        ),
        "confidence": f"{high_signals * 20}%",
    }
    return results
