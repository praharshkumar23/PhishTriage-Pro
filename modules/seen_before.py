import json, os, re
from urllib.parse import urlparse
from datetime import datetime

HISTORY_FILE = "scan_history.json"

def _load():
    if os.path.exists(HISTORY_FILE):
        try: return json.load(open(HISTORY_FILE))
        except: return []
    return []

def _extract_domain(url):
    try:
        p = urlparse(url if url.startswith("http") else "https://" + url)
        return p.netloc.replace("www.", "").split(":")[0].lower()
    except: return ""

def _extract_tld(domain):
    parts = domain.split(".")
    return "." + parts[-1] if len(parts) >= 2 else ""

def _extract_keywords(url):
    words = re.findall(r"[a-z]{4,}", url.lower())
    phish_words = {"login","verify","secure","account","update","confirm",
                   "password","signin","suspend","unlock","alert","validate"}
    return [w for w in words if w in phish_words]

def seen_before(url: str) -> dict:
    """
    Check if this URL, domain, IP, or pattern was seen in previous scans.
    Returns match type, last seen date, previous verdict, confidence.
    """
    domain  = _extract_domain(url)
    tld     = _extract_tld(domain)
    keywords = _extract_keywords(url)
    history = _load()

    exact_matches   = []
    domain_matches  = []
    pattern_matches = []

    for h in history:
        h_url    = h.get("url", "")
        h_domain = _extract_domain(h_url)
        h_kw     = _extract_keywords(h_url)

        # Exact URL match
        if h_url == url:
            exact_matches.append(h)
            continue

        # Same domain
        if h_domain and h_domain == domain:
            domain_matches.append(h)
            continue

        # Pattern match: same TLD + overlapping phishing keywords (2+)
        h_tld = _extract_tld(h_domain)
        shared_kw = set(keywords) & set(h_kw)
        if h_tld == tld and len(shared_kw) >= 2:
            pattern_matches.append({**h, "shared_keywords": list(shared_kw)})

    total = len(exact_matches) + len(domain_matches) + len(pattern_matches)

    if not total:
        return {
            "seen": False,
            "message": "🟢 First time seeing this URL — no prior history.",
            "exact": [], "domain": [], "pattern": [],
            "confidence": "NEW"
        }

    # Build summary
    all_verdicts = [h.get("verdict","?") for h in exact_matches + domain_matches + pattern_matches]
    mal_count = sum(1 for v in all_verdicts if "MALICIOUS" in str(v))

    if exact_matches:
        last = exact_matches[-1]
        msg = f"🔴 EXACT MATCH — scanned before on {last.get('ts','')} → verdict was {last.get('verdict','?')}"
    elif domain_matches:
        last = domain_matches[-1]
        msg = f"🟠 SAME DOMAIN seen {len(domain_matches)}x — last on {last.get('ts','')} → {last.get('verdict','?')}"
    else:
        last = pattern_matches[-1]
        msg = f"🟡 SIMILAR PATTERN — {len(pattern_matches)} URLs matched same TLD + keywords: {last.get('shared_keywords',[])} — last on {last.get('ts','')}"

    return {
        "seen":           True,
        "message":        msg,
        "exact":          exact_matches[-3:],
        "domain":         domain_matches[-3:],
        "pattern":        pattern_matches[-3:],
        "total_matches":  total,
        "malicious_hits": mal_count,
        "confidence":     "HIGH" if exact_matches or (mal_count >= 2) else "MEDIUM" if domain_matches else "LOW"
    }
