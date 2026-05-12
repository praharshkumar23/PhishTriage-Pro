import json, os, re
from urllib.parse import urlparse
from collections import defaultdict

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
    return "." + parts[-1] if parts else ""

def _extract_brand_targets(url):
    brands = ["paypal","amazon","microsoft","google","apple","netflix",
              "bank","office","linkedin","dropbox","facebook","instagram"]
    found = [b for b in brands if b in url.lower()]
    return found

def _extract_path_pattern(url):
    try:
        path = urlparse(url).path.lower()
        segments = [s for s in path.split("/") if s]
        return segments[:2]
    except: return []

def detect_campaign(url: str) -> dict:
    """
    Detect if URL is part of a known phishing campaign by clustering
    against scan history using: TLD, brand targets, path patterns, keywords.
    """
    domain   = _extract_domain(url)
    tld      = _extract_tld(domain)
    brands   = _extract_brand_targets(url)
    path_pat = _extract_path_pattern(url)
    kw       = set(re.findall(r"[a-z]{4,}", url.lower()))
    history  = _load()

    clusters = defaultdict(list)

    for h in history:
        h_url    = h.get("url","")
        if h_url == url: continue
        h_domain = _extract_domain(h_url)
        h_tld    = _extract_tld(h_domain)
        h_brands = _extract_brand_targets(h_url)
        h_path   = _extract_path_pattern(h_url)
        h_kw     = set(re.findall(r"[a-z]{4,}", h_url.lower()))
        shared_kw = kw & h_kw

        score = 0
        reasons = []

        if h_tld == tld and tld in [".tk",".ml",".ga",".cf",".gq",".xyz",".top"]:
            score += 30
            reasons.append(f"Same suspicious TLD: {tld}")

        shared_brands = set(brands) & set(h_brands)
        if shared_brands:
            score += 35
            reasons.append(f"Same brand targets: {', '.join(shared_brands)}")

        if h_path and h_path == path_pat:
            score += 20
            reasons.append(f"Same URL path pattern: /{'/'.join(path_pat)}")

        if len(shared_kw - {"http","https","www","com"}) >= 3:
            score += 15
            reasons.append(f"Shared keywords: {', '.join(list(shared_kw)[:4])}")

        if score >= 30:
            clusters[score].append({
                "url": h_url,
                "verdict": h.get("verdict","?"),
                "ts": h.get("ts",""),
                "score": h.get("score",0),
                "match_score": score,
                "reasons": reasons
            })

    if not clusters:
        return {
            "campaign_detected": False,
            "message": "🟢 No campaign pattern detected — isolated incident.",
            "cluster_size": 0,
            "related_urls": [],
            "campaign_confidence": "NONE",
            "recommendation": "Treat as isolated. Monitor for recurrence."
        }

    # Flatten and sort by match score
    all_matches = []
    for matches in clusters.values():
        all_matches.extend(matches)
    all_matches.sort(key=lambda x: x["match_score"], reverse=True)

    mal_count = sum(1 for m in all_matches if "MALICIOUS" in str(m.get("verdict","")))
    top = all_matches[:5]
    confidence = "HIGH" if len(all_matches) >= 3 and mal_count >= 2 else                  "MEDIUM" if len(all_matches) >= 2 else "LOW"

    return {
        "campaign_detected": True,
        "message": f"🔴 CAMPAIGN DETECTED — {len(all_matches)} related URLs found in history",
        "cluster_size": len(all_matches),
        "related_urls": top,
        "malicious_in_cluster": mal_count,
        "campaign_confidence": confidence,
        "top_reasons": top[0]["reasons"] if top else [],
        "recommendation": (
            "Escalate to L3 — this is part of an active campaign. "
            "Search email gateway logs for all domains with similar pattern. "
            "Consider blocking the entire TLD-brand combination in your proxy."
            if confidence == "HIGH" else
            "Flag for L2 review — potential campaign. Gather more evidence."
        )
    }

def get_campaign_heatmap() -> dict:
    """
    Returns a full heatmap of all scan history grouped by TLD, brand, verdict.
    Used in the dashboard to show campaign trends over time.
    """
    history = _load()
    if not history:
        return {"tld_counts": {}, "brand_counts": {}, "verdict_counts": {}, "total": 0}

    tld_counts     = defaultdict(int)
    brand_counts   = defaultdict(int)
    verdict_counts = defaultdict(int)

    for h in history:
        url = h.get("url","")
        domain = _extract_domain(url)
        tld = _extract_tld(domain)
        if tld: tld_counts[tld] += 1
        for b in _extract_brand_targets(url):
            brand_counts[b] += 1
        v = h.get("verdict","UNKNOWN")
        verdict_counts[v] += 1

    return {
        "tld_counts":     dict(sorted(tld_counts.items(), key=lambda x: -x[1])[:10]),
        "brand_counts":   dict(sorted(brand_counts.items(), key=lambda x: -x[1])[:10]),
        "verdict_counts": dict(verdict_counts),
        "total":          len(history)
    }
