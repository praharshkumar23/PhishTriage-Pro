"""
offline_fallback.py — Offline-only scoring when APIs are unavailable.
Uses only local heuristics + cached IOC file.
No API calls. Works even without internet.
"""
import json, re
from pathlib import Path
from urllib.parse import urlparse

CACHE_FILE = Path(__file__).parent.parent / "data" / "ioc_cache.json"

SUSPICIOUS_TLDS = {".tk", ".ml", ".ga", ".cf", ".gq", ".pw", ".top", ".xyz", ".click"}
PHISHING_KEYWORDS = [
    "login", "signin", "account", "verify", "secure", "update", "confirm",
    "banking", "paypal", "amazon", "apple", "microsoft", "password",
    "suspend", "locked", "unusual", "urgent", "alert", "validate",
]
TYPOSQUAT = [
    r"amaz[o0]n", r"g[o0]{2}gle", r"faceb[o0]{2}k", r"micr[o0]s[o0]ft",
    r"paypa[l1]", r"app[l1]e", r"netf[l1]ix",
]

def _load_cache() -> set:
    if CACHE_FILE.exists():
        try:
            data = json.loads(CACHE_FILE.read_text())
            return set(data.get("domains", []))
        except Exception:
            pass
    return set()

def offline_score(url: str) -> dict:
    """
    Returns a scoring result using only local data.
    Called automatically when APIs fail or timeout.
    """
    parsed = urlparse(url if url.startswith("http") else "https://" + url)
    domain = parsed.netloc.lower().replace("www.", "")
    score = 0
    flags = []

    # Check cached IOCs first
    cache = _load_cache()
    if domain in cache:
        score += 60
        flags.append("Domain found in local IOC cache")

    # IP address in URL
    if re.match(r"\d{1,3}(\.\d{1,3}){3}", domain):
        score += 30
        flags.append("IP address used instead of domain")

    # Suspicious TLD
    if any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS):
        score += 25
        flags.append(f"Suspicious TLD: {domain.split('.')[-1]}")

    # Typosquatting
    for pattern in TYPOSQUAT:
        if re.search(pattern, domain):
            score += 30
            flags.append(f"Typosquatting pattern: {pattern}")
            break

    # Phishing keywords
    kw_hits = [kw for kw in PHISHING_KEYWORDS if kw in url.lower()]
    if kw_hits:
        score += min(len(kw_hits) * 5, 20)
        flags.append(f"Keywords: {', '.join(kw_hits[:3])}")

    # HTTP instead of HTTPS
    if url.startswith("http://"):
        score += 10
        flags.append("Uses HTTP, not HTTPS")

    # Deep subdomains
    if domain.count(".") > 3:
        score += 20
        flags.append("Deep subdomain chain")

    score = min(score, 100)
    if score >= 70:
        verdict = "MALICIOUS"
    elif score >= 40:
        verdict = "SUSPICIOUS"
    else:
        verdict = "SAFE (offline only)"

    return {
        "mode": "OFFLINE — API unavailable, heuristics only",
        "score": score,
        "verdict": verdict,
        "flags": flags,
        "note": "Low score does not mean safe. Verify manually when APIs are back online."
    }