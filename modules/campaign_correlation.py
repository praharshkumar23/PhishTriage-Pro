import hashlib
from urllib.parse import urlparse
from collections import Counter

def normalize_domain(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    host = urlparse(url).netloc.lower().replace("www.", "")
    return host

def favicon_fingerprint(domain: str) -> str:
    """Offline placeholder. In production, fetch favicon and hash it."""
    return hashlib.sha256(domain.encode()).hexdigest()[:12]

def simple_campaign_cluster(url: str) -> dict:
    d = normalize_domain(url)
    parts = d.split('.')
    signals = []
    if len(parts) >= 4:
        signals.append("Deep subdomain chain")
    if any(tld in d for tld in [".tk", ".ml", ".xyz", ".click", ".pw"]):
        signals.append("Suspicious free TLD")
    if any(b in d for b in ["amazon", "microsoft", "google", "paypal", "apple", "bank"]):
        signals.append("Brand spoofing")
    if d.startswith(tuple(["login-", "secure-", "verify-", "account-", "update-", "signin-"])):
        signals.append("Phishing style prefix")
    fp = favicon_fingerprint(d)
    return {
        "domain": d,
        "signals": signals or ["No obvious campaign signal"],
        "score": min(len(signals) * 20, 100),
        "cluster_id": fp,
        "same_campaign_hint": "Likely related to similar phishing kit" if len(signals) >= 2 else "Needs more evidence"
    }