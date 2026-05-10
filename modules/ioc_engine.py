import re, socket
from urllib.parse import urlparse
from datetime import datetime, timezone

def extract_domain(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return urlparse(url).netloc.replace("www.", "")

def resolve_ip(domain: str) -> str:
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return "Could not resolve"

def get_domain_age_flag(domain: str) -> str:
    """Flag newly registered / suspicious TLDs that attackers commonly abuse."""
    suspicious_tlds = [".tk", ".ml", ".ga", ".cf", ".gq", ".pw", ".top",
                       ".xyz", ".click", ".live", ".online", ".site", ".icu"]
    for tld in suspicious_tlds:
        if domain.endswith(tld):
            return f"⚠️ Suspicious free/cheap TLD: {tld}"
    digits = sum(c.isdigit() for c in domain.split(".")[0])
    if digits >= 3:
        return "⚠️ Many digits in domain — possible typosquatting"
    brand_words = ["amazon","paypal","microsoft","google","apple","netflix",
                   "dropbox","linkedin","bank","fedex","dhl","office365","outlook"]
    for b in brand_words:
        if b in domain and not domain.endswith(f"{b}.com"):
            return f"⚠️ Brand name '{b}' in non-official domain"
    return "✅ No obvious TLD/typosquatting flags"

def build_ioc_list(url: str, attachment_hash: str = None) -> list:
    domain = extract_domain(url)
    ip     = resolve_ip(domain)
    path   = urlparse(url if url.startswith("http") else "https://" + url).path or "/"
    iocs   = [
        {"type": "URL",    "value": url,    "confidence": "High",   "note": "Reported phishing URL"},
        {"type": "Domain", "value": domain, "confidence": "High",   "note": "Extracted from URL"},
        {"type": "IP",     "value": ip,     "confidence": "Medium", "note": "DNS resolved at scan time"},
        {"type": "Path",   "value": path,   "confidence": "Medium", "note": "URL path component"},
    ]
    if attachment_hash and attachment_hash.strip():
        iocs.append({"type": "Hash", "value": attachment_hash.strip(),
                     "confidence": "High", "note": "Attachment hash"})
    return iocs