import re

SUSPICIOUS_WORDS = ["urgent","verify","suspend","reset","password","login",
                    "unusual activity","click now","expires","action required",
                    "confirm","locked","limited time","security alert","account"]
BRAND_SPOOF  = ["amazon","paypal","microsoft","google","apple","netflix",
                "dropbox","linkedin","bank","fedex","dhl","irs","outlook"]
FREE_TLDS    = [".tk",".ml",".ga",".cf",".gq",".pw",".top",".xyz",".click",".live"]

def score_block(raw: str) -> dict:
    score, reasons = 0, []
    lower         = raw.lower()
    from_match    = re.search(r'from:\s*(.+)',    raw, re.I)
    reply_match   = re.search(r'reply-to:\s*(.+)',raw, re.I)
    subject_match = re.search(r'subject:\s*(.+)', raw, re.I)
    from_val    = from_match.group(1).strip()    if from_match    else ""
    reply_val   = reply_match.group(1).strip()   if reply_match   else ""
    subject_val = subject_match.group(1).strip() if subject_match else ""
    from_dom  = re.search(r'@([\w.-]+)', from_val)
    reply_dom = re.search(r'@([\w.-]+)', reply_val)
    if from_dom and reply_dom and from_dom.group(1) != reply_dom.group(1):
        score += 25; reasons.append(f"Reply-To mismatch: {from_dom.group(1)} vs {reply_dom.group(1)}")
    if "spf=fail"   in lower or "spf=softfail" in lower: score += 20; reasons.append("SPF failed")
    if "dkim=fail"  in lower:                             score += 15; reasons.append("DKIM failed")
    if "dmarc=fail" in lower:                             score += 15; reasons.append("DMARC failed")
    for b in BRAND_SPOOF:
        if b in lower and b not in (from_dom.group(1) if from_dom else ""):
            score += 12; reasons.append(f"Brand keyword: {b}"); break
    for w in SUSPICIOUS_WORDS:
        if w in subject_val.lower():
            score += 8; reasons.append(f"Urgency keyword: '{w}'"); break
    for tld in FREE_TLDS:
        if from_dom and tld in from_dom.group(1):
            score += 20; reasons.append(f"Suspicious TLD in sender: {tld}"); break
    urls = re.findall(r'https?://[^\s<>"\']+', raw, re.I)
    if urls: score += 10; reasons.append(f"{len(urls)} URL(s) detected")
    for tld in FREE_TLDS:
        if any(tld in u for u in urls):
            score += 15; reasons.append(f"Suspicious TLD in URL: {tld}"); break
    score    = min(score, 100)
    priority = "🔴 HIGH" if score >= 60 else "🟡 MEDIUM" if score >= 30 else "🟢 LOW"
    return {"from": from_val, "reply_to": reply_val, "subject": subject_val,
            "risk_score": score, "priority": priority, "urls": urls[:5], "reasons": reasons[:6]}

def triage_all(raw_text: str) -> list:
    blocks  = re.split(r'\n[-]{3,}\n|\n\n\n+', raw_text.strip())
    blocks  = [b.strip() for b in blocks if b.strip()]
    results = []
    for i, block in enumerate(blocks, 1):
        item = score_block(block); item["email_num"] = f"Email #{i}"; results.append(item)
    return sorted(results, key=lambda x: x["risk_score"], reverse=True)