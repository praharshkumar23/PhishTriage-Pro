from urllib.parse import urlparse

def extract_domain(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return urlparse(url).netloc.replace("www.", "")

def generate_all(url: str) -> dict:
    d = extract_domain(url)
    return {
        "splunk_proxy":   f'''index=proxy sourcetype=squid cs_uri_stem="*{d}*"\n| stats count by src_ip, user\n| sort -count''',
        "splunk_dns":     f'''index=dns sourcetype=bro_dns query="*{d}*"\n| stats count by src_ip, query\n| sort -count''',
        "splunk_email":   f'''index=email sourcetype=smtp_logs\n| search message="*{d}*"\n| stats count by sender, recipient\n| sort -count''',
        "kql_network":    f'''DeviceNetworkEvents\n| where RemoteUrl contains "{d}"\n| project Timestamp, DeviceName, InitiatingProcessAccountName, RemoteUrl, RemoteIP\n| order by Timestamp desc''',
        "kql_email":      f'''EmailEvents\n| where Urls contains "{d}"\n| project Timestamp, SenderFromAddress, RecipientEmailAddress, Subject, Urls\n| order by Timestamp desc''',
        "kql_endpoint":   f'''DeviceProcessEvents\n| where InitiatingProcessCommandLine contains "{d}" or ProcessCommandLine contains "{d}"\n| project Timestamp, DeviceName, AccountName, ProcessCommandLine\n| order by Timestamp desc''',
        "block_rule":     f"Proxy/SWG: BLOCK domain {d}\nDNS Sinkhole: Add {d} to deny list\nFirewall: DENY outbound to {d} on ports 80/443\nEmail Gateway: Block all messages containing *{d}*",
    }