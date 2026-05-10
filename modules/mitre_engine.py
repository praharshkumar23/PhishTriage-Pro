MITRE_DB = {
    "phishing-link": {
        "technique_id": "T1566.002", "technique_name": "Phishing: Spearphishing Link",
        "tactic": "Initial Access", "sub_technique": "Spearphishing Link",
        "description": "Attacker sends a malicious link to gain initial access.",
        "follow_on_id": "T1078", "follow_on_name": "Valid Accounts",
        "follow_on_tactic": "Defense Evasion, Persistence, Privilege Escalation",
    },
    "phishing-attachment": {
        "technique_id": "T1566.001", "technique_name": "Phishing: Spearphishing Attachment",
        "tactic": "Initial Access", "sub_technique": "Spearphishing Attachment",
        "description": "Attacker embeds malware in an email attachment.",
        "follow_on_id": "T1204", "follow_on_name": "User Execution",
        "follow_on_tactic": "Execution",
    },
    "credential-harvest": {
        "technique_id": "T1056.003", "technique_name": "Input Capture: Web Portal Capture",
        "tactic": "Collection, Credential Access", "sub_technique": "Web Portal Capture",
        "description": "Adversary harvests credentials via a fake login page.",
        "follow_on_id": "T1078", "follow_on_name": "Valid Accounts",
        "follow_on_tactic": "Lateral Movement, Persistence",
    },
}

def get_mitre_mapping(attack_type: str = "phishing-link") -> dict:
    return MITRE_DB.get(attack_type, MITRE_DB["phishing-link"])

def get_mitre_chain(attack_type: str = "phishing-link") -> str:
    m = get_mitre_mapping(attack_type)
    return f"{m['technique_id']} ({m['tactic']}) → {m['follow_on_id']} ({m['follow_on_tactic']})"