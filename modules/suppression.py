"""
suppression.py — Allowlist & suppression rules for PhishTriage Pro
Reads from data/allowlist.json if present, falls back to defaults.
"""
import json
from pathlib import Path

_DEFAULTS = [
    "company-internal.com",
    "my-hr-portal.com",
    "security-scanner.internal",
    "knowbe4.com",
    "proofpoint.com",
]

def _load_list() -> list:
    p = Path(__file__).parent.parent / "data" / "allowlist.json"
    if p.exists():
        try:
            return json.loads(p.read_text()).get("domains", _DEFAULTS)
        except Exception:
            pass
    return _DEFAULTS

def is_allowlisted(domain: str) -> bool:
    """Return True if the domain matches any allowlisted entry."""
    domain = domain.lower().replace("https://", "").replace("http://", "").split("/")[0]
    for entry in _load_list():
        if entry.lower() in domain:
            return True
    return False

def get_allowlist() -> list:
    return _load_list()