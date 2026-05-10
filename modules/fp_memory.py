import json
from pathlib import Path
from datetime import datetime

FP_DB = Path(__file__).resolve().parent.parent / "data" / "fp_patterns.json"

FP_REASONS = [
    "Known good domain / internal tool",
    "Internal security scanner (Qualys, Tenable, Nessus)",
    "Security awareness simulation (KnowBe4, Proofpoint, Cofense)",
    "Whitelisted sender or IP",
    "Expected business workflow (e-sign, payment, portal)",
    "Misclassified by detection engine",
    "Other — analyst note",
]

def _load() -> list:
    if FP_DB.exists(): return json.loads(FP_DB.read_text())
    return []

def _save(records):
    FP_DB.parent.mkdir(parents=True, exist_ok=True)
    FP_DB.write_text(json.dumps(records, indent=2))

def log_fp(incident_id, indicator, reason, analyst, notes="") -> dict:
    records  = _load()
    existing = [r for r in records if r["indicator"] == indicator]
    record   = {"incident_id": incident_id, "indicator": indicator,
                "reason": reason, "analyst": analyst, "notes": notes,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M"),
                "repeat_count": len(existing) + 1}
    records.append(record); _save(records); return record

def get_fp_history(indicator: str) -> list:
    return [r for r in _load() if r["indicator"] == indicator]

def get_all_fp() -> list:
    return _load()