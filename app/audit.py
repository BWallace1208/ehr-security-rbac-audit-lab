import json
from datetime import datetime
from pathlib import Path

LOG_PATH = Path("logs/audit.log")
LOG_PATH.parent.mkdir(parents=True, exist_ok=True)

def write_audit(event: dict) -> None:
    event["timestamp"] = datetime.utcnow().isoformat() + "Z"
    with LOG_PATH.open("a", encoding="utf-8") as f:
        f.write(json.dumps(event) + "\n")
