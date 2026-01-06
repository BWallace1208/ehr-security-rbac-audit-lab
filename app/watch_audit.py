import json
import time
from pathlib import Path
from collections import defaultdict, deque
from datetime import datetime, timedelta

LOG_FILE = Path("logs/audit.log")

# --- Detection knobs (tune these any time) ---
INSIDER_THRESHOLD = 3
INSIDER_WINDOW_MIN = 5

BRUTE_THRESHOLD = 5
BRUTE_WINDOW_MIN = 3


def parse_ts(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", ""))


def print_alert(title: str, details: dict):
    print(f"\n🚨 {title}")
    for k, v in details.items():
        print(f"{k}: {v}")
    print()


# Rolling windows
denied_reads = defaultdict(lambda: deque(maxlen=100))         # key: (username, role)
failed_logins_by_ip = defaultdict(lambda: deque(maxlen=300))  # key: client_ip


def handle_patient_read_attempt(event: dict):
    """Insider-ish: repeated unauthorized PHI reads."""
    if event.get("event") != "patient_read_attempt":
        return
    if event.get("allowed") is True:
        return

    username = event.get("username", "unknown")
    role = event.get("role", "unknown")
    client_ip = event.get("client_ip", "unknown")
    ts = parse_ts(event["timestamp"])

    key = (username, role)
    denied_reads[key].append(ts)

    window_start = ts - timedelta(minutes=INSIDER_WINDOW_MIN)
    while denied_reads[key] and denied_reads[key][0] < window_start:
        denied_reads[key].popleft()

    if len(denied_reads[key]) >= INSIDER_THRESHOLD:
        print_alert(
            "INSIDER THREAT: Repeated Unauthorized Patient Record Access",
            {
                "User": username,
                "Role": role,
                "Client IP": client_ip,
                "Denied attempts": len(denied_reads[key]),
                "Window (minutes)": INSIDER_WINDOW_MIN,
            },
        )
        denied_reads[key].clear()


def handle_login_attempt(event: dict):
    """External: brute-force repeated failed logins from the same IP."""
    if event.get("event") != "login_attempt":
        return
    if event.get("success") is True:
        return

    client_ip = event.get("client_ip", "unknown")
    username = event.get("username", "unknown")
    ts = parse_ts(event["timestamp"])

    failed_logins_by_ip[client_ip].append(ts)

    window_start = ts - timedelta(minutes=BRUTE_WINDOW_MIN)
    while failed_logins_by_ip[client_ip] and failed_logins_by_ip[client_ip][0] < window_start:
        failed_logins_by_ip[client_ip].popleft()

    if len(failed_logins_by_ip[client_ip]) >= BRUTE_THRESHOLD:
        print_alert(
            "EXTERNAL THREAT: Possible Brute-Force Login Attempts (IP-based)",
            {
                "Source IP": client_ip,
                "Failed attempts": len(failed_logins_by_ip[client_ip]),
                "Window (minutes)": BRUTE_WINDOW_MIN,
                "Example username targeted": username,
            },
        )
        failed_logins_by_ip[client_ip].clear()


def watch():
    print("Watching:", LOG_FILE.resolve())
    print("Real-time detections enabled:")
    print(f"- Insider: {INSIDER_THRESHOLD} denied reads in {INSIDER_WINDOW_MIN} min")
    print(f"- Brute force: {BRUTE_THRESHOLD} failed logins in {BRUTE_WINDOW_MIN} min")
    print("\nWaiting for new audit events... (Ctrl+C to stop)\n")

    while not LOG_FILE.exists():
        time.sleep(0.2)

    with LOG_FILE.open("r", encoding="utf-8") as f:
        f.seek(0, 2)  # tail: new events only

        while True:
            line = f.readline()
            if not line:
                time.sleep(0.15)
                continue

            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue

            handle_patient_read_attempt(event)
            handle_login_attempt(event)


if __name__ == "__main__":
    watch()
