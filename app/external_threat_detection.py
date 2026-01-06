import json
from pathlib import Path
from collections import defaultdict, deque
from datetime import datetime, timedelta

LOG_FILE = Path("logs/audit.log")

FAILED_THRESHOLD = 5
TIME_WINDOW_MINUTES = 3

def parse_ts(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", ""))

def detect_external_bruteforce():
    failures = defaultdict(lambda: deque(maxlen=50))

    with LOG_FILE.open("r", encoding="utf-8") as f:
        for line in f:
            event = json.loads(line)

            if event.get("event") != "login_attempt":
                continue

            if event.get("success") is True:
                continue

            if event.get("source") != "external":
                continue

            ts = parse_ts(event["timestamp"])
            username = event.get("username", "unknown")

            failures[username].append(ts)

            window_start = ts - timedelta(minutes=TIME_WINDOW_MINUTES)
            while failures[username] and failures[username][0] < window_start:
                failures[username].popleft()

            if len(failures[username]) >= FAILED_THRESHOLD:
                print("\n🚨 EXTERNAL THREAT DETECTED: Brute Force Login")
                print(f"Targeted username: {username}")
                print(f"Failed attempts: {len(failures[username])}")
                print(f"Time window: {TIME_WINDOW_MINUTES} minutes\n")
                failures[username].clear()

if __name__ == "__main__":
    detect_external_bruteforce()
