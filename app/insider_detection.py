import json
from pathlib import Path
from collections import defaultdict
from datetime import datetime, timedelta

LOG_FILE = Path("logs/audit.log")

THRESHOLD_ATTEMPTS = 3
TIME_WINDOW_MINUTES = 5

def detect_insider_threats():
    attempts = defaultdict(list)

    with LOG_FILE.open("r", encoding="utf-8") as f:
        for line in f:
            event = json.loads(line)

            if event.get("event") == "patient_read_attempt" and not event.get("allowed"):
                timestamp = datetime.fromisoformat(event["timestamp"].replace("Z", ""))
                key = (event["username"], event["role"])
                attempts[key].append(timestamp)

    for (username, role), times in attempts.items():
        times.sort()
        for i in range(len(times)):
            window = times[i:i + THRESHOLD_ATTEMPTS]
            if len(window) == THRESHOLD_ATTEMPTS:
                if window[-1] - window[0] <= timedelta(minutes=TIME_WINDOW_MINUTES):
                    print("⚠️ INSIDER THREAT DETECTED")
                    print(f"User: {username}")
                    print(f"Role: {role}")
                    print(f"Unauthorized access attempts: {THRESHOLD_ATTEMPTS}")
                    print(f"Time window: {TIME_WINDOW_MINUTES} minutes\n")
                    break

if __name__ == "__main__":
    detect_insider_threats()
