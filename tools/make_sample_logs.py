"""
Create a sample security log with a KNOWN attack hidden inside normal activity,
plus a truth file (which lines are attack lines) for evaluating the rules.

Run from the project root:
    python tools/make_sample_logs.py
Output:
    data/sample/sample_security_logs.csv
    data/sample/sample_security_logs_truth.csv
"""
import random
from datetime import datetime, timedelta
from pathlib import Path

import pandas as pd

OUT_DIR = Path("data/sample")
rng = random.Random(42)

USERS = {"alice": "10.0.0.11", "bob": "10.0.0.23", "carol": "10.0.0.31", "dave": "10.0.0.42"}
HOSTS = ["WS-01", "WS-02", "WS-03", "SRV-01"]
events = []   # (timestamp, host, user, ip, event_id, event_type, status, message, label, step)


def add(ts, host, user, ip, eid, etype, status, msg, label=0, step=""):
    events.append((ts, host, user, ip, eid, etype, status, msg, label, step))


# ---- normal activity: two working days ----
for day in (14, 15):
    base = datetime(2026, 10, day)
    for user, ip in USERS.items():
        host = rng.choice(HOSTS[:3])
        login = base + timedelta(hours=8, minutes=rng.randint(0, 45), seconds=rng.randint(0, 59))
        add(login, host, user, ip, 4624, "LOGON_SUCCESS", "success", f"User {user} logged on")
        for _ in range(rng.randint(2, 4)):
            t = base + timedelta(hours=rng.randint(9, 16), minutes=rng.randint(0, 59), seconds=rng.randint(0, 59))
            add(t, host, user, ip, 4663, "FILE_ACCESS", "success", f"{user} accessed a document")
        logoff = base + timedelta(hours=17, minutes=rng.randint(0, 40), seconds=rng.randint(0, 59))
        add(logoff, host, user, ip, 4634, "LOGOFF", "success", f"User {user} logged off")

# ---- harmless noise (should NOT be flagged as brute force) ----
for t in ("2026-10-14 09:12:10", "2026-10-14 09:12:41"):
    add(datetime.fromisoformat(t), "WS-02", "bob", USERS["bob"], 4625, "LOGON_FAILURE", "failure", "Wrong password (typo)")
add(datetime(2026, 10, 15, 13, 5, 3), "WS-01", "dave", USERS["dave"], 4625, "LOGON_FAILURE", "failure", "Wrong password (typo)")

# ---- legitimate but unusual: carol works at night (expected false positive) ----
add(datetime(2026, 10, 15, 3, 5, 20), "WS-03", "carol", USERS["carol"], 4624, "LOGON_SUCCESS", "success", "User carol logged on (night shift)")

# ---- the attack, 15 Oct from an external IP ----
ATT_IP, SRV = "203.0.113.45", "SRV-01"
t0 = datetime(2026, 10, 15, 2, 10, 5)
for i in range(12):
    add(t0 + timedelta(seconds=25 * i), SRV, "administrator", ATT_IP, 4625, "LOGON_FAILURE", "failure",
        "Failed logon attempt", 1, "brute_force")
add(datetime(2026, 10, 15, 2, 15, 40), SRV, "administrator", ATT_IP, 4624, "LOGON_SUCCESS", "success",
    "User administrator logged on", 1, "account_compromise")
add(datetime(2026, 10, 15, 2, 18, 12), SRV, "administrator", ATT_IP, 7045, "SERVICE_INSTALLED", "success",
    "Service 'WinUpdateSvc' installed (path C:\\Windows\\Temp\\upd.exe)", 1, "persistence_service")
add(datetime(2026, 10, 15, 2, 21, 30), SRV, "administrator", ATT_IP, 4720, "USER_CREATED", "success",
    "User account 'support_adm' created", 1, "persistence_account")
add(datetime(2026, 10, 15, 2, 22, 5), SRV, "administrator", ATT_IP, 4732, "GROUP_MEMBER_ADDED", "success",
    "User 'support_adm' added to group Administrators", 1, "privilege_escalation")
add(datetime(2026, 10, 15, 2, 41, 10), SRV, "administrator", ATT_IP, 1102, "LOG_CLEARED", "success",
    "The audit log was cleared", 1, "defense_evasion")

# ---- write files (sorted by time; line_no = record number + 1 because of header) ----
events.sort(key=lambda e: e[0])
log = pd.DataFrame(events, columns=["timestamp", "host", "user", "source_ip", "event_id",
                                    "event_type", "status", "message", "label", "step"])
log["timestamp"] = log["timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S") if hasattr(log["timestamp"], "dt") else log["timestamp"].map(lambda x: x.strftime("%Y-%m-%d %H:%M:%S"))
truth = pd.DataFrame({"line_no": log.index + 2, "label": log["label"], "attack_step": log["step"]})
OUT_DIR.mkdir(parents=True, exist_ok=True)
log.drop(columns=["label", "step"]).to_csv(OUT_DIR / "sample_security_logs.csv", index=False)
truth.to_csv(OUT_DIR / "sample_security_logs_truth.csv", index=False)
print("Rows:", len(log), "| attack rows:", int(log["label"].sum()))
print("Saved to", OUT_DIR)
