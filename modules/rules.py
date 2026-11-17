"""
Rule-based (explainable) detection for login / system logs.

Every finding gets an ID (F-001, F-002, ...) and an evidence list that points
to the exact file and line number of the original log records, so a report
can always be traced back to the evidence.

Expected CSV columns (case-insensitive):
    required: timestamp, event_id, user, source_ip
    optional: host, message, event_type, status

Event IDs used (Windows Security / System log numbers):
    4625 failed logon        4624 successful logon
    4720 user account created        4732 member added to a security group
    7045 new service installed       1102 / 104 audit log cleared

CSV locations distinguish logical records from physical source line ranges.

Run from the project root:
    python -m modules.rules data/sample/sample_security_logs.csv
    python -m modules.rules data/sample/sample_security_logs.csv data/sample/sample_security_logs_truth.csv
"""
import sys
from pathlib import Path

import pandas as pd

from modules.event_timestamps import select_timestamp_column, chronological_findings
from modules.behavioral_detection import detect_batch
from modules.csv_evidence import read_evidence_csv, ensure_record_locations, source_locator, locator_label

REQUIRED_COLUMNS = ["timestamp", "event_id", "user", "source_ip"]
OPTIONAL_COLUMNS = ["host", "message"]


def load_log_csv(path):
    """Read CSV records with physical spans obtained from the original bytes."""
    df = read_evidence_csv(path)
    df.columns = [str(c).strip().lower() for c in df.columns]
    df["line_no"] = [source_locator(df, i).get("line") for i in df.index]
    df["line_end"] = [source_locator(df, i).get("line_end") for i in df.index]
    return df


class RuleEngine:
    def __init__(self, df, source_file="logs.csv", failed_threshold=5,
                 window_minutes=10, success_window_minutes=30,
                 odd_hour_start=0, odd_hour_end=5, timestamp_column=None):
        self.source_file = source_file
        self.failed_threshold = failed_threshold
        self.window = pd.Timedelta(minutes=window_minutes)
        self.success_window = pd.Timedelta(minutes=success_window_minutes)
        self.odd_start = odd_hour_start
        self.odd_end = odd_hour_end
        df = ensure_record_locations(df) if "line_no" not in df else df
        self._behavioral_input = df.copy()
        self._behavioral_input.columns = [str(c).strip().lower() for c in df.columns]
        self.timestamp_selection = select_timestamp_column(self._behavioral_input, timestamp_column)
        values = self.timestamp_selection['values']
        for name, items in (
            ('aegis_timestamp_original', [v.original for v in values]),
            ('aegis_timestamp_utc', [v.text for v in values]),
            ('aegis_timestamp_status', [v.status for v in values]),
        ):
            self._behavioral_input[name] = items if values else [None] * len(df)
        self._behavioral_input['aegis_timestamp_column'] = self.timestamp_selection['column']
        self.df = self._prepare(self._behavioral_input, self.timestamp_selection)
        self._bursts = []

    # ---------- helpers ----------
    @staticmethod
    def can_run(df, timestamp_column=None):
        normalized = df.copy(deep=False)
        normalized.columns = [str(c).strip().lower() for c in df.columns]
        missing = [c for c in REQUIRED_COLUMNS if c != 'timestamp' and c not in normalized.columns]
        selection = select_timestamp_column(normalized, timestamp_column)
        if not selection['candidates']:
            missing.append('event timestamp field')
        return not missing, missing

    @staticmethod
    def _prepare(df, selection):
        d = df.copy()
        for col in OPTIONAL_COLUMNS:
            if col not in d.columns:
                d[col] = ""
        values = selection["values"]
        d["timestamp"] = pd.array([v.utc for v in values] if values else [None] * len(d), dtype="datetime64[ns, UTC]")
        d["event_id"] = pd.to_numeric(d["event_id"], errors="coerce")
        for col in ["user", "source_ip", "host", "message"]:
            d[col] = d[col].fillna("").astype(str)
        return d

    def _finding(self, rule, severity, mitre, description, rows):
        rows = rows.sort_values("timestamp", kind="stable")
        users = sorted(set(rows["user"]) - {""})
        ips = sorted(set(rows["source_ip"]) - {""})
        hosts = sorted(set(rows["host"]) - {""})
        first, last = rows['timestamp'].min(), rows['timestamp'].max()
        first = None if pd.isna(first) else first
        last = None if pd.isna(last) else last
        return {
            "rule": rule,
            "severity": severity,
            "mitre": mitre,
            "description": description,
            "first_seen": first,
            "last_seen": last,
            "timestamp_status": "resolved" if first is not None else "unresolved",
            "users": ", ".join(users),
            "source_ips": ", ".join(ips),
            "hosts": ", ".join(hosts),
            "event_count": int(len(rows)),
            "timestamp_source_column": self.timestamp_selection['column'],
            "evidence": [{**source_locator(rows, index, filename=self.source_file),
                          "timestamp_original": row.get('aegis_timestamp_original'),
                          "timestamp_utc": row['timestamp'].isoformat() if pd.notna(row['timestamp']) else None,
                          "timestamp_status": row.get('aegis_timestamp_status')}
                         for index, row in rows.iterrows()],
        }

    # ---------- rules ----------
    def _behavioral_findings(self):
        records = []
        for row in self._behavioral_input.to_dict('records'):
            records.append({**row, **source_locator(self._behavioral_input,
                self._behavioral_input.index[len(records)], filename=self.source_file)})
        findings, self.behavioral_diagnostics = detect_batch(
            records, failed_threshold=self.failed_threshold,
            window_minutes=self.window.total_seconds() / 60,
            success_window_minutes=self.success_window.total_seconds() / 60,
            max_events=max(1, len(records)))
        return findings

    def _odd_hour_logins(self):
        out = []
        d = self.df[self.df["event_id"] == 4624].copy()
        hours = d["timestamp"].dt.hour
        d = d[(hours >= self.odd_start) & (hours < self.odd_end)]
        d["date"] = d["timestamp"].dt.date
        for (user, date), g in d.groupby(["user", "date"]):
            out.append(self._finding(
                "Login at unusual hour", "Medium", "T1078",
                f"'{user}' logged in {len(g)} time(s) between "
                f"{self.odd_start:02d}:00 and {self.odd_end:02d}:00 on {date}.", g))
        return out

    def _log_clearing(self):
        out = []
        d = self.df[self.df["event_id"].isin([1102, 104])]
        for _, row in d.iterrows():
            out.append(self._finding(
                "Audit log cleared", "High", "T1070.001",
                f"Event log was cleared by '{row['user']}' on "
                f"{row['host'] or 'unknown host'} (possible anti-forensics).",
                d.loc[[row.name]]))
        return out

    def _account_changes(self):
        out = []
        created = self.df[self.df["event_id"] == 4720]
        for _, row in created.iterrows():
            out.append(self._finding(
                "New user account created", "Medium", "T1136.001",
                f"A new account was created. Details: {row['message']}",
                created.loc[[row.name]]))
        grp = self.df[(self.df["event_id"] == 4732) &
                      (self.df["message"].str.contains("admin", case=False))]
        for _, row in grp.iterrows():
            out.append(self._finding(
                "Account added to administrators", "High", "T1098",
                f"Privilege escalation: {row['message']}",
                grp.loc[[row.name]]))
        return out

    def _service_install(self):
        out = []
        d = self.df[self.df["event_id"] == 7045]
        for _, row in d.iterrows():
            out.append(self._finding(
                "New service installed", "Medium", "T1543.003",
                f"A new service was installed. Details: {row['message']}",
                d.loc[[row.name]]))
        return out

    # ---------- public API ----------
    def run(self):
        self._bursts = []
        findings = []
        findings += self._behavioral_findings()
        findings += self._odd_hour_logins()
        findings += self._log_clearing()
        findings += self._account_changes()
        findings += self._service_install()
        if self.timestamp_selection.get('unresolved') or self.timestamp_selection['status'] != 'resolved':
            self.behavioral_diagnostics.append('Unresolved or ambiguous timestamps were excluded from chronological detection; no timezone was assumed.')
        timed = [f for _, f in chronological_findings(findings)]
        # Non-temporal indicators (account changes, log clearing, service installs)
        # remain reviewable even when their event time cannot establish chronology.
        unresolved = [f for f in findings if f.get('first_seen') is None]
        unresolved.sort(key=lambda f: (f['rule'], str(f['evidence'])))
        findings = timed + unresolved
        for i, f in enumerate(findings, start=1):
            f["id"] = f"F-{i:03d}"
        return findings

    @staticmethod
    def to_dataframe(findings):
        rows = []
        for f in findings:
            lines = ", ".join(locator_label(e) for e in f["evidence"])
            rows.append({
                "id": f["id"], "severity": f["severity"], "rule": f["rule"],
                "mitre": f["mitre"], "first_seen": str(pd.Timestamp(f["first_seen"])),
                "users": f["users"], "source_ips": f["source_ips"],
                "events": f["event_count"], "evidence_lines": lines,
                "description": f["description"],
            })
        return pd.DataFrame(rows)

    @staticmethod
    def summarize_for_llm(findings, max_items=20):
        """Plain-text findings list to give to the report generator."""
        lines = []
        for f in findings[:max_items]:
            ev = ", ".join(f"{e['file']}: {locator_label(e)}" for e in f["evidence"][:10])
            lines.append(f"{f['id']} [{f['severity']}] {f['rule']} "
                         f"(MITRE {f['mitre']}) at {f['first_seen']}: "
                         f"{f['description']} Evidence: {ev}")
        return "\n".join(lines) if lines else "No findings."


def _evaluate(findings, truth_csv):
    """Line-level check: how many known attack lines do the findings cover?"""
    truth = pd.read_csv(truth_csv)
    attack = set(truth.loc[truth["label"] == 1, "line_no"])
    flagged = {e["line"] for f in findings for e in f["evidence"] if "line" in e}
    tp = len(attack & flagged)
    fp = len(flagged - attack)
    fn = len(attack - flagged)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    print(f"\nLine-level evaluation: attack lines={len(attack)}, flagged lines={len(flagged)}")
    print(f"TP={tp} FP={fp} FN={fn}  precision={precision:.3f} recall={recall:.3f} f1={f1:.3f}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python -m modules.rules <log.csv> [truth.csv]")
        sys.exit(1)
    csv_path = sys.argv[1]
    frame = load_log_csv(csv_path)
    ok, missing = RuleEngine.can_run(frame)
    if not ok:
        print("Missing required columns:", missing)
        sys.exit(1)
    result = RuleEngine(frame, source_file=Path(csv_path).name).run()
    for item in result:
        lines = ", ".join(locator_label(e) for e in item["evidence"])
        print(f"{item['id']} [{item['severity']}] {item['rule']} | lines: {lines}")
        print("    ", item["description"])
    print(f"\nTotal findings: {len(result)}")
    if len(sys.argv) > 2:
        _evaluate(result, sys.argv[2])
