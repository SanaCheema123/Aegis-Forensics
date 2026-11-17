"""Behavioral correlation regression tests use synthetic records only."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

import pandas as pd

from modules.behavioral_detection import BehavioralDetector, detect_batch
from modules.evidence_reports import merge_investigation_findings
from modules.realtime_monitor import RealtimeMonitor
from modules.rules import RuleEngine
from test_event_polling import EventSource


BASE = datetime.now(timezone.utc).replace(microsecond=0) - timedelta(minutes=5)


def event(number, seconds=None, account='alice', ip='192.0.2.1', host='server', event_id=4625):
    return dict(Log='Security', RecordId=number, EventId=event_id,
                Time=(BASE + timedelta(seconds=number if seconds is None else seconds)).isoformat(),
                Computer=host, Provider='Synthetic test', Fingerprint=f'{number:064x}',
                EventData={'TargetUserName': account, 'IpAddress': ip})


def failures(**kw):
    return [event(n, **kw) for n in range(1, 6)]


class BehavioralTests(unittest.TestCase):
    def test_bounded_window_not_consecutive_gap(self):
        self.assertEqual(len(detect_batch(failures())[0]), 1)
        rows = [event(n, seconds=n * 540) for n in range(1, 6)]
        self.assertEqual(detect_batch(rows)[0], [])
        rows = [event(n, seconds=n * 150) for n in range(1, 6)]
        self.assertEqual(len(detect_batch(rows)[0]), 1)  # inclusive 600 seconds
        rows[-1] = event(5, seconds=751)
        self.assertEqual(detect_batch(rows)[0], [])

    def test_success_same_account_ip_host_and_time(self):
        for changed in [dict(account='bob'), dict(ip='192.0.2.2'), dict(host='other'),
                        dict(seconds=2000), dict(account=''), dict(ip=''), dict(host='')]:
            result, _ = detect_batch(failures() + [event(6, event_id=4624, **changed)])
            self.assertEqual(len(result), 1, changed)
        result, _ = detect_batch(failures() + [event(6, event_id=4624)])
        self.assertEqual([f['severity'] for f in result], ['High', 'Critical'])
        self.assertEqual(result[1]['event_count'], 6)
        self.assertEqual(result[1]['evidence'][-1]['RecordId'], 6)
        self.assertEqual(result[1]['evidence'][-1]['EventId'], 4624)

    def test_password_spray_preserved_without_unrelated_success(self):
        rows = [event(n, account=f'user{n}') for n in range(1, 6)]
        result, _ = detect_batch(rows + [event(6, account='unrelated', event_id=4624)])
        self.assertEqual([f['rule'] for f in result], ['Brute force login attempts'])
        result, _ = detect_batch(rows + [event(6, account='user1', event_id=4624)])
        self.assertEqual(len(result), 2)

    def test_missing_context_and_invalid_timestamp(self):
        result, notes = detect_batch(failures(ip=''))
        self.assertEqual(result, [])
        self.assertIn('source IP missing', str(notes))
        result, notes = detect_batch(failures(account='', host='') + [event(6, account='', host='', event_id=4624)])
        self.assertEqual(len(result), 1)
        self.assertFalse(result[0]['detection_metadata']['context_complete'])
        self.assertIn('account missing', str(notes))
        broken = event(9)
        broken['Time'] = 'invalid'
        self.assertIn('timestamp', str(detect_batch([broken])[1]))

    def test_no_subject_account_fallback(self):
        rows = failures()
        for row in rows:
            row['EventData'] = {'SubjectUserName': 'service', 'IpAddress': '192.0.2.1'}
        result, notes = detect_batch(rows + [event(6, account='service', event_id=4624)])
        self.assertEqual(len(result), 1)
        self.assertIn('account missing', str(notes))

    def test_batch_incremental_duplicates_late_arrivals_restart(self):
        rows = failures() + [event(6, event_id=4624)]
        expected, _ = detect_batch(rows + deepcopy(rows))
        for order in [rows, list(reversed(rows)), rows[:2] + rows[3:] + rows[2:3]]:
            detector = BehavioralDetector()
            actual = []
            for row in order:
                actual.extend(detector.feed([row, deepcopy(row)]))
                detector = BehavioralDetector(state=json.loads(json.dumps(detector.export_state())))
            self.assertEqual({f['detection_id'] for f in actual}, {f['detection_id'] for f in expected})
            self.assertEqual(len(actual), len(expected))
            self.assertEqual(detector.feed(rows), [])

    def test_long_batch_keeps_early_findings(self):
        rows = failures() + [event(10 + n, seconds=4000 + n) for n in range(5)]
        self.assertEqual(len(detect_batch(rows)[0]), 2)
        detector = BehavioralDetector()
        self.assertEqual(len(detector.feed(rows[:5])), 1)
        self.assertEqual(len(detector.feed(rows[5:])), 1)

    def test_expiration_capacity_and_late_data(self):
        detector = BehavioralDetector(max_events=6)
        detector.feed(failures())
        detector.feed([], now=BASE + timedelta(hours=2))
        self.assertEqual(detector.export_state()['events'], [])
        self.assertEqual(detector.feed(failures()), [])
        self.assertIn('horizon', str(detector.diagnostics))
        detector = BehavioralDetector(max_events=6)
        detector.feed([event(n) for n in range(20)])
        self.assertLessEqual(len(detector.export_state()['events']), 6)
        self.assertLessEqual(len(detector.export_state()['emitted']), 12)
        self.assertIn('capacity', str(detector.diagnostics))

    def test_sustained_burst_survives_retention_without_repeat_alerts(self):
        detector = BehavioralDetector()
        output = []
        for n in range(100):
            output.extend(detector.feed([event(n, seconds=n * 60)]))
        self.assertEqual(len(output), 1)
        self.assertLessEqual(len(detector.export_state()['events']), 41)
        self.assertEqual(detector.feed([event(n, seconds=n * 60) for n in range(100)]), [])
        output = detector.feed([event(200 + n, seconds=10000 + n) for n in range(5)])
        self.assertEqual(len(output), 1)

    def test_account_domain_and_mapped_ip_normalization(self):
        rows = failures(ip='::ffff:192.0.2.1')
        for row in rows:
            row['EventData']['TargetDomainName'] = 'EXAMPLE'
        success = event(6, account='example\\ALICE', event_id=4624)
        self.assertEqual(len(detect_batch(rows + [success])[0]), 2)
        success['EventData']['TargetUserName'] = 'OTHER\\alice'
        self.assertEqual(len(detect_batch(rows + [success])[0]), 1)

    def test_rule_engine_report_metadata_and_idempotence(self):
        rows = [dict(timestamp=row['Time'], event_id=row['EventId'],
                     user='alice', source_ip='192.0.2.1', host='server', record_id=row['RecordId'],
                     line_no=row['RecordId'] + 1)
                for row in failures() + [event(6, event_id=4624)]]
        engine = RuleEngine(pd.DataFrame(rows), source_file='evidence.csv')
        findings = engine.run()
        self.assertEqual(findings, engine.run())
        behavior = [f for f in findings if f.get('detection_id')]
        self.assertEqual(len(behavior), 2)
        self.assertEqual(behavior[-1]['evidence'][-1]['file'], 'evidence.csv')
        self.assertEqual(behavior[-1]['evidence'][-1]['line'], 7)
        self.assertEqual(behavior[-1]['evidence'][-1]['record_id'], 6)
        duplicate = {**behavior[0], 'source': 'Behavioral detection', 'id': 'MON-1'}
        self.assertEqual(len(merge_investigation_findings([duplicate], behavior)), 2)
        legacy = {**behavior[0], 'source': 'rule', 'evidence': [
            dict(file=e['file'], line=e['line']) for e in behavior[0]['evidence']]}
        legacy.pop('detection_id')
        self.assertEqual(len(merge_investigation_findings([legacy], behavior)), 2)

    def test_monitor_restart_and_crash_before_checkpoint_replay(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / 'alerts.jsonl'
            cursor = root / 'cursor.json'
            source = EventSource(failures()[:3])
            def monitor():
                return RealtimeMonitor([root], Mock(), alert_log_path=path,
                                       cursor_path=cursor, event_logs=('Security',))
            with patch('modules.realtime_monitor.read_security_event_page', side_effect=source.page):
                monitor()._process_event_page('Security', time.monotonic() + 20)
                source.records = failures() + [event(6, event_id=4624)]
                instance = monitor()
                with patch.object(instance._event_store, 'save', side_effect=OSError('simulated crash')):
                    with self.assertRaises(OSError):
                        instance._process_event_page('Security', time.monotonic() + 20)
                monitor()._process_event_page('Security', time.monotonic() + 20)
            alerts = [json.loads(line) for line in path.read_text().splitlines()]
            behavioral = [a for a in alerts if a['source'] == 'Behavioral detection']
            self.assertEqual(len(behavioral), 2)
            self.assertEqual(len({a['event_uid'] for a in alerts}), len(alerts))
            self.assertEqual(json.loads(cursor.read_text())['logs']['Security']['record_id'], 6)


if __name__ == '__main__':
    unittest.main()
