import tempfile
import unittest
from pathlib import Path
from modules.integrity import EvidenceIntegrity
from modules.scanned_evidence import (add_scanned_evidence, select_saved_scan,
    scan_record_id, invalidate_scan_session)
from modules.evidence_reports import build_saved_evidence_report, saved_evidence_findings


class SavedScanSelectionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.cases = self.root / 'cases'
        self.cases.mkdir()
        self.audit = self.cases / 'CASE-TEST_audit.log'

    def add(self, time, severity='Low'):
        return add_scanned_evidence(self.root / 'raw_evidence', 'sample.txt', b'evidence',
            [{'id': 'F-001', 'rule': 'Recorded check', 'severity': severity,
              'source': 'static', 'evidence': [{'file': 'sample.txt', 'line': 1}]}],
            case_id='CASE-TEST', scanned_at_utc=time, audit_log_path=self.audit,
            audit_logger=lambda c, a, d: EvidenceIntegrity.log_audit_trail(c, a, d, audit_path=self.audit))

    def select(self, record, **kwargs):
        return select_saved_scan(self.cases, record['sha256'],
            source_path=self.root / 'raw_evidence' / record['stored_filename'], **kwargs)

    def test_latest_and_history_keep_findings_and_report_consistent(self):
        old = self.add('2026-11-01T00:00:00Z')
        new = self.add('2026-11-02T00:00:00Z', 'High')
        self.assertEqual(self.select(old), new)
        selected = self.select(new, scan_id=scan_record_id(old))
        self.assertEqual(selected, old)
        report = build_saved_evidence_report(selected, 1, self.root / 'raw_evidence/sample.txt')
        self.assertEqual(report['scan_id'], scan_record_id(selected))
        self.assertEqual(report['findings'][0]['severity'], saved_evidence_findings(selected)[0]['severity'])

    def test_same_timestamp_different_findings_are_distinct_and_deterministic(self):
        one = self.add('2026-11-01T00:00:00Z')
        two = self.add('2026-11-01T00:00:00Z', 'High')
        self.assertNotEqual(scan_record_id(one), scan_record_id(two))
        self.assertEqual(self.select(one), max([one, two], key=scan_record_id))
        self.assertEqual(self.select(one, scan_id=scan_record_id(one)), one)

    def test_tampered_latest_chain_never_falls_back(self):
        old = self.add('2026-11-01T00:00:00Z')
        self.add('2026-11-02T00:00:00Z', 'High')
        self.audit.write_text(self.audit.read_text().replace('High', 'Critical'))
        with self.assertRaises(ValueError):
            self.select(old)

    def test_missing_timestamp_blocks_current_but_allows_explicit_verified_snapshot(self):
        old = self.add('')
        self.add('2026-11-02T00:00:00Z')
        with self.assertRaisesRegex(ValueError, 'timestamps'):
            self.select(old)
        self.assertEqual(self.select(old, scan_id=scan_record_id(old)), old)

    def test_legacy_identity_is_stable_without_rewriting(self):
        import json
        old = self.add('2026-11-01T00:00:00Z')
        old.pop('scan_id')
        old['scanned_at_utc'] = '2026-10-31T00:00:00Z'
        EvidenceIntegrity.log_audit_trail('CASE-TEST', 'SCANNED_EVIDENCE_ADDED',
            json.dumps(old), audit_path=self.audit)
        before = self.audit.read_bytes()
        self.assertEqual(self.select(old, scan_id=scan_record_id(old)), old)
        self.assertEqual(before, self.audit.read_bytes())

    def test_evidence_tampering_and_invalid_latest_findings_block_selection(self):
        import json
        old = self.add('2026-11-01T00:00:00Z')
        invalid = dict(old, scanned_at_utc='2026-11-03T00:00:00Z', findings=[{}], scan_id='invalid')
        EvidenceIntegrity.log_audit_trail('CASE-TEST', 'SCANNED_EVIDENCE_ADDED', json.dumps(invalid), audit_path=self.audit)
        with self.assertRaisesRegex(ValueError, 'findings'):
            self.select(old)
        (self.root / 'raw_evidence/sample.txt').write_bytes(b'tampered')
        with self.assertRaises(ValueError):
            self.select(old, scan_id=scan_record_id(old))

    def test_session_invalidates_on_version_change_only(self):
        old = self.add('2026-11-01T00:00:00Z')
        new = self.add('2026-11-02T00:00:00Z', 'High')
        state = {}
        invalidate_scan_session(state, old)
        state.update(ai_report='cached', investigation_selected_finding='F-001')
        invalidate_scan_session(state, old)
        self.assertIn('ai_report', state)
        invalidate_scan_session(state, new)
        self.assertNotIn('ai_report', state)
        self.assertNotIn('investigation_selected_finding', state)
