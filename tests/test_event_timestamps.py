"""Conservative source timestamp selection, exact UTC chronology and consumers."""
import ast
from copy import deepcopy
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import pandas as pd
from pypdf import PdfReader

from modules.event_timestamps import (parse_timestamp, select_timestamp_column,
    resolve_event_timestamp, chronological_findings)
from modules.timeline import TimelineConstructor
from modules.rules import RuleEngine, load_log_csv
from modules.parser import LogParser
from modules.csv_evidence import file_sha256
from modules.windows_security import (normalize_security_event, _event_timestamp_values,
    read_latest_windows_security_events, read_security_events)
from modules.behavioral_detection import detect_batch, BehavioralDetector
from modules.ai_reporter import LocalLLMReporter, validate_report
from modules.report_validation import bind_report_context, render_forensic_text, validate_report_export
from modules.pdf_report import render_forensic_pdf
from modules.integrity import EvidenceIntegrity

ROOT = Path(__file__).resolve().parents[1]


class EventTimestampTests(unittest.TestCase):
    def test_numeric_identifiers_are_never_chronological_evidence(self):
        frame = pd.DataFrame({'Event ID': [4624, 4625], 'Record ID': [1700000000, 1700000010],
                              'ProcessId': [1234, 5678], 'row_number': [1, 2]})
        for field in (None, 'Event ID', 'Record ID', 'ProcessId', 'row_number'):
            timeline = TimelineConstructor(frame)
            self.assertTrue(timeline.build_timeline(field).empty)
            self.assertEqual(len(timeline.unresolved_events), 2)
        for value in (4624, 1700000000, 1700000000.0, '1700000000', '20261116', True):
            self.assertIsNone(parse_timestamp(value).utc)
        frame['Timestamp'] = [1700000000, 1700000010]
        self.assertEqual(select_timestamp_column(frame)['status'], 'unresolved')
        self.assertTrue(TimelineConstructor(frame).build_timeline().empty)

    def test_later_recognized_timestamp_columns_beat_first_numeric_column(self):
        for alias in ('TimeCreated', 'EventTime', 'Timestamp', 'DateTime', 'event_time',
                      'TimeUtc', 'Time', 'TimeGenerated', 'created_at_utc'):
            with self.subTest(alias=alias):
                frame = pd.DataFrame({'EventId': [4624, 4625], 'ProcessId': [9, 8],
                    alias: ['2026-11-16T10:00:00Z', '2026-11-16T09:00:00Z']})
                builder = TimelineConstructor(frame)
                result = builder.build_timeline()
                self.assertEqual(builder.selection['column'], alias)
                self.assertEqual(result['EventId'].tolist(), [4625, 4624])
                self.assertEqual(result[alias].tolist(), frame[alias].iloc[[1, 0]].tolist())
                self.assertEqual(str(result['aegis_timestamp_utc'].dtype), 'datetime64[ns, UTC]')

    def test_no_substring_or_first_column_guess_and_explicit_custom_column(self):
        frame = pd.DataFrame({'runtime': [10, 20], 'candidate': ['2026-11-16T10:00:00Z', '2026-11-16T09:00:00Z']})
        self.assertEqual(select_timestamp_column(frame)['status'], 'no_timestamp_field')
        self.assertTrue(TimelineConstructor(frame).build_timeline().empty)
        result = TimelineConstructor(frame).build_timeline('candidate')
        self.assertEqual(result.index.tolist(), [1, 0])
        self.assertEqual(select_timestamp_column(frame, 'runtime')['status'], 'unresolved')

    def test_conflicting_aliases_require_explicit_choice_but_equivalent_utc_aliases_do_not(self):
        frame = pd.DataFrame({'Timestamp': ['2026-11-16T09:00:00Z'],
                              'TimeCreated': ['2026-11-16T10:00:00Z']})
        self.assertEqual(select_timestamp_column(frame)['status'], 'ambiguous')
        self.assertTrue(TimelineConstructor(frame).build_timeline().empty)
        chosen = select_timestamp_column(frame, 'Timestamp')
        self.assertEqual(chosen['values'][0].text, '2026-11-16T09:00:00+00:00')
        frame['TimeCreated'] = ['2026-11-16T14:00:00+05:00']
        selected = select_timestamp_column(frame)
        self.assertEqual(selected['status'], 'resolved')
        self.assertEqual(selected['column'], 'TimeCreated')
        # Disjoint coverage is also ambiguous; do not silently coalesce fields.
        frame = pd.DataFrame({'Timestamp': ['2026-11-16T09:00:00Z', None],
                              'EventTime': [None, '2026-11-16T10:00:00Z']})
        self.assertEqual(select_timestamp_column(frame)['status'], 'ambiguous')

    def test_mixed_iso_windows_and_offsets_normalize_per_value(self):
        cases = {'2026-10-14T10:07:12+02:00': '2026-10-14T08:07:12+00:00',
                 '2026-10-14 13:07:12+0500': '2026-10-14T08:07:12+00:00',
                 '2026-10-14T08:07:12Z': '2026-10-14T08:07:12+00:00',
                 '2026-10-14 08:07:12 UTC': '2026-10-14T08:07:12+00:00',
                 '/Date(1791965232702+0530)/': '2026-10-14T08:07:12.702000+00:00'}
        for original, expected in cases.items():
            with self.subTest(original=original):
                value = parse_timestamp(original)
                self.assertEqual(value.original, original)
                self.assertEqual(value.text, expected)
        selection = select_timestamp_column(pd.DataFrame({'Timestamp': list(cases)}))
        self.assertEqual(selection['resolved'], len(cases))

    def test_missing_malformed_and_naive_times_remain_unresolved(self):
        values = [None, '', 'not-a-time', '2026-99-99T12:00:00Z', '2026-11-16T09:00:00',
                  '2026-11-16', datetime(2026, 11, 16, 9), '03/04/2026 10:00:00',
                  '2026-11-16T09:00:00+25:00', '/Date(1791965232702+0060)/']
        for value in values:
            with self.subTest(value=value):
                parsed = parse_timestamp(value)
                self.assertIsNone(parsed.utc)
                self.assertNotEqual(parsed.status, 'resolved')
        self.assertEqual(parse_timestamp('2026-11-16T09:00:00').status, 'timezone_missing')
        self.assertEqual(_event_timestamp_values(datetime(2026, 11, 16, 9)), (None, 'Unknown'))
        frame = pd.DataFrame({'Timestamp': values + ['2026-11-16T09:00:00Z']})
        builder = TimelineConstructor(frame)
        self.assertEqual(len(builder.build_timeline()), 1)
        self.assertEqual(len(builder.unresolved_events), len(values))

    def test_explicit_column_selection_does_not_supply_a_timezone(self):
        frame = pd.DataFrame({'DateTime': ['2026-11-16 10:00:00']})
        selection = select_timestamp_column(frame, 'DateTime')
        self.assertEqual(selection['status'], 'unresolved')
        self.assertEqual(selection['values'][0].status, 'timezone_missing')

    def test_precision_and_window_boundaries_preserve_windows_100ns(self):
        early = parse_timestamp('2026-11-16T09:00:00.123456700Z')
        late = parse_timestamp('2026-11-16T09:00:00.123456800Z')
        self.assertEqual(late.utc.value - early.utc.value, 100)
        normalized = normalize_security_event({'EventId': 4625, 'RecordId': 42,
            'Time': '2026-11-16T09:00:00.123456700Z'})
        self.assertIn('123456700', normalized['TimeUtc'])
        self.assertEqual(normalized['RecordId'], 42)
        rows = [dict(timestamp='2026-11-16T09:00:00.000000100Z', event_id=4625,
                     user='alice', source_ip='192.0.2.1', host='server'),
                dict(timestamp='2026-11-16T09:10:00.000000200Z', event_id=4625,
                     user='alice', source_ip='192.0.2.1', host='server')]
        self.assertEqual(detect_batch(rows, failed_threshold=2)[0], [])

    def test_stable_sort_uses_utc_instants_and_native_record_ids(self):
        rows = [dict(RecordId=8, EventTime='2026-11-16T10:00:00+02:00'),
                dict(RecordId=2, EventTime='2026-11-16T08:00:00Z'),
                dict(RecordId=5, EventTime='2026-11-16T08:30:00+01:00'),
                dict(RecordId=1, EventTime='unresolved')]
        for order in (rows, rows[::-1]):
            builder = TimelineConstructor(pd.DataFrame(order))
            result = builder.build_timeline()
            self.assertEqual(result['RecordId'].tolist(), [5, 2, 8])
            self.assertEqual(builder.unresolved_events['RecordId'].tolist(), [1])
            self.assertTrue(result['aegis_timestamp_utc'].is_monotonic_increasing)

    def test_windows_normalization_preserves_source_and_marks_unresolved(self):
        for raw_time, status in [('2026-11-16T09:00:00', 'timezone_missing'),
                                 ('invalid', 'unsupported_format'), (None, 'missing')]:
            event = dict(EventId=4625, RecordId=77, Time=raw_time)
            before = deepcopy(event)
            result = normalize_security_event(event)
            self.assertIsNone(result['TimeUtc'])
            self.assertEqual(result['RecordId'], 77)
            self.assertEqual(event, before)
            self.assertEqual(result['TimestampStatus'], status)
        event = dict(EventId=4625, RecordId=88, TimeCreated={'SystemTime': '2026-11-16T09:00:00Z'})
        result = normalize_security_event(event)
        self.assertEqual(result['TimeUtc'], '2026-11-16T09:00:00.000Z')
        self.assertEqual(result['TimestampOriginal'], event['TimeCreated'])

    def test_windows_history_separates_unknown_times_and_sorts_deterministically(self):
        events = [dict(EventId=4625, RecordId=1, Time='invalid', Log='Security'),
                  dict(EventId=4625, RecordId=3, Time='2026-11-16T10:00:00+02:00', Log='Security'),
                  dict(EventId=4625, RecordId=2, Time='2026-11-16T08:00:00Z', Log='Security'),
                  dict(EventId=4625, RecordId=4, Time='1960-01-01T00:00:00Z', Log='Security')]
        for reader in (read_latest_windows_security_events, read_security_events):
            with patch('modules.windows_security._run_powershell_json', return_value={'events': events, 'errors': []}):
                result = reader()
            self.assertEqual([e['RecordId'] for e in result['events']], [3, 2, 4, 1])
            self.assertIsNone(result['events'][-1]['TimeUtc'])

    def test_unresolved_events_do_not_generate_behavioral_dates(self):
        rows = [dict(timestamp='2026-11-16T09:00:00', event_id=4625,
                     user='alice', source_ip='192.0.2.1') for _ in range(5)]
        findings, diagnostics = detect_batch(rows)
        self.assertEqual(findings, [])
        self.assertIn('timestamp', str(diagnostics))

    def test_legacy_behavioral_cache_cannot_supply_a_guessed_utc_watermark(self):
        cached = dict(uid='legacy', timestamp='2099-01-01T00:00:00+00:00',
            evidence=dict(timestamp='2099-01-01T00:00:00', event_id=4625,
                          user='alice', source_ip='192.0.2.1', host='server'))
        original = deepcopy(cached)
        detector = BehavioralDetector(failed_threshold=2, state=dict(events=[cached],
            watermark=cached['timestamp'], emitted={}, bursts=[]))
        valid = [dict(timestamp=f'2026-11-16T09:00:0{number}Z', event_id=4625,
                      user='alice', source_ip='192.0.2.1', host='server') for number in (1, 2)]
        findings = detector.feed(valid)
        self.assertEqual(len(findings), 1)
        self.assertIn('Cached events', str(detector.diagnostics))
        self.assertEqual(cached, original)
        self.assertTrue(all(e['timestamp'].startswith('2026-') for e in detector.state['events']))

    def test_csv_locators_raw_values_hashes_and_rule_report_timeline_agree(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'events.csv'
            original = (b'EventId,TimeCreated,user,source_ip,message\r\n'
                b'4624,2026-11-16T04:00:00+02:00,alice,192.0.2.1,"first\r\nrecord"\r\n'
                b'\r\n4624,2026-11-16T01:00:00Z,bob,192.0.2.2,second\r\n'
                b'4624,2026-11-16T00:30:00,carol,192.0.2.3,unresolved\r\n')
            path.write_bytes(original)
            frame = LogParser(str(path)).parse_logs()
            timeline_builder = TimelineConstructor(frame)
            timeline = timeline_builder.build_timeline()
            self.assertEqual(timeline['source_record_number'].tolist(), [2, 1])
            self.assertEqual(timeline['source_line'].tolist(), [5, 2])
            self.assertEqual(timeline['source_line_end'].tolist(), [5, 3])
            self.assertEqual(timeline['TimeCreated'].tolist(), ['2026-11-16T01:00:00Z', '2026-11-16T04:00:00+02:00'])
            raw = load_log_csv(path)
            # EventId is a recognized native column in the input, normalized explicitly
            # to the established rule schema; timestamp aliases need no renaming.
            raw = raw.rename(columns={'eventid': 'event_id'})
            engine = RuleEngine(raw, source_file=path.name)
            findings = engine.run()
            self.assertTrue(findings)
            self.assertEqual([stamp for stamp, _ in chronological_findings(findings)], timeline['aegis_timestamp_utc'].tolist())
            for finding in findings:
                for ref in finding['evidence']:
                    self.assertEqual(ref['sha256'], file_sha256(path))
                    self.assertIn('timestamp_original', ref)
                    self.assertIn('csv_record_id', ref)
            reporter = LocalLLMReporter()
            report_text = reporter.generate_grounded_report('', '', findings=findings, use_llm=False)
            self.assertTrue(reporter.last_validation['passed'], reporter.last_validation)
            audit = Path(temporary) / 'CASE-TIME_audit.log'
            EvidenceIntegrity.log_audit_trail('CASE-TIME', 'EVIDENCE_UPLOAD',
                f'File uploaded: {path.name} | SHA256: {file_sha256(path)}', audit_path=audit)
            report = dict(case_id='CASE-TIME', source_paths=[str(path)], filename=path.name,
                sha256=file_sha256(path), findings=reporter.last_report_findings, text=report_text, chronology_version=1)
            bind_report_context(report, findings, audit_path=audit)
            self.assertTrue(validate_report_export(report)['passed'], report['validation'])
            markdown = render_forensic_text(report)
            pdf_text = '\n'.join(page.extract_text() for page in PdfReader(BytesIO(render_forensic_pdf(report))).pages)
            for stamp in timeline['aegis_timestamp_utc']:
                self.assertIn(stamp.isoformat(), markdown)
                self.assertIn(stamp.isoformat(), pdf_text)
            self.assertEqual(path.read_bytes(), original)
            self.assertIn('logical CSV record 1, lines 2-3', markdown)
            # Even a newly bound report must not misorder otherwise valid dates.
            altered = deepcopy(report)
            lines = LocalLLMReporter._chronology_lines(findings)
            altered['text'] = altered['text'].replace('\n'.join(lines), '\n'.join(lines[::-1]))
            with self.assertRaisesRegex(ValueError, 'chronology'):
                bind_report_context(altered, findings, audit_path=audit)

    def test_ambiguous_rule_timestamp_selection_is_explicit_and_shared(self):
        frame = pd.DataFrame({'event_id': [4624], 'user': ['alice'], 'source_ip': ['192.0.2.1'],
            'Timestamp': ['2026-11-16T02:00:00Z'], 'EventTime': ['2026-11-16T04:00:00Z']})
        self.assertTrue(RuleEngine.can_run(frame)[0])
        self.assertEqual(RuleEngine(frame).timestamp_selection["status"], "ambiguous")
        self.assertTrue(RuleEngine.can_run(frame, 'Timestamp')[0])
        engine = RuleEngine(frame, timestamp_column='Timestamp')
        finding = engine.run()[0]
        timeline = TimelineConstructor(frame).build_timeline('Timestamp')
        self.assertEqual(finding['first_seen'], timeline.iloc[0]['aegis_timestamp_utc'])
        self.assertEqual(finding['evidence'][0]['timestamp_original'], frame.iloc[0]['Timestamp'])

    def test_non_temporal_findings_survive_unresolved_event_times_without_dates(self):
        frame = pd.DataFrame({'timestamp': ['2026-11-16T09:00:00', 'invalid'],
            'event_id': [1102, 7045], 'user': ['alice', 'alice'],
            'source_ip': ['192.0.2.1', '192.0.2.1'], 'message': ['cleared', 'service installed']})
        self.assertTrue(RuleEngine.can_run(frame)[0])
        findings = RuleEngine(frame).run()
        self.assertEqual(len(findings), 2)
        self.assertTrue(all(f['first_seen'] is None and f['last_seen'] is None for f in findings))
        self.assertTrue(all(f['timestamp_status'] == 'unresolved' for f in findings))
        reporter = LocalLLMReporter()
        text = reporter.generate_grounded_report('', '', findings=findings, use_llm=False)
        self.assertTrue(reporter.last_validation['passed'], reporter.last_validation)
        section = text.split('## Timeline Analysis', 1)[1].split('## Technical Findings', 1)[0]
        self.assertIn('Unresolved event times', section)
        self.assertNotIn('2026-11-16T09:00:00', section)
        self.assertIn('Audit log cleared', text)
        self.assertIn('New service installed', text)

    def test_report_uses_utc_order_and_does_not_mutate_historical_findings(self):
        def finding(identifier, stamp):
            return dict(id=identifier, rule='Recorded event', severity='Medium', source='rule',
                first_seen=stamp, last_seen=stamp, description='Recorded activity.', mitre='n/a',
                evidence=[dict(file='events.csv', line=2)])
        findings = [finding('F-003', '2026-11-16T10:00:00+02:00'),
                    finding('F-002', '2026-11-16T08:00:00Z'),
                    finding('F-001', '2026-11-16T08:30:00+01:00'),
                    finding('F-004', '2026-11-16T07:00:00')]
        before = deepcopy(findings)
        reporter = LocalLLMReporter()
        text = reporter.generate_grounded_report('', '', findings=findings, use_llm=False)
        self.assertTrue(reporter.last_validation['passed'], reporter.last_validation)
        timeline = text.split('## Timeline Analysis\n', 1)[1].split('## Technical Findings', 1)[0]
        event_lines = [line for line in timeline.splitlines() if line.startswith('- ')]
        self.assertEqual([line.rsplit('[', 1)[1].split(']')[0] for line in event_lines], ['F-001', 'F-002', 'F-003'])
        self.assertNotIn('2026-11-16T07:00:00', timeline)
        self.assertIn('Unresolved event times', timeline)
        self.assertEqual(findings, before)
        llm = '## Timeline Analysis\nInvented chronology [F-004].\n## Technical Findings\nReview [F-001].'
        corrected = reporter._fix_timeline(llm, findings)
        corrected_section = corrected.split('## Timeline Analysis\n', 1)[1].split('## Technical Findings', 1)[0]
        self.assertNotIn('Invented', corrected_section)
        self.assertIn('2026-11-16T07:30:00+00:00', corrected_section)

    def test_visual_finding_timeline_uses_same_utc_order_as_reports(self):
        from dashboard.forensic_ui import timeline_html
        findings = [dict(id='F-002', rule='Later event', severity='Medium',
                         first_seen='2026-11-16T09:00:00Z'),
                    dict(id='F-001', rule='Earlier event', severity='Medium',
                         first_seen='2026-11-16T10:00:00+02:00'),
                    dict(id='F-003', rule='Unresolved event', severity='Medium',
                         first_seen='2026-11-16T07:00:00')]
        html = timeline_html(findings)
        self.assertLess(html.index('Earlier event'), html.index('Later event'))
        self.assertNotIn('Unresolved event', html)
        self.assertIn('2026-11-16T08:00:00+00:00', html)

    def test_investigation_time_labels_do_not_relabel_offsets_or_naive_times_as_utc(self):
        tree = ast.parse((ROOT / 'dashboard/app.py').read_text(encoding='utf-8'))
        helper = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == '_protection_alert_time')
        namespace = {}
        exec(compile(ast.Module(body=[helper], type_ignores=[]), 'app.py', 'exec'), namespace)
        display = namespace['_protection_alert_time']
        self.assertEqual(display({'created_at_utc': '2026-11-16T10:00:00+02:00'}), '2026-11-16 08:00:00 UTC')
        self.assertEqual(display({'created_at_utc': '2026-11-16T10:00:00'}), 'Unresolved timestamp')
        self.assertEqual(display({'created_at_utc': 1700000000}), 'Unresolved timestamp')
        self.assertEqual(display({}), 'Not recorded')
        from dashboard.forensic_ui import action_html
        html = action_html([dict(id='F-001', rule='Recorded event', severity='Medium',
                                 description='Recorded activity.', first_seen='2026-11-16T10:00:00')])
        self.assertIn('Unresolved time', html)
        self.assertNotIn('2026-11-16T10:00:00', html)

    def test_overview_uses_same_explicit_column_and_never_ids(self):
        tree = ast.parse((ROOT / 'dashboard/app.py').read_text(encoding='utf-8'))
        helper = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'events_over_time')
        namespace = dict(pd=pd, select_timestamp_column=select_timestamp_column)
        exec(compile(ast.Module(body=[helper], type_ignores=[]), 'app.py', 'exec'), namespace)
        graph = namespace['events_over_time']
        ids = pd.DataFrame({'EventId': [1700000000, 1700000010]})
        self.assertEqual(graph(ids), (None, None))
        frame = pd.DataFrame({'TimeCreated': ['2026-11-16T02:00:00Z', '2026-11-16T03:00:00Z'],
                              'Timestamp': ['2026-11-16T05:00:00Z', '2026-11-16T06:00:00Z']})
        self.assertEqual(graph(frame), (None, None))
        series, column = graph(frame, 'Timestamp')
        self.assertEqual(column, 'Timestamp')
        self.assertEqual(series['events'].sum(), 2)
        source = (ROOT / 'dashboard/app.py').read_text(encoding='utf-8')
        self.assertNotIn('ts_cols[0] if ts_cols else df.columns[0]', source)
        self.assertIn('"Event timestamp column"', source)


if __name__ == '__main__':
    unittest.main()
