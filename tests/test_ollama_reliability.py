"""Real loopback HTTP tests for bounded, complete, evidence-validated generation."""
from copy import deepcopy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from io import BytesIO
import json
from pathlib import Path
import socket
import tempfile
import threading
import time
import unittest

from pypdf import PdfReader

from modules.ai_reporter import LocalLLMReporter
from modules.integrity import EvidenceIntegrity
from modules.ollama_client import generate, OllamaError
from modules.pdf_report import render_forensic_pdf
from modules.report_validation import bind_report_context, render_forensic_text, validate_report_export


FINDING = dict(id='Y-001', source='yara', rule='Test signature', severity='Low',
               mitre='n/a', description='A harmless test signature matched.', file='marker.txt',
               evidence=[dict(file='marker.txt', line=1)])
COMPLETE = ('## Executive Summary\nA harmless test signature matched. [Y-001]\n'
            '## Timeline Analysis\nNo timestamp was recorded. [Y-001]\n'
            '## Technical Findings\nA harmless test signature matched. [Y-001]\n'
            '## Recommendations\nReview the recorded match. [Y-001]')


def event(text='', done=False, **values):
    return json.dumps(dict(model='llama3.2', response=text, done=done, **values)).encode() + b'\n'


class OllamaReliabilityTests(unittest.TestCase):
    def server(self, chunks=None, *, status=200, delay=0, first_delay=0, protocol='HTTP/1.1'):
        chunks = chunks if chunks is not None else [event(COMPLETE), event(done=True, done_reason='stop')]
        requests = []

        class Handler(BaseHTTPRequestHandler):
            protocol_version = protocol

            def handle(self):
                try:
                    super().handle()
                except OSError:
                    pass  # Expected when a cancelled client closes keep-alive.

            def do_POST(self):
                requests.append(json.loads(self.rfile.read(int(self.headers['Content-Length']))))
                self.send_response(status)
                self.send_header('Content-Type', 'application/x-ndjson')
                self.send_header('Content-Length', str(sum(map(len, chunks))))
                self.end_headers()
                time.sleep(first_delay)
                try:
                    for chunk in chunks:
                        self.wfile.write(chunk); self.wfile.flush()
                        time.sleep(delay)
                except (OSError, ConnectionError):
                    pass  # The client must close a timed-out generation.

            def log_message(self, *_):
                pass

        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=lambda: server.serve_forever(poll_interval=.01), daemon=True)
        thread.start()

        def close():
            server.shutdown(); server.server_close(); thread.join(timeout=2)
        self.addCleanup(close)
        return f'http://127.0.0.1:{server.server_port}/api/generate', requests

    def call(self, endpoint, **values):
        options = dict(num_ctx=2048, max_tokens=320, timeout=1, deadline=time.monotonic() + 2,
                       keep_alive='1m', max_prompt_bytes=1472)
        options.update(values)
        return generate(endpoint, 'llama3.2', 'Harmless local test', **options)

    def test_complete_stream_records_model_loading_and_inference_metrics(self):
        endpoint, requests = self.server([event('Recorded match [Y-001].'), event(done=True, done_reason='stop',
            load_duration=2_000_000_000, prompt_eval_duration=3_000_000_000,
            eval_duration=4_000_000_000, prompt_eval_count=20, eval_count=10)])
        text, metrics = self.call(endpoint)
        self.assertEqual(text, 'Recorded match [Y-001].')
        self.assertEqual(metrics['load_seconds'], 2)
        self.assertEqual(metrics['prompt_eval_seconds'], 3)
        self.assertEqual(metrics['eval_seconds'], 4)
        self.assertIsNotNone(metrics['first_token_seconds'])
        self.assertEqual(metrics['requested_model'], 'llama3.2')
        self.assertEqual(requests[0]['options'], dict(temperature=.1, num_ctx=2048, num_predict=320))
        self.assertTrue(requests[0]['stream'])
        self.assertEqual(requests[0]['keep_alive'], '1m')

    def test_generation_is_interrupted_at_total_deadline_despite_continuous_tokens(self):
        endpoint, _ = self.server([event('recorded ') for _ in range(30)] +
            [event(done=True, done_reason='stop')], delay=.015)
        started = time.monotonic()
        with self.assertRaises(OllamaError) as caught:
            self.call(endpoint, deadline=time.monotonic() + .10)
        self.assertEqual(caught.exception.category, 'timeout')
        self.assertIn('partial', str(caught.exception))
        self.assertLess(time.monotonic() - started, .5)
        self.assertIsNotNone(caught.exception.diagnostics['first_token_seconds'])

    def test_idle_before_first_token_has_a_distinct_timeout_phase(self):
        endpoint, _ = self.server(first_delay=.15)
        with self.assertRaises(OllamaError) as caught:
            self.call(endpoint, timeout=.035)
        self.assertEqual(caught.exception.category, 'timeout')
        self.assertIn('model loading or prompt evaluation', str(caught.exception))
        self.assertIsNone(caught.exception.diagnostics['first_token_seconds'])

    def test_unavailable_service_and_missing_model_are_distinct(self):
        with socket.socket() as closed:
            closed.bind(('127.0.0.1', 0)); port = closed.getsockname()[1]
        with self.assertRaises(OllamaError) as caught:
            self.call(f'http://127.0.0.1:{port}/api/generate')
        self.assertIn(caught.exception.category, {'connection', 'connection_timeout'})
        endpoint, _ = self.server(status=404)
        with self.assertRaises(OllamaError) as caught:
            self.call(endpoint)
        self.assertEqual(caught.exception.category, 'model_unavailable')
        self.assertIn('No model was replaced or downloaded', str(caught.exception))

    def test_malformed_failed_and_partial_responses_never_return_report_text(self):
        cases = [([b'not-json\n'], 'malformed_response'),
                 ([b'\xff\n'], 'malformed_response'),
                 ([b'[]\n'], 'malformed_response'),
                 ([b'{"error":"not enough memory"}\n'], 'server_error'),
                 ([event('Valid cited fragment [Y-001].')], 'incomplete_response'),
                 ([event('Valid cited fragment [Y-001].', done=True, done_reason='length')], 'incomplete_response'),
                 ([event('Valid cited fragment [Y-001].', done=True)], 'incomplete_response'),
                 ([event(done=True, done_reason='stop')], 'malformed_response'),
                 ([event('Text', done=True, done_reason='stop')[:-1]], 'malformed_response'),
                 ([json.dumps(dict(model='another-model', response='Text', done=True, done_reason='stop')).encode()+b'\n'], 'model_mismatch')]
        for chunks, category in cases:
            with self.subTest(category=category, chunks=chunks):
                endpoint, _ = self.server(chunks)
                with self.assertRaises(OllamaError) as caught:
                    self.call(endpoint)
                self.assertEqual(caught.exception.category, category)

    def test_oversized_or_expired_request_never_contacts_service(self):
        endpoint, calls = self.server()
        with self.assertRaises(OllamaError) as caught:
            self.call(endpoint, max_prompt_bytes=2)
        self.assertEqual(caught.exception.category, 'prompt_budget')
        with self.assertRaises(OllamaError) as caught:
            self.call(endpoint, deadline=time.monotonic() - 1)
        self.assertEqual(caught.exception.category, 'timeout')
        self.assertFalse(calls)

    def test_connection_close_response_uses_same_completion_checks(self):
        # HTTP/1.0 closes the connection at EOF, independently of keep_alive's
        # model-residency meaning. The socket deadline must still work.
        endpoint, _ = self.server(protocol='HTTP/1.0')
        text, _ = self.call(endpoint)
        self.assertEqual(text, COMPLETE)

    def test_failure_is_explicit_and_validated_template_preserves_original_findings(self):
        endpoint, calls = self.server([event('Incomplete cited content [Y-001].', done=True, done_reason='length')])
        findings = [deepcopy(FINDING)]; original = deepcopy(findings)
        reporter = LocalLLMReporter(model_name='llama3.2', ollama_url=endpoint)
        text = reporter.generate_grounded_report('', '', findings=findings)
        self.assertEqual(reporter.last_mode, 'template')
        self.assertIn('partial or token-limited', reporter.last_note)
        self.assertEqual(reporter.last_llm_diagnostics[0]['error_category'], 'incomplete_response')
        self.assertEqual(len(calls), 1)
        self.assertTrue(reporter.last_validation['passed'])
        self.assertNotIn('Incomplete cited content', text)
        self.assertEqual(findings, original)

    def test_large_prompt_is_rejected_without_truncating_saved_finding_content(self):
        endpoint, calls = self.server()
        finding = dict(FINDING, description='Recorded source text. ' * 10_000)
        reporter = LocalLLMReporter(model_name='llama3.2', ollama_url=endpoint)
        text = reporter.generate_grounded_report('', '', findings=[finding])
        self.assertEqual(reporter.last_mode, 'template')
        self.assertIn('No evidence was truncated', reporter.last_note)
        self.assertFalse(calls)
        self.assertEqual(reporter.last_report_findings[0]['description'], finding['description'])
        self.assertIn(finding['description'], text)

    def test_unknown_citations_still_reject_llm_text(self):
        endpoint, _ = self.server([event('Invented finding. [F-999]'), event(done=True, done_reason='stop')])
        reporter = LocalLLMReporter(model_name='llama3.2', ollama_url=endpoint)
        text = reporter.generate_grounded_report('', '', findings=[deepcopy(FINDING)])
        self.assertEqual(reporter.last_mode, 'template')
        self.assertTrue(reporter.last_validation['passed'])
        self.assertNotIn('F-999', text)

    def test_cited_but_incomplete_report_is_never_labeled_a_full_llm_report(self):
        endpoint, _ = self.server([event('A harmless test signature matched. [Y-001]'),
                                  event(done=True, done_reason='stop')])
        reporter = LocalLLMReporter(model_name='llama3.2', ollama_url=endpoint)
        text = reporter.generate_grounded_report('', '', findings=[deepcopy(FINDING)])
        self.assertNotEqual(reporter.last_mode, 'llm')
        self.assertFalse(reporter.last_llm_diagnostics[0]['structure_validation_passed'])
        self.assertTrue(reporter.last_validation['passed'])
        self.assertIn('## Technical Findings', text)

    def test_completed_report_and_diagnostics_are_bound_to_verified_exports(self):
        endpoint, _ = self.server()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); source = root / 'marker.txt'; source.write_text('harmless marker\n')
            digest = EvidenceIntegrity.calculate_sha256(source)
            finding = dict(FINDING, sha256=digest)
            reporter = LocalLLMReporter(model_name='llama3.2', ollama_url=endpoint)
            text = reporter.generate_grounded_report('', '', findings=[finding])
            self.assertEqual(reporter.last_mode, 'llm')
            audit = root / 'CASE-LLM_audit.log'
            EvidenceIntegrity.log_audit_trail('CASE-LLM', 'EVIDENCE_UPLOAD',
                f'File uploaded: marker.txt | SHA256: {digest}', audit_path=audit)
            record = dict(case_id='CASE-LLM', filename='marker.txt', sha256=digest,
                source_paths=[str(source)], findings=reporter.last_report_findings, text=text,
                mode=reporter.last_mode, llm_generation=reporter.last_llm_diagnostics)
            bind_report_context(record, record['findings'], audit_path=audit)
            self.assertTrue(validate_report_export(record)['passed'])
            markdown = render_forensic_text(record)
            pdf = '\n'.join(page.extract_text() for page in PdfReader(BytesIO(render_forensic_pdf(record))).pages)
            for output in (markdown, pdf):
                self.assertIn('Y-001', output)
                self.assertIn(digest, output)
            record['llm_generation'][0]['model'] = 'false-model-label'
            self.assertFalse(validate_report_export(record)['passed'])

    def test_invalid_generation_configuration_is_rejected(self):
        for settings in (dict(num_ctx=0), dict(max_tokens=True), dict(max_tokens=2000),
                         dict(time_budget=float('inf')), dict(timeout=-1), dict(keep_alive='10m')):
            with self.subTest(settings=settings), self.assertRaises(ValueError):
                LocalLLMReporter(**settings)


if __name__ == '__main__':
    unittest.main()
