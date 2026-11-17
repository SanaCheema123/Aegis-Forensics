"""Real local API integration using temporary cases, original modules and checkpoints."""
from pathlib import Path
import tempfile
import time
import unittest

from fastapi.testclient import TestClient
from api.main import create_app

ROOT = Path(__file__).resolve().parents[1]


class WebAPITests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.app = create_app(self.root, {}, testing=True)
        self.client = TestClient(self.app, raise_server_exceptions=False)
        self.client.__enter__()
        self.client.headers['X-Aegis-Token'] = self.client.get('/api/v1/health').json()['csrf_token']
        self.assertEqual(self.client.post('/api/v1/cases', json={'case_id': 'WEB-TEST'}).status_code, 201)
        self.base = '/api/v1/cases/WEB-TEST'

    def tearDown(self):
        self.client.__exit__(None, None, None)
        self.temp.cleanup()

    def upload(self, data, name='sample.csv'):
        response = self.client.post(self.base + '/evidence', files={'file': (name, data, 'text/csv')})
        self.assertEqual(response.status_code, 201, response.text)
        return response.json()

    def wait_job(self, job):
        for _ in range(1200):
            result = self.client.get(self.base + '/jobs/' + job['id']).json()
            if result['status'] in {'failed', 'completed', 'cancelled'}:
                return result
            time.sleep(0.05)
        self.fail('Job did not finish within test deadline')

    def test_health_validation_csrf_origin_and_traversal(self):
        self.assertEqual(self.client.get('/api/v1/health').status_code, 200)
        self.assertEqual(self.client.post('/api/v1/cases', headers={'X-Aegis-Token': ''}, json={'case_id': 'X'}).status_code, 403)
        self.assertEqual(self.client.get('/api/v1/health', headers={'Origin': 'https://attacker.example'}).status_code, 403)
        self.assertEqual(self.client.get('/api/v1/health', headers={'Host': 'attacker.example'}).status_code, 400)
        self.assertEqual(self.client.post('/api/v1/cases', json={'case_id': '..'}).status_code, 422)
        self.assertEqual(self.client.post(self.base + '/evidence', files={'file': ('../escape.csv', b'a,b\n1,2')}).status_code, 422)
        self.assertEqual(self.client.post(self.base + '/scans', json={'evidence_id': 'x', 'model': 'made-up'}).status_code, 422)
        self.assertEqual(self.client.get(self.base + '/evidence?page_size=10000').status_code, 422)

    def test_upload_integrity_preview_search_timeline_and_cross_case(self):
        item = self.upload(b'proto,service,state,attack_cat\ntcp,http,FIN,Generic\nudp,dns,INT,Normal\ntcp,http,FIN,Generic\n')
        source = self.base + '/evidence/' + item['id']
        self.assertTrue(self.client.post(source + '/verify').json()['verified'])
        preview = self.client.get(source + '/preview?page_size=1&page_number=2').json()
        self.assertEqual(preview['items'][0]['_source']['record_number'], 2)
        search = self.client.post(source + '/search', json={'query': 'Generic'}).json()
        self.assertEqual(search['total'], 2)
        self.assertEqual(search['status'], 'success')
        self.assertEqual(self.client.post(source + '/search', json={'query': 'Generic'}).json()['key'], search['key'])
        times = self.client.get(source + '/timeline').json()
        self.assertEqual((times['resolved_count'], times['unresolved_count']), (0, 3))
        self.client.post('/api/v1/cases', json={'case_id': 'OTHER'})
        other = '/api/v1/cases/OTHER/evidence/' + item['id']
        self.assertEqual(self.client.get(other + '/preview').status_code, 404)
        (self.root / 'data/raw_evidence' / item['filename']).write_bytes(b'changed')
        self.assertEqual(self.client.post(source + '/verify').status_code, 409)

    def test_network_scan_saved_findings_review_audit_report_and_download(self):
        item = self.upload((ROOT / 'data/training/UNSW_NB15_demo_balanced.csv').read_bytes(), 'demo.csv')
        request = {'evidence_id': item['id'], 'kind': 'network', 'model': 'xgboost', 'split': 'random'}
        response = self.client.post(self.base + '/scans', json=request)
        self.assertEqual(response.status_code, 202, response.text)
        job = self.wait_job(response.json())
        self.assertEqual(job['status'], 'completed', job)
        self.assertEqual(job['result']['flagged_records'], 105)
        eid, scan_id = job['result']['evidence_id'], job['result']['scan_id']
        source = self.base + '/evidence/' + eid
        self.assertEqual(self.client.get(source + '/scans').json()['items'][0]['scan_id'], scan_id)
        prefix = source + '/scans/' + scan_id + '/findings'
        finding = self.client.get(prefix).json()['items'][0]
        self.assertTrue(finding['original_csv_record'])
        review_url = prefix + '/' + finding['id'] + '/review'
        review = self.client.post(review_url)
        self.assertEqual(review.status_code, 200, review.text)
        before = (self.root / 'data/cases/WEB-TEST_audit.log').read_bytes()
        self.assertEqual(self.client.post(review_url).status_code, 200)
        self.assertEqual((self.root / 'data/cases/WEB-TEST_audit.log').read_bytes(), before)
        self.assertTrue(self.client.get(prefix).json()['items'][0]['review_pending'])
        # Fresh service, same persisted records, no shared session dictionary.
        from api.services.forensics import ForensicsService
        self.assertTrue(ForensicsService(self.root).findings('WEB-TEST', eid, scan_id)[0]['review_pending'])
        self.assertTrue(self.client.get(self.base + '/audit').json()['verified'])
        report = self.client.post(self.base + '/reports', json={'evidence_id': eid, 'scan_id': scan_id})
        self.assertEqual(report.status_code, 201, report.text)
        rid = report.json()['id']
        for fmt, magic in [('md', b'##'), ('pdf', b'%PDF')]:
            export = self.client.get(self.base + '/reports/' + rid + '/download?format=' + fmt)
            self.assertEqual(export.status_code, 200, export.text[:300])
            self.assertTrue(export.content.startswith(magic), export.content[:50])
        (self.root / 'data/raw_evidence' / item['filename']).write_bytes(b'tampered')
        self.assertEqual(self.client.get(self.base + '/reports/' + rid + '/download?format=pdf').status_code, 409)

    def test_iforest_evaluation_and_schema_mismatch_never_fallback(self):
        item = self.upload((ROOT / 'data/training/UNSW_NB15_demo_balanced.csv').read_bytes(), 'demo.csv')
        result = self.wait_job(self.client.post(self.base + '/evaluation', json={
            'evidence_id': item['id'], 'model': 'iforest', 'split': 'random'}).json())
        self.assertEqual(result['status'], 'completed', result)
        self.assertEqual(result['result']['confusion_matrix'], [[84, 16], [47, 53]])
        bad = self.upload(b'proto,dur\ntcp,1\ntcp,2\n', 'bad.csv')
        failed = self.wait_job(self.client.post(self.base + '/scans', json={
            'evidence_id': bad['id'], 'kind': 'network', 'model': 'iforest'}).json())
        self.assertEqual(failed['status'], 'failed')
        self.assertIn('schema', failed['error'])
        self.assertEqual(self.client.get(self.base + '/evidence/' + bad['id'] + '/scans').json()['total'], 0)

    def test_audit_tampering_is_preserved_and_blocks_case_data(self):
        path = self.root / 'data/cases/WEB-TEST_audit.log'
        path.write_text(path.read_text().replace('CASE_CREATED', 'CASE_MODIFIED'))
        before = path.read_bytes()
        result = self.client.get(self.base + '/audit').json()
        self.assertFalse(result['verified'])
        self.assertIn('modified', result['message'])
        self.assertEqual(self.client.get(self.base + '/evidence').status_code, 409)
        self.assertEqual(path.read_bytes(), before)

    def test_unapproved_folder_and_static_url(self):
        self.assertEqual(self.client.post(self.base + '/scans/folder', json={'root_id': 'C:\\'}).status_code, 403)
        self.assertEqual(self.client.post('/api/v1/monitoring/start', json={'root_ids': ['C:\\']}).status_code, 403)
        response = self.client.post('/api/v1/scans/url', json={'url': 'http://127.0.0.1/internal'})
        self.assertEqual(response.status_code, 200)
        self.assertIn('no network', response.json()['method'])

    def test_upload_limit_collision_and_static_scan(self):
        response = self.client.post(self.base + '/evidence', content=b'x', headers={'Content-Length': str(22*1024*1024)})
        self.assertEqual(response.status_code, 413)
        first = self.upload(b'First original file', 'notes.txt')
        second = self.upload(b'Second original file', 'notes.txt')
        self.assertNotEqual(first['id'], second['id'])
        self.assertNotEqual(first['filename'], second['filename'])
        self.assertEqual(self.client.get(self.base+'/evidence/'+first['id']).json()['sha256'], first['sha256'])
        job = self.wait_job(self.client.post(self.base + '/scans', json={'evidence_id':first['id'],'kind':'file'}).json())
        self.assertEqual(job['status'], 'completed', job)
        self.assertEqual((self.root/'data/raw_evidence'/first['filename']).read_bytes(), b'First original file')

    def test_approved_folder_uses_existing_bounded_engine_and_redacts_paths(self):
        folder = self.root/'approved';folder.mkdir();(folder/'harmless.txt').write_text('Acceptance fixture')
        self.app.state.service.approved_roots['fixture'] = folder
        job = self.wait_job(self.client.post(self.base+'/scans/folder',json={'root_id':'fixture'}).json())
        self.assertEqual(job['status'], 'completed', job)
        self.assertEqual(job['result']['files_checked'], 1)
        self.assertNotIn(str(self.root), str(job))
        self.assertEqual((folder/'harmless.txt').read_text(),'Acceptance fixture')

    def test_timeline_explicit_timezone_and_multiline_source(self):
        item=self.upload(b'timestamp,message\n2026-11-16T11:00:00+02:00,"second\nline"\n2026-11-16T08:00:00Z,first\n')
        source=self.base+'/evidence/'+item['id']
        timeline=self.client.get(source+'/timeline?column=timestamp').json()
        self.assertEqual(timeline['resolved_count'],2)
        self.assertEqual([r['source_record_number'] for r in timeline['items']],[2,1])
        self.assertEqual(timeline['items'][1]['source_line_end'],3)
        self.assertEqual(self.client.get(source+'/timeline?start=2026-11-16').status_code,422)

    def test_event_csv_scan_reuses_existing_rule_engine(self):
        rows=['timestamp,event_id,user,source_ip,host,message']
        rows.extend(f'2026-11-16T01:00:0{i}Z,4625,alice,192.0.2.1,synthetic,failed login' for i in range(6))
        item=self.upload(('\n'.join(rows)+'\n').encode(),'events.csv')
        result=self.wait_job(self.client.post(self.base+'/scans',json={'evidence_id':item['id'],'kind':'file'}).json())
        self.assertEqual(result['status'],'completed',result)
        findings=self.app.state.service.findings('WEB-TEST',result['result']['evidence_id'],result['result']['scan_id'])
        self.assertTrue(any('Brute force' in finding.get('rule','') for finding in findings))


if __name__ == '__main__':
    unittest.main()
