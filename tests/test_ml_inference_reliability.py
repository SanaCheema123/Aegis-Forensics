"""Strict model contracts, trust boundaries, score interpretation and report provenance."""
import ast
from copy import deepcopy
import hashlib
from io import BytesIO
import json
from pathlib import Path
import pickle
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import Mock, patch

import numpy as np
import pandas as pd
from pypdf import PdfReader

import modules.ml_detector as detector_module
import modules.model_store as store
import modules.semantic_matcher as semantic
from modules.ml_detector import MLAnomalyDetector
from modules.model_store import ModelReliabilityError, load_trusted_checkpoint
from modules.ai_reporter import LocalLLMReporter, ml_to_report_findings
from modules.csv_evidence import file_sha256
from modules.rules import load_log_csv
from modules.integrity import EvidenceIntegrity
from modules.report_validation import bind_report_context, render_forensic_text, validate_report_export
from modules.pdf_report import render_forensic_pdf

ROOT = Path(__file__).resolve().parents[1]


class MLInferenceReliabilityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows = pd.read_csv(ROOT / 'data/training/holdout_test.csv', nrows=8)
        cls.bundles = {key: load_trusted_checkpoint(*key) for key in store.CHECKPOINT_SHA256}

    def infer(self, frame=None, model='xgboost', split='random', threshold=0.5):
        detector = MLAnomalyDetector(self.rows.copy() if frame is None else frame,
            model=model, split=split, threshold=threshold)
        with patch.object(detector_module, 'load_trusted_checkpoint', return_value=self.bundles[(model, split)]):
            result = detector.detect_anomalies()
        return detector, result

    def test_valid_schema_reorders_by_training_names_and_keeps_predictions_identical(self):
        for model in ('xgboost', 'iforest'):
            for split in ('random', 'official'):
                with self.subTest(model=model, split=split):
                    detector, one = self.infer(model=model, split=split)
                    _, two = self.infer(self.rows[self.rows.columns[::-1]], model=model, split=split)
                    self.assertEqual(one.index.tolist(), two.index.tolist())
                    np.testing.assert_allclose(one['ml_score'], two['ml_score'])
                    self.assertEqual(detector.last_mode, f'trained_{model}')
                    self.assertEqual(detector.last_provenance['checkpoint_sha256'], store.CHECKPOINT_SHA256[(model, split)])

    def test_missing_features_unexpected_features_and_unknown_categories_are_rejected(self):
        cases = [self.rows.drop(columns='dur'), self.rows.drop(columns='proto'),
                 self.rows.assign(unexpected_sensor=1), self.rows.assign(proto='unknown-protocol'),
                 self.rows.assign(service=None), self.rows.assign(state=123)]
        for frame in cases:
            for model in ('xgboost', 'iforest'):
                with self.subTest(columns=list(frame.columns), model=model):
                    with self.assertRaises(ModelReliabilityError):
                        self.infer(frame, model=model)

    def test_missing_nonnumeric_nonfinite_datetime_and_complex_values_are_not_zero_filled(self):
        for value in (None, 'invalid', np.inf, -np.inf, np.nan, 1e100, complex(1, 2)):
            frame = self.rows.copy()
            frame['dur'] = frame['dur'].astype(object)
            frame.loc[frame.index[0], 'dur'] = value
            with self.subTest(value=value):
                with self.assertRaises(ModelReliabilityError):
                    self.infer(frame)
        frame = self.rows.copy()
        frame['dur'] = pd.date_range('2026-11-16', periods=len(frame), tz='UTC')
        with self.assertRaises(ModelReliabilityError):
            self.infer(frame)

    def test_numeric_strings_are_explicitly_converted_without_schema_order_changes(self):
        string_rows = self.rows.copy()
        for name in MLAnomalyDetector._base_columns(self.bundles[('xgboost', 'random')][0]['columns']):
            string_rows[name] = string_rows[name].astype(str)
        _, original = self.infer()
        _, converted = self.infer(string_rows)
        np.testing.assert_allclose(original['ml_score'], converted['ml_score'])
        self.assertEqual(original.index.tolist(), converted.index.tolist())

    def test_integer_training_feature_rejects_fractional_values(self):
        frame = self.rows.copy()
        frame['spkts'] = frame['spkts'].astype(float) + 0.25
        with self.assertRaisesRegex(ModelReliabilityError, 'integer'):
            self.infer(frame)

    def test_explicit_model_names_thresholds_and_record_identities_are_validated(self):
        for model in ('unknown', 'isolationforest', '../xgboost', 'https://model'):
            with self.assertRaises(ModelReliabilityError):
                MLAnomalyDetector(self.rows, model=model)
        for value in (float('nan'), float('inf'), -0.1, 1.1, True):
            with self.assertRaises(ModelReliabilityError):
                MLAnomalyDetector(self.rows, threshold=value)
        with self.assertRaises(ModelReliabilityError):
            MLAnomalyDetector(self.rows.set_axis([0] * len(self.rows)))
        with self.assertRaises(ModelReliabilityError):
            MLAnomalyDetector(self.rows.assign(ml_score=0))
        with self.assertRaises(ModelReliabilityError):
            MLAnomalyDetector(pd.concat([self.rows, self.rows[['dur']]], axis=1))

    def test_unavailable_checkpoint_or_incompatible_schema_never_runs_generic_fallback(self):
        detector = MLAnomalyDetector(pd.DataFrame({'message': ['one', 'two']}), model='xgboost')
        with patch.object(detector, '_detect_unsupervised') as generic, patch.object(
                detector_module, 'load_trusted_checkpoint', side_effect=ModelReliabilityError('checkpoint unavailable')):
            with self.assertRaisesRegex(ModelReliabilityError, 'unavailable'):
                detector.detect_anomalies()
            generic.assert_not_called()
        with patch.object(detector, '_detect_unsupervised') as generic, patch.object(
                detector_module, 'load_trusted_checkpoint', return_value=self.bundles[('xgboost', 'random')]):
            with self.assertRaisesRegex(ModelReliabilityError, 'schema'):
                detector.detect_anomalies()
            generic.assert_not_called()
            self.assertEqual(detector.last_mode, 'blocked')

    def test_checkpoint_schema_and_estimator_type_must_agree(self):
        for change in ('reordered', 'duplicate', 'wrong_estimator'):
            bundle = dict(self.bundles[('xgboost', 'random')][0])
            if change == 'reordered':
                bundle['columns'] = bundle['columns'][::-1]
            elif change == 'duplicate':
                bundle['columns'] = bundle['columns'] + [bundle['columns'][0]]
            else:
                bundle['model'] = self.bundles[('iforest', 'random')][0]['model']
            detector = MLAnomalyDetector(self.rows)
            with patch.object(detector_module, 'load_trusted_checkpoint', return_value=(bundle, {})):
                with self.assertRaises(ModelReliabilityError):
                    detector.detect_anomalies()

    def fake_classifier(self, probabilities, classes=(1, 0)):
        detector = MLAnomalyDetector(self.rows, threshold=0.6)
        real = self.bundles[('xgboost', 'random')][0]
        columns = real['columns']
        domains = {name: [c[len(name)+1:] for c in columns if c.startswith(name+'_')] for name in detector_module.CATEGORICAL}
        fake = SimpleNamespace(classes_=np.array(classes),
            predict_proba=Mock(return_value=np.asarray(probabilities)),
            get_booster=lambda: SimpleNamespace(feature_types=real['model'].get_booster().feature_types))
        return detector, fake, columns, domains

    def test_classifier_uses_positive_class_metadata_instead_of_second_column_assumption(self):
        probabilities = [[0.9, 0.1], [0.2, 0.8]] * 4
        detector, fake, columns, domains = self.fake_classifier(probabilities)
        with patch.object(detector, '_load_bundle', return_value=(fake, columns, domains)):
            result = detector.detect_anomalies()
        self.assertEqual(result.index.tolist(), [0, 2, 4, 6])
        np.testing.assert_allclose(result['ml_score'], 0.9)
        self.assertTrue(result['ml_prediction_label'].eq(1).all())
        self.assertEqual(detector.last_provenance['score_kind'], 'attack_class_probability')
        self.assertEqual(detector.last_provenance['learning_type'], 'supervised_classification')

    def test_invalid_probability_shapes_values_and_class_labels_block_inference(self):
        arrays = [np.zeros((8, 1)), np.ones((8, 2)), np.full((8, 2), np.nan),
                  np.full((8, 2), -0.5), np.full((7, 2), 0.5)]
        for probabilities in arrays:
            detector, fake, columns, domains = self.fake_classifier(probabilities)
            with patch.object(detector, '_load_bundle', return_value=(fake, columns, domains)):
                with self.assertRaises(ModelReliabilityError):
                    detector.detect_anomalies()
        detector, fake, columns, domains = self.fake_classifier([[0.5, 0.5]] * 8, classes=(2, 3))
        with patch.object(detector, '_load_bundle', return_value=(fake, columns, domains)):
            with self.assertRaisesRegex(ModelReliabilityError, 'class labels'):
                detector.detect_anomalies()

    def test_isolation_forest_score_and_decision_label_semantics_are_preserved(self):
        detector, result = self.infer(model='iforest')
        bundle = self.bundles[('iforest', 'random')][0]
        model = bundle['model']
        domains = {name: [c[len(name)+1:] for c in bundle['columns'] if c.startswith(name+'_')] for name in detector_module.CATEGORICAL}
        features = detector._prepare_features(bundle['columns'], domains, model)
        expected = -model.score_samples(features)
        self.assertTrue(result['ml_prediction_label'].eq(-1).all())
        np.testing.assert_allclose(result['ml_score'], expected[result.index])
        self.assertEqual(detector.last_provenance['learning_type'], 'unsupervised_anomaly_detection')
        self.assertIn('Not a probability', detector.last_provenance['score_meaning'])

    def test_generic_detector_is_explicit_excludes_ids_and_targets_and_never_loads_checkpoint(self):
        frame = pd.DataFrame({'measurement': [1.0, 20.0], 'event_id': [4624, 4625],
            'record_id': [10, 11], 'line_no': [2, 3], 'label': [0, 1], 'TimeCreated': [1700000000, 1700000010]})
        fake = Mock()
        fake.fit_predict.return_value = np.array([1, -1])
        fake.score_samples.return_value = np.array([-0.3, -0.8])
        detector = MLAnomalyDetector(frame, model='generic_iforest')
        with patch.object(detector_module, 'IsolationForest', return_value=fake), patch.object(
                detector_module, 'load_trusted_checkpoint') as loaded:
            result = detector.detect_anomalies()
        loaded.assert_not_called()
        self.assertEqual(fake.fit_predict.call_args.args[0].columns.tolist(), ['measurement'])
        self.assertEqual(result.index.tolist(), [1])
        self.assertEqual(detector.last_mode, 'unsupervised_isolation_forest')
        self.assertIsNone(detector.last_provenance['checkpoint_path'])
        self.assertEqual(detector.last_provenance['learning_type'], 'unsupervised_evidence_fit')

    def test_generic_text_measurement_is_named_and_nonfinite_measurements_fail(self):
        fake = Mock(fit_predict=Mock(return_value=np.array([1, -1])),
                    score_samples=Mock(return_value=np.array([-0.3, -0.8])))
        detector = MLAnomalyDetector(pd.DataFrame({'message': ['routine', 'longer event message']}), model='generic_iforest')
        with patch.object(detector_module, 'IsolationForest', return_value=fake):
            detector.detect_anomalies()
        self.assertEqual(fake.fit_predict.call_args.args[0].columns.tolist(), ['log_length'])
        self.assertIn('Text-length', detector.last_provenance['feature_policy'])
        with self.assertRaises(ModelReliabilityError):
            MLAnomalyDetector(pd.DataFrame({'measurement': [1, np.inf]}), model='generic_iforest').detect_anomalies()

    def test_changed_missing_or_external_artifact_is_blocked_before_deserialization(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'models').mkdir()
            with patch.object(store, 'ROOT', root), patch.object(store, '_CheckpointUnpickler') as loader:
                with self.assertRaisesRegex(ModelReliabilityError, 'unavailable'):
                    store.load_trusted_checkpoint('xgboost', 'random')
                (root / 'models/xgboost.joblib').write_bytes(b'corrupted or untrusted checkpoint')
                (root / 'training').mkdir()
                (root / 'training/train_models.py').write_bytes((ROOT / 'training/train_models.py').read_bytes())
                with self.assertRaisesRegex(ModelReliabilityError, 'identity mismatch'):
                    store.load_trusted_checkpoint('xgboost', 'random')
                loader.assert_not_called()
        with self.assertRaises(ModelReliabilityError):
            store.checkpoint_identity('../../external', 'random')

    def test_disallowed_pickle_types_and_missing_embedded_metadata_are_blocked(self):
        data = pickle.dumps(str)  # Harmless reference fixture; never executes a callable.
        with self.assertRaisesRegex(ModelReliabilityError, 'disallowed'):
            store._CheckpointUnpickler('test', BytesIO(data), ensure_native_byte_order=True).load()
        with patch.object(store, '_CheckpointUnpickler') as loader:
            loader.return_value.load.return_value = {'model': object()}
            with self.assertRaisesRegex(ModelReliabilityError, 'metadata'):
                store.load_trusted_checkpoint('xgboost', 'random')

    def test_cache_identity_changes_with_policy_and_refuses_modified_artifact(self):
        signature = MLAnomalyDetector.cache_identity('xgboost', 'random')
        self.assertIn(store.CHECKPOINT_SHA256[('xgboost', 'random')], signature)
        with patch.object(detector_module, 'INFERENCE_VERSION', 999):
            self.assertNotEqual(MLAnomalyDetector.cache_identity('xgboost', 'random'), signature)
        with patch.object(store, 'CHECKPOINT_SHA256', {('xgboost', 'random'): '0' * 64}):
            with self.assertRaises(ModelReliabilityError):
                MLAnomalyDetector.cache_identity('xgboost', 'random')

    def test_report_carries_model_identity_score_meaning_and_correct_evidence_locator(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / 'flows.csv'
            self.rows.to_csv(source, index=False)
            sha = file_sha256(source)
            detector = MLAnomalyDetector(pd.read_csv(source), threshold=0, evidence_sha256=sha)
            with patch.object(detector_module, 'load_trusted_checkpoint', return_value=self.bundles[('xgboost', 'random')]):
                anomalies = detector.detect_anomalies()
            raw = load_log_csv(source)
            findings = ml_to_report_findings(anomalies, raw, detector.last_mode, 'random', source.name, sha)
            self.assertTrue(findings)
            self.assertEqual(findings[0]['checkpoint_sha256'], store.CHECKPOINT_SHA256[('xgboost', 'random')])
            self.assertEqual(findings[0]['learning_type'], 'supervised_classification')
            self.assertEqual(findings[0]['evidence'][0]['sha256'], sha)
            reporter = LocalLLMReporter()
            text = reporter.generate_grounded_report('', '', findings=findings, use_llm=False)
            self.assertTrue(reporter.last_validation['passed'], reporter.last_validation)
            report = dict(case_id='CASE-ML', filename=source.name, sha256=sha,
                source_paths=[str(source)], findings=reporter.last_report_findings, text=text)
            audit = root / 'CASE-ML_audit.log'
            EvidenceIntegrity.log_audit_trail('CASE-ML', 'EVIDENCE_UPLOAD',
                f'File uploaded: {source.name} | SHA256: {sha}', audit_path=audit)
            bind_report_context(report, findings, audit_path=audit)
            self.assertTrue(validate_report_export(report)['passed'])
            markdown = render_forensic_text(report)
            pdf = '\n'.join(p.extract_text() for p in PdfReader(BytesIO(render_forensic_pdf(report))).pages)
            for content in (markdown, pdf):
                self.assertIn('models/xgboost.joblib', content)
                self.assertIn(store.CHECKPOINT_SHA256[('xgboost', 'random')], content)
                self.assertIn('not calibrated confidence', content)
            with self.assertRaisesRegex(ValueError, 'model label'):
                ml_to_report_findings(anomalies, raw, 'trained_iforest', 'random', source.name, sha)
            with self.assertRaisesRegex(ValueError, 'split'):
                ml_to_report_findings(anomalies, raw, detector.last_mode, 'official', source.name, sha)
            unknown = anomalies.copy()
            unknown['ml_model'] = 'trained_unknown'
            with self.assertRaisesRegex(ValueError, 'identity is unknown'):
                ml_to_report_findings(unknown, raw, 'trained_unknown', 'random', source.name, sha)

    def test_dashboard_handles_blocked_inference_and_passes_checkpoint_cache_identity(self):
        text = (ROOT / 'dashboard/app.py').read_text(encoding='utf-8')
        tree = ast.parse(text)
        cached = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'cached_ml')
        self.assertIn('checkpoint_signature', [arg.arg for arg in cached.args.args])
        self.assertIn('MLAnomalyDetector.cache_identity(model_name, model_split)', text)
        self.assertIn('except ModelReliabilityError as exc', text)
        self.assertIn('generic_iforest', text)
        self.assertNotIn('an unsupervised fallback', text.lower())


class TransformerReliabilityTests(unittest.TestCase):
    def setUp(self):
        semantic._cached_model.cache_clear()
        self.addCleanup(semantic._cached_model.cache_clear)

    def test_no_manifest_or_unreviewed_name_never_loads_or_downloads_a_transformer(self):
        with patch.object(semantic, '_SENTENCE_TRANSFORMERS_AVAILABLE', True), patch.object(semantic, 'SentenceTransformer') as constructor:
            for name in ('all-MiniLM-L6-v2', '../external', 'unreviewed/model', 'https://model'):
                matcher = semantic.SemanticMatcher(name)
                matcher.correlate_events(['event'], 'query')
                self.assertEqual(matcher.last_mode, 'lexical_heuristic')
                self.assertTrue(matcher.last_error)
                self.assertIn('heuristic', matcher.last_provenance['score_meaning'])
            constructor.assert_not_called()

    def test_nonfinite_incomplete_and_invalid_cosine_scores_have_explicit_lexical_fallback(self):
        for scores in ([[float('nan'), 0.2]], [[0.2]], [[1.5, 0.2]], [[0.2, 0.3], [0.4, 0.5]]):
            matcher = semantic.SemanticMatcher.__new__(semantic.SemanticMatcher)
            matcher.model_name, matcher.model = 'reviewed-test', Mock()
            matcher.last_error, matcher.last_provenance = None, {'model_id': 'reviewed-test'}
            with patch.object(semantic, 'util') as utility:
                utility.cos_sim.return_value = scores
                result = matcher.correlate_events(['one event', 'two events'], 'event')
            self.assertEqual(len(result), 2)
            self.assertEqual(matcher.last_mode, 'lexical_heuristic')
            self.assertTrue(matcher.last_error)
            self.assertTrue(all(np.isfinite(r['similarity_score']) for r in result))

    def test_reviewed_local_manifest_must_match_every_file_and_use_safe_module_types(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            snapshot = root / 'models/semantic/test-revision'
            snapshot.mkdir(parents=True)
            contents = {'config.json': '{}', 'modules.json': '[{"type":"sentence_transformers.models.Transformer"}]',
                        'vocab.txt': 'token\n', 'model.safetensors': 'not-loaded-test-fixture'}
            for name, value in contents.items():
                (snapshot / name).write_text(value, encoding='utf-8')
            hashes = {name: file_sha256(snapshot / name) for name in contents}
            manifest = {'sentence-transformers/all-MiniLM-L6-v2': dict(relative_path='test-revision', revision='test-revision', files=hashes)}
            with patch.object(semantic, '__file__', str(root / 'modules/semantic_matcher.py')), patch.object(semantic, 'TRUSTED_TRANSFORMERS', manifest):
                path, provenance = semantic._reviewed_transformer_snapshot('all-MiniLM-L6-v2')
                self.assertEqual(path, snapshot)
                self.assertEqual(provenance['file_sha256'], hashes)
                (snapshot / 'config.json').write_text('{"changed":true}', encoding='utf-8')
                with self.assertRaisesRegex(ValueError, 'hash mismatch'):
                    semantic._reviewed_transformer_snapshot('all-MiniLM-L6-v2')
                (snapshot / 'config.json').write_text(contents['config.json'], encoding='utf-8')
                (snapshot / 'modules.json').write_text('[{"type":"sentence_transformers.models.Transformer","path":"../external"}]', encoding='utf-8')
                hashes['modules.json'] = file_sha256(snapshot / 'modules.json')
                with self.assertRaisesRegex(ValueError, 'module path'):
                    semantic._reviewed_transformer_snapshot('all-MiniLM-L6-v2')
