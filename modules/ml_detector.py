"""Explicit, schema-checked ML inference with source/checkpoint provenance."""
import hashlib
import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from xgboost import XGBClassifier

from modules.model_store import ModelReliabilityError, load_trusted_checkpoint, checkpoint_identity
from modules.event_timestamps import identifier_field, field_key, timestamp_candidates

MODEL_DIR = Path(__file__).resolve().parent.parent / 'models'
CATEGORICAL = ['proto', 'service', 'state']
DROP_COLS = ['id', 'attack_cat', 'label']
INFERENCE_VERSION = 2


class MLAnomalyDetector:
    """Run exactly the selected model; generic evidence fitting is an explicit mode."""
    def __init__(self, df, model='xgboost', threshold=0.5, split='random', evidence_sha256=None):
        if model not in {'xgboost', 'iforest', 'generic_iforest'}:
            raise ModelReliabilityError('Select xgboost, iforest, or generic_iforest explicitly. No fallback is permitted.')
        if split not in {'random', 'official'}:
            raise ModelReliabilityError('Model split must be random or official.')
        if isinstance(threshold, bool) or not isinstance(threshold, (int, float)) or not np.isfinite(threshold) or not 0 <= threshold <= 1:
            raise ModelReliabilityError('Classification threshold must be finite and between 0 and 1.')
        if not isinstance(df, pd.DataFrame) or not df.columns.is_unique or not df.index.is_unique:
            raise ModelReliabilityError('Inference requires a DataFrame with unique column and source-record identities.')
        if not all(isinstance(c, str) for c in df.columns):
            raise ModelReliabilityError('Inference feature names must be strings.')
        if any(name.startswith('ml_') or name == 'anomaly_score' for name in df.columns):
            raise ModelReliabilityError('Input contains reserved inference-output fields; predictions cannot be used as raw features.')
        self.df, self.model_name, self.threshold, self.split = df, model, float(threshold), split
        self.last_mode = None
        self.last_error = None
        self.last_provenance = dict(inference_version=INFERENCE_VERSION, requested_model=model, requested_split=split, input_evidence_sha256=evidence_sha256)

    @staticmethod
    def cache_identity(model, split):
        if model == 'generic_iforest':
            return (INFERENCE_VERSION, 'explicit-evidence-fit', hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
        _, provenance = checkpoint_identity(model, split)
        return (INFERENCE_VERSION, provenance['checkpoint_sha256'], provenance['training_source_sha256'],
                hashlib.sha256(Path(__file__).read_bytes()).hexdigest())

    def _load_bundle(self):
        bundle, provenance = load_trusted_checkpoint(self.model_name, self.split)
        model, columns = bundle['model'], bundle['columns']
        expected_type = XGBClassifier if self.model_name == 'xgboost' else IsolationForest
        if type(model) is not expected_type:
            raise ModelReliabilityError('Selected checkpoint contains a different estimator type; no inference was run.')
        if not isinstance(columns, list) or not columns or not all(isinstance(c, str) for c in columns) or len(set(columns)) != len(columns):
            raise ModelReliabilityError('Embedded training feature names are missing, duplicated or invalid. Supply verified metadata.')
        fitted = getattr(model, 'feature_names_in_', None)
        if fitted is None or list(fitted) != columns or model.n_features_in_ != len(columns):
            raise ModelReliabilityError('Bundle schema disagrees with fitted estimator metadata. Inference is blocked.')
        if self.model_name == 'xgboost' and list(model.get_booster().feature_names or []) != columns:
            raise ModelReliabilityError('XGBoost booster feature order disagrees with the checkpoint schema.')
        domains = {c: [name[len(c) + 1:] for name in columns if name.startswith(c + '_')] for c in CATEGORICAL}
        if any(not domain or len(set(domain)) != len(domain) for domain in domains.values()):
            raise ModelReliabilityError('Categorical training metadata is unavailable or ambiguous; no domain was invented.')
        provenance['feature_schema_sha256'] = hashlib.sha256(json.dumps(columns, separators=(',', ':')).encode()).hexdigest()
        provenance['feature_count'] = len(columns)
        provenance['schema_source'] = 'Embedded columns cross-checked against fitted estimator feature_names_in_; preprocessing matches reviewed training source.'
        provenance['metadata_limitations'] = 'Training dataset hashes, units, ranges, calibration and a complete raw-dtype/missing-value manifest were not recorded. No missing-value policy is inferred.'
        self.last_provenance.update(provenance)
        return model, columns, domains

    @staticmethod
    def _base_columns(columns):
        return [c for c in columns if not any(c.startswith(name + '_') for name in CATEGORICAL)]

    def is_flow_data(self, columns):
        required = set(self._base_columns(columns)) | set(CATEGORICAL)
        return required <= set(self.df.columns)

    @staticmethod
    def _numeric(series, name):
        if pd.api.types.is_datetime64_any_dtype(series) or pd.api.types.is_timedelta64_dtype(series) or pd.api.types.is_complex_dtype(series):
            raise ModelReliabilityError(f'Numeric feature {name} contains datetime or complex values.')
        try:
            converted = pd.to_numeric(series, errors='raise')
            if pd.api.types.is_complex_dtype(converted):
                raise ModelReliabilityError(f'Feature {name} contains complex values; imaginary components cannot be discarded.')
            values = converted.to_numpy(dtype=np.float64, na_value=np.nan)
        except (ValueError, TypeError, OverflowError) as exc:
            raise ModelReliabilityError(f'Feature {name} must contain finite numeric values; invalid data was not replaced by zero.') from exc
        if not np.isfinite(values).all() or (np.abs(values) > np.finfo(np.float32).max).any():
            raise ModelReliabilityError(f'Feature {name} has missing, infinite or out-of-range values; no imputation policy is recorded.')
        return converted

    def _prepare_features(self, columns, domains, model):
        numeric = self._base_columns(columns)
        required = set(numeric) | set(CATEGORICAL)
        missing = sorted(required - set(self.df.columns))
        unexpected = sorted(set(self.df.columns) - required - set(DROP_COLS))
        if missing or unexpected:
            raise ModelReliabilityError(f'Input feature schema is incompatible. Missing: {missing}; unexpected: {unexpected}. Selected model was not replaced.')
        raw = self.df[list(numeric) + CATEGORICAL].copy()
        native_types = dict(zip(columns, model.get_booster().feature_types or [])) if self.model_name == 'xgboost' else {}
        for name in numeric:
            raw[name] = self._numeric(raw[name], name)
            if native_types.get(name) == 'int':
                values = raw[name].to_numpy(dtype=np.float64)
                if not np.equal(values, np.floor(values)).all():
                    raise ModelReliabilityError(f'Feature {name} was trained as integer-valued; fractional input is incompatible.')
        for name, domain in domains.items():
            if raw[name].isna().any() or not raw[name].map(lambda value: isinstance(value, str)).all():
                raise ModelReliabilityError(f'Categorical feature {name} requires non-missing category strings.')
            unknown = sorted(set(raw[name]) - set(domain))
            if unknown:
                raise ModelReliabilityError(f'Categorical feature {name} contains untrained categories: {unknown[:10]}. Values were not silently dropped.')
        encoded = pd.get_dummies(raw, columns=CATEGORICAL)
        # Zeroes here represent known categories absent from this batch, never
        # missing raw features or unseen categories (both were rejected above).
        encoded = encoded.reindex(columns=columns, fill_value=0)
        return encoded

    def _output(self, scores, labels, flagged, mode, provenance):
        scores, labels, flagged = np.asarray(scores), np.asarray(labels), np.asarray(flagged)
        if scores.shape != (len(self.df),) or labels.shape != scores.shape or flagged.shape != scores.shape or not np.isfinite(scores).all():
            raise ModelReliabilityError('Estimator output is incomplete, non-finite or has an invalid shape.')
        self.last_mode = mode
        self.last_provenance.update(provenance, mode=mode,
            anomaly_score_meaning='Legacy decision code: -1 = flagged for review; +1 = not flagged. Not a continuous score.',
            input_feature_schema_version=INFERENCE_VERSION)
        result = self.df.copy()
        result['ml_score'] = scores
        result['ml_model'] = mode
        result['ml_prediction_label'] = labels
        result['anomaly_score'] = np.where(flagged, -1, 1)
        result['ml_provenance'] = [dict(self.last_provenance) for _ in range(len(result))]
        result.attrs['ml_provenance'] = dict(self.last_provenance)
        return result.loc[flagged].sort_values('ml_score', ascending=False, kind='stable')

    def _detect_with_trained_model(self):
        model, columns, domains = self._load_bundle()
        features = self._prepare_features(columns, domains, model)
        self.last_provenance['feature_matrix_sha256'] = hashlib.sha256(pd.util.hash_pandas_object(features, index=True).to_numpy().tobytes()).hexdigest()
        provenance = dict(checkpoint_split=self.split, estimator_class=f'{type(model).__module__}.{type(model).__name__}')
        if self.model_name == 'xgboost':
            classes = np.asarray(model.classes_)
            if classes.shape != (2,) or set(classes.tolist()) != {0, 1}:
                raise ModelReliabilityError('Classifier class labels do not match the reviewed normal=0, attack=1 training task.')
            probabilities = np.asarray(model.predict_proba(features))
            if probabilities.shape != (len(features), 2) or not np.isfinite(probabilities).all() or (probabilities < 0).any() or (probabilities > 1).any() or not np.allclose(probabilities.sum(axis=1), 1, atol=1e-6):
                raise ModelReliabilityError('Classifier returned invalid probability values or class dimensions.')
            scores = probabilities[:, int(np.flatnonzero(classes == 1)[0])]
            flagged = scores >= self.threshold
            labels = flagged.astype(int)
            provenance.update(learning_type='supervised_classification', score_kind='attack_class_probability',
                score_meaning='Estimated P(label=1), not calibrated confidence or proof of compromise.',
                positive_class=1, class_mapping={'0': 'normal', '1': 'attack'}, threshold=self.threshold)
        else:
            scores, labels = -np.asarray(model.score_samples(features)), np.asarray(model.predict(features))
            if not np.isin(labels, [-1, 1]).all():
                raise ModelReliabilityError('Isolation Forest returned invalid decision labels.')
            flagged = labels == -1
            provenance.update(learning_type='unsupervised_anomaly_detection', score_kind='negative_score_samples',
                score_meaning='Negative Isolation Forest score_samples; higher = more anomalous. Not a probability.',
                learned_decision_offset=float(model.offset_), contamination=model.contamination,
                class_mapping={'-1': 'outlier', '1': 'inlier'}, threshold=None)
        return self._output(scores, labels, flagged, f'trained_{self.model_name}', provenance)

    def _detect_unsupervised(self):
        excluded = set(DROP_COLS) | set(timestamp_candidates(self.df.columns)) | {'line_no', 'line_end', 'record_number'}
        columns = sorted(c for c in self.df.select_dtypes(include=[np.number]).columns
            if c not in excluded and not identifier_field(c) and not field_key(c).startswith(('timestamp', 'aegis', 'source')))
        if columns:
            features = pd.DataFrame({name: self._numeric(self.df[name], name) for name in columns}, index=self.df.index)
            policy = 'Finite numeric measurements; identifiers, targets and source locator metadata excluded.'
        else:
            text = [c for c in self.df if field_key(c) in {'message', 'description', 'rawlog', 'details', 'eventdetails', 'text'}]
            if not text:
                raise ModelReliabilityError('Generic anomaly detection has no numeric measurements or supported event text fields.')
            for name in text:
                if not self.df[name].dropna().map(lambda v: isinstance(v, str)).all():
                    raise ModelReliabilityError('Generic event-text measurements require strings.')
            features = pd.DataFrame({'log_length': self.df[text].fillna('').agg(' '.join, axis=1).str.len()}, index=self.df.index)
            if features['log_length'].eq(0).all():
                raise ModelReliabilityError('Generic anomaly detection has no usable event text.')
            policy = 'Text-length measurement only; no pretrained network-traffic classifier or semantic meaning.'
        self.last_provenance['feature_matrix_sha256'] = hashlib.sha256(pd.util.hash_pandas_object(features, index=True).to_numpy().tobytes()).hexdigest()
        model = IsolationForest(contamination=0.05, random_state=42)
        labels = np.asarray(model.fit_predict(features))
        if not np.isin(labels, [-1, 1]).all():
            raise ModelReliabilityError('Generic Isolation Forest returned invalid labels.')
        return self._output(-np.asarray(model.score_samples(features)), labels, labels == -1,
            'unsupervised_isolation_forest', dict(learning_type='unsupervised_evidence_fit',
                estimator_class='sklearn.ensemble.IsolationForest', checkpoint_path=None, checkpoint_sha256=None,
                checkpoint_split=None, score_kind='negative_score_samples',
                score_meaning='Higher negative score_samples = more anomalous; not a probability.',
                feature_names=list(features.columns), feature_policy=policy,
                fit_scope='Fitted only to this evidence for this analysis; no checkpoint was trained or modified.',
                class_mapping={'-1': 'outlier', '1': 'inlier'}, threshold=None))

    def detect_anomalies(self):
        if len(self.df) < 2:
            self.last_mode = 'insufficient_data'
            result = self.df.iloc[0:0].copy()
            for name in ('anomaly_score', 'ml_score', 'ml_model'):
                result[name] = pd.Series(index=result.index, dtype=object)
            result.attrs['ml_provenance'] = dict(self.last_provenance, status='not_run_insufficient_data')
            return result
        try:
            return self._detect_unsupervised() if self.model_name == 'generic_iforest' else self._detect_with_trained_model()
        except Exception as exc:
            self.last_mode, self.last_error = 'blocked', str(exc)
            if isinstance(exc, ModelReliabilityError):
                raise
            raise ModelReliabilityError(f'Selected model inference failed: {type(exc).__name__}: {exc}. No fallback was run.') from exc

    @staticmethod
    def load_metrics(split='random'):
        if split not in {'random', 'official'}:
            raise ValueError('Metric split must be random or official.')
        report_dir = MODEL_DIR.parent / 'reports'
        if split == 'official':
            report_dir /= 'official_split'
        path = report_dir / 'metrics.json'
        return json.loads(path.read_text(encoding='utf-8')) if path.exists() else {}
