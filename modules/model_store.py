"""Local checkpoint identity pins and restricted deserialization.

Pins freeze the project artifacts inspected in this audit. They are a local review
baseline, not proof of original training provenance or an external signature.
Unknown, changed, linked or externally supplied artifacts are never deserialized.
"""
import hashlib
from io import BytesIO
from pathlib import Path
import pickle
import warnings
from importlib.metadata import version
from sklearn.exceptions import InconsistentVersionWarning

from joblib.numpy_pickle import NumpyArrayWrapper, NumpyUnpickler

ROOT = Path(__file__).resolve().parents[1]
MODEL_DIR = ROOT / 'models'
TRAINING_SOURCE_SHA256 = '61905c25687700650a83c685fc5a4208ddb24cdc57959f083b83394344c2074c'
CHECKPOINT_SHA256 = {
    ('xgboost', 'random'): '443cef66999144faabde2561a78830f6dfc6ee476906697e27f88e844349085f',
    ('iforest', 'random'): '30cb17b9c7a5d968d15f797b35244f911381325267c391de2bc8d1e2836d1464',
    ('xgboost', 'official'): '617e5bb07480f956f4b23d6cdc64d31c530e740085eb2cc191844431044c26ca',
    ('iforest', 'official'): 'eda4915225ecc12e874792509643df45b3cb4307c851ce781ed2411465bad8e8',
}
MAX_CHECKPOINT_BYTES = 16 * 1024 * 1024


class ModelReliabilityError(ValueError):
    """Inference is unavailable; do not replace it with another model."""


class _SafeArrayWrapper(NumpyArrayWrapper):
    def read_array(self, unpickler, ensure_native_byte_order=True):
        if self.dtype.hasobject:
            nested = pickle._Unpickler(unpickler.file_handle)
            nested.find_class = unpickler.find_class
            return nested.load()
        return super().read_array(unpickler, ensure_native_byte_order)


class _CheckpointUnpickler(NumpyUnpickler):
    def find_class(self, module, name):
        if (module, name) == ('joblib.numpy_pickle', 'NumpyArrayWrapper'):
            return _SafeArrayWrapper
        allowed = {
            ('builtins', 'bytearray'),
            ('xgboost.sklearn', 'XGBClassifier'), ('xgboost.core', 'Booster'),
            ('sklearn.ensemble._iforest', 'IsolationForest'),
            ('sklearn.tree._classes', 'ExtraTreeRegressor'), ('sklearn.tree._tree', 'Tree'),
            ('numpy', 'ndarray'), ('numpy', 'dtype'),
            ('numpy._core.multiarray', '_reconstruct'), ('numpy._core.multiarray', 'scalar'),
            ('numpy.core.multiarray', '_reconstruct'), ('numpy.core.multiarray', 'scalar'),
        }
        if (module, name) not in allowed:
            raise ModelReliabilityError(f'Checkpoint contains a disallowed serialized type: {module}.{name}.')
        return super().find_class(module, name)


def checkpoint_identity(model, split):
    if (model, split) not in CHECKPOINT_SHA256:
        raise ModelReliabilityError('No reviewed checkpoint identity exists for this model and split.')
    relative = Path('models') / ('official' if split == 'official' else '') / f'{model}.joblib'
    path = ROOT / relative
    # Reject symlink/junction redirection, including redirection of model directories.
    if path.resolve() != path.absolute() or path.is_symlink():
        raise ModelReliabilityError('Checkpoint path is redirected; only the reviewed project artifact may be loaded.')
    if not path.is_file():
        raise ModelReliabilityError(f'Selected checkpoint is unavailable: {relative.as_posix()}. No fallback was run.')
    if path.stat().st_size > MAX_CHECKPOINT_BYTES:
        raise ModelReliabilityError('Checkpoint exceeds the reviewed artifact size limit.')
    try:
        data = path.read_bytes()
        source_digest = hashlib.sha256((ROOT / 'training/train_models.py').read_bytes()).hexdigest()
    except OSError as exc:
        raise ModelReliabilityError(f'Checkpoint or reviewed preprocessing source is unavailable: {exc}') from exc
    digest = hashlib.sha256(data).hexdigest()
    if digest != CHECKPOINT_SHA256[(model, split)]:
        raise ModelReliabilityError(f'Checkpoint identity mismatch: {relative.as_posix()}. Artifact was not loaded.')
    if source_digest != TRAINING_SOURCE_SHA256:
        raise ModelReliabilityError('Reviewed preprocessing source changed. Training schema must be reviewed before inference.')
    return data, dict(checkpoint_path=relative.as_posix(), checkpoint_sha256=digest,
        training_source_sha256=TRAINING_SOURCE_SHA256,
        provenance_status='Local audit baseline; original training provenance is not independently authenticated.',
        training_dataset_identity='Not recorded in the checkpoint; current dataset files are not proof of training inputs.')


def load_trusted_checkpoint(model, split):
    data, provenance = checkpoint_identity(model, split)
    try:
        # Consume precisely the verified bytes, avoiding a hash/load path race.
        with warnings.catch_warnings():
            warnings.simplefilter('error', InconsistentVersionWarning)
            bundle = _CheckpointUnpickler(provenance['checkpoint_path'], BytesIO(data),
                ensure_native_byte_order=True, mmap_mode=None).load()
    except Exception as exc:
        raise ModelReliabilityError(f'Selected checkpoint cannot be safely loaded: {type(exc).__name__}: {exc}') from exc
    if not isinstance(bundle, dict) or not {'model', 'columns'} <= bundle.keys():
        raise ModelReliabilityError('Checkpoint has no supported embedded feature metadata; inference is blocked.')
    provenance["inference_runtime_versions"] = {name: version(name) for name in ("xgboost", "scikit-learn", "numpy", "pandas", "joblib")}
    return bundle, provenance
