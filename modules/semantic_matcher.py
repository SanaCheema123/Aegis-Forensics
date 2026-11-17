import re
import hashlib
import json
import math
from importlib.util import find_spec
from pathlib import Path
from difflib import SequenceMatcher
from functools import lru_cache
from threading import RLock

SentenceTransformer = None
util = None
try:
    # Discover availability without importing torch/transformers or their optional
    # vision dependencies. No embedding dependency is needed for lexical search.
    _SENTENCE_TRANSFORMERS_AVAILABLE = find_spec('sentence_transformers') is not None
    _SENTENCE_TRANSFORMERS_IMPORT_ERROR = None
except Exception as exc:
    SentenceTransformer = None
    util = None
    _SENTENCE_TRANSFORMERS_AVAILABLE = False
    _SENTENCE_TRANSFORMERS_IMPORT_ERROR = f"{type(exc).__name__}: {exc}"


_MODEL_LOCK = RLock()


# No checkpoint or revision is invented. A reviewed local safetensors manifest
# is required before enabling embeddings; none is available in this project.
TRUSTED_TRANSFORMERS = {}
_TRANSFORMER_ID = 'sentence-transformers/all-MiniLM-L6-v2'


def _reviewed_transformer_snapshot(model_name):
    canonical = _TRANSFORMER_ID if model_name == 'all-MiniLM-L6-v2' else model_name
    if canonical != _TRANSFORMER_ID:
        raise ValueError('Transformer model is not on the reviewed model allowlist.')
    metadata = TRUSTED_TRANSFORMERS.get(canonical)
    if not metadata:
        raise ValueError('No reviewed local Sentence Transformer checkpoint metadata is available. Supply a trusted revision and safetensors/config/tokenizer hashes; no download was attempted.')
    root = Path(__file__).resolve().parents[1] / 'models' / 'semantic'
    relative = Path(metadata['relative_path'])
    if relative.is_absolute() or '..' in relative.parts:
        raise ValueError('Invalid reviewed transformer location.')
    snapshot = root / relative
    if snapshot.resolve() != snapshot.absolute() or not snapshot.is_dir():
        raise ValueError('Reviewed transformer snapshot is missing or redirected.')
    files = metadata.get('files', {})
    if not metadata.get('revision') or 'modules.json' not in files or 'config.json' not in files or not any(name.endswith('.safetensors') for name in files) or not ({'tokenizer.json', 'vocab.txt'} & set(files)):
        raise ValueError('Reviewed transformer metadata is incomplete.')
    # No undeclared files can influence local loading, including tokenizer/config files.
    actual = {path.relative_to(snapshot).as_posix() for path in snapshot.rglob('*') if path.is_file()}
    if actual != set(files):
        raise ValueError('Transformer snapshot differs from its reviewed file manifest.')
    for name, digest in files.items():
        path = snapshot / name
        if path.resolve() != path.absolute() or path.suffix in {'.py', '.bin', '.pt', '.pth', '.pkl', '.pickle', '.joblib'}:
            raise ValueError('Transformer snapshot contains redirected or executable/pickle artifacts.')
        hashed = hashlib.sha256()
        with path.open('rb') as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                hashed.update(chunk)
        if hashed.hexdigest() != digest:
            raise ValueError('Transformer checkpoint file hash mismatch.')
    modules = json.loads((snapshot / 'modules.json').read_text(encoding='utf-8'))
    approved = {'sentence_transformers.models.Transformer', 'sentence_transformers.models.Pooling', 'sentence_transformers.models.Normalize'}
    if not isinstance(modules, list) or not modules or any(not isinstance(item, dict) or item.get('type') not in approved for item in modules):
        raise ValueError('Transformer uses unreviewed module implementations.')
    for item in modules:
        module_path = Path(item.get('path', ''))
        if module_path.is_absolute() or '..' in module_path.parts or (snapshot / module_path).resolve() != (snapshot / module_path).absolute():
            raise ValueError('Transformer module path leaves the reviewed snapshot.')
    return snapshot, dict(model_id=canonical, revision=metadata['revision'], file_sha256=dict(files),
                          checkpoint_path=str(snapshot), artifact_format='safetensors')


@lru_cache(maxsize=2)
def _cached_model(model_name):
    snapshot, provenance = _reviewed_transformer_snapshot(model_name)
    # Verify the local allowlist and all artifact hashes before importing or
    # constructing an optional embedding model. Never download missing artifacts.
    global SentenceTransformer, util
    if SentenceTransformer is None:
        from sentence_transformers import SentenceTransformer as constructor, util as utility
        SentenceTransformer, util = constructor, utility
    model = SentenceTransformer(str(snapshot), local_files_only=True, trust_remote_code=False,
                                model_kwargs={'use_safetensors': True})
    return model, provenance


class SemanticMatcher:
    def __init__(self, model_name: str = 'all-MiniLM-L6-v2'):
        self.model_name = model_name
        self.model = None
        self.last_mode = "lexical_heuristic"
        self.last_error = None
        self.last_provenance = dict(requested_model=model_name, mode="lexical_heuristic",
            score_meaning="Token overlap / text sequence heuristic; not embedding similarity or probability.")

        if _SENTENCE_TRANSFORMERS_AVAILABLE:
            try:
                with _MODEL_LOCK:
                    self.model, provenance = _cached_model(_TRANSFORMER_ID if model_name == 'all-MiniLM-L6-v2' else model_name)
                    self.last_provenance = dict(provenance, mode="sentence_transformers", score_meaning="Cosine similarity; not a probability or malware confidence.")
                self.last_mode = "sentence_transformers"
            except Exception as exc:
                self.last_error = f"{type(exc).__name__}: {exc}"
                self.model = None
        else:
            self.last_error = (
                _SENTENCE_TRANSFORMERS_IMPORT_ERROR
                or "The sentence-transformers package is not installed."
            )

    @staticmethod
    def _normalize_text(value: str) -> str:
        return re.sub(r'\s+', ' ', str(value).lower()).strip()

    def _fallback_similarity(self, event_descriptions: list, query_indicator: str) -> list:
        query = self._normalize_text(query_indicator)
        query_tokens = set(re.findall(r"[a-z0-9]+", query))

        results = []
        for position, event in enumerate(event_descriptions):
            text = self._normalize_text(event)
            text_tokens = set(re.findall(r"[a-z0-9]+", text))
            overlap = len(query_tokens & text_tokens)
            token_score = overlap / max(len(query_tokens | text_tokens), 1)
            sequence_score = SequenceMatcher(None, query, text).ratio()
            score = max(token_score, sequence_score * 0.5)
            results.append({
                "event": event,
                "record_position": position,
                "similarity_score": float(score)
            })

        return sorted(results, key=lambda x: x['similarity_score'], reverse=True)

    def correlate_events(self, event_descriptions: list, query_indicator: str) -> list:
        """Finds semantic matches between log text and a suspicious query/indicator."""
        if not event_descriptions:
            self.last_mode = "no_input"
            return []

        if self.model is not None and util is not None:
            try:
                with _MODEL_LOCK:
                    event_embeddings = self.model.encode(event_descriptions, convert_to_tensor=True)
                    query_embedding = self.model.encode(query_indicator, convert_to_tensor=True)
                matrix = util.cos_sim(query_embedding, event_embeddings)
                if len(matrix) != 1:
                    raise ValueError('Transformer returned an invalid query dimension.')
                cos_scores = matrix[0]

                scores = [float(score) for score in cos_scores]
                if len(scores) != len(event_descriptions) or any(not math.isfinite(score) or not -1.000001 <= score <= 1.000001 for score in scores):
                    raise ValueError('Transformer returned incomplete, non-finite or invalid cosine similarities.')
                results = []
                for idx, score in enumerate(scores):
                    results.append({
                        "event": event_descriptions[idx],
                        "record_position": idx,
                        "similarity_score": min(1.0, max(-1.0, score))
                    })

                self.last_mode = "sentence_transformers"
                self.last_error = None
                return sorted(results, key=lambda x: x['similarity_score'], reverse=True)
            except Exception as exc:
                self.last_error = f"{type(exc).__name__}: {exc}"
                self.model = None

        attempted = dict(self.last_provenance)
        self.last_mode = "lexical_heuristic"
        self.last_provenance = dict(mode="lexical_heuristic", requested_model=self.model_name,
            score_meaning="Token overlap / text sequence heuristic; not embedding similarity or probability.",
            attempted_transformer=attempted, fallback_reason=self.last_error)
        return self._fallback_similarity(event_descriptions, query_indicator)
