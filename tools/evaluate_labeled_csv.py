"""Evaluate existing checkpoints on an explicitly supplied labeled CSV (no training)."""
import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from modules.csv_evidence import read_evidence_csv, CSV_METADATA
from modules.event_timestamps import select_timestamp_column
from modules.ml_detector import MLAnomalyDetector
from modules.ml_evaluation import evaluate_labeled_csv


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dataset", type=Path)
    parser.add_argument("--split", choices=["random", "official"], default="random")
    options = parser.parse_args()
    frame = read_evidence_csv(options.dataset)
    report = dict(dataset=str(options.dataset), sha256=frame.attrs[CSV_METADATA]["sha256"],
        checkpoint_split=options.split, records=len(frame),
        scope="This labeled file only; a demonstration sample does not establish full-dataset performance.", models={})
    times = select_timestamp_column(frame)
    report["timeline"] = dict(status=times["status"], resolved=sum(v.utc is not None for v in times["values"]))
    report["timeline"]["unresolved"] = len(frame) - report["timeline"]["resolved"]
    for model in ("xgboost", "iforest"):
        detector = MLAnomalyDetector(frame, model=model, split=options.split)
        anomalies = detector.detect_anomalies()
        report["models"][model] = dict(evaluate_labeled_csv(frame, anomalies), provenance=detector.last_provenance)
    print(json.dumps(report, indent=2, default=str))


if __name__ == "__main__":
    main()
