import unittest
from pathlib import Path

import numpy as np
import pandas as pd

from modules.ml_detector import MLAnomalyDetector


ROOT = Path(__file__).resolve().parents[1]
HOLDOUT_PATH = ROOT / "data" / "training" / "holdout_test.csv"


class MLAnomalyDetectorTests(unittest.TestCase):
    def test_saved_models_run_inference_for_both_training_splits(self):
        rows = pd.read_csv(HOLDOUT_PATH, nrows=32)
        for split in ("random", "official"):
            for model in ("xgboost", "iforest"):
                with self.subTest(split=split, model=model):
                    detector = MLAnomalyDetector(rows, model=model, split=split)
                    anomalies = detector.detect_anomalies()

                    self.assertEqual(detector.last_mode, f"trained_{model}")
                    self.assertIn("ml_score", anomalies.columns)
                    self.assertTrue(np.isfinite(anomalies["ml_score"]).all())

    def test_single_text_row_does_not_fit_an_unsupervised_model(self):
        detector = MLAnomalyDetector(pd.DataFrame({"message": ["one event"]}))

        anomalies = detector.detect_anomalies()

        self.assertTrue(anomalies.empty)
        self.assertEqual(detector.last_mode, "insufficient_data")

    def test_empty_input_is_reported_as_insufficient_data(self):
        detector = MLAnomalyDetector(pd.DataFrame(columns=["message"]))

        anomalies = detector.detect_anomalies()

        self.assertTrue(anomalies.empty)
        self.assertEqual(detector.last_mode, "insufficient_data")

    def test_metrics_are_available_for_both_saved_evaluation_splits(self):
        random_metrics = MLAnomalyDetector.load_metrics("random")
        official_metrics = MLAnomalyDetector.load_metrics("official")

        self.assertEqual(set(random_metrics), {"IsolationForest", "XGBoost"})
        self.assertEqual(set(official_metrics), {"IsolationForest", "XGBoost"})
        with self.assertRaises(ValueError):
            MLAnomalyDetector.load_metrics("unknown")


if __name__ == "__main__":
    unittest.main()
