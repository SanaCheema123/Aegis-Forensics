"""Explicit labeled evaluation, separate from inference and its features."""
import pandas as pd
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score

from modules.csv_evidence import CSV_METADATA, source_locator


def evaluate_labeled_csv(frame, anomalies):
    """Align flagged decisions using verified CSV record identities, never scores."""
    if "label" not in frame or frame.empty:
        raise ValueError("Evaluation requires a non-empty explicitly labeled CSV.")
    labels = pd.to_numeric(frame["label"], errors="coerce")
    if labels.isna().any() or not labels.isin([0, 1]).all():
        raise ValueError("Evaluation labels must all be valid binary 0/1 targets.")
    if CSV_METADATA not in frame.attrs or CSV_METADATA not in anomalies.attrs:
        raise ValueError("Verified CSV source identities are required for evaluation.")
    if not frame.index.is_unique or not anomalies.index.is_unique:
        raise ValueError("Ambiguous duplicate source indexes cannot be evaluated.")
    digest = frame.attrs[CSV_METADATA]["sha256"]
    if anomalies.attrs[CSV_METADATA]["sha256"] != digest:
        raise ValueError("Prediction evidence differs from evaluation evidence.")
    def identity(data, index):
        locator = source_locator(data, index, sha256=digest)
        if not locator.get("record_number"):
            raise ValueError("A prediction has no reliable CSV source record.")
        return (digest, locator["record_number"])
    sources = [identity(frame, index) for index in frame.index]
    flagged = {identity(anomalies, index) for index in anomalies.index}
    if len(set(sources)) != len(sources) or not flagged.issubset(set(sources)):
        raise ValueError("Prediction records cannot be aligned with this evaluation dataset.")
    predicted = [int(key in flagged) for key in sources]
    tn, fp, fn, tp = confusion_matrix(labels.astype(int), predicted, labels=[0, 1]).ravel()
    return dict(records=len(frame), flagged=len(flagged), tn=int(tn), fp=int(fp), fn=int(fn), tp=int(tp),
        accuracy=float(accuracy_score(labels, predicted)),
        precision=float(precision_score(labels, predicted, zero_division=0)),
        recall=float(recall_score(labels, predicted, zero_division=0)),
        f1=float(f1_score(labels, predicted, zero_division=0)),
        confusion_matrix=[[int(tn), int(fp)], [int(fn), int(tp)]])
