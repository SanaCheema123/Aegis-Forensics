"""
Train and evaluate Isolation Forest (unsupervised) and XGBoost (supervised)
on UNSW-NB15.

Two evaluation protocols:
  python training/train_models.py --split random    (default)
      Both official CSVs are merged, duplicates removed, then a stratified
      70/30 random split is made. The 30% held-out rows are saved to
      data/training/holdout_test.csv (use this file for dashboard demos).
  python training/train_models.py --split official
      Uses the official training-set / testing-set as they are. This is
      harder because the two files have different attack distributions.
      Results go to reports/official_split/ and models/official/.
"""
import argparse
import json
from pathlib import Path

import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score,
                             precision_score, recall_score, roc_auc_score,
                             roc_curve)
from sklearn.model_selection import train_test_split
from xgboost import XGBClassifier

DATA_DIR = Path("data/training")
TRAIN_CSV = DATA_DIR / "UNSW_NB15_training-set.csv"
TEST_CSV = DATA_DIR / "UNSW_NB15_testing-set.csv"
HOLDOUT_CSV = DATA_DIR / "holdout_test.csv"
CATEGORICAL = ["proto", "service", "state"]
DROP_COLS = ["id", "attack_cat", "label"]
SEED = 42


def get_split(mode):
    train = pd.read_csv(TRAIN_CSV)
    test = pd.read_csv(TEST_CSV)
    if mode == "official":
        return train, test

    full = pd.concat([train, test], ignore_index=True)
    key_cols = [c for c in full.columns if c != "id"]
    before = len(full)
    full = full.drop_duplicates(subset=key_cols).reset_index(drop=True)
    print("Removed duplicate rows:", before - len(full))

    tr, te = train_test_split(full, test_size=0.3, stratify=full["label"],
                              random_state=SEED)
    te.to_csv(HOLDOUT_CSV, index=False)
    print("Held-out test rows saved to", HOLDOUT_CSV)
    return tr.reset_index(drop=True), te.reset_index(drop=True)


def prepare(train, test):
    y_train = train["label"].astype(int)
    y_test = test["label"].astype(int)
    X_train = pd.get_dummies(train.drop(columns=DROP_COLS, errors="ignore"),
                             columns=CATEGORICAL)
    X_test = pd.get_dummies(test.drop(columns=DROP_COLS, errors="ignore"),
                            columns=CATEGORICAL)
    X_test = X_test.reindex(columns=X_train.columns, fill_value=0)
    return X_train, y_train, X_test, y_test


def metrics(y_true, y_pred, y_score):
    return {
        "accuracy": accuracy_score(y_true, y_pred),
        "precision": precision_score(y_true, y_pred, zero_division=0),
        "recall": recall_score(y_true, y_pred, zero_division=0),
        "f1": f1_score(y_true, y_pred, zero_division=0),
        "auc": roc_auc_score(y_true, y_score),
        "confusion_matrix": confusion_matrix(y_true, y_pred).tolist(),
    }


def main(mode):
    if mode == "official":
        model_dir = Path("models/official")
        report_dir = Path("reports/official_split")
    else:
        model_dir = Path("models")
        report_dir = Path("reports")
    model_dir.mkdir(parents=True, exist_ok=True)
    report_dir.mkdir(parents=True, exist_ok=True)

    train, test = get_split(mode)
    X_train, y_train, X_test, y_test = prepare(train, test)
    print("Split mode:", mode)
    print(f"Train: {X_train.shape}, Test: {X_test.shape}")
    print(f"Attack ratio  train={y_train.mean():.2%}  test={y_test.mean():.2%}")

    results, curves = {}, {}

    # 1) Isolation Forest: fit ONLY on normal traffic (label 0)
    iso = IsolationForest(n_estimators=200, contamination=0.1,
                          random_state=SEED, n_jobs=-1)
    iso.fit(X_train[y_train == 0])
    iso_pred = (iso.predict(X_test) == -1).astype(int)
    iso_score = -iso.score_samples(X_test)
    results["IsolationForest"] = metrics(y_test, iso_pred, iso_score)
    curves["IsolationForest"] = roc_curve(y_test, iso_score)
    joblib.dump({"model": iso, "columns": list(X_train.columns)},
                model_dir / "iforest.joblib")

    # 2) XGBoost: supervised, uses labels
    xgb = XGBClassifier(n_estimators=400, max_depth=8, learning_rate=0.1,
                        subsample=0.8, colsample_bytree=0.8,
                        eval_metric="logloss", random_state=SEED, n_jobs=-1)
    xgb.fit(X_train, y_train)
    xgb_prob = xgb.predict_proba(X_test)[:, 1]
    xgb_pred = (xgb_prob >= 0.5).astype(int)
    results["XGBoost"] = metrics(y_test, xgb_pred, xgb_prob)
    curves["XGBoost"] = roc_curve(y_test, xgb_prob)
    joblib.dump({"model": xgb, "columns": list(X_train.columns)},
                model_dir / "xgboost.joblib")

    table = pd.DataFrame({k: {m: v for m, v in r.items() if m != "confusion_matrix"}
                          for k, r in results.items()}).T.round(4)
    print("\n", table)
    table.to_csv(report_dir / "metrics.csv")
    with open(report_dir / "metrics.json", "w") as f:
        json.dump(results, f, indent=2)
    for name, r in results.items():
        cm = r["confusion_matrix"]
        print("")
        print(name, "confusion matrix [[TN, FP], [FN, TP]]:")
        print(cm)

    keys = ["accuracy", "precision", "recall", "f1", "auc"]
    ok = all(results["XGBoost"][k] >= 0.90 for k in keys)
    print("\nXGBoost: all five metrics >= 90%:", ok)

    plt.figure(figsize=(6, 5))
    for name, (fpr, tpr, _) in curves.items():
        plt.plot(fpr, tpr, label=f"{name} (AUC = {results[name]['auc']:.3f})")
    plt.plot([0, 1], [0, 1], "k--", label="Random guess")
    plt.xlabel("False positive rate")
    plt.ylabel("True positive rate")
    plt.title(f"ROC curve (UNSW-NB15, {mode} split)")
    plt.legend(loc="lower right")
    plt.tight_layout()
    plt.savefig(report_dir / "roc_curve.png", dpi=150)

    imp = pd.Series(xgb.feature_importances_, index=X_train.columns)
    imp.sort_values(ascending=False).head(15).to_csv(report_dir / "top_features.csv")
    print("\nSaved models to", model_dir, "and reports to", report_dir)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--split", choices=["random", "official"], default="random")
    args = parser.parse_args()
    main(args.split)