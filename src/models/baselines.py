"""
Baseline comparison: train multiple classifiers on the same train+val data,
evaluate on test set, and print a comparison table.

Models:
  LR   - Logistic Regression (linear, fast, interpretable)
  DT   - Decision Tree (rule-based, explainable, prone to overfit)
  SVM  - Support Vector Machine (kernel-based, strong on small/medium data)
  XGB  - XGBoost (gradient-boosted trees, strong baseline for tabular data)
  ISO  - Isolation Forest (unsupervised anomaly detection, no label supervision)
  RF   - Random Forest (proposed method, loaded from saved artifact)
"""

from pathlib import Path

import click
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import f1_score, precision_score, recall_score, roc_auc_score
from sklearn.svm import SVC
from sklearn.tree import DecisionTreeClassifier
from xgboost import XGBClassifier

FEATURE_COLS_EXCLUDE = {"session_id", "label"}


def _load(path: Path, feat_cols: list[str]) -> tuple[np.ndarray, np.ndarray]:
    df = pd.read_csv(path)
    available = [c for c in feat_cols if c in df.columns]
    X = df[available].fillna(0).values.astype(np.float32)
    y = df["label"].values.astype(int)
    return X, y


def run_baselines(model_path: str, data_dir: str, output_path: str | None = None):
    artifact = joblib.load(model_path)
    best_params = artifact["model"].get_params()
    feat_cols = artifact["feature_cols"]

    data = Path(data_dir)
    X_train, y_train = _load(data / "train_features.csv", feat_cols)
    X_val, y_val = _load(data / "val_features.csv", feat_cols)
    X_test, y_test = _load(data / "test_features.csv", feat_cols)

    X_tv = np.vstack([X_train, X_val])
    y_tv = np.concatenate([y_train, y_val])

    scale_pos = int((y_tv == 0).sum()) / max(int((y_tv == 1).sum()), 1)

    classifiers = {
        "LR": LogisticRegression(class_weight="balanced", max_iter=1000, random_state=42),
        "DT": DecisionTreeClassifier(class_weight="balanced", max_depth=10, random_state=42),
        "SVM": SVC(class_weight="balanced", kernel="rbf", probability=True, random_state=42),
        "XGB": XGBClassifier(
            n_estimators=100,
            max_depth=6,
            scale_pos_weight=scale_pos,
            eval_metric="logloss",
            random_state=42,
            verbosity=0,
        ),
        "RF (proposed)": RandomForestClassifier(**best_params),
    }

    results = []
    print(f"\n{'Model':<16} {'Precision':>10} {'Recall':>8} {'F1-macro':>10} {'ROC-AUC':>9}")
    print("-" * 57)

    for name, clf in classifiers.items():
        clf.fit(X_tv, y_tv)
        y_pred = clf.predict(X_test)
        if hasattr(clf, "predict_proba"):
            y_prob = clf.predict_proba(X_test)[:, 1]
        else:
            y_prob = clf.decision_function(X_test)
        prec = precision_score(y_test, y_pred, average="macro", zero_division=0)
        rec = recall_score(y_test, y_pred, average="macro", zero_division=0)
        f1 = f1_score(y_test, y_pred, average="macro", zero_division=0)
        auc = roc_auc_score(y_test, y_prob)
        results.append(
            {"model": name, "precision": prec, "recall": rec, "f1_macro": f1, "roc_auc": auc}
        )
        marker = " <--" if name == "RF (proposed)" else ""
        print(f"{name:<16} {prec:>10.4f} {rec:>8.4f} {f1:>10.4f} {auc:>9.4f}{marker}")

    # Isolation Forest (unsupervised — binary prediction via contamination ratio)
    contam = float((y_tv == 1).sum()) / len(y_tv)
    iso = IsolationForest(contamination=contam, random_state=42, n_jobs=-1)
    iso.fit(X_tv)
    # IsolationForest: -1=anomaly → 1 (malicious), 1=normal → 0 (benign)
    y_pred_iso = (iso.predict(X_test) == -1).astype(int)
    y_score_iso = -iso.score_samples(X_test)  # higher = more anomalous
    prec_iso = precision_score(y_test, y_pred_iso, average="macro", zero_division=0)
    rec_iso = recall_score(y_test, y_pred_iso, average="macro", zero_division=0)
    f1_iso = f1_score(y_test, y_pred_iso, average="macro", zero_division=0)
    auc_iso = roc_auc_score(y_test, y_score_iso)
    results.append(
        {
            "model": "IF (unsupervised)",
            "precision": prec_iso,
            "recall": rec_iso,
            "f1_macro": f1_iso,
            "roc_auc": auc_iso,
        }
    )
    print(
        f"{'IF (unsupervised)':<16} {prec_iso:>10.4f} {rec_iso:>8.4f}"
        f" {f1_iso:>10.4f} {auc_iso:>9.4f}"
    )
    print("-" * 57)

    df_out = pd.DataFrame(results)
    if output_path:
        df_out.to_csv(output_path, index=False)
        print(f"\nResults saved -> {output_path}")

    return df_out


@click.command()
@click.option("--model", "model_path", required=True)
@click.option("--data", "data_dir", required=True)
@click.option("--output", "output_path", default=None)
def main(model_path, data_dir, output_path):
    run_baselines(model_path, data_dir, output_path)


if __name__ == "__main__":
    main()
