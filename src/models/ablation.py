"""
Ablation study: remove one feature group at a time, retrain RF, report macro F1.
Uses the best hyperparams from the full-feature search (loaded from saved model)
to isolate the effect of each removed group.
"""

from pathlib import Path

import click
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import f1_score

FEATURE_GROUPS = {
    "Group1_EventCounts": [
        "count_4624",
        "count_4625",
        "count_4634",
        "count_4648",
        "count_4672",
        "count_4688",
        "count_4689",
        "count_4720",
        "count_4732",
        "count_7045",
        "count_7036",
        "count_4663",
        "count_4656",
        "count_total",
    ],
    "Group2_TimeDelta": ["td_mean", "td_std", "td_min", "td_max"],
    "Group3_Cardinality": ["n_unique_sources", "n_unique_users", "n_unique_hosts"],
    "Group4_RareFlags": [],  # populated dynamically from flag_* columns
    "Group5_Entropy": ["seq_entropy"],
}

EXCLUDE = {"session_id", "label"}


def _load(path: Path, feat_cols: list[str]) -> tuple[np.ndarray, np.ndarray]:
    df = pd.read_csv(path)
    flag_cols = [c for c in df.columns if c.startswith("flag_")]
    FEATURE_GROUPS["Group4_RareFlags"] = flag_cols

    available = [c for c in feat_cols if c in df.columns]
    X = df[available].fillna(0).values.astype(np.float32)
    y = df["label"].values.astype(int)
    return X, y, available


def run_ablation(model_path: str, data_dir: str, output_path: str | None = None):
    artifact = joblib.load(model_path)
    best_params = artifact["model"].get_params()
    feat_cols = artifact["feature_cols"]

    data = Path(data_dir)
    X_train, y_train, train_cols = _load(data / "train_features.csv", feat_cols)
    X_val, y_val, _ = _load(data / "val_features.csv", feat_cols)
    X_test, y_test, _ = _load(data / "test_features.csv", feat_cols)

    # Combine train+val (same as final fit in train.py)
    X_tv = np.vstack([X_train, X_val])
    y_tv = np.concatenate([y_train, y_val])

    results = []

    # Full features (baseline)
    clf_full = RandomForestClassifier(**best_params)
    clf_full.fit(X_tv, y_tv)
    f1_full = f1_score(y_test, clf_full.predict(X_test), average="macro")
    results.append({"removed": "None (full features)", "f1_macro": f1_full, "delta": 0.0})
    print(f"Full features:          F1={f1_full:.4f}  d=0.0000")

    # Remove one group at a time
    for group_name, group_cols in FEATURE_GROUPS.items():
        remaining = [c for c in train_cols if c not in group_cols]
        if not remaining:
            print(f"{group_name}: no features remain after removal, skipping")
            continue

        idx = [train_cols.index(c) for c in remaining]

        X_tv_sub = X_tv[:, idx]
        X_test_sub = X_test[:, idx]

        clf = RandomForestClassifier(**best_params)
        clf.fit(X_tv_sub, y_tv)
        f1 = f1_score(y_test, clf.predict(X_test_sub), average="macro")
        delta = f1 - f1_full
        results.append({"removed": group_name, "f1_macro": f1, "delta": delta})
        print(f"Remove {group_name:<28}  F1={f1:.4f}  d={delta:+.4f}")

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
    run_ablation(model_path, data_dir, output_path)


if __name__ == "__main__":
    main()
