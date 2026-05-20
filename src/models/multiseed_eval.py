"""
Multi-seed evaluation: regenerate data, retrain, and evaluate across N random seeds.
Reports mean +/- std for each metric to quantify result stability.

This addresses the single-seed limitation where results may be lucky/unlucky
due to random train/test splits or random forest initialization.
"""

from pathlib import Path

import click
import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import f1_score, precision_score, recall_score, roc_auc_score

from src.data.generator import generate
from src.data.preprocessor import preprocess
from src.features.engineer import engineer
from src.models.train import train

FEATURE_COLS_EXCLUDE = {"session_id", "label"}


def _load_test(path: Path, feat_cols: list[str]) -> tuple[np.ndarray, np.ndarray]:
    df = pd.read_csv(path)
    available = [c for c in feat_cols if c in df.columns]
    X = df[available].fillna(0).values.astype(np.float32)
    y = df["label"].values.astype(int)
    return X, y


def run_multiseed(
    n_benign: int,
    n_malicious: int,
    n_seeds: int,
    work_dir: str,
    output_path: str | None = None,
):
    work = Path(work_dir)
    raw_dir = work / "raw"
    proc_dir = work / "processed"
    model_dir = work / "models"
    raw_dir.mkdir(parents=True, exist_ok=True)

    all_results: list[dict] = []

    print(f"Multi-seed evaluation: {n_seeds} seeds, {n_benign} benign, {n_malicious} malicious\n")

    for seed in range(n_seeds):
        print(f"--- Seed {seed} ---")
        log_path = str(raw_dir / f"logs_seed{seed}.csv")
        seed_proc = proc_dir / f"seed{seed}"
        seed_model = model_dir / f"seed{seed}"

        generate(n_benign, n_malicious, log_path, seed=seed)
        preprocess(str(log_path), str(seed_proc))
        engineer(str(seed_proc), str(seed_proc))
        train(str(seed_proc), str(seed_model))

        artifact = joblib.load(seed_model / "best_model.pkl")
        model = artifact["model"]
        feat_cols = artifact["feature_cols"]

        X_test, y_test = _load_test(seed_proc / "test_features.csv", feat_cols)
        y_pred = model.predict(X_test)
        y_prob = model.predict_proba(X_test)[:, 1]

        prec = precision_score(y_test, y_pred, average="macro", zero_division=0)
        rec = recall_score(y_test, y_pred, average="macro", zero_division=0)
        f1 = f1_score(y_test, y_pred, average="macro", zero_division=0)
        auc = roc_auc_score(y_test, y_prob)
        all_results.append(
            {"seed": seed, "precision": prec, "recall": rec, "f1_macro": f1, "roc_auc": auc}
        )
        print(f"  Prec={prec:.4f}  Rec={rec:.4f}  F1={f1:.4f}  AUC={auc:.4f}")

    df = pd.DataFrame(all_results)
    metrics = ["precision", "recall", "f1_macro", "roc_auc"]
    summary = {m: (df[m].mean(), df[m].std()) for m in metrics}

    print(f"\n{'Metric':<12} {'Mean':>8} {'Std':>8}")
    print("-" * 30)
    for m, (mean, std) in summary.items():
        print(f"{m:<12} {mean:>8.4f} {std:>8.4f}")

    if output_path:
        df.to_csv(output_path, index=False)
        print(f"\nPer-seed results saved -> {output_path}")

    return df, summary


@click.command()
@click.option("--n-benign", default=5000, type=int, show_default=True)
@click.option("--n-malicious", default=1000, type=int, show_default=True)
@click.option("--n-seeds", default=5, type=int, show_default=True)
@click.option("--work-dir", required=True, help="Working directory for per-seed data/models")
@click.option("--output", "output_path", default=None)
def main(n_benign, n_malicious, n_seeds, work_dir, output_path):
    run_multiseed(n_benign, n_malicious, n_seeds, work_dir, output_path)


if __name__ == "__main__":
    main()
