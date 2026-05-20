"""Evaluate saved model on held-out test set and produce metrics + confusion matrix PNG."""

from pathlib import Path

import click
import joblib
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    roc_auc_score,
)

FEATURE_COLS_EXCLUDE = {"session_id", "label"}


def evaluate(model_path: str, data_path: str, output_dir: str = None):
    artifact = joblib.load(model_path)
    model = artifact["model"]
    feat_cols = artifact["feature_cols"]

    df = pd.read_csv(data_path)
    X = df[feat_cols].values.astype(np.float32)
    y = df["label"].values.astype(int)

    y_pred = model.predict(X)
    y_prob = model.predict_proba(X)[:, 1]

    acc = accuracy_score(y, y_pred)
    roc = roc_auc_score(y, y_prob)

    print(f"\n{'='*50}")
    print(f"Accuracy:  {acc:.4f}")
    print(f"ROC-AUC:   {roc:.4f}")
    print(f"\nClassification Report:")
    print(classification_report(y, y_pred, target_names=["benign", "malicious"]))

    # Confusion matrix PNG
    cm = confusion_matrix(y, y_pred)
    fig, ax = plt.subplots(figsize=(5, 4))
    im = ax.imshow(cm, interpolation="nearest", cmap="Blues")
    plt.colorbar(im, ax=ax)
    ax.set(
        xticks=[0, 1],
        yticks=[0, 1],
        xticklabels=["benign", "malicious"],
        yticklabels=["benign", "malicious"],
        xlabel="Predicted",
        ylabel="True",
        title="Confusion Matrix",
    )
    for i in range(2):
        for j in range(2):
            ax.text(j, i, str(cm[i, j]), ha="center", va="center",
                    color="white" if cm[i, j] > cm.max() / 2 else "black")
    plt.tight_layout()

    if output_dir is None:
        out_dir = Path(model_path).parent
    else:
        out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    cm_path = out_dir / "confusion_matrix.png"
    plt.savefig(cm_path, dpi=150)
    plt.close()
    print(f"Confusion matrix saved -> {cm_path}")


@click.command()
@click.option("--model", "model_path", required=True)
@click.option("--data", "data_path", required=True)
@click.option("--output", "output_dir", default=None)
def main(model_path, data_path, output_dir):
    evaluate(model_path, data_path, output_dir)


if __name__ == "__main__":
    main()
