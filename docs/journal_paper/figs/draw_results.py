"""Generate ROC curve and feature importance chart from trained model for journal paper."""

import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

import joblib
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.metrics import auc, roc_curve

OUT_DIR = Path(__file__).parent
MODEL_PATH = OUT_DIR.parent.parent.parent / "models" / "best_model.pkl"
TEST_PATH = OUT_DIR.parent.parent.parent / "data" / "processed" / "test_features.csv"


def generate_roc():
    artifact = joblib.load(MODEL_PATH)
    model = artifact["model"]
    feat_cols = artifact["feature_cols"]

    df = pd.read_csv(TEST_PATH)
    X = df[feat_cols].values.astype(np.float32)
    y = df["label"].values.astype(int)

    y_prob = model.predict_proba(X)[:, 1]
    fpr, tpr, _ = roc_curve(y, y_prob)
    roc_auc = auc(fpr, tpr)

    fig, axes = plt.subplots(1, 2, figsize=(10, 4))

    # ROC curve
    axes[0].plot(fpr, tpr, color="#2980B9", lw=2, label=f"Random Forest (AUC = {roc_auc:.3f})")
    axes[0].plot([0, 1], [0, 1], color="gray", lw=1, linestyle="--", label="Chance")
    axes[0].set_xlim([0.0, 1.0])
    axes[0].set_ylim([0.0, 1.02])
    axes[0].set_xlabel("False Positive Rate")
    axes[0].set_ylabel("True Positive Rate")
    axes[0].set_title("ROC Curve")
    axes[0].legend(loc="lower right", fontsize=9)
    axes[0].grid(alpha=0.3)

    # Feature importances (top 10)
    importances = model.feature_importances_
    indices = np.argsort(importances)[::-1][:10]
    feat_names = [feat_cols[i] for i in indices]
    feat_imps = [importances[i] for i in indices]

    axes[1].barh(range(10), feat_imps[::-1], color="#27AE60")
    axes[1].set_yticks(range(10))
    axes[1].set_yticklabels(feat_names[::-1], fontsize=8)
    axes[1].set_xlabel("Importance")
    axes[1].set_title("Top-10 Feature Importances")
    axes[1].grid(alpha=0.3, axis="x")

    plt.tight_layout()
    out = OUT_DIR / "results.png"
    plt.savefig(out, dpi=300, bbox_inches="tight")
    plt.close()
    print(f"Saved {out}")


if __name__ == "__main__":
    generate_roc()
