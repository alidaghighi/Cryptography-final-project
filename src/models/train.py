# Model choice: Random Forest Classifier
# Rationale: handles heterogeneous tabular features (counts, ratios, flags, entropy) without
# feature scaling; class_weight='balanced' compensates for malicious/benign imbalance without
# oversampling; feature importances provide academic interpretability; robust hyperparameters
# and no convergence issues unlike SVM/NN on this small dataset size.

from pathlib import Path

import click
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import RandomizedSearchCV, StratifiedKFold


FEATURE_COLS_EXCLUDE = {"session_id", "label"}


def _load_features(path: Path) -> tuple[np.ndarray, np.ndarray, list[str]]:
    df = pd.read_csv(path)
    feat_cols = [c for c in df.columns if c not in FEATURE_COLS_EXCLUDE]
    X = df[feat_cols].values.astype(np.float32)
    y = df["label"].values.astype(int)
    return X, y, feat_cols


def train(data_dir: str, output_dir: str):
    data_path = Path(data_dir)
    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    X_train, y_train, feat_cols = _load_features(data_path / "train_features.csv")
    X_val, y_val, _ = _load_features(data_path / "val_features.csv")

    # Combine train + val for final fit after search
    X_trainval = np.vstack([X_train, X_val])
    y_trainval = np.concatenate([y_train, y_val])

    param_dist = {
        "n_estimators": [50, 100, 200],
        "max_depth": [5, 10, None],
        "min_samples_split": [2, 5, 10],
        "max_features": ["sqrt", "log2"],
    }

    base_clf = RandomForestClassifier(class_weight="balanced", random_state=42, n_jobs=-1)
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

    search = RandomizedSearchCV(
        base_clf,
        param_distributions=param_dist,
        n_iter=20,
        cv=cv,
        scoring="f1_macro",
        random_state=42,
        n_jobs=-1,
        verbose=1,
    )
    search.fit(X_train, y_train)

    print(f"Best CV F1-macro: {search.best_score_:.4f}")
    print(f"Best params: {search.best_params_}")

    # Retrain best params on full train+val
    final_clf = RandomForestClassifier(
        **search.best_params_, class_weight="balanced", random_state=42, n_jobs=-1
    )
    final_clf.fit(X_trainval, y_trainval)

    # Top feature importances
    importances = sorted(zip(feat_cols, final_clf.feature_importances_), key=lambda x: -x[1])
    print("\nTop 10 feature importances:")
    for name, imp in importances[:10]:
        print(f"  {name}: {imp:.4f}")

    model_path = out_path / "best_model.pkl"
    joblib.dump({"model": final_clf, "feature_cols": feat_cols}, model_path)
    print(f"\nModel saved -> {model_path}")


@click.command()
@click.option("--data", "data_dir", required=True)
@click.option("--output", "output_dir", required=True)
def main(data_dir, output_dir):
    train(data_dir, output_dir)


if __name__ == "__main__":
    main()
