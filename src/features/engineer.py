"""Session-level feature extraction from raw Windows Event Log CSV."""

from pathlib import Path

import click
import numpy as np
import pandas as pd
from scipy.stats import entropy as scipy_entropy

COUNT_EVENT_IDS = [4624, 4625, 4634, 4648, 4672, 4688, 4689, 4720, 4732, 7045, 7036, 4663, 4656]

RARE_THRESHOLD = 0.05  # events appearing in <5% of benign sessions


def _shannon_entropy(series: pd.Series) -> float:
    counts = series.value_counts(normalize=True)
    return float(scipy_entropy(counts.values, base=2)) if len(counts) > 1 else 0.0


def _compute_rare_flags(df: pd.DataFrame, rare_event_ids: list[int]) -> dict:
    flags = {}
    for eid in rare_event_ids:
        flags[f"flag_{eid}"] = int(eid in df["event_id"].values)
    return flags


def extract_features(df: pd.DataFrame, rare_event_ids: list[int] | None = None) -> pd.DataFrame:
    if rare_event_ids is None:
        rare_event_ids = []

    df = df.copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"], format="ISO8601")
    df = df.sort_values(["session_id", "timestamp"])

    records = []
    for sid, group in df.groupby("session_id"):
        group = group.sort_values("timestamp")
        feat: dict = {"session_id": sid}

        # Event frequency counts
        for eid in COUNT_EVENT_IDS:
            feat[f"count_{eid}"] = int((group["event_id"] == eid).sum())
        feat["count_total"] = len(group)

        # Time-delta statistics
        ts_sorted = group["timestamp"].values
        if len(ts_sorted) > 1:
            deltas = np.diff(ts_sorted.astype("datetime64[s]").astype(np.int64))
            feat["td_mean"] = float(deltas.mean())
            feat["td_std"] = float(deltas.std())
            feat["td_min"] = float(deltas.min())
            feat["td_max"] = float(deltas.max())
        else:
            feat["td_mean"] = feat["td_std"] = feat["td_min"] = feat["td_max"] = 0.0

        # Cardinality
        feat["n_unique_sources"] = int(group["source"].nunique())
        feat["n_unique_users"] = int(group["user"].nunique())
        feat["n_unique_hosts"] = int(group["hostname"].nunique())

        # Rare event flags
        feat.update(_compute_rare_flags(group, rare_event_ids))

        # Sequence entropy
        feat["seq_entropy"] = _shannon_entropy(group["event_id"])

        # Session label
        feat["label"] = int(group["label"].max())

        records.append(feat)

    return pd.DataFrame(records)


def identify_rare_events(train_df: pd.DataFrame) -> list[int]:
    benign = train_df[train_df["label"] == 0]
    n_benign_sessions = benign["session_id"].nunique()
    if n_benign_sessions == 0:
        return []

    event_session_counts = (
        benign.groupby("event_id")["session_id"].nunique() / n_benign_sessions
    )
    rare = event_session_counts[event_session_counts < RARE_THRESHOLD].index.tolist()
    return [int(e) for e in rare]


def engineer(input_dir: str, output_dir: str):
    in_path = Path(input_dir)
    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    train_df = pd.read_csv(in_path / "train.csv")
    rare_ids = identify_rare_events(train_df)
    print(f"Rare event IDs (in <{RARE_THRESHOLD*100:.0f}pct benign sessions): {rare_ids}")

    for split in ["train", "val", "test"]:
        raw = pd.read_csv(in_path / f"{split}.csv")
        features = extract_features(raw, rare_ids)
        dest = out_path / f"{split}_features.csv"
        features.to_csv(dest, index=False)
        print(f"{split}: {len(features)} sessions, {features.shape[1]} features -> {dest}")


@click.command()
@click.option("--input", "input_dir", required=True)
@click.option("--output", "output_dir", required=True)
def main(input_dir, output_dir):
    engineer(input_dir, output_dir)


if __name__ == "__main__":
    main()
