"""Preprocessing: clean raw event log CSV and produce session-stratified train/val/test splits."""

from pathlib import Path

import click
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split


def preprocess(input_path: str, output_dir: str):
    df = pd.read_csv(input_path)
    df = df.dropna()

    # Session-level label: 1 if any event in session is malicious
    session_labels = df.groupby("session_id")["label"].max().reset_index()
    session_labels.columns = ["session_id", "session_label"]

    sessions = session_labels["session_id"].values
    labels = session_labels["session_label"].values

    # 70 / 15 / 15 stratified split on session level
    train_ids, temp_ids, _, temp_labels = train_test_split(
        sessions, labels, test_size=0.30, stratify=labels, random_state=42
    )
    val_ids, test_ids = train_test_split(
        temp_ids, test_size=0.50, stratify=temp_labels, random_state=42
    )

    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    for split_name, ids in [("train", train_ids), ("val", val_ids), ("test", test_ids)]:
        split_df = df[df["session_id"].isin(ids)]
        path = out / f"{split_name}.csv"
        split_df.to_csv(path, index=False)
        n_mal = split_df.groupby("session_id")["label"].max().sum()
        n_total = split_df["session_id"].nunique()
        print(f"{split_name}: {len(split_df)} events, {n_total} sessions ({int(n_mal)} malicious) -> {path}")


@click.command()
@click.option("--input", "input_path", required=True)
@click.option("--output", "output_dir", required=True)
def main(input_path, output_dir):
    preprocess(input_path, output_dir)


if __name__ == "__main__":
    main()
