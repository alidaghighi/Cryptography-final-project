# AI-Driven Malware Detection via Windows Event Log Engineering in Smart Grid Control Systems

Synthetic Windows Event Log generation, session-level feature engineering, and Random Forest classification for malware detection in ICS/SCADA environments.

## Prerequisites

- Python 3.11+
- [uv](https://docs.astral.sh/uv/) package manager

## Quickstart

```bash
# Install dependencies
uv sync

# 1. Generate synthetic event logs
uv run python -m src.cli generate --n-benign 5000 --n-malicious 1000 --output data/raw/logs.csv

# 2. Preprocess and split
uv run python -m src.cli preprocess --input data/raw/logs.csv --output data/processed/

# 3. Train model
uv run python -m src.cli train --data data/processed/ --output models/

# 4. Evaluate
uv run python -m src.cli evaluate --model models/best_model.pkl --data data/processed/test.csv
```

## Module Descriptions

| File | Description |
|------|-------------|
| `src/cli.py` | Click CLI entry point; routes subcommands to modules below |
| `src/data/generator.py` | Synthetic Windows Event Log generator; 4 attack patterns; smart grid hostnames |
| `src/data/preprocessor.py` | Null removal, session-stratified 70/15/15 train/val/test split |
| `src/features/engineer.py` | Session-level feature extraction: event counts, time-delta stats, cardinality, rare flags, entropy |
| `src/models/train.py` | Random Forest with 5-fold stratified CV and RandomizedSearchCV; saves `best_model.pkl` |
| `src/models/evaluate.py` | Accuracy, F1, ROC-AUC, confusion matrix PNG on held-out test set |
