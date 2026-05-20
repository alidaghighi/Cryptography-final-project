"""CLI entry point. Run via: uv run python -m src.cli <subcommand> <args>"""

import click

from src.data.generator import generate
from src.data.preprocessor import preprocess
from src.features.engineer import engineer
from src.models.baselines import run_baselines
from src.models.evaluate import evaluate
from src.models.train import train


@click.group()
def cli():
    """AI malware detection for smart grid Windows Event Logs."""


@cli.command()
@click.option("--n-benign", default=5000, type=int, show_default=True)
@click.option("--n-malicious", default=1000, type=int, show_default=True)
@click.option("--output", required=True, help="Output CSV path")
@click.option("--seed", default=42, type=int, show_default=True)
def generate_cmd(n_benign, n_malicious, output, seed):
    """Generate synthetic Windows Event Log CSV."""
    generate(n_benign, n_malicious, output, seed)


@cli.command()
@click.option("--input", "input_path", required=True, help="Raw logs CSV")
@click.option("--output", "output_dir", required=True, help="Output directory for splits")
def preprocess_cmd(input_path, output_dir):
    """Clean and split raw logs into train/val/test CSVs."""
    preprocess(input_path, output_dir)


@cli.command()
@click.option("--input", "input_dir", required=True, help="Directory with split CSVs")
@click.option("--output", "output_dir", required=True, help="Output directory for feature CSVs")
def featurize(input_dir, output_dir):
    """Extract session-level features from split CSVs."""
    engineer(input_dir, output_dir)


@cli.command()
@click.option("--data", "data_dir", required=True, help="Directory with *_features.csv files")
@click.option("--output", "output_dir", required=True, help="Output directory for model")
def train_cmd(data_dir, output_dir):
    """Train Random Forest model with cross-validation."""
    train(data_dir, output_dir)


@cli.command()
@click.option("--model", "model_path", required=True, help="Path to best_model.pkl")
@click.option("--data", "data_path", required=True, help="Path to test_features.csv")
@click.option("--output", "output_dir", default=None, help="Directory for confusion matrix PNG")
def evaluate_cmd(model_path, data_path, output_dir):
    """Evaluate model on test set; print metrics and save confusion matrix."""
    evaluate(model_path, data_path, output_dir)


@cli.command()
@click.option("--model", "model_path", required=True, help="Path to best_model.pkl")
@click.option("--data", "data_dir", required=True, help="Directory with *_features.csv files")
@click.option("--output", "output_path", default=None, help="Optional CSV output for results")
def baselines_cmd(model_path, data_dir, output_path):
    """Compare RF against LR, DT, SVM, XGBoost, and Isolation Forest baselines."""
    run_baselines(model_path, data_dir, output_path)


# Expose canonical subcommand names matching CLAUDE.md spec
cli.add_command(generate_cmd, name="generate")
cli.add_command(preprocess_cmd, name="preprocess")
cli.add_command(featurize, name="featurize")
cli.add_command(train_cmd, name="train")
cli.add_command(evaluate_cmd, name="evaluate")
cli.add_command(baselines_cmd, name="baselines")


def main():
    cli()


if __name__ == "__main__":
    main()
