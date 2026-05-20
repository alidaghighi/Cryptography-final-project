# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

**"Artificial Intelligence-Driven Malware Detection via Windows Event Log Engineering in Smart Grid Control Systems"**

Academic research project: synthetic data generation → feature engineering → AI malware detection → 4 LaTeX deliverables.

## Execution Order

Build in this sequence; commit after each step:

1. `chore:` scaffold — `pyproject.toml`, `.latexmkrc`, `README.md` skeleton, directory structure
2. `feat:` `src/data/generator.py` + smoke test
3. `feat:` `src/features/engineer.py`
4. `feat:` `src/models/train.py` + `src/models/evaluate.py`
5. `feat:` `src/cli.py` + complete `README.md`
6. `docs:` preliminary study (compile to PDF)
7. `docs:` journal paper (compile to PDF)
8. `docs:` presentation + teleprompter (compile both)
9. `chore:` `black .` + `ruff check --fix .`; verify all PDFs clean

## Python Conventions

- Package manager: `uv`. All deps in `pyproject.toml`. Never bare `pip install`.
- Run: `uv run python -m src.cli <subcommand> <args>`
- After editing Python: `black .` then `ruff check --fix .`

### CLI interface

```
uv run python -m src.cli generate  --n-benign 5000 --n-malicious 1000 --output data/raw/logs.csv
uv run python -m src.cli preprocess --input data/raw/logs.csv --output data/processed/
uv run python -m src.cli train      --data data/processed/ --output models/
uv run python -m src.cli evaluate   --model models/best_model.pkl --data data/processed/test.csv
```

## LaTeX Conventions

- XeLaTeX + biber; aux files → `_latexmk/`; `.latexmkrc` in repo root sets this.
- **Always `cd` to the directory containing the `.tex` file before compiling**, then: `latexmk <filename>` (no extra args).
- One `\input{sections/foo.tex}` per logical section — modular structure.
- `biblatex` with `style=ieee` and `backend=biber`.
- All `.bib` entries must be real, web-verified (DOI or URL must resolve). Min 15 refs for preliminary study, 20 for journal paper.

## Figure Generation

- All figures: PNG from Python scripts in the document's `figs/` directory.
- Use `graphviz.Digraph`, `fontname="Helvetica"`, `fontsize="10"`, `dpi="300"`, `cleanup=True`.
- Use colored subgraph clusters. One script per figure.

## Data Generator Requirements

Output CSV fields: `timestamp`, `event_id`, `source`, `user`, `hostname`, `description`, `label` (0=benign, 1=malicious), `session_id`.

Attack patterns (must cover all 4):
1. Lateral movement: repeated 4625 failures → 4624 success from unexpected source
2. Persistence: 7045 new service install on SCADA host
3. Privilege escalation: 4672 + 4688 sequence with unusual process
4. Reconnaissance: burst of 4663 object access on HMI/RTU hosts

Smart grid hostnames: `SCADA-HMI-01`, `RTU-CTRL-03`, `eng_station`, etc.

## Feature Engineering

Session-level features:
- Event frequency counts per event ID
- Time-delta stats (mean, std, min, max inter-event gap)
- Unique source/user/host counts per session
- Rare event flags (events in <5% of benign sessions)
- Sequence entropy (Shannon entropy over event ID distribution)

## Model Requirements

- Scikit-learn compatible or PyTorch
- 5-fold stratified cross-validation
- Hyperparameter search (grid or random)
- Save best model: `models/best_model.pkl` (or `.pt`)
- Justify model choice in comment at top of `src/models/train.py`

## Quality Gates

Before declaring done:

- [ ] `uv run python -m src.cli generate ...` produces valid CSV
- [ ] `uv run python -m src.cli train ...` completes and saves model
- [ ] `uv run python -m src.cli evaluate ...` prints metrics + saves `models/confusion_matrix.png`
- [ ] All 4 LaTeX documents compile to PDF with zero errors
- [ ] All figures render in PDFs (no missing image warnings)
- [ ] All `.bib` DOIs/URLs resolve
- [ ] `ruff check .` returns zero errors

## Presentation Notes

- Beamer theme: `metropolis` (fallback: `Madrid`)
- 15–18 slides; every slide has `\note{}` matching teleprompter entry
- `teleprompter.tex`: standalone `article` class, ≥14pt font, one section per slide, 60–90 sec of spoken content per slide, delivery cues in italics
- Compile independently: `cd docs/presentation && latexmk teleprompter.tex`
