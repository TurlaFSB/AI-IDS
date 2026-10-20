# AI-IDS

Machine-learning network intrusion detection for enterprise traffic, built around
reproducible evaluation, calibrated false-positive rates, and integrity-checked models.

> **Status: milestone 1 (foundation).** Data pipeline, two baseline detectors, evaluation,
> and a signed model registry are implemented. Live capture, threat-intelligence enrichment,
> drift-triggered retraining, the autoencoder, and the dashboard are on the roadmap below.

## What it does today

| Component | Description |
|---|---|
| Data pipeline | Loads CICIDS2017 flow CSVs, normalises labels (including the source files' encoding artefacts), removes duplicates, handles non-finite values, repairs the 12-hour-clock timestamps |
| Splitting | Per-class **chronological** train / validation / test split to avoid the near-duplicate leakage that inflates random-split results |
| Detectors | Random Forest (supervised, multi-class, score = 1 − P(benign)) and Isolation Forest (unsupervised, trained on benign traffic only) |
| Operating point | Alert threshold calibrated on held-out benign traffic to a target false-positive rate; test results reported at several operating points |
| Metrics | Recall, precision, F1, false-positive rate, MCC, ROC-AUC, PR-AUC, per-attack recall with support, single-thread latency (p50/p95/p99) |
| Model registry | SHA-256 manifest per artifact, optional HMAC-SHA256 signature, environment versions recorded |
| Taxonomy | Each attack type mapped to a MITRE ATT&CK technique for alert enrichment |

## Quickstart

Requires Python 3.11+.

```bash
git clone https://github.com/TurlaFSB/AI-IDS.git
cd AI-IDS
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -e ".[dev]"

# Verify the pipeline on synthetic data (no download needed)
ai-ids synth --out data/synthetic.csv --rows 30000
ai-ids train --data data/synthetic.csv --out models/demo --config configs/default.yaml

# Quality gates
ruff check src tests && ruff format --check src tests
mypy
pytest
```

Results on synthetic data only demonstrate that the pipeline works; they say nothing about
real-world detection performance.

## Using the real dataset (CICIDS2017)

1. Download the **labelled flow CSVs** (`TrafficLabelling` / `GeneratedLabelledFlows`, which
   include IPs and timestamps) from the official source:
   <https://www.unb.ca/cic/datasets/ids-2017.html>. Respect the dataset's license and citation terms.
2. Place the CSVs in `data/` (git-ignored) and record their digests so runs are traceable:
   ```bash
   ai-ids checksum data/
   ```
3. Train and evaluate:
   ```bash
   ai-ids train --data data/ --out models/cicids2017 --config configs/default.yaml
   ```
   Peak memory is several GB for the full dataset; 16 GB RAM is comfortable.

**Known dataset issues.** CICIDS2017 has documented labelling errors and flow-construction
problems (Engelen, Rimmer & Joosen, *Troubleshooting an Intrusion Detection Dataset: the
CICIDS2017 Case Study*, 2021). This project deduplicates and splits chronologically, but
corrected-label support is planned; treat headline numbers accordingly.

## Methodology

- **No random splits.** Within each attack type, the earliest flows train the model, the next
  slice calibrates the threshold, and the latest slice is the test set.
- **Threshold chosen without peeking at attacks or test data.** The alert threshold is the
  benign validation-score quantile for the target FPR (default 1%), so validation FPR is
  bounded by construction. Test FPR is measured, not assumed.
- **Accuracy is never the headline metric**; traffic is heavily imbalanced.
- **Latency** is measured per scoring call with a single inference thread, after warm-up.
- Tiny classes (e.g. Heartbleed, Infiltration) have very small test supports; per-attack recall
  reports support next to each value.

## Layout

```
src/ai_ids/
  labels.py        attack taxonomy and MITRE ATT&CK mapping
  data/            loader (clean), split (chronological), synthetic generator
  models/          Random Forest and Isolation Forest detectors
  evaluation/      metrics and latency profiling
  registry.py      integrity-checked model artifacts
  pipeline.py      train + evaluate + persist
  cli.py           ai-ids command
configs/           experiment configuration
tests/             unit and end-to-end tests (coverage gate: 85%)
```

## Security

- `joblib` artifacts are pickle-based: loading one executes code. Only load artifacts you
  trained and stored yourself. Set `AI_IDS_MODEL_HMAC_KEY` to sign artifacts at training time and
  require a valid signature at load time.
- Datasets, captures, trained models, and secrets are git-ignored and must never be committed.
- See [SECURITY.md](SECURITY.md) for vulnerability reporting.
- CI runs lint, type-checking, tests on Python 3.11–3.13, `bandit`, `pip-audit`, and generates a
  CycloneDX SBOM.

## Roadmap

1. **Milestone 2:** PyTorch autoencoder (GPU) as a third detector; corrected-label support.
2. **Milestone 3:** Live flow capture and real-time scoring service (Flask) with Prometheus metrics.
3. **Milestone 4:** Threat-intelligence enrichment (AbuseIPDB, AlienVault OTX) with caching and a
   local blocklist fallback; ATT&CK-tagged alerts.
4. **Milestone 5:** Drift detection (PSI/KS) gating scheduled retraining, with champion/challenger
   promotion and rollback.
5. **Milestone 6:** Dashboard, containerisation (non-root, pinned base image), threat model and
   compliance mapping (NIST CSF 2.0, OWASP ASVS).

## AI assistance disclosure

This project is developed with the assistance of an AI coding assistant (Claude, by Anthropic).
Architecture decisions, review, validation, and responsibility for the final code rest with the
project maintainer.

## License

[MIT](LICENSE)
