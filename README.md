# AI-IDS

[![CI](https://github.com/TurlaFSB/AI-IDS/actions/workflows/ci.yml/badge.svg)](https://github.com/TurlaFSB/AI-IDS/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue)
![Type checked: mypy strict](https://img.shields.io/badge/types-mypy%20strict-informational)
![Code style: ruff](https://img.shields.io/badge/style-ruff-informational)

Machine-learning network intrusion detection for enterprise traffic, built around reproducible
evaluation, calibrated false-positive rates, and integrity-checked models.

> **Status: v0.1, foundation.** Offline training and evaluation are implemented and tested.
> Real-data results are pending; live capture, threat-intelligence enrichment, drift-triggered
> retraining, an autoencoder, and a dashboard are on the [roadmap](#roadmap). Nothing here is
> validated for production use yet.

## Contents

- [Why this project](#why-this-project)
- [Features](#features)
- [Architecture](#architecture)
- [Quickstart](#quickstart)
- [Using CICIDS2017](#using-cicids2017)
- [Usage](#usage)
- [Evaluation methodology](#evaluation-methodology)
- [Results](#results)
- [Limitations](#limitations)
- [Project layout](#project-layout)
- [Documentation](#documentation)
- [Security](#security)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [Citation and acknowledgements](#citation-and-acknowledgements)
- [License](#license)

## Why this project

Most published intrusion-detection work reports high accuracy on random splits of benchmark data.
Those numbers collapse on real networks for three recurring reasons: near-duplicate flows leak
between train and test, accuracy hides the false-alarm rate that actually limits a security team,
and models are deployed without integrity guarantees. AI-IDS is built to avoid all three:
chronological splits, thresholds calibrated to an explicit false-positive budget, and verified
model artifacts.

## Features

| Area | What is implemented |
|---|---|
| Data | CICIDS2017 loader: label normalisation, duplicate and non-finite value handling, timestamp repair |
| Splitting | Per-class chronological train / validation / test split (no random splits) |
| Detectors | Random Forest (supervised, multi-class) and Isolation Forest (unsupervised, benign-only training) behind one scoring contract |
| Operating point | Alert threshold calibrated on held-out benign traffic to a target false-positive rate |
| Metrics | Recall, precision, F1, FPR, MCC, ROC-AUC, PR-AUC, per-attack recall with support, scoring latency (p50/p95/p99) |
| Model registry | SHA-256 manifest per artifact, optional HMAC-SHA256 signature, recorded environment versions |
| Threat mapping | Each attack type mapped to a MITRE ATT&CK technique for alert enrichment |
| Engineering | Typed (`mypy --strict`), linted, 85%+ coverage gate, CI on Python 3.11-3.13, SAST, dependency audit, SBOM |

## Architecture

```mermaid
flowchart LR
    A[CICIDS2017 flow CSVs] --> B[Loader and cleaner]
    B --> C[Per-class chronological split]
    C -->|train| D[Random Forest]
    C -->|benign train| E[Isolation Forest]
    C -->|benign validation| F[FPR threshold calibration]
    D --> F
    E --> F
    C -->|test| G[Evaluation]
    F --> G
    D --> H[Model registry]
    E --> H
    G --> I[report.json]
```

More detail, including the target architecture, is in [docs/architecture.md](docs/architecture.md).

## Quickstart

Requires Python 3.11 or newer.

```bash
git clone https://github.com/TurlaFSB/AI-IDS.git
cd AI-IDS
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e ".[dev]"

# Verify the pipeline on synthetic data (no download needed)
ai-ids synth --out data/synthetic.csv --rows 30000
ai-ids train --data data/synthetic.csv --out models/demo --config configs/default.yaml
```

Results on synthetic data only show that the pipeline works. They say nothing about detection
performance on real traffic.

Run the quality gates:

```bash
ruff check src tests && ruff format --check src tests
mypy
pytest
```

## Using CICIDS2017

1. Download the labelled flow files (`GeneratedLabelledFlows.zip` and its `.md5`) from the
   official source: <https://www.unb.ca/cic/datasets/ids-2017.html>. Follow the dataset's terms
   and cite it (see [Citation](#citation-and-acknowledgements)).
2. Verify the download against the published MD5, unzip into `data/raw/`, then record SHA-256
   digests of the CSVs for traceability:
   ```bash
   ai-ids checksum data/raw/TrafficLabelling
   ```
3. Train and evaluate:
   ```bash
   ai-ids train --data data/raw/TrafficLabelling --out models/cicids2017 --config configs/default.yaml
   ```

`data/` is git-ignored: datasets are never committed. The full dataset needs a few GB of RAM.
See [docs/data-governance.md](docs/data-governance.md) for provenance, privacy, and retention rules.

## Usage

```text
ai-ids synth     write a synthetic CICIDS2017-style CSV
ai-ids train     load, clean, split, train, calibrate, evaluate, and save detectors
ai-ids checksum  print SHA-256 digests of dataset files
```

Experiments are configured in YAML ([configs/default.yaml](configs/default.yaml)): seed, target
false-positive rate, operating points, split fractions, and model hyperparameters. Unknown keys
are rejected.

To sign model artifacts, set `AI_IDS_MODEL_HMAC_KEY` (see [.env.example](.env.example)) before
training; the same key is then required to load them.

Each run writes to the output directory:

```text
random_forest/model.joblib, manifest.json
isolation_forest/model.joblib, manifest.json
report.json        metrics, operating points, per-attack recall, latency, dataset statistics
```

## Evaluation methodology

- **Chronological, per-class splits.** Within each attack type the earliest 60% of flows train the
  model, the next 15% calibrate the threshold, and the latest 25% test it
  ([ADR 0002](docs/adr/0002-chronological-split.md)).
- **Threshold chosen without peeking.** The alert threshold is the benign validation-score
  quantile for the target FPR (default 1%), so validation FPR is bounded by construction. Test
  FPR is measured, not assumed ([ADR 0004](docs/adr/0004-fpr-calibrated-threshold.md)).
- **Accuracy is never the headline metric.** Traffic is heavily imbalanced; recall, FPR, and
  PR-AUC are reported, with per-attack recall and support.
- **Latency** is measured per scoring call, single inference thread, after warm-up.
- Results are reported at several operating points (0.1%, 1%, 5% target FPR).

## Results

Real-data results are pending the first full run on CICIDS2017. They will be published here and in
the [model card](docs/model-card.md) with the exact configuration, dataset checksums, and commit.

## Limitations

- CICIDS2017 has documented labelling and flow-construction problems
  (see Engelen, Rimmer and Joosen, "Troubleshooting an Intrusion Detection Dataset: the CICIDS2017
  Case Study", IEEE Security and Privacy Workshops, 2021). Corrected-label support is planned;
  treat early numbers as provisional.
- Attacks in the dataset come from a small set of tools, so models may learn tool signatures.
- Very small classes (Heartbleed, Infiltration) have tiny test sets and unreliable recall.
- No adversarial-evasion evaluation yet; performance on other networks is unknown.
- Model artifacts are pickle-based: load only verified artifacts from storage you control.

## Project layout

```text
src/ai_ids/
  labels.py        attack taxonomy and MITRE ATT&CK mapping
  data/            loader, chronological split, synthetic generator
  models/          Random Forest and Isolation Forest detectors
  evaluation/      metrics and latency profiling
  registry.py      integrity-checked model artifacts
  pipeline.py      train + evaluate + persist
  cli.py           ai-ids command
configs/           experiment configuration
docs/              architecture, threat model, compliance, data governance, model card, ADRs
tests/             unit and end-to-end tests
```

## Documentation

| Document | Purpose |
|---|---|
| [Architecture](docs/architecture.md) | Components, data flow, target design |
| [Threat model](docs/threat-model.md) | STRIDE analysis and mitigations |
| [Standards alignment](docs/compliance.md) | NIST CSF 2.0, NIST SP 800-53, MITRE ATT&CK, OWASP ASVS |
| [Data governance](docs/data-governance.md) | Provenance, privacy (GDPR), retention |
| [Model card](docs/model-card.md) | Intended use, evaluation protocol, limitations |
| [Decision records](docs/adr/README.md) | Why the design is the way it is |
| [Changelog](CHANGELOG.md) | Release history |

## Security

- Report vulnerabilities privately; see [SECURITY.md](SECURITY.md).
- Model artifacts are verified (SHA-256, optional HMAC-SHA256) before loading, but they remain
  pickle-based: loading one executes code. Only load artifacts you trained and stored yourself.
- Datasets, captures, trained models, and secrets are git-ignored and must never be committed.
- CI runs lint, type checks, tests on Python 3.11-3.13, `bandit`, `pip-audit`, and produces a
  CycloneDX SBOM.

## Roadmap

1. **Milestone 2:** PyTorch autoencoder (GPU) as a third detector; corrected-label support.
2. **Milestone 3:** Live flow capture and real-time scoring service with Prometheus metrics.
3. **Milestone 4:** Threat-intelligence enrichment (AbuseIPDB, AlienVault OTX) with caching and a
   local blocklist fallback; ATT&CK-tagged alerts.
4. **Milestone 5:** Drift detection (PSI/KS) gating scheduled retraining, with champion/challenger
   promotion and rollback.
5. **Milestone 6:** Dashboard, container image (non-root, pinned base), hash-locked dependencies.

## Contributing

Contributions are welcome; see [CONTRIBUTING.md](CONTRIBUTING.md) and the
[Code of Conduct](CODE_OF_CONDUCT.md).

## Citation and acknowledgements

To cite this software, use [CITATION.cff](CITATION.cff) (GitHub's "Cite this repository").

This project uses the CIC-IDS-2017 dataset from the Canadian Institute for Cybersecurity,
University of New Brunswick. If you use results derived from it, cite:

> I. Sharafaldin, A. H. Lashkari, and A. A. Ghorbani, "Toward Generating a New Intrusion Detection
> Dataset and Intrusion Traffic Characterization," *4th International Conference on Information
> Systems Security and Privacy (ICISSP)*, 2018.

## License

[MIT](LICENSE)
