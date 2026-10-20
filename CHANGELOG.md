# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- Packet-size padding in the evasion analysis is now self-consistent (totals, byte rates and
  averages move with the per-packet lengths); earlier numbers used a partial transformation and
  are superseded.

### Fixed
- Dates in CICIDS2017 files are day-first; they were parsed month-first, which mislabelled capture
  days in reports (chronological order was unaffected). Parsing is now day-first by default
  (`timestamp_dayfirst`).

### Added
- `ai-ids analyze`: recompute all evaluation diagnostics from a saved model without retraining;
  refuses to run if the dataset or split differs from training.
- Host-concentration diagnostics for false positives (time window, distinct ports and hosts, and a
  clearly labelled exclude-top-hosts sensitivity figure) and per-attack recall at every operating
  point.
- Hourly false-positive and recall breakdown, and a false-positive profile (which ports and hosts
  false alarms concentrate on) in every report.
- Supply-chain hardening (ADR 0006): hash-locked dependencies with a lock-freshness CI check,
  SHA-pinned GitHub Actions, a multi-stage non-root Dockerfile with a digest-pinned base image,
  and container build, smoke test and Trivy scan in CI.
- Feature-space evasion-sensitivity analysis (timing and packet-size reshaping) in every report.
- Gradient-boosting detector with continuous scores (ADR 0005); detectors selectable by name
  in the experiment config.
- Reproducibility metadata in `report.json`: SHA-256 digests of the input dataset files and a
  dirty-working-tree flag next to the git commit.
- Evaluation diagnostics: false-positive rate and recall per capture day, macro-averaged recall,
  and per-feature benign drift (Population Stability Index) in `report.json`.
- `ai-ids holdout`: leave-one-attack-family-out generalisation test.
- First real-data results in the README and model card.
- `configs/light.yaml`: lower-memory training settings for laptops.
- Repository documentation: architecture, threat model (STRIDE), compliance mapping,
  data governance, model card, and architecture decision records.
- Community files: contributing guide, code of conduct, issue and pull request templates,
  code owners, citation metadata, pre-commit configuration.

## [0.1.0] - 2026-10-20

### Added
- CICIDS2017 loader with label normalisation, duplicate and non-finite value handling,
  and timestamp repair.
- Per-class chronological train/validation/test split.
- Random Forest (supervised) and Isolation Forest (unsupervised) detectors with
  false-positive-rate-calibrated alert thresholds.
- Detection metrics (recall, precision, F1, FPR, MCC, ROC-AUC, PR-AUC), per-attack recall,
  and single-thread latency profiling.
- Integrity-checked model registry (SHA-256 manifest, optional HMAC-SHA256 signature).
- MITRE ATT&CK technique mapping for attack types.
- `ai-ids` CLI (`synth`, `train`, `checksum`), synthetic data generator, structured JSON logging.
- Continuous integration (lint, types, tests on Python 3.11-3.13, bandit, pip-audit, SBOM).

[Unreleased]: https://github.com/TurlaFSB/AI-IDS/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/TurlaFSB/AI-IDS/releases/tag/v0.1.0
