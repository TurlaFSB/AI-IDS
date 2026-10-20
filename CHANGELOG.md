# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
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
