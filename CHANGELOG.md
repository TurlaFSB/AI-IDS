# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `ai-ids transfer`: score a different dataset (CSE-CIC-IDS2018 column names and labels are
  supported) with a saved model and fixed threshold, reporting threshold-free metrics, the
  stored-threshold result and an oracle re-calibrated upper bound (ADR 0011). No cross-dataset
  results have been produced yet.
- Scoring service (Flask, waitress): `/v1/score`, `/v1/alerts`, `/v1/stats`, `/metrics`, health
  and readiness probes, OpenAPI spec, bearer-key scopes, rate limiting, strict validation and
  security headers; a same-origin dashboard; `ai-ids serve` and `ai-ids replay`; ADR 0010, API
  reference and runbook.
- Time-block bootstrap confidence intervals (recall, false-positive rate, precision) in every
  report, `ai-ids seeds` for multi-seed spread, and `fusion_mean` / `fusion_max` score-fusion
  detectors (ADR 0009).

### Results
- Host-level analysis of the augmented gradient-boosting false positives recorded (99.8% from two
  scan-like hosts).
- First full-data run of bootstrap intervals, three-seed spread and score fusion recorded; fusion
  showed no clear gain over the augmented Random Forest (ADR 0009).

### Changed
- Evasion-aware training is now symmetric (perturbed copies drawn from benign and attack flows alike)
  and trains on forward-only padding by default; the first attack-only design is documented as having
  failed its benign control and remains reproducible via `configs/robustness_attack_only.yaml`.
- The evasion analysis now applies every perturbation to benign flows as a control, and adds
  forward-only padding (consistent with whole-flow statistics, validated against packet-level
  simulation) and random per-flow forward padding as perturbation types never used in training.
- Packet-size padding in the evasion analysis is now self-consistent (totals, byte rates and
  averages move with the per-packet lengths); earlier numbers used a partial transformation and
  are superseded.

### Fixed
- A typing error in the padding code that only appeared on Python 3.11 (CI caught it); the code is
  simplified and `scripts/check_matrix.sh` now runs the CI gates on every supported version locally.
- Dates in CICIDS2017 files are day-first; they were parsed month-first, which mislabelled capture
  days in reports (chronological order was unaffected). Parsing is now day-first by default
  (`timestamp_dayfirst`).

### Added
- Real-run results for symmetric evasion-aware training: the Random Forest keeps clean accuracy and
  recovers recall under padding and slowing (0.51 to 0.96-0.99) with no increase in benign false
  positives; gradient boosting gains robustness at a large clean false-positive cost.
- Results of standard versus evasion-aware training, and the gradient-boosting host analysis, in the
  README and model card (preliminary until the benign controls are reported).
- Evasion-aware training (ADR 0008): `random_forest_aug` and `hist_gradient_boosting_aug` train on
  perturbed copies of attack flows using magnitudes disjoint from the evaluation ones;
  `configs/robustness.yaml` compares them with the standard detectors.
- Four-detector results, host-level false-positive evidence and the evasion findings from the
  second real run in the README and model card.
- Autoencoder detector (scikit-learn MLP, CPU; ADR 0007) with training diagnostics in the report,
  and per-category recall in every report for like-for-like comparison of detectors.
- Leave-one-attack-family-out results from the first real run in the README and model card.
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
