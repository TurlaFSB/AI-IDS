# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `ai-ids adaptive`: per-flow best-of-grid evasion adversary (timing and forward padding) with a
  benign control (ADR 0012). No results recorded yet.
- `ai-ids family`: descriptive comparison of one attack family across two datasets (which features
  separate it from benign traffic, whether directions agree, where a saved model's scores place it).
- `AI_IDS_TRUSTED_PROXIES`: rate limiting behind a reverse proxy keys on the proxy-appended client
  address instead of the proxy's own.
- Reports now include the validation false-positive rate actually achieved at the threshold and how
  many scores are tied there (the 1% target is unreachable when scores are tied).
- `ai-ids transfer --calibration-fraction`: calibrate on the earliest slice of the target's benign
  traffic and evaluate on later flows only, a leakage-free counterpart of the oracle point.
- `ai-ids transfer`: score a different dataset (CSE-CIC-IDS2018 column names and labels are
  supported) with a saved model and fixed threshold, reporting threshold-free metrics, the
  stored-threshold result and an oracle re-calibrated upper bound (ADR 0011). The first
  cross-dataset results are recorded under Results.
- Scoring service (Flask, waitress): `/v1/score`, `/v1/alerts`, `/v1/stats`, `/metrics`, health
  and readiness probes, OpenAPI spec, bearer-key scopes, rate limiting, strict validation and
  security headers; a same-origin dashboard; `ai-ids serve` and `ai-ids replay`; ADR 0010, API
  reference and runbook.
- Time-block bootstrap confidence intervals (recall, false-positive rate, precision) in every
  report, `ai-ids seeds` for multi-seed spread, and `fusion_mean` / `fusion_max` score-fusion
  detectors (ADR 0009).

### Results
- Adaptive evasion recorded: a per-flow adversary lowers recall from 0.99 to 0.52 (Random Forest) and
  0.90 (evasion-aware Random Forest); no benign shortcut (ADR 0012).
- Data-quality finding: the three CSE-CIC-IDS2018 day files used are truncated at Excel's row limit,
  so the cross-dataset results are a smoke test on partial files.
- Local calibration on the earliest benign slice of CSE-CIC-IDS2018 restores gradient-boosting
  recall from 0.049 to 0.830 on later flows (0.26% false-positive rate), matching the oracle.
- Per-category cross-dataset results recorded: gradient boosting ranks 2018 Bot almost perfectly
  (recall 0.956 with a target-calibrated threshold) but catches none with the stored 2017 threshold.
- First cross-dataset result (CICIDS2017 to CSE-CIC-IDS2018): a fixed 2017 threshold does not
  transfer; gradient boosting still ranks well, the Random Forest does not (ADR 0011).
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
- `ai-ids family` scored the model on every source flow, including ones it trained on, which made
  the source-side scores in-sample. The model is now scored on the held-out test split only, the
  report says which flows were scored, and it adds the categories the model assigns to the family.
- `ai-ids transfer` treated corrupted timestamps (CSE-CIC-IDS2018 contains flows dated 1970) as the
  start of the capture, so the local-calibration slice began in 1970. Timestamps before 2000 are
  now set to missing, counted in the report, and excluded from the calibration and evaluation
  slices. The calibration slice in the first run was still all benign and ended before any attack.
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
