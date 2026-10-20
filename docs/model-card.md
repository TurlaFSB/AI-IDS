# Model card

Status: **v0.1 baseline.** First real-data results below (default config, seed 42, commit
`5166bf2`). Treat them as provisional: see the limitations.

## Models

| Model | Type | Training data | Score |
|---|---|---|---|
| Random Forest (`random_forest`) | Supervised multi-class classifier (scikit-learn), class-balanced | Train split, all categories | 1 − P(benign) |
| Isolation Forest (`isolation_forest`) | Unsupervised novelty detector (scikit-learn), rank-transformed features | Train split, benign flows only | Negated isolation score |
| Gradient boosting (`hist_gradient_boosting`) | Supervised attack-vs-benign classifier (scikit-learn), balanced class weights, continuous scores (ADR 0005) | Train split, all categories | P(attack) |

## Intended use

Research and engineering baseline for flow-level intrusion detection on enterprise-style
traffic. Not validated for production deployment, safety-critical decisions, or traffic that
differs materially from the training distribution.

## Data

CIC-IDS-2017 labelled flows (see `docs/data-governance.md`). Pre-processing: label
normalisation, duplicate removal, non-finite values replaced and imputed with training
medians, identifiers excluded from features.

## Evaluation protocol

- Per-class chronological split (60% train, 15% validation, 25% test by default).
- Alert threshold set from benign validation scores at a target false-positive rate (default 1%).
- Reported: recall, precision, F1, false-positive rate, MCC, ROC-AUC, PR-AUC, per-attack recall
  with support, and single-thread scoring latency (p50/p95/p99).
- Results at several operating points (0.1%, 1%, 5% target FPR) are included in `report.json`.

## Results

Results below are for the Random Forest and Isolation Forest. The gradient-boosting detector was
added afterwards and has not yet been evaluated on real data.

Test set: 630,647 flows (106,485 attacks, 16.9%), after cleaning 3,119,345 rows to 2,522,525.
Thresholds calibrated for a 1% false-positive rate on benign validation flows.

| Metric | Random Forest | Isolation Forest |
|---|---|---|
| Recall | 0.990 | 0.040 |
| Precision | 0.713 | 0.195 |
| False-positive rate (measured on test) | **0.081** | 0.034 |
| F1 | 0.829 | 0.066 |
| MCC | 0.804 | 0.013 |
| ROC-AUC | 0.998 | 0.829 |
| PR-AUC | 0.993 | 0.354 |
| Macro recall, all attack types | 0.870 | 0.133 |
| Macro recall, types with >= 30 test flows | 0.901 | 0.096 |
| Latency, single flow, p50 / p95 / p99 | 13.3 / 15.3 / 16.7 ms | 18.3 / 26.7 / 32.7 ms |
| Latency, batch of 1,000, p50 | 30.6 ms | 28.1 ms |

Random Forest per-attack recall (test support): DDoS 0.998 (32,005); DoS Hulk 0.992 (43,213);
PortScan 0.997 (22,706); DoS GoldenEye 0.978 (2,573); DoS slowloris 0.994 (1,347); DoS
slowhttptest 0.992 (1,308); FTP-Patator 0.999 (1,485); SSH-Patator 0.984 (806); web brute force
0.997 (368); web XSS 0.976 (164); **Bot 0.000 (490)**; Infiltration 0.600 (10); SQL injection
0.667 (6); Heartbleed 1.000 (4). The last three are too small to interpret.

Isolation Forest detects slowhttptest (0.724) and, on 10 flows, infiltration (0.8); everything
else is below 0.15.

### Calibration under drift

| Target FPR (validation) | Random Forest, FPR on test | Isolation Forest, FPR on test |
|---|---|---|
| 0.1% | 0.0% (threshold saturates, nothing flagged) | 0.4% |
| 1% | 8.1% | 3.4% |
| 5% | 15.3% | 10.4% |

Later benign traffic differs from earlier benign traffic, so thresholds calibrated once on
validation data do not hold. Random Forest scores take only about 200 distinct values (share of
trees voting "attack"), which makes low-FPR operating points degenerate.

## Limitations and risks

- **Dataset artefacts:** CIC-IDS-2017 has documented labelling and flow-construction issues,
  and attacks were generated with a small set of tools, so models may learn tool signatures
  rather than general behaviour. Corrected-label support is planned.
- **Very small classes** (for example Heartbleed, Infiltration) have tiny test supports; their
  recall estimates are unreliable.
- **Distribution shift:** performance on other networks is unknown. Drift monitoring and
  retraining are planned.
- **Evasion:** an adaptive attacker can shape traffic to stay under the threshold; adversarial
  evaluation is not yet done.
- **Unseen attack types:** the Random Forest cannot detect attack families absent from training;
  the Isolation Forest can flag some but with lower precision.
- **Artifacts are pickle-based**; load only verified artifacts (see `docs/threat-model.md`).

## Maintenance

Retraining must beat the incumbent on held-out data before promotion (planned champion/challenger
workflow). Re-evaluate and update this card with every released model.
