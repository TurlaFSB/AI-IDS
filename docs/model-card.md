# Model card

Status: **v0.1 baseline. Real-data results pending.** Numbers must come from an actual run on
CIC-IDS-2017 (`ai-ids train`); none are reported here until then.

## Models

| Model | Type | Training data | Score |
|---|---|---|---|
| Random Forest (`random_forest`) | Supervised multi-class classifier (scikit-learn), class-balanced | Train split, all categories | 1 − P(benign) |
| Isolation Forest (`isolation_forest`) | Unsupervised novelty detector (scikit-learn), rank-transformed features | Train split, benign flows only | Negated isolation score |

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

Pending the first run on real data.

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
