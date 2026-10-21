# Results at a glance

One page. Every number is copied from a run recorded in the [README](../README.md) and the
[model card](model-card.md); where a number has an interval or a caveat, it is given here. All
results are CICIDS2017 only, a per-class chronological split (60/15/25), thresholds calibrated for a
1% false-positive rate on benign validation traffic, seed 42 unless a seed spread is shown.
Cross-dataset results do not exist yet.

## Data
3,119,345 flows loaded; 2,522,525 kept after removing 288,602 rows without a label and 308,218
duplicates. Test set 630,647 flows, 16.9% attacks.

## Headline: in-distribution detection looks strong, and mostly measures known tools

| Detector | Recall [95% CI] | False-positive rate [95% CI] | Precision | PR-AUC |
|---|---|---|---|---|
| Random Forest | 0.990 [0.968, 0.995] | 0.081 [0.040, 0.121] | 0.713 | 0.993 |
| Gradient boosting | 0.868 [0.657, 0.967] | 0.0026 [0.0007, 0.0052] | 0.985 | 0.988 |
| Random Forest, evasion-aware | 0.990 [0.970, 0.995] | 0.080 [0.040, 0.119] | 0.716 | 0.993 |
| Gradient boosting, evasion-aware | 0.988 [0.967, 0.993] | 0.070 [0.032, 0.109] | 0.742 | 0.976 |
| Isolation Forest | 0.040 | 0.034 | 0.195 | 0.354 |
| Autoencoder | 0.153 | 0.074 | 0.294 | 0.459 |

Intervals are 5-minute time-block bootstrap (2,000 resamples). Across three seeds the Random Forest
recall varies by ±0.0003 and false-positive rate by ±0.007; the augmented gradient boosting by
±0.015 and ±0.009. Score fusion (mean or max of the two evasion-aware models) showed no clear gain.

## Five findings

1. **The 1% false-positive target did not hold on later data.** Random Forest test rate 8.1%
   (interval 4% to 12%). 98.6% of its false positives come from two hosts doing scan-like traffic
   (999 and about 12,000 distinct destination ports); with those hosts excluded the rate is 0.14%
   (a sensitivity analysis, not a performance claim). The evidence points to mislabelled
   attack-adjacent traffic but cannot prove it without verified labels. Benign-feature drift (PSI)
   is small, so this is not broad distribution shift.
2. **Unseen attack families are mostly missed.** Leave-one-family-out recall is 0.27 pooled
   (0.32 averaged over six families) against 0.99 on known attacks; botnet 0.00, port scan 0.06.
   The unsupervised detectors do worse. In-distribution recall mostly measures recognition of the
   dataset's attack tools.
3. **Feature-space evasion works, and a naive defence fails its own control.** Padding every
   packet cut Random Forest recall from 0.99 to 0.51. Training on padded attack copies only
   "fixed" this by learning that padded means attack (24% to 70% of padded benign flows flagged),
   which is a failed design and is kept in the record (ADR 0008).
4. **Symmetric augmentation does work for the Random Forest.** Recall under padding returns to
   0.96 to 0.99 with no increase in benign flows flagged and no loss on clean data. For gradient
   boosting it costs the clean operating point (false-positive rate 0.26% to 7.0%), and 99.8% of
   that extra cost sits on the same two scan-like hosts.
5. **The Bot family is missed by every detector** (recall 0.00 on 490 test flows).

## What is not shown
- Any result on a second dataset or live traffic.
- Packet-level or adaptive-adversary evasion: the evasion work is feature-space, single-seed and
  covers only the perturbation families we modelled.
- Corrected labels: CICIDS2017's label problems are documented, and no verified corrected-label
  source has been applied.
- Seed spread for the evasion results or for fusion.

## Engineering, briefly
Hash-locked dependencies, SHA-pinned CI actions, digest-pinned non-root container, bandit,
pip-audit, Trivy and an SBOM in CI; 171 tests at 96.6% coverage on Python 3.11 to 3.13; model
artifacts are digest-checked (optionally HMAC-signed) before loading; a scoring service with a
dashboard and a replay client (ADR 0010) built against an ASVS L2 self-assessment, not an
independent one.
