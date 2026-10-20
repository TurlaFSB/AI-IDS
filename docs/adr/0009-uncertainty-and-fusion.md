# 0009. Block-bootstrap uncertainty, multi-seed studies and score fusion

Status: Accepted (2026-10-20); results pending

## Context
Every number reported so far comes from one seed and one fixed chronological split, with no
uncertainty attached. Two sources of uncertainty matter and need different treatment:
- **Model randomness** (forest sampling, augmentation sampling, initialisation). The split is
  deterministic, so this is measured by repeating training with different seeds.
- **A finite, clustered test set.** Flows from one attack run or one busy minute are strongly
  correlated; resampling individual flows would badly understate uncertainty.

Separately, the two robust detectors (Random Forest and gradient boosting, both trained with
symmetric evasion-aware augmentation, ADR 0008) behave differently on ordinary traffic and on the
attack-adjacent traffic, so combining them is a natural candidate.

## Decision
1. **Time-block bootstrap.** Every evaluation reports 95% percentile intervals for recall,
   false-positive rate and precision by resampling whole 5-minute blocks of the test set with
   replacement (2,000 resamples). Intervals are wide when a class sits in few blocks, which is the
   honest answer; tests cover that case.
2. **`ai-ids seeds`.** Trains each configured detector once per seed and reports mean, standard
   deviation, minimum and maximum of the headline metrics and of recall and benign false-positive
   rate under selected perturbations. The report states that this spread reflects model
   randomness only.
3. **Score fusion.** `fusion_mean` and `fusion_max` wrap already-fitted detectors. Each
   component score is mapped to the fraction of benign reference scores it exceeds, then combined
   by mean (alerts need broad agreement) or max (any component can alert). The percentile map is
   fitted on one interleaved half of the benign validation rows and the alert threshold is
   calibrated on the other half, so the two never share rows. Fusion is evaluated exactly like a
   single detector, evasion analysis and benign control included.

## Consequences
- Claims can be stated with intervals, and single-seed luck can be ruled out or confirmed.
- Block bootstrap treats blocks as exchangeable, which is an approximation for a time series with
  drift; it captures clustering, not non-stationarity.
- Fusion adds model size (components are stored with the fused artifact) and needs validation
  data; whether it helps is empirical and reported either way.
- Seed studies are expensive (one full training per seed per detector).
