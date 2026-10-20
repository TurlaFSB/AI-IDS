# 0005. Add gradient boosting for continuous scores

Status: Accepted (2026-10-20)

## Context
The first real-data run (see the README results) showed the Random Forest score is the share of
trees voting "attack", so it takes only about as many distinct values as there are trees. Most
benign flows score exactly 0 or 1, so a threshold for a very low false-positive target saturates:
at a 0.1% target the threshold landed at 1.0 and nothing was flagged. Operating points are the
point of the tool, so the score needs to be fine-grained.

## Decision
Add a supervised attack-vs-benign `HistGradientBoostingClassifier` detector whose score is the
boosted probability of attack (continuous), trained with balanced class weights and a fixed
number of iterations (no internal early-stopping split). It implements the same scoring contract,
so calibration and metrics are unchanged. Detectors are selected by name in the experiment config.

## Consequences
- Low-FPR operating points become meaningful (to be verified on real data, not assumed).
- A binary model cannot name the attack type; the Random Forest remains for multi-class output.
- Training time grows with the number of selected detectors; configs can select a subset.
- Whether boosting also reduces false positives under temporal drift is an open question for
  the real-data run, not a claim.
