# 0008. Evasion-aware training by symmetric flow augmentation

Status: Accepted (2026-10-20); redesigned after the first design failed its control;
redesign validated on real data (single seed, feature space)

## Context
The evasion-sensitivity analysis showed the Random Forest depends on absolute packet sizes: adding
64 bytes to every packet cut recall from 0.990 to 0.513 in feature space (port scan 0.997 to 0.014,
web attacks 0.987 to 0.076). A detector an attacker can defeat by padding is of limited value, so
robustness to such reshaping is part of the contribution.

## First design and why it failed
`random_forest_aug` and `hist_gradient_boosting_aug` first trained on the normal training split
plus perturbed copies of a random half of the **attack** flows, padded in both directions.
Recall under padding rose (Random Forest 0.51 to 1.00; gradient boosting 0.47 to 0.99 at 64 bytes),
but the evasion report's control, applying the same perturbation to benign flows, exposed the
flaw: the augmented Random Forest flagged 24%, 50% and 70% of benign flows padded by 64, 256 and
1,024 bytes (clean rate 7.1%). Perturbing only attacks makes "perturbed" a label signal, and the
model learned it. Gradient boosting also paid with its clean false-positive rate (0.26% to 3.1%).
This design is kept reproducible as `configs/robustness_attack_only.yaml` (`mode: attack_only`).

## Decision
Augment **symmetrically**: perturbed copies are sampled uniformly from all training flows, so
perturbed benign and perturbed attack flows appear in the proportions of the training data and the
perturbation carries no information about the label. Train on **forward-only padding** (what an
attacker can actually control; whole-flow statistics are recomputed, validated against packet-level
simulation in the tests) and slowdowns.

- Training magnitudes (slowdown 3x and 7x; padding 32, 128, 512 bytes) differ from evaluation
  magnitudes (2x, 5x, 10x; 64, 256, 1,024 bytes); a test enforces that they are disjoint.
- Padding of both directions, the combined perturbation and random per-flow forward padding are
  never trained on, so the evaluation always contains unseen perturbation types.
- The evasion report applies every perturbation to a sample of benign flows, so a shortcut shows
  up as a high benign false-positive rate rather than as spurious robustness.
- Calibration and evaluation are identical to the standard detectors, so they are directly
  comparable (`configs/robustness.yaml`).

## Consequences
- Clean-data accuracy may change, and robustness may cost false positives; both are reported.
- This addresses the perturbation families modelled (timing, packet size). It does not prove
  robustness to other or adaptive attacks, and the analysis remains feature-space.
- The lesson stands as part of the project: evasion defences must be evaluated against perturbed
  benign traffic, not only perturbed attacks.

## Results of the redesign

Real run (`configs/robustness.yaml`, test split). The Random Forest with symmetric augmentation keeps
its clean accuracy (recall 0.990, FPR 0.080) and its recall under perturbation matches or nears it:
forward padding 0.990, padding of both directions (never trained on) 0.96-0.98 against 0.51 for the
plain model, slowing 10x 0.978 against 0.950. Benign flows flagged under perturbation stay at or
below the clean rate, so the shortcut of the first design is absent. Gradient boosting becomes robust
to slowing and forward padding, improves on the unseen type (0.47 to 0.72), but its clean false-positive
rate rises from 0.26% to 7.0%, probably because it no longer depends on packet sizes and flags the
mislabelled scan traffic (to be verified).

Limits: feature-space transformations, one seed, perturbation families chosen by us. The conclusion
is that symmetric augmentation removes the specific weakness measured, not that the detectors are
robust to adaptive adversaries.
