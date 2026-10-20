# 0008. Evasion-aware training by attack-flow augmentation

Status: Accepted (2026-10-20); first results below, controls pending

## Context
The evasion-sensitivity analysis showed the Random Forest depends on absolute packet sizes:
adding 64 bytes to every packet cut recall from 0.990 to 0.513 in feature space (port scan 0.997
to 0.014, web attacks 0.987 to 0.076). A detector that an attacker can defeat by padding is of
limited value, so robustness to such reshaping is part of the contribution, not an extra.

## Decision
Offer evasion-aware variants of the supervised detectors (`random_forest_aug`,
`hist_gradient_boosting_aug`). Their training set is the normal training split plus perturbed
copies of a random half of its attack flows, each copy slowed down or padded once.

- Benign flows are never modified, so the benign distribution that thresholds are calibrated on
  is unchanged.
- Training magnitudes (slowdown 3x and 7x; padding 32, 128 and 512 bytes) deliberately differ
  from evaluation magnitudes (2x, 5x, 10x; 64, 256 and 1,024 bytes), so robustness is measured
  on perturbations the model never trained on. A test enforces that the grids are disjoint.
- Calibration and evaluation are identical to the standard detectors, so the two are directly
  comparable (`configs/robustness.yaml` trains standard and augmented variants side by side).

## Consequences
- Clean-data recall and false-positive rate may change; the report shows both, and the trade-off is
  reported whichever way it goes.
- This defends against the specific perturbation families modelled (timing and packet size). It
  does not prove robustness to other or adaptive attacks, and the analysis remains feature-space.
- Augmentation can only help against reshaping the analysis can express; adaptive attacks need
  packet-level evaluation (roadmap).

## First results and controls

First real run: augmentation raised recall under padding from 0.51 to 1.00 (Random Forest) and from
0.47 to 0.99 / 0.94 / 0.63 at 64 / 256 / 1,024 bytes (gradient boosting), but gradient boosting's
false-positive rate rose from 0.26% to 3.1%, and the Random Forest's recall of exactly 1.000 at every
magnitude, including one beyond the training range, suggests it may flag anything padded.

Controls added in response: the evasion report applies each perturbation to a sample of benign
flows and reports the false-positive rate under perturbation; and it evaluates forward-only padding
(the attacker-controlled direction, recomputing whole-flow statistics, validated against
packet-level simulation in the tests) and random per-flow forward padding, neither of which is used
in training. The decision to keep this approach depends on those results.
