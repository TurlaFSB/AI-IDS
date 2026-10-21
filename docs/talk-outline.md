# Talk outline: ten minutes

Working title: **"99% recall, 8% false alarms, and a defence that cheated: what a network IDS
learns from an honest evaluation."** Every figure comes from a run recorded in the
[README](../README.md) and the [model card](model-card.md); see
[results-summary.md](results-summary.md) for the one-page version. Say "feature-space" and "one
dataset pair" out loud wherever they apply.

## Arc
A familiar benchmark number is hiding three problems. Each one is measured, not asserted, and one
of our own fixes failed its control and is shown.

## Slides (about 10 minutes)

1. **The claim everyone makes (0:45).** Random Forest on CICIDS2017: recall 0.990, ROC-AUC 0.998.
   "Looks solved." Then: the split is chronological and thresholds target a 1% false-positive rate.
   Setup in one line: 2.52M flows after removing 308k duplicates, per-class time split.
2. **The first crack: the false-alarm budget did not hold (1:15).** Target 1%, measured 8.1%
   (interval 4% to 12%). 98.6% of false positives come from two hosts doing scan-like traffic;
   excluding them gives 0.14% (sensitivity analysis, not a result). The evidence points to
   mislabelled attack-adjacent traffic; we cannot prove it without verified labels. Lesson: report
   intervals and where errors concentrate, not one rate.
3. **The second crack: unseen attacks (1:00).** Leave-one-family-out recall 0.27 pooled against
   0.99 on known attacks; botnet 0.00. In-distribution recall mostly measures recognising the
   benchmark's tools.
4. **Evasion in feature space (1:15).** Padding packets cut Random Forest recall from 0.99 to 0.51.
   State the limit now: feature-space, one seed, modelled perturbations only.
5. **The centrepiece: the defence that cheated (2:15).** Train on padded attack copies: recall
   under padding rises to 1.000. The benign control (pad benign flows the same way) shows 24%,
   50% and 70% of padded benign flows flagged: the model learned "padded means attack". Redesign:
   perturb benign and attack flows alike. Result: recall under padding 0.96 to 0.99, benign flags
   not above the clean rate, no loss on clean data. Message: every robustness number needs a
   control that could have exposed a shortcut. Keep the failed design in the repo.
6. **Does it travel? Cross-dataset (1:45).** Models trained on 2017, scored on three 2018 days with
   the 2017 threshold fixed. Recall 0.085 (Random Forest) and 0.049 (gradient boosting) at under
   0.1% false positives: almost nothing alerts. Split the cause: gradient boosting ranks well
   (ROC-AUC 0.988) and a threshold set on the first 150,000 benign flows of the new network gives
   recall 0.830 at 0.26% false positives; the Random Forest's ranking is the problem (recall 0.127
   even with the best threshold). Takeaway: ship a recalibration step, and prefer scores that
   rank. Caveats on the slide: assumes a clean benign window, one model, one sample, 74% of the
   attacks are Bot.
7. **Where it still fails (0:45).** DoS reaches only about 0.48 on 2018 for both models whatever
   the threshold. Bot is missed on 2017 by every detector yet ranked almost perfectly on 2018
   (recall 0.956 with the local threshold); we do not yet know why (Bot study: see below).
8. **What we built so it is checkable (0:45).** Hash-locked dependencies, SHA-pinned CI, signed and
   digest-checked model artifacts, a scoring service with a dashboard (ASVS L2 self-assessment,
   not an independent one), 170+ tests. One screenshot of the dashboard, labelled synthetic data.
9. **Take-aways and what we did not show (0:45).** Three rules: report intervals and error
   concentration; put a control next to every robustness claim; test on a second dataset with the
   threshold fixed, then show recalibration separately. Not shown: live traffic, packet-level or
   adaptive attackers, corrected labels.

## Hard questions and honest answers
- *"Is the 8% just label noise?"* Possibly much of it. Two hosts produce 98.6% of it and look like
  scans, but no verified corrected labels exist here, so we call it supported, not proven.
- *"Why not deep learning?"* A CPU autoencoder was tried (recall 0.153, false-positive rate 0.074)
  and an Isolation Forest (recall 0.040); the supervised trees were far better on this data
  (ADR 0001, 0007). A GPU model is future work.
- *"Did you tune on the 2018 data?"* No. The threshold was fixed beforehand; the oracle and local
  calibration points are labelled as what they are, and the local one uses only the earliest
  benign slice.
- *"Is the evasion defence adaptive-attacker proof?"* No. It removes one measured weakness in a
  modelled perturbation family; adaptive and packet-level attacks are not evaluated.
- *"Single seed?"* Three seeds for the four main detectors: Random Forest recall varies by
  ±0.0003, augmented gradient boosting by ±0.015. The cross-dataset test is one seed.
- *"Fusion?"* Tried; no clear gain (ADR 0009), reported as a negative result.

## Backup slides
Per-category recall table; per-hour false-positive rates (35.1% on Thursday 15:00); block-bootstrap
method; threshold tie plateau (why the 1% target gave 0.26%); the replay demo.

## Before presenting
Re-run the numbers from a clean checkout and confirm each figure against its report file. The
Bot study (`ai-ids family`) is the one pending result for slide 7.
