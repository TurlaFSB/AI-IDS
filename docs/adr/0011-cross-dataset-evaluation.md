# 0011. Cross-dataset evaluation without refitting

Status: Accepted (2026-10-20); first results recorded (README)

## Context
Every result so far comes from one dataset, CICIDS2017, which has few attack tools, known label
noise and one lab network. The leave-one-family-out test already shows that supervised detectors
transfer poorly to unseen attack families; the open question a reviewer will ask is how a trained
model behaves on traffic from a different capture. The follow-on dataset, CSE-CIC-IDS2018, comes
from the same lab and, as far as the published column lists show, the same flow-feature extractor
under abbreviated column names, so the same model can score it without retraining.

## Decision
- `ai-ids transfer` loads a saved, integrity-checked detector and scores a second dataset. Nothing
  is refitted and the alert threshold is the one fixed at training time.
- Column names are aliased to the CICIDS2017 names and the 2018 labels are added to the taxonomy.
  If any feature the model needs is still absent the command fails and lists the missing features
  and the unmatched target columns; `--allow-missing-features` imputes them from training medians
  and records which, as a weaker comparison. The alias map was written from published column
  lists and has not been checked against every file; the failure message is the safety net.
- Repeated header rows inside the data (present in the 2018 files) are dropped and counted.
- The report separates causes of any drop: threshold-free metrics (ROC-AUC, PR-AUC) show ranking
  quality; the stored-threshold point shows deployment behaviour; an **oracle** point re-calibrated
  on the target's own benign labels shows how much recalibration could recover. The oracle point
  uses target labels, so it is an upper bound and is labelled as such.
- Timestamps use a 24-hour clock for the target (the 12-hour repair for 2017 is off by default).
  Large targets can be sampled (`--max-rows`, seeded); the sample size is recorded.

## Consequences
- The headline number is the drop from in-distribution to cross-dataset performance, reported
  with block-bootstrap intervals and without tuning on the target.
- Differences in label definitions, attack tools and network layout are confounded with
  distribution shift; a drop cannot be attributed to a single cause from this test alone.
- Attack categories absent from the target, or only in it, are reported with their support and
  not compared.
- The 2018 files have no source or destination addresses, so host-concentration diagnostics are
  unavailable for the target.

## Outcome (first run)
The column aliases matched all 78 model features on three real 2018 day files. A threshold fixed on
2017 failed to transfer for both models tested (recall below 0.09); the oracle point separated the
causes: gradient boosting still ranked well and would recover to 0.83 recall, the Random Forest did
not (0.127). Numbers and caveats are in the README.

## Addendum: local calibration
The oracle point uses all target benign labels, including those of the flows it is evaluated on, so
it cannot be deployed. `--calibration-fraction F` adds a leakage-free counterpart: the threshold is
set from benign flows in the earliest fraction F of the target (by time) at the training false-
positive target, and every reported metric is computed on the later flows only; the stored
threshold is reported on the same later flows. It assumes an operator can obtain a labelled-benign
or confidently-benign window from the new network, which is plausible but is an assumption. The
early slice also differs in attack mix from the later flows when the target spans several days, and
that is stated in the report. Flows with
implausible timestamps (before 2000; the 2018 files contain some dated 1970) are set to missing,
counted, and excluded from both slices.
