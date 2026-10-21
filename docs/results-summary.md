# Results at a glance

One page. Every number is copied from a run recorded in the [README](../README.md) and the
[model card](model-card.md); where a number has an interval or a caveat, it is given here. All
results are CICIDS2017 only, a per-class chronological split (60/15/25), thresholds calibrated for a
1% false-positive rate on benign validation traffic, seed 42 unless a seed spread is shown.
One cross-dataset test (2017 to 2018) is reported below; live-traffic results do not exist.

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
5. **Bot has recall 0 at the calibrated threshold in every detector on 2017** (490 test flows), yet
   it ranks above most benign traffic (held-out AUC 0.86 Random Forest, 0.90 gradient boosting). On
   2018 Bot (56,578 flows in the sample) gradient boosting ranks it almost perfectly (recall 0.956
   with a threshold set on the target's benign traffic) while its stored 2017 threshold catches
   none; the Random Forest labels 100% of it benign. The two datasets disagree on what separates
   Bot (feature-effect rank correlation 0.32; forward packet size flips direction), and the strongest
   2018 feature is a flag column duplicated in the files. Why gradient boosting ranks 2018 Bot well
   is not established.
6. **A threshold fixed on 2017 does not transfer to 2018.** On three CSE-CIC-IDS2018 days
   (1,000,000-flow sample, 7.7% attacks) the evasion-aware Random Forest keeps recall 0.085 and
   gradient boosting 0.049 at false-positive rates of 0.05% and 0.01%. Gradient boosting still
   ranks well (PR-AUC 0.898) and would reach recall 0.83 at 0.26% false positives with a threshold
   set on the target's benign labels; the Random Forest ranks
   poorly (PR-AUC 0.506; recall 0.127 even with that threshold). DoS reaches only about 0.48 for
   both models even then. The recalibration is deployable: a threshold set from the earliest
   150,000 benign flows of the target (before any attack) gives gradient boosting recall 0.830 at a
   0.26% false-positive rate on the later flows, matching the oracle, if an operator can get a
   clean benign window. Two models, one seed, an attack mix that is 74% Bot.

7. **A per-flow adaptive adversary still costs the evasion-aware model about ten points.** Allowed
   to pick, per flow, any of 30 slowdown and forward-padding combinations, an attacker cuts the plain
   Random Forest from 0.99 to 0.52 recall and the evasion-aware one from 0.99 to 0.90; the benign
   control shows no "perturbed means attack" shortcut (9.9% of benign flows flagged under the worst
   combination against 8.3% clean). The aggregate hides the family picture: web attacks fall from
   0.97 to 0.02 recall (about 90 of 93 sampled flows to 2) and DoS from 0.99 to 0.80, while DDoS
   and port scan barely move. Slowing flows up to 30x alone costs 3 points; at most 32 bytes of
   padding on top costs another 4.5. Feature-space only, one seed, a 20,000-flow sample per class.

## What is not shown
- Live-traffic results, and cross-dataset results beyond the two models, three days and one seed above.
- Packet-level evasion, or an adversary with gradients or a larger budget: the evasion work is
  feature-space, single-seed and covers only the modelled reshaping.
- A clean cross-dataset benchmark: the three CSE-CIC-IDS2018 files used are truncated at Excel's row
  limit (1,048,575 rows each), so the 2018 attack mix is partial.
- Corrected labels: CICIDS2017's label problems are documented, and no verified corrected-label
  source has been applied.
- Seed spread for the evasion results or for fusion.

## Engineering, briefly
Hash-locked dependencies, SHA-pinned CI actions, digest-pinned non-root container, bandit,
pip-audit, Trivy and an SBOM in CI; 171 tests at 96.6% coverage on Python 3.11 to 3.13; model
artifacts are digest-checked (optionally HMAC-signed) before loading; a scoring service with a
dashboard and a replay client (ADR 0010) built against an ASVS L2 self-assessment, not an
independent one.
