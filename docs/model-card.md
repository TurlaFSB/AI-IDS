# Model card

Status: **v0.1 baseline.** First real-data results below (default config, seed 42, commit
`5166bf2`). Treat them as provisional: see the limitations.

## Models

| Model | Type | Training data | Score |
|---|---|---|---|
| Random Forest (`random_forest`) | Supervised multi-class classifier (scikit-learn), class-balanced | Train split, all categories | 1 − P(benign) |
| Isolation Forest (`isolation_forest`) | Unsupervised novelty detector (scikit-learn), rank-transformed features | Train split, benign flows only | Negated isolation score |
| Autoencoder (`autoencoder`) | Unsupervised reconstruction-error detector (scikit-learn MLP, 64-16-64 bottleneck, CPU; ADR 0007) | Train split, benign flows only (up to 300,000 sampled) | Mean squared reconstruction error |
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

The first table is the original Random Forest / Isolation Forest run. A second full run (below)
reproduces it exactly and adds the gradient-boosting detector and the autoencoder.

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

### All four detectors (second full run)

| Detector | Recall | Precision | FPR (test) | PR-AUC | Macro recall |
|---|---|---|---|---|---|
| Random Forest | 0.990 | 0.713 | 0.081 | 0.993 | 0.870 |
| Gradient boosting | 0.868 | 0.985 | 0.0026 | 0.988 | 0.578 |
| Isolation Forest | 0.040 | 0.195 | 0.034 | 0.354 | 0.133 |
| Autoencoder | 0.153 | 0.294 | 0.074 | 0.459 | 0.057 |

Per-category recall (test flows): botnet 490: 0.00 for all four. Brute force 2,291: RF 0.99, GB
0.92, IF 0.00, AE 0.00. DDoS 32,005: 1.00, 1.00, 0.07, 0.01. DoS 48,441: 0.99, 0.73, 0.04, 0.24.
Port scan 22,706: 1.00, 0.99, 0.00, 0.19. Web attacks 538: 0.99, 0.88, 0.00, 0.00. Heartbleed (4):
RF 1.00, others 0.00. Infiltration (10): RF 0.60, GB 0.00, IF 0.80, AE 0.10.

Gradient boosting meets its 1% target comfortably (0.26% measured), unlike the other detectors
(RF 8.1%, AE 7.4%, IF 3.4%). Because false-positive measurement depends on noisy labels (next
section), this does not by itself show that boosting is the better detector.

### Calibration under temporal shift

| Target FPR (validation) | Random Forest, FPR on test | Isolation Forest, FPR on test |
|---|---|---|
| 0.1% | 0.0% (threshold saturates, nothing flagged) | 0.4% |
| 1% | 8.1% | 3.4% |
| 5% | 15.3% | 10.4% |

Random Forest, per capture day at the 1% operating point (test split):

| Day (2017) | Benign flows | False-positive rate | Attack flows | Recall |
|---|---|---|---|---|
| Tue 4 July | 0 | n/a | 2,291 | 0.994 |
| Wed 5 July | 0 | n/a | 48,445 | 0.991 |
| Thu 6 July | 129,056 | **0.222** | 548 | 0.980 |
| Fri 7 July | 395,106 | 0.035 | 55,201 | 0.989 |

All test-set benign flows come from Thursday and Friday (benign traffic is split chronologically
across the week). By hour, the false-positive rate is 0.06% to 0.31% in every hour with at least 1,000 benign flows
except two:
**Thursday 15:00 (35.1%, 81,580 benign flows)** and **Friday 16:00 (17.0%, 65,462 benign flows)**;
Friday 15:00 is 4.1%. Two source hosts produce 98.6% of all false positives (`192.168.10.8`: 67.3%
of them, false-positive rate 43.9% among its benign test flows; `192.168.10.50`: 31.2%, rate 33.7%),
and the false positives' destination ports with the highest rates are rare ports scattered across
the range (five ports with 35-40 benign flows each have 80-89% of them flagged; port 1 has 71% of
102), which looks like scan traffic. Per-feature
Population Stability Index between training and test benign traffic shows no significant drift
(0 of 78 features above 0.25; 5 moderate, maximum 0.125, all on backward packet-length features).

**Interpretation (supported by the evidence below, not proven):** the concentration points to attack-adjacent flows
labelled benign (scanning from the compromised Thursday-afternoon infiltration victim, and the web
server's side of the Friday DDoS and port-scan traffic) rather than genuine benign behaviour, in
line with the labelling and flow-construction artefacts documented for CICIDS2017. The reported
8.1% therefore mixes real false alarms with label noise. `ai-ids analyze` reports the time window,
distinct ports and hosts of each top false-positive source, and the false-positive rate with the
top hosts excluded (a sensitivity analysis, not a performance claim).

Host-level evidence (`ai-ids analyze`, Random Forest): `192.168.10.8` produced 28,589 false
positives (67.3%) spread over **exactly 1,000 distinct destination ports and 11 hosts** between
2017-07-06 15:10 and 16:48, the signature of a default port scan; `192.168.10.50` produced 13,265
(31.2%) toward **12,450 distinct destination ports on 3 hosts** between 2017-07-06 15:23 and
2017-07-07 16:16, which a server does not initiate on its own and looks like the reverse-direction
view of attack connections. With the top 1, 2 and 3 hosts excluded the false-positive rate is
3.02%, 0.144% and 0.099% (a sensitivity analysis, not a performance claim). A detector that flags
these flows is penalised by the labels; one that ignores them is flattered.

Bot (490 test flows) is detected by none of the four detectors at the 1% operating point.

Random Forest scores take only about 200 distinct values (share of trees voting "attack"), which
makes low-FPR operating points degenerate (see ADR 0005).

### Generalisation to unseen attack families

Leave-one-attack-family-out (`ai-ids holdout`): a Random Forest (50 trees, light config) is
trained with one attack family removed, the threshold is set for 1% FPR on benign validation
flows, and recall is measured on the removed family. The Isolation Forest never sees attacks, so
its normal per-category recall is the comparable figure.

| Family (test flows) | Random Forest, family unseen | Isolation Forest |
|---|---|---|
| Web attacks (538) | 0.874 | 0.000 |
| DDoS (32,005) | 0.584 | 0.071 |
| Brute force, FTP/SSH-Patator (2,291) | 0.256 | 0.000 |
| DoS (48,441) | 0.150 | 0.040 |
| Port scan (22,706) | 0.055 | 0.001 |
| Botnet (490) | 0.000 | 0.000 |
| Unweighted mean | 0.320 | 0.019 |
| Pooled over flows | 0.266 | 0.040 |

For comparison, the same family-level model recognises known attacks at 0.99 recall. The
false-positive rate in these holdout runs was 5.4% to 8.3% on test (the label-noise-affected
figure discussed above). Caveats: 50 trees rather than 200, a single seed, and attack families
grouped at category level, so related families (for example DoS and DDoS) can help each other.

## Robustness to evasion (method)

Every report includes a feature-space evasion-sensitivity analysis: attack flows are transformed
(timing slowed by 2x, 5x, 10x; packet-size statistics padded by 64, 256, 1024 bytes; and one
combination) and recall is re-measured at the already-calibrated threshold. This is a
**sensitivity indicator, not a packet-level attack**: perturbations act on derived flow
features, assume the attacker can reshape them without breaking the attack, and touch only
features present in the data. The 1,024-byte padding is not capped at the 1,500-byte Ethernet MTU.

Results, Random Forest at its calibrated threshold (baseline recall 0.990):

| Perturbation | Recall |
|---|---|
| Slow down 2x / 5x / 10x | 0.979 / 0.965 / 0.950 |
| Pad every packet by 64 / 256 / 1,024 bytes | 0.513 / 0.531 / 0.508 |
| Slow down 5x and pad 256 bytes | 0.599 |

Per family at 64 bytes (baseline in brackets): port scan 0.014 (0.997), web attacks 0.076 (0.987),
DDoS 0.585 (0.998), DoS 0.690 (0.991), brute force 0.933 (0.994), botnet 0.000 (0.000). The model
relies on absolute packet sizes. Gradient boosting behaves similarly (0.868 clean; 0.466, 0.460,
0.415 at 64, 256, 1,024 bytes) and is less robust to slowing (0.858, 0.835, 0.785 at 2x, 5x, 10x).

### Evasion-aware training (ADR 0008)

**First design (attack flows only, padding of both directions): failed its control.** Augmented
models trained on perturbed copies of half the attack flows. Recall under padding rose, but the
control (the same perturbation applied to a sample of 100,000 benign test flows) showed why.
Attack recall and benign false-positive rate (FPR) at each detector's calibrated threshold:

| Detector | Clean | Pad both directions 64 / 256 / 1,024 B | Forward-only pad 64 / 256 / 1,024 B | Slow 2x / 5x / 10x |
|---|---|---|---|---|
| Random Forest, recall | 0.990 | 0.513 / 0.531 / 0.508 | 0.567 / 0.591 / 0.547 | 0.979 / 0.965 / 0.950 |
| Random Forest, benign FPR | 0.083 | 0.000 / 0.003 / 0.001 | 0.011 / 0.008 / 0.001 | 0.083 / 0.083 / 0.085 |
| RF aug (attack-only), recall | 0.992 | 1.000 / 1.000 / 1.000 | 0.995 / 0.995 / 0.995 | 0.992 / 0.991 / 0.976 |
| RF aug (attack-only), benign FPR | 0.071 | **0.242 / 0.502 / 0.704** | 0.070 / 0.112 / 0.163 | 0.080 / 0.115 / 0.155 |
| Gradient boosting, recall | 0.868 | 0.466 / 0.460 / 0.415 | 0.517 / 0.508 / 0.534 | 0.858 / 0.835 / 0.785 |
| Gradient boosting, benign FPR | 0.003 | 0 / 0 / 0 | 0 / 0 / 0 | 0.002 / 0.020 / **0.036** |
| GB aug (attack-only), recall | 0.900 | 0.992 / 0.941 / 0.633 | 0.742 / 0.751 / 0.760 | 0.892 / 0.887 / 0.876 |
| GB aug (attack-only), benign FPR | 0.031 | 0.063 / 0.071 / 0.090 | 0.006 / 0.008 / 0.006 | 0.040 / 0.056 / 0.056 |

Reading it: the augmented Random Forest's perfect recall under padding of both directions is a
shortcut, because it flags 24% to 70% of padded benign flows; "perturbed means attack" is exactly
what attack-only augmentation teaches. On forward-only padding (the attacker-controlled direction,
never trained on) the gains are real but modest and costly: Random Forest recall 0.57 to 0.995 while
benign FPR rises with padding (7.0% to 16.3%), and gradient boosting recall about 0.52 to 0.75 with
no rise in benign FPR but a clean FPR of 3.1% instead of 0.26%. The plain Random Forest's benign FPR
falls to about zero under padding: its false alarms depend on packet sizes too. Plain gradient
boosting is hurt by slowing flows, which makes benign flows resemble slow DoS (benign flagged 3.6%
at 10x).

**Redesign (pending results).** Copies are drawn from benign and attack flows alike, so a flow being
perturbed carries no label information, and training uses forward-only padding plus slowdowns, so
padding of both directions, the combined perturbation and per-flow random padding are never
trained on. Same evaluation, benign control included. Results are not yet available.

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
