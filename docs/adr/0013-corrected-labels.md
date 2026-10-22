# 0013. Corrected CICIDS2017 labels, re-derived from published attack timelines

Status: Accepted (2026-10-21); relabel run recorded, retraining pending

## Context
The model card has said since the first real run that much of the false-positive rate may be label
noise: two hosts produce almost all false positives, and they behave like scanners. That was a
hypothesis with no independent source. Engelen, Rimmer and Joosen (IEEE SPW 2021) and Liu, Engelen,
Lynar, Essam and Joosen (IEEE CNS 2022) audited CICIDS2017 and published labelling scripts built from
the actual attack timelines (windows, attacker and victim addresses, ports, payload conditions).
Rebuilding their corrected dataset from the raw captures needs the PCAPs (tens of gigabytes), their
modified flow extractor and their scripts, which this project cannot run on a laptop.

## Decision
- `ai_ids.data.relabel` re-implements their labelling *rules* as data: per capture file, an ordered
  list of rules (window, addresses, ports, payload and packet conditions). Later rules override
  earlier ones and unclaimed flows are benign, as in the published scripts. The code is our own
  (the repository carries no licence file) and the rules are facts about the capture; the paper is
  cited.
- It corrects labels on the **original** CICFlowMeter flows. The authors also repaired the flow
  extractor, which changes the flows; that part is not reproduced, so this isolates the labelling
  correction only.
- Attack windows are UTC while the capture timestamps are local (UTC-3); windows are shifted.
  Sanity checks that did not require running anything on the data: the FTP-Patator window converts to
  09:17-10:20 local, matching the dataset's own documented 09:20-10:20, and the scan from
  `192.168.10.8` converts to 15:05-15:46, the window in which our models' false positives cluster.
- Flows inside an attack's timeline that carry no attack payload ("attempted" flows) are neither clean
  benign traffic nor an attack to detect, so the loader drops them and reports the number.
- `corrected_labels: true` in the config switches it on for loading, training and analysis;
  `ai-ids analyze` refuses a model trained with the other label set, because the flows in each split
  would differ. `ai-ids relabel` writes the old-versus-new label table without training anything.
- `configs/corrected.yaml` repeats the evasion-aware configuration with corrected labels.

## Consequences
- The headline question becomes testable: with the corrected labels, do the two hosts' false
  positives become true positives, and what do recall, false-positive rate and the unseen-family
  results look like? Retraining is required; re-scoring an old model on corrected test labels would
  put flows it trained on into the new test set.
- The port was written from the published scripts and has not been checked against the authors'
  corrected CSVs. Unit tests pin its semantics (window conversion, minute flooring, reply direction,
  override order, payload filter, blank rows), and the report's label-change table is the check to
  read. Any disagreement with the authors' files is a bug in this port, not a finding.
- Only the original CICIDS2017 capture files have rules. Other datasets are refused.
- 2018 labels are not covered; the 2018 files we used are also truncated (ADR 0011).

## Outcome (first relabel run, original CICIDS2017 files, 3,119,345 flows)
2,918,597 flows keep their label; 101,084 benign flows become attack (65,638 in the Thursday
infiltration file, 31,339 in the Friday DDoS file); 25 attack flows become benign; 1 changes attack
type; 99,638 are dropped as attempted (86,336 of them on Wednesday). The totals reconcile exactly.
The scan from `192.168.10.8` becomes the `infiltration_portscan` class (40,306 flows after cleaning)
and web attacks shrink to about 117 flows. Of 1,966 raw Bot flows, 1,472 stay Bot, 4 become benign
and 490 are dropped as attempted (flows after the documented Bot window ends), the same count as the
held-out Bot test set, so that set probably consisted of attempted flows; not confirmed until a model
is evaluated on the corrected labels. Whether these counts agree with the authors' corrected
CSVs is not checked; retraining on the corrected labels has not been done.

## Shortcut check

The rules use time windows, addresses and ports, and destination port is also a model feature, so a
model could reach near-perfect recall by learning the rules. `configs/ablation.yaml` retrains
without `destination_port` (`exclude_features`). Result (docs/results-full.md): recall changes by at most 0.0005
and the false-positive rate by 0.0003 to 0.0023, so the port is not the source of the corrected-label
results; other features could still act as proxies, and macro recall falls for gradient boosting.
