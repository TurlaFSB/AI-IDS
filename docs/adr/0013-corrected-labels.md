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
- The port is audited against the authors' labelling script (section "Audit against the authors'
  script" below), not against their corrected CSVs, which come from their own repaired flow extractor
  and cannot be matched flow by flow to the original files. Unit tests pin its semantics (window
  conversion, minute flooring, reply direction, override order, payload filter, blank rows), and the
  report's label-change table is the check to read. Any disagreement with the authors' rules is a bug
  in this port, not a finding.
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

## Audit against the authors' script (2026-10-23)

Version 1 of the rule table was written before the authors' labelling script could be read (the
project's sandbox could not reach their site), from the papers and from memory, and this ADR and the
module docstring said it was "written from the published scripts". That overstated what had been
done. The script is a public notebook, `Labelling/CICIDS2017_labelling_fixed_CICFlowMeter.ipynb` in
`GintsEngelen/CNS2022_Code` (fetched 2026-10-23; SHA-256
`dd015b0a87b6beedcceef0ae06c42999d31a895c4723e724522aa80686841910`). It is not copied into this
repository (no licence was found in the files read). `ai-ids relabel-check --notebook <file>` reads
it as data (parsed with `ast`; nothing in it is executed), reduces each `label_flows(...)` call to
label, window, addresses, ports and payload condition, and compares those with the port. It does not
compare the `additional_filters` expressions semantically; those were read side by side by a person.

Result against version 1: 51 stated rules, 44 matching literally. Reading the rest found these
deviations of the port from the script, all fixed in ruleset version 2:

| Deviation in version 1 | Fix |
|---|---|
| Infiltration scan round 1 used source port 50122 only; the script uses 50122 and 50133 | both ports |
| That window ended at the next full minute; the script's end is 14:20:45 UTC | the script's start and end |
| Friday port-scan round 2 excluded flows from ports 0 and 35952 to 35958 in its first minute; the script has no such exclusion | one rule, as in the script |
| FTP-Patator had two extra "attempted" rules (one-way flows with payload but no reply, and the mirror); the script has three FTP rules | removed |
| Brute-force "attempted" artefact flows tested 4 forward and 4 backward packets; the script tests 5 and 5 | 5 and 5 |

After the fixes all 51 stated rules match literally. What remains different by design: reply-direction
(mirrored) rules for flows the original extractor split in two, window starts rounded down to the minute
(original timestamps have minute resolution), the authors' label "Botnet" being "Bot" in the original
data, and some conditions written as predicates instead of port lists. What remains unverified:

- Packet-count conditions (for example the 5/5 above and the 20, 150 and 282 thresholds) come from the
  authors' repaired extractor and may not mean the same on the original extractor's flows.
- Agreement with their corrected CSVs, which would need their extractor and the raw captures.
- The Wednesday-to-Friday filter expressions were compared by reading, not by a test.

Consequence for results: every corrected-label result recorded before 2026-10-23 used ruleset
version 1 and has to be re-run under version 2 (`train`, `holdout`, the ablation and the studies that
retrain). The reports now record `ruleset` per file, so a result states which rules produced it.
