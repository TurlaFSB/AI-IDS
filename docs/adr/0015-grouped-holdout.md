# 0015. Grouped leave-out for unseen-family evaluation

Status: Accepted (2026-10-23)

## Context
Leave-one-family-out (ADR 0009 and the model card) estimates detection of attacks the model has not seen.
On the corrected labels the pooled unseen recall rose from 0.27 to 0.88, but the corrected classes put
close relatives into training: a large infiltration-scan class beside port scan, and a bigger DDoS class
beside DoS. A held-out family with a near-identical relative still in training is not unseen, so the
single-family number overstates generalisation exactly where it improved.

## Decision
`ai-ids holdout --group CAT,CAT` (repeatable) and `holdout.groups` in the config remove every member of a
group from training together and report recall on the whole group, plus per-member recall and support.
Without groups the behaviour is unchanged. Groups must name existing attack categories and may not
overlap; invalid groups stop the run with exit status 2. The groups are chosen by the experimenter from
domain knowledge (DoS with DDoS; port scan with infiltration scan), not from the results, and the
choice is recorded in the report (`grouped: true`, group names such as `dos+ddos`).

## Consequences
- The grouped number is a stricter estimate than the single-family one; both are reported.
- Whether two families are "related" is a judgement. The documentation states the grouping used, and a
  grouping that happens to give a flattering number is not to be chosen after the fact.
- Per-member recall inside a group shows when one member carries the group's recall.
