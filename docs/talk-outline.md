# Talk outline: ten minutes

Working title: **"Fix the labels and the benchmark stops being easy: what a network IDS learns from an
honest evaluation."** Every figure comes from a run recorded in
[results-full.md](results-full.md); [results-summary.md](results-summary.md) is the one-page version
and `ai-ids report-html` builds the figures. Say "feature-space", "one dataset pair" and "ruleset 2"
out loud wherever they apply.

## Arc
A familiar benchmark number hides three problems. Each is measured, not asserted. Correcting the labels
fixes the first, exposes the other two, and one of our own fixes failed its control and one of our own
rule sets had errors that we found by reading the source; both are shown.

## Slides (about 10 minutes)

1. **The claim everyone makes (0:45).** Random Forest on CICIDS2017: recall 0.990, ROC-AUC 0.998.
   "Looks solved." Setup in one line: chronological per-class split, alert threshold calibrated for a
   1% false-positive rate, 2.5M flows after removing duplicates.
2. **The first crack: the false-alarm budget did not hold (1:00).** Target 1%, measured 8.1% (interval
   4% to 12%). 98.6% of false positives come from two hosts doing scan-like traffic. Bot recall is 0.
   Hypothesis: label noise. Lesson: report intervals and where errors concentrate.
3. **Testing the hypothesis: corrected labels, and our own mistake (2:15).** Re-implement the published
   attack timelines as rules. Then audit our rules against the authors' public labelling script, read as
   data and never run (`ai-ids relabel-check`): 51 rules, first port deviated in five places (a missing
   source port, a window that ran a minute long, an extra port exclusion, two extra "attempted" rules,
   packet counts 4/4 for 5/5). Fixed; every report now records the ruleset and analysis refuses to
   mix rule sets (a hole in our own check, found and closed the same day). Result under the audited
   rules: Random Forest false positives 8.1% to 1.29%, recall 0.9996 (seed spread under 0.002, measured under ruleset 1). Figure
   1: the false positives stop concentrating on two hosts (worst host 11.9% of them, measured under
   ruleset 1; re-read under ruleset 2 before presenting). Port-ablation
   control: dropping the destination port, which the rules use, changes recall by under 0.0005, so the
   gain is not a port shortcut. Caveat on the slide: the corrected test set is easier (99,638 hard
   "attempted" flows are dropped) and recall of 0.9996 means in-distribution is solved.
4. **Solved in-distribution, not elsewhere (2:15).** Figure 2: hold families out of training. Singly,
   pooled unseen recall looks like 0.86; hold out each family *with its relative* (DoS with DDoS, port
   scan with infiltration) and it is 0.75, DoS falling from 0.96 to 0.77. Botnet 0.51, brute force
   0.67, web attacks 0.19 (32 flows). Then transfer: train on 2017, score three truncated 2018 days with
   the threshold fixed. The original-label model ranked 2018 well (PR-AUC 0.90) and recalibrated to
   recall 0.83; the corrected-label model ranks it worse (PR-AUC 0.38) and no threshold rescues it
   (recall 0.05 at 1% false positives), and five small rule fixes moved its stored-threshold recall
   from 0.91 to 0.10: cross-dataset behaviour is fragile. Untested hypothesis: correcting the labels
   removed the payload-free beacon flows that 2018 Bot resembles.
5. **Evasion, and the defence that cheated (2:15).** Padding packets cut Random Forest recall from
   0.99 to 0.51. Train on padded attack copies and recall returns, but the benign control flags 24% to
   70% of padded benign flows: the model learned "padded means attack"; kept in the repo as a failed
   design. Redesign: perturb benign and attack alike. Then the same trap, found by the same control:
   the corrected-label model scores 0.9988 recall against a per-flow adversary, but 81.5% of benign
   flows are flagged under some reshaping. Figure 3: benign flags stay at 1.4% to 6.8% inside the
   trained range and jump to 28% to 72% past it. High adaptive recall measured "looks unlike training",
   not robustness. Feature-space only.
6. **What we built so it is checkable (0:45).** `scripts/reproduce_synthetic.sh` trains twice and fails
   unless the runs agree exactly (run by CI), hash-locked dependencies, SHA-pinned CI, digest-checked
   model artifacts, a scoring service with an ASVS L2 self-assessment (not independent), and a
   script-free results page with a hash-pinned content-security policy.
7. **Take-aways and what we did not show (0:30).** Four rules: report intervals and error
   concentration; audit your labels against their source, then audit your audit; put a control next to
   every robustness claim; test on a second dataset with the threshold fixed. Not shown: live traffic,
   packet-level or gradient adversaries, the authors' own corrected CSVs (their extractor differs), an
   untruncated 2018 set.

## Hard questions and honest answers
- *"Is your corrected-label port right?"* Audited against the authors' script: all 51 stated rules
  match literally after five fixes. Not verified: packet-count conditions (their extractor differs
  from the one that made the data), and agreement with their corrected CSVs, which would need their
  extractor and the raw captures. Mirrored rules and minute rounding are our adaptations.
- *"Is 0.9996 recall real?"* It is a measurement on an easier, cleaner test set (hard "attempted" flows
  dropped); it says nothing about other networks or unseen attacks, which the next slides show.
- *"Why did transfer get worse after fixing the labels?"* Not established. Seeds do not explain it
  (spread is tiny in-distribution) but transfer has not been repeated over seeds. Untested hypothesis:
  the dropped beacon-style flows.
- *"Is the destination port a shortcut?"* Ablation says no for the large classes; two classes with
  fewer than a dozen test flows (infiltration, SQL injection) lose recall without it.
- *"Why not deep learning?"* A CPU autoencoder (recall 0.153) and Isolation Forest (0.040) were far
  worse on this data (ADR 0001, 0007). A GPU model is future work.
- *"Is the evasion defence adaptive-attacker proof?"* No. Its high adaptive recall comes with 81.5%
  benign flags under reshaping. Packet-level and gradient attacks are not evaluated.
- *"Did you tune on the 2018 data?"* No. The threshold was fixed beforehand; oracle and local
  calibration are labelled as what they are.
- *"Fusion?"* Tried; no clear gain (ADR 0009), reported as a negative result.

## Backup slides
Per-category recall table; per-hour false-positive rates; block-bootstrap method; the threshold tie
plateau; the rule audit table (ADR 0013); grouped leave-out members; the replay demo.

## Before presenting
Rebuild the figures from the report files (`ai-ids report-html`), confirm each number against them, and
read the per-category recall of the ruleset 2 model (Bot recall under ruleset 2 is not yet read).
Re-run the synthetic reproduction from a clean checkout.
