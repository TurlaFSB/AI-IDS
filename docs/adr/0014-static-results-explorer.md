# 0014. A static results explorer instead of a results web app

Status: Accepted (2026-10-22)

## Context
The evidence behind the findings lives in JSON reports and Markdown. The live dashboard (ADR 0010)
monitors a scoring service; it does not show results. A conference audience and a reviewer both need
to see the results and trace each number to a run, without installing anything or trusting a server.

## Decision
`ai-ids report-html` builds one self-contained HTML page from saved reports (training
`report.json`, adaptive, leave-one-family-out and transfer outputs). It shows provenance (version,
commit, dirty flag, seed, label set, excluded features), headline results with bootstrap intervals,
a side-by-side comparison of runs, per-category recall with test supports, where false positives
concentrate, the adaptive-adversary frontier, unseen-family recall and transfer operating points.

- **No scripts, no network.** The page has no JavaScript and loads nothing. A Content Security Policy
  of `default-src 'none'` allows only the single inline style block, identified by its SHA-256 hash
  (no `unsafe-inline`), so a page built from untrusted report files still cannot execute code or make
  requests. Every dynamic value is HTML-escaped; a test injects a hostile label and checks the output.
- **Numbers are copied, not computed**, except the pooled and unweighted holdout means, which are
  labelled as computed in the page. Missing fields show "n/a" and absent sections are omitted.
- **Accessible by construction:** real tables with captions and column scope, values printed beside
  every bar, colour never the only encoding, light and dark themes, readable at phone width and in
  print.
- Small test supports (under 30) are flagged in the category table.

## Consequences
- The page can be published on any static host or attached to a talk; it needs no service to run.
- It is a view of the reports, not a source of truth: the reports and the documentation remain the
  record, and the page says to read the limitations before quoting a figure.
- Not built, deliberately: authentication, stored history and user management. They would add
  attack surface (ASVS) for no research value; the service dashboard stays an in-memory monitor.
