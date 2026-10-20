# 0004. Alert threshold calibrated to a target false-positive rate

Status: Accepted (2026-10-20)

## Context
Security teams are limited by alert volume. A model's default decision boundary says nothing
about how many benign flows it will flag, and accuracy on imbalanced traffic is misleading.

## Decision
Choose the threshold as the benign validation-score quantile for the target FPR (default 1%),
using a method that never interpolates below the empirical quantile so validation FPR is bounded
by the target. Report test metrics at several operating points.

## Consequences
- Operators pick an alert budget and see the resulting recall.
- The threshold is chosen without looking at attacks or test data.
- Test FPR is measured, not assumed, and may differ from the target under distribution shift.
