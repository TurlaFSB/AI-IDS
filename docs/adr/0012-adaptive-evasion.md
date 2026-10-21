# 0012. Adaptive evasion in feature space

Status: Accepted (2026-10-21); no results yet

## Context
The evasion results so far apply one fixed perturbation to every attack flow ("pad by 64 bytes").
A real adversary picks, per flow, whichever reshaping scores lowest, so fixed perturbations can
overstate robustness. Packet-level evaluation would be stronger still, but it needs real packet
captures and the original flow extractor (the CICIDS2017 captures are tens of gigabytes per day),
which this project cannot run on a laptop.

## Decision
`ai-ids adaptive` gives a per-flow adversary a grid of slowdown factors (1 to 30) and forward-
padding amounts (0 to 1,460 bytes), scores every combination with the saved model, and keeps each
flow's lowest score. It reports clean recall, adaptive recall, a frontier of recall against how
much slowing and padding the adversary may use, per-family results, and a benign control (the share
of benign flows flagged under any combination, which would reveal a "perturbed means attack"
shortcut). The grids must start at the identity so the clean point is always included. The data and
split are verified against the model exactly as `analyze` does.

## Consequences
- This narrows, but does not close, the adaptive-attacker caveat. The adversary still acts on
  derived features, not packets; it only reshapes timing and forward packet size; the transformations
  assume the attack still works after reshaping; and the grid is coarse, so more freedom could evade
  more. Anything quoted from it must say so.
- The adversary queries the model score freely and exhaustively. That is a worst case for the
  defender on access and a weak one on search (no gradients).
- A packet-level check remains future work and needs real captures plus the original extractor.
