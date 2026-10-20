# 0001. Start with classical models, add deep learning as a comparison

Status: Accepted (2026-10-20)

## Context
Flow records are tabular numeric features. Tree ensembles are strong on tabular data, train
quickly, are cheap to run, and are easier to explain than neural networks. A credible deep
learning result needs a solid baseline to be compared against.

## Decision
Ship a Random Forest (supervised) and an Isolation Forest (unsupervised) first. Add a PyTorch
autoencoder as a third detector behind the same scoring contract, and compare all three with the
same splits and metrics.

## Consequences
- A trustworthy baseline exists before added complexity.
- The shared "higher score = more suspicious" contract keeps calibration and metrics model-agnostic.
- Language models are not used in the detection path.
