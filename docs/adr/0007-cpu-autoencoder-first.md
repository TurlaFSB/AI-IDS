# 0007. Autoencoder with scikit-learn on CPU first

Status: Accepted (2026-10-20)

## Context
The leave-one-attack-family-out test shows supervised detection generalises poorly to unseen
attack families (pooled recall 0.27 with the family removed, versus 0.99 on known attacks), while
the Isolation Forest, which never sees attacks, is weaker still. An autoencoder trained on benign
traffic is the standard next candidate for novelty detection.

A PyTorch implementation is the usual choice, but on this project it carries real costs:
- PyTorch wheels on Linux pull large CUDA dependencies, which slows CI, bloats the container
  image, and complicates the universal hash-locked requirements (ADR 0006).
- GPU training depends on driver stability on the development machine.
- At 78 tabular features and a few hundred thousand benign rows, a small network trains in minutes
  on CPU, so a GPU is not needed to answer the research question.

## Decision
Implement the autoencoder as a scikit-learn `MLPRegressor` that reconstructs rank-normalised
benign features through a bottleneck (default 64-16-64). The score is the mean squared
reconstruction error; it uses the same scoring contract as every other detector. Training
diagnostics (epochs, whether the epoch limit was reached) are recorded in the report.

PyTorch and GPU training remain an option behind an optional extra if experiments show the
architecture needs it; that is a separate decision with its own lock file.

## Consequences
- No new dependencies; CI, the container image, and the hash-locked installs are unchanged.
- The model is small and not tuned; results are a baseline, not a ceiling.
- Whether it beats the Isolation Forest, or helps at all against unseen families, is an empirical
  question answered by the per-category recall in the report, not assumed.
