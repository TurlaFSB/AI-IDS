# 0002. Per-class chronological splitting

Status: Accepted (2026-10-20)

## Context
CIC-IDS-2017 contains many near-identical flows produced by the same attack tool run. Random
splits put near-duplicates in both train and test, inflating results and hiding poor
generalisation.

## Decision
Within each attack type, sort flows by time; the earliest 60% train, the next 15% calibrate the
threshold, and the latest 25% test. Classes with fewer than three flows go entirely to training.

## Consequences
- Test performance is measured on later traffic than the model saw, which is closer to
  deployment.
- Very small classes have tiny test supports; per-class results report support.
- Splits are deterministic and require no random seed.
