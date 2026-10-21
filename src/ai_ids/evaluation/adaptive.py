"""Adaptive evasion in feature space: an attacker who tries every allowed reshaping per flow.

The fixed perturbations in `robustness` ask "what if every attack flow is padded by 64 bytes?".
A real adversary chooses, per flow, whichever allowed reshaping scores lowest. This module gives
that adversary a grid of slowdown factors and forward-padding amounts (the two things an
attacker plausibly controls), scores every combination, and keeps each flow's best outcome.

Reported: recall against this per-flow adversary as a function of how much slowing and padding the
adversary may use, and a benign control (does any allowed combination push benign flows over the
threshold, which would show a "perturbed means attack" shortcut). Limits that must travel with any
number from here: the transformations act on derived flow features, not packets; the adversary
only sees the grid, not model gradients, and only reshapes timing and forward packet size; the
detector's score is queried freely (a white-box oracle), which is a strong assumption in the
defender's favour on access but a weak one on search; and a larger grid or other features could
evade more. It is a defensive stress test, not a bound on real-world evasion.
"""

from __future__ import annotations

from typing import Any

import numpy as np
import pandas as pd
from numpy.typing import NDArray

from ai_ids.data.loader import CATEGORY
from ai_ids.evaluation.robustness import MIN_FAMILY_SUPPORT, pad_forward_packets, slow_down
from ai_ids.models.detectors import BaseDetector

DEFAULT_SLOWDOWN_GRID = (1.0, 2.0, 5.0, 10.0, 30.0)
DEFAULT_PADDING_GRID = (0.0, 32.0, 128.0, 512.0, 1024.0, 1460.0)
DEFAULT_MAX_FLOWS = 20_000

FloatArray = NDArray[np.float64]


def _reshape(x: pd.DataFrame, slowdown: float, padding: float) -> pd.DataFrame:
    out = x if slowdown == 1.0 else slow_down(x, slowdown)
    return out if padding == 0.0 else pad_forward_packets(out, padding)


def score_grid(
    detector: BaseDetector,
    x: pd.DataFrame,
    slowdowns: tuple[float, ...],
    paddings: tuple[float, ...],
) -> FloatArray:
    """Scores of every flow under every (slowdown, padding): shape (flows, slowdowns, paddings)."""
    scores = np.empty((len(x), len(slowdowns), len(paddings)))
    for i, slowdown in enumerate(slowdowns):
        for j, padding in enumerate(paddings):
            scores[:, i, j] = detector.score(_reshape(x, slowdown, padding))
    return scores


def _frontier(
    scores: FloatArray, threshold: float, slowdowns: tuple[float, ...], paddings: tuple[float, ...]
) -> dict[str, dict[str, float]]:
    """Recall when the adversary may use slowdowns up to a cap and padding up to a cap."""
    table: dict[str, dict[str, float]] = {}
    for i, s_cap in enumerate(slowdowns):
        row = {}
        for j, p_cap in enumerate(paddings):
            lowest = scores[:, : i + 1, : j + 1].min(axis=(1, 2))
            row[f"pad<={p_cap:g}B"] = float((lowest > threshold).mean())
        table[f"slow<=x{s_cap:g}"] = row
    return table


def adaptive_evasion(
    detector: BaseDetector,
    attacks: pd.DataFrame,
    benign: pd.DataFrame,
    features: list[str],
    threshold: float,
    *,
    slowdowns: tuple[float, ...] = DEFAULT_SLOWDOWN_GRID,
    paddings: tuple[float, ...] = DEFAULT_PADDING_GRID,
    max_flows: int = DEFAULT_MAX_FLOWS,
    seed: int = 42,
) -> dict[str, Any]:
    """Recall against a per-flow best-of-grid adversary, with a benign control."""
    if not slowdowns or slowdowns[0] != 1.0 or not paddings or paddings[0] != 0.0:
        raise ValueError("the grids must start at the identity (slowdown 1, padding 0)")
    if attacks.empty or benign.empty:
        raise ValueError("adaptive evasion needs both attack and benign flows")

    def sample(frame: pd.DataFrame) -> pd.DataFrame:
        if len(frame) <= max_flows:
            return frame
        return frame.sample(n=max_flows, random_state=seed)

    attack_sample, benign_sample = sample(attacks), sample(benign)
    attack_scores = score_grid(detector, attack_sample[features], slowdowns, paddings)
    benign_scores = score_grid(detector, benign_sample[features], slowdowns, paddings)

    clean_detected = attack_scores[:, 0, 0] > threshold
    best = attack_scores.min(axis=(1, 2))
    adaptive_detected = best > threshold
    families = attack_sample[CATEGORY].to_numpy()
    per_family = {
        str(f): {
            "clean_recall": float(clean_detected[families == f].mean()),
            "adaptive_recall": float(adaptive_detected[families == f].mean()),
        }
        for f in sorted(set(families))
        if int((families == f).sum()) >= MIN_FAMILY_SUPPORT
    }
    benign_worst = benign_scores.max(axis=(1, 2))
    n_detected = int(clean_detected.sum())
    evaded_among_detected = (
        float(np.sum(~adaptive_detected & clean_detected)) / n_detected if n_detected else None
    )
    return {
        "note": (
            "per-flow best-of-grid adversary in feature space (timing and forward padding); not a "
            "packet-level or gradient attack; see the module docstring for limits"
        ),
        "grid": {"slowdowns": list(slowdowns), "paddings_bytes": list(paddings)},
        "attack_flows": len(attack_sample),
        "benign_flows": len(benign_sample),
        "clean_recall": float(clean_detected.mean()),
        "adaptive_recall": float(adaptive_detected.mean()),
        "share_of_detected_flows_evaded": evaded_among_detected,
        "recall_frontier": _frontier(attack_scores, threshold, slowdowns, paddings),
        "by_family": per_family,
        "benign_control": {
            "clean_false_positive_rate": float((benign_scores[:, 0, 0] > threshold).mean()),
            "flagged_under_any_combination": float((benign_worst > threshold).mean()),
        },
    }
