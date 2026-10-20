"""Confidence intervals that respect the temporal clustering of flows.

Flows from one attack run or one busy minute are strongly correlated, so resampling individual
flows (a naive bootstrap) badly understates uncertainty. Here flows are grouped into fixed time
blocks and whole blocks are resampled with replacement. Intervals are therefore wide when a class
is concentrated in a few blocks, which is the honest answer for this dataset.
"""

from __future__ import annotations

import numpy as np
import pandas as pd
from numpy.typing import NDArray

BoolArray = NDArray[np.bool_]

DEFAULT_BLOCK_MINUTES = 5
DEFAULT_RESAMPLES = 2000
DEFAULT_LEVEL = 0.95


def _ratio(numerator: NDArray[np.float64], denominator: NDArray[np.float64]) -> NDArray[np.float64]:
    out = np.full(numerator.shape, np.nan)
    np.divide(numerator, denominator, out=out, where=denominator > 0)
    return out


def block_bootstrap(
    timestamps: pd.Series,
    y_true: BoolArray,
    y_pred: BoolArray,
    *,
    block_minutes: int = DEFAULT_BLOCK_MINUTES,
    n_resamples: int = DEFAULT_RESAMPLES,
    level: float = DEFAULT_LEVEL,
    seed: int = 0,
) -> dict[str, object]:
    """Percentile intervals for recall, false-positive rate and precision via a block bootstrap."""
    if not 0.0 < level < 1.0:
        raise ValueError("level must be in (0, 1)")
    if block_minutes < 1 or n_resamples < 1:
        raise ValueError("block_minutes and n_resamples must be positive")
    known = timestamps.notna().to_numpy()
    if not known.any():
        raise ValueError("no valid timestamps")
    blocks, _ = pd.factorize(timestamps[known].dt.floor(f"{block_minutes}min"))
    truth, pred = y_true[known], y_pred[known]
    n_blocks = int(blocks.max()) + 1

    def per_block(mask: BoolArray) -> NDArray[np.float64]:
        return np.bincount(blocks, weights=mask.astype(float), minlength=n_blocks).astype(
            np.float64
        )

    counts = np.stack(
        [
            per_block(truth & pred),  # true positives
            per_block(~truth & pred),  # false positives
            per_block(~truth & ~pred),  # true negatives
            per_block(truth & ~pred),  # false negatives
        ],
        axis=1,
    )

    def metrics(totals: NDArray[np.float64]) -> dict[str, NDArray[np.float64]]:
        tp, fp, tn, fn = (totals[..., i] for i in range(4))
        return {
            "recall": _ratio(tp, tp + fn),
            "false_positive_rate": _ratio(fp, fp + tn),
            "precision": _ratio(tp, tp + fp),
        }

    estimate = metrics(counts.sum(axis=0))
    rng = np.random.default_rng(seed)
    picks = rng.integers(0, n_blocks, size=(n_resamples, n_blocks))
    resampled = metrics(counts[picks].sum(axis=1))
    low, high = (1.0 - level) / 2.0 * 100.0, (1.0 + level) / 2.0 * 100.0

    result: dict[str, object] = {
        "method": "time-block bootstrap",
        "block_minutes": block_minutes,
        "n_blocks": n_blocks,
        "n_resamples": n_resamples,
        "level": level,
    }
    for name, values in resampled.items():
        finite = values[np.isfinite(values)]
        point = float(estimate[name])
        result[name] = {
            "estimate": point if np.isfinite(point) else None,
            "low": float(np.percentile(finite, low)) if finite.size else None,
            "high": float(np.percentile(finite, high)) if finite.size else None,
        }
    return result
