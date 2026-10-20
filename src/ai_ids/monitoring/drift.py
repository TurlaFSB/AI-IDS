"""Distribution drift measurement using the Population Stability Index (PSI).

PSI compares how a feature is distributed in a reference sample versus a current sample.
Common industry rule of thumb: below 0.1 stable, 0.1 to 0.25 moderate shift, above 0.25
significant shift.
"""

from __future__ import annotations

import numpy as np
import pandas as pd
from numpy.typing import NDArray

FloatArray = NDArray[np.float64]

_EPS = 1e-6
MODERATE_PSI = 0.1
SIGNIFICANT_PSI = 0.25


def psi(reference: FloatArray, current: FloatArray, bins: int = 10) -> float:
    """PSI of `current` against `reference`, using quantile bins of the reference."""
    ref = reference[np.isfinite(reference)]
    cur = current[np.isfinite(current)]
    if ref.size == 0 or cur.size == 0:
        return 0.0
    edges = np.unique(np.quantile(ref, np.linspace(0.0, 1.0, bins + 1)))
    if edges.size < 3:  # constant (or near-constant) reference feature
        return 0.0
    inner = edges[1:-1]
    n_bins = edges.size - 1
    ref_frac = np.bincount(np.searchsorted(inner, ref, side="right"), minlength=n_bins) / ref.size
    cur_frac = np.bincount(np.searchsorted(inner, cur, side="right"), minlength=n_bins) / cur.size
    ref_frac = np.clip(ref_frac, _EPS, None)
    cur_frac = np.clip(cur_frac, _EPS, None)
    return float(np.sum((cur_frac - ref_frac) * np.log(cur_frac / ref_frac)))


def rating(value: float) -> str:
    if value >= SIGNIFICANT_PSI:
        return "significant"
    if value >= MODERATE_PSI:
        return "moderate"
    return "stable"


def drift_report(
    reference: pd.DataFrame, current: pd.DataFrame, *, top_k: int = 10, bins: int = 10
) -> dict[str, object]:
    """Per-feature PSI summary: counts by rating and the `top_k` most-shifted features."""
    scores = {
        column: psi(
            reference[column].to_numpy(dtype=np.float64),
            current[column].to_numpy(dtype=np.float64),
            bins,
        )
        for column in reference.columns
        if column in current.columns
    }
    ranked = sorted(scores.items(), key=lambda item: item[1], reverse=True)
    ratings = [rating(value) for value in scores.values()]
    return {
        "features_significant": ratings.count("significant"),
        "features_moderate": ratings.count("moderate"),
        "features_stable": ratings.count("stable"),
        "top": [
            {"feature": name, "psi": value, "rating": rating(value)}
            for name, value in ranked[:top_k]
        ],
    }
