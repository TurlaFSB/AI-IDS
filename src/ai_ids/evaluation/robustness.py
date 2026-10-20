"""Evasion-sensitivity analysis: how much does recall drop when an attacker reshapes flows?

This is a defensive stress test of the detectors, not an attack tool. It applies simple,
physically motivated transformations to the flow features an adversary can plausibly control
(timing and packet size) and measures detection at the already-calibrated alert threshold.

Limits to state whenever results are quoted: the perturbations act on derived flow features,
not on packets; they assume the attacker can reshape these features without breaking the
attack; and only features present in the data are touched. Treat the numbers as a sensitivity
indicator that guides hardening, not as a bound on real-world evasion.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from functools import partial

import numpy as np
import pandas as pd

from ai_ids.data.loader import CATEGORY
from ai_ids.models.detectors import BaseDetector

# Slowing a flow down by k stretches durations and inter-arrival times and divides rates by k.
_TIME_COLUMNS = (
    "flow_duration",
    "flow_iat_mean",
    "flow_iat_std",
    "flow_iat_max",
    "flow_iat_min",
    "fwd_iat_total",
    "fwd_iat_mean",
    "fwd_iat_std",
    "fwd_iat_max",
    "fwd_iat_min",
    "bwd_iat_total",
    "bwd_iat_mean",
    "bwd_iat_std",
    "bwd_iat_max",
    "bwd_iat_min",
    "idle_mean",
    "idle_std",
    "idle_max",
    "idle_min",
)
_RATE_COLUMNS = ("flow_bytes_s", "flow_packets_s", "fwd_packets_s", "bwd_packets_s")

# Padding adds a constant number of bytes to packet-size statistics.
_SIZE_COLUMNS = (
    "fwd_packet_length_mean",
    "fwd_packet_length_max",
    "fwd_packet_length_min",
    "bwd_packet_length_mean",
    "bwd_packet_length_max",
    "bwd_packet_length_min",
    "min_packet_length",
    "max_packet_length",
    "packet_length_mean",
    "average_packet_size",
    "avg_fwd_segment_size",
    "avg_bwd_segment_size",
)

DEFAULT_SLOWDOWNS = (2.0, 5.0, 10.0)
DEFAULT_PADDINGS = (64.0, 256.0, 1024.0)
MIN_FAMILY_SUPPORT = 30


def slow_down(features: pd.DataFrame, factor: float) -> pd.DataFrame:
    """Return a copy with timing stretched and rates reduced by `factor`."""
    if factor <= 0:
        raise ValueError("factor must be positive")
    out = features.copy()
    for column in _TIME_COLUMNS:
        if column in out:
            out[column] = out[column] * factor
    for column in _RATE_COLUMNS:
        if column in out:
            out[column] = out[column] / factor
    return out


def pad_packets(features: pd.DataFrame, extra_bytes: float) -> pd.DataFrame:
    """Return a copy with `extra_bytes` added to packet-size statistics."""
    if extra_bytes < 0:
        raise ValueError("extra_bytes must be non-negative")
    out = features.copy()
    for column in _SIZE_COLUMNS:
        if column in out:
            out[column] = out[column] + extra_bytes
    return out


def modified_columns(features: pd.DataFrame, perturbed: pd.DataFrame) -> int:
    """How many feature columns a perturbation actually changed."""
    changed = 0
    for column in features.columns:
        if not np.array_equal(
            features[column].to_numpy(), perturbed[column].to_numpy(), equal_nan=True
        ):
            changed += 1
    return changed


@dataclass(frozen=True)
class Perturbation:
    name: str
    apply: Callable[[pd.DataFrame], pd.DataFrame]


def _combined(features: pd.DataFrame, factor: float, extra_bytes: float) -> pd.DataFrame:
    return pad_packets(slow_down(features, factor), extra_bytes)


def default_perturbations(
    slowdowns: tuple[float, ...] = DEFAULT_SLOWDOWNS,
    paddings: tuple[float, ...] = DEFAULT_PADDINGS,
) -> list[Perturbation]:
    perturbations = [
        Perturbation(f"slowdown_x{k:g}", partial(slow_down, factor=k)) for k in slowdowns
    ]
    perturbations += [
        Perturbation(f"padding_{b:g}B", partial(pad_packets, extra_bytes=b)) for b in paddings
    ]
    if slowdowns and paddings:
        k, b = slowdowns[len(slowdowns) // 2], paddings[len(paddings) // 2]
        perturbations.append(
            Perturbation(f"combined_x{k:g}_{b:g}B", partial(_combined, factor=k, extra_bytes=b))
        )
    return perturbations


def evasion_report(
    detector: BaseDetector,
    attacks: pd.DataFrame,
    features: list[str],
    threshold: float,
    perturbations: list[Perturbation] | None = None,
) -> dict[str, object]:
    """Recall at a fixed threshold on attack flows, before and after each perturbation."""
    if attacks.empty:
        raise ValueError("no attack flows to evaluate")
    perturbations = perturbations if perturbations is not None else default_perturbations()
    base_x = attacks[features]
    families = attacks[CATEGORY].to_numpy()
    base_detected = detector.score(base_x) > threshold

    def per_family(detected: np.ndarray) -> dict[str, float]:
        result = {}
        for family in sorted(set(families)):
            mask = families == family
            if int(mask.sum()) >= MIN_FAMILY_SUPPORT:
                result[str(family)] = float(detected[mask].mean())
        return result

    baseline_recall = float(base_detected.mean())
    baseline = {"recall": baseline_recall, "by_family": per_family(base_detected)}
    results: dict[str, object] = {}
    for perturbation in perturbations:
        perturbed_x = perturbation.apply(base_x)
        detected = detector.score(perturbed_x) > threshold
        recall = float(detected.mean())
        results[perturbation.name] = {
            "columns_modified": modified_columns(base_x, perturbed_x),
            "recall": recall,
            "recall_drop": baseline_recall - recall,
            "by_family": per_family(detected),
        }
    return {
        "note": (
            "Feature-space sensitivity analysis on derived flow features, not a packet-level "
            "attack; families with fewer than 30 test flows are omitted."
        ),
        "baseline": baseline,
        "perturbations": results,
    }
