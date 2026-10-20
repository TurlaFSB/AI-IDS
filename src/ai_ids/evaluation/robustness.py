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

from ai_ids.data.loader import CATEGORY, IS_ATTACK
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

DEFAULT_SLOWDOWNS = (2.0, 5.0, 10.0)
DEFAULT_PADDINGS = (64.0, 256.0, 1024.0)
MIN_FAMILY_SUPPORT = 30
RANDOM_PADDING = (16.0, 512.0)
BENIGN_CONTROL_SAMPLE = 100_000


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


ExtraBytes = float | np.ndarray | pd.Series


def _extra(features: pd.DataFrame, extra_bytes: ExtraBytes) -> pd.Series:
    """Padding per flow, as a Series aligned with `features` (a scalar applies to every flow)."""
    if np.isscalar(extra_bytes):
        values = pd.Series(float(extra_bytes), index=features.index)
    else:
        values = pd.Series(np.asarray(extra_bytes, dtype="float64"), index=features.index)
    if (values < 0).any():
        raise ValueError("extra_bytes must be non-negative")
    return values


def pad_packets(features: pd.DataFrame, extra_bytes: ExtraBytes) -> pd.DataFrame:
    """Return a copy in which every packet carries `extra_bytes` of additional payload.

    The transformation keeps related features consistent: packet-length statistics shift by the
    padding, totals grow by padding times packet count, and byte rates grow by padding times
    packet rate. Spread statistics (standard deviation, variance) are unchanged because every
    packet shifts equally, and statistics of a direction with no packets stay zero.
    `extra_bytes` may be a scalar or one value per flow.
    """
    extra = _extra(features, extra_bytes)
    out = features.copy()
    directions = {"fwd": "total_fwd_packets", "bwd": "total_backward_packets"}
    for direction, count_column in directions.items():
        shift = extra * (out[count_column] > 0) if count_column in out else extra
        for column in (
            f"{direction}_packet_length_max",
            f"{direction}_packet_length_min",
            f"{direction}_packet_length_mean",
            f"avg_{direction}_segment_size",
        ):
            if column in out:
                out[column] = out[column] + shift
        total_column = f"total_length_of_{direction}_packets"
        if total_column in out and count_column in out:
            out[total_column] = out[total_column] + extra * out[count_column]
        subflow_bytes = f"subflow_{direction}_bytes"
        subflow_packets = f"subflow_{direction}_packets"
        if subflow_bytes in out and subflow_packets in out:
            out[subflow_bytes] = out[subflow_bytes] + extra * out[subflow_packets]
    for column in (
        "min_packet_length",
        "max_packet_length",
        "packet_length_mean",
        "average_packet_size",
    ):
        if column in out:
            out[column] = out[column] + extra
    if "flow_bytes_s" in out and "flow_packets_s" in out:
        out["flow_bytes_s"] = out["flow_bytes_s"] + extra * out["flow_packets_s"]
    return out


def _pooled_variance(
    n_fwd: pd.Series,
    mean_fwd: pd.Series,
    std_fwd: pd.Series,
    n_bwd: pd.Series,
    mean_bwd: pd.Series,
    std_bwd: pd.Series,
) -> pd.Series:
    """Whole-flow packet-length variance from per-direction counts, means and spreads."""
    n = (n_fwd + n_bwd).where(lambda v: v > 0)
    mean = (n_fwd * mean_fwd + n_bwd * mean_bwd) / n
    return (
        n_fwd * (std_fwd**2 + (mean_fwd - mean) ** 2)
        + n_bwd * (std_bwd**2 + (mean_bwd - mean) ** 2)
    ) / n


def _shift_overall_statistics(before: pd.DataFrame, after: pd.DataFrame, extra: pd.Series) -> None:
    """Update whole-flow packet statistics in `after` once only forward packets were padded."""
    n_fwd, n_bwd = before["total_fwd_packets"], before["total_backward_packets"]
    n = (n_fwd + n_bwd).where(lambda v: v > 0)
    for column in ("packet_length_mean", "average_packet_size"):
        if column in after:
            after[column] = after[column] + extra * n_fwd / n
    for stat, combine in (("min", np.minimum), ("max", np.maximum)):
        overall, fwd, bwd = (
            f"{stat}_packet_length",
            f"fwd_packet_length_{stat}",
            f"bwd_packet_length_{stat}",
        )
        if all(column in after for column in (overall, fwd, bwd)):
            both = pd.Series(combine(after[fwd], after[bwd]), index=after.index)
            updated = after[fwd].where(n_bwd == 0, both.where(n_fwd > 0, after[bwd]))
            after[overall] = updated.where(n.notna(), before[overall])
    needed = (
        "fwd_packet_length_mean",
        "fwd_packet_length_std",
        "bwd_packet_length_mean",
        "bwd_packet_length_std",
        "packet_length_variance",
    )
    if all(column in after for column in needed):
        # Change in the pooled variance, so the dataset's own variance convention is preserved.
        pre = _pooled_variance(
            n_fwd,
            before["fwd_packet_length_mean"],
            before["fwd_packet_length_std"],
            n_bwd,
            before["bwd_packet_length_mean"],
            before["bwd_packet_length_std"],
        )
        post = _pooled_variance(
            n_fwd,
            after["fwd_packet_length_mean"],
            after["fwd_packet_length_std"],
            n_bwd,
            after["bwd_packet_length_mean"],
            after["bwd_packet_length_std"],
        )
        variance = (before["packet_length_variance"] + (post - pre)).clip(lower=0)
        after["packet_length_variance"] = variance
        if "packet_length_std" in after:
            after["packet_length_std"] = np.sqrt(variance)


def pad_forward_packets(features: pd.DataFrame, extra_bytes: ExtraBytes) -> pd.DataFrame:
    """Return a copy in which only forward-direction packets carry `extra_bytes` of padding.

    A realistic attacker controls the packets they send, not the replies. Forward statistics,
    totals and the forward byte rate shift; whole-flow minimum, maximum, mean and variance are
    recomputed from the per-direction statistics; backward statistics are untouched.
    """
    extra = _extra(features, extra_bytes)
    out = features.copy()
    n_fwd = out.get("total_fwd_packets")
    shift = extra * (n_fwd > 0) if n_fwd is not None else extra
    for column in (
        "fwd_packet_length_max",
        "fwd_packet_length_min",
        "fwd_packet_length_mean",
        "avg_fwd_segment_size",
    ):
        if column in out:
            out[column] = out[column] + shift
    if n_fwd is not None and "total_length_of_fwd_packets" in out:
        out["total_length_of_fwd_packets"] = out["total_length_of_fwd_packets"] + extra * n_fwd
    if "subflow_fwd_bytes" in out and "subflow_fwd_packets" in out:
        out["subflow_fwd_bytes"] = out["subflow_fwd_bytes"] + extra * out["subflow_fwd_packets"]
    if "total_fwd_packets" in out and "total_backward_packets" in out:
        _shift_overall_statistics(features, out, extra)
    if "flow_bytes_s" in out and "fwd_packets_s" in out:
        out["flow_bytes_s"] = out["flow_bytes_s"] + extra * out["fwd_packets_s"]
    return out


def _pad_forward_random(features: pd.DataFrame, low: float, high: float, seed: int) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    return pad_forward_packets(features, rng.uniform(low, high, len(features)))


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
    """Evaluation perturbations.

    Padding of both directions and slowdowns are the families modelled by evasion-aware training
    (at different magnitudes). Forward-only padding, the attacker-realistic variant, and random
    per-flow forward padding are never used in training, so they test generalisation across
    perturbation types.
    """
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
    perturbations += [
        Perturbation(f"fwd_padding_{b:g}B", partial(pad_forward_packets, extra_bytes=b))
        for b in paddings
    ]
    perturbations.append(
        Perturbation(
            f"fwd_padding_random_{RANDOM_PADDING[0]:g}_{RANDOM_PADDING[1]:g}B",
            partial(
                _pad_forward_random,
                low=RANDOM_PADDING[0],
                high=RANDOM_PADDING[1],
                seed=0,
            ),
        )
    )
    return perturbations


def evasion_report(
    detector: BaseDetector,
    attacks: pd.DataFrame,
    features: list[str],
    threshold: float,
    perturbations: list[Perturbation] | None = None,
    *,
    benign: pd.DataFrame | None = None,
    benign_sample: int = BENIGN_CONTROL_SAMPLE,
    seed: int = 42,
) -> dict[str, object]:
    """Recall at a fixed threshold on attack flows, before and after each perturbation.

    If `benign` flows are given, the same perturbation is applied to a sample of them and the
    false-positive rate is reported too. This control matters: a detector trained to recognise
    perturbed attacks can score perfectly simply by flagging anything perturbed.
    """
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
    baseline: dict[str, object] = {
        "recall": baseline_recall,
        "by_family": per_family(base_detected),
    }
    benign_x: pd.DataFrame | None = None
    if benign is not None and not benign.empty:
        sample = (
            benign
            if len(benign) <= benign_sample
            else benign.sample(n=benign_sample, random_state=seed)
        )
        benign_x = sample[features]
        baseline["benign_false_positive_rate"] = float(
            (detector.score(benign_x) > threshold).mean()
        )
        baseline["benign_sample_size"] = len(sample)

    results: dict[str, object] = {}
    for perturbation in perturbations:
        perturbed_x = perturbation.apply(base_x)
        detected = detector.score(perturbed_x) > threshold
        recall = float(detected.mean())
        entry: dict[str, object] = {
            "columns_modified": modified_columns(base_x, perturbed_x),
            "recall": recall,
            "recall_drop": baseline_recall - recall,
            "by_family": per_family(detected),
        }
        if benign_x is not None:
            flagged = detector.score(perturbation.apply(benign_x)) > threshold
            entry["benign_false_positive_rate"] = float(flagged.mean())
        results[perturbation.name] = entry
    return {
        "note": (
            "Feature-space sensitivity analysis on derived flow features, not a packet-level "
            "attack; families with fewer than 30 test flows are omitted. "
            "benign_false_positive_rate is the same perturbation applied to benign flows."
        ),
        "baseline": baseline,
        "perturbations": results,
    }


# Training magnitudes deliberately differ from the evaluation magnitudes above, so that
# robustness is measured on perturbations the model has not been trained on.
TRAIN_SLOWDOWNS = (3.0, 7.0)
TRAIN_PADDINGS = (32.0, 128.0, 512.0)


def augment_attack_flows(
    train: pd.DataFrame,
    features: list[str],
    *,
    slowdowns: tuple[float, ...] = TRAIN_SLOWDOWNS,
    paddings: tuple[float, ...] = TRAIN_PADDINGS,
    fraction: float = 0.5,
    seed: int = 42,
) -> pd.DataFrame:
    """Return `train` plus perturbed copies of a random share of its attack flows.

    Benign flows are never modified. The sampled attack flows are split evenly across the
    perturbations (each copy is perturbed once), so the training set grows by about
    `fraction` times the number of attack flows.
    """
    if not 0.0 < fraction <= 1.0:
        raise ValueError("fraction must be in (0, 1]")
    transforms: list[Callable[[pd.DataFrame], pd.DataFrame]] = [
        partial(slow_down, factor=k) for k in slowdowns
    ]
    transforms += [partial(pad_packets, extra_bytes=b) for b in paddings]
    if not transforms:
        raise ValueError("at least one perturbation is required")
    attacks = train[train[IS_ATTACK]]
    if attacks.empty:
        return train
    rng = np.random.default_rng(seed)
    chosen = rng.permutation(len(attacks))[: int(len(attacks) * fraction)]
    parts = [train]
    for transform, indices in zip(transforms, np.array_split(chosen, len(transforms)), strict=True):
        copies = attacks.iloc[indices].copy()
        copies[features] = transform(copies[features])
        parts.append(copies)
    return pd.concat(parts, ignore_index=True)
