"""Detection-quality and latency metrics."""

from __future__ import annotations

import time
from collections.abc import Callable

import numpy as np
import pandas as pd
from numpy.typing import NDArray
from sklearn.metrics import average_precision_score, matthews_corrcoef, roc_auc_score

BoolArray = NDArray[np.bool_]
FloatArray = NDArray[np.float64]


def _safe_div(num: float, den: float) -> float:
    return float(num / den) if den else 0.0


def threshold_for_fpr(benign_scores: FloatArray, target_fpr: float) -> float:
    """Smallest threshold such that at most `target_fpr` of these benign scores exceed it."""
    if not 0.0 < target_fpr < 1.0:
        raise ValueError("target_fpr must be in (0, 1)")
    if benign_scores.size == 0:
        raise ValueError("cannot derive a threshold without benign scores")
    # "higher" never interpolates below the empirical quantile, so strict exceedance <= target.
    return float(np.quantile(benign_scores, 1.0 - target_fpr, method="higher"))


def binary_report(
    y_true: BoolArray, scores: FloatArray, threshold: float
) -> dict[str, float | None]:
    """Metrics for attack-vs-benign detection at a fixed alert threshold."""
    y_pred = scores > threshold
    tp = int(np.sum(y_true & y_pred))
    fp = int(np.sum(~y_true & y_pred))
    tn = int(np.sum(~y_true & ~y_pred))
    fn = int(np.sum(y_true & ~y_pred))
    both_classes = bool(y_true.any() and (~y_true).any())
    recall = _safe_div(tp, tp + fn)
    precision = _safe_div(tp, tp + fp)
    return {
        "threshold": float(threshold),
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "recall": recall,
        "precision": precision,
        "f1": _safe_div(2 * precision * recall, precision + recall),
        "false_positive_rate": _safe_div(fp, fp + tn),
        "false_negative_rate": _safe_div(fn, fn + tp),
        "mcc": float(matthews_corrcoef(y_true, y_pred)) if both_classes else None,
        "roc_auc": float(roc_auc_score(y_true, scores)) if both_classes else None,
        "pr_auc": float(average_precision_score(y_true, scores)) if y_true.any() else None,
    }


def per_class_recall(
    labels: pd.Series, y_pred: BoolArray, attack_mask: BoolArray
) -> dict[str, dict[str, float | int]]:
    """Detection rate for each attack type (support included, small classes are noisy)."""
    result: dict[str, dict[str, float | int]] = {}
    for label in sorted(set(labels[attack_mask])):
        mask = (labels == label).to_numpy()
        support = int(mask.sum())
        result[str(label)] = {"support": support, "recall": float(y_pred[mask].mean())}
    return result


def macro_recall(
    per_class: dict[str, dict[str, float | int]], min_support: int = 1
) -> float | None:
    """Unweighted mean of per-attack recall, ignoring attack types below `min_support` flows."""
    values = [float(v["recall"]) for v in per_class.values() if int(v["support"]) >= min_support]
    return float(np.mean(values)) if values else None


def breakdown_by_group(
    groups: pd.Series, y_true: BoolArray, y_pred: BoolArray
) -> dict[str, dict[str, float | int | None]]:
    """False-positive rate (benign flows) and recall (attack flows) within each group."""
    result: dict[str, dict[str, float | int | None]] = {}
    for key in sorted(groups.dropna().unique()):
        mask = (groups == key).to_numpy()
        benign = mask & ~y_true
        attacks = mask & y_true
        result[str(key)] = {
            "flows": int(mask.sum()),
            "benign": int(benign.sum()),
            "attacks": int(attacks.sum()),
            "false_positive_rate": float(y_pred[benign].mean()) if benign.any() else None,
            "recall": float(y_pred[attacks].mean()) if attacks.any() else None,
        }
    return result


def latency_profile(
    score_fn: Callable[[pd.DataFrame], FloatArray],
    X: pd.DataFrame,
    *,
    batch_sizes: tuple[int, ...] = (1, 100, 1000),
    repeats: int = 30,
    warmup: int = 3,
) -> dict[str, dict[str, float]]:
    """Wall-clock scoring latency per batch (ms), plus per-flow throughput."""
    profile: dict[str, dict[str, float]] = {}
    for size in batch_sizes:
        if len(X) < size:
            continue
        batch = X.iloc[:size]
        for _ in range(warmup):
            score_fn(batch)
        samples = []
        for _ in range(repeats):
            start = time.perf_counter()
            score_fn(batch)
            samples.append((time.perf_counter() - start) * 1000.0)
        arr = np.asarray(samples)
        profile[f"batch_{size}"] = {
            "p50_ms": float(np.percentile(arr, 50)),
            "p95_ms": float(np.percentile(arr, 95)),
            "p99_ms": float(np.percentile(arr, 99)),
            "flows_per_second": float(size / (np.median(arr) / 1000.0)),
        }
    return profile
