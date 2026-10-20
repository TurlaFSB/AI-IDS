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


def _display(value: object) -> str:
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    return str(value)


def false_positive_profile(
    frame: pd.DataFrame,
    y_true: BoolArray,
    y_pred: BoolArray,
    columns: tuple[str, ...],
    top_k: int = 10,
) -> dict[str, object]:
    """Which values of each column the false positives concentrate on.

    For each value: how many false positives it has, its share of all false positives, and the
    false-positive rate among benign flows with that value. A few values with a very high rate
    point to a specific traffic cluster (or label noise) rather than broad drift.
    """
    benign = frame[~y_true]
    false_positives = frame[~y_true & y_pred]
    total = len(false_positives)
    result: dict[str, object] = {"false_positives": total, "benign_flows": len(benign)}
    if total == 0:
        return result
    for column in columns:
        if column not in frame.columns:
            continue
        counts = false_positives[column].value_counts().head(top_k)
        benign_counts = benign[column].value_counts().to_dict()
        result[column] = [
            {
                "value": _display(value),
                "false_positives": int(count),
                "share_of_false_positives": float(count / total),
                "false_positive_rate": float(count / benign_counts[value]),
                "benign_flows": int(benign_counts[value]),
            }
            for value, count in counts.items()
        ]
    return result


def host_concentration(
    frame: pd.DataFrame,
    y_true: BoolArray,
    y_pred: BoolArray,
    *,
    host_column: str = "source_ip",
    top_k: int = 3,
    port_column: str = "destination_port",
    peer_column: str = "destination_ip",
    time_column: str = "timestamp",
) -> dict[str, object]:
    """How concentrated false positives are on a few hosts, and when they occurred.

    Also reports the false-positive rate with the top hosts excluded. That figure is a
    sensitivity analysis only: excluding hosts after seeing where errors fall is not a
    performance claim.
    """
    if host_column not in frame.columns:
        return {}
    false_positives = frame[~y_true & y_pred]
    total = len(false_positives)
    if total == 0:
        return {}
    benign = frame[~y_true]
    benign_counts = benign[host_column].value_counts().to_dict()
    hosts = false_positives[host_column].value_counts().head(top_k)

    top_hosts = []
    for host, count in hosts.items():
        rows = false_positives[false_positives[host_column] == host]
        entry: dict[str, object] = {
            "host": str(host),
            "false_positives": int(count),
            "share_of_false_positives": float(count / total),
            "benign_flows": int(benign_counts[host]),
            "false_positive_rate": float(count / benign_counts[host]),
        }
        if port_column in rows.columns:
            entry["distinct_destination_ports"] = int(rows[port_column].nunique())
        if peer_column in rows.columns:
            entry["distinct_destination_hosts"] = int(rows[peer_column].nunique())
        if time_column in rows.columns and rows[time_column].notna().any():
            entry["first_false_positive"] = str(rows[time_column].min())
            entry["last_false_positive"] = str(rows[time_column].max())
        top_hosts.append(entry)

    excluding: dict[str, dict[str, object]] = {}
    for k in range(1, len(hosts) + 1):
        excluded = list(hosts.index[:k])
        benign_left = int((~benign[host_column].isin(excluded)).sum())
        false_left = int((~false_positives[host_column].isin(excluded)).sum())
        excluding[str(k)] = {
            "excluded_hosts": [str(h) for h in excluded],
            "benign_flows_remaining": benign_left,
            "false_positive_rate": float(false_left / benign_left) if benign_left else None,
        }
    return {
        "top_hosts": top_hosts,
        "fpr_excluding_top_hosts": excluding,
        "note": (
            "Sensitivity analysis only: excluding hosts after seeing where errors fall is not "
            "a performance claim."
        ),
    }


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
