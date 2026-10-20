import numpy as np
import pandas as pd

from ai_ids.evaluation.metrics import binary_report, latency_profile, per_class_recall


def test_binary_report_known_values() -> None:
    y = np.array([True, True, False, False])
    scores = np.array([0.9, 0.2, 0.1, 0.6])
    r = binary_report(y, scores, threshold=0.5)
    assert (r["tp"], r["fp"], r["tn"], r["fn"]) == (1, 1, 1, 1)
    assert r["recall"] == 0.5
    assert r["false_positive_rate"] == 0.5
    assert r["precision"] == 0.5


def test_single_class_yields_no_auc() -> None:
    r = binary_report(np.array([False, False]), np.array([0.1, 0.2]), 0.5)
    assert r["roc_auc"] is None
    assert r["recall"] == 0.0


def test_per_class_recall() -> None:
    labels = pd.Series(["a", "a", "b", "benign"])
    pred = np.array([True, False, True, False])
    attack = np.array([True, True, True, False])
    result = per_class_recall(labels, pred, attack)
    assert result["a"] == {"support": 2, "recall": 0.5}
    assert result["b"]["recall"] == 1.0
    assert "benign" not in result


def test_latency_profile_shape() -> None:
    X = pd.DataFrame({"a": np.arange(200.0)})
    profile = latency_profile(lambda b: b["a"].to_numpy(), X, batch_sizes=(1, 100, 1000), repeats=5)
    assert set(profile) == {"batch_1", "batch_100"}
    assert profile["batch_1"]["p50_ms"] <= profile["batch_1"]["p99_ms"]
    assert profile["batch_100"]["flows_per_second"] > 0
