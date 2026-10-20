import numpy as np
import pandas as pd
import pytest

from ai_ids.evaluation.metrics import (
    binary_report,
    breakdown_by_group,
    false_positive_profile,
    latency_profile,
    macro_recall,
    per_class_recall,
)


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


def test_macro_recall_and_support_filter() -> None:
    per_class = {
        "a": {"support": 100, "recall": 1.0},
        "b": {"support": 100, "recall": 0.0},
        "tiny": {"support": 3, "recall": 1.0},
    }
    assert macro_recall(per_class) == pytest.approx(2 / 3)
    assert macro_recall(per_class, min_support=30) == 0.5
    assert macro_recall({}) is None


def test_breakdown_by_group() -> None:
    groups = pd.Series(["d1", "d1", "d1", "d2", "d2", None])
    y_true = np.array([False, False, True, False, True, False])
    y_pred = np.array([True, False, True, False, False, True])
    result = breakdown_by_group(groups, y_true, y_pred)
    assert set(result) == {"d1", "d2"}
    assert result["d1"]["false_positive_rate"] == 0.5
    assert result["d1"]["recall"] == 1.0
    assert result["d2"]["recall"] == 0.0
    assert result["d2"]["benign"] == 1


def test_false_positive_profile_concentration() -> None:
    frame = pd.DataFrame(
        {
            "destination_port": [80.0, 80.0, 80.0, 443.0, 443.0, 22.0],
            "source_ip": ["a", "a", "b", "c", "c", "d"],
        }
    )
    y_true = np.array([False, False, False, False, False, True])
    y_pred = np.array([True, True, False, False, False, True])
    profile = false_positive_profile(
        frame, y_true, y_pred, ("destination_port", "source_ip", "nope")
    )
    assert profile["false_positives"] == 2
    assert profile["benign_flows"] == 5
    ports = profile["destination_port"]
    assert isinstance(ports, list)
    assert ports[0]["value"] == "80"
    assert ports[0]["share_of_false_positives"] == 1.0
    assert ports[0]["false_positive_rate"] == pytest.approx(2 / 3)
    assert "nope" not in profile


def test_false_positive_profile_without_false_positives() -> None:
    frame = pd.DataFrame({"destination_port": [80.0, 443.0]})
    result = false_positive_profile(
        frame, np.array([False, True]), np.array([False, True]), ("destination_port",)
    )
    assert result == {"false_positives": 0, "benign_flows": 1}
