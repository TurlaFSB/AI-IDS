import numpy as np
import pandas as pd
import pytest

from ai_ids.evaluation.uncertainty import block_bootstrap


def _times(n_blocks: int, per_block: int, minutes: int = 5) -> pd.Series:
    stamps = [
        pd.Timestamp("2017-07-07 09:00") + pd.Timedelta(minutes=minutes * b)
        for b in range(n_blocks)
        for _ in range(per_block)
    ]
    return pd.Series(stamps)


def test_perfect_predictions_give_degenerate_intervals() -> None:
    times = _times(20, 10)
    truth = np.tile([True, False], len(times) // 2)
    result = block_bootstrap(times, truth, truth.copy(), n_resamples=200, seed=1)
    for metric in ("recall", "precision"):
        assert result[metric] == {"estimate": 1.0, "low": 1.0, "high": 1.0}  # type: ignore[comparison-overlap]
    assert result["false_positive_rate"]["estimate"] == 0.0  # type: ignore[index]
    assert result["n_blocks"] == 20


def test_estimate_matches_the_pooled_counts() -> None:
    times = _times(10, 10)
    truth = np.tile([True, False], 50)
    pred = truth.copy()
    pred[truth] = np.tile([True, True, True, False], 13)[:50]  # 75% recall, no false positives
    result = block_bootstrap(times, truth, pred, n_resamples=100, seed=2)
    recall = result["recall"]
    assert isinstance(recall, dict)
    assert recall["estimate"] == pytest.approx(pred[truth].mean())
    assert recall["low"] <= recall["estimate"] <= recall["high"]


def test_intervals_are_wide_when_a_class_sits_in_few_blocks() -> None:
    """All attacks in two blocks, caught in one and missed in the other: very uncertain recall."""
    times = _times(40, 25)
    truth = np.zeros(len(times), dtype=bool)
    truth[:25] = True  # block 0
    truth[25:50] = True  # block 1
    pred = np.zeros(len(times), dtype=bool)
    pred[:25] = True  # caught in block 0 only
    result = block_bootstrap(times, truth, pred, n_resamples=500, seed=3)
    recall = result["recall"]
    assert isinstance(recall, dict)
    assert recall["estimate"] == pytest.approx(0.5)
    assert recall["high"] - recall["low"] > 0.5  # a naive flow bootstrap would give ~0.14


def test_deterministic_and_validated() -> None:
    times = _times(8, 5)
    truth = np.tile([True, False], 20)
    a = block_bootstrap(times, truth, truth, n_resamples=50, seed=9)
    b = block_bootstrap(times, truth, truth, n_resamples=50, seed=9)
    assert a == b
    with pytest.raises(ValueError, match="level"):
        block_bootstrap(times, truth, truth, level=1.5)
    with pytest.raises(ValueError, match="positive"):
        block_bootstrap(times, truth, truth, block_minutes=0)
    with pytest.raises(ValueError, match="timestamps"):
        block_bootstrap(pd.Series([pd.NaT] * 40), truth, truth)


def test_missing_timestamps_are_ignored() -> None:
    times = _times(6, 5)
    times.iloc[:3] = pd.NaT
    truth = np.tile([True, False], 15)
    result = block_bootstrap(times, truth, truth, n_resamples=50, seed=4)
    assert result["recall"]["estimate"] == 1.0  # type: ignore[index]
