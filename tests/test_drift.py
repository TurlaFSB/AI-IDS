import numpy as np
import pandas as pd

from ai_ids.monitoring.drift import drift_report, psi, rating


def test_identical_distributions_have_near_zero_psi() -> None:
    rng = np.random.default_rng(0)
    a = rng.normal(size=20_000)
    b = rng.normal(size=20_000)
    assert psi(a, b) < 0.01


def test_shifted_distribution_is_significant() -> None:
    rng = np.random.default_rng(0)
    a = rng.normal(size=20_000)
    b = rng.normal(loc=2.0, size=20_000)
    assert psi(a, b) > 0.25


def test_constant_and_empty_features_are_safe() -> None:
    assert psi(np.ones(100), np.ones(100) * 5) == 0.0
    assert psi(np.array([np.nan]), np.array([1.0])) == 0.0


def test_non_finite_values_ignored() -> None:
    rng = np.random.default_rng(1)
    a = rng.normal(size=5_000)
    b = np.concatenate([rng.normal(size=5_000), [np.nan, np.inf]])
    assert psi(a, b) < 0.05


def test_rating_thresholds() -> None:
    assert rating(0.05) == "stable"
    assert rating(0.15) == "moderate"
    assert rating(0.30) == "significant"


def test_drift_report_ranks_shifted_feature_first() -> None:
    rng = np.random.default_rng(2)
    ref = pd.DataFrame({"stable": rng.normal(size=10_000), "shifted": rng.normal(size=10_000)})
    cur = pd.DataFrame(
        {"stable": rng.normal(size=10_000), "shifted": rng.normal(loc=3.0, size=10_000)}
    )
    report = drift_report(ref, cur, top_k=2)
    top = report["top"]
    assert isinstance(top, list)
    assert top[0]["feature"] == "shifted"
    assert report["features_significant"] == 1
    assert report["features_stable"] == 1
