import numpy as np
import pandas as pd
import pytest

from ai_ids.data.loader import CATEGORY, IS_ATTACK, feature_columns
from ai_ids.evaluation.familystudy import (
    compare_separability,
    feature_separability,
    run_family_study,
    split_family,
)
from ai_ids.models.detectors import RandomForestDetector


def _frame(seed: int, shift: float) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    n = 400
    benign = pd.DataFrame(
        {"a": rng.normal(0, 1, n), "b": rng.normal(0, 1, n), "c": rng.normal(0, 1, n)}
    )
    family = pd.DataFrame(
        {"a": rng.normal(shift, 1, n), "b": rng.normal(-shift, 1, n), "c": rng.normal(0, 1, n)}
    )
    frame = pd.concat(
        [benign.assign(**{CATEGORY: "benign"}), family.assign(**{CATEGORY: "botnet"})]
    )
    frame[IS_ATTACK] = frame[CATEGORY] != "benign"
    return frame.reset_index(drop=True)


def test_separability_reports_direction_and_strength() -> None:
    frame = _frame(1, 2.0)
    family, benign = split_family(frame, "botnet", max_per_class=1000, seed=0)
    table = feature_separability(family, benign, ["a", "b", "c"])
    assert table.loc["a", "effect"] > 0.3  # larger for the family
    assert table.loc["b", "effect"] < -0.3  # smaller for the family
    assert abs(table.loc["c", "effect"]) < 0.1  # uninformative


def test_comparison_detects_agreeing_and_opposing_datasets() -> None:
    features = ["a", "b", "c"]
    same_a = feature_separability(
        *split_family(_frame(1, 2.0), "botnet", max_per_class=500, seed=0), features
    )
    same_b = feature_separability(
        *split_family(_frame(2, 2.0), "botnet", max_per_class=500, seed=0), features
    )
    flipped = feature_separability(
        *split_family(_frame(3, -2.0), "botnet", max_per_class=500, seed=0), features
    )
    agree = compare_separability(same_a, same_b, top_k=2)
    assert agree["spearman_of_effects"] > 0.9
    assert agree["same_direction_among_shared"] == len(agree["shared_top_features"])
    opposed = compare_separability(same_a, flipped, top_k=2)
    assert opposed["same_direction_among_shared"] == 0


def test_missing_family_or_benign_fails_loudly() -> None:
    frame = _frame(1, 1.0)
    with pytest.raises(ValueError, match="no flows"):
        split_family(frame, "dos", max_per_class=10, seed=0)
    with pytest.raises(ValueError, match="no benign"):
        split_family(frame[frame[IS_ATTACK]], "botnet", max_per_class=10, seed=0)


def test_study_with_model_scores(cleaned: pd.DataFrame) -> None:
    features = feature_columns(cleaned)
    detector = RandomForestDetector(n_estimators=10).fit(cleaned[features], cleaned[CATEGORY])
    detector.calibrate(detector.score(cleaned[~cleaned[IS_ATTACK]][features]), 0.05)
    report = run_family_study(
        cleaned, cleaned, "botnet", detector=detector, max_per_class=300, seed=1
    )
    assert report["comparison"]["spearman_of_effects"] == pytest.approx(1.0)
    for side in ("source", "target"):
        scores = report["model_scores"][side]
        assert 0.0 <= scores["auc_family_vs_benign"] <= 1.0
        assert scores["family_above_stored_threshold"] is not None
    assert "cannot separate" in report["note"]
