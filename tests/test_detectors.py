import numpy as np
import pandas as pd
import pytest

from ai_ids.data.loader import CATEGORY, IS_ATTACK, feature_columns
from ai_ids.data.split import chronological_split
from ai_ids.models.detectors import IsolationForestDetector, RandomForestDetector


@pytest.fixture(scope="module")
def split(cleaned: pd.DataFrame):  # type: ignore[no-untyped-def]
    return chronological_split(cleaned)


@pytest.fixture(scope="module")
def features(cleaned: pd.DataFrame) -> list[str]:
    return feature_columns(cleaned)


def test_random_forest_separates_attacks(split, features) -> None:  # type: ignore[no-untyped-def]
    det = RandomForestDetector(n_estimators=50, seed=1).fit(
        split.train[features], split.train[CATEGORY]
    )
    scores = det.score(split.test[features])
    y = split.test[IS_ATTACK].to_numpy()
    assert scores[y].mean() > scores[~y].mean()
    assert set(det.predict_category(split.test[features])) <= set(split.train[CATEGORY])


def test_isolation_forest_scores_attacks_higher(split, features) -> None:  # type: ignore[no-untyped-def]
    det = IsolationForestDetector(n_estimators=50, seed=1).fit(
        split.train[features], split.train[CATEGORY]
    )
    scores = det.score(split.test[features])
    y = split.test[IS_ATTACK].to_numpy()
    assert scores[y].mean() > scores[~y].mean()


def test_calibration_bounds_validation_fpr(split, features) -> None:  # type: ignore[no-untyped-def]
    det = RandomForestDetector(n_estimators=30, seed=1).fit(
        split.train[features], split.train[CATEGORY]
    )
    benign = split.val[~split.val[IS_ATTACK]]
    scores = det.score(benign[features])
    det.calibrate(scores, 0.02)
    assert (scores > det.threshold_).mean() <= 0.02


def test_predict_requires_calibration(split, features) -> None:  # type: ignore[no-untyped-def]
    det = RandomForestDetector(n_estimators=10).fit(split.train[features], split.train[CATEGORY])
    with pytest.raises(RuntimeError, match="threshold"):
        det.predict(split.test[features])


def test_unfitted_detector_rejected() -> None:
    with pytest.raises(RuntimeError, match="not fitted"):
        RandomForestDetector().score(pd.DataFrame({"a": [1.0]}))


def test_missing_feature_rejected(split, features) -> None:  # type: ignore[no-untyped-def]
    det = RandomForestDetector(n_estimators=10).fit(split.train[features], split.train[CATEGORY])
    with pytest.raises(ValueError, match="missing"):
        det.score(split.test[features].drop(columns=[features[0]]))


def test_training_without_benign_rejected(split, features) -> None:  # type: ignore[no-untyped-def]
    attacks = split.train[split.train[IS_ATTACK]]
    with pytest.raises(ValueError, match="benign"):
        RandomForestDetector().fit(attacks[features], attacks[CATEGORY])
    with pytest.raises(ValueError, match="benign"):
        IsolationForestDetector().fit(attacks[features], attacks[CATEGORY])


def test_invalid_target_fpr_rejected() -> None:
    det = RandomForestDetector()
    with pytest.raises(ValueError, match="target_fpr"):
        det.calibrate(np.array([0.1]), 1.5)
    with pytest.raises(ValueError, match="benign"):
        det.calibrate(np.array([]), 0.01)
