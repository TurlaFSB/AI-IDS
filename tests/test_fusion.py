import numpy as np
import pandas as pd
import pytest

from ai_ids.models.detectors import (
    FUSION_RULES,
    BaseDetector,
    FusionMaxDetector,
    FusionMeanDetector,
)


class _Column(BaseDetector):
    """Test double: the score is simply one column of the input."""

    name = "column"

    def __init__(self, column: str, features: list[str] | None = None) -> None:
        super().__init__()
        self.column = column
        self.feature_names_ = features or ["a", "b"]

    def fit(self, X: pd.DataFrame, categories: pd.Series) -> "_Column":
        return self

    def score(self, X: pd.DataFrame) -> np.ndarray:
        return X[self.column].to_numpy(dtype=float)

    def set_inference_threads(self, n_jobs: int) -> None:
        self.threads = n_jobs


def _benign() -> pd.DataFrame:
    rng = np.random.default_rng(0)
    return pd.DataFrame({"a": rng.uniform(0, 1, 400), "b": rng.uniform(0, 100, 400)})


def test_rules_registered() -> None:
    assert set(FUSION_RULES) == {"mean", "max"}


def test_scores_are_mapped_to_benign_percentiles() -> None:
    benign = _benign()
    fusion = FusionMaxDetector([_Column("a"), _Column("b")]).fit_reference(benign)
    scored = fusion.score(pd.DataFrame({"a": [-5.0, 0.5, 99.0], "b": [-5.0, 50.0, 1e6]}))
    assert scored[0] == 0.0  # below every benign reference score
    assert scored[2] == 1.0  # above every benign reference score
    assert 0.3 < scored[1] < 0.9  # mid-range benign-like values land mid-percentile


def test_mean_requires_agreement_and_max_does_not() -> None:
    benign = _benign()
    only_a = pd.DataFrame({"a": [99.0], "b": [-5.0]})  # a sees an attack, b sees nothing
    mean = FusionMeanDetector([_Column("a"), _Column("b")]).fit_reference(benign)
    maximum = FusionMaxDetector([_Column("a"), _Column("b")]).fit_reference(benign)
    assert maximum.score(only_a)[0] == 1.0
    assert mean.score(only_a)[0] == pytest.approx(0.5)


def test_reference_and_calibration_halves_do_not_overlap() -> None:
    benign = _benign()
    fusion = FusionMeanDetector([_Column("a"), _Column("b")])
    calibration = fusion.select_calibration_rows(benign)
    assert len(calibration) == len(benign) // 2
    fusion.fit_reference(benign)
    assert len(fusion.references_[0]) == len(benign) - len(calibration)
    assert set(benign.iloc[1::2].index) == set(calibration.index)


def test_validation_errors() -> None:
    with pytest.raises(ValueError, match="at least two"):
        FusionMeanDetector([_Column("a")])
    with pytest.raises(ValueError, match="same features"):
        FusionMeanDetector([_Column("a"), _Column("b", features=["a"])])
    fusion = FusionMeanDetector([_Column("a"), _Column("b")])
    with pytest.raises(TypeError, match="already-fitted"):
        fusion.fit(_benign(), pd.Series(["benign"] * 400))
    with pytest.raises(RuntimeError, match="reference"):
        fusion.score(_benign())
    with pytest.raises(ValueError, match="no benign"):
        fusion.fit_reference(_benign().iloc[:0])


def test_threads_propagate_to_components() -> None:
    components = [_Column("a"), _Column("b")]
    FusionMaxDetector(components).set_inference_threads(3)
    assert all(c.threads == 3 for c in components)  # type: ignore[attr-defined]
