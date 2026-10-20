"""Detectors that turn flow features into an attack score (higher = more suspicious)."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, ClassVar, Self

import numpy as np
import pandas as pd
from numpy.typing import NDArray
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import QuantileTransformer

from ai_ids.evaluation.metrics import threshold_for_fpr
from ai_ids.labels import BENIGN

FloatArray = NDArray[np.float64]


class BaseDetector(ABC):
    name: ClassVar[str]

    def __init__(self) -> None:
        self.feature_names_: list[str] = []
        self.threshold_: float | None = None
        self._pipeline: Pipeline | None = None

    def _align(self, X: pd.DataFrame) -> pd.DataFrame:
        missing = [c for c in self.feature_names_ if c not in X.columns]
        if missing:
            raise ValueError(f"input is missing {len(missing)} feature(s): {missing[:5]}")
        return X[self.feature_names_]

    def _fitted(self) -> Pipeline:
        if self._pipeline is None:
            raise RuntimeError(f"{self.name} detector is not fitted")
        return self._pipeline

    @abstractmethod
    def fit(self, X: pd.DataFrame, categories: pd.Series) -> Self:
        """Fit on training flows; `categories` holds the attack category per row."""

    @abstractmethod
    def score(self, X: pd.DataFrame) -> FloatArray:
        """Return an attack score per row; higher means more likely malicious."""

    def calibrate(self, benign_scores: FloatArray, target_fpr: float) -> float:
        """Set the alert threshold so at most `target_fpr` of benign validation flows alert."""
        self.threshold_ = threshold_for_fpr(benign_scores, target_fpr)
        return self.threshold_

    def predict(self, X: pd.DataFrame) -> NDArray[np.bool_]:
        if self.threshold_ is None:
            raise RuntimeError("detector has no calibrated threshold")
        return self.score(X) > self.threshold_

    @abstractmethod
    def set_inference_threads(self, n_jobs: int) -> None:
        """Adjust parallelism of the fitted estimator (1 is best for single-flow latency)."""


class RandomForestDetector(BaseDetector):
    """Supervised multi-class classifier; score is 1 - P(benign)."""

    name = "random_forest"

    def __init__(
        self,
        n_estimators: int = 200,
        max_depth: int | None = None,
        min_samples_leaf: int = 1,
        seed: int = 42,
        n_jobs: int = -1,
    ) -> None:
        super().__init__()
        self._params: dict[str, Any] = {
            "n_estimators": n_estimators,
            "max_depth": max_depth,
            "min_samples_leaf": min_samples_leaf,
            "class_weight": "balanced_subsample",
            "random_state": seed,
            "n_jobs": n_jobs,
        }

    def fit(self, X: pd.DataFrame, categories: pd.Series) -> Self:
        if BENIGN not in set(categories):
            raise ValueError("training data contains no benign flows")
        self.feature_names_ = list(X.columns)
        self._pipeline = Pipeline(
            [
                ("impute", SimpleImputer(strategy="median", keep_empty_features=True)),
                ("clf", RandomForestClassifier(**self._params)),
            ]
        )
        self._pipeline.fit(X, categories.to_numpy())
        return self

    def _classifier(self) -> RandomForestClassifier:
        clf = self._fitted().named_steps["clf"]
        assert isinstance(clf, RandomForestClassifier)
        return clf

    def score(self, X: pd.DataFrame) -> FloatArray:
        proba = self._fitted().predict_proba(self._align(X))
        benign_idx = list(self._classifier().classes_).index(BENIGN)
        return np.asarray(1.0 - proba[:, benign_idx], dtype=np.float64)

    def predict_category(self, X: pd.DataFrame) -> NDArray[np.str_]:
        return np.asarray(self._fitted().predict(self._align(X)))

    def set_inference_threads(self, n_jobs: int) -> None:
        self._classifier().n_jobs = n_jobs


class IsolationForestDetector(BaseDetector):
    """Unsupervised novelty detector trained on benign traffic only."""

    name = "isolation_forest"

    def __init__(
        self,
        n_estimators: int = 200,
        max_samples: int | str = 256,
        seed: int = 42,
        n_jobs: int = -1,
    ) -> None:
        super().__init__()
        self._seed = seed
        self._params: dict[str, Any] = {
            "n_estimators": n_estimators,
            "max_samples": max_samples,
            "contamination": "auto",
            "random_state": seed,
            "n_jobs": n_jobs,
        }

    def fit(self, X: pd.DataFrame, categories: pd.Series) -> Self:
        benign = X[(categories == BENIGN).to_numpy()]
        if benign.empty:
            raise ValueError("training data contains no benign flows")
        self.feature_names_ = list(X.columns)
        self._pipeline = Pipeline(
            [
                ("impute", SimpleImputer(strategy="median", keep_empty_features=True)),
                (
                    # Flow features are heavy-tailed; rank-transform so tree splits are useful.
                    "rank",
                    QuantileTransformer(
                        n_quantiles=min(1000, len(benign)),
                        output_distribution="uniform",
                        subsample=200_000,
                        random_state=self._seed,
                    ),
                ),
                ("iso", IsolationForest(**self._params)),
            ]
        )
        self._pipeline.fit(benign)
        return self

    def score(self, X: pd.DataFrame) -> FloatArray:
        iso = self._fitted().named_steps["iso"]
        features = self._fitted()[:-1].transform(self._align(X))
        return np.asarray(-iso.score_samples(features), dtype=np.float64)

    def set_inference_threads(self, n_jobs: int) -> None:
        self._fitted().named_steps["iso"].n_jobs = n_jobs
