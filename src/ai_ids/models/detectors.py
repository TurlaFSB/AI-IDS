"""Detectors that turn flow features into an attack score (higher = more suspicious)."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Sequence
from typing import Any, ClassVar, Self

import numpy as np
import pandas as pd
from numpy.typing import NDArray
from sklearn.ensemble import (
    HistGradientBoostingClassifier,
    IsolationForest,
    RandomForestClassifier,
)
from sklearn.impute import SimpleImputer
from sklearn.neural_network import MLPRegressor
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import QuantileTransformer
from threadpoolctl import threadpool_limits

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

    def select_calibration_rows(self, val_benign: pd.DataFrame) -> pd.DataFrame:
        """Benign validation rows to calibrate the threshold on (all of them by default)."""
        return val_benign

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


class HistGradientBoostingDetector(BaseDetector):
    """Supervised attack-vs-benign gradient boosting; score is P(attack).

    Unlike a Random Forest vote share, boosted probabilities are continuous, so alert
    thresholds at very low false-positive rates remain meaningful. Missing values are handled
    natively by the estimator.
    """

    name = "hist_gradient_boosting"

    def __init__(
        self,
        max_iter: int = 200,
        learning_rate: float = 0.1,
        max_leaf_nodes: int = 31,
        seed: int = 42,
        n_jobs: int | None = None,
    ) -> None:
        super().__init__()
        self._threads = n_jobs
        self._params: dict[str, Any] = {
            "max_iter": max_iter,
            "learning_rate": learning_rate,
            "max_leaf_nodes": max_leaf_nodes,
            "class_weight": "balanced",
            "early_stopping": False,
            "random_state": seed,
        }

    def fit(self, X: pd.DataFrame, categories: pd.Series) -> Self:
        is_attack = (categories != BENIGN).to_numpy()
        if is_attack.all() or not is_attack.any():
            raise ValueError("training data must contain both benign and attack flows")
        self.feature_names_ = list(X.columns)
        self._pipeline = Pipeline([("clf", HistGradientBoostingClassifier(**self._params))])
        with threadpool_limits(limits=self._threads):
            self._pipeline.fit(X, is_attack)
        return self

    def score(self, X: pd.DataFrame) -> FloatArray:
        with threadpool_limits(limits=self._threads):
            proba = self._fitted().predict_proba(self._align(X))
        return np.asarray(proba[:, 1], dtype=np.float64)

    def set_inference_threads(self, n_jobs: int) -> None:
        self._threads = n_jobs


class AutoencoderDetector(BaseDetector):
    """Reconstruction-error anomaly detector trained on benign traffic only.

    A small multilayer perceptron learns to reproduce rank-normalised benign flow features
    through a narrow bottleneck; flows it reconstructs poorly are scored as suspicious. It never
    sees attack labels, so its recall on any attack family is a measure of novelty detection.
    Implemented with scikit-learn (CPU) to keep the dependency set small and reproducible.
    """

    name = "autoencoder"

    def __init__(
        self,
        hidden_layer_sizes: tuple[int, ...] = (64, 16, 64),
        max_iter: int = 40,
        learning_rate_init: float = 1e-3,
        max_train_rows: int = 300_000,
        seed: int = 42,
        n_jobs: int | None = None,
    ) -> None:
        super().__init__()
        self._seed = seed
        self._threads = n_jobs
        self._max_train_rows = max_train_rows
        self._net: MLPRegressor | None = None
        self.training_info_: dict[str, Any] = {}
        self._params: dict[str, Any] = {
            "hidden_layer_sizes": tuple(hidden_layer_sizes),
            "activation": "relu",
            "solver": "adam",
            "learning_rate_init": learning_rate_init,
            "max_iter": max_iter,
            "early_stopping": True,
            "validation_fraction": 0.1,
            "n_iter_no_change": 5,
            "random_state": seed,
        }

    def fit(self, X: pd.DataFrame, categories: pd.Series) -> Self:
        benign = X[(categories == BENIGN).to_numpy()]
        if benign.empty:
            raise ValueError("training data contains no benign flows")
        if len(benign) > self._max_train_rows:
            benign = benign.sample(n=self._max_train_rows, random_state=self._seed)
        self.feature_names_ = list(X.columns)
        prep = Pipeline(
            [
                ("impute", SimpleImputer(strategy="median", keep_empty_features=True)),
                (
                    "rank",
                    QuantileTransformer(
                        n_quantiles=min(1000, len(benign)),
                        output_distribution="normal",
                        subsample=200_000,
                        random_state=self._seed,
                    ),
                ),
            ]
        )
        with threadpool_limits(limits=self._threads):
            features = prep.fit_transform(benign)
            net = MLPRegressor(**self._params)
            net.fit(features, features)
        self._pipeline = prep
        self._net = net
        self.training_info_ = {
            "epochs": int(net.n_iter_),
            "max_epochs": int(self._params["max_iter"]),
            "reached_max_epochs": bool(net.n_iter_ >= self._params["max_iter"]),
            "training_rows": len(benign),
            "best_validation_loss": float(net.best_loss_) if net.best_loss_ is not None else None,
        }
        return self

    def score(self, X: pd.DataFrame) -> FloatArray:
        if self._net is None:
            raise RuntimeError(f"{self.name} detector is not fitted")
        with threadpool_limits(limits=self._threads):
            features = self._fitted().transform(self._align(X))
            reconstruction = self._net.predict(features)
        return np.asarray(((features - reconstruction) ** 2).mean(axis=1), dtype=np.float64)

    def set_inference_threads(self, n_jobs: int) -> None:
        self._threads = n_jobs


class AugmentedRandomForestDetector(RandomForestDetector):
    """Random Forest trained on evasion-augmented attack flows (augmented by the pipeline)."""

    name = "random_forest_aug"


class AugmentedHistGradientBoostingDetector(HistGradientBoostingDetector):
    """Gradient boosting trained on evasion-augmented attack flows (see the pipeline)."""

    name = "hist_gradient_boosting_aug"


class _FusionDetector(BaseDetector):
    """Combine already-fitted detectors by averaging or maximising their benign percentiles.

    Component scores live on different scales, so each is mapped to the fraction of benign
    reference scores it exceeds (a value in [0, 1]); benign flows are then roughly uniform and
    attacks sit near 1 for every component. The reference uses one interleaved half of the benign
    validation rows and the threshold is calibrated on the other half, so the percentile map is
    never fitted on the rows used to set the alert threshold.
    """

    rule: ClassVar[str]

    def __init__(self, components: Sequence[BaseDetector]) -> None:
        super().__init__()
        if len(components) < 2:
            raise ValueError("fusion needs at least two detectors")
        if len({tuple(c.feature_names_) for c in components}) != 1:
            raise ValueError("fusion components must use the same features")
        self.components = list(components)
        self.feature_names_ = list(components[0].feature_names_)
        self.references_: list[FloatArray] = []

    def fit(self, X: pd.DataFrame, categories: pd.Series) -> Self:
        raise TypeError("fusion wraps already-fitted detectors; call fit_reference instead")

    def fit_reference(self, val_benign: pd.DataFrame) -> Self:
        rows = val_benign.iloc[::2]
        if rows.empty:
            raise ValueError("no benign validation rows for the fusion reference")
        self.references_ = [np.sort(c.score(rows)) for c in self.components]
        return self

    def select_calibration_rows(self, val_benign: pd.DataFrame) -> pd.DataFrame:
        return val_benign.iloc[1::2]

    def _combine(self, ranks: FloatArray) -> FloatArray:
        raise NotImplementedError

    def score(self, X: pd.DataFrame) -> FloatArray:
        if not self.references_:
            raise RuntimeError(f"{self.name} detector has no reference; call fit_reference")
        aligned = self._align(X)
        ranks = np.vstack(
            [
                np.searchsorted(reference, component.score(aligned), side="right") / len(reference)
                for component, reference in zip(self.components, self.references_, strict=True)
            ]
        )
        return self._combine(ranks)

    def set_inference_threads(self, n_jobs: int) -> None:
        for component in self.components:
            component.set_inference_threads(n_jobs)


class FusionMeanDetector(_FusionDetector):
    """Average of component benign percentiles: an alert needs broad agreement."""

    name = "fusion_mean"
    rule = "mean"

    def _combine(self, ranks: FloatArray) -> FloatArray:
        return np.asarray(ranks.mean(axis=0), dtype=np.float64)


class FusionMaxDetector(_FusionDetector):
    """Maximum of component benign percentiles: any one component can raise an alert."""

    name = "fusion_max"
    rule = "max"

    def _combine(self, ranks: FloatArray) -> FloatArray:
        return np.asarray(ranks.max(axis=0), dtype=np.float64)


FUSION_RULES: dict[str, type[_FusionDetector]] = {
    FusionMeanDetector.rule: FusionMeanDetector,
    FusionMaxDetector.rule: FusionMaxDetector,
}
