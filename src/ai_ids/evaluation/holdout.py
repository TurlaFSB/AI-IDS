"""Leave-one-attack-family-out evaluation.

CICIDS2017 attack runs are bursts of near-identical flows, so an in-distribution test
mostly measures recall on attack tools the model has already seen. Here a family is removed
from the training data entirely and the model must detect it anyway, which estimates how
well a supervised detector generalises to novel attacks.
"""

from __future__ import annotations

import logging
from typing import Any

from ai_ids.config import TrainConfig
from ai_ids.data.loader import CATEGORY, IS_ATTACK
from ai_ids.data.split import DatasetSplit
from ai_ids.labels import BENIGN
from ai_ids.models.detectors import RandomForestDetector

logger = logging.getLogger(__name__)

DEFAULT_HOLDOUT_TREES = 50
DEFAULT_MIN_TEST_SUPPORT = 30


def leave_one_family_out(
    split: DatasetSplit, features: list[str], config: TrainConfig
) -> dict[str, dict[str, float | int]]:
    """For each attack family, train without it and measure how much of it is still detected.

    The alert threshold is calibrated on benign validation flows exactly as in normal
    training, so recall here is at the same false-positive budget.
    """
    n_estimators = int(config.holdout.get("n_estimators", DEFAULT_HOLDOUT_TREES))
    min_support = int(config.holdout.get("min_test_support", DEFAULT_MIN_TEST_SUPPORT))
    n_jobs = int(config.random_forest.get("n_jobs", -1))

    test_counts = split.test[CATEGORY].value_counts()
    families = sorted(
        str(name)
        for name, count in test_counts.items()
        if name != BENIGN and int(count) >= min_support
    )
    val_benign = split.val[~split.val[IS_ATTACK]]
    test_benign = split.test[~split.test[IS_ATTACK]]

    results: dict[str, dict[str, float | int]] = {}
    for family in families:
        logger.info("holdout", extra={"fields": {"family": family}})
        train = split.train[split.train[CATEGORY] != family]
        detector = RandomForestDetector(n_estimators=n_estimators, seed=config.seed, n_jobs=n_jobs)
        detector.fit(train[features], train[CATEGORY])
        threshold = detector.calibrate(detector.score(val_benign[features]), config.target_fpr)
        family_test = split.test[split.test[CATEGORY] == family]
        recall = float((detector.score(family_test[features]) > threshold).mean())
        fpr = float((detector.score(test_benign[features]) > threshold).mean())
        results[family] = {
            "test_support": len(family_test),
            "train_flows_removed": len(split.train) - len(train),
            "recall_unseen": recall,
            "false_positive_rate": fpr,
        }
    return results


def run_holdout(split: DatasetSplit, features: list[str], config: TrainConfig) -> dict[str, Any]:
    return {
        "target_fpr": config.target_fpr,
        "n_estimators": int(config.holdout.get("n_estimators", DEFAULT_HOLDOUT_TREES)),
        "families": leave_one_family_out(split, features, config),
    }
