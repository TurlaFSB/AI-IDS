"""End-to-end training and evaluation run."""

from __future__ import annotations

import dataclasses
import json
import logging
import platform
import subprocess
from pathlib import Path
from typing import Any

import numpy as np
import sklearn

from ai_ids import __version__
from ai_ids.config import TrainConfig
from ai_ids.data.loader import CATEGORY, IS_ATTACK, LABEL, feature_columns, load_dataset
from ai_ids.data.split import DatasetSplit, chronological_split
from ai_ids.evaluation.metrics import (
    binary_report,
    latency_profile,
    per_class_recall,
    threshold_for_fpr,
)
from ai_ids.models.detectors import (
    BaseDetector,
    IsolationForestDetector,
    RandomForestDetector,
)
from ai_ids.registry import save_detector

logger = logging.getLogger(__name__)


def _git_commit() -> str | None:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],  # noqa: S607
            capture_output=True,
            text=True,
            timeout=5,
            check=True,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return result.stdout.strip() or None


def _class_counts(split: DatasetSplit) -> dict[str, dict[str, int]]:
    return {
        name: {str(k): int(v) for k, v in part[LABEL].value_counts().sort_index().items()}
        for name, part in (("train", split.train), ("val", split.val), ("test", split.test))
    }


def evaluate_detector(
    detector: BaseDetector, split: DatasetSplit, features: list[str], config: TrainConfig
) -> dict[str, Any]:
    val_benign = split.val[~split.val[IS_ATTACK]]
    val_scores = detector.score(val_benign[features])
    threshold = detector.calibrate(val_scores, config.target_fpr)

    test_scores = detector.score(split.test[features])
    y_true = split.test[IS_ATTACK].to_numpy(dtype=bool)
    y_pred = test_scores > threshold

    operating_points = {}
    for fpr in config.operating_fprs:
        point_threshold = threshold_for_fpr(val_scores, fpr)
        operating_points[f"fpr_{fpr:g}"] = binary_report(y_true, test_scores, point_threshold)

    detector.set_inference_threads(1)
    report: dict[str, Any] = {
        "target_fpr": config.target_fpr,
        "test": binary_report(y_true, test_scores, threshold),
        "operating_points": operating_points,
        "per_attack_recall": per_class_recall(split.test[LABEL], y_pred, y_true),
        "latency_single_thread": latency_profile(detector.score, split.test[features]),
    }
    if isinstance(detector, RandomForestDetector):
        predicted = detector.predict_category(split.test[features])
        actual = split.test[CATEGORY].to_numpy()
        report["category_accuracy"] = float(np.mean(predicted == actual))
    return report


def run_training(
    data_path: Path,
    output_dir: Path,
    config: TrainConfig,
    *,
    hmac_key: bytes | None = None,
) -> dict[str, Any]:
    df, cleaning = load_dataset(data_path, pm_fix_before_hour=config.timestamp_pm_fix_before_hour)
    features = feature_columns(df)
    split = chronological_split(df, config.split_fractions)
    if split.val[~split.val[IS_ATTACK]].empty or split.test.empty:
        raise ValueError("dataset too small: validation or test split has no usable rows")
    logger.info(
        "dataset ready",
        extra={"fields": {"features": len(features), "train": len(split.train)}},
    )

    detectors: list[BaseDetector] = [
        RandomForestDetector(seed=config.seed, **config.random_forest),
        IsolationForestDetector(seed=config.seed, **config.isolation_forest),
    ]
    report: dict[str, Any] = {
        "version": __version__,
        "config": dataclasses.asdict(config),
        "environment": {
            "python": platform.python_version(),
            "scikit_learn": sklearn.__version__,
            "git_commit": _git_commit(),
        },
        "dataset": {
            "cleaning": cleaning.to_dict(),
            "n_features": len(features),
            "rows": {"train": len(split.train), "val": len(split.val), "test": len(split.test)},
            "class_counts": _class_counts(split),
        },
        "models": {},
    }

    for detector in detectors:
        logger.info("training", extra={"fields": {"detector": detector.name}})
        detector.fit(split.train[features], split.train[CATEGORY])
        result = evaluate_detector(detector, split, features, config)
        report["models"][detector.name] = result
        save_detector(
            detector,
            output_dir / detector.name,
            metadata={"test": result["test"], "dataset": report["dataset"]["rows"]},
            hmac_key=hmac_key,
        )

    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "report.json").write_text(json.dumps(report, indent=2, default=str) + "\n")
    return report
