"""End-to-end training and evaluation run."""

from __future__ import annotations

import dataclasses
import json
import logging
import platform
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any

import numpy as np
import sklearn

from ai_ids import __version__
from ai_ids.config import TrainConfig
from ai_ids.data.integrity import dataset_checksums
from ai_ids.data.loader import (
    CATEGORY,
    IS_ATTACK,
    LABEL,
    TIMESTAMP,
    CleaningReport,
    feature_columns,
    load_dataset,
)
from ai_ids.data.split import DatasetSplit, chronological_split
from ai_ids.evaluation.metrics import (
    binary_report,
    breakdown_by_group,
    false_positive_profile,
    latency_profile,
    macro_recall,
    per_class_recall,
    threshold_for_fpr,
)
from ai_ids.evaluation.robustness import evasion_report
from ai_ids.models.detectors import (
    BaseDetector,
    HistGradientBoostingDetector,
    IsolationForestDetector,
    RandomForestDetector,
)
from ai_ids.monitoring.drift import drift_report
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


def build_detectors(config: TrainConfig) -> list[BaseDetector]:
    factories: dict[str, Callable[[], BaseDetector]] = {
        "random_forest": lambda: RandomForestDetector(seed=config.seed, **config.random_forest),
        "isolation_forest": lambda: IsolationForestDetector(
            seed=config.seed, **config.isolation_forest
        ),
        "hist_gradient_boosting": lambda: HistGradientBoostingDetector(
            seed=config.seed, **config.hist_gradient_boosting
        ),
    }
    return [factories[name]() for name in config.detectors]


def _git_dirty() -> bool | None:
    """True if the working tree has uncommitted changes (results then aren't reproducible)."""
    try:
        result = subprocess.run(
            ["git", "status", "--porcelain"],  # noqa: S607
            capture_output=True,
            text=True,
            timeout=10,
            check=True,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return bool(result.stdout.strip())


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
    per_attack = per_class_recall(split.test[LABEL], y_pred, y_true)
    report: dict[str, Any] = {
        "target_fpr": config.target_fpr,
        "test": binary_report(y_true, test_scores, threshold),
        "operating_points": operating_points,
        "per_attack_recall": per_attack,
        "macro_recall": macro_recall(per_attack),
        "macro_recall_min_support_30": macro_recall(per_attack, min_support=30),
        "latency_single_thread": latency_profile(detector.score, split.test[features]),
    }
    if config.evasion_analysis:
        report["evasion"] = evasion_report(
            detector, split.test[split.test[IS_ATTACK]], features, threshold
        )
    if TIMESTAMP in split.test.columns:
        days = split.test[TIMESTAMP].dt.strftime("%Y-%m-%d")
        report["by_day"] = breakdown_by_group(days, y_true, y_pred)
        hours = split.test[TIMESTAMP].dt.strftime("%Y-%m-%d %H:00")
        report["by_hour"] = breakdown_by_group(hours, y_true, y_pred)
    report["false_positive_profile"] = false_positive_profile(
        split.test, y_true, y_pred, config.fp_profile_columns
    )
    if isinstance(detector, RandomForestDetector):
        predicted = detector.predict_category(split.test[features])
        actual = split.test[CATEGORY].to_numpy()
        report["category_accuracy"] = float(np.mean(predicted == actual))
    return report


def _drift_section(split: DatasetSplit, features: list[str]) -> dict[str, Any]:
    """How far later benign traffic has drifted from the benign traffic used for training."""
    reference = split.train[~split.train[IS_ATTACK]][features]
    return {
        name: drift_report(reference, part[~part[IS_ATTACK]][features])
        for name, part in (("train_vs_val", split.val), ("train_vs_test", split.test))
    }


def prepare_data(
    data_path: Path, config: TrainConfig
) -> tuple[DatasetSplit, list[str], CleaningReport]:
    """Load, clean, and split a dataset; shared by training and holdout evaluation."""
    df, cleaning = load_dataset(
        data_path,
        pm_fix_before_hour=config.timestamp_pm_fix_before_hour,
        dayfirst=config.timestamp_dayfirst,
    )
    features = feature_columns(df)
    split = chronological_split(df, config.split_fractions)
    if split.val[~split.val[IS_ATTACK]].empty or split.test.empty:
        raise ValueError("dataset too small: validation or test split has no usable rows")
    logger.info(
        "dataset ready",
        extra={"fields": {"features": len(features), "train": len(split.train)}},
    )
    return split, features, cleaning


def run_training(
    data_path: Path,
    output_dir: Path,
    config: TrainConfig,
    *,
    hmac_key: bytes | None = None,
) -> dict[str, Any]:
    split, features, cleaning = prepare_data(data_path, config)

    detectors = build_detectors(config)
    report: dict[str, Any] = {
        "version": __version__,
        "config": dataclasses.asdict(config),
        "environment": {
            "python": platform.python_version(),
            "scikit_learn": sklearn.__version__,
            "git_commit": _git_commit(),
            "git_dirty": _git_dirty(),
        },
        "dataset": {
            "files_sha256": dataset_checksums(data_path),
            "cleaning": cleaning.to_dict(),
            "n_features": len(features),
            "rows": {"train": len(split.train), "val": len(split.val), "test": len(split.test)},
            "class_counts": _class_counts(split),
        },
        "benign_drift": _drift_section(split, features),
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
