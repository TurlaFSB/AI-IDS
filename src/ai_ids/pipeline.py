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
import pandas as pd
import sklearn

from ai_ids import __version__
from ai_ids.config import AUGMENTED_SUFFIX, TrainConfig
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
    host_concentration,
    latency_profile,
    macro_recall,
    per_class_recall,
    threshold_for_fpr,
)
from ai_ids.evaluation.robustness import augment_attack_flows, evasion_report
from ai_ids.models.detectors import (
    AugmentedHistGradientBoostingDetector,
    AugmentedRandomForestDetector,
    AutoencoderDetector,
    BaseDetector,
    HistGradientBoostingDetector,
    IsolationForestDetector,
    RandomForestDetector,
)
from ai_ids.monitoring.drift import drift_report
from ai_ids.registry import load_detector, read_manifest, save_detector

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


def _augmentation_params(config: TrainConfig) -> dict[str, Any]:
    allowed = {"slowdowns", "paddings", "fraction"}
    unknown = sorted(set(config.augmentation) - allowed)
    if unknown:
        raise ValueError(f"unknown augmentation keys: {unknown}")
    params: dict[str, Any] = dict(config.augmentation)
    for key in ("slowdowns", "paddings"):
        if key in params:
            params[key] = tuple(float(v) for v in params[key])
    return params


def build_detectors(config: TrainConfig) -> list[BaseDetector]:
    factories: dict[str, Callable[[], BaseDetector]] = {
        "random_forest": lambda: RandomForestDetector(seed=config.seed, **config.random_forest),
        "isolation_forest": lambda: IsolationForestDetector(
            seed=config.seed, **config.isolation_forest
        ),
        "hist_gradient_boosting": lambda: HistGradientBoostingDetector(
            seed=config.seed, **config.hist_gradient_boosting
        ),
        "autoencoder": lambda: AutoencoderDetector(seed=config.seed, **config.autoencoder),
        "random_forest_aug": lambda: AugmentedRandomForestDetector(
            seed=config.seed, **config.random_forest
        ),
        "hist_gradient_boosting_aug": lambda: AugmentedHistGradientBoostingDetector(
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
    detector: BaseDetector,
    split: DatasetSplit,
    features: list[str],
    config: TrainConfig,
    *,
    calibrate: bool = True,
) -> dict[str, Any]:
    """Evaluate on the test split. With `calibrate=False` the stored threshold is used as is."""
    val_benign = split.val[~split.val[IS_ATTACK]]
    val_scores = detector.score(val_benign[features])
    if calibrate:
        threshold = detector.calibrate(val_scores, config.target_fpr)
    elif detector.threshold_ is not None:
        threshold = detector.threshold_
    else:
        raise ValueError("detector has no stored threshold; evaluate with calibrate=True")

    test_scores = detector.score(split.test[features])
    y_true = split.test[IS_ATTACK].to_numpy(dtype=bool)
    y_pred = test_scores > threshold

    operating_points: dict[str, dict[str, Any]] = {}
    for fpr in config.operating_fprs:
        point_threshold = threshold_for_fpr(val_scores, fpr)
        point: dict[str, Any] = dict(binary_report(y_true, test_scores, point_threshold))
        point["per_attack_recall"] = per_class_recall(
            split.test[LABEL], test_scores > point_threshold, y_true
        )
        operating_points[f"fpr_{fpr:g}"] = point

    detector.set_inference_threads(1)
    per_attack = per_class_recall(split.test[LABEL], y_pred, y_true)
    report: dict[str, Any] = {
        "target_fpr": config.target_fpr,
        "test": binary_report(y_true, test_scores, threshold),
        "operating_points": operating_points,
        "per_attack_recall": per_attack,
        "per_category_recall": per_class_recall(split.test[CATEGORY], y_pred, y_true),
        "macro_recall": macro_recall(per_attack),
        "macro_recall_min_support_30": macro_recall(per_attack, min_support=30),
        "latency_single_thread": latency_profile(detector.score, split.test[features]),
    }
    if config.evasion_analysis:
        report["evasion"] = evasion_report(
            detector,
            split.test[split.test[IS_ATTACK]],
            features,
            threshold,
            benign=split.test[~split.test[IS_ATTACK]],
            seed=config.seed,
        )
    if TIMESTAMP in split.test.columns:
        days = split.test[TIMESTAMP].dt.strftime("%Y-%m-%d")
        report["by_day"] = breakdown_by_group(days, y_true, y_pred)
        hours = split.test[TIMESTAMP].dt.strftime("%Y-%m-%d %H:00")
        report["by_hour"] = breakdown_by_group(hours, y_true, y_pred)
    profile = false_positive_profile(split.test, y_true, y_pred, config.fp_profile_columns)
    if "source_ip" in config.fp_profile_columns:
        profile["host_concentration"] = host_concentration(split.test, y_true, y_pred)
    report["false_positive_profile"] = profile
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

    augmented_train: pd.DataFrame | None = None
    for detector in detectors:
        logger.info("training", extra={"fields": {"detector": detector.name}})
        train_frame = split.train
        if detector.name.endswith(AUGMENTED_SUFFIX):
            if augmented_train is None:
                augmented_train = augment_attack_flows(
                    split.train, features, seed=config.seed, **_augmentation_params(config)
                )
            train_frame = augmented_train
        detector.fit(train_frame[features], train_frame[CATEGORY])
        result = evaluate_detector(detector, split, features, config)
        training_info = dict(getattr(detector, "training_info_", None) or {})
        if train_frame is not split.train:
            training_info["augmented_training_rows"] = len(train_frame) - len(split.train)
        if training_info:
            result["training_info"] = training_info
        report["models"][detector.name] = result
        save_detector(
            detector,
            output_dir / detector.name,
            metadata={
                "test": result["test"],
                "dataset": report["dataset"]["rows"],
                "split_fractions": list(config.split_fractions),
                "dataset_files_sha256": report["dataset"]["files_sha256"],
            },
            hmac_key=hmac_key,
        )

    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "report.json").write_text(json.dumps(report, indent=2, default=str) + "\n")
    return report


def _verify_split(metadata: dict[str, Any], config: TrainConfig, data_path: Path) -> dict[str, Any]:
    """Check that analysis uses the same data and split as training (no train/test leakage)."""
    if "split_fractions" not in metadata or "dataset_files_sha256" not in metadata:
        logger.warning("artifact has no split metadata; split cannot be verified")
        return {"verified": False, "reason": "artifact predates split metadata; retrain to enable"}
    if tuple(metadata["split_fractions"]) != tuple(config.split_fractions):
        raise ValueError(
            "split_fractions differ from training; analysing would leak training data into test"
        )
    if metadata["dataset_files_sha256"] != dataset_checksums(data_path):
        raise ValueError("dataset files differ from those the model was trained on")
    return {"verified": True}


def run_analysis(
    data_path: Path,
    model_dir: Path,
    config: TrainConfig,
    *,
    hmac_key: bytes | None = None,
) -> dict[str, Any]:
    """Re-run the evaluation diagnostics on a saved model without retraining."""
    split, features, _ = prepare_data(data_path, config)
    detector = load_detector(model_dir, hmac_key=hmac_key)
    split_check = _verify_split(read_manifest(model_dir).get("metadata", {}), config, data_path)
    return {
        "detector": detector.name,
        "split_check": split_check,
        "evaluation": evaluate_detector(detector, split, features, config, calibrate=False),
    }
