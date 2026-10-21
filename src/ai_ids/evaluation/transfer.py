"""Cross-dataset evaluation: score a second dataset with a model trained on the first.

Nothing is refitted and the alert threshold is the one fixed at training time, so the result
answers "what happens if this model is deployed on different traffic". Two further numbers separate
the causes of any drop: the threshold-free metrics (ranking quality) and an *oracle* operating point
re-calibrated on the target's own benign traffic, which uses target labels and is therefore an upper
bound for what recalibration could recover, never a deployable setting.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

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
from ai_ids.evaluation.metrics import (
    binary_report,
    breakdown_by_group,
    macro_recall,
    per_class_recall,
    threshold_for_fpr,
)
from ai_ids.evaluation.uncertainty import block_bootstrap
from ai_ids.models.detectors import BaseDetector

# Some exports contain flows with corrupted timestamps (CSE-CIC-IDS2018 has dates in 1970).
# Anything earlier than this is treated as a missing time, so it cannot pose as the capture start.
PLAUSIBLE_AFTER = pd.Timestamp("2000-01-01")


def prepare_target(
    path: Path,
    *,
    pm_fix_before_hour: int | None = None,
    dayfirst: bool = True,
    max_rows: int | None = None,
    seed: int = 0,
) -> tuple[pd.DataFrame, CleaningReport, dict[str, Any]]:
    """Load and clean the target dataset; optionally keep a seeded random sample of its rows.

    The 12-hour repair used for CICIDS2017 timestamps is off by default because other datasets
    use a 24-hour clock.
    """
    frame, cleaning = load_dataset(path, pm_fix_before_hour=pm_fix_before_hour, dayfirst=dayfirst)
    implausible = (frame[TIMESTAMP] < PLAUSIBLE_AFTER).to_numpy()
    frame.loc[implausible, TIMESTAMP] = pd.NaT
    sampling: dict[str, Any] = {
        "max_rows": max_rows,
        "rows_before": len(frame),
        "timestamps_set_missing_as_implausible": int(implausible.sum()),
    }
    if max_rows is not None and len(frame) > max_rows:
        frame = frame.sample(n=max_rows, random_state=seed).sort_values(TIMESTAMP, kind="stable")
        frame = frame.reset_index(drop=True)
    sampling["rows_after"] = len(frame)
    return frame, cleaning, sampling


def feature_coverage(
    frame: pd.DataFrame, features: list[str], *, allow_missing: bool
) -> tuple[pd.DataFrame, dict[str, Any]]:
    """Check the target has the model's features; optionally add the absent ones as missing."""
    missing = [name for name in features if name not in frame.columns]
    coverage: dict[str, Any] = {
        "model_features": len(features),
        "present": len(features) - len(missing),
        "missing": missing,
        "unused_target_columns": sorted(set(feature_columns(frame)) - set(features)),
    }
    if missing and not allow_missing:
        raise ValueError(
            f"the target dataset lacks {len(missing)} of the model's {len(features)} features "
            f"(first: {missing[:8]}). Unmatched target columns: "
            f"{coverage['unused_target_columns'][:12]}. Fix the column mapping, or pass "
            "allow_missing to impute them from training medians (this weakens the comparison)."
        )
    if missing:
        frame = frame.assign(**dict.fromkeys(missing, np.nan))
    return frame, coverage


def _operating_point(
    frame: pd.DataFrame, y_true: np.ndarray, scores: np.ndarray, threshold: float
) -> dict[str, Any]:
    y_pred = scores > threshold
    result: dict[str, Any] = dict(binary_report(y_true, scores, threshold))
    result["per_category_recall"] = per_class_recall(frame[CATEGORY], y_pred, y_true)
    per_attack = per_class_recall(frame[LABEL], y_pred, y_true)
    result["per_attack_recall"] = per_attack
    result["macro_recall"] = macro_recall(per_attack)
    return result


def local_calibration(
    frame: pd.DataFrame,
    scores: np.ndarray,
    y_true: np.ndarray,
    stored_threshold: float,
    target_fpr: float,
    fraction: float,
) -> dict[str, Any]:
    """Calibrate on the earliest slice of the target's benign traffic and test on the rest.

    This is the deployable counterpart of the oracle point: only benign flows from the first
    `fraction` of the target (by time) set the threshold, and every metric is computed on later
    flows only, so no evaluated flow influenced it. The stored threshold is reported on the same
    later flows for a like-for-like comparison.
    """
    if not 0.0 < fraction < 0.9:
        raise ValueError("calibration_fraction must be in (0, 0.9)")
    if TIMESTAMP not in frame.columns:
        raise ValueError("local calibration needs a timestamp column")
    valid = np.flatnonzero(frame[TIMESTAMP].notna().to_numpy())
    if valid.size == 0:
        raise ValueError("local calibration needs flows with valid timestamps")
    # Flows without a usable time are left out of both slices; their count is reported.
    order = valid[np.argsort(frame[TIMESTAMP].to_numpy()[valid], kind="stable")]
    cut = int(len(order) * fraction)
    calibration, evaluation = order[:cut], order[cut:]
    benign_scores = scores[calibration][~y_true[calibration]]
    if benign_scores.size == 0:
        raise ValueError("no benign flows in the calibration slice")
    threshold = threshold_for_fpr(benign_scores, target_fpr)
    later = frame.iloc[evaluation]
    later_scores, later_true = scores[evaluation], y_true[evaluation]
    if not later_true.any() or later_true.all():
        raise ValueError("the evaluation slice must contain both benign and attack flows")
    return {
        "note": (
            "threshold set from benign flows in the earliest part of the target only; metrics "
            "are on the later flows, which did not influence it"
        ),
        "calibration_fraction": fraction,
        "flows_without_valid_timestamp_excluded": int(len(frame) - valid.size),
        "calibration_flows": int(cut),
        "calibration_benign_flows": int(benign_scores.size),
        "achieved_calibration_fpr": float(np.mean(benign_scores > threshold)),
        "calibration_scores_tied_at_threshold": float(np.mean(benign_scores == threshold)),
        "calibration_window": [
            str(frame[TIMESTAMP].iloc[calibration].min()),
            str(frame[TIMESTAMP].iloc[calibration].max()),
        ],
        "evaluation_flows": len(evaluation),
        "evaluation_attacks": int(later_true.sum()),
        "local_calibration": _operating_point(later, later_true, later_scores, threshold),
        "stored_threshold_same_flows": _operating_point(
            later, later_true, later_scores, stored_threshold
        ),
    }


def evaluate_transfer(
    detector: BaseDetector,
    frame: pd.DataFrame,
    config: TrainConfig,
    *,
    allow_missing: bool = False,
    calibration_fraction: float | None = None,
) -> dict[str, Any]:
    """Evaluate a fitted, calibrated detector on a different dataset without any refitting."""
    if detector.threshold_ is None:
        raise ValueError("the detector has no stored threshold")
    features = list(detector.feature_names_)
    frame, coverage = feature_coverage(frame, features, allow_missing=allow_missing)
    y_true = frame[IS_ATTACK].to_numpy(dtype=bool)
    if not y_true.any() or y_true.all():
        raise ValueError("the target dataset must contain both benign and attack flows")

    scores = detector.score(frame[features])
    stored = float(detector.threshold_)
    y_pred = scores > stored
    benign_scores = scores[~y_true]

    report: dict[str, Any] = {
        "detector": detector.name,
        "target_flows": len(frame),
        "target_benign": int((~y_true).sum()),
        "target_attacks": int(y_true.sum()),
        "label_counts": {str(k): int(v) for k, v in frame[LABEL].value_counts().items()},
        "feature_coverage": coverage,
        "stored_threshold": _operating_point(frame, y_true, scores, stored),
        "oracle_recalibrated": {
            "note": (
                "threshold chosen from the target's own benign labels at the training target "
                "false-positive rate; an upper bound, not a deployable setting"
            ),
            **_operating_point(
                frame, y_true, scores, threshold_for_fpr(benign_scores, config.target_fpr)
            ),
        },
        "benign_score_quantiles": {
            f"p{q}": float(np.percentile(benign_scores, q)) for q in (50, 90, 99, 99.9)
        },
    }
    if calibration_fraction is not None:
        report["local_calibration_study"] = local_calibration(
            frame, scores, y_true, stored, config.target_fpr, calibration_fraction
        )
    if TIMESTAMP in frame.columns and frame[TIMESTAMP].notna().any():
        days = frame[TIMESTAMP].dt.strftime("%Y-%m-%d")
        report["by_day"] = breakdown_by_group(days, y_true, y_pred)
        allowed = {"block_minutes", "n_resamples", "level"}
        params = {k: v for k, v in config.bootstrap.items() if k in allowed}
        report["confidence_intervals"] = block_bootstrap(
            frame[TIMESTAMP], y_true, y_pred, seed=config.seed, **params
        )
    return report


def run_transfer(
    data_path: Path,
    model_dir: Path,
    config: TrainConfig,
    detector: BaseDetector,
    *,
    allow_missing: bool = False,
    max_rows: int | None = None,
    pm_fix_before_hour: int | None = None,
    calibration_fraction: float | None = None,
) -> dict[str, Any]:
    """Load the target dataset, evaluate, and record what was evaluated and how."""
    frame, cleaning, sampling = prepare_target(
        data_path,
        pm_fix_before_hour=pm_fix_before_hour,
        dayfirst=config.timestamp_dayfirst,
        max_rows=max_rows,
        seed=config.seed,
    )
    report = evaluate_transfer(
        detector,
        frame,
        config,
        allow_missing=allow_missing,
        calibration_fraction=calibration_fraction,
    )
    report["model_dir"] = str(model_dir)
    report["target_dataset"] = {
        "files_sha256": dataset_checksums(data_path),
        "cleaning": cleaning.to_dict(),
        "sampling": sampling,
    }
    return report
