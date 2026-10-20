"""Multi-seed study: how much do the headline results depend on the random seed?

The chronological split is deterministic, so seed variation here reflects model randomness
(forest sampling, augmentation sampling, network initialisation) and not data sampling.
Uncertainty from the finite, clustered test set is reported separately by the time-block bootstrap.
"""

from __future__ import annotations

import dataclasses
import logging
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import numpy as np

from ai_ids.config import TrainConfig
from ai_ids.data.loader import CATEGORY, IS_ATTACK, LABEL
from ai_ids.evaluation.metrics import binary_report, macro_recall, per_class_recall
from ai_ids.evaluation.robustness import default_perturbations, evasion_report
from ai_ids.pipeline import _training_frame, build_detectors, prepare_data

logger = logging.getLogger(__name__)

DEFAULT_PERTURBATIONS = ("slowdown_x10", "padding_64B", "fwd_padding_64B")


def summarize(values: Sequence[float]) -> dict[str, Any]:
    array = np.asarray(values, dtype=float)
    return {
        "mean": float(array.mean()),
        "std": float(array.std(ddof=1)) if array.size > 1 else 0.0,
        "min": float(array.min()),
        "max": float(array.max()),
        "values": [float(v) for v in array],
    }


def run_seed_study(
    data_path: Path,
    config: TrainConfig,
    seeds: Sequence[int],
    *,
    perturbation_names: Sequence[str] = DEFAULT_PERTURBATIONS,
) -> dict[str, Any]:
    """Train every configured detector once per seed and summarise the key metrics."""
    if not seeds:
        raise ValueError("at least one seed is required")
    split, features, _ = prepare_data(data_path, config)
    val_benign = split.val[~split.val[IS_ATTACK]]
    test_benign = split.test[~split.test[IS_ATTACK]]
    attacks = split.test[split.test[IS_ATTACK]]
    y_true = split.test[IS_ATTACK].to_numpy(dtype=bool)
    perturbations = [p for p in default_perturbations() if p.name in set(perturbation_names)]

    runs: dict[str, list[dict[str, float]]] = {}
    for seed in seeds:
        seeded = dataclasses.replace(config, seed=seed)
        cache: dict[str, Any] = {}
        for detector in build_detectors(seeded):
            logger.info("seed study", extra={"fields": {"seed": seed, "detector": detector.name}})
            train_frame = _training_frame(detector, split, features, seeded, cache)
            detector.fit(train_frame[features], train_frame[CATEGORY])
            threshold = detector.calibrate(detector.score(val_benign[features]), seeded.target_fpr)
            scores = detector.score(split.test[features])
            summary = binary_report(y_true, scores, threshold)
            per_attack = per_class_recall(split.test[LABEL], scores > threshold, y_true)
            row: dict[str, float] = {
                "recall": float(summary["recall"] or 0.0),
                "precision": float(summary["precision"] or 0.0),
                "false_positive_rate": float(summary["false_positive_rate"] or 0.0),
                "pr_auc": float(summary["pr_auc"] or 0.0),
                "macro_recall": float(macro_recall(per_attack) or 0.0),
            }
            if perturbations:
                evasion = evasion_report(
                    detector,
                    attacks,
                    features,
                    threshold,
                    perturbations,
                    benign=test_benign,
                    seed=seed,
                )
                for name, outcome in evasion["perturbations"].items():  # type: ignore[attr-defined]
                    row[f"{name}_recall"] = float(outcome["recall"])
                    row[f"{name}_benign_fpr"] = float(outcome["benign_false_positive_rate"])
            runs.setdefault(detector.name, []).append(row)

    return {
        "seeds": list(seeds),
        "target_fpr": config.target_fpr,
        "note": (
            "Spread across seeds reflects model randomness only; the chronological split is fixed. "
            "See confidence_intervals in the training report for test-set uncertainty."
        ),
        "detectors": {
            name: {metric: summarize([r[metric] for r in rows]) for metric in rows[0]}
            for name, rows in runs.items()
        },
    }
