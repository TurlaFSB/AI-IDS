"""Leave-one-attack-family-out evaluation, optionally holding out groups of related families.

CICIDS2017 attack runs are bursts of near-identical flows, so an in-distribution test
mostly measures recall on attack tools the model has already seen. Here a family is removed
from the training data entirely and the model must detect it anyway, which estimates how
well a supervised detector generalises to novel attacks.

Families that behave alike (for example DoS and DDoS, or a port scan and the scan an infiltrated
host runs) are not independent: holding out one leaves a close relative in training and flatters the
result. A group removes all of its members together, so the model sees no relative at all.
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


GROUP_SEPARATOR = "+"


def parse_groups(specs: list[str] | list[list[str]]) -> list[tuple[str, ...]]:
    """Normalise groups given as 'dos,ddos' strings or lists of category names."""
    groups = []
    for spec in specs:
        members = [m.strip() for m in spec.split(",")] if isinstance(spec, str) else list(spec)
        members = [m for m in members if m]
        if not members:
            raise ValueError("a holdout group must name at least one category")
        groups.append(tuple(members))
    return groups


def _validated_groups(groups: list[tuple[str, ...]], split: DatasetSplit) -> list[tuple[str, ...]]:
    known = {str(c) for c in split.test[CATEGORY].unique()} | {
        str(c) for c in split.train[CATEGORY].unique()
    }
    seen: set[str] = set()
    for group in groups:
        for member in group:
            if member == BENIGN or member not in known:
                raise ValueError(f"holdout group member {member!r} is not an attack category")
            if member in seen or group.count(member) > 1:
                raise ValueError(f"category {member!r} appears in more than one holdout group")
            seen.add(member)
    return groups


def leave_one_family_out(
    split: DatasetSplit,
    features: list[str],
    config: TrainConfig,
    groups: list[tuple[str, ...]] | None = None,
) -> dict[str, dict[str, Any]]:
    """For each attack family (or group), train without it and measure how much is still detected.

    The alert threshold is calibrated on benign validation flows exactly as in normal
    training, so recall here is at the same false-positive budget. Without `groups`, every
    family with enough test flows is held out alone; with `groups`, exactly those groups are
    evaluated, each removing all of its members from training at once.
    """
    n_estimators = int(config.holdout.get("n_estimators", DEFAULT_HOLDOUT_TREES))
    min_support = int(config.holdout.get("min_test_support", DEFAULT_MIN_TEST_SUPPORT))
    n_jobs = int(config.random_forest.get("n_jobs", -1))

    if groups is None and config.holdout.get("groups"):
        groups = parse_groups(config.holdout["groups"])
    if groups is not None:
        held_out = _validated_groups(groups, split)
    else:
        test_counts = split.test[CATEGORY].value_counts()
        held_out = [
            (str(name),)
            for name in sorted(
                str(n)
                for n, count in test_counts.items()
                if n != BENIGN and int(count) >= min_support
            )
        ]
    val_benign = split.val[~split.val[IS_ATTACK]]
    test_benign = split.test[~split.test[IS_ATTACK]]

    results: dict[str, dict[str, Any]] = {}
    for members in held_out:
        family = GROUP_SEPARATOR.join(members)
        logger.info("holdout", extra={"fields": {"family": family}})
        train = split.train[~split.train[CATEGORY].isin(members)]
        detector = RandomForestDetector(n_estimators=n_estimators, seed=config.seed, n_jobs=n_jobs)
        detector.fit(train[features], train[CATEGORY])
        threshold = detector.calibrate(detector.score(val_benign[features]), config.target_fpr)
        family_test = split.test[split.test[CATEGORY].isin(members)]
        flagged = detector.score(family_test[features]) > threshold
        recall = float(flagged.mean())
        fpr = float((detector.score(test_benign[features]) > threshold).mean())
        results[family] = {
            "test_support": len(family_test),
            "train_flows_removed": len(split.train) - len(train),
            "recall_unseen": recall,
            "false_positive_rate": fpr,
        }
        if len(members) > 1:
            member_of = family_test[CATEGORY].to_numpy()
            results[family]["members"] = {
                member: {
                    "test_support": int((member_of == member).sum()),
                    "recall_unseen": float(flagged[member_of == member].mean())
                    if (member_of == member).any()
                    else None,
                }
                for member in members
            }
    return results


def run_holdout(
    split: DatasetSplit,
    features: list[str],
    config: TrainConfig,
    groups: list[tuple[str, ...]] | None = None,
) -> dict[str, Any]:
    return {
        "target_fpr": config.target_fpr,
        "n_estimators": int(config.holdout.get("n_estimators", DEFAULT_HOLDOUT_TREES)),
        "grouped": groups is not None or bool(config.holdout.get("groups")),
        "families": leave_one_family_out(split, features, config, groups),
    }
