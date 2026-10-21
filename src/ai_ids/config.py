"""Experiment configuration loaded from YAML."""

from __future__ import annotations

from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any

import yaml

DEFAULT_DETECTORS = (
    "random_forest",
    "isolation_forest",
    "hist_gradient_boosting",
    "autoencoder",
)


AUGMENTED_SUFFIX = "_aug"
AVAILABLE_DETECTORS = (*DEFAULT_DETECTORS, "random_forest_aug", "hist_gradient_boosting_aug")


@dataclass(frozen=True)
class TrainConfig:
    seed: int = 42
    target_fpr: float = 0.01
    operating_fprs: tuple[float, ...] = (0.001, 0.01, 0.05)
    split_fractions: tuple[float, float, float] = (0.60, 0.15, 0.25)
    timestamp_pm_fix_before_hour: int | None = 8
    timestamp_dayfirst: bool = True
    corrected_labels: bool = False
    fp_profile_columns: tuple[str, ...] = ("destination_port", "source_ip", "destination_ip")
    random_forest: dict[str, Any] = field(default_factory=dict)
    isolation_forest: dict[str, Any] = field(default_factory=dict)
    hist_gradient_boosting: dict[str, Any] = field(default_factory=dict)
    autoencoder: dict[str, Any] = field(default_factory=dict)
    augmentation: dict[str, Any] = field(default_factory=dict)
    fusion: dict[str, Any] = field(default_factory=dict)
    bootstrap: dict[str, Any] = field(default_factory=dict)
    detectors: tuple[str, ...] = DEFAULT_DETECTORS
    evasion_analysis: bool = True
    holdout: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_mapping(cls, raw: dict[str, Any]) -> TrainConfig:
        known = {f.name for f in fields(cls)}
        unknown = sorted(set(raw) - known)
        if unknown:
            raise ValueError(f"unknown config keys: {unknown}")
        values = dict(raw)
        for key in ("operating_fprs", "split_fractions", "detectors", "fp_profile_columns"):
            if key in values:
                values[key] = tuple(values[key])
        config = cls(**values)
        if not 0.0 < config.target_fpr < 1.0:
            raise ValueError("target_fpr must be in (0, 1)")
        unknown_detectors = sorted(set(config.detectors) - set(AVAILABLE_DETECTORS))
        if unknown_detectors or not config.detectors:
            raise ValueError(f"detectors must be a non-empty subset of {AVAILABLE_DETECTORS}")
        cls._validate_fusion(config)
        return config

    @staticmethod
    def _validate_fusion(config: TrainConfig) -> None:
        if not config.fusion:
            return
        unknown = sorted(set(config.fusion) - {"components", "rules"})
        if unknown:
            raise ValueError(f"unknown fusion keys: {unknown}")
        components = list(config.fusion.get("components", []))
        if len(components) < 2 or not set(components) <= set(config.detectors):
            raise ValueError("fusion.components needs at least two entries from `detectors`")
        rules = list(config.fusion.get("rules", ["mean"]))
        if not rules or not set(rules) <= {"mean", "max"}:
            raise ValueError("fusion.rules must be a non-empty subset of ['mean', 'max']")

    @classmethod
    def from_yaml(cls, path: Path) -> TrainConfig:
        raw = yaml.safe_load(path.read_text()) or {}
        if not isinstance(raw, dict):
            raise ValueError(f"{path}: expected a mapping at the top level")
        return cls.from_mapping(raw)
