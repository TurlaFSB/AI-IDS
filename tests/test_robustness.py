import numpy as np
import pandas as pd
import pytest

from ai_ids.data.loader import CATEGORY, IS_ATTACK, feature_columns
from ai_ids.data.split import chronological_split
from ai_ids.evaluation.robustness import (
    default_perturbations,
    evasion_report,
    modified_columns,
    pad_packets,
    slow_down,
)
from ai_ids.models.detectors import RandomForestDetector


def _frame() -> pd.DataFrame:
    return pd.DataFrame(
        {
            "flow_duration": [10.0, 20.0],
            "flow_iat_mean": [1.0, 2.0],
            "flow_bytes_s": [100.0, 200.0],
            "fwd_packet_length_mean": [50.0, 60.0],
            "destination_port": [80.0, 443.0],
        }
    )


def test_slow_down_scales_time_and_rates_only() -> None:
    original = _frame()
    out = slow_down(original, 5.0)
    assert out["flow_duration"].tolist() == [50.0, 100.0]
    assert out["flow_iat_mean"].tolist() == [5.0, 10.0]
    assert out["flow_bytes_s"].tolist() == [20.0, 40.0]
    assert out["destination_port"].tolist() == original["destination_port"].tolist()
    assert out["fwd_packet_length_mean"].tolist() == [50.0, 60.0]
    assert original["flow_duration"].tolist() == [10.0, 20.0]  # input is not mutated


def test_pad_packets_changes_size_columns_only() -> None:
    out = pad_packets(_frame(), 100.0)
    assert out["fwd_packet_length_mean"].tolist() == [150.0, 160.0]
    assert out["flow_duration"].tolist() == [10.0, 20.0]


def test_invalid_arguments_rejected() -> None:
    with pytest.raises(ValueError, match="factor"):
        slow_down(_frame(), 0.0)
    with pytest.raises(ValueError, match="extra_bytes"):
        pad_packets(_frame(), -1.0)


def test_modified_columns_counts_changes() -> None:
    frame = _frame()
    assert modified_columns(frame, frame.copy()) == 0
    assert modified_columns(frame, slow_down(frame, 2.0)) == 3


def test_default_perturbation_names() -> None:
    names = [p.name for p in default_perturbations()]
    assert names == [
        "slowdown_x2",
        "slowdown_x5",
        "slowdown_x10",
        "padding_64B",
        "padding_256B",
        "padding_1024B",
        "combined_x5_256B",
    ]


def test_evasion_report_structure(cleaned: pd.DataFrame) -> None:
    split = chronological_split(cleaned)
    features = feature_columns(cleaned)
    detector = RandomForestDetector(n_estimators=20, seed=1).fit(
        split.train[features], split.train[CATEGORY]
    )
    benign = split.val[~split.val[IS_ATTACK]]
    threshold = detector.calibrate(detector.score(benign[features]), 0.01)
    attacks = split.test[split.test[IS_ATTACK]]

    report = evasion_report(detector, attacks, features, threshold)
    baseline = report["baseline"]
    assert isinstance(baseline, dict)
    perturbations = report["perturbations"]
    assert isinstance(perturbations, dict)
    assert set(perturbations) == {p.name for p in default_perturbations()}
    for result in perturbations.values():
        assert result["columns_modified"] > 0
        assert result["recall_drop"] == pytest.approx(baseline["recall"] - result["recall"])
        assert all(0.0 <= v <= 1.0 for v in result["by_family"].values())
    assert "note" in report


def test_evasion_report_requires_attacks(cleaned: pd.DataFrame) -> None:
    features = feature_columns(cleaned)
    detector = RandomForestDetector(n_estimators=5).fit(cleaned[features], cleaned[CATEGORY])
    with pytest.raises(ValueError, match="no attack"):
        evasion_report(detector, cleaned.iloc[0:0], features, 0.5)


def test_evasion_flag_in_pipeline(synthetic_csv, tmp_path) -> None:  # type: ignore[no-untyped-def]
    import json

    from ai_ids.cli import main

    cfg = tmp_path / "cfg.yaml"
    cfg.write_text("detectors: [random_forest]\nrandom_forest: {n_estimators: 10}\n")
    out = tmp_path / "with"
    assert (
        main(["train", "--data", str(synthetic_csv), "--out", str(out), "--config", str(cfg)]) == 0
    )
    with_evasion = json.loads((out / "report.json").read_text())["models"]["random_forest"]
    assert "evasion" in with_evasion
    assert np.isfinite(with_evasion["evasion"]["baseline"]["recall"])

    cfg.write_text(
        "detectors: [random_forest]\nrandom_forest: {n_estimators: 10}\nevasion_analysis: false\n"
    )
    out2 = tmp_path / "without"
    assert (
        main(["train", "--data", str(synthetic_csv), "--out", str(out2), "--config", str(cfg)]) == 0
    )
    without = json.loads((out2 / "report.json").read_text())["models"]["random_forest"]
    assert "evasion" not in without
