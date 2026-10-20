import numpy as np
import pandas as pd
import pytest

from ai_ids.data.loader import CATEGORY, IS_ATTACK, feature_columns
from ai_ids.data.split import chronological_split
from ai_ids.evaluation.robustness import (
    TRAIN_PADDINGS,
    TRAIN_SLOWDOWNS,
    augment_attack_flows,
    default_perturbations,
    evasion_report,
    modified_columns,
    pad_forward_packets,
    pad_packets,
    slow_down,
)
from ai_ids.models.detectors import BaseDetector, RandomForestDetector


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
        "fwd_padding_64B",
        "fwd_padding_256B",
        "fwd_padding_1024B",
        "fwd_padding_random_16_512B",
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
    for name, result in perturbations.items():
        assert result["columns_modified"] > 0, name
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
    baseline = with_evasion["evasion"]["baseline"]
    assert 0.0 <= baseline["benign_false_positive_rate"] <= 1.0
    assert baseline["benign_sample_size"] > 0
    perturbed = with_evasion["evasion"]["perturbations"]
    assert "fwd_padding_64B" in perturbed
    assert all("benign_false_positive_rate" in p for p in perturbed.values())

    cfg.write_text(
        "detectors: [random_forest]\nrandom_forest: {n_estimators: 10}\nevasion_analysis: false\n"
    )
    out2 = tmp_path / "without"
    assert (
        main(["train", "--data", str(synthetic_csv), "--out", str(out2), "--config", str(cfg)]) == 0
    )
    without = json.loads((out2 / "report.json").read_text())["models"]["random_forest"]
    assert "evasion" not in without


def test_padding_keeps_related_features_consistent() -> None:
    frame = pd.DataFrame(
        {
            "total_fwd_packets": [4.0, 3.0],
            "total_backward_packets": [2.0, 0.0],
            "fwd_packet_length_min": [10.0, 5.0],
            "fwd_packet_length_max": [100.0, 50.0],
            "fwd_packet_length_mean": [40.0, 20.0],
            "bwd_packet_length_max": [80.0, 0.0],
            "bwd_packet_length_mean": [60.0, 0.0],
            "avg_fwd_segment_size": [40.0, 20.0],
            "avg_bwd_segment_size": [60.0, 0.0],
            "total_length_of_fwd_packets": [160.0, 60.0],
            "total_length_of_bwd_packets": [120.0, 0.0],
            "subflow_fwd_packets": [4.0, 3.0],
            "subflow_fwd_bytes": [160.0, 60.0],
            "min_packet_length": [10.0, 5.0],
            "packet_length_mean": [47.0, 20.0],
            "packet_length_std": [30.0, 10.0],
            "flow_packets_s": [100.0, 50.0],
            "flow_bytes_s": [4700.0, 1000.0],
        }
    )
    out = pad_packets(frame, 10.0)
    assert out["fwd_packet_length_mean"].tolist() == [50.0, 30.0]
    assert out["total_length_of_fwd_packets"].tolist() == [200.0, 90.0]  # + 10 * packets
    assert out["total_length_of_bwd_packets"].tolist() == [140.0, 0.0]
    assert out["subflow_fwd_bytes"].tolist() == [200.0, 90.0]
    assert out["flow_bytes_s"].tolist() == [5700.0, 1500.0]  # + 10 * packets/s
    assert out["packet_length_std"].tolist() == [30.0, 10.0]  # spread is unchanged
    # a direction with no packets stays at zero
    assert out["bwd_packet_length_max"].tolist() == [90.0, 0.0]
    assert out["avg_bwd_segment_size"].tolist() == [70.0, 0.0]


def test_augmentation_adds_perturbed_attack_copies_only(cleaned: pd.DataFrame) -> None:
    features = feature_columns(cleaned)
    train = cleaned.iloc[:4000].reset_index(drop=True)
    n_attacks = int(train[IS_ATTACK].sum())
    out = augment_attack_flows(train, features, fraction=0.5, seed=3)

    added = out.iloc[len(train) :]
    assert len(added) == int(n_attacks * 0.5)
    assert added[IS_ATTACK].all()  # benign flows are never duplicated or modified
    assert out.iloc[: len(train)].equals(train)
    # the copies really are perturbed
    assert not np.allclose(
        added["flow_duration"].to_numpy(),
        train.loc[train[IS_ATTACK], "flow_duration"].iloc[: len(added)].to_numpy(),
    )


def test_augmentation_is_deterministic_and_validated(cleaned: pd.DataFrame) -> None:
    features = feature_columns(cleaned)
    train = cleaned.iloc[:3000].reset_index(drop=True)
    a = augment_attack_flows(train, features, seed=5)
    b = augment_attack_flows(train, features, seed=5)
    assert a.equals(b)
    with pytest.raises(ValueError, match="fraction"):
        augment_attack_flows(train, features, fraction=0.0)
    with pytest.raises(ValueError, match="perturbation"):
        augment_attack_flows(train, features, slowdowns=(), paddings=())
    benign_only = train[~train[IS_ATTACK]]
    assert augment_attack_flows(benign_only, features) is benign_only


def test_training_and_evaluation_magnitudes_are_disjoint() -> None:
    evaluation = {p.name for p in default_perturbations()}
    for k in TRAIN_SLOWDOWNS:
        assert f"slowdown_x{k:g}" not in evaluation
    for b in TRAIN_PADDINGS:
        assert f"padding_{b:g}B" not in evaluation


_FLOW_COLUMNS = (
    "total_fwd_packets",
    "total_backward_packets",
    "fwd_packet_length_min",
    "fwd_packet_length_max",
    "fwd_packet_length_mean",
    "fwd_packet_length_std",
    "bwd_packet_length_min",
    "bwd_packet_length_max",
    "bwd_packet_length_mean",
    "bwd_packet_length_std",
    "min_packet_length",
    "max_packet_length",
    "packet_length_mean",
    "packet_length_std",
    "packet_length_variance",
    "average_packet_size",
    "avg_fwd_segment_size",
    "avg_bwd_segment_size",
    "total_length_of_fwd_packets",
    "total_length_of_bwd_packets",
    "subflow_fwd_packets",
    "subflow_fwd_bytes",
    "flow_packets_s",
    "fwd_packets_s",
    "flow_bytes_s",
)


def _aggregates(fwd: list[float], bwd: list[float], duration: float = 2.0) -> dict[str, float]:
    """Flow features computed from raw per-packet lengths (population statistics)."""
    all_packets = np.array(fwd + bwd, dtype=float)
    f, b = np.array(fwd, dtype=float), np.array(bwd, dtype=float)

    def stat(values: np.ndarray, fn: object) -> float:
        return float(fn(values)) if values.size else 0.0  # type: ignore[operator]

    return {
        "total_fwd_packets": float(len(f)),
        "total_backward_packets": float(len(b)),
        "fwd_packet_length_min": stat(f, np.min),
        "fwd_packet_length_max": stat(f, np.max),
        "fwd_packet_length_mean": stat(f, np.mean),
        "fwd_packet_length_std": stat(f, np.std),
        "bwd_packet_length_min": stat(b, np.min),
        "bwd_packet_length_max": stat(b, np.max),
        "bwd_packet_length_mean": stat(b, np.mean),
        "bwd_packet_length_std": stat(b, np.std),
        "min_packet_length": float(all_packets.min()),
        "max_packet_length": float(all_packets.max()),
        "packet_length_mean": float(all_packets.mean()),
        "packet_length_std": float(all_packets.std()),
        "packet_length_variance": float(all_packets.var()),
        "average_packet_size": float(all_packets.mean()),
        "avg_fwd_segment_size": stat(f, np.mean),
        "avg_bwd_segment_size": stat(b, np.mean),
        "total_length_of_fwd_packets": float(f.sum()),
        "total_length_of_bwd_packets": float(b.sum()),
        "subflow_fwd_packets": float(len(f)),
        "subflow_fwd_bytes": float(f.sum()),
        "flow_packets_s": float(all_packets.size / duration),
        "fwd_packets_s": float(len(f) / duration),
        "flow_bytes_s": float(all_packets.sum() / duration),
    }


def _random_flows(seed: int) -> tuple[list[tuple[list[float], list[float]]], pd.DataFrame]:
    rng = np.random.default_rng(seed)
    flows: list[tuple[list[float], list[float]]] = []
    for _ in range(40):
        n_fwd = int(rng.integers(0, 12))
        n_bwd = int(rng.integers(0, 12)) if n_fwd else int(rng.integers(1, 12))
        flows.append(
            (
                [float(x) for x in rng.integers(0, 1400, n_fwd)],
                [float(x) for x in rng.integers(0, 1400, n_bwd)],
            )
        )
    frame = pd.DataFrame([_aggregates(f, b) for f, b in flows])
    return flows, frame[list(_FLOW_COLUMNS)]


def _assert_matches_packet_level(
    transformed: pd.DataFrame,
    flows: list[tuple[list[float], list[float]]],
    pad_fwd: float | np.ndarray,
    pad_bwd: float | np.ndarray,
) -> None:
    pad_f = np.broadcast_to(np.asarray(pad_fwd, dtype=float), (len(flows),))
    pad_b = np.broadcast_to(np.asarray(pad_bwd, dtype=float), (len(flows),))
    expected = pd.DataFrame(
        [
            _aggregates([x + pf for x in f], [x + pb for x in b])
            for (f, b), pf, pb in zip(flows, pad_f, pad_b, strict=True)
        ]
    )[list(_FLOW_COLUMNS)]
    for column in _FLOW_COLUMNS:
        np.testing.assert_allclose(
            transformed[column].to_numpy(),
            expected[column].to_numpy(),
            rtol=1e-9,
            atol=1e-6,
            err_msg=column,
        )


def test_pad_packets_matches_packet_level_simulation() -> None:
    flows, frame = _random_flows(1)
    _assert_matches_packet_level(pad_packets(frame, 64.0), flows, 64.0, 64.0)


def test_pad_forward_packets_matches_packet_level_simulation() -> None:
    flows, frame = _random_flows(2)
    _assert_matches_packet_level(pad_forward_packets(frame, 100.0), flows, 100.0, 0.0)


def test_per_flow_padding_matches_packet_level_simulation() -> None:
    flows, frame = _random_flows(3)
    amounts = np.random.default_rng(9).uniform(16, 512, len(frame))
    _assert_matches_packet_level(pad_forward_packets(frame, amounts), flows, amounts, 0.0)
    _assert_matches_packet_level(pad_packets(frame, amounts), flows, amounts, amounts)


def test_forward_padding_leaves_backward_statistics_untouched() -> None:
    _, frame = _random_flows(4)
    out = pad_forward_packets(frame, 50.0)
    for column in (
        "bwd_packet_length_min",
        "bwd_packet_length_max",
        "bwd_packet_length_mean",
        "total_length_of_bwd_packets",
        "avg_bwd_segment_size",
    ):
        assert out[column].tolist() == frame[column].tolist()


def test_negative_per_flow_padding_rejected() -> None:
    _, frame = _random_flows(5)
    with pytest.raises(ValueError, match="extra_bytes"):
        pad_forward_packets(frame, np.full(len(frame), -1.0))


def test_benign_control_detects_a_perturbation_shortcut() -> None:
    """A detector that flags anything padded scores perfect recall but flags benign flows too."""

    class FlagsPaddedFlows(BaseDetector):
        name = "toy"

        def fit(self, X: pd.DataFrame, categories: pd.Series) -> "FlagsPaddedFlows":
            return self

        def score(self, X: pd.DataFrame) -> np.ndarray:
            return np.asarray((X["fwd_packet_length_mean"] >= 70).astype(float))

        def set_inference_threads(self, n_jobs: int) -> None:
            return None

    attacks = pd.DataFrame({"fwd_packet_length_mean": [10.0] * 40, CATEGORY: "dos"})
    benign = pd.DataFrame({"fwd_packet_length_mean": [20.0] * 40, CATEGORY: "benign"})
    report = evasion_report(
        FlagsPaddedFlows(), attacks, ["fwd_packet_length_mean"], 0.5, benign=benign
    )
    assert report["baseline"]["recall"] == 0.0  # type: ignore[index]
    assert report["baseline"]["benign_false_positive_rate"] == 0.0  # type: ignore[index]
    result = report["perturbations"]["padding_64B"]  # type: ignore[index]
    assert result["recall"] == 1.0  # looks like perfect robustness...
    assert result["benign_false_positive_rate"] == 1.0  # ...but only because everything is flagged
