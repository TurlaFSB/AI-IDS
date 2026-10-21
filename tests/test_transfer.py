import json
from pathlib import Path

import pandas as pd
import pytest

from ai_ids.cli import main
from ai_ids.config import TrainConfig
from ai_ids.data.loader import IS_ATTACK, clean_flows, harmonise_columns, read_csv_file
from ai_ids.data.split import chronological_split
from ai_ids.data.synthetic import generate_flows
from ai_ids.evaluation.transfer import evaluate_transfer, feature_coverage, prepare_target
from ai_ids.models.detectors import RandomForestDetector

# The synthetic generator writes CICIDS2017-style names; map them to the 2018 abbreviations and
# labels so the target file looks like a CSE-CIC-IDS2018 export.
RENAMES_2018 = {
    " Destination Port": "Dst Port",
    " Total Fwd Packets": "Tot Fwd Pkts",
    " Total Backward Packets": "Tot Bwd Pkts",
    " Fwd Packet Length Mean": "Fwd Pkt Len Mean",
    "Flow Bytes/s": "Flow Byts/s",
    " Flow Packets/s": "Flow Pkts/s",
    " SYN Flag Count": "SYN Flag Cnt",
    " ACK Flag Count": "ACK Flag Cnt",
    "Init_Win_bytes_forward": "Init Fwd Win Byts",
    " Timestamp": "Timestamp",
    " Label": "Label",
}
LABELS_2018 = {"DoS Hulk": "DoS attacks-Hulk", "FTP-Patator": "FTP-BruteForce", "PortScan": "Bot"}


@pytest.fixture(scope="module")
def target_csv(tmp_path_factory: pytest.TempPathFactory) -> Path:
    raw = generate_flows(4_000, seed=11)
    raw = raw.rename(columns=RENAMES_2018)
    raw["Label"] = raw["Label"].replace(LABELS_2018)
    raw["Timestamp"] = pd.to_datetime(  # 24-hour clock, as in the 2018 export
        pd.Series(range(len(raw))) * 4, unit="s", origin="2018-03-02 09:00"
    ).dt.strftime("%d/%m/%Y %H:%M:%S")
    repeated_header = pd.DataFrame([{c: c for c in raw.columns}])
    path = tmp_path_factory.mktemp("target") / "day.csv"
    pd.concat([raw.iloc[:50], repeated_header, raw.iloc[50:]]).to_csv(
        path, index=False, encoding="latin-1"
    )
    return path


@pytest.fixture(scope="module")
def fitted(cleaned: pd.DataFrame) -> RandomForestDetector:
    from ai_ids.data.loader import feature_columns

    split = chronological_split(cleaned)
    features = feature_columns(cleaned)
    detector = RandomForestDetector(n_estimators=20).fit(
        split.train[features], split.train["category"]
    )
    benign = split.val[~split.val[IS_ATTACK]]
    detector.calibrate(detector.score(benign[features]), 0.01)
    return detector


def test_aliases_map_2018_names_and_labels(target_csv: Path) -> None:
    frame = harmonise_columns(read_csv_file(target_csv))
    assert {"destination_port", "total_fwd_packets", "flow_bytes_s", "syn_flag_count"} <= set(frame)
    cleaned, report = clean_flows(frame, pm_fix_before_hour=None)
    assert report.rows_missing_label >= 1  # the repeated header row
    assert set(cleaned["label"]) >= {"dos_attacks_hulk", "ftp_bruteforce"}
    assert set(cleaned.loc[cleaned["label"] == "ftp_bruteforce", "category"]) == {"brute_force"}


def test_harmonise_does_not_overwrite_existing_columns() -> None:
    frame = pd.DataFrame({"dst_port": [1], "destination_port": [2]})
    assert list(harmonise_columns(frame).columns) == ["dst_port", "destination_port"]


def test_missing_features_fail_loudly_with_names(fitted: RandomForestDetector) -> None:
    frame = pd.DataFrame({"destination_port": [80.0]})
    with pytest.raises(ValueError, match="lacks"):
        feature_coverage(frame, list(fitted.feature_names_), allow_missing=False)
    filled, coverage = feature_coverage(frame, list(fitted.feature_names_), allow_missing=True)
    assert filled[fitted.feature_names_].shape[1] == len(fitted.feature_names_)
    assert len(coverage["missing"]) == len(fitted.feature_names_) - 1


def test_evaluate_transfer_reports_fixed_and_oracle_thresholds(
    fitted: RandomForestDetector, target_csv: Path
) -> None:
    frame, _, sampling = prepare_target(target_csv)
    assert sampling["rows_after"] == len(frame)
    report = evaluate_transfer(fitted, frame, TrainConfig(bootstrap={"n_resamples": 50}))
    fixed, oracle = report["stored_threshold"], report["oracle_recalibrated"]
    assert fixed["threshold"] == fitted.threshold_
    assert oracle["false_positive_rate"] <= 0.01 + 1e-9
    assert 0.0 <= fixed["recall"] <= 1.0
    assert report["feature_coverage"]["missing"] == []
    assert "confidence_intervals" in report
    assert "by_day" in report
    assert report["target_benign"] + report["target_attacks"] == report["target_flows"]


def test_evaluate_transfer_needs_both_classes(
    fitted: RandomForestDetector, target_csv: Path
) -> None:
    frame, _, _ = prepare_target(target_csv)
    with pytest.raises(ValueError, match="both benign and attack"):
        evaluate_transfer(fitted, frame[~frame[IS_ATTACK]], TrainConfig())


def test_max_rows_samples_reproducibly(target_csv: Path) -> None:
    a, _, info = prepare_target(target_csv, max_rows=500, seed=3)
    b, _, _ = prepare_target(target_csv, max_rows=500, seed=3)
    assert len(a) == 500
    assert info["rows_before"] > 500
    assert a.equals(b)


@pytest.mark.filterwarnings("ignore::sklearn.exceptions.ConvergenceWarning")
def test_transfer_cli_end_to_end(
    synthetic_csv: Path, target_csv: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    cfg = tmp_path / "cfg.yaml"
    cfg.write_text("detectors: [random_forest]\nrandom_forest: {n_estimators: 20}\n")
    out = tmp_path / "run"
    args = ["--data", str(synthetic_csv), "--out", str(out), "--config", str(cfg)]
    assert main(["train", *args]) == 0
    result = tmp_path / "transfer.json"
    code = main(
        [
            "transfer",
            "--data", str(target_csv),
            "--model-dir", str(out / "random_forest"),
            "--out", str(result),
            "--config", str(cfg),
        ]
    )  # fmt: skip
    assert code == 0
    report = json.loads(result.read_text())
    assert report["detector"] == "random_forest"
    assert report["target_dataset"]["files_sha256"]
    assert "stored_threshold" in capsys.readouterr().out


def test_local_calibration_uses_only_the_early_slice(
    fitted: RandomForestDetector, target_csv: Path
) -> None:
    frame, _, _ = prepare_target(target_csv)
    report = evaluate_transfer(
        fitted, frame, TrainConfig(bootstrap={"n_resamples": 20}), calibration_fraction=0.3
    )
    study = report["local_calibration_study"]
    assert study["calibration_flows"] == int(len(frame) * 0.3)
    assert study["evaluation_flows"] == len(frame) - study["calibration_flows"]
    assert (
        study["local_calibration"]["threshold"] != study["stored_threshold_same_flows"]["threshold"]
    )
    first_later = frame["timestamp"].sort_values().iloc[study["calibration_flows"]]
    assert pd.Timestamp(study["calibration_window"][1]) <= first_later


def test_local_calibration_rejects_bad_fractions(
    fitted: RandomForestDetector, target_csv: Path
) -> None:
    frame, _, _ = prepare_target(target_csv)
    for bad in (0.0, 0.95):
        with pytest.raises(ValueError, match="calibration_fraction"):
            evaluate_transfer(fitted, frame, TrainConfig(), calibration_fraction=bad)


def test_implausible_timestamps_are_excluded_from_local_calibration(
    fitted: RandomForestDetector, target_csv: Path, tmp_path: Path
) -> None:
    raw = pd.read_csv(target_csv, encoding="latin-1")
    raw.loc[:20, "Timestamp"] = "10/01/1970 03:04:26"
    corrupted = tmp_path / "corrupted.csv"
    raw.to_csv(corrupted, index=False, encoding="latin-1")

    frame, _, info = prepare_target(corrupted)
    missing = int(frame["timestamp"].isna().sum())
    assert missing > 0
    assert info["timestamps_set_missing_as_implausible"] == missing

    report = evaluate_transfer(
        fitted, frame, TrainConfig(bootstrap={"n_resamples": 20}), calibration_fraction=0.3
    )
    study = report["local_calibration_study"]
    assert study["flows_without_valid_timestamp_excluded"] == missing
    assert pd.Timestamp(study["calibration_window"][0]).year >= 2000


@pytest.mark.filterwarnings("ignore::sklearn.exceptions.ConvergenceWarning")
def test_family_cli_end_to_end(
    synthetic_csv: Path, target_csv: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    cfg = tmp_path / "cfg.yaml"
    cfg.write_text("detectors: [random_forest]\nrandom_forest: {n_estimators: 20}\n")
    out = tmp_path / "run"
    train = ["train", "--data", str(synthetic_csv), "--out", str(out), "--config", str(cfg)]
    assert main(train) == 0
    result = tmp_path / "family.json"
    code = main(
        [
            "family",
            "--source-data", str(synthetic_csv),
            "--target-data", str(target_csv),
            "--category", "botnet",
            "--model-dir", str(out / "random_forest"),
            "--out", str(result),
            "--config", str(cfg),
            "--max-per-class", "500",
        ]
    )  # fmt: skip
    assert code == 0
    report = json.loads(result.read_text())
    assert report["category"] == "botnet"
    assert set(report["model_scores"]) == {"source", "target"}
    assert report["comparison"]["features_compared"] > 0
    assert "botnet" in capsys.readouterr().out
