from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from ai_ids.data import loader
from ai_ids.data.loader import (
    IS_ATTACK,
    LABEL,
    TIMESTAMP,
    clean_column_name,
    clean_flows,
    feature_columns,
    load_dataset,
    read_csv_file,
)
from ai_ids.data.synthetic import generate_flows


def test_clean_column_name() -> None:
    assert clean_column_name(" Flow Bytes/s") == "flow_bytes_s"
    assert clean_column_name("Init_Win_bytes_forward") == "init_win_bytes_forward"


def test_cleaning_report_counts(synthetic_csv: Path) -> None:
    raw = read_csv_file(synthetic_csv)
    df, report = clean_flows(raw)
    assert report.rows_in == len(raw)
    assert report.rows_out == len(df)
    assert report.duplicates_removed > 0
    assert report.infinite_values_replaced > 0
    assert report.missing_values > 0
    assert not np.isinf(df[feature_columns(df)].to_numpy()).any()


def test_labels_are_normalised(cleaned: pd.DataFrame) -> None:
    assert "web_attack_brute_force" in set(cleaned[LABEL])
    assert cleaned[IS_ATTACK].dtype == bool
    assert not cleaned.loc[cleaned[LABEL] == "benign", IS_ATTACK].any()


def test_identifiers_are_not_features(cleaned: pd.DataFrame) -> None:
    features = set(feature_columns(cleaned))
    assert not features & {"flow_id", "source_ip", "destination_ip", "source_port", TIMESTAMP}
    assert "destination_port" in features


def test_timestamps_sorted_and_pm_fixed(cleaned: pd.DataFrame) -> None:
    stamps = cleaned[TIMESTAMP]
    assert stamps.is_monotonic_increasing
    assert stamps.dt.hour.min() >= 9
    assert stamps.dt.hour.max() <= 17


def test_known_duplicate_column_dropped() -> None:
    df = pd.DataFrame(
        {
            "fwd_header_length": [1.0, 2.0],
            "fwd_header_length_1": [1.0, 2.0],
            "label": ["BENIGN", "PortScan"],
        }
    )
    cleaned_df, report = clean_flows(df)
    assert report.columns_dropped == ["fwd_header_length_1"]
    assert "fwd_header_length_1" not in cleaned_df.columns


def test_missing_label_column_rejected() -> None:
    with pytest.raises(ValueError, match="label"):
        clean_flows(pd.DataFrame({"a": [1.0]}))


def test_load_directory(tmp_path: Path) -> None:
    for i in range(2):
        generate_flows(300, seed=i).to_csv(
            tmp_path / f"day{i}.csv", index=False, encoding="latin-1"
        )
    df, report = load_dataset(tmp_path)
    assert report.rows_in >= 600
    assert len(df) == report.rows_out


def test_empty_directory_raises(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        load_dataset(tmp_path)


def test_dates_are_parsed_day_first_like_cicids2017() -> None:
    # "4/7/2017" is 4 July in CICIDS2017 (capture ran 3-7 July 2017), not 7 April.
    df = pd.DataFrame(
        {
            "timestamp": ["4/7/2017 8:45", "7/7/2017 1:05", "6/7/2017 10:30"],
            "x": [1.0, 2.0, 3.0],
            "label": ["BENIGN", "BENIGN", "PortScan"],
        }
    )
    cleaned_df, _ = clean_flows(df)
    stamps = cleaned_df[TIMESTAMP].dt.strftime("%Y-%m-%d %H:%M").tolist()
    assert stamps == ["2017-07-04 08:45", "2017-07-06 10:30", "2017-07-07 13:05"]


def test_month_first_still_available() -> None:
    df = pd.DataFrame({"timestamp": ["4/7/2017 9:00"], "x": [1.0], "label": ["BENIGN"]})
    cleaned_df, _ = clean_flows(df, dayfirst=False)
    assert cleaned_df[TIMESTAMP].iloc[0].month == 4


def test_files_at_the_spreadsheet_row_limit_are_flagged(
    synthetic_csv: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    frame = pd.read_csv(synthetic_csv, encoding="latin-1")
    exact = tmp_path / "exact.csv"
    frame.head(500).to_csv(exact, index=False, encoding="latin-1")
    other = tmp_path / "other.csv"
    frame.head(400).to_csv(other, index=False, encoding="latin-1")

    monkeypatch.setattr(loader, "EXCEL_MAX_DATA_ROWS", 500)
    with caplog.at_level("WARNING"):
        _, report = loader.load_dataset(tmp_path)
    assert report.possibly_truncated_files == ["exact.csv"]
    assert report.to_dict()["possibly_truncated_files"] == ["exact.csv"]
    assert any("truncated" in record.getMessage() for record in caplog.records)

    monkeypatch.setattr(loader, "EXCEL_MAX_DATA_ROWS", 1_048_575)
    _, clean_report = loader.load_dataset(tmp_path)
    assert clean_report.possibly_truncated_files == []
