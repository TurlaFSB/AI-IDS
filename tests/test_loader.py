from pathlib import Path

import numpy as np
import pandas as pd
import pytest

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
