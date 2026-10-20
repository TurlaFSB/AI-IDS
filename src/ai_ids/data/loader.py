"""Loading and cleaning of CICIDS2017-style flow CSV files."""

from __future__ import annotations

import logging
import re
from dataclasses import asdict, dataclass
from pathlib import Path

import numpy as np
import pandas as pd

from ai_ids.labels import resolve

logger = logging.getLogger(__name__)

LABEL = "label"
CATEGORY = "category"
IS_ATTACK = "is_attack"
TIMESTAMP = "timestamp"

IDENTIFIER_COLUMNS = frozenset({"flow_id", "source_ip", "destination_ip", "source_port", TIMESTAMP})
NON_FEATURE_COLUMNS = IDENTIFIER_COLUMNS | {LABEL, CATEGORY, IS_ATTACK}

# CICIDS2017 ships "Fwd Header Length" twice; the second copy is exported as ".1".
_KNOWN_DUPLICATE_COLUMNS = {"fwd_header_length_1": "fwd_header_length"}


@dataclass(frozen=True)
class CleaningReport:
    rows_in: int
    rows_out: int
    rows_missing_label: int
    duplicates_removed: int
    infinite_values_replaced: int
    missing_values: int
    columns_dropped: list[str]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def clean_column_name(name: str) -> str:
    """`' Flow Bytes/s'` -> `'flow_bytes_s'`."""
    return re.sub(r"[^0-9a-z]+", "_", name.strip().lower()).strip("_")


def normalize_columns(df: pd.DataFrame, source: str = "frame") -> pd.DataFrame:
    """Normalise column names in place of the file reader, rejecting collisions."""
    out = df.copy()
    out.columns = pd.Index([clean_column_name(str(c)) for c in out.columns])
    if out.columns.duplicated().any():
        dupes = sorted(set(out.columns[out.columns.duplicated()]))
        raise ValueError(f"{source}: duplicate columns after normalisation: {dupes}")
    return out


# CSE-CIC-IDS2018 exports the same CICFlowMeter features under abbreviated names. Each alias maps
# to the CICIDS2017 name (after `clean_column_name`), so one trained model can score both. This map
# is written from the published column lists and has not been checked against every file: any
# feature a model needs that is still missing after aliasing is reported by `ai-ids transfer`.
_ALIASES_2018 = {
    "dst_port": "destination_port",
    "tot_fwd_pkts": "total_fwd_packets",
    "tot_bwd_pkts": "total_backward_packets",
    "totlen_fwd_pkts": "total_length_of_fwd_packets",
    "totlen_bwd_pkts": "total_length_of_bwd_packets",
    "fwd_pkt_len_max": "fwd_packet_length_max",
    "fwd_pkt_len_min": "fwd_packet_length_min",
    "fwd_pkt_len_mean": "fwd_packet_length_mean",
    "fwd_pkt_len_std": "fwd_packet_length_std",
    "bwd_pkt_len_max": "bwd_packet_length_max",
    "bwd_pkt_len_min": "bwd_packet_length_min",
    "bwd_pkt_len_mean": "bwd_packet_length_mean",
    "bwd_pkt_len_std": "bwd_packet_length_std",
    "flow_byts_s": "flow_bytes_s",
    "flow_pkts_s": "flow_packets_s",
    "fwd_iat_tot": "fwd_iat_total",
    "bwd_iat_tot": "bwd_iat_total",
    "fwd_header_len": "fwd_header_length",
    "bwd_header_len": "bwd_header_length",
    "fwd_pkts_s": "fwd_packets_s",
    "bwd_pkts_s": "bwd_packets_s",
    "pkt_len_min": "min_packet_length",
    "pkt_len_max": "max_packet_length",
    "pkt_len_mean": "packet_length_mean",
    "pkt_len_std": "packet_length_std",
    "pkt_len_var": "packet_length_variance",
    "fin_flag_cnt": "fin_flag_count",
    "syn_flag_cnt": "syn_flag_count",
    "rst_flag_cnt": "rst_flag_count",
    "psh_flag_cnt": "psh_flag_count",
    "ack_flag_cnt": "ack_flag_count",
    "urg_flag_cnt": "urg_flag_count",
    "ece_flag_cnt": "ece_flag_count",
    "pkt_size_avg": "average_packet_size",
    "fwd_seg_size_avg": "avg_fwd_segment_size",
    "bwd_seg_size_avg": "avg_bwd_segment_size",
    "fwd_byts_b_avg": "fwd_avg_bytes_bulk",
    "fwd_pkts_b_avg": "fwd_avg_packets_bulk",
    "fwd_blk_rate_avg": "fwd_avg_bulk_rate",
    "bwd_byts_b_avg": "bwd_avg_bytes_bulk",
    "bwd_pkts_b_avg": "bwd_avg_packets_bulk",
    "bwd_blk_rate_avg": "bwd_avg_bulk_rate",
    "subflow_fwd_pkts": "subflow_fwd_packets",
    "subflow_fwd_byts": "subflow_fwd_bytes",
    "subflow_bwd_pkts": "subflow_bwd_packets",
    "subflow_bwd_byts": "subflow_bwd_bytes",
    "init_fwd_win_byts": "init_win_bytes_forward",
    "init_bwd_win_byts": "init_win_bytes_backward",
    "fwd_act_data_pkts": "act_data_pkt_fwd",
    "fwd_seg_size_min": "min_seg_size_forward",
}


def harmonise_columns(df: pd.DataFrame) -> pd.DataFrame:
    """Rename CSE-CIC-IDS2018 column names to their CICIDS2017 equivalents (no-op otherwise)."""
    present = set(df.columns)
    renames = {a: b for a, b in _ALIASES_2018.items() if a in present and b not in present}
    return df.rename(columns=renames) if renames else df


def read_csv_file(path: Path) -> pd.DataFrame:
    # CICIDS2017 CSVs are not valid UTF-8 (web-attack labels contain a Windows-1252 dash);
    # latin-1 decodes every byte, and label normalisation absorbs the artefact.
    df = pd.read_csv(path, encoding="latin-1", low_memory=False, skipinitialspace=True)
    return harmonise_columns(normalize_columns(df, path.name))


def _parse_timestamps(
    series: pd.Series, pm_fix_before_hour: int | None, *, dayfirst: bool
) -> pd.Series:
    # CICIDS2017 writes dates day-first ("4/7/2017" is 4 July); parsing them month-first
    # silently mislabels days and can misorder data for other date ranges.
    parsed = pd.to_datetime(series, format="mixed", dayfirst=dayfirst, errors="coerce")
    if pm_fix_before_hour is not None:
        # The source files use a 12-hour clock without AM/PM while capture ran ~09:00-17:00,
        # so hours earlier than the capture start are afternoon times.
        hours = parsed.dt.hour
        parsed = parsed.where(~(hours < pm_fix_before_hour), parsed + pd.Timedelta(hours=12))
    return parsed


def clean_flows(
    df: pd.DataFrame, *, pm_fix_before_hour: int | None = 8, dayfirst: bool = True
) -> tuple[pd.DataFrame, CleaningReport]:
    """Normalise labels, coerce features to numeric, drop duplicates and non-finite values.

    NaN feature values are kept (and counted) so that imputation is fitted on training
    data only, inside the model pipeline.
    """
    if LABEL not in df.columns:
        raise ValueError(f"missing required column {LABEL!r}")

    rows_in = len(df)
    out = df.dropna(subset=[LABEL])
    # Some exports repeat the header line inside the data (CSE-CIC-IDS2018 does); drop those rows.
    out = out[out[LABEL].astype(str).str.strip().str.lower() != "label"].copy()
    rows_missing_label = rows_in - len(out)

    raw_labels = out[LABEL].astype(str)
    mapping = {raw: resolve(raw) for raw in raw_labels.unique()}
    out[LABEL] = raw_labels.map({raw: info.name for raw, info in mapping.items()})
    out[CATEGORY] = raw_labels.map({raw: info.category for raw, info in mapping.items()})
    out[IS_ATTACK] = out[CATEGORY] != "benign"

    dropped = [dup for dup, orig in _KNOWN_DUPLICATE_COLUMNS.items() if {dup, orig} <= set(out)]
    out = out.drop(columns=dropped)

    features = [c for c in out.columns if c not in NON_FEATURE_COLUMNS]
    out[features] = out[features].apply(pd.to_numeric, errors="coerce").astype("float64")
    values = out[features].to_numpy()
    infinite = int(np.isinf(values).sum())
    out[features] = out[features].replace([np.inf, -np.inf], np.nan)
    missing = int(out[features].isna().to_numpy().sum())

    before = len(out)
    out = out.drop_duplicates(subset=[*features, LABEL])
    duplicates_removed = before - len(out)

    if TIMESTAMP in out.columns:
        out[TIMESTAMP] = _parse_timestamps(out[TIMESTAMP], pm_fix_before_hour, dayfirst=dayfirst)
        out = out.sort_values(TIMESTAMP, kind="stable", na_position="last")

    out = out.reset_index(drop=True)
    report = CleaningReport(
        rows_in=rows_in,
        rows_out=len(out),
        rows_missing_label=rows_missing_label,
        duplicates_removed=duplicates_removed,
        infinite_values_replaced=infinite,
        missing_values=missing,
        columns_dropped=dropped,
    )
    logger.info("cleaned flows", extra={"fields": report.to_dict()})
    return out, report


def feature_columns(df: pd.DataFrame) -> list[str]:
    return [c for c in df.columns if c not in NON_FEATURE_COLUMNS]


def load_dataset(
    path: Path, *, pm_fix_before_hour: int | None = 8, dayfirst: bool = True
) -> tuple[pd.DataFrame, CleaningReport]:
    """Load one CSV file or every `*.csv` in a directory, then clean the combined frame."""
    path = Path(path)
    files = sorted(path.glob("*.csv")) if path.is_dir() else [path]
    if not files:
        raise FileNotFoundError(f"no CSV files found at {path}")
    frames = [read_csv_file(f) for f in files]
    logger.info("loaded csv files", extra={"fields": {"files": [f.name for f in files]}})
    return clean_flows(
        pd.concat(frames, ignore_index=True),
        pm_fix_before_hour=pm_fix_before_hour,
        dayfirst=dayfirst,
    )
