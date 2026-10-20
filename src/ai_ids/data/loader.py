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


def read_csv_file(path: Path) -> pd.DataFrame:
    # CICIDS2017 CSVs are not valid UTF-8 (web-attack labels contain a Windows-1252 dash);
    # latin-1 decodes every byte, and label normalisation absorbs the artefact.
    df = pd.read_csv(path, encoding="latin-1", low_memory=False, skipinitialspace=True)
    df.columns = pd.Index([clean_column_name(str(c)) for c in df.columns])
    if df.columns.duplicated().any():
        dupes = sorted(set(df.columns[df.columns.duplicated()]))
        raise ValueError(f"{path.name}: duplicate columns after normalisation: {dupes}")
    return df


def _parse_timestamps(series: pd.Series, pm_fix_before_hour: int | None) -> pd.Series:
    parsed = pd.to_datetime(series, format="mixed", errors="coerce")
    if pm_fix_before_hour is not None:
        # The source files use a 12-hour clock without AM/PM while capture ran ~09:00-17:00,
        # so hours earlier than the capture start are afternoon times.
        hours = parsed.dt.hour
        parsed = parsed.where(~(hours < pm_fix_before_hour), parsed + pd.Timedelta(hours=12))
    return parsed


def clean_flows(
    df: pd.DataFrame, *, pm_fix_before_hour: int | None = 8
) -> tuple[pd.DataFrame, CleaningReport]:
    """Normalise labels, coerce features to numeric, drop duplicates and non-finite values.

    NaN feature values are kept (and counted) so that imputation is fitted on training
    data only, inside the model pipeline.
    """
    if LABEL not in df.columns:
        raise ValueError(f"missing required column {LABEL!r}")

    rows_in = len(df)
    out = df.dropna(subset=[LABEL]).copy()
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
        out[TIMESTAMP] = _parse_timestamps(out[TIMESTAMP], pm_fix_before_hour)
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
    path: Path, *, pm_fix_before_hour: int | None = 8
) -> tuple[pd.DataFrame, CleaningReport]:
    """Load one CSV file or every `*.csv` in a directory, then clean the combined frame."""
    path = Path(path)
    files = sorted(path.glob("*.csv")) if path.is_dir() else [path]
    if not files:
        raise FileNotFoundError(f"no CSV files found at {path}")
    frames = [read_csv_file(f) for f in files]
    logger.info("loaded csv files", extra={"fields": {"files": [f.name for f in files]}})
    return clean_flows(pd.concat(frames, ignore_index=True), pm_fix_before_hour=pm_fix_before_hour)
