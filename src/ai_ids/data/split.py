"""Leakage-aware dataset splitting.

CICIDS2017 contains many near-identical flows from the same attack tool run, so random
splits overstate performance. Each class is split chronologically instead: the earliest
flows train the model, later ones calibrate thresholds, the latest ones test it.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import pandas as pd

from ai_ids.data.loader import LABEL, TIMESTAMP

_MIN_ROWS_TO_SPLIT = 3


@dataclass(frozen=True)
class DatasetSplit:
    train: pd.DataFrame
    val: pd.DataFrame
    test: pd.DataFrame


def chronological_split(
    df: pd.DataFrame,
    fractions: tuple[float, float, float] = (0.60, 0.15, 0.25),
) -> DatasetSplit:
    if not np.isclose(sum(fractions), 1.0) or min(fractions) <= 0:
        raise ValueError(f"fractions must be positive and sum to 1, got {fractions}")

    train_pos: list[np.ndarray] = []
    val_pos: list[np.ndarray] = []
    test_pos: list[np.ndarray] = []

    for _, group in df.groupby(LABEL, sort=True):
        positions = df.index.get_indexer(group.index)
        if TIMESTAMP in df.columns:
            order = np.argsort(group[TIMESTAMP].to_numpy(), kind="stable")
            positions = positions[order]
        n = len(positions)
        if n < _MIN_ROWS_TO_SPLIT:
            train_pos.append(positions)
            continue
        n_train = max(1, int(n * fractions[0]))
        n_val = max(1, int(n * fractions[1]))
        if n_train + n_val >= n:
            n_val = n - n_train - 1
        train_pos.append(positions[:n_train])
        val_pos.append(positions[n_train : n_train + n_val])
        test_pos.append(positions[n_train + n_val :])

    def take(parts: list[np.ndarray]) -> pd.DataFrame:
        if not parts:
            return df.iloc[0:0]
        return df.iloc[np.concatenate(parts)].reset_index(drop=True)

    return DatasetSplit(train=take(train_pos), val=take(val_pos), test=take(test_pos))
