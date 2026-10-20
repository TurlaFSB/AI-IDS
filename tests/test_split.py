import pandas as pd
import pytest

from ai_ids.data.loader import LABEL, TIMESTAMP
from ai_ids.data.split import chronological_split


def test_partitions_are_disjoint_and_complete(cleaned: pd.DataFrame) -> None:
    split = chronological_split(cleaned)
    assert len(split.train) + len(split.val) + len(split.test) == len(cleaned)


def test_per_class_chronological_order(cleaned: pd.DataFrame) -> None:
    split = chronological_split(cleaned)
    for label in cleaned[LABEL].unique():
        train_max = split.train.loc[split.train[LABEL] == label, TIMESTAMP].max()
        val = split.val.loc[split.val[LABEL] == label, TIMESTAMP]
        test_min = split.test.loc[split.test[LABEL] == label, TIMESTAMP].min()
        assert train_max <= test_min
        if not val.empty:
            assert train_max <= val.min() <= val.max() <= test_min


def test_every_class_present_in_every_part(cleaned: pd.DataFrame) -> None:
    split = chronological_split(cleaned)
    labels = set(cleaned[LABEL])
    assert set(split.train[LABEL]) == labels
    assert set(split.test[LABEL]) == labels


def test_tiny_class_goes_to_train() -> None:
    df = pd.DataFrame({LABEL: ["a", "a", "b"], "x": [1.0, 2.0, 3.0]})
    split = chronological_split(df)
    assert len(split.train) == 3
    assert split.val.empty
    assert split.test.empty


def test_invalid_fractions_rejected(cleaned: pd.DataFrame) -> None:
    with pytest.raises(ValueError, match="fractions"):
        chronological_split(cleaned, (0.5, 0.5, 0.5))
