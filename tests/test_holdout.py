import pandas as pd
import pytest

from ai_ids.config import TrainConfig
from ai_ids.data.loader import CATEGORY, IS_ATTACK, feature_columns
from ai_ids.data.split import chronological_split
from ai_ids.evaluation.holdout import leave_one_family_out, parse_groups


def test_holdout_removes_family_and_reports_recall(cleaned: pd.DataFrame) -> None:
    split = chronological_split(cleaned)
    features = feature_columns(cleaned)
    config = TrainConfig.from_mapping({"holdout": {"n_estimators": 10, "min_test_support": 20}})
    results = leave_one_family_out(split, features, config)

    attack_families = set(split.test.loc[split.test[IS_ATTACK], CATEGORY])
    assert set(results) <= attack_families
    assert results  # synthetic data has several families with enough support
    for family, row in results.items():
        assert 0.0 <= row["recall_unseen"] <= 1.0
        assert 0.0 <= row["false_positive_rate"] <= 1.0
        assert row["train_flows_removed"] == int((split.train[CATEGORY] == family).sum())


def _small_config() -> TrainConfig:
    return TrainConfig.from_mapping({"holdout": {"n_estimators": 10, "min_test_support": 20}})


def test_grouped_holdout_removes_every_member_together(cleaned: pd.DataFrame) -> None:
    split = chronological_split(cleaned)
    features = feature_columns(cleaned)
    pair = ("dos", "portscan")
    results = leave_one_family_out(split, features, _small_config(), groups=[pair])

    assert list(results) == ["dos+portscan"]
    row = results["dos+portscan"]
    removed = int(split.train[CATEGORY].isin(pair).sum())
    assert row["train_flows_removed"] == removed
    assert row["test_support"] == int(split.test[CATEGORY].isin(pair).sum())
    members = row["members"]
    assert set(members) == set(pair)
    assert sum(m["test_support"] for m in members.values()) == row["test_support"]
    pooled = sum(m["recall_unseen"] * m["test_support"] for m in members.values())
    assert abs(pooled / row["test_support"] - row["recall_unseen"]) < 1e-9


def test_groups_come_from_config_and_cli_style_strings(cleaned: pd.DataFrame) -> None:
    split = chronological_split(cleaned)
    features = feature_columns(cleaned)
    assert parse_groups(["dos, portscan", "botnet"]) == [("dos", "portscan"), ("botnet",)]
    config = TrainConfig.from_mapping(
        {"holdout": {"n_estimators": 5, "groups": [["dos", "portscan"], ["botnet"]]}}
    )
    results = leave_one_family_out(split, features, config)
    assert set(results) == {"dos+portscan", "botnet"}
    assert "members" not in results["botnet"]


@pytest.mark.parametrize(
    "groups",
    [[("dos", "dos")], [("dos",), ("dos", "portscan")], [("benign",)], [("no_such_family",)]],
)
def test_bad_groups_are_rejected(cleaned: pd.DataFrame, groups: list[tuple[str, ...]]) -> None:
    split = chronological_split(cleaned)
    with pytest.raises(ValueError, match=r"holdout group|more than one"):
        leave_one_family_out(split, feature_columns(cleaned), _small_config(), groups=groups)
    with pytest.raises(ValueError, match="at least one"):
        parse_groups([" , "])
