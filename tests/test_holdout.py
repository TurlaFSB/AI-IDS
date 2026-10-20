import pandas as pd

from ai_ids.config import TrainConfig
from ai_ids.data.loader import CATEGORY, IS_ATTACK, feature_columns
from ai_ids.data.split import chronological_split
from ai_ids.evaluation.holdout import leave_one_family_out


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
