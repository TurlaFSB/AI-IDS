"""Descriptive comparison of one attack family across two datasets.

The cross-dataset test showed a model ranking the 2018 Bot family almost perfectly while the same
family was missed on 2017. This study asks what differs, without training anything: which
features separate the family from benign traffic in each dataset, whether those features and
their directions agree, and where a saved model's scores place the family in each dataset.
It is descriptive, not causal: a difference may come from the attack tool, the network, the
capture or the label definition, and the study cannot tell these apart.
"""

from __future__ import annotations

from typing import Any

import numpy as np
import pandas as pd
from sklearn.metrics import roc_auc_score

from ai_ids.data.loader import CATEGORY, IS_ATTACK
from ai_ids.models.detectors import BaseDetector

MIN_VALID_PER_GROUP = 20
SCORE_QUANTILES = (5, 25, 50, 75, 95)


def _sample(frame: pd.DataFrame, n: int, seed: int) -> pd.DataFrame:
    return frame if len(frame) <= n else frame.sample(n=n, random_state=seed)


def split_family(
    frame: pd.DataFrame, category: str, *, max_per_class: int, seed: int
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Seeded samples of the family's flows and of benign flows."""
    family = frame[frame[CATEGORY] == category]
    benign = frame[~frame[IS_ATTACK]]
    if family.empty:
        raise ValueError(f"no flows of category {category!r} in the dataset")
    if benign.empty:
        raise ValueError("the dataset has no benign flows")
    return _sample(family, max_per_class, seed), _sample(benign, max_per_class, seed)


def feature_separability(
    family: pd.DataFrame, benign: pd.DataFrame, features: list[str]
) -> pd.DataFrame:
    """Univariate ROC-AUC of each feature for family versus benign (0.5 means no separation).

    The sign of `effect` (AUC minus 0.5) is the direction: positive means the family has larger
    values than benign traffic. Non-finite values are ignored feature by feature.
    """
    rows = []
    for name in features:
        a = family[name].to_numpy(dtype=float)
        b = benign[name].to_numpy(dtype=float)
        a, b = a[np.isfinite(a)], b[np.isfinite(b)]
        if len(a) < MIN_VALID_PER_GROUP or len(b) < MIN_VALID_PER_GROUP:
            rows.append({"feature": name, "auc": np.nan})
            continue
        labels = np.r_[np.ones(len(a)), np.zeros(len(b))]
        rows.append({"feature": name, "auc": float(roc_auc_score(labels, np.r_[a, b]))})
    table = pd.DataFrame(rows).set_index("feature")
    table["effect"] = table["auc"] - 0.5
    return table


def compare_separability(
    source: pd.DataFrame, target: pd.DataFrame, *, top_k: int = 15
) -> dict[str, Any]:
    """How alike the two datasets' separating features are."""
    both = source[["auc", "effect"]].join(
        target[["auc", "effect"]], lsuffix="_source", rsuffix="_target"
    )
    both = both.dropna()
    result: dict[str, Any] = {"features_compared": len(both)}
    if len(both) < 3:
        return result
    result["spearman_of_effects"] = float(
        both["effect_source"].corr(both["effect_target"], method="spearman")
    )
    top_source = set(both["effect_source"].abs().nlargest(top_k).index)
    top_target = set(both["effect_target"].abs().nlargest(top_k).index)
    shared = sorted(top_source & top_target)
    result["top_k"] = top_k
    result["shared_top_features"] = shared
    result["same_direction_among_shared"] = int(
        sum(
            np.sign(both.loc[f, "effect_source"]) == np.sign(both.loc[f, "effect_target"])
            for f in shared
        )
    )
    ranked = both.assign(strength=both[["effect_source", "effect_target"]].abs().max(axis=1))
    result["strongest"] = [
        {
            "feature": str(name),
            "auc_source": float(row["auc_source"]),
            "auc_target": float(row["auc_target"]),
        }
        for name, row in ranked.nlargest(top_k, "strength").iterrows()
    ]
    return result


def score_summary(
    detector: BaseDetector, family: pd.DataFrame, benign: pd.DataFrame
) -> dict[str, Any]:
    """Where the saved model's scores place the family, against benign scores of the same data."""
    features = list(detector.feature_names_)
    fam, ben = detector.score(family[features]), detector.score(benign[features])
    labels = np.r_[np.ones(len(fam)), np.zeros(len(ben))]
    threshold = detector.threshold_
    predict = getattr(detector, "predict_category", None)
    categories: dict[str, float] | None = None
    if predict is not None:
        predicted = pd.Series(predict(family[features]))
        categories = {str(k): float(v) for k, v in predicted.value_counts(normalize=True).items()}
    return {
        "predicted_category_shares": categories,
        "family_flows": len(fam),
        "benign_flows": len(ben),
        "auc_family_vs_benign": float(roc_auc_score(labels, np.r_[fam, ben])),
        "family_score_quantiles": {f"p{q}": float(np.percentile(fam, q)) for q in SCORE_QUANTILES},
        "benign_score_quantiles": {f"p{q}": float(np.percentile(ben, q)) for q in SCORE_QUANTILES},
        "stored_threshold": None if threshold is None else float(threshold),
        "family_above_stored_threshold": None
        if threshold is None
        else float((fam > threshold).mean()),
    }


def run_family_study(
    source: pd.DataFrame,
    target: pd.DataFrame,
    category: str,
    *,
    detector: BaseDetector | None = None,
    max_per_class: int = 50_000,
    seed: int = 42,
    top_k: int = 15,
    scoring_source: pd.DataFrame | None = None,
) -> dict[str, Any]:
    """Compare one family across two cleaned datasets, optionally with a saved model's scores.

    `scoring_source` is the part of the source dataset the model scores. It must be flows the model
    never trained on (for example the held-out test split); scoring training flows gives in-sample
    numbers that say nothing about generalisation. Feature separability always uses all flows.
    """
    shared = [c for c in source.columns if c in target.columns]
    features = (
        list(detector.feature_names_)
        if detector is not None
        else [
            c
            for c in shared
            if c not in {CATEGORY, IS_ATTACK, "label", "timestamp"}
            and pd.api.types.is_numeric_dtype(source[c])
        ]
    )
    missing = [f for f in features if f not in source.columns or f not in target.columns]
    if missing:
        raise ValueError(f"features missing from one dataset: {missing[:8]}")
    s_family, s_benign = split_family(source, category, max_per_class=max_per_class, seed=seed)
    t_family, t_benign = split_family(target, category, max_per_class=max_per_class, seed=seed)
    source_sep = feature_separability(s_family, s_benign, features)
    target_sep = feature_separability(t_family, t_benign, features)
    report: dict[str, Any] = {
        "category": category,
        "note": (
            "descriptive comparison of two datasets; differences may come from the attack tool, "
            "the network, the capture or label definitions, which this study cannot separate"
        ),
        "source_flows": {
            "family": int((source[CATEGORY] == category).sum()),
            "sampled": len(s_family),
        },
        "target_flows": {
            "family": int((target[CATEGORY] == category).sum()),
            "sampled": len(t_family),
        },
        "comparison": compare_separability(source_sep, target_sep, top_k=top_k),
    }
    if detector is not None:
        scored = source if scoring_source is None else scoring_source
        m_family, m_benign = split_family(scored, category, max_per_class=max_per_class, seed=seed)
        report["model_scores_source_scored_on"] = (
            "all source flows (INCLUDES training flows: in-sample)"
            if scoring_source is None
            else "supplied held-out flows"
        )
        report["model_scores"] = {
            "source": score_summary(detector, m_family, m_benign),
            "target": score_summary(detector, t_family, t_benign),
        }
    return report
