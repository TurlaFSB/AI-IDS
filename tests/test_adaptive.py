import json
from pathlib import Path

import pandas as pd
import pytest

from ai_ids.cli import main
from ai_ids.data.loader import CATEGORY, IS_ATTACK, feature_columns
from ai_ids.data.split import chronological_split
from ai_ids.evaluation.adaptive import adaptive_evasion, score_grid
from ai_ids.models.detectors import RandomForestDetector


@pytest.fixture(scope="module")
def fitted(cleaned: pd.DataFrame):  # type: ignore[no-untyped-def]
    split = chronological_split(cleaned)
    features = feature_columns(cleaned)
    detector = RandomForestDetector(n_estimators=20).fit(
        split.train[features], split.train[CATEGORY]
    )
    benign = split.val[~split.val[IS_ATTACK]]
    detector.calibrate(detector.score(benign[features]), 0.01)
    return detector, split.test, features


def test_grid_scores_have_the_expected_shape_and_identity(fitted) -> None:  # type: ignore[no-untyped-def]
    detector, test, features = fitted
    x = test[features].head(50)
    grid = score_grid(detector, x, (1.0, 5.0), (0.0, 128.0, 512.0))
    assert grid.shape == (50, 2, 3)
    assert grid[:, 0, 0] == pytest.approx(detector.score(x))


def test_adaptive_recall_never_exceeds_clean_recall(fitted) -> None:  # type: ignore[no-untyped-def]
    detector, test, features = fitted
    report = adaptive_evasion(
        detector,
        test[test[IS_ATTACK]],
        test[~test[IS_ATTACK]],
        features,
        float(detector.threshold_ or 0.0),
        slowdowns=(1.0, 3.0, 10.0),
        paddings=(0.0, 128.0, 1024.0),
        max_flows=400,
    )
    assert report["adaptive_recall"] <= report["clean_recall"] + 1e-12
    frontier = report["recall_frontier"]
    assert frontier["slow<=x1"]["pad<=0B"] == pytest.approx(report["clean_recall"])
    # a larger budget can only help the adversary
    assert frontier["slow<=x10"]["pad<=1024B"] <= frontier["slow<=x3"]["pad<=128B"] + 1e-12
    assert frontier["slow<=x10"]["pad<=1024B"] == pytest.approx(report["adaptive_recall"])
    control = report["benign_control"]
    assert control["flagged_under_any_combination"] >= control["clean_false_positive_rate"]
    # per-combination benign rates: the identity cell is the clean rate, and the union over all
    # combinations is at least as large as every single cell
    cells = report["benign_by_combination"]
    assert cells["slow=x1"]["pad=0B"] == pytest.approx(control["clean_false_positive_rate"])
    assert max(v for row in cells.values() for v in row.values()) <= (
        control["flagged_under_any_combination"] + 1e-12
    )


def test_grids_must_start_at_the_identity(fitted) -> None:  # type: ignore[no-untyped-def]
    detector, test, features = fitted
    with pytest.raises(ValueError, match="identity"):
        adaptive_evasion(
            detector,
            test[test[IS_ATTACK]],
            test[~test[IS_ATTACK]],
            features,
            0.5,
            slowdowns=(2.0,),
        )


@pytest.mark.filterwarnings("ignore::sklearn.exceptions.ConvergenceWarning")
def test_adaptive_cli_end_to_end(
    synthetic_csv: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    cfg = tmp_path / "cfg.yaml"
    cfg.write_text("detectors: [random_forest]\nrandom_forest: {n_estimators: 20}\n")
    out = tmp_path / "run"
    train = ["train", "--data", str(synthetic_csv), "--out", str(out), "--config", str(cfg)]
    assert main(train) == 0
    result = tmp_path / "adaptive.json"
    code = main(
        [
            "adaptive",
            "--data", str(synthetic_csv),
            "--model-dir", str(out / "random_forest"),
            "--out", str(result),
            "--config", str(cfg),
            "--max-flows", "300",
        ]
    )  # fmt: skip
    assert code == 0
    report = json.loads(result.read_text())
    assert report["split_check"]["verified"] is True
    assert "adaptive_evasion" in report
    assert "adaptive recall" in capsys.readouterr().out
