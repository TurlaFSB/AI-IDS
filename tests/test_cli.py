import json
from pathlib import Path

import pytest

from ai_ids.cli import main
from ai_ids.config import TrainConfig
from ai_ids.registry import load_detector


def test_train_end_to_end(
    synthetic_csv: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("AI_IDS_MODEL_HMAC_KEY", "test-key")
    out = tmp_path / "run"
    cfg = tmp_path / "cfg.yaml"
    cfg.write_text("random_forest: {n_estimators: 20}\nisolation_forest: {n_estimators: 20}\n")
    assert (
        main(["train", "--data", str(synthetic_csv), "--out", str(out), "--config", str(cfg)]) == 0
    )

    report = json.loads((out / "report.json").read_text())
    assert set(report["models"]) == {"random_forest", "isolation_forest"}
    rf = report["models"]["random_forest"]
    assert 0.0 <= rf["test"]["false_positive_rate"] <= 0.05
    assert "batch_1" in rf["latency_single_thread"]
    assert "fpr_0.001" in rf["operating_points"]
    assert load_detector(out / "random_forest", hmac_key=b"test-key").threshold_ is not None
    assert "recall=" in capsys.readouterr().out


def test_synth_and_checksum(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    csv = tmp_path / "s.csv"
    assert main(["synth", "--out", str(csv), "--rows", "200"]) == 0
    assert main(["checksum", str(csv)]) == 0
    digests = json.loads(capsys.readouterr().out)
    assert len(digests["s.csv"]) == 64


def test_config_rejects_unknown_keys(tmp_path: Path) -> None:
    cfg = tmp_path / "bad.yaml"
    cfg.write_text("typo_key: 1\n")
    with pytest.raises(ValueError, match="unknown config keys"):
        TrainConfig.from_yaml(cfg)


def test_config_rejects_bad_fpr() -> None:
    with pytest.raises(ValueError, match="target_fpr"):
        TrainConfig.from_mapping({"target_fpr": 2})
