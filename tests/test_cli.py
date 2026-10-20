import json
from pathlib import Path

import pytest

from ai_ids.cli import main
from ai_ids.config import TrainConfig
from ai_ids.data.integrity import dataset_checksums
from ai_ids.registry import load_detector


@pytest.mark.filterwarnings("ignore::sklearn.exceptions.ConvergenceWarning")  # tiny epoch budget
def test_train_end_to_end(
    synthetic_csv: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("AI_IDS_MODEL_HMAC_KEY", "test-key")
    out = tmp_path / "run"
    cfg = tmp_path / "cfg.yaml"
    cfg.write_text(
        "random_forest: {n_estimators: 20}\n"
        "isolation_forest: {n_estimators: 20}\n"
        "hist_gradient_boosting: {max_iter: 20}\n"
        "autoencoder: {max_iter: 5, max_train_rows: 3000}\n"
    )
    assert (
        main(["train", "--data", str(synthetic_csv), "--out", str(out), "--config", str(cfg)]) == 0
    )

    report = json.loads((out / "report.json").read_text())
    assert set(report["models"]) == {
        "random_forest",
        "isolation_forest",
        "hist_gradient_boosting",
        "autoencoder",
    }
    rf = report["models"]["random_forest"]
    assert 0.0 <= rf["test"]["false_positive_rate"] <= 0.05
    assert "batch_1" in rf["latency_single_thread"]
    assert report["models"]["autoencoder"]["training_info"]["epochs"] >= 1
    assert rf["macro_recall"] is not None
    assert set(rf["per_category_recall"]) >= {"dos", "portscan"}
    assert (
        report["dataset"]["files_sha256"]["flows.csv"]
        == dataset_checksums(synthetic_csv)["flows.csv"]
    )
    assert "git_dirty" in report["environment"]
    assert set(rf["by_day"]) == {"2017-07-03"}
    assert all(key.startswith("2017-07-03 ") for key in rf["by_hour"])
    assert rf["false_positive_profile"]["benign_flows"] > 0
    assert "per_attack_recall" in rf["operating_points"]["fpr_0.05"]
    assert set(report["benign_drift"]) == {"train_vs_val", "train_vs_test"}
    assert "top" in report["benign_drift"]["train_vs_test"]
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


def test_holdout_command(
    synthetic_csv: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    cfg = tmp_path / "cfg.yaml"
    cfg.write_text("holdout: {n_estimators: 10, min_test_support: 20}\n")
    out = tmp_path / "holdout.json"
    assert (
        main(["holdout", "--data", str(synthetic_csv), "--out", str(out), "--config", str(cfg)])
        == 0
    )
    report = json.loads(out.read_text())
    assert report["families"]
    assert "recall_unseen=" in capsys.readouterr().out


def test_config_rejects_unknown_detector() -> None:
    with pytest.raises(ValueError, match="detectors"):
        TrainConfig.from_mapping({"detectors": ["random_forest", "magic"]})
    with pytest.raises(ValueError, match="detectors"):
        TrainConfig.from_mapping({"detectors": []})


def test_detector_selection(synthetic_csv: Path, tmp_path: Path) -> None:
    cfg = tmp_path / "cfg.yaml"
    cfg.write_text("detectors: [hist_gradient_boosting]\nhist_gradient_boosting: {max_iter: 10}\n")
    out = tmp_path / "run"
    assert (
        main(["train", "--data", str(synthetic_csv), "--out", str(out), "--config", str(cfg)]) == 0
    )
    report = json.loads((out / "report.json").read_text())
    assert set(report["models"]) == {"hist_gradient_boosting"}


def _train_small(synthetic_csv: Path, out: Path, cfg: Path) -> None:
    cfg.write_text(
        "detectors: [random_forest]\nrandom_forest: {n_estimators: 10}\nevasion_analysis: false\n"
    )
    argv = ["train", "--data", str(synthetic_csv), "--out", str(out), "--config", str(cfg)]
    assert main(argv) == 0


def test_analyze_reuses_saved_model_and_verifies_split(
    synthetic_csv: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out, cfg = tmp_path / "run", tmp_path / "cfg.yaml"
    _train_small(synthetic_csv, out, cfg)
    trained = json.loads((out / "report.json").read_text())["models"]["random_forest"]

    analysis_path = tmp_path / "analysis.json"
    argv = [
        "analyze",
        "--data",
        str(synthetic_csv),
        "--model-dir",
        str(out / "random_forest"),
        "--out",
        str(analysis_path),
        "--config",
        str(cfg),
    ]
    assert main(argv) == 0
    analysis = json.loads(analysis_path.read_text())
    assert analysis["split_check"] == {"verified": True}
    # Same model, same data, same threshold: identical test metrics, no retraining.
    assert analysis["evaluation"]["test"] == trained["test"]
    assert "split_verified=True" in capsys.readouterr().out


def test_analyze_rejects_a_different_split(synthetic_csv: Path, tmp_path: Path) -> None:
    out, cfg = tmp_path / "run", tmp_path / "cfg.yaml"
    _train_small(synthetic_csv, out, cfg)
    other = tmp_path / "other.yaml"
    other.write_text("split_fractions: [0.5, 0.2, 0.3]\n")
    argv = [
        "analyze",
        "--data",
        str(synthetic_csv),
        "--model-dir",
        str(out / "random_forest"),
        "--out",
        str(tmp_path / "a.json"),
        "--config",
        str(other),
    ]
    with pytest.raises(ValueError, match="split_fractions"):
        main(argv)


def test_augmented_detectors_train_and_report(synthetic_csv: Path, tmp_path: Path) -> None:
    cfg = tmp_path / "cfg.yaml"
    cfg.write_text(
        "detectors: [random_forest, random_forest_aug, hist_gradient_boosting_aug]\n"
        "random_forest: {n_estimators: 10}\n"
        "hist_gradient_boosting: {max_iter: 10}\n"
        "augmentation: {slowdowns: [3], paddings: [32, 128], fraction: 0.4}\n"
    )
    out = tmp_path / "run"
    argv = ["train", "--data", str(synthetic_csv), "--out", str(out), "--config", str(cfg)]
    assert main(argv) == 0
    models = json.loads((out / "report.json").read_text())["models"]
    assert set(models) == {"random_forest", "random_forest_aug", "hist_gradient_boosting_aug"}
    assert "training_info" not in models["random_forest"]
    assert models["random_forest_aug"]["training_info"]["augmented_training_rows"] > 0
    assert (out / "random_forest_aug" / "model.joblib").exists()


def test_config_rejects_unknown_augmentation_keys(synthetic_csv: Path, tmp_path: Path) -> None:
    cfg = tmp_path / "cfg.yaml"
    cfg.write_text("detectors: [random_forest_aug]\naugmentation: {bogus: 1}\n")
    argv = [
        "train",
        "--data",
        str(synthetic_csv),
        "--out",
        str(tmp_path / "o"),
        "--config",
        str(cfg),
    ]
    with pytest.raises(ValueError, match="augmentation"):
        main(argv)
