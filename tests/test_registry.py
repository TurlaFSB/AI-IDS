import json
from pathlib import Path

import pandas as pd
import pytest

from ai_ids.data.loader import CATEGORY, feature_columns
from ai_ids.models.detectors import RandomForestDetector
from ai_ids.registry import MANIFEST_FILE, MODEL_FILE, IntegrityError, load_detector, save_detector


@pytest.fixture(scope="module")
def detector(cleaned: pd.DataFrame) -> RandomForestDetector:
    feats = feature_columns(cleaned)
    det = RandomForestDetector(n_estimators=10, seed=3).fit(cleaned[feats], cleaned[CATEGORY])
    det.threshold_ = 0.5
    return det


def test_roundtrip_preserves_predictions(
    detector: RandomForestDetector, cleaned: pd.DataFrame, tmp_path: Path
) -> None:
    save_detector(detector, tmp_path)
    loaded = load_detector(tmp_path)
    feats = feature_columns(cleaned)
    assert (loaded.score(cleaned[feats]) == detector.score(cleaned[feats])).all()
    assert loaded.threshold_ == 0.5


def test_tampered_artifact_rejected(detector: RandomForestDetector, tmp_path: Path) -> None:
    save_detector(detector, tmp_path)
    with (tmp_path / MODEL_FILE).open("ab") as handle:
        handle.write(b"x")
    with pytest.raises(IntegrityError, match="digest"):
        load_detector(tmp_path)


def test_signed_roundtrip_and_wrong_key(detector: RandomForestDetector, tmp_path: Path) -> None:
    save_detector(detector, tmp_path, hmac_key=b"k1")
    assert load_detector(tmp_path, hmac_key=b"k1").name == "random_forest"
    with pytest.raises(IntegrityError, match="signature"):
        load_detector(tmp_path, hmac_key=b"k2")


def test_signed_manifest_requires_key(detector: RandomForestDetector, tmp_path: Path) -> None:
    save_detector(detector, tmp_path, hmac_key=b"k1")
    with pytest.raises(IntegrityError, match="no verification key"):
        load_detector(tmp_path)


def test_unsigned_manifest_rejected_when_key_supplied(
    detector: RandomForestDetector, tmp_path: Path
) -> None:
    save_detector(detector, tmp_path)
    with pytest.raises(IntegrityError, match="unsigned"):
        load_detector(tmp_path, hmac_key=b"k1")


def test_manifest_tampering_breaks_signature(
    detector: RandomForestDetector, tmp_path: Path
) -> None:
    save_detector(detector, tmp_path, hmac_key=b"k1")
    path = tmp_path / MANIFEST_FILE
    manifest = json.loads(path.read_text())
    manifest["threshold"] = 0.0
    path.write_text(json.dumps(manifest))
    with pytest.raises(IntegrityError, match="signature"):
        load_detector(tmp_path, hmac_key=b"k1")
