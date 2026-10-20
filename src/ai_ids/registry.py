"""Versioned, integrity-checked model artifacts.

Models are serialised with joblib, which uses pickle: loading an artifact executes code.
Every artifact therefore has a manifest with a SHA-256 digest, and can additionally be
signed with HMAC-SHA256. Only load artifacts from storage you control.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import platform
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import joblib
import numpy
import pandas
import sklearn

from ai_ids.models.detectors import BaseDetector

logger = logging.getLogger(__name__)

MANIFEST_FILE = "manifest.json"
MODEL_FILE = "model.joblib"
SCHEMA_VERSION = 1


class IntegrityError(RuntimeError):
    """Raised when an artifact fails digest or signature verification."""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical(manifest: dict[str, Any]) -> bytes:
    body = {k: v for k, v in manifest.items() if k != "signature"}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), default=str).encode()


def _sign(manifest: dict[str, Any], key: bytes) -> str:
    return hmac.new(key, _canonical(manifest), hashlib.sha256).hexdigest()


def save_detector(
    detector: BaseDetector,
    directory: Path,
    *,
    metadata: dict[str, Any] | None = None,
    hmac_key: bytes | None = None,
) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    model_path = directory / MODEL_FILE
    joblib.dump(detector, model_path)
    manifest: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "detector": detector.name,
        "artifact": MODEL_FILE,
        "sha256": _sha256(model_path),
        "created_at": datetime.now(UTC).isoformat(),
        "threshold": detector.threshold_,
        "features": detector.feature_names_,
        "environment": {
            "python": platform.python_version(),
            "scikit_learn": sklearn.__version__,
            "numpy": numpy.__version__,
            "pandas": pandas.__version__,
        },
        "metadata": metadata or {},
        "signature": None,
    }
    if hmac_key is not None:
        manifest["signature"] = _sign(manifest, hmac_key)
    manifest_path = directory / MANIFEST_FILE
    manifest_path.write_text(json.dumps(manifest, indent=2, default=str) + "\n")
    return manifest_path


def load_detector(directory: Path, *, hmac_key: bytes | None = None) -> BaseDetector:
    manifest = json.loads((directory / MANIFEST_FILE).read_text())
    signature = manifest.get("signature")
    if hmac_key is not None:
        if not signature:
            raise IntegrityError("signing key supplied but manifest is unsigned")
        if not hmac.compare_digest(signature, _sign(manifest, hmac_key)):
            raise IntegrityError("manifest signature mismatch")
    elif signature:
        raise IntegrityError("manifest is signed but no verification key was supplied")

    model_path = directory / manifest["artifact"]
    if not hmac.compare_digest(_sha256(model_path), manifest["sha256"]):
        raise IntegrityError("model artifact digest mismatch")

    recorded = manifest.get("environment", {}).get("scikit_learn")
    if recorded and recorded != sklearn.__version__:
        logger.warning(
            "scikit-learn version differs from training",
            extra={"fields": {"trained": recorded, "runtime": sklearn.__version__}},
        )
    detector = joblib.load(model_path)
    if not isinstance(detector, BaseDetector):
        raise IntegrityError("artifact is not a detector")
    return detector
