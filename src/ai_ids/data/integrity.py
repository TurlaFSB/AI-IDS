"""Dataset file integrity: SHA-256 digests for traceable experiments."""

from __future__ import annotations

import hashlib
from pathlib import Path


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def dataset_files(path: Path) -> list[Path]:
    """The CSV files a dataset path refers to (a single file, or every `*.csv` in a directory)."""
    return sorted(path.glob("*.csv")) if path.is_dir() else [path]


def dataset_checksums(path: Path) -> dict[str, str]:
    return {file.name: sha256_file(file) for file in dataset_files(path)}
