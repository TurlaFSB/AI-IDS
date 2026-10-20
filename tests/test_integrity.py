import hashlib
from pathlib import Path

from ai_ids.data.integrity import dataset_checksums, dataset_files, sha256_file


def test_sha256_file_matches_hashlib(tmp_path: Path) -> None:
    file = tmp_path / "a.csv"
    file.write_bytes(b"hello" * 100_000)
    assert sha256_file(file) == hashlib.sha256(b"hello" * 100_000).hexdigest()


def test_directory_and_single_file(tmp_path: Path) -> None:
    (tmp_path / "b.csv").write_text("b")
    (tmp_path / "a.csv").write_text("a")
    (tmp_path / "ignored.txt").write_text("x")
    assert [f.name for f in dataset_files(tmp_path)] == ["a.csv", "b.csv"]
    assert set(dataset_checksums(tmp_path)) == {"a.csv", "b.csv"}
    assert set(dataset_checksums(tmp_path / "a.csv")) == {"a.csv"}
