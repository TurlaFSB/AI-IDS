import pytest

from ai_ids.labels import UnknownLabelError, categories, normalize_label, resolve


@pytest.mark.parametrize(
    "raw",
    ["Web Attack \x96 Brute Force", "Web Attack \u2013 Brute Force", "web attack - brute force"],
)
def test_encoding_artefacts_resolve_to_same_label(raw: str) -> None:
    assert resolve(raw).name == "web_attack_brute_force"


def test_benign_has_no_technique() -> None:
    assert resolve("BENIGN").technique is None


def test_attack_has_mitre_technique() -> None:
    assert resolve("PortScan").technique == "T1046"


def test_unknown_label_fails_loudly() -> None:
    with pytest.raises(UnknownLabelError):
        resolve("Totally New Attack")


def test_normalize_and_categories() -> None:
    assert normalize_label("  FTP-Patator ") == "ftp patator"
    assert "benign" in categories()
