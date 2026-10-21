"""Attack taxonomy for CICIDS2017 labels with MITRE ATT&CK technique mapping.

ATT&CK mappings are analyst-assigned approximations of the behaviour each label
describes; they are intended for alert enrichment, not as ground truth.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

BENIGN = "benign"


class UnknownLabelError(ValueError):
    """Raised when a dataset label is not part of the known taxonomy."""


@dataclass(frozen=True)
class AttackInfo:
    name: str
    category: str
    technique: str | None


_TAXONOMY: dict[str, AttackInfo] = {
    info_key: AttackInfo(info_key.replace(" ", "_"), category, technique)
    for info_key, category, technique in (
        ("benign", BENIGN, None),
        ("dos hulk", "dos", "T1499"),
        ("dos goldeneye", "dos", "T1499"),
        ("dos slowloris", "dos", "T1499"),
        ("dos slowhttptest", "dos", "T1499"),
        ("ddos", "ddos", "T1498"),
        ("portscan", "portscan", "T1046"),
        ("ftp patator", "brute_force", "T1110"),
        ("ssh patator", "brute_force", "T1110"),
        ("web attack brute force", "web_attack", "T1110"),
        ("web attack xss", "web_attack", "T1190"),
        ("web attack sql injection", "web_attack", "T1190"),
        ("bot", "botnet", "T1071"),
        ("infiltration", "infiltration", "T1105"),
        ("heartbleed", "exploit", "T1190"),
        # Corrected CICIDS2017 labels (data.relabel): scans run from compromised internal hosts.
        ("infiltration portscan", "infiltration", "T1046"),
        # CSE-CIC-IDS2018 names. "Infilteration" is the dataset's own spelling.
        ("dos attacks goldeneye", "dos", "T1499"),
        ("dos attacks slowloris", "dos", "T1499"),
        ("dos attacks slowhttptest", "dos", "T1499"),
        ("dos attacks hulk", "dos", "T1499"),
        ("ddos attacks loic http", "ddos", "T1498"),
        ("ddos attack hoic", "ddos", "T1498"),
        ("ddos attack loic udp", "ddos", "T1498"),
        ("brute force web", "web_attack", "T1110"),
        ("brute force xss", "web_attack", "T1190"),
        ("sql injection", "web_attack", "T1190"),
        ("ftp bruteforce", "brute_force", "T1110"),
        ("ssh bruteforce", "brute_force", "T1110"),
        ("infilteration", "infiltration", "T1105"),
    )
}


def normalize_label(raw: str) -> str:
    """Lowercase and collapse punctuation/encoding artefacts to single spaces."""
    return re.sub(r"[^a-z0-9]+", " ", raw.lower()).strip()


def resolve(raw: str) -> AttackInfo:
    """Map a raw dataset label to its taxonomy entry, failing loudly if unknown."""
    try:
        return _TAXONOMY[normalize_label(raw)]
    except KeyError:
        raise UnknownLabelError(f"Unknown label: {raw!r}") from None


def categories() -> list[str]:
    return sorted({info.category for info in _TAXONOMY.values()})


def techniques_for_category(category: str) -> list[str]:
    """MITRE ATT&CK technique IDs associated with an attack category (empty for benign)."""
    return sorted(
        {
            info.technique
            for info in _TAXONOMY.values()
            if info.category == category and info.technique is not None
        }
    )
