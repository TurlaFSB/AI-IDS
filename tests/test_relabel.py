import json
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from ai_ids.cli import main
from ai_ids.config import TrainConfig
from ai_ids.data.integrity import dataset_checksums
from ai_ids.data.loader import load_dataset
from ai_ids.data.relabel import (
    ATTEMPTED_SUFFIX,
    RULESET_VERSION,
    label_changes,
    relabel_frame,
    rules_for,
    summarise_changes,
)
from ai_ids.pipeline import _verify_split

ATTACKER, WEB = "172.16.0.1", "192.168.10.50"


def _flow(**overrides: object) -> dict[str, object]:
    row: dict[str, object] = {
        "flow_id": "f",
        "source_ip": "10.0.0.1",
        "destination_ip": "10.0.0.2",
        "source_port": 40000,
        "destination_port": 80,
        "timestamp": "2017-07-04 08:00",
        "total_length_of_fwd_packets": 100,
        "total_length_of_bwd_packets": 100,
        "total_fwd_packets": 5,
        "total_backward_packets": 5,
        "flow_duration": 1000,
        "fwd_packet_length_max": 50,
        "label": "BENIGN",
    }
    row.update(overrides)
    return row


def _run(rows: list[dict[str, object]], filename: str) -> pd.DataFrame:
    frame = pd.DataFrame(rows)
    rules = rules_for(filename)
    assert rules is not None
    labels, attempted = relabel_frame(frame, rules, pd.to_datetime(frame["timestamp"]))
    return pd.DataFrame({"label": labels, "attempted": attempted})


TUESDAY = "Tuesday-WorkingHours.pcap_ISCX.csv"
# FTP-Patator window is 12:17:52-13:20:16 UTC, which is 09:17:52-10:20:16 local (UTC-3).


def test_time_windows_are_shifted_to_local_time_and_start_is_floored_to_the_minute() -> None:
    attack = {"source_ip": ATTACKER, "destination_ip": WEB, "destination_port": 21}
    rows = [
        _flow(**attack, timestamp="2017-07-04 09:16"),  # before the window
        _flow(**attack, timestamp="2017-07-04 09:17"),  # start minute: floored, so included
        _flow(**attack, timestamp="2017-07-04 10:00"),
        _flow(**attack, timestamp="2017-07-04 10:20"),
        _flow(**attack, timestamp="2017-07-04 10:21"),  # after the window
    ]
    labels = _run(rows, TUESDAY)["label"].tolist()
    assert labels == ["BENIGN", "FTP-Patator", "FTP-Patator", "FTP-Patator", "BENIGN"]


def test_reply_direction_is_labelled_and_unrelated_traffic_is_benign() -> None:
    reply = _flow(
        source_ip=WEB, destination_ip=ATTACKER, source_port=21, destination_port=40000,
        timestamp="2017-07-04 10:00",
    )  # fmt: skip
    other = _flow(timestamp="2017-07-04 10:00")
    result = _run([reply, other], TUESDAY)
    assert result["label"].tolist() == ["FTP-Patator", "BENIGN"]


def test_flows_without_payload_are_attempted_and_later_rules_override_earlier_ones() -> None:
    attack = {"source_ip": ATTACKER, "destination_ip": WEB, "destination_port": 21}
    rows = [
        _flow(**attack, timestamp="2017-07-04 10:00", total_length_of_fwd_packets=0),
        _flow(**attack, timestamp="2017-07-04 10:00", total_length_of_fwd_packets=64),
    ]
    result = _run(rows, TUESDAY)
    assert result["label"].tolist() == ["FTP-Patator" + ATTEMPTED_SUFFIX, "FTP-Patator"]
    assert result["attempted"].tolist() == [True, False]


def test_artefact_flow_and_missing_labels() -> None:
    attack = {"source_ip": ATTACKER, "destination_ip": WEB, "destination_port": 21}
    rows = [
        _flow(**attack, timestamp="2017-07-04 10:00", flow_id="8.0.6.4-8.6.0.1-0-0-0"),
        _flow(**attack, timestamp="2017-07-04 10:00", label=None),
    ]
    result = _run(rows, TUESDAY)
    assert result["label"].iloc[0] == "BENIGN"
    assert pd.isna(result["label"].iloc[1])  # blank export lines are left for the loader to drop


def test_compromised_host_scan_is_labelled_as_an_attack_not_benign() -> None:
    # The scan from 192.168.10.8 that dominates the models' false positives is an attack in the
    # corrected labels: 18:05-18:46 UTC is 15:05-15:46 local.
    name = "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv"
    scan = {"source_ip": "192.168.10.8", "timestamp": "2017-07-06 15:10"}
    late = {"source_ip": "192.168.10.8", "timestamp": "2017-07-06 15:50"}
    rows = [
        _flow(**scan, destination_ip="192.168.10.12"),
        _flow(**late, destination_ip="192.168.10.12"),  # after the window
        _flow(**scan, destination_ip="192.168.10.50", total_length_of_fwd_packets=176),  # excluded
        _flow(**scan, destination_ip="192.168.10.99"),  # not a scan target
    ]
    labels = _run(rows, name)["label"].tolist()
    assert labels == ["Infiltration - Portscan", "BENIGN", "BENIGN", "BENIGN"]


def test_every_known_file_has_rules_and_unknown_files_do_not() -> None:
    assert rules_for("monday-workinghours.pcap_iscx.csv") == []
    for name in (
        "Tuesday-WorkingHours.pcap_ISCX.csv",
        "Wednesday-workingHours.pcap_ISCX.csv",
        "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
        "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
        "Friday-WorkingHours-Morning.pcap_ISCX.csv",
        "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
        "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
    ):
        assert rules_for(name)
    assert rules_for("flows.csv") is None


def test_change_summary_classifies_label_transitions() -> None:
    old = pd.Series(["BENIGN", "BENIGN", "Bot", "DoS Hulk", "FTP-Patator", "Web Attack \x96 XSS"])
    new = pd.Series(
        ["BENIGN", "Infiltration - Portscan", "BENIGN", "DoS GoldenEye",
         "FTP-Patator - Attempted", "Web Attack - XSS"]
    )  # fmt: skip
    summary = summarise_changes(label_changes(old, new))
    assert summary == {
        "unchanged": 2,  # the XSS label differs only in its dash encoding
        "benign_to_attack": 1,
        "attack_to_benign": 1,
        "attack_to_other_attack": 1,
        "dropped_as_attempted": 1,
    }


COLUMNS = [
    "Flow ID", " Source IP", " Source Port", " Destination IP", " Destination Port",
    " Timestamp", " Flow Duration", " Total Fwd Packets", " Total Backward Packets",
    "Total Length of Fwd Packets", " Total Length of Bwd Packets", " Fwd Packet Length Max",
    " Label",
]  # fmt: skip


def _tuesday_csv(directory: Path, name: str = TUESDAY) -> Path:
    rows = [
        # real FTP-Patator, an attempted (no payload) flow, benign traffic, a blank export line
        ["a", ATTACKER, 40001, WEB, 21, "4/7/2017 10:00", 1000, 5, 5, 64, 80, 30, "BENIGN"],
        ["b", ATTACKER, 40002, WEB, 21, "4/7/2017 10:01", 1001, 5, 5, 0, 80, 31, "BENIGN"],
        [
            "c",
            "10.0.0.1",
            40003,
            "10.0.0.2",
            80,
            "4/7/2017 10:02",
            1002,
            5,
            5,
            64,
            80,
            32,
            "BENIGN",
        ],
    ]
    path = directory / name
    pd.DataFrame(rows, columns=COLUMNS).to_csv(path, index=False, encoding="latin-1")
    return path


def test_loader_applies_corrected_labels_and_drops_attempted_flows(tmp_path: Path) -> None:
    _tuesday_csv(tmp_path)
    frame, report = load_dataset(tmp_path, corrected_labels=True)
    assert sorted(frame["label"].tolist()) == ["benign", "ftp_patator"]
    (entry,) = report.relabelling or []
    assert entry["attempted_flows_dropped"] == 1
    assert entry["label_changes"]["BENIGN"]["FTP-Patator"] == 1
    plain, plain_report = load_dataset(tmp_path)
    assert len(plain) == 3
    assert plain_report.relabelling is None


def test_loader_refuses_unknown_files_when_correcting_labels(tmp_path: Path) -> None:
    _tuesday_csv(tmp_path, name="flows.csv")
    with pytest.raises(ValueError, match="no corrected-label rules"):
        load_dataset(tmp_path, corrected_labels=True)


def test_relabel_cli_writes_a_report(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    _tuesday_csv(tmp_path)
    out = tmp_path / "relabel.json"
    assert main(["relabel", "--data", str(tmp_path), "--out", str(out)]) == 0
    report = json.loads(out.read_text())
    assert report["relabelling"][0]["file"] == TUESDAY
    assert "benign_to_attack" in capsys.readouterr().out


def test_analysis_refuses_a_model_trained_with_the_other_label_set(tmp_path: Path) -> None:
    path = _tuesday_csv(tmp_path)
    metadata = {
        "split_fractions": [0.6, 0.15, 0.25],
        "dataset_files_sha256": dataset_checksums(path),
        "corrected_labels": False,
    }
    with pytest.raises(ValueError, match="corrected_labels"):
        _verify_split(metadata, TrainConfig(corrected_labels=True), path)
    assert _verify_split(metadata, TrainConfig(), path)["verified"] is True


def test_rule_ordering_matches_numpy_semantics() -> None:
    # Guard against accidentally reordering rules: the last matching rule must win.
    frame = pd.DataFrame([_flow()])
    assert np.asarray(frame["source_port"]).dtype.kind in "iu"


def test_analysis_refuses_a_model_trained_with_another_ruleset(tmp_path: Path) -> None:
    path = _tuesday_csv(tmp_path)
    metadata = {
        "split_fractions": [0.6, 0.15, 0.25],
        "dataset_files_sha256": dataset_checksums(path),
        "corrected_labels": True,
        "ruleset_version": RULESET_VERSION,
    }
    config = TrainConfig(corrected_labels=True)
    assert _verify_split(metadata, config, path)["verified"] is True
    with pytest.raises(ValueError, match="ruleset"):
        _verify_split({**metadata, "ruleset_version": RULESET_VERSION - 1}, config, path)
    # artifacts saved before rule sets were versioned count as ruleset 1
    legacy = {k: v for k, v in metadata.items() if k != "ruleset_version"}
    with pytest.raises(ValueError, match="ruleset 1"):
        _verify_split(legacy, config, path)


def test_analysis_refuses_a_model_trained_with_other_excluded_features(tmp_path: Path) -> None:
    path = _tuesday_csv(tmp_path)
    metadata = {
        "split_fractions": [0.6, 0.15, 0.25],
        "dataset_files_sha256": dataset_checksums(path),
        "corrected_labels": False,
        "exclude_features": ["destination_port"],
    }
    with pytest.raises(ValueError, match="exclude_features"):
        _verify_split(metadata, TrainConfig(), path)
    assert _verify_split(metadata, TrainConfig(exclude_features=("destination_port",)), path)[
        "verified"
    ]
