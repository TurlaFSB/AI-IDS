import json
from pathlib import Path

import pytest

from ai_ids.cli import main
from ai_ids.data.relabel import RULESET_VERSION, rules_for
from ai_ids.data.rulecheck import audit, audit_file, extract_calls

# A synthetic stand-in written for this test, in the shape of a labelling script.
SCRIPT = """
import os
os.system("echo this must never run")
open("/tmp/ai_ids_rulecheck_marker", "w").write("executed")

tuesday_df = read(DATASET_PATH + "Tuesday-WorkingHours.pcap_Flow.csv")
label_flows(tuesday_df, "FTP-Patator", 1499170672838272000, 1499174416931403000,
            ["172.16.0.1"], ["192.168.10.50"], dst_port_list=[21])
label_flows(tuesday_df, "SSH-Patator", 1499188141049616000, 1499195059018486000,
            ["172.16.0.1"], ["192.168.10.50"], dst_port_list=[22], payload_filter=True)
friday_df = read("friday")
label_flows(friday_df, "Botnet", 1499432653990571000, 1499436122903736000,
            ["192.168.10.15", "192.168.10.9", "192.168.10.14", "192.168.10.5", "192.168.10.8"],
            ["205.174.165.73"])
label_flows(friday_df, "Portscan", 1, 2, ["172.16.0.1"], ["192.168.10.50"],
            additional_filters=[(friday_df["Src Port"] == 80) | (friday_df["Src Port"] == 81)])
label_flows(friday_df, "DDoS", 3, 4, ["172.16.0.1"], ["192.168.10.50"],
            additional_filters=[friday_df["Total Fwd Packet"] > 3])
label_flows(other, "ignored", 1, 2)
"""


def test_extraction_reduces_calls_to_literal_parameters_and_never_executes() -> None:
    marker = Path("/tmp/ai_ids_rulecheck_marker")
    marker.unlink(missing_ok=True)
    calls = extract_calls(SCRIPT)
    assert not marker.exists()
    by_label = {c.label: c for c in calls}
    assert set(by_label) == {"FTP-Patator", "SSH-Patator", "Bot", "Portscan", "DDoS"}
    assert by_label["Bot"].label == "Bot"  # the authors' "Botnet" is mapped to the dataset's label
    assert by_label["SSH-Patator"].payload_filter is True
    assert by_label["Portscan"].src_ports == (80, 81)  # folded from an `or` of port equalities
    assert by_label["Portscan"].opaque_filters == 0
    assert by_label["DDoS"].opaque_filters == 1
    assert by_label["FTP-Patator"].dst_ports == (21,)


def test_audit_reports_matches_and_one_sided_rules() -> None:
    report = audit(SCRIPT)
    assert report["totals"]["stated"] == 5
    friday = report["days"]["friday"]
    stated_only = {(item["label"], item["start"]) for item in friday["stated_only"]}
    assert ("Portscan", 1) in stated_only  # not a rule of ours: reported, not hidden
    tuesday = report["days"]["tuesday"]
    assert tuesday["stated_only"] == [] or all(
        i["label"] != "FTP-Patator" for i in tuesday["stated_only"]
    )
    assert report["scope"].startswith("literal parameters only")


def test_audit_file_records_the_sha256_and_ruleset(tmp_path: Path) -> None:
    path = tmp_path / "labelling.ipynb"
    path.write_text(
        json.dumps({"cells": [{"cell_type": "code", "source": SCRIPT.splitlines(True)}]})
    )
    report = audit_file(path)
    assert len(report["source_sha256"]) == 64
    assert report["ruleset_version"] == RULESET_VERSION
    out = tmp_path / "audit.json"
    assert main(["relabel-check", "--notebook", str(path), "--out", str(out)]) == 0
    assert json.loads(out.read_text())["totals"]["stated"] == 5
    assert (
        main(["relabel-check", "--notebook", str(tmp_path / "missing.ipynb"), "--out", str(out)])
        == 2
    )


def test_audited_corrections_are_in_the_rule_table() -> None:
    # Findings of the audit against the authors' script (ADR 0013), pinned so they cannot regress.
    infiltration = rules_for("Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv") or []
    first_scan = next(r for r in infiltration if r.label == "Infiltration - Portscan")
    assert first_scan.src_ports == (50122, 50133)
    assert (first_scan.start_ns, first_scan.end_ns) == (1499360431706755000, 1499360445728887000)

    portscan = rules_for("Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv") or []
    rounds = [r for r in portscan if r.label == "Portscan"]
    assert [(r.start_ns, r.end_ns) for r in rounds] == [
        (1499446532117090000, 1499447948582083000),
        (1499449905450532000, 1499451841699238000),
    ]
    assert all(r.where is None for r in rounds)

    tuesday = rules_for("Tuesday-WorkingHours.pcap_ISCX.csv") or []
    ftp_attempted = [r for r in tuesday if r.label == "FTP-Patator - Attempted"]
    assert len(ftp_attempted) == 2  # payload-free flows and the start-up flow, as in the script


@pytest.mark.parametrize("name", ["not-a-notebook.ipynb"])
def test_unreadable_notebook_is_a_clean_error(tmp_path: Path, name: str) -> None:
    path = tmp_path / name
    path.write_text("{ not json")
    assert main(["relabel-check", "--notebook", str(path), "--out", str(tmp_path / "o.json")]) == 2
