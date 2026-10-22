import base64
import hashlib
import json
import re
from pathlib import Path

import pytest

from ai_ids.cli import main
from ai_ids.reporting.explorer import Labelled, build_page, load_report

RUN = {
    "version": "0.1.0",
    "config": {"seed": 42, "corrected_labels": True, "exclude_features": ["destination_port"]},
    "environment": {"git_commit": "abcdef0123456789", "git_dirty": True},
    "dataset": {"rows": {"train": 10, "val": 2, "test": 5}},
    "models": {
        "random_forest": {
            "target_fpr": 0.01,
            "test": {
                "recall": 0.999,
                "false_positive_rate": 0.013,
                "precision": 0.9,
                "pr_auc": 0.99,
            },
            "macro_recall": 0.98,
            "per_category_recall": {
                "dos": {"recall": 1.0, "support": 500},
                "botnet": {"recall": 0.5, "support": 12},
            },
            "confidence_intervals": {
                "recall": {"estimate": 0.999, "low": 0.99, "high": 1.0},
                "false_positive_rate": {"estimate": 0.013, "low": 0.01, "high": 0.02},
            },
            "false_positive_profile": {
                "host_concentration": {
                    "top_hosts": [
                        {
                            "host": "10.0.0.1",
                            "false_positives": 5,
                            "share_of_false_positives": 0.5,
                            "false_positive_rate": 0.02,
                            "distinct_destination_ports": 7,
                        }
                    ],
                    "fpr_excluding_top_hosts": {"1": {"false_positive_rate": 0.009}},
                }
            },
        }
    },
}
ADAPTIVE = {
    "adaptive_evasion": {
        "clean_recall": 0.99,
        "adaptive_recall": 0.5,
        "attack_flows": 100,
        "benign_control": {"clean_false_positive_rate": 0.08, "flagged_under_any_combination": 0.1},
        "recall_frontier": {"slow<=x1": {"pad<=0B": 0.99, "pad<=32B": 0.9}},
        "by_family": {"dos": {"clean_recall": 1.0, "adaptive_recall": 0.8}},
        "note": "feature space only",
    }
}
HOLDOUT = {
    "families": {
        "dos": {"test_support": 100, "recall_unseen": 0.9, "false_positive_rate": 0.01},
        "web": {"test_support": 100, "recall_unseen": 0.1, "false_positive_rate": 0.01},
    }
}
TRANSFER = {
    "target_flows": 10,
    "target_attacks": 2,
    "stored_threshold": {
        "recall": 0.05,
        "false_positive_rate": 0.0,
        "precision": 1.0,
        "pr_auc": 0.9,
    },
    "oracle_recalibrated": {
        "recall": 0.8,
        "false_positive_rate": 0.01,
        "precision": 0.9,
        "pr_auc": 0.9,
    },
}


def _page(**kwargs: object) -> str:
    return build_page(title="T", **kwargs)  # type: ignore[arg-type]


def test_full_page_contains_every_section_and_the_reported_numbers() -> None:
    page = _page(
        runs=[Labelled("original", RUN), Labelled("corrected", RUN)],
        adaptive=[Labelled("rf", ADAPTIVE)],
        holdout=[Labelled("rf", HOLDOUT)],
        transfer=[Labelled("gb", TRANSFER)],
    )
    for needle in (
        "Headline results",
        "Side by side",
        "Recall by attack category",
        "Where the false positives come from",
        "Adaptive evasion",
        "Unseen attack families",
        "Cross-dataset transfer",
        "0.999 [0.990, 1.000]",
        "1.30% [1.00%, 2.00%]",
        "1.3x target",
        "1.00 (n=500)",
        "0.50 (n=12) †",
        "abcdef0123 (dirty tree)",
        "destination_port",
        "Pooled over 200 flows: <strong>0.500</strong>",
    ):
        assert needle in page


def test_page_is_inert_and_escapes_everything() -> None:
    hostile = '<script>alert(1)</script>"&'
    run = json.loads(json.dumps(RUN))
    run["models"][hostile] = run["models"].pop("random_forest")
    page = build_page(title=hostile, runs=[Labelled(hostile, run)], notes=[hostile])
    assert "<script" not in page.lower()
    assert "alert(1)</script>" not in page
    assert "&lt;script&gt;" in page
    assert not re.search(r"(src|href)=", page)
    assert " style=" not in page


def test_content_security_policy_hash_matches_the_inline_style() -> None:
    page = _page(runs=[Labelled("a", RUN)])
    css = re.search(r"<style>(.*)</style>", page, re.S)
    assert css is not None
    digest = base64.b64encode(hashlib.sha256(css.group(1).encode()).digest()).decode()
    assert f"style-src 'sha256-{digest}'" in page
    assert "default-src 'none'" in page


def test_missing_data_is_left_out_rather_than_invented() -> None:
    page = _page(runs=[Labelled("bare", {"models": {"m": {}}})])
    assert "n/a" in page
    assert "Adaptive evasion" not in page
    assert "Cross-dataset" not in page
    with pytest.raises(ValueError, match="nothing to render"):
        build_page(title="T")


def test_load_report_rejects_non_objects(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("[1, 2]")
    with pytest.raises(ValueError, match="JSON object"):
        load_report(bad)


def test_cli_writes_the_page_and_rejects_bad_specs(tmp_path: Path) -> None:
    path = tmp_path / "run.json"
    path.write_text(json.dumps(RUN))
    out = tmp_path / "out" / "page.html"
    assert main(["report-html", "--run", f"orig={path}", "--out", str(out)]) == 0
    assert "Headline results" in out.read_text(encoding="utf-8")
    with pytest.raises(SystemExit):
        main(["report-html", "--run", "no-equals-sign", "--out", str(out)])
    assert main(["report-html", "--out", str(out)]) == 2
