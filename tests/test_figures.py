import re

from ai_ids.reporting.explorer import Labelled, build_page
from ai_ids.reporting.figures import figure_benign_reshaping, figure_concentration, figure_holdout

CELLS = {
    "slow=x1": {"pad=0B": 0.014, "pad=512B": 0.019, "pad=1024B": 0.277},
    "slow=x5": {"pad=0B": 0.022, "pad=512B": 0.068, "pad=1024B": 0.285},
}
ADAPTIVE = {"adaptive_evasion": {"benign_by_combination": CELLS}}
RUN = {
    "config": {"augmentation": {"paddings": [32, 128, 512]}},
    "models": {
        "random_forest": {
            "false_positive_profile": {
                "host_concentration": {
                    "top_hosts": [
                        {"host": "10.0.0.1", "share_of_false_positives": 0.9},
                        {"host": "10.0.0.2", "share_of_false_positives": 0.05},
                    ]
                }
            }
        }
    },
}


def test_benign_figure_has_a_line_per_slowdown_and_marks_the_training_range() -> None:
    figure = figure_benign_reshaping(ADAPTIVE, RUN)
    assert figure.count("<polyline") == 2
    assert 'class="mark"' in figure
    assert "largest training padding" in figure
    assert "<title" in figure
    assert "slowdown x5" in figure
    # without the training configuration there is nothing to mark
    assert 'class="mark"' not in figure_benign_reshaping(ADAPTIVE, None)
    assert figure_benign_reshaping({}, RUN) == ""


def test_holdout_figure_expands_group_members_and_leaves_gaps() -> None:
    single = {"families": {"dos": {"recall_unseen": 0.96}, "web": {"recall_unseen": 0.2}}}
    grouped = {
        "families": {
            "dos+ddos": {
                "recall_unseen": 0.7,
                "members": {
                    "dos": {"recall_unseen": 0.77},
                    "ddos": {"recall_unseen": 0.64},
                },
            }
        }
    }
    figure = figure_holdout([("single", single), ("grouped", grouped)])
    for text in ("ddos", "0.96", "0.77", "0.64", "0.20"):
        assert text in figure
    assert figure_holdout([("empty", {})]) == ""


def test_concentration_figure_pads_missing_hosts() -> None:
    figure = figure_concentration([("original", RUN), ("none", {"models": {}})])
    assert "90.0%" in figure
    assert figure.count("<rect") >= 3
    assert figure_concentration([("none", {})]) == ""


def test_page_with_figures_stays_inert_and_escapes_labels() -> None:
    hostile = "<script>alert(1)</script>"
    page = build_page(
        title="T",
        runs=[Labelled(hostile, RUN)],
        adaptive=[Labelled("a", ADAPTIVE)],
        holdout=[Labelled(hostile, {"families": {"dos": {"recall_unseen": 0.5}}})],
    )
    assert "<h2>Figures</h2>" in page
    assert "<script" not in page.lower()
    assert " style=" not in page
    assert not re.search(r"(src|href)=", page)
    assert "&lt;script&gt;" in page
    assert page.count("<svg") == 3
