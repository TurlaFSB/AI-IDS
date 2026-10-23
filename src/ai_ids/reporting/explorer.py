"""Static results explorer: one self-contained HTML page built from saved JSON reports.

The page has no scripts, no external requests and no fonts or images to fetch. A Content Security
Policy with a hash of the single inline style block forbids everything else, so a page opened from
disk or a static host cannot phone home or run code, whatever the report files contain. Every value
is copied from the report files and escaped before it is written; sections whose inputs are absent
are omitted, never filled with defaults.
"""

from __future__ import annotations

import base64
import hashlib
import html
import json
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

MAX_REPORT_BYTES = 64 * 1024 * 1024
SMALL_SUPPORT = 30

_CSS_TEMPLATE = """
:root{--bg:#fff;--fg:#14181f;--muted:#56606f;--line:#d6dbe3;--card:#f6f8fb;--bar:#2563a8;
--bar2:#b45309;--warn:#b42318;--ok:#146c43;--cell:37,99,168}
@media (prefers-color-scheme:dark){:root:not([data-theme=light]){--bg:#0e1116;--fg:#e6e9ef;
--muted:#9aa4b2;--line:#2a313c;--card:#161b22;--bar:#6aa9f0;--bar2:#f0a04b;--warn:#ff8a80;
--ok:#6fd49b;--cell:106,169,240}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.5 system-ui,-apple-system,Segoe UI,
Roboto,sans-serif}
main{max-width:1100px;margin:0 auto;padding:24px 16px 64px}
h1{font-size:1.75rem;margin:0 0 4px}h2{font-size:1.25rem;margin:40px 0 8px;
border-bottom:1px solid var(--line);padding-bottom:4px}h3{font-size:1rem;margin:20px 0 6px}
p,li{max-width:75ch}.muted{color:var(--muted)}.warn{color:var(--warn)}.ok{color:var(--ok)}
.note{background:var(--card);border:1px solid var(--line);border-radius:6px;padding:10px 14px;
margin:12px 0}
.scroll{overflow-x:auto}
table{border-collapse:collapse;width:100%;margin-top:14px;font-size:.9rem;font-variant-numeric:tabular-nums}
th,td{border-bottom:1px solid var(--line);padding:6px 8px;text-align:left;vertical-align:middle}
th{font-weight:600;color:var(--muted);white-space:nowrap}
td.n,th.n{text-align:right}
.bar{display:inline-block;height:.8rem;background:var(--bar);border-radius:2px;vertical-align:middle}
.bar.b2{background:var(--bar2)}
.barcell{width:34%;min-width:170px;white-space:nowrap}
.barcell span.v{margin-left:8px}
.heat{text-align:right}
code{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:.85em}
footer{margin-top:48px;color:var(--muted);font-size:.85rem}
@media print{:root{--bg:#fff;--fg:#000}.scroll{overflow:visible}}
"""


def _bar_css() -> str:
    widths = "".join(f".w{i}{{width:{i * 0.6:.1f}%}}" for i in range(101))
    heat = "".join(f".h{i}{{background:rgba(var(--cell),{i / 10 * 0.75:.3f})}}" for i in range(11))
    return _CSS_TEMPLATE + widths + heat


@dataclass(frozen=True)
class Labelled:
    label: str
    data: dict[str, Any]


def load_report(path: Path) -> dict[str, Any]:
    """Read one JSON report, refusing anything that is not a reasonably sized JSON object."""
    if path.stat().st_size > MAX_REPORT_BYTES:
        raise ValueError(f"{path} is larger than {MAX_REPORT_BYTES} bytes")
    with path.open(encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError(f"{path} does not contain a JSON object")
    return data


def esc(value: object) -> str:
    return html.escape(str(value), quote=True)


def _dict(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _num(value: object) -> float | None:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    return float(value)


def _fmt(value: object, digits: int = 3) -> str:
    number = _num(value)
    return "n/a" if number is None else f"{number:.{digits}f}"


def _pct(value: object, digits: int = 2) -> str:
    number = _num(value)
    return "n/a" if number is None else f"{number * 100:.{digits}f}%"


def _interval(block: object, kind: str) -> str:
    """'estimate [low, high]' from a bootstrap block, or the bare estimate when absent."""
    data = _dict(block)
    fmt = _pct if kind == "pct" else _fmt
    low, high, est = _num(data.get("low")), _num(data.get("high")), data.get("estimate")
    if low is None or high is None:
        return fmt(est)
    return f"{fmt(est)} [{fmt(low)}, {fmt(high)}]"


def _width_class(fraction: float | None, maximum: float = 1.0) -> str:
    if fraction is None or maximum <= 0:
        return "w0"
    return f"w{max(0, min(100, round(fraction / maximum * 100)))}"


def _bar(fraction: float | None, text: str, *, second: bool = False, maximum: float = 1.0) -> str:
    klass = "bar b2" if second else "bar"
    return (
        f'<td class="barcell"><span class="{klass} {_width_class(fraction, maximum)}" '
        f'role="presentation"></span><span class="v">{esc(text)}</span></td>'
    )


def _heat(value: object, text: str | None = None) -> str:
    number = _num(value)
    shown = text if text is not None else _fmt(value, 2)
    level = 0 if number is None else max(0, min(10, round(number * 10)))
    return f'<td class="heat h{level}">{esc(shown)}</td>'


def _table(head: Sequence[tuple[str, bool]], rows: Iterable[str], caption: str) -> str:
    cells = "".join(
        f'<th scope="col"{" class=n" if numeric else ""}>{esc(h)}</th>' for h, numeric in head
    )
    return (
        f'<div class="scroll"><table><caption class="muted">{esc(caption)}</caption>'
        f"<thead><tr>{cells}</tr></thead><tbody>{''.join(rows)}</tbody></table></div>"
    )


def _row(cells: Sequence[str]) -> str:
    return f"<tr>{''.join(cells)}</tr>"


def _td(value: object, numeric: bool = False) -> str:
    return f"<td{' class=n' if numeric else ''}>{esc(value)}</td>"


def _th(value: object) -> str:
    return f'<th scope="row">{esc(value)}</th>'


def _provenance(runs: Sequence[Labelled]) -> str:
    rows = []
    for run in runs:
        env, cfg = _dict(run.data.get("environment")), _dict(run.data.get("config"))
        rows_by_split = _dict(_dict(run.data.get("dataset")).get("rows"))
        commit = str(env.get("git_commit", "n/a"))[:10]
        dirty = " (dirty tree)" if env.get("git_dirty") else ""
        excluded = ", ".join(str(x) for x in cfg.get("exclude_features", [])) or "none"
        rows.append(
            _row(
                [
                    _th(run.label),
                    _td(run.data.get("version", "n/a")),
                    _td(commit + dirty),
                    _td(cfg.get("seed", "n/a"), True),
                    _td("corrected" if cfg.get("corrected_labels") else "original"),
                    _td(excluded),
                    _td(rows_by_split.get("train", "n/a"), True),
                    _td(rows_by_split.get("test", "n/a"), True),
                ]
            )
        )
    head = [
        ("Run", False),
        ("Version", False),
        ("Commit", False),
        ("Seed", True),
        ("Labels", False),
        ("Excluded features", False),
        ("Train flows", True),
        ("Test flows", True),
    ]
    return _table(head, rows, "Provenance of each run (copied from the report files)")


def _headline(run: Labelled) -> str:
    models = _dict(run.data.get("models"))
    rows = []
    for name, raw in models.items():
        model = _dict(raw)
        test, ci = _dict(model.get("test")), _dict(model.get("confidence_intervals"))
        target = _num(model.get("target_fpr"))
        fpr = _num(test.get("false_positive_rate"))
        ratio = ""
        if fpr is not None and target:
            ratio = f"  ({fpr / target:.1f}x target)"
        fpr_text = _interval(ci.get("false_positive_rate"), "pct") if ci else _pct(fpr)
        rows.append(
            _row(
                [
                    _th(name),
                    _td(
                        _interval(ci.get("recall"), "num") if ci else _fmt(test.get("recall")),
                        True,
                    ),
                    _bar(fpr, fpr_text + ratio, second=True, maximum=max(0.1, (fpr or 0) * 1.2)),
                    _td(_fmt(test.get("precision")), True),
                    _td(_fmt(test.get("pr_auc")), True),
                    _td(_fmt(model.get("macro_recall")), True),
                ]
            )
        )
    head = [
        ("Detector", False),
        ("Recall [95% CI]", True),
        ("False-positive rate [95% CI] (bar scaled per run)", False),
        ("Precision", True),
        ("PR-AUC", True),
        ("Macro recall", True),
    ]
    target = next((_dict(m).get("target_fpr") for m in models.values()), None)
    caption = (
        f"{run.label}: test-set results, alert threshold calibrated for a "
        f"{_pct(target, 1)} false-positive rate"
    )
    return f"<h3>{esc(run.label)}</h3>" + _table(head, rows, caption)


def _comparison(runs: Sequence[Labelled]) -> str:
    names = [
        n
        for n in _dict(runs[0].data.get("models"))
        if all(n in _dict(r.data.get("models")) for r in runs[1:])
    ]
    if not names:
        return ""
    head: list[tuple[str, bool]] = [("Detector", False)]
    for run in runs:
        head += [(f"{run.label}: recall", True), (f"{run.label}: false-positive rate", True)]
    rows = []
    for name in names:
        cells = [_th(name)]
        for run in runs:
            test = _dict(_dict(_dict(run.data.get("models")).get(name)).get("test"))
            cells += [
                _td(_fmt(test.get("recall"), 4), True),
                _td(_pct(test.get("false_positive_rate")), True),
            ]
        rows.append(_row(cells))
    intro = (
        "<p class=muted>The runs may differ in more than the label set (for example the corrected "
        "labels drop flows the original run keeps); read the notes under each run before "
        "attributing a change.</p>"
    )
    return "<h2>Side by side</h2>" + intro + _table(head, rows, "Same detectors across runs")


def _categories(run: Labelled) -> str:
    models = _dict(run.data.get("models"))
    categories = sorted(
        {c for m in models.values() for c in _dict(_dict(m).get("per_category_recall"))}
    )
    if not categories:
        return ""
    rows = []
    for name, raw in models.items():
        recall = _dict(_dict(raw).get("per_category_recall"))
        cells = []
        for category in categories:
            entry = _dict(recall.get(category))
            support = entry.get("support")
            small = isinstance(support, int | float) and support < SMALL_SUPPORT
            text = _fmt(entry.get("recall"), 2)
            if support is not None and text != "n/a":
                text += f" (n={support}){' †' if small else ''}"
            cells.append(_heat(entry.get("recall"), text))
        rows.append(_row([_th(name), *cells]))
    head = [("Detector", False)] + [(c, True) for c in categories]
    note = (
        f'<p class="muted">n = test flows. † = fewer than {SMALL_SUPPORT} test flows; '
        "recall is unreliable.</p>"
    )
    caption = f"{run.label}: recall per attack category at the calibrated threshold"
    return f"<h3>{esc(run.label)}</h3>" + _table(head, rows, caption) + note


def _concentration(run: Labelled) -> str:
    out = []
    for name, raw in _dict(run.data.get("models")).items():
        conc = _dict(_dict(_dict(raw).get("false_positive_profile")).get("host_concentration"))
        hosts = conc.get("top_hosts")
        if not isinstance(hosts, list) or not hosts:
            continue
        rows = [
            _row(
                [
                    _th(_dict(h).get("host", "n/a")),
                    _td(_dict(h).get("false_positives", "n/a"), True),
                    _bar(
                        _num(_dict(h).get("share_of_false_positives")),
                        _pct(_dict(h).get("share_of_false_positives"), 1),
                    ),
                    _td(_pct(_dict(h).get("false_positive_rate")), True),
                    _td(_dict(h).get("distinct_destination_ports", "n/a"), True),
                ]
            )
            for h in hosts
        ]
        head = [
            ("Source host", False),
            ("False positives", True),
            ("Share of all false positives", False),
            ("Host false-positive rate", True),
            ("Distinct destination ports", True),
        ]
        excluded = _dict(conc.get("fpr_excluding_top_hosts"))
        note = ""
        if excluded:
            parts = [
                f"top {k}: {_pct(_dict(v).get('false_positive_rate'))}" for k, v in excluded.items()
            ]
            note = (
                '<p class="muted">Rate with the top hosts excluded ('
                + esc("; ".join(parts))
                + "). A sensitivity analysis chosen after seeing the errors, "
                "not a performance claim.</p>"
            )
        out.append(
            f"<h3>{esc(run.label)}, {esc(name)}</h3>"
            + _table(head, rows, f"{run.label} / {name}: where the false positives come from")
            + note
        )
    return "".join(out)


def _adaptive(items: Sequence[Labelled]) -> str:
    out = ["<h2>Adaptive evasion (feature space)</h2>"]
    for item in items:
        data = _dict(item.data.get("adaptive_evasion"))
        if not data:
            continue
        control = _dict(data.get("benign_control"))
        out.append(f"<h3>{esc(item.label)}</h3>")
        out.append(
            f"<p>Clean recall <strong>{esc(_fmt(data.get('clean_recall')))}</strong>, "
            "recall against a per-flow best-of-grid adversary "
            f"<strong>{esc(_fmt(data.get('adaptive_recall')))}</strong> "
            f"({esc(data.get('attack_flows', 'n/a'))} attack flows sampled). Benign control: "
            f"{esc(_pct(control.get('clean_false_positive_rate'), 1))} of benign flows flagged "
            "clean, "
            f"{esc(_pct(control.get('flagged_under_any_combination'), 1))} under the worst "
            "combination. A "
            "large gap there would mean the model learned that perturbed means attack.</p>"
        )
        frontier = _dict(data.get("recall_frontier"))
        pads = list(_dict(next(iter(frontier.values()), {})))
        if pads:
            rows = [
                _row([_th(slow)] + [_heat(_dict(row).get(p)) for p in pads])
                for slow, row in frontier.items()
            ]
            head = [("Adversary budget: slowdown", False)] + [(p, True) for p in pads]
            out.append(
                _table(head, rows, "Recall as the adversary's allowed slowdown and padding grow")
            )
        benign_cells = _dict(data.get("benign_by_combination"))
        pads_b = list(_dict(next(iter(benign_cells.values()), {})))
        if pads_b:
            rows = [
                _row(
                    [_th(slow)]
                    + [_heat(_dict(row).get(p), _pct(_dict(row).get(p), 1)) for p in pads_b]
                )
                for slow, row in benign_cells.items()
            ]
            head = [("Every benign flow reshaped by: slowdown", False)] + [
                (p, True) for p in pads_b
            ]
            out.append(
                _table(
                    head,
                    rows,
                    "Share of benign flows flagged when every flow gets one reshaping "
                    "(not a best-of-grid); "
                    "high values mean the detector treats reshaped traffic as an attack",
                )
            )
        families = _dict(data.get("by_family"))
        if families:
            rows = []
            for fam, raw in families.items():
                f = _dict(raw)
                rows.append(
                    _row(
                        [
                            _th(fam),
                            _bar(_num(f.get("clean_recall")), _fmt(f.get("clean_recall"))),
                            _bar(
                                _num(f.get("adaptive_recall")),
                                _fmt(f.get("adaptive_recall")),
                                second=True,
                            ),
                        ]
                    )
                )
            head = [("Family", False), ("Clean recall", False), ("Adaptive recall", False)]
            out.append(_table(head, rows, "Per-family recall under the adaptive adversary"))
        note = data.get("note")
        if note:
            out.append(f'<p class="note">{esc(note)}</p>')
    return "".join(out) if len(out) > 1 else ""


def _holdout(items: Sequence[Labelled]) -> str:
    out = ["<h2>Unseen attack families (leave-one-family-out)</h2>"]
    for item in items:
        families = _dict(item.data.get("families"))
        if not families:
            continue
        rows, total, weighted, recalls = [], 0, 0.0, []
        for fam, raw in families.items():
            f = _dict(raw)
            recall, support = _num(f.get("recall_unseen")), _num(f.get("test_support"))
            if recall is not None and support:
                total += int(support)
                weighted += recall * support
                recalls.append(recall)
            rows.append(
                _row(
                    [
                        _th(fam),
                        _bar(recall, _fmt(recall)),
                        _td(f.get("test_support", "n/a"), True),
                        _td(_pct(f.get("false_positive_rate")), True),
                    ]
                )
            )
        head = [
            ("Held-out family", False),
            ("Recall on the unseen family", False),
            ("Test flows", True),
            ("False-positive rate", True),
        ]
        summary = ""
        if total:
            summary = (
                f"<p>Pooled over {total:,} flows: <strong>{weighted / total:.3f}</strong>; "
                f"unweighted mean over {len(recalls)} families: "
                f"<strong>{sum(recalls) / len(recalls):.3f}</strong> "
                "(computed here from the table).</p>"
            )
        out.append(
            f"<h3>{esc(item.label)}</h3>"
            + summary
            + _table(head, rows, "Recall on a family the model never saw in training")
        )
    return "".join(out) if len(out) > 1 else ""


def _transfer(items: Sequence[Labelled]) -> str:
    out = ["<h2>Cross-dataset transfer</h2>"]
    points = (
        ("stored_threshold", "Stored threshold (fixed on the source dataset)"),
        ("oracle_recalibrated", "Oracle threshold (target benign labels; an upper bound)"),
    )
    for item in items:
        rows = []
        pairs = list(points)
        study = _dict(item.data.get("local_calibration_study"))
        if study:
            pairs += [
                ("stored_on_later", "Stored threshold, later flows only"),
                ("local_calibration", "Threshold set on the earliest benign slice (deployable)"),
            ]
        for key, label in pairs:
            point = (
                _dict(study.get(key))
                if key in ("stored_on_later", "local_calibration")
                else _dict(item.data.get(key))
            )
            if not point:
                continue
            rows.append(
                _row(
                    [
                        _th(label),
                        _td(_fmt(point.get("recall")), True),
                        _td(_pct(point.get("false_positive_rate")), True),
                        _td(_fmt(point.get("precision")), True),
                        _td(_fmt(point.get("pr_auc")), True),
                    ]
                )
            )
        if rows:
            head = [
                ("Operating point", False),
                ("Recall", True),
                ("False-positive rate", True),
                ("Precision", True),
                ("PR-AUC", True),
            ]
            flows = (
                f"{item.data.get('target_flows', 'n/a')} flows, "
                f"{item.data.get('target_attacks', 'n/a')} attacks"
            )
            out.append(
                f"<h3>{esc(item.label)}</h3>"
                + _table(head, rows, f"{item.label}: scoring a second dataset ({flows})")
            )
    return "".join(out) if len(out) > 1 else ""


def build_page(
    *,
    title: str,
    runs: Sequence[Labelled] = (),
    adaptive: Sequence[Labelled] = (),
    holdout: Sequence[Labelled] = (),
    transfer: Sequence[Labelled] = (),
    notes: Sequence[str] = (),
) -> str:
    """Render the explorer. At least one input is required; empty sections are left out."""
    if not (runs or adaptive or holdout or transfer):
        raise ValueError("nothing to render: pass at least one report")
    body = [f"<h1>{esc(title)}</h1>"]
    body.append(
        '<p class="muted">Values are copied unchanged from the listed report files. '
        "Intervals, where "
        "shown, are time-block bootstrap 95% intervals. Read the limitations in the repository "
        "documentation before quoting any figure.</p>"
    )
    for note in notes:
        body.append(f'<p class="note">{esc(note)}</p>')
    if runs:
        body.append("<h2>Runs</h2>" + _provenance(runs))
        body.append("<h2>Headline results</h2>" + "".join(_headline(r) for r in runs))
        if len(runs) > 1:
            body.append(_comparison(runs))
        cats = "".join(_categories(r) for r in runs)
        if cats:
            body.append("<h2>Recall by attack category</h2>" + cats)
        conc = "".join(_concentration(r) for r in runs)
        if conc:
            body.append("<h2>Where the false positives come from</h2>" + conc)
    for section in (
        _adaptive(adaptive) if adaptive else "",
        _holdout(holdout) if holdout else "",
        _transfer(transfer) if transfer else "",
    ):
        body.append(section)
    css = _bar_css()
    digest = base64.b64encode(hashlib.sha256(css.encode("utf-8")).digest()).decode("ascii")
    csp = f"default-src 'none'; style-src 'sha256-{digest}'; base-uri 'none'; form-action 'none'"
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f'<meta http-equiv="Content-Security-Policy" content="{csp}">'
        '<meta name="referrer" content="no-referrer">'
        f"<title>{esc(title)}</title><style>{css}</style></head><body><main>"
        + "".join(body)
        + "<footer>Static page generated by <code>ai-ids report-html</code>. "
        "It contains no scripts "
        "and makes no network requests.</footer></main></body></html>"
    )
