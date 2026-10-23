"""Inline SVG figures for the results page: no scripts, no external files, readable without colour.

Charts are plain SVG built from the report data. Colours come from CSS classes defined in the page's
hashed style block (so the Content Security Policy stays strict), every chart has a title and a
description for assistive technology, and each data series is also labelled in text, so colour is
never the only way to read one. Values are copied from the reports; a series with no value for a
point leaves a gap instead of a default.
"""

from __future__ import annotations

import html
import re
from collections.abc import Sequence
from typing import Any

WIDTH = 640
LEFT, RIGHT, TOP, BOTTOM = 56, 40, 28, 56
PALETTE_LIGHT = ("#2563a8", "#b45309", "#146c43", "#7e3fb2", "#56606f")
PALETTE_DARK = ("#6aa9f0", "#f0a04b", "#6fd49b", "#c49bf0", "#9aa4b2")

FIGURE_CSS = (
    f":root{{{''.join(f'--c{i}:{c};' for i, c in enumerate(PALETTE_LIGHT))}}}"
    "@media (prefers-color-scheme:dark){:root:not([data-theme=light]){"
    f"{''.join(f'--c{i}:{c};' for i, c in enumerate(PALETTE_DARK))}}}}}"
    + "".join(f".l{i}{{stroke:var(--c{i});fill:none}}.f{i}{{fill:var(--c{i})}}" for i in range(5))
    + "svg.fig{width:100%;height:auto;max-width:720px;margin:8px 0}"
    "svg.fig text{fill:var(--fg);font:12px system-ui,sans-serif}"
    "svg.fig .grid{stroke:var(--line);stroke-width:1}"
    "svg.fig .axis{stroke:var(--muted);stroke-width:1}"
    "svg.fig .line{stroke-width:2.5;stroke-linejoin:round}"
    "svg.fig .mark{stroke:var(--warn);stroke-width:1.5;stroke-dasharray:5 4}"
    "svg.fig .muted{fill:var(--muted)}svg.fig .warnt{fill:var(--warn)}"
    "figure{margin:24px 0}figcaption{color:var(--muted);font-size:.9rem;max-width:75ch}"
)


def _e(value: object) -> str:
    return html.escape(str(value), quote=True)


def _pct_tick(value: float) -> str:
    return f"{value * 100:.0f}%"


def _frame(height: int, title: str, desc: str, inner: str, ident: str) -> str:
    return (
        f'<svg class="fig" viewBox="0 0 {WIDTH} {height}" role="img" '
        f'aria-labelledby="{ident}-t {ident}-d" xmlns="http://www.w3.org/2000/svg">'
        f'<title id="{ident}-t">{_e(title)}</title>'
        f'<desc id="{ident}-d">{_e(desc)}</desc>{inner}</svg>'
    )


def _y_axis(height: int, top: float, bottom: float, maximum: float) -> str:
    parts = []
    for step in range(5):
        value = maximum * step / 4
        y = bottom - (bottom - top) * step / 4
        parts.append(
            f'<line class="grid" x1="{LEFT}" x2="{WIDTH - RIGHT}" y1="{y:.1f}" y2="{y:.1f}"/>'
            f'<text class="muted" x="{LEFT - 8}" y="{y + 4:.1f}" text-anchor="end">'
            f"{_pct_tick(value)}</text>"
        )
    parts.append(f'<line class="axis" x1="{LEFT}" x2="{LEFT}" y1="{top}" y2="{bottom}"/>')
    return "".join(parts)


def line_chart(
    ident: str,
    title: str,
    desc: str,
    x_labels: Sequence[str],
    series: Sequence[tuple[str, Sequence[float | None]]],
    *,
    mark_after: int | None = None,
    mark_label: str = "",
    maximum: float = 1.0,
) -> str:
    """Lines over categorical x positions with a 0..maximum percentage y axis and a legend."""
    height = 300 + 18 * ((len(series) + 2) // 3)
    top, bottom = TOP, 250.0
    left, right = LEFT, WIDTH - RIGHT
    step = (right - left) / max(1, len(x_labels) - 1)
    inner = [_y_axis(height, top, bottom, maximum)]
    for i, label in enumerate(x_labels):
        x = left + step * i
        inner.append(
            f'<text class="muted" x="{x:.1f}" y="{bottom + 18:.0f}" text-anchor="middle">'
            f"{_e(label)}</text>"
        )
    if mark_after is not None and 0 <= mark_after < len(x_labels) - 1:
        x = left + step * (mark_after + 0.5)
        inner.append(f'<line class="mark" x1="{x:.1f}" x2="{x:.1f}" y1="{top}" y2="{bottom}"/>')
        inner.append(f'<text class="warnt" x="{x + 6:.1f}" y="{top + 12}">{_e(mark_label)}</text>')
    for index, (name, values) in enumerate(series):
        cls = index % 5
        points = [
            (left + step * i, bottom - (bottom - top) * min(v, maximum) / maximum)
            for i, v in enumerate(values)
            if v is not None
        ]
        if len(points) > 1:
            path = " ".join(f"{x:.1f},{y:.1f}" for x, y in points)
            inner.append(f'<polyline class="line l{cls}" points="{path}"/>')
        for x, y in points:
            inner.append(f'<circle class="f{cls}" cx="{x:.1f}" cy="{y:.1f}" r="3"/>')
        lx = left + (index % 3) * 190
        ly = bottom + 44 + 18 * (index // 3)
        inner.append(
            f'<rect class="f{cls}" x="{lx}" y="{ly - 9}" width="12" height="12"/>'
            f'<text x="{lx + 18}" y="{ly + 2}">{_e(name)}</text>'
        )
    return _frame(height, title, desc, "".join(inner), ident)


def grouped_bars(
    ident: str,
    title: str,
    desc: str,
    categories: Sequence[str],
    series: Sequence[tuple[str, Sequence[float | None]]],
    *,
    percent: bool = False,
) -> str:
    """Horizontal bars, one group per category, one bar per series, value printed on every bar."""
    bar, gap = 14, 12
    group = bar * len(series) + gap
    left = 150
    top = TOP
    plot_h = group * len(categories)
    height = int(top + plot_h + 30 + 18 * ((len(series) + 2) // 3))
    inner = []
    for step in range(5):
        x = left + (WIDTH - RIGHT - left) * step / 4
        inner.append(
            f'<line class="grid" x1="{x:.1f}" x2="{x:.1f}" y1="{top}" y2="{top + plot_h}"/>'
            f'<text class="muted" x="{x:.1f}" y="{top - 8}" text-anchor="middle">'
            f"{_pct_tick(step / 4)}</text>"
        )
    for ci, category in enumerate(categories):
        y0 = top + ci * group
        inner.append(
            f'<text x="{left - 8}" y="{y0 + bar * len(series) / 2 + 4:.1f}" text-anchor="end">'
            f"{_e(category)}</text>"
        )
        for si, (_, values) in enumerate(series):
            value = values[ci]
            if value is None:
                continue
            shown = f"{value * 100:.1f}%" if percent else f"{value:.2f}"
            width = (WIDTH - RIGHT - left) * max(0.0, min(value, 1.0))
            y = y0 + si * bar
            inner.append(
                f'<rect class="f{si % 5}" x="{left}" y="{y}" width="{width:.1f}" '
                f'height="{bar - 2}"/>'
                f'<text x="{left + width + 6:.1f}" y="{y + bar - 4}">{shown}</text>'
            )
    for index, (name, _) in enumerate(series):
        lx = left + (index % 3) * 150
        ly = top + plot_h + 22 + 18 * (index // 3)
        inner.append(
            f'<rect class="f{index % 5}" x="{lx}" y="{ly - 9}" width="12" height="12"/>'
            f'<text x="{lx + 18}" y="{ly + 2}">{_e(name)}</text>'
        )
    return _frame(height, title, desc, "".join(inner), ident)


def _padding_value(label: str) -> float:
    match = re.search(r"([0-9.]+)", label)
    return float(match.group(1)) if match else 0.0


def figure_benign_reshaping(adaptive: dict[str, Any], run: dict[str, Any] | None) -> str:
    """Share of benign flows flagged per single slowdown and padding, training range marked."""
    cells = adaptive.get("adaptive_evasion", {}).get("benign_by_combination")
    if not isinstance(cells, dict) or not cells:
        return ""
    paddings = list(next(iter(cells.values())))
    series = [
        (f"slowdown {slow.removeprefix('slow=')}", [row.get(p) for p in paddings])
        for slow, row in cells.items()
    ]
    trained = (run or {}).get("config", {}).get("augmentation", {}).get("paddings")
    mark = None
    if isinstance(trained, list) and trained:
        limit = max(float(v) for v in trained)
        inside = [i for i, p in enumerate(paddings) if _padding_value(p) <= limit]
        mark = inside[-1] if inside else None
    svg = line_chart(
        "fig-benign",
        "Benign flows flagged as attacks when reshaped",
        "Line chart: share of benign flows the detector flags after every flow is slowed and "
        "padded; "
        "one line per slowdown factor, padding on the horizontal axis.",
        [p.removeprefix("pad=") for p in paddings],
        series,
        mark_after=mark,
        mark_label="largest training padding",
    )
    return (
        f"<figure>{svg}<figcaption>Share of benign flows flagged when every flow receives one "
        "slowdown and one forward padding. A detector that is robust to reshaping stays flat; a "
        "rise past the dashed line shows it flags flows that look unlike its training data. "
        "High recall against an adversary has to be read together with this.</figcaption></figure>"
    )


def figure_holdout(items: Sequence[tuple[str, dict[str, Any]]]) -> str:
    """Unseen-family recall per family, one bar per holdout run (members of groups expanded)."""
    per_item: list[dict[str, float | None]] = []
    for _, data in items:
        recalls: dict[str, float | None] = {}
        for family, raw in (data.get("families") or {}).items():
            members = raw.get("members") if isinstance(raw, dict) else None
            if isinstance(members, dict) and members:
                for member, detail in members.items():
                    recalls[member] = (
                        detail.get("recall_unseen") if isinstance(detail, dict) else None
                    )
            elif isinstance(raw, dict):
                recalls[family] = raw.get("recall_unseen")
        per_item.append(recalls)
    categories = sorted({c for recalls in per_item for c in recalls})
    if not categories:
        return ""
    series = [
        (label, [recalls.get(c) for c in categories])
        for (label, _), recalls in zip(items, per_item, strict=True)
    ]
    svg = grouped_bars(
        "fig-holdout",
        "Recall on attack families the model never saw in training",
        "Horizontal bars: recall on each held-out family, one bar per leave-out design.",
        categories,
        series,
    )
    return (
        f"<figure>{svg}<figcaption>Recall on a family withheld from training. Where related "
        "families are withheld together (a group), the bar is the family's own recall inside the "
        "group; a drop against the single-family bar measures how much a close relative in "
        "training had helped.</figcaption></figure>"
    )


def figure_concentration(runs: Sequence[tuple[str, dict[str, Any]]]) -> str:
    """Share of all false positives held by the three worst hosts, per run."""
    series: list[tuple[str, list[float | None]]] = []
    for label, report in runs:
        models = report.get("models") or {}
        preferred: dict[str, Any] = models.get("random_forest") or next(iter(models.values()), {})
        hosts = (preferred.get("false_positive_profile") or {}).get("host_concentration", {})
        top = hosts.get("top_hosts") if isinstance(hosts, dict) else None
        if isinstance(top, list) and top:
            shares = [h.get("share_of_false_positives") for h in top[:3]]
            series.append((label, shares + [None] * (3 - len(shares))))
    if not series:
        return ""
    svg = grouped_bars(
        "fig-concentration",
        "How concentrated the false positives are",
        "Horizontal bars: share of all false positives caused by the worst, second and third host.",
        ["worst host", "second host", "third host"],
        series,
        percent=True,
    )
    return (
        f"<figure>{svg}<figcaption>Share of all false positives caused by each run's three worst "
        "source hosts (Random Forest). Concentration on a few scan-like hosts points to label "
        "noise; spreading over many hosts does not.</figcaption></figure>"
    )
