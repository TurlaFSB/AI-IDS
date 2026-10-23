"""Audit the re-implemented label rules against the authors' published labelling script.

The authors of the corrected CICIDS2017 labels publish their labelling as a notebook of
`label_flows(...)` calls. This module reads such a notebook **as data**: it is parsed with `ast`
and only literal arguments are evaluated, so nothing in the file is ever executed. Each call is
reduced to a signature (label, window, source and destination addresses, ports, payload condition)
and compared with the rules in `ai_ids.data.relabel`.

The check is deliberately narrow. It verifies that every rule the authors state has a counterpart
in the port with the same literal parameters, and lists what is only on one side. It does not
compare the `additional_filters` expressions semantically (they are arbitrary pandas expressions);
those are reported as text for a human to read, and the report says so. Nor does it show that our
labels equal theirs flow by flow: the authors label flows from their own repaired CICFlowMeter run,
which differ from the original CSVs, so that comparison needs their output files.
"""

from __future__ import annotations

import ast
import hashlib
import json
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ai_ids.data.relabel import ATTEMPTED_SUFFIX, RULESET_VERSION, Rule, rules_for

MAX_NOTEBOOK_BYTES = 8 * 1024 * 1024
POSITIONAL = ("df", "label", "start", "end", "src_ips", "dst_ips")
DAY_FILES: dict[str, tuple[str, ...]] = {
    "monday": ("Monday-WorkingHours.pcap_ISCX.csv",),
    "tuesday": ("Tuesday-WorkingHours.pcap_ISCX.csv",),
    "wednesday": ("Wednesday-WorkingHours.pcap_ISCX.csv",),
    "thursday": (
        "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
        "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
    ),
    "friday": (
        "Friday-WorkingHours-Morning.pcap_ISCX.csv",
        "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
        "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
    ),
}

Signature = tuple[Any, ...]

# The authors' vocabulary differs from the original dataset's in one label.
LABEL_ALIASES = {"Botnet": "Bot"}
PORT_COLUMNS = {"Src Port": "src_ports", "Dst Port": "dst_ports"}


@dataclass(frozen=True)
class Stated:
    """One `label_flows` call, reduced to the parameters that can be compared literally."""

    day: str
    label: str
    start: int
    end: int
    src_ips: tuple[str, ...] | None
    dst_ips: tuple[str, ...] | None
    src_ports: tuple[int, ...] | None
    dst_ports: tuple[int, ...] | None
    payload_filter: bool
    filter_text: tuple[str, ...]
    opaque_filters: int


def _port_column(node: ast.expr) -> str | None:
    """'src_ports' or 'dst_ports' when `node` is df["Src Port"] or df["Dst Port"]."""
    if isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Constant):
        return PORT_COLUMNS.get(str(node.slice.value))
    return None


def _port_filter(node: ast.expr) -> tuple[str, set[int]] | None:
    """Fold simple literal port conditions into (column, ports); None if the filter is opaque.

    Recognised: `df["Src Port"] == n`, `df["Src Port"].isin([...])` and an `or` of such
    conditions on one column. Anything else (negations, packet-size tests, ...) stays opaque.
    """
    if isinstance(node, ast.Compare) and len(node.ops) == 1 and isinstance(node.ops[0], ast.Eq):
        column = _port_column(node.left)
        right = node.comparators[0]
        if column and isinstance(right, ast.Constant) and isinstance(right.value, int):
            return column, {right.value}
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "isin"
        and (column := _port_column(node.func.value))
        and len(node.args) == 1
    ):
        try:
            return column, {int(v) for v in ast.literal_eval(node.args[0])}
        except (ValueError, TypeError):
            return None
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        first, second = _port_filter(node.left), _port_filter(node.right)
        if first and second and first[0] == second[0]:
            return first[0], first[1] | second[1]
    return None


def _literal(node: ast.expr | None) -> Any:
    return None if node is None else ast.literal_eval(node)


def _set_or_none(value: Any) -> set[int] | None:
    return None if value is None else {int(v) for v in value}


def _tuple_or_none(value: Any) -> tuple[Any, ...] | None:
    return None if value is None else tuple(sorted(value))


def read_notebook_source(path: Path) -> str:
    """Concatenate the code cells of a notebook (or read a plain Python file)."""
    if path.stat().st_size > MAX_NOTEBOOK_BYTES:
        raise ValueError(f"{path} is larger than {MAX_NOTEBOOK_BYTES} bytes")
    text = path.read_text(encoding="utf-8")
    if path.suffix != ".ipynb":
        return text
    cells = json.loads(text).get("cells", [])
    return "\n".join(
        "".join(cell.get("source", [])) for cell in cells if cell.get("cell_type") == "code"
    )


def extract_calls(source: str) -> list[Stated]:
    """All `label_flows(<frame>, ...)` calls in source order. Never executes the source."""
    calls: list[Stated] = []
    for node in ast.walk(ast.parse(source)):
        if not (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "label_flows"
        ):
            continue
        frame = node.args[0]
        if not isinstance(frame, ast.Name) or "_df" not in frame.id:
            continue
        day = frame.id.split("_df")[0]
        values: dict[str, ast.expr | None] = dict(zip(POSITIONAL[1:], node.args[1:], strict=False))
        values.update({k.arg: k.value for k in node.keywords if k.arg})
        extra = values.get("additional_filters")
        filters = list(extra.elts) if isinstance(extra, ast.List) else []
        texts = tuple(ast.unparse(e) for e in filters)
        ports: dict[str, set[int] | None] = {
            "src_ports": _set_or_none(_literal(values.get("src_port_list"))),
            "dst_ports": _set_or_none(_literal(values.get("dst_port_list"))),
        }
        opaque = 0
        for expression in filters:
            folded = _port_filter(expression)
            if folded is None:
                opaque += 1
                continue
            column, found = folded
            current = ports[column]
            ports[column] = found if current is None else current & found
        label = str(_literal(values["label"]))
        for authors_name, ours_name in LABEL_ALIASES.items():
            if label.startswith(authors_name):
                label = ours_name + label[len(authors_name) :]
        calls.append(
            Stated(
                day=day,
                label=label,
                start=int(_literal(values["start"])),
                end=int(_literal(values["end"])),
                src_ips=_tuple_or_none(_literal(values.get("src_ips"))),
                dst_ips=_tuple_or_none(_literal(values.get("dst_ips"))),
                src_ports=_tuple_or_none(ports["src_ports"]),
                dst_ports=_tuple_or_none(ports["dst_ports"]),
                payload_filter=bool(_literal(values.get("payload_filter")) or False),
                filter_text=texts,
                opaque_filters=opaque,
            )
        )
    calls.sort(key=lambda c: (c.day, c.start, c.label))
    return calls


def _core(
    label: str,
    start: int,
    end: int,
    src: Any,
    dst: Any,
    src_ports: Any,
    dst_ports: Any,
    payload: bool,
) -> Signature:
    return (label, start, end, src, dst, src_ports, dst_ports, payload)


def _stated_signature(call: Stated) -> Signature:
    return _core(
        call.label,
        call.start,
        call.end,
        call.src_ips,
        call.dst_ips,
        call.src_ports,
        call.dst_ports,
        call.payload_filter,
    )


def _port_signatures(rule: Rule) -> list[tuple[Signature, bool]]:
    """Signatures a port rule covers: as written, and mirrored when `flip` is set.

    The second element says whether the signature is the rule as written (True) or only its
    reply-direction mirror (False). A rule written with swapped endpoints is its own signature.
    """

    def build(mirrored: bool) -> Signature:
        src, dst = (rule.dst_ips, rule.src_ips) if mirrored else (rule.src_ips, rule.dst_ips)
        sp, dp = (rule.dst_ports, rule.src_ports) if mirrored else (rule.src_ports, rule.dst_ports)
        return _core(
            rule.label,
            rule.start_ns,
            rule.end_ns,
            _tuple_or_none(src),
            _tuple_or_none(dst),
            _tuple_or_none(sp),
            _tuple_or_none(dp),
            rule.payload_filter,
        )

    signatures = [(build(False), True)]
    if rule.flip:
        signatures.append((build(True), False))
    return signatures


def audit(source: str) -> dict[str, Any]:
    """Compare the authors' stated rules with ours, per capture day."""
    stated = extract_calls(source)
    by_day: dict[str, list[Stated]] = defaultdict(list)
    for call in stated:
        by_day[call.day].append(call)

    days: dict[str, Any] = {}
    totals = {"stated": 0, "matched": 0, "stated_only": 0, "ours_only": 0}
    for day, files in DAY_FILES.items():
        ours: list[Rule] = []
        for name in files:
            ours += rules_for(name) or []
        ours_sigs = {sig for rule in ours for sig, _ in _port_signatures(rule)}
        written_sigs = {sig for rule in ours for sig, written in _port_signatures(rule) if written}
        calls = by_day.get(day, [])
        stated_sigs = {_stated_signature(c) for c in calls}

        stated_only = [c for c in calls if _stated_signature(c) not in ours_sigs]
        ours_only = [
            rule
            for rule in ours
            if not any(sig in stated_sigs for sig, _ in _port_signatures(rule))
        ]
        days[day] = {
            "stated_rules": len(calls),
            "matched": len(calls) - len(stated_only),
            "stated_only": [_describe_stated(c) for c in stated_only],
            "ours_only": [_describe_ours(r) for r in ours_only],
            "ours_written_signatures": len(written_sigs),
            "filters_to_read_by_hand": [
                {"label": c.label, "start": c.start, "filters": list(c.filter_text)}
                for c in calls
                if c.opaque_filters
            ],
        }
        totals["stated"] += len(calls)
        totals["matched"] += len(calls) - len(stated_only)
        totals["stated_only"] += len(stated_only)
        totals["ours_only"] += len(ours_only)
    return {
        "scope": (
            "literal parameters only (label, window, addresses, ports, payload condition); "
            "additional_filters are listed as text and are not compared"
        ),
        "attempted_suffix": ATTEMPTED_SUFFIX,
        "totals": totals,
        "days": days,
    }


def _describe_stated(call: Stated) -> dict[str, Any]:
    return {
        "label": call.label,
        "start": call.start,
        "end": call.end,
        "src_ips": call.src_ips,
        "dst_ips": call.dst_ips,
        "src_ports": call.src_ports,
        "dst_ports": call.dst_ports,
        "payload_filter": call.payload_filter,
        "opaque_filters": call.opaque_filters,
    }


def _describe_ours(rule: Rule) -> dict[str, Any]:
    return {
        "label": rule.label,
        "start": rule.start_ns,
        "end": rule.end_ns,
        "src_ips": rule.src_ips,
        "dst_ips": rule.dst_ips,
        "src_ports": rule.src_ports,
        "dst_ports": rule.dst_ports,
        "payload_filter": rule.payload_filter,
        "flip": rule.flip,
        "has_predicate": rule.where is not None,
    }


def audit_file(path: Path) -> dict[str, Any]:
    """Audit a notebook file; the report records its SHA-256 so the audited text is identifiable."""
    report = audit(read_notebook_source(path))
    report["source_sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    report["ruleset_version"] = RULESET_VERSION
    return report
