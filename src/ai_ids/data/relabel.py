"""Corrected CICIDS2017 labels, re-derived from published attack timelines.

The labels shipped with CICIDS2017 contain errors (Engelen, Rimmer and Joosen, "Troubleshooting an
Intrusion Detection Dataset: the CICIDS2017 Case Study", IEEE SPW 2021; Liu, Engelen, Lynar, Essam
and Joosen, "Error Prevalence in NIDS datasets", IEEE CNS 2022). Their published labelling
script defines each attack by a time window, attacker and victim addresses, ports, and a few
packet-level conditions. This module re-implements those *rules* (facts about the capture: windows,
addresses, ports) as data, so they can be applied to the flows we already have. The code is our own
and is not a copy of theirs. `ai_ids.data.rulecheck` audits the table below against the authors'
script (ADR 0013); version 1 of the table was written before that script could be read and the
audit found and fixed several deviations (see RULESET_VERSION).

What this is and is not:
- It re-labels the original CICFlowMeter flows. The authors also fixed the flow extractor, which
  changes the flows themselves; that part is not reproduced, so this is the labelling correction
  only (the authors ran the same kind of experiment to isolate the effect of labelling errors).
- Rules apply in order and a later rule overrides an earlier one; anything no rule claims is
  benign.
- Flows that belong to an attack's timeline but carry no attack payload (they call them "attempted")
  are labelled as such and dropped by the loader, because they are neither clean benign traffic nor
  an attack to be detected. The number dropped is reported.
- The attack windows are UTC. CICIDS2017 timestamps are local time, UTC-3, so windows are shifted.
- The rules are audited against the authors' script, not against their corrected CSVs, which come
  from their own repaired flow extractor and cannot be matched flow by flow to the original files.
  Deliberate adaptations: reply-direction (mirrored) rules for flows the original extractor split,
  and window starts rounded down to the minute because original timestamps have minute resolution.
  Packet-count conditions come from the authors' extractor and may not mean the same on the
  original flows.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

import numpy as np
import pandas as pd
from numpy.typing import NDArray

from ai_ids.labels import normalize_label

BoolArray = NDArray[np.bool_]
Columns = Mapping[str, NDArray[Any]]
Predicate = Callable[[Columns], BoolArray]

# Bump when a rule changes, so every report says which rules produced its labels.
#   1: first port, written before the authors' script could be read.
#   2: audited against the authors' CNS 2022 labelling script (docs/adr/0013): removed two
#      attempted-flow rules for FTP-Patator, added source port 50133 and the exact window to
#      the first infiltration scan, merged the Friday port-scan round 2 rules, and used the
#      script's 5/5 packet counts for the brute-force artefact flows.
RULESET_VERSION = 2

UTC_OFFSET = pd.Timedelta(hours=3)  # capture clocks were UTC-3 (New Brunswick, summer)
ATTEMPTED_SUFFIX = " - Attempted"
BENIGN_LABEL = "BENIGN"
_UNLABELLED = "NeedManualLabel"
_ARTEFACT_FLOW_ID = "8.0.6.4-8.6.0.1-0-0-0"

ATTACKER = "172.16.0.1"
WEB_SERVER = "192.168.10.50"
HEARTBLEED_VICTIM = "192.168.10.51"
COMMAND_SERVER = "205.174.165.73"
BOTS = ("192.168.10.15", "192.168.10.9", "192.168.10.14", "192.168.10.5", "192.168.10.8")
INTERNAL_SCAN_TARGETS = (
    "192.168.10.5",
    "192.168.10.9",
    "192.168.10.12",
    "192.168.10.14",
    "192.168.10.15",
    "192.168.10.16",
    "192.168.10.17",
    "192.168.10.19",
    "192.168.10.25",
    "192.168.10.50",
    "192.168.10.51",
)


@dataclass(frozen=True)
class Rule:
    """One labelling rule. `flip` also applies the mirrored (reply-direction) rule."""

    label: str
    start_ns: int
    end_ns: int
    src_ips: tuple[str, ...] | None = None
    dst_ips: tuple[str, ...] | None = None
    src_ports: tuple[int, ...] | None = None
    dst_ports: tuple[int, ...] | None = None
    payload_filter: bool = False
    flip: bool = False
    where: Predicate | None = None

    def __post_init__(self) -> None:
        if self.flip and self.where is not None:
            raise ValueError("a rule cannot be both flipped and carry an extra predicate")


def _ips(*addresses: str) -> tuple[str, ...]:
    return tuple(addresses)


def _window(rule: Rule) -> tuple[pd.Timestamp, pd.Timestamp]:
    # The start is rounded down to the minute because flow timestamps have minute resolution.
    start = pd.Timestamp(rule.start_ns, unit="ns").floor("min") - UTC_OFFSET
    end = pd.Timestamp(rule.end_ns, unit="ns") - UTC_OFFSET
    return start, end


def _member(
    cols: Columns,
    cache: dict[tuple[str, tuple[object, ...]], BoolArray],
    column: str,
    values: tuple[object, ...],
) -> BoolArray:
    key = (column, values)
    if key not in cache:
        cache[key] = np.asarray(pd.Series(cols[column]).isin(values).to_numpy(), dtype=bool)
    return cache[key]


def _rule_mask(
    rule: Rule,
    cols: Columns,
    cache: dict[tuple[str, tuple[object, ...]], BoolArray],
    *,
    mirrored: bool,
) -> BoolArray:
    stamps = cols["timestamp"]
    start, end = _window(rule)
    mask: BoolArray = (stamps >= np.datetime64(start)) & (stamps <= np.datetime64(end))
    src_ip, dst_ip = (
        ("destination_ip", "source_ip") if mirrored else ("source_ip", "destination_ip")
    )
    src_port, dst_port = (
        ("destination_port", "source_port") if mirrored else ("source_port", "destination_port")
    )
    if rule.src_ips is not None:
        mask &= _member(cols, cache, src_ip, rule.src_ips)
    if rule.dst_ips is not None:
        mask &= _member(cols, cache, dst_ip, rule.dst_ips)
    if rule.src_ports is not None:
        mask &= _member(cols, cache, src_port, rule.src_ports)
    if rule.dst_ports is not None:
        mask &= _member(cols, cache, dst_port, rule.dst_ports)
    if rule.payload_filter:
        payload = "total_length_of_bwd_packets" if mirrored else "total_length_of_fwd_packets"
        mask &= cols[payload] == 0
    if rule.where is not None:
        mask &= rule.where(cols)
    return mask


# ---------------------------------------------------------------------------------------------
# Rule tables, one per capture file. Epoch values are nanoseconds, UTC.
# ---------------------------------------------------------------------------------------------
def _tuesday() -> list[Rule]:
    ftp = (1499170672838272000, 1499174416931403000)
    ssh = (1499188141049616000, 1499195059018486000)
    att = _ips(ATTACKER)
    web = _ips(WEB_SERVER)
    return [
        Rule("FTP-Patator", *ftp, att, web, dst_ports=(21,), flip=True),
        Rule(
            "FTP-Patator" + ATTEMPTED_SUFFIX,
            *ftp,
            att,
            web,
            dst_ports=(21,),
            payload_filter=True,
            flip=True,
        ),
        Rule("FTP-Patator" + ATTEMPTED_SUFFIX, *ftp, att, web, src_ports=(52108,), dst_ports=(21,)),
        Rule("SSH-Patator", *ssh, att, web, dst_ports=(22,), flip=True),
        Rule(
            "SSH-Patator" + ATTEMPTED_SUFFIX,
            *ssh,
            att,
            web,
            dst_ports=(22,),
            payload_filter=True,
            flip=True,
        ),
        Rule(
            "SSH-Patator" + ATTEMPTED_SUFFIX,
            *ssh,
            att,
            web,
            dst_ports=(22,),
            where=lambda c: (
                (c["total_length_of_fwd_packets"] <= 32) & (c["total_length_of_bwd_packets"] == 0)
            ),
        ),
    ]


def _wednesday() -> list[Rule]:
    att, web = _ips(ATTACKER), _ips(WEB_SERVER)
    rules: list[Rule] = []

    def not_in(column: str, values: tuple[int, ...]) -> Predicate:
        return lambda c: ~np.isin(c[column], values)

    # Slowloris
    sl = (1499258934539220000, 1499260278500956000)
    sl_odd = (33358, 33360, 33362, 54114)
    rules += [
        Rule(
            "DoS Slowloris" + ATTEMPTED_SUFFIX,
            1499258926211817000,
            1499258927000000000,
            att,
            web,
            dst_ports=(80,),
        ),
        Rule("DoS Slowloris", *sl, att, web, dst_ports=(80,), where=not_in("source_port", sl_odd)),
        Rule(
            "DoS Slowloris",
            *sl,
            web,
            att,
            src_ports=(80,),
            where=not_in("destination_port", sl_odd),
        ),
        Rule(
            "DoS Slowloris" + ATTEMPTED_SUFFIX,
            *sl,
            att,
            web,
            src_ports=(33358, 33360, 33362),
            dst_ports=(80,),
        ),
        Rule(
            "DoS Slowloris" + ATTEMPTED_SUFFIX,
            *sl,
            att,
            web,
            dst_ports=(80,),
            payload_filter=True,
            where=not_in("source_port", (33358, 33360, 33362, 54114)),
        ),
        Rule(
            "DoS Slowloris" + ATTEMPTED_SUFFIX,
            *sl,
            web,
            att,
            src_ports=(80,),
            where=lambda c: (
                ~np.isin(c["destination_port"], sl_odd) & (c["total_length_of_bwd_packets"] == 0)
            ),
        ),
        Rule(
            "DoS Slowloris" + ATTEMPTED_SUFFIX,
            *sl,
            web,
            att,
            src_ports=(80,),
            where=lambda c: (
                ~np.isin(c["destination_port"], sl_odd)
                & (c["total_length_of_bwd_packets"] == 0)
                & (c["flow_duration"] >= 199800)
            ),
        ),
        Rule(
            "DoS Slowloris" + ATTEMPTED_SUFFIX, *sl, att, web, src_ports=(54114,), dst_ports=(80,)
        ),
    ]
    # Slowhttptest
    sh = (1499260537936810000, 1499261869331517000)
    rules += [
        Rule(
            "DoS Slowhttptest",
            *sh,
            att,
            web,
            dst_ports=(80,),
            where=not_in("source_port", (33372,)),
        ),
        Rule(
            "DoS Slowhttptest",
            *sh,
            web,
            att,
            src_ports=(80,),
            where=not_in("destination_port", (33372,)),
        ),
        Rule(
            "DoS Slowhttptest" + ATTEMPTED_SUFFIX,
            *sh,
            att,
            web,
            src_ports=(33372,),
            dst_ports=(80,),
        ),
        Rule(
            "DoS Slowhttptest" + ATTEMPTED_SUFFIX,
            *sh,
            att,
            web,
            dst_ports=(80,),
            payload_filter=True,
            where=not_in("source_port", (33372, 37670)),
        ),
        Rule(
            "DoS Slowhttptest" + ATTEMPTED_SUFFIX,
            *sh,
            web,
            att,
            src_ports=(80,),
            where=lambda c: (
                ~np.isin(c["destination_port"], (33372, 37670))
                & (c["total_length_of_bwd_packets"] == 0)
            ),
        ),
        Rule(
            "DoS Slowhttptest" + ATTEMPTED_SUFFIX,
            *sh,
            att,
            web,
            dst_ports=(80,),
            where=lambda c: (
                ~np.isin(c["source_port"], (33372,))
                & (c["total_length_of_fwd_packets"] == 0)
                & (c["flow_duration"] >= 199984)
                & (c["total_backward_packets"] == 0)
            ),
        ),
        Rule(
            "DoS Slowhttptest" + ATTEMPTED_SUFFIX,
            *sh,
            att,
            web,
            src_ports=(37670,),
            dst_ports=(80,),
        ),
    ]
    # Hulk
    hulk_a, hulk_b, hulk_all = (
        (1499262203194704000, 1499262299999999999),
        (1499262300000000000, 1499263641326171000),
        (1499262203194704000, 1499263641326171000),
    )
    odd = (48678, 43664)
    rules += [
        Rule("DoS Hulk", *hulk_a, att, web, dst_ports=(80,), where=not_in("source_port", odd)),
        Rule("DoS Hulk", *hulk_a, web, att, src_ports=(80,), where=not_in("destination_port", odd)),
        Rule("DoS Hulk", *hulk_b, att, web, dst_ports=(80,), flip=True),
        Rule("DoS Hulk" + ATTEMPTED_SUFFIX, *hulk_a, att, web, src_ports=odd, dst_ports=(80,)),
        Rule(
            "DoS Hulk" + ATTEMPTED_SUFFIX,
            *hulk_all,
            att,
            web,
            dst_ports=(80,),
            payload_filter=True,
            where=not_in("source_port", odd),
        ),
        Rule(
            "DoS Hulk" + ATTEMPTED_SUFFIX,
            *hulk_all,
            web,
            att,
            src_ports=(80,),
            where=lambda c: (
                ~np.isin(c["destination_port"], odd) & (c["total_length_of_bwd_packets"] == 0)
            ),
        ),
        Rule(
            "DoS Hulk" + ATTEMPTED_SUFFIX,
            *hulk_all,
            att,
            web,
            dst_ports=(80,),
            where=lambda c: (
                ~np.isin(c["source_port"], odd)
                & (c["total_length_of_fwd_packets"] > 0)
                & (c["total_length_of_fwd_packets"] < 282)
            ),
        ),
        Rule(
            "DoS Hulk" + ATTEMPTED_SUFFIX,
            *hulk_all,
            web,
            att,
            src_ports=(80,),
            where=lambda c: (
                ~np.isin(c["destination_port"], odd)
                & (c["total_length_of_bwd_packets"] > 0)
                & (c["total_length_of_bwd_packets"] < 282)
            ),
        ),
    ]
    # GoldenEye and Heartbleed
    ge = (1499263803231753000, 1499264408915718000)
    hb = (1499278335650811000, 1499279563294455000)
    victim = _ips(HEARTBLEED_VICTIM)
    rules += [
        Rule("DoS GoldenEye", *ge, att, web, dst_ports=(80,), flip=True),
        Rule(
            "DoS GoldenEye" + ATTEMPTED_SUFFIX,
            *ge,
            att,
            web,
            dst_ports=(80,),
            payload_filter=True,
            flip=True,
        ),
        Rule("Heartbleed", *hb, att, victim, src_ports=(45022,), dst_ports=(444,), flip=True),
        Rule(
            "Heartbleed" + ATTEMPTED_SUFFIX,
            *hb,
            att,
            victim,
            src_ports=(45022,),
            dst_ports=(444,),
            payload_filter=True,
            flip=True,
        ),
    ]
    return rules


def _thursday_web() -> list[Rule]:
    att, web = _ips(ATTACKER), _ips(WEB_SERVER)
    bf_pre = (1499343354880049000, 1499343531179279000)
    bf = (1499343567660566000, 1499346011622209000)
    xss = (1499346935283859000, 1499348121341704000)
    sql_pre = (1499348127852814000, 1499348145720612000)
    sql = (1499348145732950000, 1499348575320284000)
    xss_ports = (36180, 36182, 36184, 36186, 36188, 36190)
    sql_ports = (36180, 36182, 36184, 36186, 36188)

    def bf_real_fwd(c: Columns) -> BoolArray:
        return np.asarray((c["total_fwd_packets"] > 20) | (c["source_port"] == 44464), dtype=bool)

    def bf_real_bwd(c: Columns) -> BoolArray:
        return np.asarray(
            (c["total_backward_packets"] > 20) | (c["destination_port"] == 44464), dtype=bool
        )

    bf_label = "Web Attack - Brute Force"
    xss_label = "Web Attack - XSS"
    sql_label = "Web Attack - SQL Injection"
    return [
        Rule(bf_label + ATTEMPTED_SUFFIX, *bf_pre, att, web, dst_ports=(80,), flip=True),
        Rule(bf_label, *bf, att, web, dst_ports=(80,), where=bf_real_fwd),
        Rule(bf_label, *bf, web, att, src_ports=(80,), where=bf_real_bwd),
        Rule(
            bf_label + ATTEMPTED_SUFFIX,
            *bf,
            att,
            web,
            dst_ports=(80,),
            payload_filter=True,
            where=lambda c: ~bf_real_fwd(c),
        ),
        Rule(
            bf_label + ATTEMPTED_SUFFIX,
            *bf,
            web,
            att,
            src_ports=(80,),
            where=lambda c: ~bf_real_bwd(c) & (c["total_length_of_bwd_packets"] == 0),
        ),
        Rule(
            bf_label + ATTEMPTED_SUFFIX,
            *bf,
            att,
            web,
            dst_ports=(80,),
            where=lambda c: (
                (c["total_length_of_fwd_packets"] > 0)
                & (c["source_port"] != 44464)
                & (c["total_fwd_packets"] == 5)
                & (c["total_backward_packets"] == 5)
            ),
        ),
        Rule(
            bf_label + ATTEMPTED_SUFFIX,
            *bf,
            web,
            att,
            src_ports=(80,),
            where=lambda c: (
                (c["total_length_of_bwd_packets"] > 0)
                & (c["destination_port"] != 44464)
                & (c["total_backward_packets"] == 5)
                & (c["total_fwd_packets"] == 5)
            ),
        ),
        Rule(
            xss_label,
            *xss,
            att,
            web,
            dst_ports=(80,),
            where=lambda c: ~np.isin(c["source_port"], xss_ports) & (c["total_fwd_packets"] >= 150),
        ),
        Rule(
            xss_label,
            *xss,
            web,
            att,
            src_ports=(80,),
            where=lambda c: (
                ~np.isin(c["destination_port"], xss_ports) & (c["total_backward_packets"] >= 150)
            ),
        ),
        Rule(
            xss_label + ATTEMPTED_SUFFIX,
            *xss,
            att,
            web,
            dst_ports=(80,),
            payload_filter=True,
            where=lambda c: ~np.isin(c["source_port"], xss_ports),
        ),
        Rule(
            xss_label + ATTEMPTED_SUFFIX,
            *xss,
            att,
            web,
            src_ports=(80,),
            where=lambda c: (
                ~np.isin(c["destination_port"], xss_ports) & (c["total_length_of_bwd_packets"] == 0)
            ),
        ),
        Rule(
            xss_label + ATTEMPTED_SUFFIX,
            *xss,
            att,
            web,
            dst_ports=(80,),
            where=lambda c: (
                ~np.isin(c["source_port"], xss_ports)
                & (c["total_length_of_fwd_packets"] > 0)
                & (c["total_fwd_packets"] < 150)
            ),
        ),
        Rule(
            xss_label + ATTEMPTED_SUFFIX,
            *xss,
            web,
            att,
            src_ports=(80,),
            where=lambda c: (
                ~np.isin(c["destination_port"], xss_ports)
                & (c["total_length_of_bwd_packets"] > 0)
                & (c["total_backward_packets"] < 150)
            ),
        ),
        Rule(
            sql_label + ATTEMPTED_SUFFIX,
            *sql_pre,
            att,
            web,
            src_ports=sql_ports,
            dst_ports=(80,),
            flip=True,
        ),
        Rule(
            sql_label,
            *sql,
            att,
            web,
            dst_ports=(80,),
            where=lambda c: ~np.isin(c["source_port"], sql_ports),
        ),
        Rule(
            sql_label,
            *sql,
            web,
            att,
            src_ports=(80,),
            where=lambda c: ~np.isin(c["destination_port"], sql_ports),
        ),
        Rule(
            sql_label + ATTEMPTED_SUFFIX,
            *sql_pre,
            att,
            web,
            dst_ports=(80,),
            payload_filter=True,
            flip=True,
        ),
    ]


def _thursday_infiltration() -> list[Rule]:
    c2 = _ips(COMMAND_SERVER)
    dropbox = (1499361542547210000, 1499366769364731000)
    cooldisk = (1499363616453990000, 1499371339347892000)
    return [
        Rule("Infiltration", *dropbox, _ips("192.168.10.8"), c2, flip=True),
        Rule(
            "Infiltration" + ATTEMPTED_SUFFIX,
            *dropbox,
            _ips("192.168.10.8"),
            c2,
            payload_filter=True,
            flip=True,
        ),
        Rule(
            "Infiltration" + ATTEMPTED_SUFFIX,
            1499361228830533000,
            1499361301251276000,
            _ips("192.168.10.9"),
            c2,
            flip=True,
        ),
        Rule("Infiltration", *cooldisk, _ips("192.168.10.25"), c2, flip=True),
        Rule(
            "Infiltration" + ATTEMPTED_SUFFIX,
            *cooldisk,
            _ips("192.168.10.25"),
            c2,
            payload_filter=True,
            flip=True,
        ),
        # The compromised hosts then scan the internal network.
        Rule(
            "Infiltration - Portscan",
            1499360431706755000,
            1499360445728887000,
            _ips(ATTACKER),
            _ips(HEARTBLEED_VICTIM),
            src_ports=(50122, 50133),
        ),
        Rule(
            "Infiltration - Portscan",
            1499362410884008000,
            1499362444285175000,
            _ips("192.168.10.8"),
            _ips("192.168.10.5"),
        ),
        Rule(
            "Infiltration - Portscan",
            1499364314425162000,
            1499366764331875000,
            _ips("192.168.10.8"),
            INTERNAL_SCAN_TARGETS,
            where=lambda c: (
                ~((c["fwd_packet_length_max"] == 408) & (c["destination_ip"] == WEB_SERVER))
                & ~(
                    np.isin(c["total_length_of_fwd_packets"], (176, 20514))
                    & (c["destination_ip"] == WEB_SERVER)
                )
            ),
        ),
    ]


def _bot_rules() -> list[Rule]:
    c2 = _ips(COMMAND_SERVER)
    return [
        Rule("Bot", 1499432653990571000, 1499436122903736000, BOTS, c2, flip=True),
        Rule(
            "Bot" + ATTEMPTED_SUFFIX,
            1499432653990571000,
            1499436122903736000,
            BOTS,
            c2,
            payload_filter=True,
            flip=True,
        ),
        Rule(
            "Bot" + ATTEMPTED_SUFFIX, 1499436180000000000, 1499457684606663000, BOTS, c2, flip=True
        ),
    ]


def _friday_portscan() -> list[Rule]:
    att, web = _ips(ATTACKER), _ips(WEB_SERVER)
    return [
        Rule("Portscan", 1499446532117090000, 1499447948582083000, att, web, flip=True),
        Rule("Portscan", 1499449905450532000, 1499451841699238000, att, web),
        *_bot_rules(),
    ]


def _friday_ddos() -> list[Rule]:
    att, web = _ips(ATTACKER), _ips(WEB_SERVER)
    span = (1499453791796937000, 1499454972216560000)
    return [
        Rule("DDoS", *span, att, web, flip=True),
        Rule("DDoS" + ATTEMPTED_SUFFIX, *span, att, web, payload_filter=True, flip=True),
        Rule(
            "DDoS" + ATTEMPTED_SUFFIX,
            *span,
            web,
            att,
            where=lambda c: c["total_length_of_bwd_packets"] == 0,
        ),
        *_bot_rules(),
    ]


def rules_for(filename: str) -> list[Rule] | None:
    """Rules for a CICIDS2017 capture file, or None if the file is not a known one."""
    tables: dict[str, Callable[[], list[Rule]]] = {
        "monday-workinghours.pcap_iscx.csv": list,
        "tuesday-workinghours.pcap_iscx.csv": _tuesday,
        "wednesday-workinghours.pcap_iscx.csv": _wednesday,
        "thursday-workinghours-morning-webattacks.pcap_iscx.csv": _thursday_web,
        "thursday-workinghours-afternoon-infilteration.pcap_iscx.csv": _thursday_infiltration,
        "friday-workinghours-morning.pcap_iscx.csv": _bot_rules,
        "friday-workinghours-afternoon-portscan.pcap_iscx.csv": _friday_portscan,
        "friday-workinghours-afternoon-ddos.pcap_iscx.csv": _friday_ddos,
    }
    builder = tables.get(filename.lower())
    return None if builder is None else builder()


def _numeric(frame: pd.DataFrame, name: str) -> NDArray[np.float64]:
    return pd.to_numeric(frame[name], errors="coerce").to_numpy(dtype=float)


def relabel_frame(
    frame: pd.DataFrame, rules: list[Rule], timestamps: pd.Series, label_column: str = "label"
) -> tuple[pd.Series, pd.Series]:
    """Apply `rules` in order. Returns (new labels, whether each flow is an attempted flow)."""
    needed_numeric = (
        "source_port",
        "destination_port",
        "total_length_of_fwd_packets",
        "total_length_of_bwd_packets",
        "total_fwd_packets",
        "total_backward_packets",
        "flow_duration",
    )
    cols: dict[str, NDArray[Any]] = {
        "timestamp": timestamps.to_numpy(dtype="datetime64[ns]"),
        "source_ip": frame["source_ip"].astype(str).str.strip().to_numpy(),
        "destination_ip": frame["destination_ip"].astype(str).str.strip().to_numpy(),
    }
    for name in needed_numeric:
        cols[name] = _numeric(frame, name)
    cols["fwd_packet_length_max"] = (
        _numeric(frame, "fwd_packet_length_max")
        if "fwd_packet_length_max" in frame
        else np.full(len(frame), np.nan)
    )
    labels = np.full(len(frame), _UNLABELLED, dtype=object)
    cache: dict[tuple[str, tuple[object, ...]], BoolArray] = {}
    for rule in rules:
        for mirrored in (False, True) if rule.flip else (False,):
            labels[_rule_mask(rule, cols, cache, mirrored=mirrored)] = rule.label
    labels[labels == _UNLABELLED] = BENIGN_LABEL
    artefact = frame["flow_id"].astype(str).str.strip().to_numpy() == _ARTEFACT_FLOW_ID
    labels[artefact] = BENIGN_LABEL
    attempted = np.array([str(x).endswith(ATTEMPTED_SUFFIX) for x in labels], dtype=bool)
    # Rows without an original label are blank export lines; leave them for the loader to drop.
    blank = frame[label_column].isna().to_numpy()
    labels[blank] = None
    attempted[blank] = False
    return pd.Series(labels, index=frame.index), pd.Series(attempted, index=frame.index)


def label_changes(original: pd.Series, corrected: pd.Series) -> dict[str, dict[str, int]]:
    """Original label -> corrected label -> number of flows, for the report."""
    table = pd.crosstab(original.astype(str).str.strip(), corrected.astype(str))
    return {
        str(old): {str(new): int(n) for new, n in row.items() if n} for old, row in table.iterrows()
    }


def summarise_changes(changes: dict[str, dict[str, int]]) -> dict[str, int]:
    """Collapse an old-to-new label table into how many flows changed attack status."""
    benign = normalize_label(BENIGN_LABEL)
    out = {
        "unchanged": 0,
        "benign_to_attack": 0,
        "attack_to_benign": 0,
        "attack_to_other_attack": 0,
        "dropped_as_attempted": 0,
    }
    for old, row in changes.items():
        for new, count in row.items():
            if new.endswith(ATTEMPTED_SUFFIX):
                out["dropped_as_attempted"] += count
                continue
            old_key, new_key = normalize_label(old), normalize_label(new)
            if old_key == new_key:
                out["unchanged"] += count
            elif old_key == benign:
                out["benign_to_attack"] += count
            elif new_key == benign:
                out["attack_to_benign"] += count
            else:
                out["attack_to_other_attack"] += count
    return out
