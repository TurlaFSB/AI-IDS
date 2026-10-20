"""Replay recorded flows into a running service at (scaled) original timing.

The replay client holds the ground-truth labels; the service never sees them. Used for demos and
for end-to-end checks of the scoring path.
"""

from __future__ import annotations

import json
import math
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Sequence
from dataclasses import asdict, dataclass
from typing import Any

import numpy as np
import pandas as pd

from ai_ids.data.loader import IS_ATTACK, TIMESTAMP
from ai_ids.service.settings import DEFAULT_CONTEXT_FIELDS

MAX_RETRIES = 5


class ReplayRateLimitedError(Exception):
    def __init__(self, retry_after: float) -> None:
        super().__init__(f"rate limited; retry after {retry_after}s")
        self.retry_after = retry_after


PostFn = Callable[[str, dict[str, str], bytes], dict[str, Any]]


def http_post(
    url: str, headers: dict[str, str], body: bytes, timeout: float = 30.0
) -> dict[str, Any]:
    if not url.startswith(("http://", "https://")):
        raise ValueError("url must start with http:// or https://")
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")  # noqa: S310
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
            parsed = json.loads(response.read())
    except urllib.error.HTTPError as error:
        if error.code == 429:
            raise ReplayRateLimitedError(float(error.headers.get("Retry-After", "1"))) from None
        raise
    if not isinstance(parsed, dict):
        raise ValueError("unexpected response from the service")
    return parsed


@dataclass
class ReplaySummary:
    flows_sent: int = 0
    batches: int = 0
    alerts: int = 0
    attacks_sent: int = 0
    benign_sent: int = 0
    true_positives: int = 0
    false_positives: int = 0

    @property
    def recall(self) -> float | None:
        return self.true_positives / self.attacks_sent if self.attacks_sent else None

    @property
    def false_positive_rate(self) -> float | None:
        return self.false_positives / self.benign_sent if self.benign_sent else None

    def to_dict(self) -> dict[str, Any]:
        return {
            **asdict(self),
            "recall": self.recall,
            "false_positive_rate": self.false_positive_rate,
        }


def _json_value(value: object) -> object:
    if value is None or (isinstance(value, float) and math.isnan(value)):
        return None
    if isinstance(value, pd.Timestamp):
        return value.isoformat()
    if hasattr(value, "item"):  # numpy scalar
        return _json_value(value.item())
    return value


def build_payload(
    rows: pd.DataFrame, features: Sequence[str], context_fields: Sequence[str]
) -> dict[str, Any]:
    columns = [*features, *[c for c in context_fields if c in rows.columns]]
    flows = [
        {name: _json_value(record[name]) for name in columns}
        for record in rows[columns].to_dict(orient="records")
    ]
    return {"flows": flows}


def replay_flows(
    frame: pd.DataFrame,
    features: Sequence[str],
    *,
    base_url: str,
    api_key: str,
    speed: float = 120.0,
    rate: float | None = None,
    batch_size: int = 50,
    max_wait: float = 2.0,
    context_fields: Sequence[str] = DEFAULT_CONTEXT_FIELDS,
    sleep: Callable[[float], None] = time.sleep,
    post: PostFn = http_post,
    on_batch: Callable[[ReplaySummary], None] | None = None,
) -> ReplaySummary:
    """Send `frame` in time order.

    By default the pause between batches follows the capture timing divided by `speed`. With
    `rate` set, flows are instead paced evenly at that many flows per second, which gives a steady
    stream for demos and simple load tests.
    """
    if speed <= 0 or batch_size < 1 or (rate is not None and rate <= 0):
        raise ValueError("speed, rate and batch_size must be positive")
    ordered = frame.sort_values(TIMESTAMP, kind="stable") if TIMESTAMP in frame else frame
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    url = base_url.rstrip("/") + "/v1/score"
    summary = ReplaySummary()
    previous_end: pd.Timestamp | None = None

    for start in range(0, len(ordered), batch_size):
        chunk = ordered.iloc[start : start + batch_size]
        if rate is not None:
            if start > 0:
                sleep(len(chunk) / rate)
        elif TIMESTAMP in chunk and previous_end is not None and chunk[TIMESTAMP].notna().any():
            gap = (chunk[TIMESTAMP].min() - previous_end).total_seconds() / speed
            sleep(min(max(gap, 0.0), max_wait))
        body = json.dumps(build_payload(chunk, features, context_fields)).encode()
        for attempt in range(MAX_RETRIES):
            try:
                response = post(url, headers, body)
                break
            except ReplayRateLimitedError as limited:
                if attempt == MAX_RETRIES - 1:
                    raise
                sleep(limited.retry_after)
        flagged = np.array([bool(result["alert"]) for result in response["results"]], dtype=bool)
        summary.flows_sent += len(chunk)
        summary.batches += 1
        summary.alerts += int(flagged.sum())
        if IS_ATTACK in chunk:
            truth = chunk[IS_ATTACK].to_numpy(dtype=bool)
            summary.attacks_sent += int(truth.sum())
            summary.benign_sent += int((~truth).sum())
            summary.true_positives += int((flagged & truth).sum())
            summary.false_positives += int((flagged & ~truth).sum())
        if TIMESTAMP in chunk and chunk[TIMESTAMP].notna().any():
            previous_end = chunk[TIMESTAMP].max()
        if on_batch is not None:
            on_batch(summary)
    return summary
