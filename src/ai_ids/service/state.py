"""In-memory service state: counters, a bounded alert buffer and latency percentiles.

Everything here is bounded and lives only in memory; nothing is written to disk. Alert context
can include IP addresses, which are personal data: see docs/data-governance.md.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from collections.abc import Callable
from typing import Any

import numpy as np

LATENCY_SAMPLES = 2000
BUCKET_SECONDS = 5
SERIES_BUCKETS = 120  # ten minutes of five-second buckets


class ServiceState:
    def __init__(self, alert_buffer: int, *, clock: Callable[[], float] = time.time) -> None:
        self._clock = clock
        self._lock = threading.Lock()
        self._alerts: deque[dict[str, Any]] = deque(maxlen=alert_buffer)
        self._latency_ms: deque[float] = deque(maxlen=LATENCY_SAMPLES)
        self._buckets: dict[int, list[int]] = {}
        self.flows_scored = 0
        self.alerts_raised = 0
        self.started_at = clock()

    def record_batch(self, n_flows: int, alerts: list[dict[str, Any]], latency_ms: float) -> None:
        index = int(self._clock() // BUCKET_SECONDS)
        with self._lock:
            self.flows_scored += n_flows
            self.alerts_raised += len(alerts)
            self._alerts.extend(alerts)
            self._latency_ms.append(latency_ms)
            bucket = self._buckets.setdefault(index, [0, 0])
            bucket[0] += n_flows
            bucket[1] += len(alerts)
            for stale in [i for i in self._buckets if i <= index - SERIES_BUCKETS]:
                del self._buckets[stale]

    def recent_alerts(self, limit: int) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._alerts)[-limit:][::-1]

    def snapshot(self) -> dict[str, Any]:
        index = int(self._clock() // BUCKET_SECONDS)
        with self._lock:
            series = []
            for i in range(index - SERIES_BUCKETS + 1, index + 1):
                flows, alerts = self._buckets.get(i, [0, 0])
                series.append({"flows": flows, "alerts": alerts})
            latency = np.asarray(self._latency_ms, dtype=float)
            return {
                "uptime_seconds": round(self._clock() - self.started_at, 1),
                "flows_scored": self.flows_scored,
                "alerts_raised": self.alerts_raised,
                "alerts_buffered": len(self._alerts),
                "bucket_seconds": BUCKET_SECONDS,
                "series": series,
                "request_latency_ms": {
                    "p50": float(np.percentile(latency, 50)) if latency.size else None,
                    "p95": float(np.percentile(latency, 95)) if latency.size else None,
                    "p99": float(np.percentile(latency, 99)) if latency.size else None,
                    "samples": int(latency.size),
                },
            }
