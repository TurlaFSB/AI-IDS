"""Thread-safe token-bucket rate limiter, keyed by client address."""

from __future__ import annotations

import threading
import time
from collections.abc import Callable


class TokenBucketLimiter:
    """Allow `per_minute` requests per key on average, with bursts up to `burst`."""

    def __init__(
        self,
        per_minute: int,
        burst: int | None = None,
        *,
        clock: Callable[[], float] = time.monotonic,
        max_keys: int = 10_000,
    ) -> None:
        if per_minute < 1:
            raise ValueError("per_minute must be positive")
        self._rate = per_minute / 60.0
        self._capacity = float(burst if burst is not None else per_minute)
        self._clock = clock
        self._max_keys = max_keys
        self._buckets: dict[str, tuple[float, float]] = {}
        self._lock = threading.Lock()

    def allow(self, key: str) -> tuple[bool, float]:
        """Return (allowed, seconds until a token is available)."""
        now = self._clock()
        with self._lock:
            tokens, updated = self._buckets.get(key, (self._capacity, now))
            tokens = min(self._capacity, tokens + (now - updated) * self._rate)
            if tokens >= 1.0:
                self._buckets[key] = (tokens - 1.0, now)
                self._prune()
                return True, 0.0
            self._buckets[key] = (tokens, now)
            return False, (1.0 - tokens) / self._rate

    def _prune(self) -> None:
        if len(self._buckets) <= self._max_keys:
            return
        oldest = sorted(self._buckets, key=lambda k: self._buckets[k][1])
        for key in oldest[: len(oldest) // 10 + 1]:
            del self._buckets[key]
