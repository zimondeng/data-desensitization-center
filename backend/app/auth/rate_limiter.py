from __future__ import annotations

import threading
import time
from collections import deque
from collections.abc import Callable


class SlidingWindowRateLimiter:
    """Thread-safe per-key sliding-window RPM rate limiter."""

    def __init__(
        self,
        window_seconds: float = 60.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._window_seconds = float(window_seconds)
        self._clock = clock
        self._lock = threading.Lock()
        self._buckets: dict[int | str, deque[float]] = {}

    def allow(self, key_id: int | str, rate_limit_rpm: int) -> bool:
        if rate_limit_rpm <= 0:
            return False
        now = self._clock()
        cutoff = now - self._window_seconds
        with self._lock:
            dq = self._buckets.get(key_id)
            if dq is None:
                dq = deque()
                self._buckets[key_id] = dq
            while dq and dq[0] <= cutoff:
                dq.popleft()
            if len(dq) >= rate_limit_rpm:
                return False
            dq.append(now)
            return True

    def reset(self) -> None:
        with self._lock:
            self._buckets.clear()
