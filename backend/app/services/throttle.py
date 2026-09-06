"""Failed-login throttling.

Deliberately simple and deliberately documented as limited: state lives in this
process's memory, so it is per-worker and resets on restart. That is acceptable
for a single-container development deployment and is NOT sufficient for a real
one, where this belongs in Redis so every worker shares a view.

It is included because an authentication endpoint with no rate limit is a
finding in any review, and an honest partial control with its limitation stated
is better than none.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field


@dataclass
class _Bucket:
    failures: list[float] = field(default_factory=list)
    locked_until: float = 0.0


class LoginThrottle:
    def __init__(
        self,
        *,
        max_failures: int = 5,
        window_seconds: int = 300,
        lockout_seconds: int = 300,
    ) -> None:
        self.max_failures = max_failures
        self.window_seconds = window_seconds
        self.lockout_seconds = lockout_seconds
        self._buckets: dict[str, _Bucket] = defaultdict(_Bucket)
        self._lock = threading.Lock()

    def _prune(self, bucket: _Bucket, now: float) -> None:
        cutoff = now - self.window_seconds
        bucket.failures = [t for t in bucket.failures if t > cutoff]

    def is_locked(self, key: str) -> tuple[bool, int]:
        """Return (locked, seconds_remaining)."""
        now = time.monotonic()
        with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                return False, 0
            if bucket.locked_until > now:
                return True, int(bucket.locked_until - now) + 1
            return False, 0

    def record_failure(self, key: str) -> None:
        now = time.monotonic()
        with self._lock:
            bucket = self._buckets[key]
            self._prune(bucket, now)
            bucket.failures.append(now)
            if len(bucket.failures) >= self.max_failures:
                bucket.locked_until = now + self.lockout_seconds
                bucket.failures.clear()

    def record_success(self, key: str) -> None:
        with self._lock:
            self._buckets.pop(key, None)

    def reset(self) -> None:
        with self._lock:
            self._buckets.clear()


login_throttle = LoginThrottle()
