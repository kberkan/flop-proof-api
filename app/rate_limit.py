import time
from collections import defaultdict
from threading import Lock


class RateLimiter:
    def __init__(self, max_requests: int = 100, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._requests = defaultdict(list)
        self._lock = Lock()

    def check(self, key: str) -> tuple[bool, int]:
        now = time.monotonic()

        with self._lock:
            timestamps = self._requests[key]

            cutoff = now - self.window_seconds
            while timestamps and timestamps[0] <= cutoff:
                timestamps.pop(0)

            if len(timestamps) >= self.max_requests:
                retry_after = max(
                    1,
                    int(self.window_seconds - (now - timestamps[0])),
                )
                return False, retry_after

            timestamps.append(now)
            return True, 0

    def reset(self):
        with self._lock:
            self._requests.clear()
