"""Thread-safe hard analysis budget adapted from Trident's LLMBudget."""

from __future__ import annotations

import threading
from dataclasses import dataclass, field


@dataclass
class LLMBudget:
    """Reserve calls before they run, making the ceiling real across workers."""

    limit: int | None = None
    used: int = 0
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False, compare=False)

    def take(self, n: int = 1) -> bool:
        if not isinstance(n, int) or isinstance(n, bool) or n < 1:
            raise ValueError("budget reservations must be positive integers")
        with self._lock:
            if self.limit is not None and self.used + n > self.limit:
                return False
            self.used += n
            return True

    def charge(self, n: int = 1) -> None:
        if not isinstance(n, int) or isinstance(n, bool) or n < 1:
            raise ValueError("budget charges must be positive integers")
        with self._lock:
            self.used += n

    @property
    def exhausted(self) -> bool:
        with self._lock:
            return self.limit is not None and self.used >= self.limit


AnalysisBudget = LLMBudget
