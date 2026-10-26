"""Wall-clock deadline enforcement for bounded analysis.

A graph is attacker-controlled input. Bounded search (``max_hops``,
``max_paths``, ``MAX_STATES_PER_NODE``) caps the *size* of the search, but not
the *time* it takes: a dense estate can still spend a long time inside a single
enumeration. This module adds the missing dimension — a monotonic wall-clock
budget the engine checks as it works, so a pathological input fails fast with a
clear, documented error instead of pinning a CPU.

The clock is injectable so the timeout path is testable deterministically
rather than by sleeping.

Copyright (c) 2026 kk (kkdev9715). All Rights Reserved. Proprietary — see LICENSE.
"""

from __future__ import annotations

import time
from collections.abc import Callable


class AnalysisTimeout(RuntimeError):
    """Raised when an analysis exceeds its configured wall-clock budget."""


class Deadline:
    """A monotonic wall-clock budget shared across one analysis run.

    Parameters
    ----------
    seconds:
        Budget in seconds. ``None`` disables enforcement entirely.
    check_every:
        Raise only after this many :meth:`tick` calls. Defaults to 1 (check on
        every unit of work); raise it if the clock call itself ever shows up in
        a profile.
    clock:
        Monotonic time source. Injectable so tests can drive the timeout
        deterministically instead of sleeping.
    """

    __slots__ = ("_budget", "_check_every", "_clock", "_start", "_counter")

    def __init__(
        self,
        seconds: float | None,
        *,
        check_every: int = 1,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if seconds is not None and seconds <= 0:
            raise ValueError("timeout must be positive, or None to disable")
        self._budget = seconds
        self._check_every = max(1, int(check_every))
        self._clock = clock
        self._start = clock()
        self._counter = 0

    @property
    def enabled(self) -> bool:
        return self._budget is not None

    @property
    def budget(self) -> float | None:
        return self._budget

    @property
    def elapsed(self) -> float:
        return self._clock() - self._start

    @property
    def remaining(self) -> float | None:
        if self._budget is None:
            return None
        return self._budget - self.elapsed

    def expired(self) -> bool:
        if self._budget is None:
            return False
        return self.elapsed > self._budget

    def tick(self) -> None:
        """Account for one unit of work; raise once the budget is exhausted."""
        if self._budget is None:
            return
        self._counter += 1
        if self._counter < self._check_every:
            return
        self._counter = 0
        if self.expired():
            raise AnalysisTimeout(
                f"analysis exceeded the {self._budget:g}s wall-clock budget; "
                "raise --timeout or reduce the estate size"
            )
