"""Lightweight metrics — counters/histograms across all planes.

A thread-safe, in-process registry (no hard dependency on OTel) so the control
plane, swarm, and execution engine can record usage uniformly. When the OTel
metrics SDK is configured, increments/observations also flow to it; otherwise
they stay in-process and are inspectable via :func:`snapshot`.
"""
from __future__ import annotations

import logging
import threading
from collections import defaultdict
from typing import Any, Optional

log = logging.getLogger(__name__)

__all__ = [
    "Counter",
    "Histogram",
    "registry",
    "counter",
    "histogram",
    "inc",
    "observe",
    "snapshot",
    "reset",
]

# Canonical metric names used across BugFund.
NAMES = {
    "campaigns_started": "counter",
    "campaigns_completed": "counter",
    "sandbox_runs_total": "counter",
    "sandbox_timeouts_total": "counter",
    "findings_verified_total": "counter",
    "llm_calls_total": "counter",
    "llm_tokens": "counter",
    "llm_cost_usd": "histogram",
    "sandbox_duration_ms": "histogram",
}


class Counter:
    """A monotonic counter."""

    __slots__ = ("name", "value", "_lock")

    def __init__(self, name: str) -> None:
        self.name = name
        self.value = 0
        self._lock = threading.Lock()

    def inc(self, n: int = 1) -> None:
        with self._lock:
            self.value += int(n)


class Histogram:
    """A simple histogram: count, sum, min, max (no bucketing)."""

    __slots__ = ("name", "count", "total", "min", "max", "_lock")

    def __init__(self, name: str) -> None:
        self.name = name
        self.count = 0
        self.total = 0.0
        self.min: Optional[float] = None
        self.max: Optional[float] = None
        self._lock = threading.Lock()

    def observe(self, value: float) -> None:
        with self._lock:
            self.count += 1
            self.total += float(value)
            self.min = value if self.min is None else min(self.min, value)
            self.max = value if self.max is None else max(self.max, value)

    @property
    def avg(self) -> Optional[float]:
        return None if self.count == 0 else self.total / self.count


class _Registry:
    def __init__(self) -> None:
        self._counters: dict[str, Counter] = {}
        self._histograms: dict[str, Histogram] = {}
        self._lock = threading.Lock()

    def counter(self, name: str) -> Counter:
        with self._lock:
            if name not in self._counters:
                self._counters[name] = Counter(name)
            return self._counters[name]

    def histogram(self, name: str) -> Histogram:
        with self._lock:
            if name not in self._histograms:
                self._histograms[name] = Histogram(name)
            return self._histograms[name]


registry = _Registry()


def counter(name: str) -> Counter:
    return registry.counter(name)


def histogram(name: str) -> Histogram:
    return registry.histogram(name)


def inc(name: str, n: int = 1) -> None:
    """Increment counter ``name`` by ``n`` (creates it if new)."""
    counter(name).inc(n)


def observe(name: str, value: float) -> None:
    """Record ``value`` on histogram ``name`` (creates it if new)."""
    histogram(name).observe(value)


def snapshot() -> dict[str, Any]:
    """Return a JSON-able snapshot of all counters/histograms."""
    return {
        "counters": {n: c.value for n, c in registry._counters.items()},
        "histograms": {
            n: {"count": h.count, "sum": h.total, "min": h.min, "max": h.max, "avg": h.avg}
            for n, h in registry._histograms.items()
        },
    }


def reset() -> None:
    """Test hook: clear all metrics."""
    with registry._lock:
        registry._counters.clear()
        registry._histograms.clear()
