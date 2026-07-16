"""Observability — tracing, metrics, and LLM tracing across all planes.

Each submodule degrades to a no-op when its optional dependency or endpoint is
absent, so importing this package never hard-requires OpenTelemetry or Langfuse.
Call :func:`setup_all` once at process start (idempotent).
"""
from __future__ import annotations

import logging

from observability.langfuse import is_enabled as langfuse_enabled
from observability.langfuse import setup_langfuse, trace_generation
from observability.metrics import inc, observe, snapshot
from observability.tracing import is_enabled as tracing_enabled
from observability.tracing import setup_tracing, span

log = logging.getLogger(__name__)

__all__ = [
    "setup_tracing",
    "span",
    "tracing_enabled",
    "inc",
    "observe",
    "snapshot",
    "setup_langfuse",
    "trace_generation",
    "langfuse_enabled",
    "setup_all",
]


def setup_all() -> None:
    """Initialize tracing + Langfuse (idempotent; safe to call at startup)."""
    setup_tracing()
    setup_langfuse()
