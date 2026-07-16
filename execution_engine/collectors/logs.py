"""Structured stdout/stderr capture helpers.

Bound raw container output to sizes safe to persist and feed to LLM agents,
while preserving the tail (where errors usually live). Pure functions.
"""
from __future__ import annotations

from typing import TypedDict

__all__ = ["LogCapture", "capture_logs", "truncate_middle", "truncate_tail"]

_DEFAULT_STDOUT = 16_000
_DEFAULT_STDERR = 16_000


class LogCapture(TypedDict):
    stdout: str
    stderr: str
    stdout_truncated: bool
    stderr_truncated: bool


def truncate_tail(text: str, limit: int) -> tuple[str, bool]:
    """Keep the last ``limit`` chars (the tail), flagging truncation."""
    if len(text) <= limit:
        return text, False
    return text[-limit:], True


def truncate_middle(text: str, limit: int) -> tuple[str, bool]:
    """Keep head + tail, dropping the middle (preserves start banner + final error)."""
    if len(text) <= limit:
        return text, False
    if limit <= 64:
        return text[-limit:], True
    keep_head = limit // 4
    keep_tail = limit - keep_head - len("\n...[truncated]...\n")
    marker = "\n...[truncated]...\n"
    return text[:keep_head] + marker + text[-keep_tail:], True


def capture_logs(
    stdout: str,
    stderr: str,
    *,
    stdout_limit: int = _DEFAULT_STDOUT,
    stderr_limit: int = _DEFAULT_STDERR,
) -> LogCapture:
    """Bound stdout/stderr to agent-safe sizes (tail-preserving)."""
    out, out_trunc = truncate_tail(stdout or "", stdout_limit)
    err, err_trunc = truncate_tail(stderr or "", stderr_limit)
    return LogCapture(
        stdout=out,
        stderr=err,
        stdout_truncated=out_trunc,
        stderr_truncated=err_trunc,
    )
