"""Evidence collectors — raw material for the Critic.

Parses sandbox output (logs, traces, crashes/ASan) into structured JSON the
Critic and Reporter consume. All pure functions over text — no I/O.
"""
from __future__ import annotations

from execution_engine.collectors.crash import (
    ASanReport,
    CrashSummary,
    classify_crash,
    classify_signal,
    parse_asan,
)
from execution_engine.collectors.logs import LogCapture, capture_logs, truncate_tail
from execution_engine.collectors.traces import (
    SyscallEvent,
    TraceReport,
    parse_strace,
    suspicious_syscalls,
)

__all__ = [
    "parse_asan",
    "classify_crash",
    "classify_signal",
    "ASanReport",
    "CrashSummary",
    "capture_logs",
    "truncate_tail",
    "LogCapture",
    "parse_strace",
    "suspicious_syscalls",
    "SyscallEvent",
    "TraceReport",
]
