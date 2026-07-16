"""Crash / AddressSanitizer parsing & classification.

Turns raw sandbox output (exit code + stdout/stderr) into a structured verdict
the Critic can reason about: was there a real memory-safety fault, what kind,
and where? Pure functions — no I/O — so they unit-test cleanly.
"""
from __future__ import annotations

import re
from typing import Any, Optional, TypedDict

__all__ = [
    "SIGNAL_BY_EXIT",
    "ASanReport",
    "CrashSummary",
    "parse_asan",
    "classify_crash",
    "classify_signal",
]

# POSIX exit codes for signal deaths are 128 + signum.
SIGNAL_BY_EXIT: dict[int, str] = {
    134: "SIGABRT",  # often ASan abort_on_error or assert
    139: "SIGSEGV",
    135: "SIGBUS",
    136: "SIGFPE",
    132: "SIGILL",
    137: "SIGKILL",  # typically the sandbox watchdog timeout
    138: "SIGUSR2",
}

_ASAN_ERROR_RE = re.compile(
    r"==\d+==ERROR: AddressSanitizer:\s*(?P<bug>.+)", re.IGNORECASE
)
_ASAN_ADDR_RE = re.compile(r"on address\s+(?P<addr>0x[0-9a-fA-F]+)", re.IGNORECASE)
_ASAN_SUMMARY_RE = re.compile(
    r"SUMMARY:\s*AddressSanitizer:\s*(?P<bug>.+?)\s+(?:in\s+(?P<where>.+))?",
    re.IGNORECASE,
)
_UBSAN_ERROR_RE = re.compile(
    r"runtime error:\s*(?P<msg>[^\n]+)", re.IGNORECASE
)


class ASanReport(TypedDict):
    detected: bool
    sanitizer: str  # "asan" | "ubsan" | "none"
    bug_type: Optional[str]
    address: Optional[str]
    location: Optional[str]
    runtime_errors: list[str]


class CrashSummary(TypedDict):
    crashed: bool
    signal: Optional[str]
    exit_code: Optional[int]
    timed_out: bool
    sanitizer: ASanReport
    classification: str  # human-readable bucket


def parse_asan(stderr: str, stdout: str = "") -> ASanReport:
    """Extract AddressSanitizer / UndefinedBehaviorSanitizer facts from output."""
    blob = f"{stderr}\n{stdout}"

    bug_type: Optional[str] = None
    address: Optional[str] = None
    err = _ASAN_ERROR_RE.search(blob)
    if err:
        # The error line is "<bug> on address 0x.. at pc 0x.. ..."; keep just the bug.
        bug_type = re.split(
            r"\s+on address\s+", err.group("bug").strip(), maxsplit=1
        )[0].strip()
        addr_m = _ASAN_ADDR_RE.search(blob)
        if addr_m:
            address = addr_m.group("addr")
    summary = _ASAN_SUMMARY_RE.search(blob)
    location: Optional[str] = None
    if summary:
        if not bug_type:
            bug_type = summary.group("bug").strip()
        location = summary.group("where")

    runtime_errors = [m.group("msg").strip() for m in _UBSAN_ERROR_RE.finditer(blob)]
    detected = bool(bug_type) or bool(runtime_errors)
    sanitizer = "asan" if bug_type else ("ubsan" if runtime_errors else "none")

    return ASanReport(
        detected=detected,
        sanitizer=sanitizer,
        bug_type=bug_type,
        address=address,
        location=location,
        runtime_errors=runtime_errors,
    )


def classify_signal(exit_code: Optional[int]) -> Optional[str]:
    """Map a signal-death exit code (128+n) to its signal name, else ``None``."""
    if exit_code is None or exit_code < 128:
        return None
    return SIGNAL_BY_EXIT.get(exit_code)


def classify_crash(
    exit_code: Optional[int],
    stdout: str = "",
    stderr: str = "",
    *,
    timed_out: bool = False,
) -> CrashSummary:
    """Produce a structured crash verdict from a sandbox run's captured output."""
    sanitizer = parse_asan(stderr, stdout)
    signal = classify_signal(exit_code)

    if timed_out and signal == "SIGKILL":
        classification = "timeout (watchdog killed)"
    elif sanitizer["detected"]:
        classification = f"sanitizer: {sanitizer['sanitizer']} {sanitizer['bug_type'] or ''}".strip()
    elif signal in {"SIGSEGV", "SIGBUS", "SIGFPE", "SIGILL"}:
        classification = f"native crash: {signal}"
    elif signal == "SIGABRT":
        classification = "abort / assertion"
    elif exit_code not in (None, 0):
        classification = f"non-zero exit ({exit_code})"
    else:
        classification = "clean exit"

    crashed = bool(
        sanitizer["detected"]
        or (signal in {"SIGSEGV", "SIGBUS", "SIGFPE", "SIGILL", "SIGABRT"})
    )

    return CrashSummary(
        crashed=crashed,
        signal=signal,
        exit_code=exit_code,
        timed_out=timed_out,
        sanitizer=sanitizer,
        classification=classification,
    )
