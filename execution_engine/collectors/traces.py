"""strace / ltrace collection & parsing.

When a sandbox run is traced, the syscall stream is parsed into structured
events the Critic can scan for suspicious syscalls (open of sensitive paths,
exec, network connects) without reading raw trace text.
"""
from __future__ import annotations

import re
from typing import Optional, TypedDict

__all__ = ["SyscallEvent", "TraceReport", "parse_strace", "suspicious_syscalls"]

# Matches a typical strace line:
#   `1234  openat(AT_FDCWD, "/etc/shadow", O_RDONLY) = -1 EACCES (Permission denied)`
#   `open("/etc/passwd", O_RDONLY)        = 3`
_STRACE_RE = re.compile(
    r"^(?:(?P<pid>\d+)\s+)?(?P<name>[a-zA-Z_][\w]*)\((?P<args>.*)\)\s*=\s*(?P<ret>.+)$"
)

_SUSPICIOUS = {
    "execve", "execveat", "open", "openat", "creat", "connect", "socket",
    "bind", "sendto", "sendmsg", "ptrace", "mount", "unshare", "clone",
    "clone3", "prctl",
}


class SyscallEvent(TypedDict):
    pid: Optional[str]
    name: str
    args: str
    ret: str


class TraceReport(TypedDict):
    total: int
    events: list[SyscallEvent]
    suspicious: list[SyscallEvent]
    parse_errors: int


def parse_strace(text: str, *, max_events: int = 5000) -> TraceReport:
    """Parse a strace/ltrace stream into structured syscall events."""
    events: list[SyscallEvent] = []
    parse_errors = 0
    truncated = False

    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("+++", "---")):
            continue
        m = _STRACE_RE.match(line)
        if not m:
            parse_errors += 1
            continue
        if len(events) >= max_events:
            truncated = True  # noqa: F841 -- surfaced via len(events) == max_events
            break
        events.append(
            SyscallEvent(
                pid=m.group("pid"),
                name=m.group("name"),
                args=m.group("args"),
                ret=m.group("ret").strip(),
            )
        )

    suspicious = [e for e in events if e["name"] in _SUSPICIOUS]
    return TraceReport(
        total=len(events),
        events=events,
        suspicious=suspicious,
        parse_errors=parse_errors,
    )


def suspicious_syscalls(report: TraceReport) -> list[str]:
    """Return the distinct suspicious syscall names seen in the trace."""
    return sorted({e["name"] for e in report["suspicious"]})
