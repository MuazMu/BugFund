"""Guaranteed container teardown + watchdog timeout.

Module-level, duck-typed helpers (operate on any container object exposing
``status``/``reload``/``kill``/``remove``) so the pool, runner, and the reaper
task all share one cleanup path. Nothing here ever raises — teardown is in a
``finally``-equivalent position and must not abort the caller.
"""
from __future__ import annotations

import logging
import threading
from typing import Any, Optional

log = logging.getLogger(__name__)

__all__ = ["force_kill", "force_remove", "watchdog", "reap_labeled"]


def force_kill(container: Any) -> bool:
    """SIGKILL ``container`` if it is running. Returns whether a kill was issued."""
    try:
        container.reload()
        if container.status == "running":
            container.kill()
            return True
    except Exception:
        pass  # already gone / transient SDK error — nothing to do
    return False


def force_remove(container: Any) -> None:
    """Unconditional teardown: kill if alive, then force-remove. Never raises."""
    try:
        container.kill()
    except Exception:
        pass
    try:
        container.remove(force=True)
    except Exception:
        pass


def watchdog(
    container: Any, timeout_s: float, flag: Optional[dict[str, bool]] = None
) -> threading.Timer:
    """Arm a watchdog that SIGKILLs ``container`` at ``timeout_s``.

    Args:
        container: A Docker container-like object.
        timeout_s: Seconds before the kill.
        flag: Optional mutable flag dict; ``flag["v"]`` is set True if the
            watchdog killed (indicating a timeout). Pass the same dict the
            caller inspects for ``timed_out``.

    Returns:
        An armed (started) :class:`threading.Timer`; call ``.cancel()`` on it
        once the container exits naturally.
    """
    flag = flag if flag is not None else {"v": False}

    def _on_timeout() -> None:
        if force_kill(container):
            flag["v"] = True
            log.warning("sandbox watchdog killed container after %.1fs", timeout_s)

    timer = threading.Timer(timeout_s, _on_timeout)
    timer.daemon = True
    timer.start()
    return timer


def reap_labeled(
    client: Any, label: str = "app=bugfund", *, statuses: tuple[str, ...] = ("exited", "dead")
) -> int:
    """Force-remove all containers with ``label`` in a terminal ``status``.

    Returns the number removed. Best-effort: skips and counts past errors.
    """
    removed = 0
    try:
        containers = client.containers.list(all=True, filters={"label": label})
    except Exception as exc:  # pragma: no cover - no docker daemon
        log.warning("reap_labeled: could not list containers: %s", exc)
        return 0
    for ctr in containers:
        try:
            if getattr(ctr, "status", None) in statuses:
                force_remove(ctr)
                removed += 1
        except Exception as exc:  # pragma: no cover - defensive
            log.warning("reap_labeled: could not remove %s: %s", getattr(ctr, "id", "?"), exc)
    return removed
