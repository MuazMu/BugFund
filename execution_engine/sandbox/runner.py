"""High-level sandbox runner — executes a PoV and attaches parsed evidence.

``SandboxRunner`` sits one layer above the raw :class:`SandboxManager`: it runs
a PoV through a pool (or any client) and post-processes the captured output
with the collectors into a single :class:`ExecutionEvidence` blob the Critic
and Reporter consume (raw logs + a structured crash verdict).
"""
from __future__ import annotations

from typing import Any, Optional, TypedDict

from execution_engine.collectors import capture_logs, classify_crash

__all__ = ["ExecutionEvidence", "SandboxRunner"]


class ExecutionEvidence(TypedDict):
    """A sandbox run result plus structured crash + bounded-log evidence."""

    stdout: str
    stderr: str
    exit_code: Optional[int]
    duration_ms: int
    container_id: Optional[str]
    timed_out: bool
    crash: dict[str, Any]
    logs: dict[str, Any]


class SandboxRunner:
    """Run a PoV and return evidence enriched with collector output."""

    def __init__(self, client: Any, executor: Any | None = None) -> None:
        """
        Args:
            client: The underlying sandbox client (has ``run_script``).
            executor: Optional concurrency-limited executor (e.g.
                :class:`SandboxPool`). Defaults to ``client``.
        """
        self._client = client
        self._executor = executor or client

    async def run_pov(
        self,
        script_code: str,
        env_vars: dict[str, str] | None = None,
        *,
        timeout_s: int = 60,
        network: bool = False,
    ) -> ExecutionEvidence:
        """Execute ``script_code`` and return enriched evidence."""
        result = await self._executor.run_script(
            script_code=script_code,
            env_vars=dict(env_vars or {}),
            timeout_s=timeout_s,
            network=network,
        )
        crash = classify_crash(
            result.get("exit_code"),
            result.get("stdout", "") or "",
            result.get("stderr", "") or "",
            timed_out=bool(result.get("timed_out", False)),
        )
        logs = capture_logs(result.get("stdout", "") or "", result.get("stderr", "") or "")
        return ExecutionEvidence(
            stdout=result.get("stdout", "") or "",
            stderr=result.get("stderr", "") or "",
            exit_code=result.get("exit_code"),
            duration_ms=result.get("duration_ms", 0),
            container_id=result.get("container_id"),
            timed_out=bool(result.get("timed_out", False)),
            crash=crash,
            logs=logs,
        )
