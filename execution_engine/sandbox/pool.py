"""Bounded container pool + concurrency limiter.

Wraps any :class:`~agent_swarm.skills.SandboxClient`-compatible object with an
:class:`asyncio.Semaphore` so concurrent campaigns can't exhaust the Docker
host. ``SandboxPool`` itself satisfies the ``SandboxClient`` protocol (it
exposes ``run_script``), so it can be injected via
``agent_swarm.set_sandbox_client(...)`` in place of a bare manager.
"""
from __future__ import annotations

import asyncio
from typing import Any

__all__ = ["SandboxPool"]


class SandboxPool:
    """Concurrency-limited wrapper over a sandbox client."""

    def __init__(self, client: Any, max_concurrency: int) -> None:
        if max_concurrency < 1:
            raise ValueError("max_concurrency must be >= 1")
        self._client = client
        self._max = max_concurrency
        self._sem = asyncio.Semaphore(max_concurrency)

    @property
    def max_concurrency(self) -> int:
        return self._max

    async def run_script(
        self,
        *,
        script_code: str,
        env_vars: dict[str, str] | None = None,
        timeout_s: int = 60,
        network: bool = False,
    ) -> dict[str, Any]:
        """Acquire a slot, then delegate to the wrapped client."""
        async with self._sem:
            return await self._client.run_script(
                script_code=script_code,
                env_vars=dict(env_vars or {}),
                timeout_s=timeout_s,
                network=network,
            )

    async def run_many(self, jobs: list[dict[str, Any]]) -> list[Any]:
        """Run many jobs concurrently (capped), preserving input order.

        Each job is a kwargs dict for :meth:`run_script`. Per-job failures are
        captured as ``{"error": str}`` rather than aborting the batch.
        """
        tasks = [self.run_script(**job) for job in jobs]
        gathered = await asyncio.gather(*tasks, return_exceptions=True)
        return [
            r if not isinstance(r, BaseException) else {"error": str(r)}
            for r in gathered
        ]
