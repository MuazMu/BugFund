"""Internal sandbox HTTP API — consumed only by the swarm's sandbox tool.

A tiny ASGI service wrapping :class:`~execution_engine.sandbox.runner.SandboxRunner`.
It is bound to a localhost interface / unix socket in production and is **never**
exposed to tenants. The runner is injected at startup via :func:`configure`.

Endpoints:
- ``GET  /health`` — liveness + whether a runner is wired.
- ``POST /run``    — execute one PoV/script, return captured output.
- ``POST /cancel`` — no-op stub (cancellation is the reaper's job).
"""
from __future__ import annotations

import logging
from typing import Optional

from fastapi import FastAPI, HTTPException, status

from execution_engine.api.schemas import HealthResponse, RunRequest, RunResponse
from execution_engine.sandbox.runner import SandboxRunner

log = logging.getLogger(__name__)

__all__ = ["app", "create_app", "configure", "get_runner"]

_runner: Optional[SandboxRunner] = None


def configure(runner: SandboxRunner) -> None:
    """Inject the sandbox runner (called once at service startup)."""
    global _runner
    _runner = runner
    log.info("internal sandbox API configured with %s", type(runner).__name__)


def get_runner() -> SandboxRunner:
    if _runner is None:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "No sandbox runner configured. Call execution_engine.api.configure(...).",
        )
    return _runner


def create_app() -> FastAPI:
    app = FastAPI(title="BugFund Sandbox API (internal)", version="0.1.0")

    @app.get("/health", response_model=HealthResponse)
    async def health() -> HealthResponse:
        return HealthResponse(
            status="ok" if _runner is not None else "degraded",
            runner=type(_runner).__name__ if _runner else "none",
        )

    @app.post("/run", response_model=RunResponse)
    async def run(req: RunRequest) -> RunResponse:
        runner = get_runner()
        ev = await runner.run_pov(
            req.script_code,
            req.env_vars,
            timeout_s=req.timeout_s,
            network=req.network,
        )
        return RunResponse(
            stdout=ev["stdout"],
            stderr=ev["stderr"],
            exit_code=ev["exit_code"],
            duration_ms=ev["duration_ms"],
            timed_out=ev["timed_out"],
            container_id=ev["container_id"],
        )

    @app.post("/cancel")
    async def cancel() -> dict[str, str]:
        # Cancellation is handled by the container teardown/reaper, not per-request.
        return {"status": "not_supported"}

    return app


app = create_app()
