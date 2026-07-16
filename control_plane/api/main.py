"""FastAPI app factory, lifespan wiring, and domain→HTTP exception handlers.

Routes live in ``api/v1``; this module mounts them under ``APP_API_PREFIX``
and registers a consistent JSON error envelope for the control-plane exception
hierarchy. ``/health`` is exposed unauthenticated at the root for liveness
probes; everything under ``/api/v1`` is authenticated + rate-limited.
"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from control_plane.api.v1.router import router as v1_router
from control_plane.api.v1.schemas.common import ErrorEnvelope
from control_plane.core.config import get_settings
from control_plane.core.exceptions import (
    BudgetExceeded,
    Conflict,
    ControlPlaneError,
    NotFound,
    Unauthorized,
    ValidationFailed,
)

log = logging.getLogger(__name__)


def wire_swarm() -> None:
    """Inject the Docker SandboxManager + LLM provider into the agent swarm.

    Best-effort: in dev/test without a Docker daemon or LLM keys this is a no-op,
    so the API still serves (campaigns enqueue but won't fully execute).
    """
    settings = get_settings()
    try:
        from execution_engine import SandboxManager
        from agent_swarm import set_sandbox_client
        from ai_gateway import LiteLLMProvider, configure

        mgr = SandboxManager(
            image=settings.sandbox_image,
            target_resolver=lambda tid: f"{settings.targets_root}/{tid}",
        )
        set_sandbox_client(mgr)
        configure(LiteLLMProvider(model=settings.llm_model))
        log.info("wired SandboxManager + LLM provider into the swarm")
    except Exception as exc:  # no docker daemon / no keys in dev/test
        log.warning("swarm wiring skipped: %s", exc)


@asynccontextmanager
async def lifespan(app: FastAPI):
    wire_swarm()
    yield


def _envelope(code: str, message: str, request: Request, status_code: int) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content=ErrorEnvelope(
            code=code,
            message=message,
            request_id=getattr(request.state, "request_id", None),
        ).model_dump(),
    )


def _register_handlers(app: FastAPI) -> None:
    """Map the control-plane exception hierarchy to consistent JSON envelopes."""

    @app.exception_handler(NotFound)
    async def _not_found(request, exc):
        return _envelope("not_found", str(exc), request, 404)

    @app.exception_handler(Unauthorized)
    async def _unauthorized(request, exc):
        return _envelope("unauthorized", str(exc), request, 401)

    @app.exception_handler(ValidationFailed)
    async def _validation(request, exc):
        return _envelope("validation_failed", str(exc), request, 400)

    @app.exception_handler(BudgetExceeded)
    async def _budget(request, exc):
        return _envelope("budget_exceeded", str(exc), request, 402)

    @app.exception_handler(Conflict)
    async def _conflict(request, exc):
        return _envelope("conflict", str(exc), request, 409)

    @app.exception_handler(ControlPlaneError)
    async def _control_plane(request, exc):
        return _envelope("control_plane_error", str(exc), request, 500)

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception):
        # Database connectivity issues → 503 (transient, retry-friendly).
        type_name = type(exc).__name__
        if "Operational" in type_name or "Connection" in type_name or "DBAPI" in type_name:
            log.warning("database error: %s", exc)
            return _envelope("service_unavailable", "database unavailable", request, 503)
        log.exception("unhandled error")
        return _envelope("internal_error", "internal server error", request, 500)


def create_app() -> FastAPI:
    """Build the FastAPI application."""
    settings = get_settings()
    app = FastAPI(title="BugFund CRS", version="0.1.0", lifespan=lifespan)

    # Unauthenticated liveness probe at the root.
    @app.get("/health", tags=["meta"])
    async def health() -> dict[str, Any]:
        return {"status": "ok", "env": settings.env}

    # Authenticated, rate-limited versioned surface.
    app.include_router(v1_router, prefix=settings.api_prefix)

    _register_handlers(app)
    return app


app = create_app()
