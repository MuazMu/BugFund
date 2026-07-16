"""Aggregate all v1 routers under the authenticated, rate-limited surface."""
from __future__ import annotations

from fastapi import APIRouter, Depends

from control_plane.api.middleware import authenticate, rate_limit
from control_plane.api.v1.endpoints import campaigns, findings, health, targets, tasks

router = APIRouter(dependencies=[Depends(authenticate), Depends(rate_limit)])

router.include_router(health.router)
router.include_router(targets.router)
router.include_router(campaigns.router)
router.include_router(findings.router)
router.include_router(tasks.router)

__all__ = ["router"]
