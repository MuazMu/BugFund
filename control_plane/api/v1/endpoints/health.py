"""Liveness / readiness endpoint."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter

from control_plane.api.deps import SettingsDep

router = APIRouter(tags=["meta"])


@router.get("/health")
async def health(settings: SettingsDep) -> dict[str, Any]:
    """Liveness probe — process is up and answering."""
    return {"status": "ok", "env": settings.env}
