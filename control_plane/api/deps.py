"""Shared FastAPI dependencies: settings, DB session, pagination.

Tenant resolution lives in ``middleware/auth.py`` (it must run the auth check),
so ``TenantDep`` is defined there and re-exported via ``middleware`` to avoid a
``deps <-> auth`` import cycle.
"""
from __future__ import annotations

from typing import Annotated

from fastapi import Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from control_plane.core.config import Settings, get_settings
from control_plane.db.session import get_session

__all__ = [
    "SettingsDep",
    "SessionDep",
    "PageDep",
    "get_settings",
    "get_db",
    "get_page",
]

SettingsDep = Annotated[Settings, Depends(get_settings)]
SessionDep = Annotated[AsyncSession, Depends(get_session)]


async def get_db() -> AsyncSession:  # pragma: no cover - thin alias
    """Alias for :func:`control_plane.db.session.get_session` (convention)."""
    async for session in get_session():
        yield session


def get_page(
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> dict[str, int]:
    """Pagination query params (``?limit=&offset=``)."""
    return {"limit": limit, "offset": offset}


PageDep = Annotated[dict[str, int], Depends(get_page)]
