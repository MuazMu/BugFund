"""API-key authentication dependency (B2B).

Credential resolution order: ``X-API-Key`` header, then ``Authorization: Bearer``
or ``Authorization: ApiKey``. A presented key is looked up by its SHA-256 hash
(see :func:`control_plane.core.security.hash_secret`) and must belong to an
active tenant. On success a real :class:`TenantContext` is attached.

In dev/test (``APP_ENV`` in ``{"dev","test"}``) requests with no/invalid
credential fall through to a dev tenant context so the API is usable without
provisioning keys; in other environments a missing credential is rejected
with ``401``. All DB access is best-effort — a missing DB never blocks auth.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from control_plane.api.deps import SessionDep, SettingsDep
from control_plane.api.middleware.tenant import TenantContext, set_tenant
from control_plane.core.security import hash_secret
from control_plane.db.models import ApiKey, Tenant

log = logging.getLogger(__name__)

_DEV_ENVS = {"dev", "test", "local"}


def _extract_credential(request: Request) -> str | None:
    api_key = request.headers.get("x-api-key") or request.headers.get("X-API-Key")
    if api_key:
        return api_key.strip() or None
    auth = request.headers.get("authorization", "").strip()
    if not auth:
        return None
    parts = auth.split(None, 1)
    if len(parts) == 2 and parts[0].lower() in {"bearer", "apikey"}:
        return parts[1].strip() or None
    return None


async def _resolve_credential(session: AsyncSession, credential: str) -> TenantContext | None:
    """Look the key up by hash; return its tenant context or ``None``."""
    key_hash = hash_secret(credential)
    try:
        stmt = (
            select(ApiKey, Tenant)
            .join(Tenant, ApiKey.tenant_id == Tenant.id)
            .where(
                ApiKey.key_hash == key_hash,
                ApiKey.revoked.is_(False),
                Tenant.active.is_(True),
            )
        )
        row = (await session.execute(stmt)).first()
    except Exception as exc:  # no DB / connection error → treat as unresolved
        log.debug("auth DB lookup failed: %s", exc)
        return None
    if row is None:
        return None
    api_key: ApiKey = row[0]
    tenant: Tenant = row[1]
    if api_key.expires_at is not None and api_key.expires_at <= datetime.now(timezone.utc):
        return None
    # Best-effort last-used stamp (never blocks the request).
    try:
        api_key.last_used_at = datetime.now(timezone.utc)
        await session.commit()
    except Exception:  # pragma: no cover - defensive
        await session.rollback()
    return TenantContext.for_tenant(tenant.id, tenant.slug)


async def authenticate(
    request: Request,
    settings: SettingsDep,
    session: SessionDep,
) -> TenantContext:
    """Resolve the caller's tenant. Raises ``401`` in non-dev envs without a key."""
    credential = _extract_credential(request)
    if credential:
        ctx = await _resolve_credential(session, credential)
        if ctx is not None:
            set_tenant(request, ctx)
            return ctx

    if settings.api_keys_enabled and settings.env not in _DEV_ENVS:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="A valid API key is required.",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    ctx = TenantContext.dev_default()
    set_tenant(request, ctx)
    return ctx


# The tenant the endpoint sees is exactly the authenticated context. Depending
# on this (rather than reading request.state directly) guarantees auth resolves
# before the tenant is consumed, and FastAPI caches the result per request.
TenantDep = Annotated[TenantContext, Depends(authenticate)]
