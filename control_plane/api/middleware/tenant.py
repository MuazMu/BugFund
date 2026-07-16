"""Tenant context value object + request-state plumbing.

The :class:`TenantContext` is resolved per-request by the auth dependency
(``middleware/auth.py``) and stashed on ``request.state``; it is the single
tenant-isolation handle every tenant-facing query filters by. A dev/default
context (``tenant_id=None``) is used when auth is lenient.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Optional

__all__ = ["TenantContext", "set_tenant", "REQUEST_STATE_KEY"]

REQUEST_STATE_KEY = "tenant"


@dataclass(slots=True)
class TenantContext:
    """The resolved tenant for the current request."""

    tenant_id: Optional[uuid.UUID] = None
    slug: str = "dev"
    is_dev: bool = True

    @classmethod
    def dev_default(cls) -> "TenantContext":
        return cls(tenant_id=None, slug="dev", is_dev=True)

    @classmethod
    def for_tenant(cls, tenant_id: uuid.UUID, slug: str) -> "TenantContext":
        return cls(tenant_id=tenant_id, slug=slug, is_dev=False)


def set_tenant(request, ctx: TenantContext) -> None:
    """Attach the resolved tenant to the request for downstream consumers."""
    setattr(request.state, REQUEST_STATE_KEY, ctx)
