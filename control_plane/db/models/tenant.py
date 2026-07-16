"""Multi-tenant tables: tenants, API keys, and per-tenant quotas.

These back the auth/tenant/rate-limit middleware. A tenant owns targets,
campaigns, findings, and tasks. API keys are stored **only** as a SHA-256 hash
(``control_plane.core.security.hash_secret``); the plaintext is returned to the
tenant exactly once at creation (``generate_api_key``).
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from control_plane.db.base import Base, TimestampMixin, UUIDPKMixin

__all__ = ["Tenant", "ApiKey", "Quota"]


class Tenant(UUIDPKMixin, TimestampMixin, Base):
    """A B2B customer. Owns all tenant-scoped rows via ``TenantScopedMixin``."""

    __tablename__ = "tenants"

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    slug: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    plan: Mapped[str] = mapped_column(String(32), nullable=False, default="trial")
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    api_keys: Mapped[list["ApiKey"]] = relationship(
        back_populates="tenant", cascade="all, delete-orphan", passive_deletes=True
    )
    quotas: Mapped[list["Quota"]] = relationship(
        back_populates="tenant", cascade="all, delete-orphan", passive_deletes=True
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Tenant id={self.id} slug={self.slug!r} plan={self.plan!r}>"


class ApiKey(UUIDPKMixin, TimestampMixin, Base):
    """A tenant API credential. Only the hash is persisted.

    ``key_hash`` is a SHA-256 hex digest of the full ``bf_live_…`` key, looked
    up on each request and verified constant-time. Revocation is soft
    (``revoked``) so audit history is retained.
    """

    __tablename__ = "api_keys"

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False, default="default")
    key_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    key_prefix: Mapped[str] = mapped_column(
        String(16), nullable=False, comment="Non-secret prefix for UI display (e.g. 'bf_live_ab12')."
    )
    last_used_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    tenant: Mapped["Tenant"] = relationship(back_populates="api_keys")

    __table_args__ = (
        Index("ix_api_keys_tenant", "tenant_id"),
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<ApiKey id={self.id} prefix={self.key_prefix!r} revoked={self.revoked}>"


class Quota(UUIDPKMixin, TimestampMixin, Base):
    """A per-tenant usage limit/counter (e.g. ``campaigns_per_month``)."""

    __tablename__ = "quotas"

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    resource: Mapped[str] = mapped_column(String(64), nullable=False)
    limit_value: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    used_value: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    window: Mapped[str] = mapped_column(String(32), nullable=False, default="monthly")

    tenant: Mapped["Tenant"] = relationship(back_populates="quotas")

    __table_args__ = (
        UniqueConstraint("tenant_id", "resource", "window", name="uq_quota_tenant_resource_window"),
    )

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"<Quota tenant={self.tenant_id} resource={self.resource!r} "
            f"{self.used_value}/{self.limit_value} ({self.window})>"
        )
