"""Declarative base, reusable mixins, and shared enumerations.

All ORM models register on the single :class:`Base` metadata (the Alembic
``env.py`` reflects this metadata to autogenerate migrations). Mixins factor
out the columns every table shares: a server-generated UUID primary key,
audit timestamps, and (for tenant-owned rows) a tenant scope.

PostgreSQL 15+ is the target dialect: ``UUID`` and ``JSONB`` are native, and
``gen_random_uuid()`` is in core (no extension needed).
"""
from __future__ import annotations

import enum
import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, ForeignKey, Index, String, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

__all__ = [
    "Base",
    "UUIDPKMixin",
    "TimestampMixin",
    "TenantScopedMixin",
    "enum_values",
    "IngestionStatus",
    "CampaignStatus",
    "TaskState",
    "FindingSeverity",
]


class Base(DeclarativeBase):
    """Declarative base for all control-plane ORM models."""


class UUIDPKMixin:
    """UUID primary key generated server-side by Postgres."""

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=func.gen_random_uuid(),
    )


class TimestampMixin:
    """``created_at`` / ``updated_at`` with server-side defaults."""

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )


class TenantScopedMixin:
    """Rows owned by a tenant. Nullable so dev/single-tenant mode still works.

    Every tenant-facing query filters on this column; the API middleware
    (``control_plane/api/middleware/tenant.py``) stamps it onto new rows.
    """

    tenant_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )


def enum_values(e: type[enum.Enum]) -> list[str]:
    """``values_callable`` keeping DB enum values stable regardless of member name."""
    return [m.value for m in e]


# --------------------------------------------------------------------------- #
# Enumerations (str enums — DB values stay stable & JSON-friendly)
# --------------------------------------------------------------------------- #
class IngestionStatus(str, enum.Enum):
    """Lifecycle of a target from submission to readiness for hunting."""

    PENDING = "pending"
    CLONING = "cloning"
    BUILDING = "building"
    READY = "ready"
    FAILED = "failed"


class CampaignStatus(str, enum.Enum):
    """Lifecycle of a hunt campaign."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class TaskState(str, enum.Enum):
    """Celery task lifecycle (mirrors Celery's states)."""

    PENDING = "pending"
    STARTED = "started"
    SUCCESS = "success"
    FAILURE = "failure"
    RETRY = "retry"
    REVOKED = "revoked"


class FindingSeverity(str, enum.Enum):
    """CVSS-aligned severity buckets for verified findings."""

    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
