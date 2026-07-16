"""The system under test."""
from __future__ import annotations

from typing import Any, Optional

from sqlalchemy import Enum as SAEnum, Index, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from control_plane.db.base import (
    Base,
    IngestionStatus,
    TenantScopedMixin,
    TimestampMixin,
    UUIDPKMixin,
    enum_values,
)

__all__ = ["Target"]


class Target(UUIDPKMixin, TimestampMixin, TenantScopedMixin, Base):
    """The system under test.

    ``build_instructions`` is JSONB so it can carry structured, reproducible
    build metadata (commands, environment, base image, language toolchain)
    rather than freeform text. ``tenant_id`` is injected by
    :class:`TenantScopedMixin` when present (mixed in via ``models/__init__``
    composition is avoided; tenant scoping is applied at the campaign/finding
    layer instead — see ``docs/architecture.md``).
    """

    __tablename__ = "targets"

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    repo_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    commit_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    build_instructions: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        comment="Structured build recipe: {image, commands, env, language, ...}",
    )
    language: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    ingestion_status: Mapped[IngestionStatus] = mapped_column(
        SAEnum(IngestionStatus, name="ingestion_status", values_callable=enum_values),
        nullable=False,
        default=IngestionStatus.PENDING,
    )

    campaigns: Mapped[list["HuntCampaign"]] = relationship(  # noqa: F821
        back_populates="target",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

    __table_args__ = (
        Index("ix_targets_repo_commit", "repo_url", "commit_hash"),
    )

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"<Target id={self.id} name={self.name!r} "
            f"commit={self.commit_hash!r} status={self.ingestion_status.value}>"
        )
