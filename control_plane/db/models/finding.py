"""Verified findings + raw sandbox execution evidence.

``Finding`` is a Critic-graduated, reproducible vulnerability record (CWE,
CVSS/severity, the PoV reference, evidence references). ``ExecutionLog`` is the
raw stdout/stderr/exit captured from a single Docker sandbox run — the evidence
the Critic reasons over. Both are campaign-scoped.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Optional

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Index, Integer, String, Text
from sqlalchemy import Enum as SAEnum
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from control_plane.db.base import (
    Base,
    FindingSeverity,
    TimestampMixin,
    UUIDPKMixin,
    enum_values,
)

__all__ = ["Finding", "ExecutionLog"]


class Finding(UUIDPKMixin, TimestampMixin, Base):
    """A verified, reproducible vulnerability produced by a campaign.

    ``pov_ref`` points at the proof-of-vulnerability artifact (the PoV script
    itself, or an out-of-band reference); ``evidence_ref`` holds the sandbox
    evidence bundle (stdout/exit, crash/ASan refs). ``patch_verified`` records
    whether the Patcher's differential patch proof succeeded.
    """

    __tablename__ = "findings"

    campaign_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("hunt_campaigns.id", ondelete="CASCADE"), nullable=False
    )
    hypothesis_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    cwe: Mapped[str] = mapped_column(String(32), nullable=False)
    severity: Mapped[FindingSeverity] = mapped_column(
        SAEnum(FindingSeverity, name="finding_severity", values_callable=enum_values),
        nullable=False,
        default=FindingSeverity.MEDIUM,
    )
    cvss_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    pov_ref: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True, comment="The PoV script or an out-of-band artifact reference."
    )
    evidence_ref: Mapped[Optional[dict[str, Any]]] = mapped_column(JSONB, nullable=True)
    verified: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    patch_verified: Mapped[Optional[bool]] = mapped_column(Boolean, nullable=True)

    campaign: Mapped["HuntCampaign"] = relationship(  # noqa: F821
        back_populates="findings"
    )

    __table_args__ = (
        Index("ix_findings_campaign_cwe", "campaign_id", "cwe"),
    )

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"<Finding id={self.id} campaign_id={self.campaign_id} "
            f"cwe={self.cwe!r} severity={self.severity.value} verified={self.verified}>"
        )


class ExecutionLog(UUIDPKMixin, TimestampMixin, Base):
    """Output captured from a single Docker sandbox run.

    Written by the execution engine's collectors after a containerized test
    action completes. ``exit_code`` + ``stdout`` + ``stderr`` are the raw
    evidence the Critic reasons over; ``evidence_ref`` points at larger
    artifacts (crash dumps, ASan traces) stored out-of-band.
    """

    __tablename__ = "execution_logs"

    campaign_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("hunt_campaigns.id", ondelete="CASCADE"), nullable=False
    )
    container_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    exit_code: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    stdout: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    stderr: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    duration_ms: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    evidence_ref: Mapped[Optional[dict[str, Any]]] = mapped_column(
        JSONB,
        nullable=True,
        comment="Refs to out-of-band artifacts: {crash_dump, asan_log, trace, ...}",
    )

    campaign: Mapped["HuntCampaign"] = relationship(  # noqa: F821
        back_populates="execution_logs"
    )

    __table_args__ = (
        Index("ix_execlogs_campaign_created", "campaign_id", "created_at"),
    )

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"<ExecutionLog id={self.id} campaign_id={self.campaign_id} "
            f"container={self.container_id!r} exit={self.exit_code}>"
        )
