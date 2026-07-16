"""Hunt campaigns — one investigation run against a target + its budget envelope."""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import BigInteger, DateTime, ForeignKey, Index, Integer
from sqlalchemy import Enum as SAEnum
from sqlalchemy.orm import Mapped, mapped_column, relationship

from control_plane.db.base import (
    Base,
    CampaignStatus,
    TimestampMixin,
    UUIDPKMixin,
    enum_values,
)

__all__ = ["HuntCampaign"]


class HuntCampaign(UUIDPKMixin, TimestampMixin, Base):
    """One investigation run against a :class:`Target`.

    Carries the budget envelope the Supervisor enforces: ``token_budget`` /
    ``max_iterations`` set the ceiling; ``tokens_used`` / ``current_iteration``
    track consumption so the orchestrator can terminate cleanly.
    """

    __tablename__ = "hunt_campaigns"

    target_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("targets.id", ondelete="CASCADE"), nullable=False
    )
    status: Mapped[CampaignStatus] = mapped_column(
        SAEnum(CampaignStatus, name="campaign_status", values_callable=enum_values),
        nullable=False,
        default=CampaignStatus.PENDING,
    )

    # Budget envelope (set at creation, immutable in spirit).
    token_budget: Mapped[int] = mapped_column(BigInteger, nullable=False)
    max_iterations: Mapped[int] = mapped_column(Integer, nullable=False)

    # Live consumption (advanced by the orchestrator).
    tokens_used: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    current_iteration: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # Run-window timestamps (distinct from the row audit timestamps).
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    target: Mapped["Target"] = relationship(back_populates="campaigns")  # noqa: F821
    agent_states: Mapped[list["AgentState"]] = relationship(  # noqa: F821
        back_populates="campaign",
        cascade="all, delete-orphan",
        passive_deletes=True,
        order_by="AgentState.step",
    )
    execution_logs: Mapped[list["ExecutionLog"]] = relationship(  # noqa: F821
        back_populates="campaign",
        cascade="all, delete-orphan",
        passive_deletes=True,
        order_by="ExecutionLog.created_at",
    )
    findings: Mapped[list["Finding"]] = relationship(  # noqa: F821
        back_populates="campaign",
        cascade="all, delete-orphan",
        passive_deletes=True,
        order_by="Finding.created_at",
    )
    tasks: Mapped[list["TaskRecord"]] = relationship(  # noqa: F821
        back_populates="campaign",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

    __table_args__ = (
        Index("ix_campaigns_target_status", "target_id", "status"),
    )

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"<HuntCampaign id={self.id} target_id={self.target_id} "
            f"status={self.status.value} iter={self.current_iteration}/"
            f"{self.max_iterations} tok={self.tokens_used}/{self.token_budget}>"
        )
