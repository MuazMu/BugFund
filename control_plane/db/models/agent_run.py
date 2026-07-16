"""Serialized LangGraph swarm-state snapshots (the resumable memory buffer)."""
from __future__ import annotations

import uuid
from typing import Any, Optional

from sqlalchemy import ForeignKey, Index, Integer, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from control_plane.db.base import Base, TimestampMixin, UUIDPKMixin

__all__ = ["AgentState"]


class AgentState(UUIDPKMixin, TimestampMixin, Base):
    """A serialized LangGraph swarm-state snapshot.

    ``state`` holds the JSON memory buffer the swarm nodes read/write (target
    handle, threat model, CWE backlog, Actor/Critic transcript, evidence,
    budget counters). ``checkpoint_id`` cross-references the LangGraph
    checkpointer so a row can be tied to a resumable graph checkpoint.
    """

    __tablename__ = "agent_states"

    campaign_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("hunt_campaigns.id", ondelete="CASCADE"), nullable=False
    )
    node_name: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        comment="Producing node: supervisor|threat_modeler|actor|critic|reporter",
    )
    step: Mapped[int] = mapped_column(Integer, nullable=False)
    state: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        comment="Serialized LangGraph swarm state (memory buffer)",
    )
    checkpoint_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)

    campaign: Mapped["HuntCampaign"] = relationship(  # noqa: F821
        back_populates="agent_states"
    )

    __table_args__ = (
        Index("ix_agent_states_campaign_step", "campaign_id", "step"),
    )

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"<AgentState id={self.id} campaign_id={self.campaign_id} "
            f"node={self.node_name!r} step={self.step}>"
        )
