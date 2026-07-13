"""SQLAlchemy ORM models for the BugFund control-plane database.

Persistence schema for campaign orchestration:

* ``Target``        — the system under test (repo URL, commit, build instructions).
* ``HuntCampaign``  — one investigation run against a target + its budget envelope.
* ``AgentState``    — a serialized LangGraph swarm-state snapshot (the memory buffer).
* ``ExecutionLog``  — stdout / stderr / exit-code captured from a Docker sandbox run.

Target dialect: PostgreSQL 15+ (native ``UUID`` and ``JSONB``). ``gen_random_uuid()``
is in core since PG13, so no extension is required.

This is a single-file schema (per request). It can be split into per-model modules
later by moving ``Base`` into ``control_plane/db/base.py`` without changing any
column definitions.
"""
from __future__ import annotations

import enum
import uuid
from datetime import datetime
from typing import Any, Optional

from sqlalchemy import (
    BigInteger,
    DateTime,
    Enum as SAEnum,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

__all__ = [
    "Base",
    "UUIDPKMixin",
    "TimestampMixin",
    "IngestionStatus",
    "CampaignStatus",
    "Target",
    "HuntCampaign",
    "AgentState",
    "ExecutionLog",
]


# --------------------------------------------------------------------------- #
# Base + reusable mixins
# --------------------------------------------------------------------------- #
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
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )


# String enums keep DB values stable & JSON-friendly regardless of member name.
def _enum_values(e: type[enum.Enum]) -> list[str]:
    return [m.value for m in e]


# --------------------------------------------------------------------------- #
# Enumerations
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


# --------------------------------------------------------------------------- #
# Core tables
# --------------------------------------------------------------------------- #
class Target(UUIDPKMixin, TimestampMixin, Base):
    """The system under test.

    ``build_instructions`` is JSONB so it can carry structured, reproducible
    build metadata (commands, environment, base image, language toolchain)
    rather than freeform text.
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
        SAEnum(
            IngestionStatus,
            name="ingestion_status",
            values_callable=_enum_values,
        ),
        nullable=False,
        default=IngestionStatus.PENDING,
    )

    campaigns: Mapped[list["HuntCampaign"]] = relationship(
        back_populates="target",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

    __table_args__ = (
        Index("ix_targets_repo_commit", "repo_url", "commit_hash"),
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return (
            f"<Target id={self.id} name={self.name!r} "
            f"commit={self.commit_hash!r} status={self.ingestion_status.value}>"
        )


class HuntCampaign(UUIDPKMixin, TimestampMixin, Base):
    """One investigation run against a :class:`Target`.

    Carries the budget envelope the Supervisor enforces: ``token_budget`` /
    ``max_iterations`` set the ceiling; ``tokens_used`` / ``current_iteration``
    track consumption so the orchestrator can terminate cleanly.
    """

    __tablename__ = "hunt_campaigns"

    target_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("targets.id", ondelete="CASCADE"),
        nullable=False,
    )
    status: Mapped[CampaignStatus] = mapped_column(
        SAEnum(
            CampaignStatus,
            name="campaign_status",
            values_callable=_enum_values,
        ),
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
    started_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    finished_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    target: Mapped["Target"] = relationship(back_populates="campaigns")
    agent_states: Mapped[list["AgentState"]] = relationship(
        back_populates="campaign",
        cascade="all, delete-orphan",
        passive_deletes=True,
        order_by="AgentState.step",
    )
    execution_logs: Mapped[list["ExecutionLog"]] = relationship(
        back_populates="campaign",
        cascade="all, delete-orphan",
        passive_deletes=True,
        order_by="ExecutionLog.created_at",
    )

    __table_args__ = (
        Index("ix_campaigns_target_status", "target_id", "status"),
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return (
            f"<HuntCampaign id={self.id} target_id={self.target_id} "
            f"status={self.status.value} iter={self.current_iteration}/"
            f"{self.max_iterations} tok={self.tokens_used}/{self.token_budget}>"
        )


class AgentState(UUIDPKMixin, TimestampMixin, Base):
    """A serialized LangGraph swarm-state snapshot.

    ``state`` holds the JSON memory buffer the swarm nodes read/write (target
    handle, threat model, CWE backlog, Actor/Critic transcript, evidence,
    budget counters). ``checkpoint_id`` cross-references the LangGraph
    checkpointer so a row can be tied to a resumable graph checkpoint.
    """

    __tablename__ = "agent_states"

    campaign_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("hunt_campaigns.id", ondelete="CASCADE"),
        nullable=False,
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

    campaign: Mapped["HuntCampaign"] = relationship(back_populates="agent_states")

    __table_args__ = (
        Index("ix_agent_states_campaign_step", "campaign_id", "step"),
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return (
            f"<AgentState id={self.id} campaign_id={self.campaign_id} "
            f"node={self.node_name!r} step={self.step}>"
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
        ForeignKey("hunt_campaigns.id", ondelete="CASCADE"),
        nullable=False,
    )
    container_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    exit_code: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    stdout: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    stderr: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    duration_ms: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    started_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    finished_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    evidence_ref: Mapped[Optional[dict[str, Any]]] = mapped_column(
        JSONB,
        nullable=True,
        comment="Refs to out-of-band artifacts: {crash_dump, asan_log, trace, ...}",
    )

    campaign: Mapped["HuntCampaign"] = relationship(back_populates="execution_logs")

    __table_args__ = (
        Index("ix_execlogs_campaign_created", "campaign_id", "created_at"),
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return (
            f"<ExecutionLog id={self.id} campaign_id={self.campaign_id} "
            f"container={self.container_id!r} exit={self.exit_code}>"
        )
