"""Celery task records — durable pointers into the async task queue.

Each campaign-launching or sandbox job gets a row here so the API can report
task state (``GET /tasks/{id}``) without coupling to Celery's result backend
directly. ``state`` mirrors Celery's task states.
"""
from __future__ import annotations

import uuid
from typing import Any, Optional

from sqlalchemy import ForeignKey, Index, String, Text
from sqlalchemy import Enum as SAEnum
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from control_plane.db.base import Base, TaskState, TimestampMixin, UUIDPKMixin, enum_values

__all__ = ["TaskRecord"]


class TaskRecord(UUIDPKMixin, TimestampMixin, Base):
    """A durable record of an async task (campaign run or sandbox job)."""

    __tablename__ = "task_records"

    campaign_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        ForeignKey("hunt_campaigns.id", ondelete="CASCADE"), nullable=True, index=True
    )
    celery_task_id: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    task_name: Mapped[str] = mapped_column(String(128), nullable=False)
    state: Mapped[TaskState] = mapped_column(
        SAEnum(TaskState, name="task_state", values_callable=enum_values),
        nullable=False,
        default=TaskState.PENDING,
    )
    result_ref: Mapped[Optional[dict[str, Any]]] = mapped_column(JSONB, nullable=True)
    error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    campaign: Mapped[Optional["HuntCampaign"]] = relationship(  # noqa: F821
        back_populates="tasks"
    )

    __table_args__ = (
        Index("ix_task_records_state", "state"),
    )

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"<TaskRecord id={self.id} celery={self.celery_task_id!r} "
            f"name={self.task_name!r} state={self.state.value}>"
        )
