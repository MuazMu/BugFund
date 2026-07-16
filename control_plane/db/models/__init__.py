"""ORM model package.

Importing this package registers every model on the shared ``Base.metadata``
(used by ``init_db`` and Alembic autogenerate). All public symbols — legacy
and new — are re-exported so ``from control_plane.db.models import Target,
HuntCampaign, AgentState, ExecutionLog, Base`` (and the new tenant/finding/task
models) all resolve.
"""
from __future__ import annotations

from control_plane.db.base import (
    Base,
    CampaignStatus,
    FindingSeverity,
    IngestionStatus,
    TaskState,
    TenantScopedMixin,
    TimestampMixin,
    UUIDPKMixin,
    enum_values,
)
from control_plane.db.models.agent_run import AgentState
from control_plane.db.models.campaign import HuntCampaign
from control_plane.db.models.finding import ExecutionLog, Finding
from control_plane.db.models.target import Target
from control_plane.db.models.task import TaskRecord
from control_plane.db.models.tenant import ApiKey, Quota, Tenant

__all__ = [
    # base + mixins + enums
    "Base",
    "UUIDPKMixin",
    "TimestampMixin",
    "TenantScopedMixin",
    "enum_values",
    "IngestionStatus",
    "CampaignStatus",
    "TaskState",
    "FindingSeverity",
    # entities
    "Tenant",
    "ApiKey",
    "Quota",
    "Target",
    "HuntCampaign",
    "AgentState",
    "ExecutionLog",
    "Finding",
    "TaskRecord",
]
