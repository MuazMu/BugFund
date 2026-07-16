"""Campaign request/response schemas.

``CampaignCreate.target_id`` is typed ``int`` to match the legacy ingest
contract exercised by the smoke tests; production deployments pass the target's
UUID (accepted as an ``int | str`` by the runner).
"""
from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, Field

from control_plane.db.base import CampaignStatus

__all__ = ["CampaignCreate", "CampaignResponse", "CampaignDetail"]


class CampaignCreate(BaseModel):
    """Launch a hunt campaign against a target."""

    target_id: int | str
    target_path: str
    repo_url: Optional[str] = None
    commit_hash: Optional[str] = None
    nuclei_target: Optional[str] = None
    max_iterations: int = 20
    token_budget: int = 200_000


class CampaignResponse(BaseModel):
    """Returned synchronously on launch — the heavy work runs on the queue."""

    campaign_id: str
    status: str


class CampaignDetail(BaseModel):
    """Campaign status, budget consumption, and a result summary."""

    id: str
    target_id: Optional[str] = None
    status: CampaignStatus
    current_iteration: int = 0
    max_iterations: int = 0
    tokens_used: int = 0
    token_budget: int = 0
    findings_count: int = 0
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    summary: Optional[dict[str, Any]] = None
