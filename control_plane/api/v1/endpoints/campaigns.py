"""Campaign endpoints — launch and observe investigations."""
from __future__ import annotations

import logging
import uuid

from fastapi import APIRouter
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from control_plane.api.deps import SessionDep, SettingsDep
from control_plane.api.middleware import TenantDep
from control_plane.api.v1.schemas.campaign import CampaignCreate, CampaignDetail, CampaignResponse
from control_plane.db.base import CampaignStatus
from control_plane.db.models import HuntCampaign

log = logging.getLogger(__name__)
router = APIRouter(prefix="/campaigns", tags=["campaigns"])


@router.post("", response_model=CampaignResponse)
async def create_campaign(
    body: CampaignCreate,
    tenant: TenantDep,
    settings: SettingsDep,
) -> CampaignResponse:
    """Enqueue a hunt campaign. Returns immediately; work runs on the queue.

    Status is ``"queued"`` when the broker accepted the task, else
    ``"queued_no_broker"`` (e.g. Redis not running in a dev environment).
    """
    campaign_id = str(uuid.uuid4())
    status = "queued_no_broker"
    try:
        from control_plane.tasks.celery_app import run_campaign_task

        run_campaign_task.delay(
            body.target_id,
            body.target_path,
            repo_url=body.repo_url,
            commit_hash=body.commit_hash,
            nuclei_target=body.nuclei_target,
            max_iterations=body.max_iterations,
            token_budget=body.token_budget,
        )
        status = "queued"
    except Exception as exc:  # no broker in dev/test
        log.warning("could not enqueue campaign: %s", exc)
    return CampaignResponse(campaign_id=campaign_id, status=status)


@router.get("/{campaign_id}", response_model=CampaignDetail)
async def get_campaign(campaign_id: str, tenant: TenantDep, session: SessionDep) -> CampaignDetail:
    """Fetch a campaign's status, budget consumption, and finding count."""
    try:
        cid = uuid.UUID(campaign_id)
        row: HuntCampaign | None = (
            await session.execute(select(HuntCampaign).where(HuntCampaign.id == cid))
        ).scalar_one_or_none()
    except (ValueError, Exception) as exc:  # noqa: BLE001 — best-effort lookup
        log.debug("get_campaign lookup failed: %s", exc)
        row = None

    if row is None:
        # DB unavailable / not yet persisted (dev): return a placeholder.
        return CampaignDetail(id=campaign_id, status=CampaignStatus.PENDING)

    return CampaignDetail(
        id=str(row.id),
        target_id=str(row.target_id),
        status=row.status,
        current_iteration=row.current_iteration,
        max_iterations=row.max_iterations,
        tokens_used=row.tokens_used,
        token_budget=row.token_budget,
        findings_count=len(row.findings),
        started_at=str(row.started_at) if row.started_at else None,
        finished_at=str(row.finished_at) if row.finished_at else None,
    )
