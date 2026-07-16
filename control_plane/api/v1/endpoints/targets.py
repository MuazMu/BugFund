"""Target endpoints — ingest and inspect test targets."""
from __future__ import annotations

import logging
import uuid

from fastapi import APIRouter, HTTPException, status
from sqlalchemy import func, select

from control_plane.api.deps import PageDep, SessionDep
from control_plane.api.middleware import TenantDep
from control_plane.api.middleware.tenant import TenantContext
from control_plane.api.v1.schemas.common import Page
from control_plane.api.v1.schemas.finding import FindingRead
from control_plane.api.v1.schemas.target import TargetCreate, TargetRead
from control_plane.db.base import IngestionStatus
from control_plane.db.models import Finding, HuntCampaign, Target

log = logging.getLogger(__name__)
router = APIRouter(prefix="/targets", tags=["targets"])


def _tenant_scope(stmt, tenant: TenantContext):
    """Apply the tenant filter when running in a real (non-dev) context."""
    if tenant.tenant_id is not None:
        return stmt.where(Target.tenant_id == tenant.tenant_id)
    return stmt


@router.post("", response_model=TargetRead, status_code=status.HTTP_201_CREATED)
async def create_target(
    body: TargetCreate, tenant: TenantDep, session: SessionDep
) -> TargetRead:
    """Ingest a target source tree (status starts ``pending``)."""
    target = Target(
        name=body.name,
        repo_url=str(body.repo_url),
        commit_hash=body.commit_hash,
        build_instructions=body.build_instructions,
        language=body.language,
        ingestion_status=IngestionStatus.PENDING,
        tenant_id=tenant.tenant_id,
    )
    session.add(target)
    await session.commit()
    await session.refresh(target)
    return TargetRead(
        id=str(target.id),
        name=target.name,
        repo_url=target.repo_url,
        commit_hash=target.commit_hash,
        language=target.language,
        ingestion_status=target.ingestion_status,
    )


@router.get("/{target_id}", response_model=TargetRead)
async def get_target(target_id: str, tenant: TenantDep, session: SessionDep) -> TargetRead:
    """Fetch a target's metadata + ingestion status."""
    stmt = _tenant_scope(
        select(Target).where(Target.id == uuid.UUID(target_id)), tenant
    )
    target = (await session.execute(stmt)).scalar_one_or_none()
    if target is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="target not found")
    return TargetRead(
        id=str(target.id),
        name=target.name,
        repo_url=target.repo_url,
        commit_hash=target.commit_hash,
        language=target.language,
        ingestion_status=target.ingestion_status,
    )


@router.get("/{target_id}/findings", response_model=Page[FindingRead])
async def list_target_findings(
    target_id: str,
    tenant: TenantDep,
    session: SessionDep,
    page: PageDep,
) -> Page[FindingRead]:
    """List verified findings produced for a target (tenant-scoped)."""
    tid = uuid.UUID(target_id)
    base = (
        select(Finding)
        .join(HuntCampaign, Finding.campaign_id == HuntCampaign.id)
        .where(HuntCampaign.target_id == tid)
    )
    if tenant.tenant_id is not None:
        base = base.join(Target, HuntCampaign.target_id == Target.id).where(
            Target.tenant_id == tenant.tenant_id
        )

    total = (await session.execute(select(func.count()).select_from(base.subquery()))).scalar_one()
    rows = (
        await session.execute(base.offset(page["offset"]).limit(page["limit"]))
    ).scalars().all()

    return Page[FindingRead](
        items=[
            FindingRead(
                id=str(f.id),
                campaign_id=str(f.campaign_id),
                hypothesis_id=f.hypothesis_id,
                cwe=f.cwe,
                severity=f.severity,
                cvss_score=f.cvss_score,
                title=f.title,
                description=f.description,
                verified=f.verified,
                patch_verified=f.patch_verified,
            )
            for f in rows
        ],
        total=total,
        limit=page["limit"],
        offset=page["offset"],
    )
