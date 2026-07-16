"""Finding endpoints — read verified findings and their evidence bundles."""
from __future__ import annotations

import uuid

from fastapi import APIRouter, HTTPException, status
from sqlalchemy import select

from control_plane.api.deps import SessionDep
from control_plane.api.middleware import TenantDep
from control_plane.api.v1.schemas.finding import EvidenceBundle
from control_plane.db.models import Finding

router = APIRouter(prefix="/findings", tags=["findings"])


@router.get("/{finding_id}/evidence", response_model=EvidenceBundle)
async def get_finding_evidence(
    finding_id: str, tenant: TenantDep, session: SessionDep
) -> EvidenceBundle:
    """Download the reproducibility bundle (PoV + sandbox evidence) for a finding."""
    finding = (
        await session.execute(
            select(Finding).where(Finding.id == uuid.UUID(finding_id))
        )
    ).scalar_one_or_none()
    if finding is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="finding not found")

    return EvidenceBundle(
        finding_id=str(finding.id),
        pov_script=finding.pov_ref,
        evidence=finding.evidence_ref or {},
        patch=None,  # populated from the serialized transcript when wired
    )
