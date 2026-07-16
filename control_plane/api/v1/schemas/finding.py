"""Finding + evidence response schemas."""
from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel

from control_plane.db.base import FindingSeverity

__all__ = ["FindingRead", "EvidenceBundle"]


class FindingRead(BaseModel):
    """A verified, reproducible finding (Critic-graduated)."""

    id: str
    campaign_id: str
    hypothesis_id: Optional[str] = None
    cwe: str
    severity: FindingSeverity
    cvss_score: Optional[float] = None
    title: str
    description: str = ""
    verified: bool = True
    patch_verified: Optional[bool] = None


class EvidenceBundle(BaseModel):
    """The reproducibility artifacts for a finding (PoV + sandbox evidence)."""

    finding_id: str
    pov_script: Optional[str] = None
    evidence: dict[str, Any] = {}
    patch: Optional[dict[str, Any]] = None
