"""Target request/response schemas."""
from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, Field, HttpUrl

from control_plane.db.base import IngestionStatus

__all__ = ["TargetCreate", "TargetRead"]


class TargetCreate(BaseModel):
    """Ingest a target source tree.

    ``build_instructions`` carries the reproducible build recipe
    (``{image, commands, env, language}``) persisted verbatim to JSONB.
    """

    name: str = Field(min_length=1, max_length=255)
    repo_url: HttpUrl
    commit_hash: Optional[str] = Field(default=None, max_length=64)
    build_instructions: dict[str, Any] = Field(default_factory=dict)
    language: Optional[str] = Field(default=None, max_length=64)
    nuclei_target: Optional[str] = Field(
        default=None,
        description="Optional URL/host:port for deterministic Nuclei scanning.",
    )


class TargetRead(BaseModel):
    """Public target view (tenant-scoped fields excluded)."""

    id: str
    name: str
    repo_url: str
    commit_hash: Optional[str] = None
    language: Optional[str] = None
    ingestion_status: IngestionStatus
