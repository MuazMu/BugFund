"""Request/response models for the internal sandbox HTTP API."""
from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field

__all__ = ["RunRequest", "RunResponse", "HealthResponse"]


class RunRequest(BaseModel):
    """A single sandboxed script execution (a PoV or smoke command)."""

    script_code: str = Field(description="Full Python source to execute.")
    env_vars: dict[str, str] = Field(default_factory=dict)
    timeout_s: int = Field(default=60, ge=1, le=600)
    network: bool = False


class RunResponse(BaseModel):
    """Captured output of a sandbox run."""

    stdout: str = ""
    stderr: str = ""
    exit_code: Optional[int] = None
    duration_ms: int = 0
    timed_out: bool = False
    container_id: Optional[str] = None


class HealthResponse(BaseModel):
    status: str
    runner: str
