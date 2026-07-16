"""Shared API schemas: pagination, error envelopes, reusable generics."""
from __future__ import annotations

from typing import Any, Generic, Optional, TypeVar

from pydantic import BaseModel, Field

T = TypeVar("T")

__all__ = ["PageParams", "Page", "ErrorEnvelope"]


class PageParams(BaseModel):
    """Pagination query params (``?limit=50&offset=0``)."""

    limit: int = Field(default=50, ge=1, le=500)
    offset: int = Field(default=0, ge=0)


class Page(BaseModel, Generic[T]):
    """A page of results plus the total count for paging UIs."""

    items: list[T]
    total: int = 0
    limit: int
    offset: int


class ErrorEnvelope(BaseModel):
    """The standard JSON error body returned by the exception handlers."""

    code: str = Field(description="Stable machine error code, e.g. 'not_found'.")
    message: str
    request_id: Optional[str] = None
    details: Optional[dict[str, Any]] = None
