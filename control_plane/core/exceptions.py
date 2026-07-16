"""Domain exception hierarchy for the BugFund control plane.

A small, single-rooted hierarchy so API middleware can map each family to a
consistent HTTP response (see ``control_plane/api/middleware``) and Celery
tasks can distinguish recoverable from terminal failures.

Previously these lived in ``config.py``; split out so ``config.py`` only holds
settings. ``config.py`` still re-exports them for backward compatibility.
"""
from __future__ import annotations

__all__ = [
    "ControlPlaneError",
    "NotFound",
    "BudgetExceeded",
    "ValidationFailed",
    "Conflict",
    "Unauthorized",
]


class ControlPlaneError(Exception):
    """Base class for all control-plane domain errors."""


class NotFound(ControlPlaneError):
    """A referenced entity (target, campaign, finding, ...) does not exist."""


class BudgetExceeded(ControlPlaneError):
    """A campaign budget (steps / tokens / USD / wall-clock) is exhausted."""


class ValidationFailed(ControlPlaneError):
    """Request payload or internal state failed validation."""


class Conflict(ControlPlaneError):
    """The operation conflicts with current state (duplicate, bad transition)."""


class Unauthorized(ControlPlaneError):
    """Authentication or tenant-authorization failed (no/invalid API key)."""
