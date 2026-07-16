"""v1 endpoint routers."""
from __future__ import annotations

from control_plane.api.v1.endpoints import campaigns, findings, health, targets, tasks

__all__ = ["health", "targets", "campaigns", "findings", "tasks"]
