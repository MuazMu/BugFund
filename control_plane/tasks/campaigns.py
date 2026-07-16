"""Campaign tasks — the Celery entrypoints that drive a hunt to completion."""
from __future__ import annotations

import asyncio
import logging

from control_plane.orchestrator.graph import build_initial_state, run_campaign
from control_plane.tasks.celery_app import app

log = logging.getLogger(__name__)

__all__ = ["run_campaign_task"]


@app.task(name="bugfund.campaigns.run_campaign_task", bind=True)
def run_campaign_task(self, target_id, target_path, **opts):
    """Run a hunt campaign to completion and return a summary dict.

    Offloads the (potentially long) LangGraph run from the API request path.
    Failures are caught and reported as a ``{"status": "failed", ...}`` payload
    rather than raising, so the Celery result stays inspectable.
    """
    state = build_initial_state(target_id, target_path, **opts)
    try:
        result = asyncio.run(run_campaign(state))
        return {
            "status": result.get("status"),
            "iterations": result.get("iteration", 0),
            "findings": result.get("findings", []),
        }
    except Exception as exc:  # pragma: no cover - defensive
        log.exception("campaign %s failed", self.request.id)
        return {"status": "failed", "error": str(exc)}
