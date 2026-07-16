"""Celery app — broker/backend, queue routing, and beat schedule.

Defines the process-wide ``app`` and wires queue routing (campaigns vs sandbox
queues) plus a beat schedule for the periodic sandbox lifecycle jobs. Task
modules are imported at the bottom so their ``@app.task`` decorators register.
"""
from __future__ import annotations

import logging

from celery import Celery

from control_plane.core.config import get_settings

log = logging.getLogger(__name__)
_settings = get_settings()

app = Celery("bugfund", broker=_settings.redis_url, backend=_settings.redis_url)
app.conf.update(
    task_default_queue="campaigns",
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    task_routes={
        "bugfund.campaigns.*": {"queue": "campaigns"},
        "bugfund.sandbox.*": {"queue": "sandbox"},
    },
    beat_schedule={
        # Periodic reaper: every 15 minutes, GC orphaned sandbox containers.
        "reap-orphaned-containers": {
            "task": "bugfund.sandbox.reap_orphans",
            "schedule": 900.0,
            "kwargs": {"max_age_seconds": 3600},
        },
        # Daily evidence + budget cleanup.
        "evidence-gc": {
            "task": "bugfund.sandbox.evidence_gc",
            "schedule": 86400.0,
        },
        "budget-sweep": {
            "task": "bugfund.sandbox.budget_sweep",
            "schedule": 3600.0,
            "kwargs": {"max_age_seconds": 7200},
        },
    },
)

# Importing the task modules registers their @app.task functions on `app`.
from control_plane.tasks import campaigns as _campaigns  # noqa: E402,F401
from control_plane.tasks import sandbox_jobs as _sandbox_jobs  # noqa: E402,F401

# Backward-compatible re-export (callers import run_campaign_task from here).
from control_plane.tasks.campaigns import run_campaign_task  # noqa: E402,F401

__all__ = ["app", "run_campaign_task"]
