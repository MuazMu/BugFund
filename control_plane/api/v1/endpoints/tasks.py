"""Task endpoints — async (Celery) task status."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, status

from control_plane.api.deps import SettingsDep

router = APIRouter(prefix="/tasks", tags=["tasks"])


@router.get("/{task_id}")
async def get_task(task_id: str, settings: SettingsDep) -> dict:
    """Report an async task's state by querying Celery's result backend.

    Best-effort: returns ``{"state": "unknown"}`` when the broker/result backend
    is unreachable (dev without Redis).
    """
    try:
        from control_plane.tasks.celery_app import app as celery_app

        result = celery_app.AsyncResult(task_id)
        return {
            "task_id": task_id,
            "state": result.state,
            "ready": result.ready(),
        }
    except Exception as exc:  # no broker in dev/test
        return {"task_id": task_id, "state": "unknown", "note": str(exc)}
