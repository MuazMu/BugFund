"""Sandbox lifecycle jobs — the reaper, evidence GC, and budget sweeps.

Periodic Celery tasks that keep the execution engine tidy: orphaned containers
are garbage-collected, stale evidence/patch trees are removed, and campaigns
stuck past their budget window are marked failed. All are best-effort and
defensive — a missing Docker daemon or DB must never crash the beat scheduler.
"""
from __future__ import annotations

import logging
import shutil
import time
from pathlib import Path

from control_plane.tasks.celery_app import app

log = logging.getLogger(__name__)

__all__ = ["reap_orphaned_containers", "evidence_gc", "campaign_budget_sweep"]

# Containers created by the execution engine carry this label.
_SANDBOX_LABEL = {"app": "bugfund"}


@app.task(name="bugfund.sandbox.reap_orphans")
def reap_orphaned_containers(max_age_seconds: int = 3600) -> dict:
    """Force-remove exited/ancient bugfund sandbox containers.

    Args:
        max_age_seconds: Remove containers older than this (created time).

    Returns:
        A small ``{"removed": n, "errors": n}`` summary.
    """
    removed = errors = 0
    try:
        import docker  # lazy: keeps the task importable without the SDK

        client = docker.from_env()
        cutoff = time.time() - max_age_seconds
        for ctr in client.containers.list(all=True, filters={"label": "app=bugfund"}):
            created = ctr.attrs.get("Created", "")
            try:
                # Created looks like "2026-07-15T12:34:56.7890123Z"; epoch-fallible.
                ts = time.mktime(time.strptime(created[:19], "%Y-%m-%dT%H:%M:%S"))
                stale = ts < cutoff
            except (ValueError, TypeError):
                stale = False
            if ctr.status in {"exited", "dead"} or stale:
                try:
                    ctr.remove(force=True)
                    removed += 1
                except Exception as exc:  # pragma: no cover - defensive
                    errors += 1
                    log.warning("could not remove container %s: %s", ctr.id, exc)
        client.close()
    except Exception as exc:  # pragma: no cover - no docker daemon in CI
        log.warning("reap_orphaned_containers skipped: %s", exc)
    return {"removed": removed, "errors": errors}


@app.task(name="bugfund.sandbox.evidence_gc")
def evidence_gc(targets_root: str = "", *, max_age_seconds: int = 86400) -> dict:
    """Delete stale ``*.patched`` staging trees and old PoV temp dirs.

    Args:
        targets_root: Root under which ``*.patched`` dirs are GC'd. Defaults to
            the app ``APP_TARGETS_ROOT`` setting.
        max_age_seconds: Remove staging trees older than this.

    Returns:
        ``{"removed_dirs": n, "errors": n}``.
    """
    if not targets_root:
        from control_plane.core.config import get_settings

        targets_root = get_settings().targets_root

    removed = errors = 0
    root = Path(targets_root)
    if not root.is_dir():
        return {"removed_dirs": 0, "errors": 0}

    cutoff = time.time() - max_age_seconds
    for p in root.rglob("*.patched"):
        try:
            if p.is_dir() and p.stat().st_mtime < cutoff:
                shutil.rmtree(p, ignore_errors=True)
                removed += 1
        except Exception as exc:  # pragma: no cover - defensive
            errors += 1
            log.warning("evidence_gc: could not remove %s: %s", p, exc)
    return {"removed_dirs": removed, "errors": errors}


@app.task(name="bugfund.sandbox.budget_sweep")
def campaign_budget_sweep(max_age_seconds: int = 7200) -> dict:
    """Mark campaigns stuck in RUNNING past ``max_age_seconds`` as FAILED.

    A safety net for campaigns whose runner crashed without updating status.
    Best-effort: no-ops if the DB is unreachable.

    Returns:
        ``{"swept": n}``.
    """
    swept = 0
    try:
        import asyncio

        from datetime import datetime, timedelta, timezone

        from sqlalchemy import select, update

        from control_plane.db.models import CampaignStatus, HuntCampaign
        from control_plane.db.session import SessionLocal

        async def _sweep() -> int:
            cutoff = datetime.now(timezone.utc) - timedelta(seconds=max_age_seconds)
            async with SessionLocal() as session:
                res = await session.execute(
                    update(HuntCampaign)
                    .where(HuntCampaign.status == CampaignStatus.RUNNING, HuntCampaign.started_at < cutoff)
                    .values(status=CampaignStatus.FAILED)
                )
                await session.commit()
                return res.rowcount or 0

        swept = asyncio.run(_sweep())
    except Exception as exc:  # pragma: no cover - no DB in dev/test
        log.warning("campaign_budget_sweep skipped: %s", exc)
    return {"swept": swept}
