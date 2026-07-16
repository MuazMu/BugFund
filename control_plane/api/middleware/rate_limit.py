"""Per-tenant rate limiting (in-memory sliding window).

A simple, dependency-free sliding-window limiter keyed by tenant slug. Adequate
for a single worker; for horizontal scaling swap in Redis (the broker is already
a dependency). A ``rate_limit_rpm`` of ``0`` disables limiting.
"""
from __future__ import annotations

import time
from collections import defaultdict, deque
from typing import Annotated

from fastapi import Depends, HTTPException, status

from control_plane.api.deps import SettingsDep
from control_plane.api.middleware.auth import authenticate
from control_plane.api.middleware.tenant import TenantContext

__all__ = ["rate_limit", "reset"]

_WINDOW_S = 60.0
# tenant_slug -> deque[monotonic timestamps within the window]
_buckets: dict[str, "deque[float]"] = defaultdict(deque)


def _prune(bucket: "deque[float]", now: float) -> None:
    while bucket and bucket[0] <= now - _WINDOW_S:
        bucket.popleft()


async def rate_limit(
    settings: SettingsDep,
    tenant: Annotated[TenantContext, Depends(authenticate)],
) -> None:
    """Reject (``429``) requests beyond ``rate_limit_rpm`` for the tenant."""
    rpm = settings.rate_limit_rpm
    if rpm <= 0:
        return

    now = time.monotonic()
    bucket = _buckets[tenant.slug]
    _prune(bucket, now)
    if len(bucket) >= rpm:
        retry = max(1, int(_WINDOW_S - (now - bucket[0])))
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded: {rpm} requests/minute.",
            headers={"Retry-After": str(retry)},
        )
    bucket.append(now)


def reset() -> None:
    """Test hook: clear all buckets."""
    _buckets.clear()
