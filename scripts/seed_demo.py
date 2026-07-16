"""Seed a demo target and launch a BugFund campaign against the local API.

Run with::

    python -m scripts.seed_demo

This is a best-effort dev smoke test. It uses only the standard library
(``urllib``, ``json``) so it has no extra dependencies beyond the project
itself. It:

  1. Reads the typed ``Settings`` (so the API base URL / prefix come from the
     same env-driven config the server uses).
  2. POSTs a small demo Target payload to ``POST /api/v1/targets``.
  3. POSTs a HuntCampaign against that target to ``POST /api/v1/campaigns``.
  4. Prints both responses.

If the API, broker, or database is not up, the script degrades gracefully and
prints a helpful message rather than raising. It never hard-fails a dev
environment that hasn't been fully bootstrapped yet.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any


def _post_json(url: str, payload: dict[str, Any], timeout: float = 5.0) -> dict[str, Any]:
    """POST ``payload`` as JSON to ``url`` and return the parsed JSON response.

    Uses only :mod:`urllib` to keep this script dependency-light. Raises
    :class:`urllib.error.URLError` on network failure or
    :class:`SystemExit`-friendly messages on non-2xx responses.
    """
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = resp.read().decode("utf-8")
    return json.loads(body) if body else {}


def main() -> int:
    # Import settings lazily so the script can still print a helpful message
    # if the project config itself is misconfigured.
    try:
        from control_plane.core.config import get_settings

        settings = get_settings()
    except Exception as exc:  # pragma: no cover - dev-time guard
        print(f"[seed_demo] Could not load BugFund settings: {exc}")
        print("[seed_demo] Is the project installed (`pip install -e .`) and .env present?")
        return 1

    base = f"http://localhost:8000{settings.APP_API_PREFIX}".rstrip("/")
    # NOTE: a dev API typically has no auth middleware active; if auth is on,
    # set the API key header here before calling.

    # --- 1. Seed a demo target ------------------------------------------------
    target_payload = {
        "name": "demo-target",
        "kind": "image",
        # Use the hardened target ingestion image built via `make sandbox-images`.
        "ref": "bugfund/sandbox-target:latest",
        "notes": "Seeded by scripts.seed_demo for a local smoke test.",
    }

    try:
        print(f"[seed_demo] POST {base}/targets ...")
        target = _post_json(f"{base}/targets", target_payload)
        target_id = target.get("id")
        print(f"[seed_demo]   -> target_id={target_id}")
    except urllib.error.URLError as exc:
        print(f"[seed_demo] Could not reach the API at {base}/targets: {exc}")
        print("[seed_demo] Start the API first:  make api   (or)   uvicorn control_plane.api.main:app --reload")
        return 1
    except Exception as exc:  # pragma: no cover - dev-time guard
        print(f"[seed_demo] Target ingest failed: {exc}")
        return 1

    if not target_id:
        print("[seed_demo] Target response had no 'id'; aborting campaign launch.")
        return 1

    # --- 2. Launch a campaign against it -------------------------------------
    campaign_payload = {
        "target_id": target_id,
        # Sensible dev defaults; the server applies its own caps on top.
        "max_steps": 25,
        "max_tokens_usd": 5.0,
    }

    try:
        print(f"[seed_demo] POST {base}/campaigns ...")
        campaign = _post_json(f"{base}/campaigns", campaign_payload)
        campaign_id = campaign.get("id")
        task_id = campaign.get("task_id")
        print(f"[seed_demo]   -> campaign_id={campaign_id}  task_id={task_id}")
        print("[seed_demo] OK. Poll status with:")
        print(f"[seed_demo]   curl {base}/campaigns/{campaign_id}")
        print(f"[seed_demo]   curl {base}/tasks/{task_id}")
    except Exception as exc:  # pragma: no cover - dev-time guard
        print(f"[seed_demo] Campaign launch failed: {exc}")
        print("[seed_demo] Is the Celery worker up?  make worker")
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
