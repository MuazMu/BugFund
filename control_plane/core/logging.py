"""Structured logging setup for the BugFund control plane.

A single :func:`setup_logging` entrypoint configures the root logger with a
consistent format. Idempotent: calling it repeatedly only adjusts the level.
"""
from __future__ import annotations

import logging

__all__ = ["setup_logging", "LOG_FORMAT"]

LOG_FORMAT = "%(asctime)s %(levelname)s %(name)s :: %(message)s"


def setup_logging(level: str | None = None) -> None:
    """Configure root logging once.

    Args:
        level: Optional explicit level (e.g. ``"DEBUG"``). Defaults to the
            ``APP_LOG_LEVEL`` setting.
    """
    # Imported lazily to avoid a config <-> logging import cycle.
    from control_plane.core.config import get_settings

    resolved = (level or get_settings().log_level).upper()
    logging.basicConfig(level=resolved, format=LOG_FORMAT)
    logging.getLogger().setLevel(resolved)
