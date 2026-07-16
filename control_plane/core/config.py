"""Typed, env-driven configuration for the BugFund control plane.

All runtime knobs live on :class:`Settings` (read from ``APP_*`` env vars or a
``.env`` file via pydantic-settings). Cross-cutting concerns have been split
into sibling modules — ``exceptions.py``, ``logging.py``, ``security.py`` —
and are re-exported here so existing imports (``from control_plane.core.config
import BudgetExceeded``) keep working during the modularization.
"""
from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict

# Re-exported for backward compatibility (formerly inlined here).
from control_plane.core.exceptions import (  # noqa: F401
    BudgetExceeded,
    Conflict,
    ControlPlaneError,
    NotFound,
    Unauthorized,
    ValidationFailed,
)
from control_plane.core.logging import setup_logging  # noqa: F401

__all__ = [
    "Settings",
    "get_settings",
    # re-exports
    "ControlPlaneError",
    "NotFound",
    "BudgetExceeded",
    "ValidationFailed",
    "Conflict",
    "Unauthorized",
    "setup_logging",
]


class Settings(BaseSettings):
    """Process-wide configuration.

    Env prefix is ``APP_`` (e.g. ``APP_DATABASE_URL``). Provider SDKs, the
    OTel SDK, and Langfuse read their own conventional env vars directly
    (``ANTHROPIC_API_KEY``, ``OTEL_EXPORTER_OTLP_ENDPOINT``, ``LANGFUSE_*``).
    """

    model_config = SettingsConfigDict(env_file=".env", env_prefix="APP_", extra="ignore")

    # ── app ──
    env: str = "dev"
    log_level: str = "INFO"
    api_prefix: str = "/api/v1"

    # ── datastores / queue ──
    database_url: str = "postgresql+asyncpg://bugfund:bugfund@localhost:5432/bugfund"
    redis_url: str = "redis://localhost:6379/0"
    celery_queues: str = "campaigns,sandbox"

    # ── LLM gateway ──
    llm_model: str = "claude-3-5-sonnet"
    llm_routing_config: str = "ai_gateway/config/providers.yaml"

    # ── execution engine ──
    sandbox_max_concurrency: int = 4
    sandbox_timeout_s: int = 30
    sandbox_no_egress: bool = True
    sandbox_image: str = "ubuntu:22.04"
    targets_root: str = "/var/bugfund/targets"

    # ── campaign budgets ──
    campaign_max_steps: int = 20
    campaign_max_tokens: int = 200_000
    campaign_max_usd: float = 5.0

    # ── API / tenancy ──
    api_keys_enabled: bool = True
    default_page_size: int = 50
    rate_limit_rpm: int = 120  # per-tenant requests/minute (0 = unlimited)

    # ── observability (empty endpoint == disabled) ──
    otel_endpoint: str = ""
    langfuse_host: str = "https://cloud.langfuse.com"


@lru_cache
def get_settings() -> Settings:
    """Return the cached singleton :class:`Settings`."""
    return Settings()
