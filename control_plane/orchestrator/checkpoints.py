"""LangGraph checkpointers — durable campaign state for resume & replay.

A campaign run with a checkpointer can be paused, resumed after a crash, and
replayed end-to-end for auditing. Postgres is the production backend; an
in-memory saver is the dev/test default.

The Postgres saver requires an async psycopg pool and an ``await saver.setup()``
call before first use — so this module exposes async-aware factories and degrades
to an in-memory saver (or ``None``) when the optional dependency is absent,
keeping the orchestrator importable in minimal environments.
"""
from __future__ import annotations

import logging
from typing import Any, Optional

log = logging.getLogger(__name__)

__all__ = [
    "build_memory_checkpointer",
    "build_async_postgres_checkpointer",
    "build_checkpointer",
]


def build_memory_checkpointer() -> Any:
    """Return a process-local in-memory checkpointer (dev/test only)."""
    from langgraph.checkpoint.memory import MemorySaver

    return MemorySaver()


async def build_async_postgres_checkpointer(database_url: Optional[str] = None) -> Any:
    """Build & initialize an async Postgres-backed LangGraph checkpointer.

    Args:
        database_url: Sync ``postgresql://`` URL (not ``+asyncpg``). Defaults to
            the app setting with any driver suffix stripped.

    Raises:
        RuntimeError: if the ``langgraph-checkpoint-postgres`` extra (and async
            psycopg) are not installed.
    """
    try:
        from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver
    except ImportError as exc:  # pragma: no cover - optional dependency
        raise RuntimeError(
            "Postgres checkpointer requires `pip install langgraph-checkpoint-postgres` "
            "with async psycopg."
        ) from exc

    if database_url is None:
        from control_plane.core.config import get_settings

        database_url = get_settings().database_url.split("+", 1)[0]

    from psycopg_pool import AsyncConnectionPool  # type: ignore[import-not-found]

    pool = AsyncConnectionPool(conninfo=database_url, max_size=20, open=False)
    await pool.open()
    saver = AsyncPostgresSaver(pool)
    await saver.setup()
    log.info("Postgres LangGraph checkpointer initialized")
    return saver


def build_checkpointer(database_url: Optional[str] = None, *, use_postgres: bool = False) -> Any:
    """Synchronous factory: a memory saver by default, else attempt Postgres.

    The Postgres async saver cannot be constructed synchronously; when
    ``use_postgres=True`` this logs and falls back to a memory saver so callers
    that don't await can still proceed. Prefer :func:`build_async_postgres_checkpointer`
    in async contexts.
    """
    if use_postgres:
        log.warning(
            "build_checkpointer(use_postgres=True) is sync; falling back to a memory "
            "saver. Use build_async_postgres_checkpointer() in async contexts."
        )
    return build_memory_checkpointer()
