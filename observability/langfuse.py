"""Langfuse LLM tracing — prompts, tokens, latency, cost per LLM call.

Wraps each gateway call in a traceable generation. The Langfuse client is built
lazily from ``LANGFUSE_PUBLIC_KEY`` / ``LANGFUSE_SECRET_KEY`` (read directly, as
the SDK expects) and ``APP_LANGFUSE_HOST``; when keys are absent this module is
a no-op, recording nothing. The :func:`trace_generation` context manager always
yields a record dict the caller can populate (tokens, cost) regardless.
"""
from __future__ import annotations

import logging
import os
import time
from contextlib import contextmanager
from typing import Any, Iterator, Optional

log = logging.getLogger(__name__)

__all__ = ["setup_langfuse", "trace_generation", "is_enabled"]

_client: Any = None


def _settings():
    from control_plane.core.config import get_settings

    return get_settings()


def is_enabled() -> bool:
    return _client is not None


def setup_langfuse() -> Optional[Any]:
    """Build the Langfuse client from env. Returns ``None`` if unconfigured."""
    global _client
    public_key = os.environ.get("LANGFUSE_PUBLIC_KEY")
    secret_key = os.environ.get("LANGFUSE_SECRET_KEY")
    host = _settings().langfuse_host
    if not (public_key and secret_key):
        log.info("Langfuse disabled (LANGFUSE_PUBLIC_KEY/SECRET_KEY not set)")
        return None
    try:
        from langfuse import Langfuse

        _client = Langfuse(host=host, public_key=public_key, secret_key=secret_key)
        log.info("Langfuse tracing -> %s", host)
        return _client
    except Exception as exc:  # pragma: no cover - optional dependency
        log.warning("Langfuse unavailable: %s", exc)
        return None


@contextmanager
def trace_generation(
    name: str,
    *,
    model: Optional[str] = None,
    prompt: Optional[str] = None,
    metadata: Optional[dict[str, Any]] = None,
) -> Iterator[dict[str, Any]]:
    """Trace one LLM generation. Yields a record to populate before exit.

    The caller fills ``record["output"]``, ``record["usage"]`` (prompt/completion
    tokens), and ``record["cost"]``; on exit, if a client is configured, a
    Langfuse generation is recorded. Always no-ops cleanly without a client.
    """
    start = time.perf_counter()
    record: dict[str, Any] = {
        "name": name,
        "model": model,
        "prompt": prompt,
        "metadata": metadata or {},
        "output": None,
        "usage": {},
        "cost": None,
    }
    try:
        yield record
    finally:
        latency_ms = int((time.perf_counter() - start) * 1000)
        record["latency_ms"] = latency_ms
        if _client is None:
            return
        try:
            usage = record.get("usage") or {}
            _client.generation(
                name=name,
                model=model,
                input=prompt,
                output=record.get("output"),
                usage={
                    "promptTokens": usage.get("prompt_tokens", 0),
                    "completionTokens": usage.get("completion_tokens", 0),
                    "totalTokens": usage.get("prompt_tokens", 0)
                    + usage.get("completion_tokens", 0),
                },
                metadata={**(metadata or {}), "latency_ms": latency_ms, "cost_usd": record.get("cost")},
            )
        except Exception as exc:  # pragma: no cover - never let tracing break a call
            log.debug("langfuse generation record failed: %s", exc)
