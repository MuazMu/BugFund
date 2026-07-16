"""Unified chat/completion/embedding entrypoint — the canonical gateway surface.

For schema-validated agent output use :func:`generate_structured_response`
(re-exported here); for raw completions or embeddings (e.g. long-term-memory
vectorization) use :func:`complete_async` / :func:`embed_async`. All routes go
through LiteLLM so provider selection stays centralized.
"""
from __future__ import annotations

from typing import Any

from ai_gateway import (  # noqa: F401  (re-exported)
    generate_structured_response,
    generate_structured_response_async,
)
from ai_gateway.base import GatewayError
from ai_gateway.litellm_provider import LiteLLMProvider

__all__ = [
    "generate_structured_response",
    "generate_structured_response_async",
    "complete_async",
    "embed_async",
    "GatewayError",
]


async def complete_async(
    model: str,
    messages: list[dict[str, Any]],
    *,
    temperature: float = 0.0,
    timeout: float = 90.0,
    **kwargs: Any,
) -> str:
    """Raw async chat completion; returns the assistant text."""
    import litellm  # lazy

    resp = await litellm.acompletion(
        model=model, messages=messages, temperature=temperature, timeout=timeout, **kwargs
    )
    return LiteLLMProvider._extract_content(resp)


async def embed_async(model: str, input: str, **kwargs: Any) -> list[float]:
    """Async embedding; returns the embedding vector for ``input``."""
    import litellm  # lazy

    resp = await litellm.aembedding(model=model, input=input, **kwargs)
    try:
        return resp["data"][0]["embedding"]  # type: ignore[index]
    except (KeyError, IndexError, TypeError) as exc:
        raise GatewayError(f"unexpected embedding response shape: {exc}") from exc
