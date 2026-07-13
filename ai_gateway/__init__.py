"""BugFund AI Gateway — model-agnostic LLM access with enforced structured outputs.

All agent-swarm nodes import the wrapper from here rather than any provider SDK:

    from ai_gateway import generate_structured_response
    verdict: Verdict = generate_structured_response(prompt, schema=Verdict)

The wrapper resolves the default LiteLLM provider (built lazily from the
``LLM_MODEL`` env var, or whatever was registered via :func:`configure`) and
delegates to ``LLMProvider.generate_structured``, which guarantees the returned
object validates against the supplied Pydantic model and retries automatically
on malformed / plain-text responses.
"""
from __future__ import annotations

import logging
import os
from typing import Any, TypeVar

from pydantic import BaseModel

from .base import GatewayError, LLMProvider, StructuredOutputError
from .litellm_provider import LiteLLMProvider

logger = logging.getLogger(__name__)

T = TypeVar("T", bound=BaseModel)

_default_provider: LLMProvider | None = None

__all__ = [
    "LLMProvider",
    "LiteLLMProvider",
    "GatewayError",
    "StructuredOutputError",
    "get_provider",
    "configure",
    "generate_structured_response",
    "generate_structured_response_async",
]


def configure(provider: LLMProvider) -> None:
    """Set the process-wide default provider."""
    global _default_provider
    _default_provider = provider
    logger.debug("default LLM provider configured: %s", provider.name())


def get_provider() -> LLMProvider:
    """Return the default provider, lazily constructing a LiteLLM provider.

    Raises:
        GatewayError: if no provider is configured and ``LLM_MODEL`` is unset.
    """
    global _default_provider
    if _default_provider is None:
        model = os.environ.get("LLM_MODEL")
        if not model:
            raise GatewayError(
                "No default LLM provider configured. Set the LLM_MODEL env var "
                "(e.g. 'claude-3-5-sonnet') or call ai_gateway.configure(...)."
            )
        _default_provider = LiteLLMProvider(model=model)
        logger.info("default LLM provider initialized: %s", _default_provider.name())
    return _default_provider


def generate_structured_response(
    prompt: str,
    schema: type[T],
    *,
    system_prompt: str | None = None,
    retries: int = 3,
    context: dict[str, Any] | None = None,
    temperature: float | None = None,
    provider: LLMProvider | None = None,
) -> T:
    """Generate an LLM response guaranteed to validate against the Pydantic ``schema``.

    Args:
        prompt: The instruction / question for the model.
        schema: A Pydantic model class describing the required JSON shape.
        system_prompt: Optional persona / system preamble.
        retries: Max corrective retries on malformed or invalid output.
        context: Optional dict injected as extra system context.
        temperature: Override the provider's default sampling temperature
            (``None`` → provider default).
        provider: Use an explicit provider instead of the process default.

    Returns:
        An instance of ``schema`` populated from the model's JSON response.

    Raises:
        StructuredOutputError: if the model cannot produce valid output in time.
        GatewayError: if no provider is available.
    """
    active = provider or get_provider()
    return active.generate_structured(
        prompt,
        schema,
        system_prompt=system_prompt,
        retries=retries,
        context=context,
        temperature=temperature,
    )


async def generate_structured_response_async(
    prompt: str,
    schema: type[T],
    *,
    system_prompt: str | None = None,
    retries: int = 3,
    context: dict[str, Any] | None = None,
    temperature: float | None = None,
    provider: LLMProvider | None = None,
) -> T:
    """Async twin of :func:`generate_structured_response`."""
    active = provider or get_provider()
    return await active.generate_structured_async(
        prompt,
        schema,
        system_prompt=system_prompt,
        retries=retries,
        context=context,
        temperature=temperature,
    )
