"""Abstract LLM provider interface for the BugFund AI gateway.

Every swarm node talks to the gateway instead of any provider SDK directly.
The contract every provider must honor: a call to :meth:`generate_structured`
returns an instance of the requested Pydantic model — **guaranteed valid**.
If a provider cannot meet that contract after its retry budget it raises
:class:`StructuredOutputError`; callers never receive raw or unvalidated text.

A new provider (e.g. a self-hosted vLLM endpoint, a Bedrock route) is added by
subclassing :class:`LLMProvider` and implementing ``generate_structured``.
"""
from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from typing import Any, TypeVar

from pydantic import BaseModel

T = TypeVar("T", bound=BaseModel)

__all__ = ["GatewayError", "StructuredOutputError", "LLMProvider"]


class GatewayError(Exception):
    """Base class for all AI-gateway errors."""


class StructuredOutputError(GatewayError):
    """The provider could not return schema-conformant JSON after all retries."""


class LLMProvider(ABC):
    """Model-agnostic interface for structured LLM completion.

    Implementations enforce structured output in two layers:

    1. **At the request** — advertise the response JSON Schema to the model
       (native ``response_format`` where supported, schema-in-prompt otherwise).
    2. **At the response** — parse and validate against the Pydantic model,
       retrying with corrective feedback whenever the model emits plain text or
       schema-violating JSON.
    """

    #: Human-readable provider identifier (e.g. ``"litellm:claude-3-5-sonnet"``).
    @abstractmethod
    def name(self) -> str:
        ...

    @abstractmethod
    def generate_structured(
        self,
        prompt: str,
        response_model: type[T],
        *,
        system_prompt: str | None = None,
        retries: int = 3,
        context: dict[str, Any] | None = None,
        temperature: float = 0.0,
    ) -> T:
        """Return ``response_model(**validated)``.

        Args:
            prompt: The user instruction / question.
            response_model: Pydantic model the response must validate against.
            system_prompt: Optional persona/system preamble.
            retries: Max corrective retries on malformed/invalid output.
            context: Optional dict injected as extra system context.
            temperature: Sampling temperature for this call.

        Raises:
            StructuredOutputError: if every attempt failed to validate.
        """
        ...

    async def generate_structured_async(
        self,
        prompt: str,
        response_model: type[T],
        *,
        system_prompt: str | None = None,
        retries: int = 3,
        context: dict[str, Any] | None = None,
        temperature: float = 0.0,
    ) -> T:
        """Async counterpart.

        Default implementation runs the synchronous method in a worker thread,
        so a provider that lacks a native async client still works. Providers
        with a true async client (e.g. LiteLLM) override this for concurrency.
        """
        return await asyncio.to_thread(
            self.generate_structured,
            prompt,
            response_model,
            system_prompt=system_prompt,
            retries=retries,
            context=context,
            temperature=temperature,
        )
