"""LiteLLM-backed LLM provider with enforced structured outputs.

Enforcement is **defense in depth** so the guarantee holds across every model
LiteLLM can route to, regardless of native structured-output support:

  1. The response JSON Schema (from ``Model.model_json_schema()``) is injected
     into the system prompt, instructing the model to emit *only* JSON.
  2. Where the backend supports it, ``response_format`` constrains decoding
     (``json_object`` by default for broad compatibility; ``json_schema`` /
     ``none`` selectable). If the backend rejects the requested mode, the call
     transparently falls back to a plain completion.
  3. The returned text is parsed (markdown fences stripped, outermost JSON
     extracted) and validated with ``response_model.model_validate``.
  4. On any failure — plain text, truncated JSON, or a Pydantic
     ``ValidationError`` — the failing output and the *exact* error are fed
     back to the model and the call is retried, up to ``retries`` times.

Provider/transport errors (timeouts, rate limits, auth) are **not** swallowed
by the validation-retry budget; they propagate so callers (or LiteLLM's own
retry config) can decide. Only structured-output failures consume the loop.
"""
from __future__ import annotations

import json
import logging
import re
from typing import Any, Callable, Literal, TypeVar

import litellm
from pydantic import BaseModel, ValidationError

from .base import LLMProvider, StructuredOutputError

logger = logging.getLogger(__name__)

T = TypeVar("T", bound=BaseModel)

StructuredMode = Literal["json_schema", "json_object", "none"]

# Matches a ```json ... ``` (or bare ``` ... ```) fenced block, capturing its body.
_FENCE_RE = re.compile(r"```(?:json)?\s*(.*?)```", re.DOTALL | re.IGNORECASE)

_SCHEMA_PREAMBLE = (
    "You are a precise security-reasoning assistant. Respond with a SINGLE "
    "valid JSON object that conforms EXACTLY to the JSON Schema below. "
    "Output ONLY the JSON — no prose, no markdown fences, no commentary, "
    "no leading/trailing text."
)

# Substrings that indicate an API error is about response_format, not transport.
_FORMAT_ERROR_HINTS = (
    "response_format",
    "json_object",
    "json_schema",
    "unrecognized argument",
    "additional_properties",
    "does not support",
    "not supported",
)


class LiteLLMProvider(LLMProvider):
    """Structured-output LLM provider built on LiteLLM (model-agnostic)."""

    def __init__(
        self,
        model: str,
        *,
        temperature: float = 0.0,
        timeout: float = 90.0,
        structured_mode: StructuredMode = "json_object",
        fallback_on_mode_error: bool = True,
        extra_headers: dict[str, str] | None = None,
        completion_kwargs: dict[str, Any] | None = None,
    ) -> None:
        """
        Args:
            model: LiteLLM model string, e.g. ``"claude-3-5-sonnet"``,
                ``"gpt-4o"``, ``"ollama/llama3"``.
            temperature: Default sampling temperature (overridable per call).
            timeout: Per-call timeout in seconds.
            structured_mode: How to constrain decoding. ``"json_object"`` is the
                safe default (widely supported). ``"json_schema"`` requests
                strict native schema (OpenAI structured outputs etc.).
                ``"none"`` relies on prompt + validation only.
            fallback_on_mode_error: If the backend rejects ``response_format``,
                retry the same call without it before failing.
            extra_headers: Optional headers sent on every call (e.g. routing).
            completion_kwargs: Extra kwargs forwarded to ``litellm.completion``.
        """
        self.model = model
        self.default_temperature = temperature
        self.timeout = timeout
        self.structured_mode: StructuredMode = structured_mode
        self.fallback_on_mode_error = fallback_on_mode_error
        self.extra_headers = extra_headers
        self.completion_kwargs: dict[str, Any] = completion_kwargs or {}

    def name(self) -> str:
        return f"litellm:{self.model}"

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #
    def generate_structured(
        self,
        prompt: str,
        response_model: type[T],
        *,
        system_prompt: str | None = None,
        retries: int = 3,
        context: dict[str, Any] | None = None,
        temperature: float | None = None,
    ) -> T:
        messages = self._build_initial_messages(
            prompt, response_model, system_prompt, context
        )
        return self._loop(
            self._complete_sync,
            messages,
            response_model,
            retries,
            self.default_temperature if temperature is None else temperature,
        )

    async def generate_structured_async(
        self,
        prompt: str,
        response_model: type[T],
        *,
        system_prompt: str | None = None,
        retries: int = 3,
        context: dict[str, Any] | None = None,
        temperature: float | None = None,
    ) -> T:
        # Native async path: uses litellm.acompletion (no worker-thread wrapping).
        messages = self._build_initial_messages(
            prompt, response_model, system_prompt, context
        )
        return await self._loop_async(
            self._complete_async,
            messages,
            response_model,
            retries,
            self.default_temperature if temperature is None else temperature,
        )

    # ------------------------------------------------------------------ #
    # Retry loop — the core enforcement
    # ------------------------------------------------------------------ #
    def _loop(
        self,
        call: Callable[[list[dict[str, Any]], float], str],
        messages: list[dict[str, Any]],
        response_model: type[T],
        retries: int,
        temperature: float,
    ) -> T:
        last_error: Exception | None = None
        for attempt in range(retries + 1):
            # Transport/provider errors propagate (not a structured-output failure).
            content = call(messages, temperature)
            try:
                parsed = self._parse_json(content)
                return response_model.model_validate(parsed)
            except (ValueError, ValidationError) as exc:
                last_error = exc
                logger.info(
                    "structured output invalid (attempt %d/%d) for %s via %s: %s",
                    attempt + 1, retries + 1, response_model.__name__, self.name(), exc,
                )
                if attempt < retries:
                    messages = self._corrective_messages(messages, content, exc)
        raise StructuredOutputError(
            f"{self.name()} failed to produce a valid {response_model.__name__} "
            f"after {retries + 1} attempt(s); last error: {last_error!r}"
        )

    async def _loop_async(
        self,
        call,
        messages: list[dict[str, Any]],
        response_model: type[T],
        retries: int,
        temperature: float,
    ) -> T:
        last_error: Exception | None = None
        for attempt in range(retries + 1):
            content = await call(messages, temperature)
            try:
                parsed = self._parse_json(content)
                return response_model.model_validate(parsed)
            except (ValueError, ValidationError) as exc:
                last_error = exc
                logger.info(
                    "structured output invalid (attempt %d/%d) for %s via %s: %s",
                    attempt + 1, retries + 1, response_model.__name__, self.name(), exc,
                )
                if attempt < retries:
                    messages = self._corrective_messages(messages, content, exc)
        raise StructuredOutputError(
            f"{self.name()} failed to produce a valid {response_model.__name__} "
            f"after {retries + 1} attempt(s); last error: {last_error!r}"
        )

    # ------------------------------------------------------------------ #
    # LiteLLM calls (with graceful response_format fallback)
    # ------------------------------------------------------------------ #
    def _complete_sync(self, messages: list[dict[str, Any]], temperature: float) -> str:
        params, response_format = self._call_params(messages, temperature)
        return self._extract_content(self._invoke(litellm.completion, params, response_format))

    async def _complete_async(self, messages: list[dict[str, Any]], temperature: float) -> str:
        params, response_format = self._call_params(messages, temperature)
        return self._extract_content(
            await self._invoke_async(litellm.acompletion, params, response_format)
        )

    def _invoke(self, fn, params: dict[str, Any], response_format: dict[str, Any] | None):
        try:
            return fn(**params, response_format=response_format) if response_format else fn(**params)
        except Exception as exc:
            if response_format is not None and self.fallback_on_mode_error and self._is_format_error(exc):
                logger.warning(
                    "response_format=%s rejected by %s (%s); retrying plain",
                    response_format, self.name(), exc,
                )
                return fn(**params)
            raise

    async def _invoke_async(self, fn, params: dict[str, Any], response_format: dict[str, Any] | None):
        try:
            return (
                await fn(**params, response_format=response_format)
                if response_format
                else await fn(**params)
            )
        except Exception as exc:
            if response_format is not None and self.fallback_on_mode_error and self._is_format_error(exc):
                logger.warning(
                    "response_format=%s rejected by %s (%s); retrying plain",
                    response_format, self.name(), exc,
                )
                return await fn(**params)
            raise

    def _call_params(
        self, messages: list[dict[str, Any]], temperature: float
    ) -> tuple[dict[str, Any], dict[str, Any] | None]:
        params: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            "timeout": self.timeout,
            **self.completion_kwargs,
        }
        if self.extra_headers:
            params["extra_headers"] = dict(self.extra_headers)
        return params, self._response_format()

    def _response_format(self) -> dict[str, Any] | None:
        if self.structured_mode == "none":
            return None
        if self.structured_mode == "json_object":
            return {"type": "json_object"}
        # "json_schema" — strict native schema where the backend supports it.
        return {
            "type": "json_schema",
            "json_schema": {"name": "response", "strict": False},
        }

    @staticmethod
    def _is_format_error(exc: Exception) -> bool:
        text = str(exc).lower()
        return any(hint in text for hint in _FORMAT_ERROR_HINTS)

    @staticmethod
    def _extract_content(resp: Any) -> str:
        """Pull the assistant text out of a LiteLLM ModelResponse (with fallback)."""
        try:
            msg = resp.choices[0].message  # type: ignore[union-attr]
        except AttributeError:
            msg = resp["choices"][0]["message"]  # type: ignore[index]
        content = getattr(msg, "content", None)
        if content is None and isinstance(msg, dict):
            content = msg.get("content")  # type: ignore[union-attr]
        return content or ""

    # ------------------------------------------------------------------ #
    # Message construction
    # ------------------------------------------------------------------ #
    def _build_initial_messages(
        self,
        prompt: str,
        response_model: type[BaseModel],
        system_prompt: str | None,
        context: dict[str, Any] | None,
    ) -> list[dict[str, Any]]:
        schema = response_model.model_json_schema()
        persona = system_prompt or "You are a precise security-reasoning assistant."
        system_blob = (
            f"{persona}\n\n{_SCHEMA_PREAMBLE}\n\n"
            f"JSON Schema:\n{json.dumps(schema, indent=2)}"
        )
        messages: list[dict[str, Any]] = [{"role": "system", "content": system_blob}]
        if context:
            messages.append(
                {"role": "system", "content": "Context:\n" + json.dumps(context, default=str)}
            )
        messages.append({"role": "user", "content": prompt})
        return messages

    def _corrective_messages(
        self,
        messages: list[dict[str, Any]],
        bad_output: str,
        error: Exception,
    ) -> list[dict[str, Any]]:
        """Append the failing output + a precise correction request for the next try."""
        corrected = list(messages)
        corrected.append({"role": "assistant", "content": bad_output or ""})
        corrected.append(
            {
                "role": "user",
                "content": (
                    f"That was not valid: {type(error).__name__}: {error}. "
                    "Return ONLY a single JSON object that conforms to the schema. "
                    "Do not include markdown fences or any text outside the JSON."
                ),
            }
        )
        return corrected

    # ------------------------------------------------------------------ #
    # JSON extraction — robust to fences, prose wrappers, partial output
    # ------------------------------------------------------------------ #
    @staticmethod
    def _parse_json(content: str) -> Any:
        if not content or not content.strip():
            raise ValueError("empty model response")

        text = content.strip()

        # 1) Strip a single surrounding ```json ... ``` fence if present.
        fence = _FENCE_RE.search(text)
        if fence:
            text = fence.group(1).strip()

        # 2) Direct parse.
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

        # 3) Fall back to the outermost {...} or [...] span.
        for opener, closer in (("{", "}"), ("[", "]")):
            start, end = text.find(opener), text.rfind(closer)
            if start != -1 and end > start:
                try:
                    return json.loads(text[start : end + 1])
                except json.JSONDecodeError:
                    continue

        raise ValueError(f"no parseable JSON found in response head: {content[:200]!r}")
