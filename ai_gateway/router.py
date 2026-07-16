"""Per-role model routing + fallback chains.

A :class:`ModelRouter` resolves which LiteLLM model an agent role should use and
the ordered fallback chain to try on failure. Configuration is loaded from the
providers YAML (``ai_gateway/config/providers.yaml``) — overridable per call.

The router is decoupled from actual LLM execution: it only decides *which*
model strings to attempt; the provider (:class:`LiteLLMProvider`) does the call.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Optional

__all__ = ["RouterError", "ModelRouter", "load_routing_config", "DEFAULT_CONFIG_PATH"]

log = logging.getLogger(__name__)
DEFAULT_CONFIG_PATH = Path(__file__).resolve().parent / "config" / "providers.yaml"


class RouterError(RuntimeError):
    """Raised for missing/malformed routing configuration."""


def load_routing_config(path: Optional[str | Path] = None) -> dict[str, Any]:
    """Load and lightly validate the providers YAML."""
    import yaml  # lazy: keeps the gateway importable without PyYAML

    target = Path(path) if path else DEFAULT_CONFIG_PATH
    if not target.is_file():
        raise RouterError(f"routing config not found: {target}")
    config = yaml.safe_load(target.read_text(encoding="utf-8")) or {}
    if "default" not in config:
        raise RouterError(f"routing config {target} missing 'default' model")
    return config


class ModelRouter:
    """Resolve a role to a primary model + fallback chain."""

    def __init__(self, config: Optional[dict[str, Any]] = None) -> None:
        self._config = config if config is not None else load_routing_config()
        self._roles: dict[str, Any] = self._config.get("roles", {}) or {}
        self._fallbacks: dict[str, list[str]] = self._config.get("fallbacks", {}) or {}
        self._default_model = self._model_of(self._config["default"])

    @staticmethod
    def _model_of(entry: Any) -> str:
        return entry["model"] if isinstance(entry, dict) else str(entry)

    def primary(self, role: Optional[str]) -> str:
        """Return the primary model for ``role`` (falls back to the default)."""
        if role and role in self._roles:
            return self._model_of(self._roles[role])
        return self._default_model

    def chain(self, role: Optional[str]) -> list[str]:
        """Return the ordered ``[primary, fallback, ...]`` chain, de-duplicated."""
        primary = self.primary(role)
        chain = [primary]
        for model in self._fallbacks.get(primary, []):
            if model not in chain:
                chain.append(model)
        return chain

    def role_models(self) -> dict[str, str]:
        """Snapshot of every configured role → primary model (for inspection)."""
        return {role: self._model_of(entry) for role, entry in self._roles.items()}
