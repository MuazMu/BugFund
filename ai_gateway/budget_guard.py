"""Per-campaign / per-agent token & USD budget guard for the AI gateway.

Sits in front of LLM execution: every call's token usage is accounted against
the guard, and :class:`BudgetExceeded` is raised the moment an allocation is
breached — so a runaway agent can't exceed its campaign envelope. Complements
the orchestrator's coarse step/token ``Budget`` (which is campaign-wide); this
is per-call and USD-aware via the pricing table below.

Prices are USD per 1M tokens (prompt / completion); best-effort and easily
overridden. Unknown models default to $0 so the guard never blocks on a typo.
"""
from __future__ import annotations

from typing import Optional

from control_plane.core.exceptions import BudgetExceeded

__all__ = ["PRICING", "estimate_cost", "BudgetGuard"]

# USD per 1,000,000 tokens: {"model": (prompt_per_1m, completion_per_1m)}.
PRICING: dict[str, tuple[float, float]] = {
    "claude-3-5-sonnet": (3.0, 15.0),
    "claude-3-5-haiku": (0.8, 4.0),
    "claude-3-opus": (15.0, 75.0),
    "gpt-4o": (5.0, 15.0),
    "gpt-4o-mini": (0.15, 0.6),
    "gpt-4-turbo": (10.0, 30.0),
}


def estimate_cost(model: str, prompt_tokens: int, completion_tokens: int) -> float:
    """Estimate USD cost for a call; unknown models cost $0 (never blocks)."""
    p_in, p_out = PRICING.get(model, (0.0, 0.0))
    return (prompt_tokens / 1_000_000.0) * p_in + (completion_tokens / 1_000_000.0) * p_out


class BudgetGuard:
    """Track token + USD consumption against a per-campaign/per-agent cap."""

    def __init__(
        self,
        *,
        max_tokens: Optional[int] = None,
        max_usd: Optional[float] = None,
        label: str = "campaign",
    ) -> None:
        self.max_tokens = max_tokens
        self.max_usd = max_usd
        self.label = label
        self.tokens_used = 0
        self.usd_used = 0.0

    @property
    def remaining_tokens(self) -> Optional[int]:
        return None if self.max_tokens is None else max(0, self.max_tokens - self.tokens_used)

    @property
    def remaining_usd(self) -> Optional[float]:
        return None if self.max_usd is None else max(0.0, self.max_usd - self.usd_used)

    def consume(self, tokens: int, *, usd: Optional[float] = None, model: Optional[str] = None) -> None:
        """Account ``tokens`` (and derived/explicit ``usd``) against the cap.

        Raises:
            BudgetExceeded: if the token or USD allocation is breached.
        """
        cost = usd if usd is not None else estimate_cost(model or "", 0, tokens)
        self.tokens_used += int(tokens)
        self.usd_used += float(cost)

        if self.max_tokens is not None and self.tokens_used > self.max_tokens:
            raise BudgetExceeded(
                f"{self.label} token budget exhausted: {self.tokens_used}/{self.max_tokens}"
            )
        if self.max_usd is not None and self.usd_used > self.max_usd:
            raise BudgetExceeded(
                f"{self.label} USD budget exhausted: {self.usd_used:.4f}/{self.max_usd}"
            )

    def consume_call(
        self, model: str, prompt_tokens: int, completion_tokens: int
    ) -> float:
        """Consume a full call's tokens + cost in one step; returns the USD cost."""
        tokens = int(prompt_tokens) + int(completion_tokens)
        cost = estimate_cost(model, prompt_tokens, completion_tokens)
        self.consume(tokens, usd=cost, model=model)
        return cost
