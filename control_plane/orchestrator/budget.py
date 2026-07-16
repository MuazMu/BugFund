"""Step / token / USD budget envelope for a campaign.

The Supervisor and runner consult a :class:`Budget` to guarantee a campaign
terminates. ``BudgetExceeded`` is raised the moment any axis is breached.
"""
from __future__ import annotations

from control_plane.core.config import BudgetExceeded

__all__ = ["Budget"]


class Budget:
    """Step/token/USD budget envelope for a campaign."""

    def __init__(self, max_steps: int, max_tokens: int, max_usd: float) -> None:
        self.max_steps = max_steps
        self.max_tokens = max_tokens
        self.max_usd = max_usd
        self.tokens_used = 0
        self.usd_used = 0.0

    def check_step(self, current_step: int) -> None:
        if current_step >= self.max_steps:
            raise BudgetExceeded(f"step budget exhausted: {current_step}/{self.max_steps}")

    def consume_tokens(self, n: int, usd: float = 0.0) -> None:
        self.tokens_used += n
        self.usd_used += usd
        if self.tokens_used > self.max_tokens:
            raise BudgetExceeded(f"token budget exhausted: {self.tokens_used}/{self.max_tokens}")
        if self.usd_used > self.max_usd:
            raise BudgetExceeded(f"USD budget exhausted: {self.usd_used}/{self.max_usd}")
