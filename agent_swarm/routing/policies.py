"""Termination + re-prioritization decision rules (pure functions).

These encode the swarm's control-flow policy independently of the node bodies,
so they can be unit-tested and reused (e.g. by the orchestrator's budget guard
or a future re-planner). The node implementations apply the same rules inline;
this module is the canonical, documented statement of them.
"""
from __future__ import annotations

from typing import Any, Optional

from agent_swarm.state import HuntState, HypothesisStatus

__all__ = [
    "OPEN_STATUSES",
    "is_open",
    "open_count",
    "should_terminate",
    "next_open_hypothesis",
    "prioritize",
]

OPEN_STATUSES = (None, HypothesisStatus.PENDING.value, HypothesisStatus.TESTING.value)


def is_open(hypothesis: dict[str, Any]) -> bool:
    """A hypothesis is actionable when unverified/unrejected."""
    return hypothesis.get("status") in OPEN_STATUSES


def open_count(state: HuntState) -> int:
    return sum(1 for h in (state.get("hypotheses") or []) if is_open(h))


def _budget_exhausted(state: HuntState) -> bool:
    max_iter = state.get("max_iterations", 0)
    return bool(max_iter) and state.get("iteration", 0) >= max_iter


def should_terminate(state: HuntState) -> bool:
    """True when the campaign has no more useful work (or is out of budget)."""
    hyps = state.get("hypotheses") or []
    if _budget_exhausted(state):
        return True
    if not hyps:
        return True
    return open_count(state) == 0


def next_open_hypothesis(
    state: HuntState, exclude_id: Optional[str] = None
) -> Optional[dict[str, Any]]:
    """Return the next actionable hypothesis (excluding ``exclude_id``), if any."""
    for h in state.get("hypotheses") or []:
        if h.get("id") == exclude_id:
            continue
        if is_open(h):
            return h
    return None


def prioritize(state: HuntState) -> list[dict[str, Any]]:
    """Open hypotheses sorted by descending confidence (stable)."""
    open_hyps = [h for h in (state.get("hypotheses") or []) if is_open(h)]
    return sorted(open_hyps, key=lambda h: h.get("confidence", 0.0), reverse=True)
