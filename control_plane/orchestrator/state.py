"""Swarm state factory + re-export of the LangGraph ``HuntState``.

The authoritative :class:`~agent_swarm.state.HuntState` TypedDict lives in
``agent_swarm`` (it is what flows through every node and is serialized into
``AgentState.state``). It is re-exported here so the orchestrator layer has a
single import surface, alongside :func:`build_initial_state` which constructs a
fresh, budget-seeded hunt state for a new campaign.
"""
from __future__ import annotations

from typing import Any, Optional

from agent_swarm import HuntState, Route  # noqa: F401  (re-exported)

__all__ = ["HuntState", "Route", "build_initial_state"]


def build_initial_state(
    target_id: Any,
    target_path: str,
    *,
    repo_url: Optional[str] = None,
    commit_hash: Optional[str] = None,
    nuclei_target: Optional[str] = None,
    max_iterations: int = 20,
    token_budget: int = 200_000,
) -> HuntState:
    """Construct the initial swarm state for a campaign."""
    return {
        "target_id": str(target_id),
        "target_path": target_path,
        "repo_url": repo_url,
        "commit_hash": commit_hash,
        "nuclei_target": nuclei_target,
        "iteration": 0,
        "max_iterations": max_iterations,
        "token_budget": token_budget,
        "tokens_used": 0,
        "hypotheses": [],
        "findings": [],
        "status": "running",
        "transcript": [],
    }
