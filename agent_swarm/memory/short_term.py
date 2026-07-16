"""Short-term (working) memory — read-only views over the in-graph state.

The authoritative working memory *is* the LangGraph :class:`~agent_swarm.state.HuntState`
(the serialized transcript + backlog carried node-to-node). This module provides
compact, prompt-friendly projections of it so an agent can ask "what just
happened?" without re-reading the whole buffer.
"""
from __future__ import annotations

import json
from typing import Any

from agent_swarm.state import HuntState

__all__ = ["recent_transcript", "working_set", "summarize_for_prompt"]


def recent_transcript(state: HuntState, n: int = 8) -> list[dict[str, Any]]:
    """Return the last ``n`` transcript entries."""
    return list((state.get("transcript") or [])[-n:])


def working_set(state: HuntState) -> dict[str, Any]:
    """The actionable slice of state an agent needs right now."""
    return {
        "current_hypothesis_id": state.get("current_hypothesis_id"),
        "hypotheses": state.get("hypotheses", []),
        "last_result": state.get("last_result"),
        "critique": state.get("critique"),
        "findings_count": len(state.get("findings", [])),
        "iteration": state.get("iteration", 0),
        "max_iterations": state.get("max_iterations"),
    }


def summarize_for_prompt(state: HuntState, *, max_chars: int = 1200) -> str:
    """A compact textual digest of the run suitable for injecting into a prompt."""
    bits: list[str] = []
    bits.append(f"iteration: {state.get('iteration', 0)}/{state.get('max_iterations')}")
    bits.append(f"findings: {len(state.get('findings', []))}")
    hyps = state.get("hypotheses", []) or []
    open_ids = [
        h.get("id") for h in hyps if h.get("status") in (None, "pending", "testing")
    ]
    bits.append(f"open hypotheses: {open_ids}")
    if state.get("critique"):
        bits.append(f"last critique: {state['critique']}")
    transcript = recent_transcript(state, n=4)
    if transcript:
        bits.append("recent: " + json.dumps(transcript, default=str))
    text = " | ".join(bits)
    return text[:max_chars]
