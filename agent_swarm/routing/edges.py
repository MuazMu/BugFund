"""Conditional-edge functions (Supervisor → next node).

The authoritative edge resolver is :func:`agent_swarm.nodes.route_from_state`,
re-exported here so the graph-wiring layer can import the routing surface from a
single place (``agent_swarm.routing``).
"""
from __future__ import annotations

from agent_swarm.nodes import route_from_state
from agent_swarm.state import HuntState, Route

__all__ = ["route_from_state", "route_value", "Route"]


def route_value(state: HuntState) -> str:
    """Return the next node name as a plain string (LangGraph conditional edge)."""
    return route_from_state(state).value
