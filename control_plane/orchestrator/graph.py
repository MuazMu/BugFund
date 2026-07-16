"""Compile the BugFund LangGraph swarm.

Every node sets ``state["route"]``; one conditional edge per node dispatches via
:func:`_router` (which reads the Supervisor's decision). Termination is
guaranteed by the Actor's step-budget guard and the Supervisor's budget check.

This module holds *only* graph construction. Budget enforcement, the initial
state factory, and the campaign runner live in sibling modules and are
re-exported here so existing imports keep working:

    from control_plane.orchestrator.graph import build_graph, Budget, build_initial_state, run_campaign
"""
from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from agent_swarm import (
    HuntState,  # noqa: F401  (re-exported)
    Route,
    actor_node,
    critic_node,
    patcher_node,
    route_from_state,
    supervisor_node,
    threat_modeler_node,
)
from control_plane.orchestrator.budget import Budget  # noqa: F401  (re-exported)
from control_plane.orchestrator.runner import run_campaign  # noqa: F401  (re-exported)
from control_plane.orchestrator.state import build_initial_state  # noqa: F401  (re-exported)

# Map the Route enum (returned by route_from_state) to graph node names.
_ROUTE_MAP: dict[str, Any] = {
    Route.THREAT_MODELER.value: "threat_modeler",
    Route.ACTOR.value: "actor",
    Route.CRITIC.value: "critic",
    Route.PATCHER.value: "patcher",
    Route.END.value: END,
}


def _router(state: HuntState) -> str:
    """Conditional-edge resolver: return the next node name as a string."""
    return route_from_state(state).value


def build_graph(checkpointer: Any = None):
    """Compile the swarm into a LangGraph.

    Every node sets ``state["route"]``; one conditional edge per node dispatches
    via :func:`_router`. Termination is guaranteed by the Actor's step-budget
    guard and the Supervisor's budget check.
    """
    graph = StateGraph(HuntState)
    graph.add_node("supervisor", supervisor_node)
    graph.add_node("threat_modeler", threat_modeler_node)
    graph.add_node("actor", actor_node)
    graph.add_node("critic", critic_node)
    graph.add_node("patcher", patcher_node)

    graph.set_entry_point("supervisor")
    for name in ("supervisor", "threat_modeler", "actor", "critic", "patcher"):
        graph.add_conditional_edges(name, _router, _ROUTE_MAP)

    return graph.compile(checkpointer=checkpointer)


__all__ = [
    "build_graph",
    "Budget",
    "build_initial_state",
    "run_campaign",
    "HuntState",
]
