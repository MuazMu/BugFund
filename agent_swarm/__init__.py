"""BugFund agent swarm — LangGraph nodes, prompts, skills, and shared state.

Public surface for the orchestrator (``control_plane/orchestrator/graph.py``)
and for tests.
"""
from __future__ import annotations

from agent_swarm.nodes import (
    actor_node,
    critic_node,
    patcher_node,
    route_from_state,
    supervisor_node,
    threat_modeler_node,
)
from agent_swarm.skills import (
    apply_source_patch,
    execute_sandbox_script,
    find_function_references,
    get_sandbox_client,
    read_codebase,
    run_nuclei,
    run_sast_scanner,
    set_sandbox_client,
)
from agent_swarm.state import (
    ActorPlan,
    AgentRole,
    CriticVerdict,
    Finding,
    HuntState,
    Hypothesis,
    InterestingFinding,
    NucleiTriage,
    PatchFile,
    PatchPlan,
    ResearchPlan,
    Route,
    RouterDecision,
    ThreatModelOutput,
)

__all__ = [
    # state + contracts
    "AgentRole",
    "Route",
    "HuntState",
    "Hypothesis",
    "Finding",
    "RouterDecision",
    "ResearchPlan",
    "ThreatModelOutput",
    "InterestingFinding",
    "NucleiTriage",
    "ActorPlan",
    "CriticVerdict",
    "PatchFile",
    "PatchPlan",
    # skills
    "read_codebase",
    "run_sast_scanner",
    "run_nuclei",
    "find_function_references",
    "apply_source_patch",
    "execute_sandbox_script",
    "set_sandbox_client",
    "get_sandbox_client",
    # nodes
    "supervisor_node",
    "threat_modeler_node",
    "actor_node",
    "critic_node",
    "patcher_node",
    "route_from_state",
]
