"""Shared LangGraph swarm state and LLM structured-output contracts.

``HuntState`` is the TypedDict that flows through every node of the BugFund
LangGraph graph — and is exactly what gets serialized into the
``AgentState.state`` JSONB column by the orchestrator.

The Pydantic models are the *response contracts* handed to the AI gateway so
each agent's output is JSON-Schema-validated and auto-retried on malformed
responses (see ``ai_gateway.generate_structured_response``).
"""
from __future__ import annotations

import enum
from typing import Annotated, Any, Optional, TypedDict

from pydantic import BaseModel, Field

__all__ = [
    "AgentRole",
    "Route",
    "HypothesisStatus",
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
    "HuntState",
]


# --------------------------------------------------------------------------- #
# Enums
# --------------------------------------------------------------------------- #
class AgentRole(str, enum.Enum):
    SUPERVISOR = "supervisor"
    THREAT_MODELER = "threat_modeler"
    ACTOR = "actor"
    CRITIC = "critic"
    PATCHER = "patcher"
    REPORTER = "reporter"


class Route(str, enum.Enum):
    """Next-hop decision emitted by the Supervisor / read by the conditional edge."""

    THREAT_MODELER = "threat_modeler"
    ACTOR = "actor"
    CRITIC = "critic"
    PATCHER = "patcher"
    END = "end"


class HypothesisStatus(str, enum.Enum):
    PENDING = "pending"
    TESTING = "testing"
    VERIFIED = "verified"
    REJECTED = "rejected"


def _append(left: list | None, right: list | None) -> list:
    """Reducer for append-only state fields (e.g. the run transcript)."""
    return [*(left or []), *(right or [])]


# --------------------------------------------------------------------------- #
# Structured-output contracts (passed to the AI gateway as the `schema`)
# --------------------------------------------------------------------------- #
class Hypothesis(BaseModel):
    id: str = Field(description="Stable hypothesis id, e.g. 'H-001'.")
    cwe: str = Field(description="CWE identifier, e.g. 'CWE-89'.")
    title: str
    target_path: Optional[str] = Field(
        default=None, description="File/symbol/endpoint where the flaw likely lives."
    )
    rationale: str
    confidence: float = Field(ge=0.0, le=1.0)
    status: HypothesisStatus = HypothesisStatus.PENDING


class Finding(BaseModel):
    hypothesis_id: str
    cwe: str
    severity: str  # informational | low | medium | high | critical
    title: str
    description: str
    pov_script: str
    evidence: dict[str, Any]
    verified: bool = True
    # Populated by the Patcher after differential patch verification.
    patch: Optional[dict[str, Any]] = None
    patch_verified: Optional[bool] = None


class RouterDecision(BaseModel):
    next: Route = Field(description="Next node: threat_modeler | actor | critic | patcher | end.")
    rationale: str


class ResearchPlan(BaseModel):
    """Threat-Modeler AST-research step: which symbols to pull call-sites for."""

    function_names: list[str] = Field(
        default_factory=list,
        description="Functions/methods whose call-sites should be retrieved (<=10).",
    )
    rationale: str


class ThreatModelOutput(BaseModel):
    business_logic: dict[str, Any] = Field(
        description="Business-logic state machine: states, transitions, guards."
    )
    permission_matrix: list[dict[str, Any]] = Field(
        description="Roles x resources x allowed actions; flag privilege boundaries."
    )
    attack_surface: list[str] = Field(default_factory=list)
    hypotheses: list[Hypothesis] = Field(default_factory=list)


class InterestingFinding(BaseModel):
    template_id: str
    severity: str
    title: str
    target_path: Optional[str] = None
    cwe: Optional[str] = None
    rationale: str


class NucleiTriage(BaseModel):
    """Supervisor's triage of deterministic Nuclei findings -> hypotheses."""

    interesting: list[InterestingFinding] = Field(default_factory=list)
    skip: list[str] = Field(default_factory=list, description="template_ids dismissed as noise.")
    rationale: str


class ActorPlan(BaseModel):
    pov_script: str = Field(description="A complete, self-contained Python PoV.py.")
    explanation: str
    expected_signal: str = Field(
        description="Exact stdout marker the PoV prints on success (e.g. 'POV_SUCCESS')."
    )


class CriticVerdict(BaseModel):
    verified: bool
    confidence: float = Field(ge=0.0, le=1.0)
    diagnosis: str
    rewrite_instructions: str = Field(
        default="", description="Empty when verified; otherwise precise Actor guidance."
    )
    severity: Optional[str] = None
    cwe: Optional[str] = None


class PatchFile(BaseModel):
    path: str = Field(description="Repo-relative path of the file to overwrite.")
    new_content: str = Field(description="Full new contents of the file after patching.")


class PatchPlan(BaseModel):
    patched_files: list[PatchFile]
    rationale: str
    verification_strategy: str
    smoke_command: Optional[str] = Field(
        default=None,
        description="Optional build/test command to prove the patched tree still builds.",
    )


# --------------------------------------------------------------------------- #
# LangGraph state (plain JSON-able — serialized into AgentState.state JSONB)
# --------------------------------------------------------------------------- #
class HuntState(TypedDict, total=False):
    # Target under test.
    target_id: str
    target_path: str
    repo_url: str
    commit_hash: Optional[str]
    nuclei_target: Optional[str]  # URL/host:port for deterministic Nuclei scanning.

    # Budget envelope (Supervisor enforces).
    iteration: int
    max_iterations: int
    token_budget: int
    tokens_used: int

    # Threat Modeler output.
    threat_model: Optional[dict[str, Any]]
    hypotheses: list[dict[str, Any]]
    current_hypothesis_id: Optional[str]

    # Actor / Critic working set.
    pending_pov: Optional[str]
    pending_expected_signal: Optional[str]
    last_result: Optional[dict[str, Any]]
    critique: Optional[str]

    # Deterministic-scan bookkeeping.
    nuclei_run: bool

    # Graduated results + control flow.
    findings: list[dict[str, Any]]
    route: Optional[Route]
    status: str  # running | completed | failed

    # Append-only run log (reducer-merged).
    transcript: Annotated[list[dict[str, Any]], _append]
