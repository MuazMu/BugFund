"""LangGraph node functions for the BugFund swarm.

Each node is an async function ``async def X_node(state: HuntState) -> dict``
returning a partial state delta that LangGraph merges. Routing is driven by the
Supervisor and by loop nodes themselves: the active route is read by
``route_from_state`` (the conditional edge ``graph.py`` wires up).

Control-flow summary:

    supervisor -> {threat_modeler | actor | critic | patcher | end}
    threat_modeler -> actor            (also runs a bounded AST-research round)
    actor -> critic                    (writes PoV, runs it in the sandbox)
    critic  -> actor (rejected) | patcher (verified, source target) | end
    patcher -> actor (next hypothesis) | end

All LLM calls go through ``ai_gateway.generate_structured_response_async`` so
each response is JSON-Schema-validated and auto-retried on plain-text output.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Optional

from ai_gateway import generate_structured_response_async

from agent_swarm.prompts import (
    ACTOR_SYSTEM,
    CRITIC_SYSTEM,
    PATCHER_SYSTEM,
    SUPERVISOR_SYSTEM,
    THREAT_MODELER_RESEARCH_SYSTEM,
    THREAT_MODELER_SYSTEM,
)
from agent_swarm.skills import (
    ReadDepth,
    ToolError,
    apply_source_patch,
    execute_sandbox_script,
    find_function_references,
    read_codebase,
    run_nuclei,
    run_sast_scanner,
)
from agent_swarm.state import (
    ActorPlan,
    CriticVerdict,
    Finding,
    HuntState,
    HypothesisStatus,
    NucleiTriage,
    PatchPlan,
    ResearchPlan,
    Route,
    RouterDecision,
    ThreatModelOutput,
)

logger = logging.getLogger(__name__)

__all__ = [
    "supervisor_node",
    "threat_modeler_node",
    "actor_node",
    "critic_node",
    "patcher_node",
    "route_from_state",
]


# --------------------------------------------------------------------------- #
# small state helpers (state stores plain dicts; statuses are strings)
# --------------------------------------------------------------------------- #
def _is_open(h: dict[str, Any]) -> bool:
    """A hypothesis is actionable when unverified/unrejected."""
    s = h.get("status")
    return s in (None, HypothesisStatus.PENDING.value, HypothesisStatus.TESTING.value)


def _current_hypothesis(state: HuntState) -> Optional[dict[str, Any]]:
    hid = state.get("current_hypothesis_id")
    for h in state.get("hypotheses", []):
        if h.get("id") == hid:
            return h
    for h in state.get("hypotheses", []):
        if _is_open(h):
            return h
    return None


def _next_open(state: HuntState, exclude_id: Optional[str]) -> Optional[dict[str, Any]]:
    for h in state.get("hypotheses", []):
        if h.get("id") == exclude_id:
            continue
        if _is_open(h):
            return h
    return None


def _budget_exhausted(state: HuntState) -> bool:
    max_iter = state.get("max_iterations", 0)
    return bool(max_iter) and state.get("iteration", 0) >= max_iter


def _set_status(hypotheses: list[dict[str, Any]], hid: Optional[str], status: str) -> None:
    if not hid:
        return
    for h in hypotheses:
        if h.get("id") == hid:
            h["status"] = status
            return


# --------------------------------------------------------------------------- #
# Supervisor  (routing + one-shot deterministic Nuclei triage)
# --------------------------------------------------------------------------- #
async def supervisor_node(state: HuntState) -> dict[str, Any]:
    """Read the hunt state, optionally triage Nuclei, and choose the next hop."""
    extra: dict[str, Any] = {}
    transcript: list[dict[str, Any]] = []

    nuclei_target = state.get("nuclei_target")
    if nuclei_target and not state.get("nuclei_run"):
        try:
            report = await run_nuclei(nuclei_target)
            triage = await generate_structured_response_async(
                prompt=_nuclei_triage_prompt(report),
                schema=NucleiTriage,
                system_prompt=SUPERVISOR_SYSTEM,
                retries=2,
                context={"findings": report.get("findings", [])},
            )
            promoted = [
                _interesting_to_hypothesis(i, idx)
                for idx, i in enumerate(triage.interesting)
            ]
            if promoted:
                merged = [*state.get("hypotheses", []), *promoted]
                extra["hypotheses"] = merged
                if not state.get("current_hypothesis_id"):
                    extra["current_hypothesis_id"] = merged[0]["id"]
            transcript.append(
                {
                    "node": "supervisor",
                    "nuclei_findings": len(report.get("findings", [])),
                    "promoted": len(promoted),
                    "skipped": len(triage.skip),
                }
            )
        except ToolError as exc:
            transcript.append({"node": "supervisor", "nuclei_error": str(exc)})
        extra["nuclei_run"] = True

    if _budget_exhausted(state):
        return {
            **extra,
            "route": Route.END,
            "status": "completed",
            "transcript": [
                *transcript,
                {"node": "supervisor", "next": Route.END.value, "rationale": "budget exhausted"},
            ],
        }

    decision = await generate_structured_response_async(
        prompt=_supervisor_prompt(state),
        schema=RouterDecision,
        system_prompt=SUPERVISOR_SYSTEM,
        retries=2,
        context={
            "iteration": state.get("iteration", 0),
            "max_iterations": state.get("max_iterations"),
            "has_threat_model": state.get("threat_model") is not None,
            "hypotheses": state.get("hypotheses", []),
            "has_unprocessed_result": state.get("last_result") is not None,
            "findings_count": len(state.get("findings", [])),
        },
    )
    return {
        **extra,
        "route": decision.next,
        "status": "completed" if decision.next == Route.END else state.get("status", "running"),
        "transcript": [
            *transcript,
            {"node": "supervisor", "next": decision.next.value, "rationale": decision.rationale},
        ],
    }


def _supervisor_prompt(state: HuntState) -> str:
    pending = sum(1 for h in state.get("hypotheses", []) if _is_open(h))
    return (
        "Choose the next node for this hunt.\n"
        f"- threat model present: {state.get('threat_model') is not None}\n"
        f"- open hypotheses: {pending}\n"
        f"- unprocessed sandbox result: {state.get('last_result') is not None}\n"
        f"- verified findings: {len(state.get('findings', []))}\n"
        f"- iteration: {state.get('iteration', 0)}/{state.get('max_iterations')}\n"
        "Apply the routing rules and return the decision."
    )


def _nuclei_triage_prompt(report: dict[str, Any]) -> str:
    return (
        "Triage these deterministic Nuclei findings. Promote only genuinely "
        "interesting, exploitable ones into hypotheses; dismiss noise via `skip`.\n\n"
        f"{json.dumps(report.get('findings', [])[:100])[:8000]}\n"
    )


def _interesting_to_hypothesis(i: Any, idx: int) -> dict[str, Any]:
    return {
        "id": f"NUC-{idx + 1:03d}",
        "cwe": getattr(i, "cwe", None) or "CWE-Unknown",
        "title": getattr(i, "title", "") or getattr(i, "template_id", ""),
        "target_path": getattr(i, "target_path", None),
        "rationale": getattr(i, "rationale", ""),
        "confidence": 0.6,
        "status": HypothesisStatus.PENDING.value,
    }


def route_from_state(state: HuntState) -> Route:
    """Conditional-edge function: read the Supervisor/loop route decision."""
    return state.get("route") or Route.THREAT_MODELER


# --------------------------------------------------------------------------- #
# Threat Modeler  (AST research round -> business logic + hypotheses)
# --------------------------------------------------------------------------- #
async def threat_modeler_node(state: HuntState) -> dict[str, Any]:
    """Ingest codebase + SAST + targeted call-site snippets; emit the threat model."""
    target_path = state.get("target_path", "")
    codebase = await read_codebase(target_path)
    sast = await run_sast_scanner(target_path, rule_type="security")

    # Bounded AST-research round: pick symbols, pull just their call-sites.
    references: dict[str, Any] = {}
    if target_path:
        try:
            research = await generate_structured_response_async(
                prompt=_research_prompt(codebase),
                schema=ResearchPlan,
                system_prompt=THREAT_MODELER_RESEARCH_SYSTEM,
                retries=2,
                context={"tree": codebase.get("tree", ""), "languages": codebase.get("languages")},
            )
            for fn in research.function_names[:10]:
                try:
                    rep = await find_function_references(fn, search_root=target_path, max_results=15)
                except ToolError:
                    continue
                references[fn] = rep.get("references", [])
        except ToolError:
            pass  # non-fatal: proceed without AST snippets

    model = await generate_structured_response_async(
        prompt=_threat_modeler_prompt(codebase, sast, references),
        schema=ThreatModelOutput,
        system_prompt=THREAT_MODELER_SYSTEM,
        retries=3,
        context={"sast_findings": sast.get("findings", []), "references": references},
    )

    hypotheses = [h.model_dump(mode="json") for h in model.hypotheses]
    first = hypotheses[0]["id"] if hypotheses else None
    return {
        "threat_model": {
            "business_logic": model.business_logic,
            "permission_matrix": model.permission_matrix,
            "attack_surface": model.attack_surface,
        },
        "hypotheses": hypotheses,
        "current_hypothesis_id": first,
        "transcript": [
            {"node": "threat_modeler", "hypotheses": len(hypotheses), "symbols": len(references)}
        ],
    }


def _research_prompt(codebase: dict[str, Any]) -> str:
    return (
        "Name the functions/methods whose call-sites the threat modeler should "
        "inspect to map data flow and authorization. Return up to 10 names.\n\n"
        f"Languages: {codebase.get('languages')}\n"
        f"Tree (truncated={codebase.get('truncated')}, "
        f"file_count={codebase.get('file_count')}):\n{codebase.get('tree', '')}\n"
    )


def _threat_modeler_prompt(
    codebase: dict[str, Any], sast: dict[str, Any], references: dict[str, Any]
) -> str:
    files = codebase.get("files", [])[:120]
    return (
        "Produce a threat model for this authorized target.\n\n"
        f"Languages: {codebase.get('languages')}\n"
        f"Tree (truncated={codebase.get('truncated')}, "
        f"file_count={codebase.get('file_count')}):\n{codebase.get('tree', '')}\n\n"
        f"Code sample (signatures/snippets):\n{json.dumps(files)[:8000]}\n\n"
        f"SAST findings:\n{json.dumps(sast.get('findings', [])[:50])[:4000]}\n\n"
        f"AST call-site snippets for key functions:\n{json.dumps(references)[:6000]}\n"
    )


# --------------------------------------------------------------------------- #
# Actor (exploit generator)
# --------------------------------------------------------------------------- #
async def actor_node(state: HuntState) -> dict[str, Any]:
    """Write a PoV for the current hypothesis and run it in the sandbox."""
    hypothesis = _current_hypothesis(state)
    if hypothesis is None:
        return {"route": Route.END, "transcript": [{"node": "actor", "note": "no open hypothesis"}]}

    plan = await generate_structured_response_async(
        prompt=_actor_prompt(hypothesis, state.get("critique")),
        schema=ActorPlan,
        system_prompt=ACTOR_SYSTEM,
        retries=3,
        context={"hypothesis": hypothesis},
    )

    result = await execute_sandbox_script(
        plan.pov_script,
        env_vars={
            "POV_TARGET": state.get("target_path", ""),
            "POV_HYPOTHESIS": hypothesis.get("id", ""),
        },
    )

    return {
        "pending_pov": plan.pov_script,
        "pending_expected_signal": plan.expected_signal,
        "last_result": result,
        "critique": None,
        "iteration": state.get("iteration", 0) + 1,
        "transcript": [
            {
                "node": "actor",
                "hypothesis": hypothesis.get("id"),
                "exit_code": result.get("exit_code"),
            }
        ],
    }


def _actor_prompt(hypothesis: dict[str, Any], critique: Optional[str]) -> str:
    base = (
        f"Hypothesis {hypothesis.get('id')} [{hypothesis.get('cwe')}]: "
        f"{hypothesis.get('title')}\n"
        f"Target: {hypothesis.get('target_path')}\n"
        f"Rationale: {hypothesis.get('rationale')}\n"
        "\nRemember: read the target path from os.environ['POV_TARGET'] and "
        "print a unique success marker."
    )
    if critique:
        base += (
            "\n\nThe Critic rejected your previous PoV. Address every point:\n"
            f"{critique}\n"
        )
    base += "\n\nWrite the complete `pov_script` and the exact `expected_signal`."
    return base


# --------------------------------------------------------------------------- #
# Critic (adversarial evaluator)
# --------------------------------------------------------------------------- #
async def critic_node(state: HuntState) -> dict[str, Any]:
    """Evaluate the last sandbox result: graduate a finding, or feedback the Actor."""
    result = state.get("last_result") or {}
    hypothesis = _current_hypothesis(state) or {"id": "", "cwe": "", "title": "unknown"}

    verdict = await generate_structured_response_async(
        prompt=_critic_prompt(hypothesis, result),
        schema=CriticVerdict,
        system_prompt=CRITIC_SYSTEM,
        retries=3,
        context={"hypothesis": hypothesis, "result": result},
    )

    transcript = [
        {
            "node": "critic",
            "hypothesis": hypothesis.get("id"),
            "verified": verdict.verified,
            "diagnosis": verdict.diagnosis,
        }
    ]
    hypotheses = list(state.get("hypotheses", []))
    _set_status(
        hypotheses,
        hypothesis.get("id"),
        HypothesisStatus.VERIFIED.value if verdict.verified else HypothesisStatus.TESTING.value,
    )

    if verdict.verified:
        finding = Finding(
            hypothesis_id=hypothesis.get("id", ""),
            cwe=verdict.cwe or hypothesis.get("cwe", ""),
            severity=verdict.severity or "medium",
            title=hypothesis.get("title", "Verified finding"),
            description=verdict.diagnosis,
            pov_script=state.get("pending_pov", "") or "",
            evidence={
                "stdout": result.get("stdout"),
                "stderr": result.get("stderr"),
                "exit_code": result.get("exit_code"),
                "expected_signal": state.get("pending_expected_signal"),
                "diagnosis": verdict.diagnosis,
            },
        )
        findings = [*state.get("findings", []), finding.model_dump(mode="json")]
        nxt = _next_open(state, hypothesis.get("id"))
        # Fix verified -> Patcher (if there's source to patch); else next/END.
        if state.get("target_path"):
            nxt_route = Route.PATCHER
        else:
            nxt_route = Route.ACTOR if nxt else Route.END
        return {
            "findings": findings,
            "hypotheses": hypotheses,
            "current_hypothesis_id": nxt["id"] if nxt else None,
            "last_result": None,
            "critique": None,
            "route": nxt_route,
            "transcript": transcript,
        }

    return {
        "hypotheses": hypotheses,
        "critique": verdict.rewrite_instructions or verdict.diagnosis,
        "route": Route.ACTOR,
        "transcript": transcript,
    }


def _critic_prompt(hypothesis: dict[str, Any], result: dict[str, Any]) -> str:
    return (
        f"Evaluate the PoV result for hypothesis {hypothesis.get('id')} "
        f"[{hypothesis.get('cwe')}]: {hypothesis.get('title')}\n"
        f"Target: {hypothesis.get('target_path')}\n\n"
        f"exit_code: {result.get('exit_code')}\n"
        f"timed_out: {result.get('timed_out')}\n"
        f"stdout:\n{(result.get('stdout') or '')[:6000]}\n\n"
        f"stderr:\n{(result.get('stderr') or '')[:4000]}\n\n"
        "Decide if the flaw was genuinely triggered. If not, give precise rewrite instructions."
    )


# --------------------------------------------------------------------------- #
# Patcher (differential patch verification)
# --------------------------------------------------------------------------- #
async def patcher_node(state: HuntState) -> dict[str, Any]:
    """Patch the just-verified finding and prove the fix by re-running the PoV.

    The exact same PoV is executed against a patched copy of the target. The
    patch is accepted only if the PoV's success marker no longer appears — a
    deterministic proof that the fix closes the vulnerability.
    """
    target_path = state.get("target_path", "")
    pov = state.get("pending_pov") or ""
    signal = state.get("pending_expected_signal") or "POV_SUCCESS"
    findings = list(state.get("findings", []))

    if not findings:
        return {"route": _after_patch_route(state),
                "transcript": [{"node": "patcher", "note": "no findings to patch"}]}
    finding = findings[-1]
    if finding.get("patch_verified") is not None:
        return {"route": _after_patch_route(state),
                "transcript": [{"node": "patcher", "note": "finding already patched"}]}
    if not target_path or not pov:
        return {"route": _after_patch_route(state),
                "transcript": [{"node": "patcher", "note": "no source/PoV to patch"}]}

    hypothesis = _current_hypothesis(state) or {
        "id": finding.get("hypothesis_id"),
        "cwe": finding.get("cwe"),
        "title": finding.get("title"),
        "target_path": "",
    }

    try:
        codebase = await read_codebase(target_path, ReadDepth.FULL, max_files=120)
    except ToolError:
        codebase = {"files": []}

    plan = await generate_structured_response_async(
        prompt=_patcher_prompt(finding, hypothesis, codebase),
        schema=PatchPlan,
        system_prompt=PATCHER_SYSTEM,
        retries=3,
        context={"finding": finding, "hypothesis": hypothesis, "target_path": target_path},
    )
    patches = [pf.model_dump() for pf in plan.patched_files]

    # Materialize the patched copy of the target.
    try:
        patched = await apply_source_patch(target_path, patches)
    except ToolError as exc:
        _mark_patch(finding, verified=False, patches=patches, rationale=plan.rationale, error=str(exc))
        return {
            "findings": findings,
            "route": _after_patch_route(state),
            "transcript": [{"node": "patcher", "finding": finding.get("hypothesis_id"),
                            "error": str(exc)}],
        }

    # Optional smoke build/test against the patched tree.
    smoke_ok = True
    if plan.smoke_command:
        try:
            smoke = await execute_sandbox_script(
                plan.smoke_command,
                env_vars={"POV_TARGET": patched["patched_root"]},
                timeout_s=120,
            )
            smoke_ok = smoke.get("exit_code") == 0
        except ToolError:
            smoke_ok = False  # treat missing harness as non-blocking; rely on PoV re-run

    # The proof: re-run the EXACT same PoV against the patched tree.
    rerun = await execute_sandbox_script(
        pov,
        env_vars={"POV_TARGET": patched["patched_root"], "POV_HYPOTHESIS": finding.get("hypothesis_id", "")},
    )
    now_triggered = bool(signal) and (signal in (rerun.get("stdout") or ""))
    inconclusive = bool(rerun.get("timed_out"))
    patch_verified = smoke_ok and (not inconclusive) and (not now_triggered)

    _mark_patch(
        finding,
        verified=patch_verified,
        patches=patches,
        patched_root=patched["patched_root"],
        rationale=plan.rationale,
        rerun=rerun,
        smoke_ok=smoke_ok,
    )
    return {
        "findings": findings,
        "route": _after_patch_route(state),
        "transcript": [
            {
                "node": "patcher",
                "finding": finding.get("hypothesis_id"),
                "patch_verified": patch_verified,
                "still_triggered": now_triggered,
                "rerun_exit": rerun.get("exit_code"),
                "smoke_ok": smoke_ok,
            }
        ],
    }


def _patcher_prompt(
    finding: dict[str, Any], hypothesis: dict[str, Any], codebase: dict[str, Any]
) -> str:
    files_blob = json.dumps(
        [{"path": f.get("path"), "content": f.get("content", "")}
         for f in codebase.get("files", []) if f.get("content")][:40]
    )[:12000]
    return (
        "Patch the VERIFIED vulnerability below. Return FULL new file contents.\n\n"
        f"Finding: {finding.get('title')} [{finding.get('cwe')}]\n"
        f"Description: {finding.get('description')}\n"
        f"Hypothesis target: {hypothesis.get('target_path')}\n\n"
        f"PoV that currently triggers it:\n{(finding.get('pov_script') or '')[:4000]}\n\n"
        f"Relevant source (path -> content):\n{files_blob}\n\n"
        "Produce `patched_files` (full new_content per changed file) and a smoke_command if any."
    )


def _mark_patch(
    finding: dict[str, Any],
    *,
    verified: bool,
    patches: Optional[list[dict[str, Any]]] = None,
    patched_root: Optional[str] = None,
    rationale: str = "",
    rerun: Optional[dict[str, Any]] = None,
    smoke_ok: Optional[bool] = None,
    error: Optional[str] = None,
) -> None:
    finding["patch"] = {
        "patched_files": [p.get("path") for p in (patches or [])],
        "patched_root": patched_root,
        "rationale": rationale,
        "smoke_ok": smoke_ok,
    }
    finding["patch_verified"] = verified
    if rerun is not None:
        finding["patch_evidence"] = {
            "stdout": rerun.get("stdout"),
            "stderr": rerun.get("stderr"),
            "exit_code": rerun.get("exit_code"),
            "timed_out": rerun.get("timed_out"),
        }
    if error:
        finding["patch_error"] = error


def _after_patch_route(state: HuntState) -> Route:
    """After patching, test the next hypothesis if any remain, else end."""
    if state.get("current_hypothesis_id"):
        return Route.ACTOR
    return Route.ACTOR if _next_open(state, None) else Route.END
