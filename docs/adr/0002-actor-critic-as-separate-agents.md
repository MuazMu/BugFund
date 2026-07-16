# ADR 0002 — Actor and Critic as Separate Agents

- **Status:** Accepted
- **Date:** 2026-07-15
- **Related:** [README §4 — The Agent Swarm](../../README.md#4-the-agent-swarm),
  [README §5 — Data Flow: The Actor-Critic Loop](../../README.md#5-data-flow--the-actorcritic-loop)

## Context

The core of a Cyber Reasoning System is the loop that turns a vulnerability hypothesis into verified
evidence: *propose a PoV → run it → evaluate the result → refine*. There are two distinct
optimization objectives inside that loop:

- **Recall** — generate *something* that might trigger the hypothesized flaw. This rewards
  creativity, breadth, and a willingness to fail. A recall-optimized reasoner should propose many
  candidate PoVs, including low-probability ones.
- **Precision** — decide whether the evidence *actually* demonstrates the hypothesized flaw. This
  rewards skepticism, evidence-groundedness, and a refusal to be convinced by anything other than
  reproducible, in-target signal. A precision-optimized reasoner should reject benign crashes,
  harness artifacts, and Actor narratives.

A single agent asked to do both roles tends to exhibit a well-known failure mode: it talks itself
into its own proposal. Once an LLM has generated a candidate PoV and articulated why it *should*
work, it is biased to find that reasoning persuasive when asked to evaluate the result. This
produces false-positive findings — the single most damaging failure mode for a vulnerability
discovery tool, because it erodes operator trust and wastes remediation effort.

We had to decide whether to implement this loop as one agent wearing two hats, or as two distinct
agents with asymmetric objectives.

## Decision

Implement **Actor** and **Critic** as **two separate LangGraph nodes backed by separate LLM
personas**, with the Critic as the sole authority to graduate a finding:

- The **Actor** (offensive reasoner) optimizes for recall. It pops a CWE hypothesis, crafts a
  candidate PoV or test action, and requests execution. It has no authority to declare a finding.
- The **Critic** (adversarial evaluator) optimizes for precision. For every Actor output it asks:
  *did this actually trigger the hypothesized flaw in the real target?* It scores confidence,
  rejects false positives (benign crashes, harness shim artifacts, non-reproducible signals), maps
  confirmed triggers to CWE/CVSS, and returns **structured feedback** to the Actor for the next
  iteration. A finding only graduates to `verified` when the Critic accepts it with a reproducible
  PoV.

The two agents do not share hidden state beyond the explicit LangGraph swarm state. The Critic
reasons over **collected sandbox evidence**, not the Actor's narrative.

## Consequences

**Positive**

- Eliminates the single-agent self-persuasion failure mode. The Actor cannot graduate its own
  proposal; an independent agent with a precision objective must be convinced by evidence.
- Asymmetric objectives can be tuned independently: the Actor prompt rewards breadth; the Critic
  prompt rewards skepticism. Different model tiers can be assigned (e.g., a stronger reasoning model
  for the Critic, a faster model for the Actor) via the AI Gateway.
- Structured feedback from the Critic gives the Actor an actionable delta ("the crash is in the
  harness shim, not the target; re-craft input to reach `parse_header()`") rather than a yes/no,
  making the refinement loop converge instead of restart.
- The loop is bounded by the Supervisor's per-hypothesis and per-campaign budget, so it is
  terminating and cost-predictable regardless of how the two agents interact.

**Negative**

- Two agents means two LLM calls per iteration, roughly doubling per-step LLM cost versus a single
  agent. Accepted: the cost is justified by the precision gain, and the budget guard caps it.
- Two prompts to maintain in parallel. Accepted: the prompts have disjoint objectives, so they do
  not suffer from duplication drift.
- A pathological Critic could reject everything, stalling the loop. Mitigated by the budget cap
  (which forces termination) and by the Supervisor's authority to reprioritize the backlog away from
  a stuck hypothesis.

## Alternatives Considered

- **Single "investigator" agent** that proposes and then self-evaluates. Rejected: empirically prone
  to false-positive self-endorsement. This is the primary failure mode this ADR exists to prevent.

- **Single agent with an external deterministic verifier** (no LLM Critic). Rejected for the
  general case: deterministic verification works for well-instrumented targets (AIxCC challenge
  binaries with crash oracles), but BugFund must handle arbitrary targets where "did this trigger
  the real flaw?" is itself a reasoning problem requiring the Critic to interpret ASan output,
  distinguish harness from target, and judge reproducibility. A deterministic verifier alone cannot
  do this in general.

- **N-Critic ensemble** (multiple Critic agents must agree). Rejected for now as cost-ineffective at
  the current stage; the single-Critic-plus-evidence-grounding design already bounds false
  positives adequately. Revisit if false-positive rates in production warrant an ensemble quorum.

- **Critic as a deterministic post-processor** over evidence (regex/rule-based). Rejected: too
  brittle across target types and vulnerability classes; the Critic's value is precisely that it can
  reason about novel evidence shapes.
