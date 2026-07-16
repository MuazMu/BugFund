# ADR 0001 — Three-Plane Separation

- **Status:** Accepted
- **Date:** 2026-07-15
- **Related:** [README §3 — System Architecture](../../README.md#3-system-architecture),
  [`PROJECT_STRUCTURE.md` — Dependency direction](../../PROJECT_STRUCTURE.md#dependency-direction-enforced),
  [ADR 0003](./0003-internal-only-sandbox-api.md)

## Context

BugFund has three fundamentally different kinds of work happening at once:

1. Serving HTTP, persisting state, and running a task queue (**control plane**).
2. LLM-driven reasoning over a shared state machine (**agent swarm**).
3. Running untrusted code inside ephemeral Docker containers (**execution engine**).

These three concerns have incompatible change velocities, testability requirements, and risk
profiles. The reasoning layer iterates on prompts and schemas weekly; the sandbox layer iterates on
kernel hardening profiles rarely but under high scrutiny; the control plane iterates on API
contracts somewhere in between. If they are tangled into one package, every change risks crossing a
trust boundary, and every unit test drags in dependencies it should not need (e.g., reasoning-logic
tests that require a running Postgres, or sandbox tests that require a provider API key).

We needed a package structure that makes the trust and dependency direction explicit and
non-circumventable at review time.

## Decision

Organize the codebase as **three top-level packages** with a strict, acyclic, downward dependency
direction:

```
control_plane  ──▶  agent_swarm  ──▶  execution_engine
     │                  │
     └──── ai_gateway ◀─┘        (both control_plane & agent_swarm call the gateway)
            │
            └─▶ observability    (every plane emits telemetry)
```

- `execution_engine/` depends on **nothing** above it — no `agent_swarm`, no `control_plane`. It is
  a leaf concerned only with container lifecycle, isolation policy, and evidence collection.
- `agent_swarm/` depends on `execution_engine` (through `skills/sandbox_tool.py`) and `ai_gateway`
  only. It contains no DB access and serves no HTTP.
- `control_plane/` depends on `agent_swarm` (to compile the graph) and on its own DB/queue. It never
  imports `execution_engine` directly — it reaches the engine only *through* the swarm's
  `sandbox_tool`, preserving the engine's ignorance of the plane above.

The cross-cutting layers `ai_gateway/` and `observability/` are leaves: anyone imports them, they
import no one above.

## Consequences

**Positive**

- Each plane is independently unit-testable: the execution engine is testable with no swarm and no
  control plane importable; the swarm is testable with no DB; the control plane integration tests
  compose all three.
- Trust boundaries map directly to import boundaries. The engine, which runs untrusted code, is
  structurally incapable of reaching tenant data because it cannot import the DB layer.
- Change velocity is decoupled. Prompt/schema churn lives entirely in `agent_swarm`; kernel
  hardening lives entirely in `execution_engine`.
- Deployment is flexible: the engine can be moved to a dedicated hardened node, or the swarm to a
  GPU pool, without touching the control plane.

**Negative**

- Three packages means more boilerplate (`__init__.py`, separate test trees, separate review
  owners). This is accepted as the cost of the boundaries above.
- The control plane must reach the engine indirectly via the swarm's `sandbox_tool` rather than
  calling the engine directly. This is intentional but adds one indirection.
- Enforcement is review-time and test-time, not compile-time (Python has no module-level visibility
  modifier). Mitigated by unit tests that must pass without the layers above importable.

## Alternatives Considered

- **Single monolithic package** (`bugfund/` with submodules). Rejected: trust boundaries become
  convention, not structure; a single `import` can silently cross from the engine to the DB. Not
  acceptable for a system that runs untrusted code.

- **Two-package split** (fuse the swarm into the control plane, since the control plane compiles the
  graph). Rejected: coupling prompt logic to the DB layer makes swarm nodes un-unit-testable without
  Postgres, and couples the two fastest-iterating surfaces (API contracts and prompts) together.

- **Four-package split** (also separate `ai_gateway` and `observability` as first-class planes).
  Rejected as over-modeling: those two are *cross-cutting leaves*, not planes with their own trust
  boundaries or deployable surfaces. Keeping them as leaves, rather than planes, preserves the
  three-plane narrative while still giving them their own packages.

- **Layered `src/` layout with namespace packages.** Rejected for now: adds tooling complexity
  (editable installs, PEP 621 src layout) without strengthening the boundary over a clear top-level
  package convention. Revisit if the monorepo grows additional products.
