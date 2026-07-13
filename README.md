# BugFund CRS — Autonomous Vulnerability Discovery Platform

> A B2B **Cyber Reasoning System (CRS)** orchestration platform, architected in the spirit of
> DARPA's **AIxCC** (AI Cyber Challenge). BugFund coordinates a multi-agent swarm to autonomously
> discover, prove, and triage vulnerabilities inside isolated execution sandboxes — at scale.

BugFund is **not** an LLM wrapper. It is a *reasoning pipeline*: a state machine that routes work
between specialized agents, materializes hypotheses as executable proof-of-vulnerabilities (PoVs),
validates them against the real target inside ephemeral Docker sandboxes, and converges on
high-confidence findings through an **Actor–Critic** feedback loop.

---

## Table of Contents

1. [What Is a Cyber Reasoning System?](#1-what-is-a-cyber-reasoning-system)
2. [Design Principles](#2-design-principles)
3. [System Architecture](#3-system-architecture)
4. [The Agent Swarm](#4-the-agent-swarm)
5. [Data Flow — The Actor–Critic Loop](#5-data-flow--the-actorcritic-loop)
6. [Orchestration — LangGraph State Machine](#6-orchestration--langgraph-state-machine)
7. [Execution Engine & Sandbox Isolation](#7-execution-engine--sandbox-isolation)
8. [AI Gateway (Model-Agnostic LLM Proxy)](#8-ai-gateway-model-agnostic-llm-proxy)
9. [Technology Stack](#9-technology-stack)
10. [Repository Layout](#10-repository-layout)
11. [Setup & Installation](#11-setup--installation)
12. [Configuration](#12-configuration)
13. [API Overview](#13-api-overview)
14. [Safety, Scope & Responsible Use](#14-safety-scope--responsible-use)
15. [Roadmap](#15-roadmap)
16. [License](#16-license)

---

## 1. What Is a Cyber Reasoning System?

A **Cyber Reasoning System** is a system that autonomously reasons about software to find
security flaws. DARPA's **AIxCC** established the modern reference architecture: a CRS ingests
one or more "challenge binaries" (or services), then autonomously:

- **Discovers** the attack surface,
- **Hypothesizes** vulnerability classes (buffer overflows, type confusions, logic bugs, injection, etc.),
- **Crafts** a proof-of-vulnerability (PoV) — an input or sequence that triggers the bug,
- **Validates** that the PoV genuinely triggers the flaw in a controlled harness,
- **Reports** a triaged finding with evidence, severity, and remediation guidance.

BugFund generalizes this model to a **B2B SaaS**: tenants submit targets (container images,
binaries, source repos), the swarm runs an investigation **campaign**, and verified findings are
returned through an API with full reproducibility artifacts.

> **Defensive intent.** BugFund exists to find vulnerabilities *so they can be fixed*. It is
> scoped to targets the operator is authorized to test. See [§14](#14-safety-scope--responsible-use).

---

## 2. Design Principles

| Principle | What it means in practice |
|---|---|
| **Separation of concerns across three planes** | *Control plane* (API + DB + orchestrator), *agent swarm* (LLM nodes), and *execution engine* (sandboxes) are independently deployable and independently testable. |
| **Hypothesis → Action → Evidence** | Agents never *claim* a vulnerability. Every claim must be backed by a sandbox-validated PoV. The Critic enforces this contract. |
| **Safety by isolation** | Untrusted target code and agent-generated test cases run **only** inside ephemeral, hardened, network-restricted containers that are torn down after each step. |
| **Deterministic orchestration, probabilistic agents** | LangGraph provides a deterministic, inspectable state machine. The LLM agents are the probabilistic reasoning components executing *inside* that machine. |
| **Model-agnostic by design** | No agent is hard-coupled to a provider. The AI Gateway routes through LiteLLM so models can be swapped, fallback-chained, and budget-capped per campaign. |
| **Full reproducibility** | Every campaign is checkpointed: inputs, agent messages, sandbox invocations, and outputs are persisted so a finding can be replayed and audited. |

---

## 3. System Architecture

BugFund is organized into **three primary planes** plus two cross-cutting support layers.

```
                         ┌─────────────────────────────────────────────┐
   Tenant (B2B)  ───────▶│              CONTROL PLANE                  │
   POST /targets         │  FastAPI  •  PostgreSQL  •  Celery/Redis    │
   POST /campaigns       │  LangGraph Orchestrator (state machine)     │
                         └───────────────┬─────────────────────────────┘
                                         │  (compiled graph execution)
                            ┌────────────▼────────────┐
                            │      AGENT SWARM        │
                            │  Supervisor             │
                            │  Threat Modeler         │
                            │  Actor  ⇄  Critic       │  ◀── AI Gateway (LiteLLM)
                            │  Reporter               │
                            └────────────┬────────────┘
                                         │  (tool calls: run PoV, collect evidence)
                         ┌───────────────▼─────────────────────────────┐
                         │           EXECUTION ENGINE                 │
                         │  Docker SDK  •  ephemeral sandbox pool     │
                         │  harnesses  •  crash/log/trace collectors  │
                         └─────────────────────────────────────────────┘
                                         │
                                  (evidence + verdicts flow back up)
```

### Cross-cutting layers

- **`ai_gateway/`** — a model-agnostic LLM proxy (LiteLLM) that all agents call instead of any
  provider SDK directly. Handles routing, fallback, retries, token budgets, and LLM tracing.
- **`observability/`** — OpenTelemetry tracing, metrics, and LLM-specific tracing (Langfuse)
  wired across all three planes.

### Responsibility split

| Plane | Owns | Does **not** own |
|---|---|---|
| **Control plane** | HTTP entry, persistence, task queue, the LangGraph graph definition & runner | LLM prompting logic, container internals |
| **Agent swarm** | Node implementations, prompts, skills/tools, routing policies | Database access, HTTP serving |
| **Execution engine** | Container lifecycle, isolation policy, evidence collection | Reasoning about *what* to run next |

---

## 4. The Agent Swarm

The swarm is a small set of highly-specialized roles. Each is a **LangGraph node** (a function over
shared swarm state) backed by an LLM persona and a set of **skills** (deterministic tools).

### Supervisor
The conductor. Reads the campaign state and decides **which agent runs next** (a conditional edge
in the graph). It enforces the global budget (wall-clock, steps, tokens, dollars), terminates the
campaign when the budget is exhausted or a termination criterion is met, and resolves contention
between agents. The Supervisor holds no domain opinions — it routes.

### Threat Modeler
The first specialist on any target. Produces a structured **threat model**: attack-surface map,
entry points, trust boundaries, and ranked **CWE hypotheses** (e.g., `CWE-121` stack overflow,
`CWE-416` use-after-free, `CWE-89` SQL injection). Output becomes the prioritized backlog the
Actor pulls from. Often uses static-analysis skills (disassembly, code review, AST queries).

### Actor
The offensive reasoner. Given a CWE hypothesis (or Critic feedback), the Actor proposes a concrete,
**executable** action: a fuzzing configuration, a crafted input, a stateful sequence, or a PoV
candidate. It then requests the execution engine run it. The Actor is creative and willing to fail —
its job is to *generate* candidate evidence, not to judge it.

### Critic
The adversarial evaluator. For every Actor output, the Critic asks: *did this actually trigger the
hypothesized flaw?* It scores confidence, rejects false positives (e.g., benign crashes, harness
artifacts), maps confirmed triggers to CWE/CVSS, and — crucially — **returns structured feedback**
to the Actor for the next iteration. A finding only graduates to "verified" when the Critic accepts
it with a reproducible PoV.

### Reporter
Runs once at termination. Aggregates verified findings into a triaged report: vulnerability
description, CWE/CVSS, the minimal PoV, sandbox evidence (logs/crash dumps), and remediation
guidance.

```
                ┌───────────────┐
                │  Supervisor   │  (routing + budget + termination)
                └───────┬───────┘
                        │
                ┌───────▼───────┐
                │ Threat Modeler│  ──▶ CWE hypothesis backlog
                └───────┬───────┘
                        │
              ┌─────────▼─────────┐
              │       Actor       │  ──▶ candidate PoV ──▶ [sandbox]
              └─────────┬─────────┘            │ evidence
                        │                       │
                ┌───────▼───────┐               │
                │     Critic    │ ◀─────────────┘
                └───────┬───────┘
                        │  (accept → verified finding · reject → feedback to Actor)
                        │
                ┌───────▼───────┐
                │    Reporter   │
                └───────────────┘
```

---

## 5. Data Flow — The Actor–Critic Loop

This is the heart of BugFund. Each campaign walks the following path; the Actor–Critic pair is a
**converging refinement loop**.

```
 ① INGEST            ② PLAN                 ③ HYPOTHESIZE
 ─────────           ───────                ─────────────
 Tenant submits      Supervisor creates     Threat Modeler maps
 target image/       a campaign, allocates  attack surface, emits
 binary/source       budget, pulls in       ranked CWE hypotheses
 via API.            the threat modeler.    into the backlog.

 ④ ACT (propose)     ⑤ EXECUTE (sandbox)    ⑥ CRITIQUE (evaluate)
 ──────────────      ──────────────────     ────────────────────
 Actor pops a        Execution engine runs  Critic inspects evidence:
 hypothesis, crafts  the PoV in an ephemeral did it trigger the *real*
 a candidate PoV     hardened container.    flaw? crash legitimacy,
 /test action.       Collects logs/crash/   CWE match, reproducibility.
                     traces as evidence.

 ⑦ DECISION (loop or graduate)
 ─────────────────────────────
  ┌── REJECT  ──▶ Critic feedback → back to ④ (Actor refines)   ──┐
  │                                                                │ ▼ (loop)
  └── ACCEPT  ──▶ verified finding persisted to DB ──────────────▶ next hypothesis

 ⑧ TERMINATE         ⑨ REPORT
 ───────────         ────────
 Budget exhausted    Reporter emits the
 or backlog empty →  triaged, reproducible
 Supervisor halts.   findings report.
```

### Why the loop converges

- **Asymmetric roles.** The Actor optimizes for *recall* (find something); the Critic optimizes for
  *precision* (is it real?). Keeping these in separate agents prevents the common failure mode of a
  single agent talking itself into a false positive.
- **Evidence-grounded feedback.** The Critic returns **structured** critiques ("the crash is in the
  harness shim, not the target; re-craft input to reach `parse_header()`"), giving the Actor an
  actionable delta rather than a yes/no.
- **Bounded by budget.** The Supervisor caps iterations per hypothesis and per campaign, so the loop
  is terminating and cost-predictable.
- **Checkpointed state.** Every iteration is persisted via LangGraph's checkpointer, so a campaign
  can be paused, resumed, replayed, and audited end-to-end.

---

## 6. Orchestration — LangGraph State Machine

LangGraph is the *deterministic spine* of BugFund. It models a campaign as a directed graph over a
strongly-typed shared state.

- **State** (`agent_swarm`/orchestrator `state.py`): a `TypedDict` carrying the target handle,
  threat model, CWE backlog, the current Actor/Critic transcript, accumulated evidence, verified
  findings, and budget counters.
- **Nodes**: one per agent role (Supervisor, Threat Modeler, Actor, Critic, Reporter).
- **Edges**: the Supervisor node emits a conditional edge that selects the next node — this is the
  only place routing decisions are made, making the control flow fully inspectable.
- **Checkpointer**: Postgres-backed, enabling resume-after-crash and full replay.
- **Runner**: a Celery task that compiles the graph for a campaign and streams it to completion,
  offloading long investigations from the API request path.

```
              START
                │
                ▼
        [threat_modeler]──────────────▶ (backlog ready)
                │                            │
                ▼                            ▼
            [supervisor] ◀────────────── [supervisor]   ◀── routing hub (conditional edges)
                │              ▲              │
        "actor next"           │       "terminate"
                │              │              │
                ▼              │              ▼
            [actor] ──▶ (sandbox) ──▶ [critic] ──┐
                ▲                               │ accept
                └───── reject/feedback ─────────┘
                                                ▼
                                          [reporter] ──▶ END
```

---

## 7. Execution Engine & Sandbox Isolation

The execution engine is where **untrusted code runs**. Its design assumes everything inside a
sandbox is hostile.

- **Ephemeral containers.** Each test action runs in a brand-new container, created via the Docker
  SDK, used once, and force-removed — no state carries between actions.
- **Container pool.** A bounded pool + concurrency limiter prevents resource exhaustion when many
  campaigns run concurrently.
- **Hardened images.** A tiered image set: a stripped `base`, per-target-type `harness` images, and
  `target` ingestion images. Built non-root, read-only rootfs where possible.
- **Isolation policy.** Each container starts with: a restrictive **seccomp** profile, an
  **AppArmor** profile, **drop-all Linux capabilities**, a **no-egress** network namespace (or a
  strict allowlist), and per-container resource caps (CPU/mem/PIDs).
- **Evidence collectors.** Structured capture of stdout/stderr, `strace`/`ltrace` traces,
  AddressSanitizer output, and crash/core-dump metadata — this is the raw material the Critic
  reasons over.
- **Guaranteed teardown.** Cleanup runs in a `finally` path with a watchdog timeout; orphaned
  containers are garbage-collected by a periodic reaper.

> The execution engine exposes a small **internal** HTTP API consumed only by the swarm's
> `sandbox_tool` skill — it is never exposed to tenants.

---

## 8. AI Gateway (Model-Agnostic LLM Proxy)

Every LLM call in the swarm goes through `ai_gateway/`, never through a provider SDK directly.

- **LiteLLM under the hood** normalizes the chat/completion/embedding interfaces across providers
  (Anthropic, OpenAI, open-weight/self-hosted, etc.).
- **Routing & fallback**: per-role model assignment (e.g., a strong reasoning model for the Critic,
  a faster model for the Supervisor) with automatic fallback chains.
- **Budget guard**: per-campaign and per-agent token/USD caps enforced at the gateway, so a runaway
  agent cannot exceed its allocation.
- **Structured output enforcement**: agents that must return JSON (hypothesis lists, verdicts) get
  schema-validated responses with retry-on-malformed.
- **LLM tracing**: every call is logged with latency, tokens, cost, and prompt/response hashes,
  feeding the observability layer.

---

## 9. Technology Stack

| Concern | Choice |
|---|---|
| Backend API | **FastAPI** (Python 3.11+) |
| Persistence | **PostgreSQL** + **SQLAlchemy 2.x** (async) |
| Migrations | **Alembic** |
| Async task queue | **Celery** + **Redis** (broker & result backend) |
| Agent orchestration | **LangGraph** (Postgres checkpointer) |
| Execution sandbox | **Docker SDK for Python** |
| LLM gateway | **LiteLLM** |
| Validation | **Pydantic v2** |
| Observability | **OpenTelemetry** + **Langfuse** (LLM tracing) |
| Container orchestration (dev) | **Docker Compose** |

---

## 10. Repository Layout

BugFund separates the three planes as top-level packages. A fully-annotated, file-level tree lives
in **[`PROJECT_STRUCTURE.md`](./PROJECT_STRUCTURE.md)**. High-level summary:

```
bugfund-crs/
├── control_plane/        # API (FastAPI) • DB (SQLAlchemy/Postgres) • Orchestrator (LangGraph) • Celery
│   ├── api/              # HTTP layer, v1 routers, Pydantic schemas, middleware (auth/tenant/rate-limit)
│   ├── db/               # models, async session, Alembic migrations
│   ├── orchestrator/     # graph construction, swarm state, runner, budget, checkpointer
│   ├── tasks/            # Celery app + campaign/sandbox task definitions
│   └── core/             # config, logging, security, exceptions
│
├── agent_swarm/          # LangGraph nodes • prompts • skills • routing policy
│   ├── nodes/            # supervisor, threat_modeler, actor, critic, reporter
│   ├── prompts/          # per-role prompt templates + shared system/schemas
│   ├── skills/           # deterministic tools: disasm, code_review, fuzz bridge, PoV crafter, sandbox tool
│   ├── memory/           # short-term (graph state) + long-term (vector RAG of prior findings)
│   └── routing/          # conditional edges + supervisor decision policy
│
├── execution_engine/     # Docker managers • sandbox API • isolation profiles • evidence collectors
│   ├── sandbox/          # manager, pool, runner, guaranteed teardown
│   ├── images/           # base / harness / target Dockerfiles
│   ├── api/              # internal sandbox HTTP server
│   ├── isolation/        # seccomp, AppArmor, network policy
│   └── collectors/       # logs, traces, crash/ASan parsing
│
├── ai_gateway/           # LiteLLM proxy: routing, fallback, budget guard, provider config
├── observability/        # OpenTelemetry tracing, metrics, Langfuse LLM tracing
├── tests/                # unit / integration / e2e
├── scripts/              # dev + seed scripts
└── docs/                 # architecture, ADRs, threat model
```

---

## 11. Setup & Installation

### Prerequisites

- **Python 3.11+**
- **Docker** (with the Docker daemon running) and **Docker Compose v2**
- **PostgreSQL 15+** and **Redis 7+** — or just use the bundled Compose stack (recommended)
- `make` (optional, for the convenience targets)

### 1. Clone & create the environment

```bash
git clone <your-org>/bugfund-crs.git
cd bugfund-crs

python -m venv .venv
# Windows (PowerShell):  .\.venv\Scripts\Activate.ps1
# macOS / Linux:         source .venv/bin/activate
pip install -U pip
pip install -e ".[dev]"
```

### 2. Configure environment

```bash
cp .env.example .env
# edit .env — set DATABASE_URL, REDIS_URL, LLM provider keys, Docker socket path, etc.
```

### 3. Start infrastructure (Postgres, Redis)

```bash
docker compose up -d postgres redis
```

### 4. Apply database migrations

```bash
alembic upgrade head
```

### 5. Build the sandbox images

The execution engine needs its hardened image tiers built once:

```bash
make sandbox-images      # builds execution_engine/images/{base,harness,target}
```

### 6. Run the services

Open three terminals (or use the provided process manager / Make targets):

```bash
# Control plane API
uvicorn control_plane.api.main:app --reload --port 8000

# Celery worker (runs campaigns + sandbox jobs)
celery -A control_plane.tasks.celery_app worker -l info -Q campaigns,sandbox

# Celery beat (optional — periodic reaper / budget sweeps)
celery -A control_plane.tasks.celery_app beat -l info
```

### 7. Smoke test

```bash
make smoke       # submits a demo target and polls for a campaign result
```

### Docker Compose (full stack)

To run everything (API, worker, Postgres, Redis) in containers:

```bash
docker compose up -d
```

---

## 12. Configuration

All configuration is environment-driven via `pydantic-settings`
(`control_plane/core/config.py`). Key groups:

| Group | Example vars |
|---|---|
| **App** | `APP_ENV`, `LOG_LEVEL`, `API_PREFIX=/api/v1` |
| **Database** | `DATABASE_URL=postgresql+asyncpg://...` |
| **Redis / Queue** | `REDIS_URL=redis://...`, `CELERY_QUEUES=campaigns,sandbox` |
| **LLM (gateway)** | `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `LLM_ROUTING_CONFIG`, per-role model overrides |
| **Sandbox** | `DOCKER_HOST`, `SANDBOX_MAX_CONCURRENCY`, `SANDBOX_TIMEOUT_S`, `SANDBOX_NO_EGRESS=true` |
| **Budgets** | `DEFAULT_CAMPAIGN_MAX_STEPS`, `DEFAULT_CAMPAIGN_MAX_TOKENS`, `DEFAULT_CAMPAIGN_MAX_USD` |
| **Observability** | `OTEL_EXPORTER_OTLP_ENDPOINT`, `LANGFUSE_*` |

A complete, commented template is provided in [`.env.example`](./.env.example).

---

## 13. API Overview

All endpoints are versioned under `/api/v1` and require tenant authentication (API key or mTLS).

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/targets` | Ingest a target (image / binary / source archive) |
| `GET`  | `/targets/{id}` | Fetch target metadata + ingestion status |
| `POST` | `/campaigns` | Launch an investigation campaign against a target |
| `GET`  | `/campaigns/{id}` | Campaign status, progress, budget consumed |
| `GET`  | `/campaigns/{id}/trace` | Replayable agent transcript (LangGraph checkpoints) |
| `GET`  | `/targets/{id}/findings` | Verified findings (CWE, CVSS, PoV, evidence refs) |
| `GET`  | `/findings/{id}/evidence` | Download sandbox evidence bundle |
| `GET`  | `/tasks/{id}` | Async Celery task status |
| `GET`  | `/health` | Liveness / readiness |

Interactive docs are auto-generated at `/docs` (Swagger) and `/redoc`.

---

## 14. Safety, Scope & Responsible Use

BugFund is engineered for **authorized, defensive** vulnerability discovery. The platform enforces
safety through both architecture and policy:

- **Containment first.** Target code and agent-generated inputs execute *only* inside ephemeral,
  capability-dropped, network-restricted containers. The execution engine has no path to tenant
  networks or the control plane's data store.
- **Tenant isolation.** All data is multi-tenant isolated at the DB and API layers; one tenant
  cannot observe another's targets, transcripts, or findings.
- **Authorization boundary.** Operators are responsible for submitting only targets they are
  authorized to assess. The platform is intended for the operator's own software, software they are
  engaged to test, or explicitly authorized evaluation corpora (e.g., AIxCC challenge sets).
- **No weaponization.** BugFund produces triage-grade PoVs sufficient to demonstrate and fix a flaw.
  It does not generate operational exploits, C2, or evasion tooling.
- **Auditability.** Every campaign is fully checkpointed and replayable; every LLM call is traced.

Misuse of this software against systems without authorization is prohibited and may be illegal.

---

## 15. Roadmap

- [ ] Long-term agent memory: cross-campaign RAG over an org's historical findings.
- [ ] Source-level vs. binary-level threat modeler specialization.
- [ ] Auto-remediation / patch-suggestion node (defensive counterpart to the Actor).
- [ ] GPU sandbox tier for model-assisted binary analysis.
- [ ] Multi-tenant billing & usage metering on the gateway.

---

## 16. License

TBD — see [`LICENSE`](./LICENSE) (add before any distribution).
