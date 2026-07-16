# Architecture Deep-Dive — BugFund CRS

> Companion to [`README.md`](../README.md). This document expands the three-plane architecture into
> a **deployment view**, **sequence diagrams**, the **dependency-direction rule**, the **data model**,
> and the **budget / checkpoint / resume** mechanics. Read the README first for orientation.

---

## Table of Contents

1. [Deployment View](#1-deployment-view)
2. [Sequence Diagrams](#2-sequence-diagrams)
3. [Dependency-Direction Rule](#3-dependency-direction-rule)
4. [Data Model Overview](#4-data-model-overview)
5. [Budget, Checkpoint & Resume](#5-budget-checkpoint--resume)

---

## 1. Deployment View

BugFund runs as a set of cooperating processes over Postgres + Redis. In production these are
independent deployables; in dev they come up via `docker compose`.

```
                         ┌──────────────────────────────────────────────────────────────┐
                         │                        TENANT (B2B)                           │
                         │   POST /api/v1/targets   POST /api/v1/campaigns   GET /trace  │
                         └─────────────────────────────────┬────────────────────────────┘
                                                           │ HTTPS (API key / mTLS)
                         ┌─────────────────────────────────▼────────────────────────────┐
                         │                          API (FastAPI)                        │
                         │   uvicorn control_plane.api.main:app                          │
                         │   • routers (targets/campaigns/findings/tasks/health)         │
                         │   • auth + tenant + rate-limit middleware                     │
                         │   • enqueue Celery task on campaign launch                    │
                         │   • LangGraph graph construction (reads compiled graph spec)   │
                         └──────────┬───────────────────────────────┬────────────────────┘
                                    │ async (asyncpg)               │ enqueue
                  ┌─────────────────▼──────────────┐    ┌────────────▼─────────────┐
                  │        PostgreSQL 15           │    │     Redis 7 (broker)     │
                  │  tenants · targets · campaigns │◄──►│  results backend · queue │
                  │  findings · agent_runs · tasks │    │  Celery events           │
                  │  LangGraph checkpoints         │    └────────────┬─────────────┘
                  │  budget ledger                 │                 │
                  └────────────────────────────────┘                 │
                                                                     │ consume (Q: campaigns, sandbox)
                         ┌───────────────────────────────────────────▼──────────────────────┐
                         │                          WORKER (Celery)                          │
                         │   celery -A control_plane.tasks.celery_app worker                 │
                         │   • run_campaign task → orchestrator.runner → compiled swarm graph│
                         │   • sandbox_jobs task → reaper / evidence GC / budget sweeps      │
                         │   • holds the Docker SDK client (manages sandbox pool)            │
                         └──────────┬─────────────────────────┬─────────────────────────────┘
                                    │ HTTP (internal)         │ Docker SDK
                                    │ to sandbox API          │ over /var/run/docker.sock
                         ┌──────────▼───────────┐  ┌──────────▼──────────────────────────────┐
                         │  SANDBOX API (ASGI)  │  │           SANDBOX POOL                  │
                         │  execution_engine/   │  │   ephemeral, cap-dropped, no-egress     │
                         │  api/server.py       │──▶   containers (base / harness / target)  │
                         │  run · cancel · collect│  │   evidence collectors → blob store      │
                         └──────────────────────┘  └─────────────────────────────────────────┘

                         ┌──────────────────────────────────────────────────────────────────┐
                         │                            BEAT (Celery)                          │
                         │   celery -A control_plane.tasks.celery_app beat                   │
                         │   schedules: orphan reaper, budget sweeps, checkpoint GC          │
                         └──────────────────────────────────────────────────────────────────┘

                         ┌──────────────────────────────────────────────────────────────────┐
                         │   AI Gateway (LiteLLM proxy)  ←─ all agent LLM calls              │
                         │   Observability sink (OTLP)  ←─ spans + metrics from all planes   │
                         │   Langfuse                  ←─ LLM call tracing                  │
                         └──────────────────────────────────────────────────────────────────┘
```

### Components

| Component | Process | Owns | Listens on |
|---|---|---|---|
| **api** | `uvicorn control_plane.api.main:app` | HTTP entry, request validation, tenant auth, task enqueue | `:8000` (tenant-facing) |
| **worker** | `celery -A control_plane.tasks.celery_app worker -Q campaigns,sandbox` | Compiled graph execution, sandbox lifecycle, reaper jobs | Redis queue `campaigns`, `sandbox` |
| **beat** | `celery -A control_plane.tasks.celery_app beat` | Periodic sweeps (orphan reaper, budget enforcement, checkpoint GC) | Redis (scheduler) |
| **postgres** | Postgres 15 | All relational state + LangGraph checkpoints | `:5432` |
| **redis** | Redis 7 | Celery broker + result backend, ephemeral coordination | `:6379` |
| **sandbox API** | `execution_engine.api.server` (ASGI) | Internal HTTP wrapper around sandbox manager | internal only (loopback / overlay) |
| **sandbox pool** | Docker containers (managed by worker) | Untrusted execution: PoV runs, harnesses, target code | none (no-egress namespace) |
| **ai gateway** | LiteLLM proxy | Model-agnostic LLM routing, fallback, budget guard | internal |

### Trust boundaries

1. **Tenant → API**: only authenticated ingress. Everything past this point is operator-trusted.
2. **API → Worker**: via Redis (Celery). Messages carry campaign + tenant IDs; the worker never
   re-derives authority from tenant input beyond those IDs.
3. **Worker → Sandbox API → Sandbox pool**: untrusted code lives here. The pool has **no path back**
   to Postgres, Redis, the API, or tenant networks.
4. **Worker → Docker socket**: privileged. The socket is mounted read-only on the worker for sandbox
   management; see the [threat model](./threat_model.md) for residual risk.

---

## 2. Sequence Diagrams

### 2.1 Target ingest → Campaign launch → Swarm run → Verified finding

```
 TENANT        API           POSTGRES       REDIS         WORKER        SWARM         SANDBOX API     POOL
   │             │               │            │              │            │                │             │
   │ POST /targets│              │            │              │            │                │             │
   ├────────────▶│               │            │              │            │                │             │
   │             │ INSERT target │            │              │            │                │             │
   │             ├──────────────▶│            │              │            │                │             │
   │             │ 201 target_id │            │              │            │                │             │
   │◀────────────┤               │            │              │            │                │             │
   │             │               │            │              │            │                │             │
   │ POST /campaigns{target_id, budget}       │            │              │            │                │             │
   ├────────────▶│               │            │              │            │                │             │
   │             │ INSERT campaign (status=queued)          │            │                │             │
   │             ├──────────────▶│            │              │            │                │             │
   │             │ enqueue run_campaign(campaign_id)        │            │                │             │
   │             ├──────────────▶│            │              │            │                │             │
   │             │ task_id       │            │              │            │                │             │
   │◀────────────┤ 202 task_id   │            │              │            │                │             │
   │             │               │            │              │            │                │             │
   │             │               │            │  deliver     │            │                │             │
   │             │               │            ├─────────────▶│            │                │             │
   │             │               │            │              │ fetch campaign + target     │                │             │
   │             │               │◀───────────┤              │            │                │             │
   │             │               │            │              │ build compiled graph        │                │             │
   │             │               │            │              │───────────▶│                │             │
   │             │               │            │              │            │ threat_modeler │                │             │
   │             │               │            │              │            │──▶ backlog     │                │             │
   │             │               │            │              │            │ supervisor ──▶ actor           │             │
   │             │               │            │              │            │ (see §2.2 for the inner loop)   │             │
   │             │               │            │              │            │ critic ACCEPT                 │             │
   │             │               │            │              │            │ reporter ──▶ verified finding  │             │
   │             │               │            │              │◀───────────┤                │             │
   │             │               │            │              │ persist Finding + evidence  │             │
   │             │               │            │              │ status=done │                │             │
   │             │               │◀───────────┤              │            │                │             │
   │             │               │            │              │            │                │             │
   │ GET /findings/{id}/evidence │            │              │            │                │             │
   ├────────────▶│               │            │              │            │                │             │
   │             │ SELECT finding + evidence ref             │            │                │             │
   │             ├──────────────▶│            │              │            │                │             │
   │◀────────────┤ evidence bundle            │              │            │                │             │
```

Key invariants on this path:

- The API request path **never executes the swarm**. Campaign launch is `202 Accepted` + a Celery
  task. Long investigations are offloaded to the worker.
- The worker **does not receive tenant credentials**. It operates off `campaign_id` + `tenant_id`
  resolved from Postgres.
- A finding is only persisted once the Critic accepts it **and** the Reporter aggregates it.

### 2.2 The Actor → Sandbox → Critic loop

This is the inner refinement loop. It repeats, bounded by the per-hypothesis and per-campaign budget.

```
  SUPERVISOR         ACTOR             SANDBOX_TOOL       SANDBOX API        POOL            CRITIC
      │                 │                   │                 │                │                 │
      │ "actor next"    │                   │                 │                │                 │
      ├────────────────▶│                   │                 │                │                 │
      │                 │ pop CWE hypothesis │                 │                │                 │
      │                 │ craft candidate PoV/test action     │                │                 │
      │                 │ tool_call: run(action)              │                │                 │
      │                 ├──────────────────▶│                 │                │                 │
      │                 │                   │ POST /run       │                │                 │
      │                 │                   ├────────────────▶│                │                 │
      │                 │                   │                 │ acquire pool slot                 │
      │                 │                   │                 ├───────────────▶│                 │
      │                 │                   │                 │ create ephemeral container        │
      │                 │                   │                 │ (cap-drop, no-egress, seccomp)    │
      │                 │                   │                 │ execute PoV against target        │
      │                 │                   │                 │ collect logs/crash/ASan/traces    │
      │                 │                   │                 │ force-remove container (finally)  │
      │                 │                   │                 │◀────────────────│                 │
      │                 │                   │ 200 evidence    │                │                 │
      │                 │                   │◀────────────────┤                │                 │
      │                 │ evidence          │                 │                │                 │
      │                 │◀──────────────────┤                 │                │                 │
      │                 │ "critic next"     │                 │                │                 │
      │                 ├──────────────────────────────────────────────────────────────────────▶│
      │                 │                   │                 │                │  evaluate:       │
      │                 │                   │                 │                │  • crash legit?  │
      │                 │                   │                 │                │  • CWE match?    │
      │                 │                   │                 │                │  • reproducible? │
      │                 │                   │                 │                │                 │
      │                 │                   │                 │                │ ACCEPT ─┐        │
      │                 │                   │                 │                │         │ REJECT │
      │                 │                   │                 │                │◀────────┘        │
      │                 │◀──────────────── structured feedback (delta to next PoV)               │
      │                 │                   │                 │                │                 │
      │ ◀─────────────┐ │                   │                 │                │                 │
      │  REJECT loop  └▶│ (refine PoV)      │                 │                │                 │
      │  ACCEPT ────────────────────────────────────────────▶ verified finding persisted         │
```

Why this loop is the heart of precision:

- The **Actor** only ever proposes; it has no authority to declare a finding.
- The **sandbox** is the source of truth — the Critic reasons over *collected evidence*, not the
  Actor's narrative.
- The **Critic** returns a structured delta ("crash is in the harness shim, not `parse_header()`"),
  not a boolean, so the Actor gets an actionable refinement target.
- Every iteration is persisted to a LangGraph checkpoint; the loop is resumable and auditable.

---

## 3. Dependency-Direction Rule

The three planes are separated by a **strict, acyclic, downward dependency direction**. This is
load-bearing: it is what makes each plane independently testable and deployable.

```
control_plane  ──▶  agent_swarm  ──▶  execution_engine
     │                  │
     └──── ai_gateway ◀─┘        (both control_plane & agent_swarm call the gateway)
            │
            └─▶ observability    (every plane emits telemetry)
```

### The rule, stated

| Layer | May import | May NOT import |
|---|---|---|
| **`execution_engine`** | stdlib, third-party (docker SDK, fastify for its ASGI), its own subpackages | anything above it — no `agent_swarm`, no `control_plane` |
| **`agent_swarm`** | `execution_engine` (via `skills/sandbox_tool.py`), `ai_gateway`, `observability`, its own subpackages | `control_plane` (no DB, no HTTP serving, no Celery) |
| **`control_plane`** | `agent_swarm` (to compile the graph), `ai_gateway`, `observability`, its own subpackages, DB/queue | `execution_engine` directly — it reaches the engine only through the swarm's `sandbox_tool`, keeping the engine ignorant of the plane above |

### Why acyclic and downward

- **No layer reaches up.** The execution engine never imports swarm or control-plane code, so it can
  be evolved, hardened, and audited without coupling to reasoning logic.
- **The graph is compiled in the control plane** (`orchestrator/graph.py`), but the *node
  implementations* live in `agent_swarm`. The control plane imports the swarm; the swarm never
  imports the control plane. This keeps node logic unit-testable without a DB.
- **Cross-cutting layers are leaves.** `ai_gateway` and `observability` are imported by whoever
  needs them; they import nothing from the three planes.

### Practical enforcement

- Review-time: PRs that add an upward import are blocked.
- Test-time: each plane has its own unit test suite that runs without the layers above it.
  (`execution_engine` unit tests must pass with neither `agent_swarm` nor `control_plane`
  importable.)

---

## 4. Data Model Overview

All persistence is Postgres via SQLAlchemy 2.x async (`control_plane/db/models/`). Every row carries
`id`, `tenant_id`, and timestamps via the declarative base mixins. LangGraph checkpoints live in a
dedicated table managed by the Postgres checkpointer.

### Entities

```
 ┌──────────────┐        ┌──────────────────┐        ┌────────────────────┐
 │   Tenant     │ 1    * │   ApiKey         │        │   Quota            │
 │  (B2B org)   │────────│  (auth creds)    │        │ (step/token/USD)   │
 └──────┬───────┘        └──────────────────┘        └────────────────────┘
        │ 1
        │
        │ *                ┌─────────────────────────┐
        ├─────────────────▶│      Target             │
        │  (owns)          │  • kind: image|binary|  │
        │                  │    source               │
        │                  │  • storage_handle       │
        │                  │  • ingestion_status     │
        │                  │  • read-only mount path │
        │                  └───────────┬─────────────┘
        │                              │ 1
        │                              │ *
        │                  ┌───────────▼─────────────┐        ┌────────────────────┐
        │                  │     HuntCampaign        │ 1    * │   ExecutionLog     │
        │                  │  • status: queued|      │────────│  (per-step sandbox │
        │                  │    running|done|failed  │        │   invocations +   │
        │                  │  • budget_ledger        │        │   evidence refs)  │
        │                  │  • task_id              │        └────────────────────┘
        │                  └───────────┬─────────────┘
        │                              │ 1
        │                              │ *
        │                  ┌───────────▼─────────────┐
        │                  │      Finding            │
        │                  │  • cwe                  │
        │                  │  • cvss                 │
        │                  │  • pov_ref              │
        │                  │  • evidence_ref         │
        │                  │  • status: verified     │
        │                  └─────────────────────────┘
        │
        │                  ┌─────────────────────────┐
        └─────────────────▶│    AgentRun             │
           (owns)          │  • campaign_id          │
                           │  • checkpoint_id        │
                           │  • transcript pointers  │
                           └─────────────────────────┘
```

### Entity responsibilities

| Entity | Responsibility |
|---|---|
| **Tenant** | A B2B organization. Root of multi-tenant isolation. All child rows inherit `tenant_id`. |
| **ApiKey** | Authentication credential (hashed at rest) + associated Quota. Drives the auth middleware. |
| **Quota** | Per-tenant caps (steps/tokens/USD over a window). Enforced jointly by the API rate limiter and the gateway budget guard. |
| **Target** | An ingested target — container image, binary, or source archive. Carries its read-only mount path inside the sandbox. |
| **HuntCampaign** | One investigation run against a target. Owns the budget ledger, status, and the Celery task reference. |
| **ExecutionLog** | One row per sandbox invocation: the action, the container config, captured evidence refs, and the outcome. This is the Critic's raw material. |
| **AgentRun** | Points at the LangGraph checkpoint for a campaign (enabling resume + replay) and the persisted transcript. |
| **Finding** | A Critic-accepted, Reporter-aggregated vulnerability. Carries CWE, CVSS, the minimal PoV ref, and an evidence bundle ref. Only `status = verified` is ever returned via the API. |

### Multi-tenant isolation

Every query is scoped by `tenant_id` resolved from the authenticated `ApiKey` in middleware. The
swarm never sees another tenant's targets, transcripts, or findings. See
[ADR 0003](./adr/0003-internal-only-sandbox-api.md) and the [threat model](./threat_model.md) for
how the sandbox pool is kept off the data store entirely.

---

## 5. Budget, Checkpoint & Resume

### 5.1 Budget enforcement

A campaign runs under a **four-axis budget** owned by the Supervisor and enforced at three points:

| Axis | Where enforced |
|---|---|
| **Steps** (graph iterations) | Supervisor node — decrements per iteration; halts at `APP_CAMPAIGN_MAX_STEPS` |
| **Tokens** (LLM input + output) | AI Gateway `budget_guard` — rejects calls that would exceed the remaining allocation |
| **USD** (modeled cost) | AI Gateway `budget_guard` — same gate, modeled from per-model pricing |
| **Wall-clock** | Supervisor — compares against the campaign deadline on each iteration |

The **budget ledger** is a column on `HuntCampaign` updated atomically per iteration, so partial
consumption is durable across crashes. A Beat-driven sweep force-terminates any campaign whose
wall-clock deadline has passed even if its worker died silently.

### 5.2 Checkpointing

LangGraph persists a checkpoint to Postgres after **every node transition** via the Postgres
checkpointer (`control_plane/orchestrator/checkpoints.py`). Each checkpoint captures the full
swarm state: target handle, threat model, CWE backlog, Actor/Critic transcript, accumulated
evidence, verified findings, and budget counters.

Consequences:

- **Resume-after-crash**: if a worker dies mid-campaign, the next `run_campaign` invocation (or the
  Beat reaper) resumes from the last checkpoint rather than restarting.
- **Full replay**: `GET /campaigns/{id}/trace` reads the checkpoint chain and reconstructs the
  agent transcript for audit.
- **Deterministic spine, probabilistic nodes**: the *control flow* is identical on replay; only the
  LLM outputs are probabilistic (and those are themselves logged via Langfuse).

### 5.3 Termination & graduation

The Supervisor terminates a campaign when any of the following holds:

1. The CWE backlog is empty **and** no Actor/Critic loop is in flight.
2. Any budget axis is exhausted.
3. A hard termination signal is received (operator cancel, Beat sweep).

On termination the **Reporter** runs exactly once, aggregating all `status = verified` findings into
the final triaged report. The campaign transitions to `done` (or `failed` on an unrecoverable
error), and the budget ledger is closed.

---

*See also: [Threat Model](./threat_model.md), [ADR 0001](./adr/0001-three-plane-separation.md),
[ADR 0002](./adr/0002-actor-critic-as-separate-agents.md),
[ADR 0003](./adr/0003-internal-only-sandbox-api.md).*
