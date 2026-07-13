# Project Structure — BugFund CRS

Complete file-level layout. The three primary planes — **`control_plane/`**, **`agent_swarm/`**,
and **`execution_engine/`** — are top-level packages, each independently deployable and testable.
Two cross-cutting support layers (`ai_gateway/`, `observability/`) serve all three.

> See [`README.md`](./README.md) for architecture rationale and the Actor–Critic data flow.
> Annotations describe each file's *responsibility* — no implementation is committed yet.

Legend: `# doc` = documentation/config only · `# pkg` = Python package · `# entry` = runnable entrypoint · `# image` = container build context

---

## Root

```
bugfund-crs/
│
├── README.md                       # doc — system overview, architecture, data flow, setup
├── PROJECT_STRUCTURE.md            # doc — this file (file-level tree)
├── pyproject.toml                  # pkg metadata, deps, tool config (ruff/mypy/pytest)
├── .env.example                    # doc — annotated env-var template
├── .gitignore
├── docker-compose.yml              # infra: postgres, redis, api, worker (full-stack dev)
├── Makefile                        # convenience targets: sandbox-images, migrate, smoke, test
├── alembic.ini                     # Alembic config (DB migrations)
└── LICENSE                         # doc — TBD before distribution
```

---

## control_plane/ — API • DB • Orchestrator

Owns HTTP entry, persistence, the async task queue, and the **LangGraph graph definition & runner**.
It wires the swarm together and drives campaigns, but contains no LLM prompting logic and no
container internals.

```
control_plane/
├── __init__.py
│
├── api/                            # ── FastAPI HTTP layer ──
│   ├── __init__.py
│   ├── main.py                     # entry — FastAPI app factory, lifespan, router mounting
│   ├── deps.py                     # shared dependencies (db session, tenant context, settings)
│   │
│   ├── v1/                         # versioned surface
│   │   ├── __init__.py
│   │   ├── router.py               # aggregates all v1 routers under /api/v1
│   │   ├── endpoints/
│   │   │   ├── __init__.py
│   │   │   ├── targets.py          # POST/GET /targets — ingest & inspect test targets
│   │   │   ├── campaigns.py        # POST/GET /campaigns — launch & observe investigations
│   │   │   ├── findings.py         # GET /findings, /findings/{id}/evidence
│   │   │   ├── tasks.py            # GET /tasks/{id} — Celery task status
│   │   │   └── health.py           # GET /health — liveness/readiness
│   │   └── schemas/                # Pydantic v2 request/response models
│   │       ├── __init__.py
│   │       ├── target.py
│   │       ├── campaign.py
│   │       ├── finding.py
│   │       └── common.py           # pagination, error envelopes, enums
│   │
│   └── middleware/
│       ├── __init__.py
│       ├── auth.py                 # API-key / mTLS authentication (B2B)
│       ├── tenant.py               # multi-tenant isolation context propagation
│       └── rate_limit.py           # per-tenant throttling
│
├── db/                             # ── Persistence (SQLAlchemy 2.x async) ──
│   ├── __init__.py
│   ├── base.py                     # declarative base + common mixins (id, timestamps, tenant_id)
│   ├── session.py                  # async engine + sessionmaker factory
│   └── models/
│       ├── __init__.py
│       ├── tenant.py               # tenants, api_keys, quotas
│       ├── target.py               # ingested targets + storage handles
│       ├── campaign.py             # investigation campaigns + budget ledger
│       ├── task.py                 # Celery task records + result refs
│       ├── finding.py              # verified findings: CWE, CVSS, PoV ref, evidence ref
│       └── agent_run.py            # LangGraph checkpoint + transcript pointers
│
├── migrations/                     # ── Alembic ──
│   ├── env.py
│   ├── script.py.mako
│   └── versions/                   # numbered migration scripts (empty until first revision)
│
├── orchestrator/                   # ── LangGraph state machine (graph wiring lives HERE) ──
│   ├── __init__.py
│   ├── graph.py                    # builds & compiles the swarm graph (nodes + conditional edges)
│   ├── state.py                    # TypedDict swarm state (target, backlog, transcript, evidence, budget)
│   ├── runner.py                   # executes a compiled graph for a campaign (called by Celery)
│   ├── budget.py                   # step/token/USD/wall-clock budget enforcement + accounting
│   └── checkpoints.py              # Postgres-backed LangGraph checkpointer (resume + replay)
│
├── tasks/                          # ── Celery ──
│   ├── __init__.py
│   ├── celery_app.py               # entry — Celery app, broker/backend, queue routing
│   ├── campaigns.py                # run_campaign task → invokes orchestrator.runner
│   └── sandbox_jobs.py             # sandbox lifecycle jobs (reaper, evidence GC, sweeps)
│
└── core/                           # ── cross-cutting fundamentals ──
    ├── __init__.py
    ├── config.py                   # pydantic-settings: typed env config (Settings)
    ├── logging.py                  # structured logging setup
    ├── security.py                 # secret handling, hashing, token utilities
    └── exceptions.py               # domain exception hierarchy + handlers
```

---

## agent_swarm/ — LangGraph Nodes • Prompts • Skills

Owns the reasoning layer: the node implementations (one per agent role), their prompt templates,
the deterministic **skills** (tools) they can call, agent memory, and the routing policy that turns
Supervisor decisions into graph edges. Contains no DB access and serves no HTTP.

```
agent_swarm/
├── __init__.py
│
├── nodes/                          # ── one LangGraph node per role ──
│   ├── __init__.py
│   ├── supervisor.py               # routing hub: selects next node, enforces budget, terminates
│   ├── threat_modeler.py           # maps attack surface → ranked CWE hypothesis backlog
│   ├── actor.py                    # proposes executable PoVs / test actions from a hypothesis
│   ├── critic.py                   # adversarial verdict on evidence; structured feedback to Actor
│   └── reporter.py                 # aggregates verified findings into a triaged report
│
├── prompts/                        # ── prompt templates (versioned, externalized) ──
│   ├── supervisor.yaml
│   ├── threat_modeler.yaml
│   ├── actor.yaml
│   ├── critic.yaml
│   └── _shared/
│       ├── system.md               # shared system prompt / safety preamble
│       └── schemas.json            # structured-output schemas (hypothesis lists, verdicts)
│
├── skills/                         # ── deterministic tools agents may invoke ──
│   ├── __init__.py
│   ├── disasm.py                   # binary disassembly / symbol extraction
│   ├── code_review.py              # source analysis (AST, taint, pattern queries)
│   ├── fuzzer_bridge.py            # drives AFL/libFuzzer runs (via execution_engine)
│   ├── pov_crafter.py              # assembles / mutates proof-of-vulnerability inputs
│   ├── cwe_knowledge.py            # CWE/CVSS knowledge lookup & mapping
│   └── sandbox_tool.py             # thin client over execution_engine internal API
│
├── memory/                         # ── agent memory ──
│   ├── __init__.py
│   ├── short_term.py               # working memory carried in LangGraph state
│   └── long_term.py                # vector store of prior findings (RAG across campaigns)
│
└── routing/                        # ── control-flow policy ──
    ├── __init__.py
    ├── edges.py                    # conditional-edge functions (Supervisor → next node)
    └── policies.py                 # termination + re-prioritization decision rules
```

---

## execution_engine/ — Docker Managers • Sandbox APIs

Owns container lifecycle, isolation policy, and evidence collection. Everything untrusted
(target code, agent-generated inputs) runs **only** here, inside ephemeral hardened containers.
Exposes a small **internal** API consumed by the swarm's `sandbox_tool`; never tenant-facing.

```
execution_engine/
├── __init__.py
│
├── sandbox/                        # ── container lifecycle (Docker SDK) ──
│   ├── __init__.py
│   ├── manager.py                  # create / start / stop / remove ephemeral containers
│   ├── pool.py                     # bounded container pool + concurrency limiter
│   ├── runner.py                   # executes test harnesses / PoVs inside a container
│   └── teardown.py                 # guaranteed cleanup + watchdog timeout
│
├── images/                         # ── container build contexts (hardened tiers) ──
│   ├── base/                       # image — stripped, non-root base image
│   │   └── Dockerfile
│   ├── harness/                    # image — per-target-type test harness images
│   │   └── Dockerfile
│   └── targets/                    # image — target ingestion / packaging images
│       └── Dockerfile
│
├── api/                            # ── internal sandbox HTTP API (swarm-only) ──
│   ├── __init__.py
│   ├── server.py                   # entry — small ASGI service wrapping sandbox ops
│   └── schemas.py                  # run/cancel/collect request-response models
│
├── isolation/                      # ── containment policy ──
│   ├── seccomp.json                # restrictive syscall whitelist
│   ├── apparmor.profile            # container confinement profile
│   └── network_policy.py           # no-egress namespace / strict allowlist enforcement
│
└── collectors/                     # ── evidence capture (raw material for the Critic) ──
    ├── __init__.py
    ├── logs.py                     # structured stdout/stderr capture
    ├── traces.py                   # strace / ltrace collection
    └── crash.py                    # core-dump + AddressSanitizer parsing & classification
```

---

## Cross-cutting support layers

```
ai_gateway/                         # model-agnostic LLM proxy (LiteLLM) — used by all nodes
├── __init__.py
├── proxy.py                        # unified chat/completion/embedding entrypoint
├── router.py                       # per-role model routing + fallback chains
├── budget_guard.py                 # per-campaign / per-agent token & USD caps
└── config/
    └── providers.yaml              # provider + per-role model assignments

observability/                      # tracing + metrics across all three planes
├── __init__.py
├── tracing.py                      # OpenTelemetry setup (spans across API → swarm → sandbox)
├── metrics.py                      # counters/histograms (campaigns, sandbox runs, costs)
└── langfuse.py                     # LLM call tracing (prompts, tokens, latency, cost)
```

---

## Tests, scripts, docs

```
tests/
├── unit/                           # node logic, budget math, schema validation
├── integration/                    # graph wiring, DB, gateway, sandbox API
└── e2e/                            # full campaign: ingest → swarm → verified finding

scripts/
├── seed_demo.py                    # load a demo target + expected findings
└── run_dev.sh                      # bring up api + worker + beat locally

docs/
├── architecture.md                 # deep-dive diagrams (sequence + deployment views)
├── threat_model.md                 # BugFund's own threat model (sandbox escape, prompt injection)
└── adr/                            # architecture decision records (numbered)
    ├── 0001-three-plane-separation.md
    ├── 0002-actor-critic-as-separate-agents.md
    └── 0003-internal-only-sandbox-api.md
```

---

### Dependency direction (enforced)

```
control_plane  ──▶  agent_swarm  ──▶  execution_engine
     │                  │
     └──── ai_gateway ◀─┘        (both control_plane & agent_swarm call the gateway)
            │
            └─▶ observability    (every plane emits telemetry)
```

- `execution_engine` depends on **nothing** above it (no swarm, no control-plane imports).
- `agent_swarm` depends on `execution_engine` (via `sandbox_tool`) and `ai_gateway` only.
- `control_plane` depends on `agent_swarm` (to compile the graph) and its own DB/queue.
- No layer reaches *up*: the execution engine never imports swarm or control-plane code.
