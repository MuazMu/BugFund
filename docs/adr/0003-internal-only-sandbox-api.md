# ADR 0003 — Internal-Only Sandbox API

- **Status:** Accepted
- **Date:** 2026-07-15
- **Related:** [README §7 — Execution Engine & Sandbox Isolation](../../README.md#7-execution-engine--sandbox-isolation),
  [`docs/threat_model.md` — T7. Docker socket exposure](../threat_model.md#t7-docker-socket-exposure),
  [ADR 0001](./0001-three-plane-separation.md)

## Context

The execution engine manages the Docker socket on the worker and exposes operations over it: create
an ephemeral container, run a PoV/harness, collect evidence, force-remove the container. These
operations are powerful — the underlying Docker socket is, in effect, root on the host. Anything
that can drive those operations can attempt to create containers outside the hardened profile, mount
host paths, or exhaust the pool.

We had to decide *who is allowed to call* the execution engine's HTTP surface. The candidates were:

1. Expose it as a tenant-facing endpoint (so tenants could submit PoVs directly).
2. Expose it on the internal network only, callable by any internal service.
3. Expose it on the internal network only, callable by **exactly one** consumer: the swarm's
   `sandbox_tool` skill.

## Decision

The execution engine exposes an **internal-only HTTP API** (`execution_engine/api/server.py`)
consumed **solely** by the swarm's `sandbox_tool` skill (`agent_swarm/skills/sandbox_tool.py`). It is
never tenant-facing.

Concretely:

- The sandbox API binds to a loopback / overlay address reachable only inside the deployment, not
  to the tenant-ingress listener.
- There is no route from the public API (`/api/v1/...`) to the sandbox API. A tenant request can
  only influence sandbox execution *indirectly*, by launching a campaign that the worker runs
  through the compiled swarm graph, where the `sandbox_tool` is the single chokepoint.
- The `sandbox_tool` is the only code path that constructs sandbox requests, and it constructs them
  exclusively from the hardened profile (cap-drop, seccomp, AppArmor, no-egress, read-only target
  mount, resource caps). No other component is permitted to call the engine.

## Consequences

**Positive**

- Tenants cannot drive the Docker socket, even via a campaign. They can influence *which* target is
  analyzed and *how much* budget is spent; they cannot influence the *shape* of the container that
  gets created.
- The hardened container profile is enforced at a single chokepoint. Reviewing `sandbox_tool` is
  sufficient to gain confidence that every sandbox invocation uses the approved isolation config.
- The execution engine remains ignorant of tenants, auth, and API keys — it trusts its single
  internal caller, which preserves the dependency-direction rule from [ADR 0001](./0001-three-plane-separation.md).
- Limits the blast radius of a worker compromise: even an attacker who lands on the internal network
  must still go through the one skill that enforces the profile.

**Negative**

- Adds one HTTP hop (swarm → internal API → Docker SDK) versus calling the Docker SDK inline. The
  latency is acceptable for PoV runs, which are dominated by container create/exec time.
- The "single caller" property is enforced by network topology and review convention, not by a
  cryptographic credential. A misconfigured internal network could, in principle, admit a second
  caller. Mitigated by network policy and by the fact that the profile is enforced inside the
  engine regardless of caller.

## Alternatives Considered

- **Tenant-facing sandbox endpoint** (option 1). Rejected outright: it hands the Docker socket to
  tenants through a thin wrapper. Unacceptable for a system whose sandbox runs untrusted code.

- **Internal API callable by any internal service** (option 2). Rejected: broadens the attack
  surface to every service on the internal network. A compromised beat, observability exporter, or
  future microservice would all become paths to the socket. The principle of least privilege
  demands exactly one caller.

- **No HTTP API at all — call the Docker SDK inline from the swarm.** Rejected: couples the swarm
  node directly to the Docker SDK and to the worker's process space, breaking the ability to move
  the execution engine to a dedicated hardened node. The internal HTTP API is what keeps the engine
  independently deployable (a goal of [ADR 0001](./0001-three-plane-separation.md)).

- **mTLS-authenticated internal API with a client certificate issued only to `sandbox_tool`.**
  Deferred: stronger than network-topology-only isolation, but adds a certificate-provisioning
  burden that is not yet justified. Revisit if the execution engine moves to a dedicated node or if
  the internal network becomes less trusted. The enforcement that matters most — the hardened
  container profile — lives inside the engine regardless of the caller's identity.
