"""BugFund execution engine.

Isolated Docker sandboxes for running Actor-generated PoVs. This package depends
only on the Docker SDK and the stdlib — it imports nothing from the control plane
or agent swarm. The control plane injects a ``SandboxManager`` into the swarm at
startup via ``agent_swarm.set_sandbox_client(...)``.
"""
from execution_engine.sandbox.manager import SandboxError, SandboxManager

__all__ = ["SandboxManager", "SandboxError"]
