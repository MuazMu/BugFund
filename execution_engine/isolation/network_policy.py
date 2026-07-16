"""Container isolation policy helpers.

Builds the Docker ``containers.create`` kwargs that harden every sandbox:
all capabilities dropped, no-new-privileges, no-egress (default), optional
seccomp/AppArmor, read-only rootfs, and per-container resource caps. The
profile files referenced here live alongside this module (``seccomp.json``,
``apparmor.profile``).
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional

__all__ = [
    "ISOLATION_DIR",
    "SECCOMP_PROFILE",
    "APPARMOR_PROFILE",
    "docker_isolation_opts",
    "load_seccomp_profile",
    "egress_allowlisted",
]

ISOLATION_DIR = Path(__file__).resolve().parent
SECCOMP_PROFILE = ISOLATION_DIR / "seccomp.json"
APPARMOR_PROFILE = ISOLATION_DIR / "apparmor.profile"

# Default per-container resource caps (mirrors SandboxManager defaults).
_DEFAULT_PID_LIMIT = 256
_DEFAULT_MEM_LIMIT = "512m"
_DEFAULT_CPU_PERIOD = 100_000
_DEFAULT_CPU_QUOTA = 50_000  # 0.5 CPU


def docker_isolation_opts(
    *,
    network: bool = False,
    seccomp_path: Optional[str] = str(SECCOMP_PROFILE),
    apparmor_profile: Optional[str] = None,
    read_only_rootfs: bool = True,
    no_new_privileges: bool = True,
    pids_limit: int = _DEFAULT_PID_LIMIT,
    mem_limit: str = _DEFAULT_MEM_LIMIT,
    cpu_quota: int = _DEFAULT_CPU_QUOTA,
) -> dict[str, Any]:
    """Return Docker ``create()`` kwargs implementing the hardened profile.

    Args:
        network: If False (default) the container gets ``network_mode="none"``
            — no outbound egress. If True, ``bridge`` (still NAT-bound).
        seccomp_path: Path to the seccomp JSON; ``None`` to omit.
        apparmor_profile: Optional AppArmor profile name.
        read_only_rootfs: Make the container rootfs read-only (writable tmpfs
            mounted at ``/tmp``).
        no_new_privileges: Set ``no-new-privileges``.
        pids_limit / mem_limit / cpu_quota: Per-container resource caps.

    Returns:
        A dict of kwargs to splat into ``client.containers.create(**opts)``.
    """
    security_opt: list[str] = []
    if no_new_privileges:
        security_opt.append("no-new-privileges")
    if seccomp_path:
        security_opt.append(f"seccomp={seccomp_path}")
    if apparmor_profile:
        security_opt.append(f"apparmor={apparmor_profile}")

    opts: dict[str, Any] = {
        "cap_drop": ["ALL"],
        "cap_add": [],  # explicitly none by default
        "security_opt": security_opt,
        "network_mode": "none" if not network else "bridge",
        "pids_limit": pids_limit,
        "mem_limit": mem_limit,
        "cpu_period": _DEFAULT_CPU_PERIOD,
        "cpu_quota": cpu_quota,
        "privileged": False,
    }
    if read_only_rootfs:
        opts["read_only"] = True
        opts["tmpfs"] = {"/tmp": "rw,noexec,nosuid,size=64m"}
    return opts


def load_seccomp_profile(path: Optional[str | Path] = None) -> dict[str, Any]:
    """Load and return the seccomp profile JSON (default: the bundled one)."""
    target = Path(path) if path else SECCOMP_PROFILE
    return json.loads(target.read_text(encoding="utf-8"))


# A conservative allowlist for the (rare) network-enabled case: only these
# destinations are permitted when egress is selectively allowed.
_EGRESS_ALLOW: tuple[str, ...] = ()


def egress_allowlisted(host: str) -> bool:
    """True if ``host`` is on the (currently empty) egress allowlist.

    With an empty allowlist every outbound host is denied — callers should
    treat a ``False`` result as "blocked". Kept as a hook for future
    provider/model egress (e.g. an LLM gateway) without opening general egress.
    """
    if not _EGRESS_ALLOW:
        return False
    return any(host == allowed or host.endswith("." + allowed) for allowed in _EGRESS_ALLOW)
