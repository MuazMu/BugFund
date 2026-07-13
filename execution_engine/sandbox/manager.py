"""Docker-backed sandbox manager for the BugFund execution engine.

``SandboxManager`` runs an Actor-generated PoV inside an ephemeral, hardened
Ubuntu container and returns captured stdout/stderr/exit_code for the Critic.

Design contract (matches ``agent_swarm.skills.SandboxClient`` by duck-typing;
this module imports nothing from the upper layers):

* The target source tree is bind-mounted **read-only** at ``/srv/target``.
* The PoV is materialized into a throwaway host temp dir and bind-mounted
  read-only at ``/srv/pov/pov.py`` (so it appears as a file *inside* the
  container without needing ``exec``/``cp``).
* The container runs with all capabilities dropped, ``no-new-privileges``,
  ``network_mode="none"``, a memory/PID cap, and a writable ``/tmp`` tmpfs.
* A wall-clock timeout is enforced by a watchdog thread that force-kills
  (SIGKILL) the container at ``timeout_s``.
* Cleanup is unconditional: ``finally`` always kills (if alive) and
  ``remove(force=True)`` — success, failure, or timeout alike — and also removes
  the host temp dir.

The image must provide ``python3`` on PATH (``ubuntu:22.04`` does; for stricter
reproducibility swap in a pre-baked harness image via ``image=``).
"""
from __future__ import annotations

import asyncio
import os
import shutil
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Callable, Optional

import docker
from docker.errors import DockerException

__all__ = ["SandboxError", "SandboxManager"]

# In-container mount points (constants — the PoV reads os.environ["POV_TARGET"]).
_TARGET_MOUNT = "/srv/target"
_SCRIPT_MOUNT_DIR = "/srv/pov"
_SCRIPT_MOUNT_PATH = f"{_SCRIPT_MOUNT_DIR}/pov.py"


class SandboxError(RuntimeError):
    """Raised for sandbox misconfiguration (missing target, missing image, ...)."""


class SandboxManager:
    """Manages ephemeral Docker sandboxes for PoV execution.

    This class is the concrete implementation of the swarm's ``SandboxClient``
    protocol; inject it at startup with ``agent_swarm.set_sandbox_client(...)``.
    """

    def __init__(
        self,
        docker_client: Any = None,
        *,
        image: str = "ubuntu:22.04",
        target_resolver: Optional[Callable[[int], str]] = None,
        mem_limit: str = "512m",
        pids_limit: int = 256,
    ) -> None:
        """
        Args:
            docker_client: An existing ``docker.DockerClient`` (else ``docker.from_env()``).
            image: Container image to use. Must provide ``python3`` on PATH.
            target_resolver: Maps ``target_id`` -> host directory of the target
                source tree. Defaults to ``/var/bugfund/targets/{id}``. Wire a
                real resolver from the control plane so this layer stays DB-free.
            mem_limit: Per-container memory limit (Docker notation, e.g. ``"512m"``).
            pids_limit: Max processes inside the container.
        """
        self.client = docker_client if docker_client is not None else docker.from_env()
        self.image = image
        self.target_resolver: Callable[[int], str] = target_resolver or (
            lambda tid: f"/var/bugfund/targets/{int(tid)}"
        )
        self.mem_limit = mem_limit
        self.pids_limit = pids_limit
        self._ensure_image()

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #
    def run_pov(
        self,
        target_id: int,
        pov_script: str,
        *,
        timeout_s: int = 30,
        env_vars: Optional[dict[str, str]] = None,
        network: bool = False,
    ) -> dict[str, Any]:
        """Run a PoV against target ``target_id`` and return captured logs.

        Args:
            target_id: Identifier resolved (via ``target_resolver``) to the host
                directory of the target source tree.
            pov_script: Python source written by the Actor agent.
            timeout_s: Hard wall-clock timeout (default 30s). The container is
                SIGKILLed if exceeded.
            env_vars: Extra env vars for the container. ``POV_TARGET`` is always
                set to the in-container mount point ``/srv/target``.
            network: If False (default), the container has no network.

        Returns:
            ``{stdout, stderr, exit_code, timed_out, duration_ms, container_id}``.

        Raises:
            SandboxError: if the target directory does not exist on the host.
        """
        host_target = self.target_resolver(target_id)
        return self._execute_sync(host_target, pov_script, env_vars, timeout_s, network)

    async def run_script(
        self,
        *,
        script_code: str,
        env_vars: Optional[dict[str, str]] = None,
        timeout_s: int = 60,
        network: bool = False,
    ) -> dict[str, Any]:
        """Protocol-conformant async entrypoint (used by ``execute_sandbox_script``).

        The host target path is taken from ``env_vars["POV_TARGET"]``; the
        in-container ``POV_TARGET`` is then (re)set to the read-only mount point.
        The blocking Docker calls run in a worker thread.
        """
        env = dict(env_vars or {})
        host_target = env.get("POV_TARGET")
        if not host_target:
            raise SandboxError(
                "run_script: env_vars['POV_TARGET'] (host target path) is required"
            )
        return await asyncio.to_thread(
            self._execute_sync, host_target, script_code, env, timeout_s, network
        )

    def close(self) -> None:
        """Close the underlying Docker client."""
        try:
            self.client.close()
        except Exception:  # pragma: no cover - best-effort
            pass

    # ------------------------------------------------------------------ #
    # Core execution
    # ------------------------------------------------------------------ #
    def _execute_sync(
        self,
        host_target: str,
        pov_script: str,
        env_vars: Optional[dict[str, str]],
        timeout_s: int,
        network: bool,
    ) -> dict[str, Any]:
        if not os.path.isdir(host_target):
            raise SandboxError(f"target directory not found: {host_target}")

        started = time.monotonic()
        # Materialize the PoV in a throwaway host dir; bind-mount it read-only.
        script_dir = Path(tempfile.mkdtemp(prefix="bugfund-pov-"))
        (script_dir / "pov.py").write_text(pov_script or "", encoding="utf-8")

        container: Optional[Any] = None
        timed_out = {"v": False}
        try:
            container = self._create_container(script_dir, host_target, env_vars, network)
            container.start()

            # Watchdog: force SIGKILL at timeout_s.
            timer = threading.Timer(timeout_s, self._force_kill, args=(container, timed_out))
            timer.start()
            exit_code: Optional[int]
            try:
                result = container.wait()
                exit_code = result.get("StatusCode")
            except DockerException:
                exit_code = None
            finally:
                timer.cancel()

            out_b, err_b = self._demux_logs(container)
            return {
                "stdout": (out_b or b"").decode("utf-8", "replace"),
                "stderr": (err_b or b"").decode("utf-8", "replace"),
                "exit_code": exit_code,
                "timed_out": timed_out["v"],
                "duration_ms": int((time.monotonic() - started) * 1000),
                "container_id": getattr(container, "id", None),
            }
        finally:
            if container is not None:
                self._force_remove(container)
            shutil.rmtree(script_dir, ignore_errors=True)

    def _create_container(
        self,
        script_dir: Path,
        host_target: str,
        env_vars: Optional[dict[str, str]],
        network: bool,
    ) -> Any:
        env = dict(env_vars or {})
        # The in-container POV_TARGET always points at the read-only mount, not
        # the host path (so the same PoV works against original or patched tree).
        env["POV_TARGET"] = _TARGET_MOUNT
        env["PYTHONUNBUFFERED"] = "1"  # flush stdout so logs survive a SIGKILL

        volumes = {
            str(script_dir.resolve()): {"bind": _SCRIPT_MOUNT_DIR, "mode": "ro"},
            str(Path(host_target).resolve()): {"bind": _TARGET_MOUNT, "mode": "ro"},
        }
        return self.client.containers.create(
            image=self.image,
            command=["python3", "-u", _SCRIPT_MOUNT_PATH],
            environment=env,
            volumes=volumes,
            network_mode="none" if not network else "bridge",
            mem_limit=self.mem_limit,
            pids_limit=self.pids_limit,
            cap_drop=["ALL"],
            security_opt=["no-new-privileges"],
            tmpfs={"/tmp": "rw,size=64m"},
            detach=True,
            tty=False,
            labels={"app": "bugfund", "role": "pov-sandbox"},
        )

    # ------------------------------------------------------------------ #
    # Logging + guaranteed cleanup
    # ------------------------------------------------------------------ #
    @staticmethod
    def _demux_logs(container: Any) -> tuple[bytes, bytes]:
        """Return (stdout, stderr) bytes, tolerant of SDK/backend quirks."""
        try:
            out, err = container.logs(stdout=True, stderr=True, demux=True)
            return out or b"", err or b""
        except Exception:
            try:
                data = container.logs(stdout=True, stderr=True)
                if isinstance(data, tuple):
                    return data[0] or b"", data[1] or b""
                return data or b"", b""
            except Exception:
                return b"", b""

    @staticmethod
    def _force_kill(container: Any, flag: dict[str, bool]) -> None:
        """Watchdog callback: SIGKILL a still-running container and flag timeout."""
        try:
            container.reload()
            if container.status == "running":
                container.kill()
                flag["v"] = True
        except Exception:
            pass  # container already gone; nothing to do

    @staticmethod
    def _force_remove(container: Any) -> None:
        """Unconditional teardown: kill if alive, then force-remove. Never raises."""
        try:
            container.kill()
        except Exception:
            pass
        try:
            container.remove(force=True)
        except Exception:
            pass

    def _ensure_image(self) -> None:
        """Pull the image on first use if it is not present locally."""
        try:
            self.client.images.get(self.image)
        except Exception:
            try:
                self.client.images.pull(self.image)
            except Exception as exc:
                raise SandboxError(
                    f"image '{self.image}' not present and could not be pulled: {exc}"
                ) from exc
