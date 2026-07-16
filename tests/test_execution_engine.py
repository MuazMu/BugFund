"""Offline tests for the execution-engine collectors, isolation, pool, runner, API.

No Docker daemon required: collectors/isolation are pure functions; the pool and
runner are exercised with fakes; the internal API is driven via TestClient with
an injected fake runner.
"""
from __future__ import annotations

import asyncio

import pytest


# --------------------------------------------------------------------------- #
# Collectors — crash / ASan
# --------------------------------------------------------------------------- #
def test_parse_asan_detects_heap_overflow():
    from execution_engine.collectors import parse_asan

    stderr = (
        "==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x60200000dead\n"
        "SUMMARY: AddressSanitizer: heap-buffer-overflow in parse_header /x.c:42:5\n"
    )
    rep = parse_asan(stderr)
    assert rep["detected"] is True
    assert rep["sanitizer"] == "asan"
    assert "heap-buffer-overflow" in rep["bug_type"]
    assert rep["address"] == "0x60200000dead"
    assert "parse_header" in rep["location"]


def test_parse_asan_clean_when_no_sanitizer():
    from execution_engine.collectors import parse_asan

    rep = parse_asan("just some output\nnothing wrong")
    assert rep["detected"] is False
    assert rep["sanitizer"] == "none"


def test_classify_crash_signal_and_clean():
    from execution_engine.collectors import classify_crash

    segv = classify_crash(139, stderr="")
    assert segv["crashed"] is True
    assert segv["signal"] == "SIGSEGV"
    assert "native crash" in segv["classification"]

    clean = classify_crash(0, stdout="POV_SUCCESS")
    assert clean["crashed"] is False
    assert clean["classification"] == "clean exit"


def test_classify_crash_timeout_kill():
    from execution_engine.collectors import classify_crash

    res = classify_crash(137, timed_out=True)
    assert res["signal"] == "SIGKILL"
    assert "timeout" in res["classification"]


def test_capture_logs_truncates_tail():
    from execution_engine.collectors import capture_logs

    big = "x" * 50_000
    cap = capture_logs(big, big, stdout_limit=100, stderr_limit=100)
    assert cap["stdout_truncated"] is True
    assert len(cap["stdout"]) == 100
    assert cap["stderr_truncated"] is True


# --------------------------------------------------------------------------- #
# Collectors — strace
# --------------------------------------------------------------------------- #
def test_parse_strace_flags_suspicious():
    from execution_engine.collectors import parse_strace, suspicious_syscalls

    text = (
        '1234  openat(AT_FDCWD, "/etc/shadow", O_RDONLY) = -1 EACCES (Permission denied)\n'
        "1234  fstat(3) = 0\n"
        "1234  execve(\"/bin/sh\", ...) = 0\n"
    )
    rep = parse_strace(text)
    assert rep["total"] == 3
    names = suspicious_syscalls(rep)
    assert "openat" in names and "execve" in names
    assert "fstat" not in names


# --------------------------------------------------------------------------- #
# Isolation policy
# --------------------------------------------------------------------------- #
def test_docker_isolation_opts_hardened_defaults():
    from execution_engine.isolation.network_policy import docker_isolation_opts

    opts = docker_isolation_opts()
    assert opts["cap_drop"] == ["ALL"]
    assert opts["privileged"] is False
    assert opts["network_mode"] == "none"
    assert opts["read_only"] is True
    assert "/tmp" in opts["tmpfs"]
    assert any("seccomp" in s for s in opts["security_opt"])
    assert any("no-new-privileges" in s for s in opts["security_opt"])


def test_docker_isolation_opts_network_enabled():
    from execution_engine.isolation.network_policy import docker_isolation_opts

    opts = docker_isolation_opts(network=True)
    assert opts["network_mode"] == "bridge"


def test_load_seccomp_profile_defaults_deny():
    from execution_engine.isolation.network_policy import load_seccomp_profile

    profile = load_seccomp_profile()
    assert profile["defaultAction"] == "SCMP_ACT_ERRNO"
    names = {s for grp in profile["syscalls"] for s in grp.get("names", [])}
    assert "read" in names  # allowed
    assert "ptrace" not in names or any(
        grp.get("action") == "SCMP_ACT_ERRNO" and "ptrace" in grp.get("names", [])
        for grp in profile["syscalls"]
    )


# --------------------------------------------------------------------------- #
# SandboxPool — concurrency cap + delegation
# --------------------------------------------------------------------------- #
async def test_pool_delegates_and_caps_concurrency():
    from execution_engine.sandbox.pool import SandboxPool

    state = {"active": 0, "peak": 0}

    class FakeClient:
        async def run_script(self, *, script_code, env_vars, timeout_s, network):
            state["active"] += 1
            state["peak"] = max(state["peak"], state["active"])
            await asyncio.sleep(0.01)
            state["active"] -= 1
            return {"stdout": script_code, "stderr": "", "exit_code": 0,
                    "duration_ms": 1, "container_id": "c", "timed_out": False}

    pool = SandboxPool(FakeClient(), max_concurrency=2)
    jobs = [{"script_code": f"p{i}"} for i in range(6)]
    results = await pool.run_many(jobs)

    assert [r["stdout"] for r in results] == [f"p{i}" for i in range(6)]  # order preserved
    assert state["peak"] <= 2  # never exceeded the cap


async def test_pool_run_many_captures_errors():
    from execution_engine.sandbox.pool import SandboxPool

    class FlakyClient:
        async def run_script(self, *, script_code, env_vars, timeout_s, network):
            if script_code == "boom":
                raise RuntimeError("nope")
            return {"stdout": "ok", "exit_code": 0}

    pool = SandboxPool(FlakyClient(), max_concurrency=1)
    results = await pool.run_many([{"script_code": "ok"}, {"script_code": "boom"}])
    assert results[0]["stdout"] == "ok"
    assert "error" in results[1]


def test_pool_rejects_bad_concurrency():
    from execution_engine.sandbox.pool import SandboxPool

    with pytest.raises(ValueError):
        SandboxPool(object(), max_concurrency=0)


# --------------------------------------------------------------------------- #
# SandboxRunner — evidence enrichment
# --------------------------------------------------------------------------- #
async def test_runner_enriches_with_crash_and_logs():
    from execution_engine.sandbox.runner import SandboxRunner

    class FakeExecutor:
        async def run_script(self, *, script_code, env_vars, timeout_s, network):
            return {
                "stdout": "POV_SUCCESS\n",
                "stderr": "==1==ERROR: AddressSanitizer: heap-use-after-free\n",
                "exit_code": 1,
                "duration_ms": 7,
                "container_id": "c1",
                "timed_out": False,
            }

    runner = SandboxRunner(client=object(), executor=FakeExecutor())
    ev = await runner.run_pov("print(1)", env_vars={"POV_TARGET": "/x"})
    assert ev["container_id"] == "c1"
    assert ev["crash"]["sanitizer"]["detected"] is True
    assert ev["logs"]["stdout"] == "POV_SUCCESS\n"


# --------------------------------------------------------------------------- #
# Teardown — never raises
# --------------------------------------------------------------------------- #
class _UnrulyContainer:
    status = "running"

    def reload(self):
        raise Exception("reload blew up")

    def kill(self):
        raise Exception("kill blew up")

    def remove(self, force=False):
        raise Exception("remove blew up")


def test_force_remove_swallows_all_errors():
    from execution_engine.sandbox.teardown import force_remove

    # Must not raise despite every call throwing.
    force_remove(_UnrulyContainer())


# --------------------------------------------------------------------------- #
# Internal sandbox API (TestClient + injected fake runner)
# --------------------------------------------------------------------------- #
def test_internal_api_run_and_health():
    from fastapi.testclient import TestClient

    import execution_engine.api as sb_api
    from execution_engine.api.schemas import RunResponse

    class FakeRunner:
        async def run_pov(self, script_code, env_vars=None, *, timeout_s=60, network=False):
            return {
                "stdout": "POV_SUCCESS\n", "stderr": "", "exit_code": 0,
                "duration_ms": 3, "container_id": "ctr-9", "timed_out": False,
                "crash": {"crashed": False}, "logs": {"stdout": "POV_SUCCESS\n"},
            }

    sb_api.configure(FakeRunner())
    try:
        client = TestClient(sb_api.app)
        r = client.get("/health")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"

        r = client.post("/run", json={"script_code": "print('POV_SUCCESS')", "env_vars": {}})
        assert r.status_code == 200
        body = r.json()
        assert body["stdout"] == "POV_SUCCESS\n"
        assert body["container_id"] == "ctr-9"
        RunResponse(**body)  # validates the response schema
    finally:
        sb_api.server._runner = None
