"""Runtime tests for BugFund (offline).

No real LLM, no Docker daemon, no Semgrep/Nuclei required:
- The LiteLLM provider is exercised by monkeypatching ``litellm.completion``.
- ``SandboxManager`` is exercised with a fake Docker client.
- The swarm loop is driven with a scripted provider + fake sandbox client.
"""
from __future__ import annotations

import time

import pytest
from pydantic import BaseModel


# --------------------------------------------------------------------------- #
# 1. Smoke imports
# --------------------------------------------------------------------------- #
def test_imports():
    from ai_gateway import (  # noqa: F401
        LLMProvider, LiteLLMProvider, generate_structured_response,
        generate_structured_response_async, StructuredOutputError, GatewayError,
        configure, get_provider,
    )
    from agent_swarm import (  # noqa: F401
        supervisor_node, threat_modeler_node, actor_node, critic_node, patcher_node,
        route_from_state, run_nuclei, find_function_references, apply_source_patch,
        read_codebase, run_sast_scanner, execute_sandbox_script, set_sandbox_client,
        HuntState, Route, ActorPlan, CriticVerdict, PatchPlan,
    )
    from execution_engine import SandboxManager, SandboxError  # noqa: F401
    import control_plane.db.models as models

    assert models.Target.__tablename__ == "targets"
    assert models.HuntCampaign.__tablename__ == "hunt_campaigns"
    assert models.AgentState.__tablename__ == "agent_states"
    assert models.ExecutionLog.__tablename__ == "execution_logs"
    assert Route.PATCHER.value == "patcher"


# --------------------------------------------------------------------------- #
# 2. AI gateway — structured-output enforcement + retry
# --------------------------------------------------------------------------- #
class Answer(BaseModel):
    answer: int


class _Msg:
    def __init__(self, content):
        self.content = content


class _Choice:
    def __init__(self, content):
        self.message = _Msg(content)


class _Resp:
    def __init__(self, content):
        self.choices = [_Choice(content)]


def test_gateway_parses_fenced_json_after_plain_text_retry(monkeypatch):
    litellm = pytest.importorskip("litellm")
    from ai_gateway import LiteLLMProvider

    outputs = iter(["plain text, no json", "```json\n{\"answer\": 42}\n```"])
    monkeypatch.setattr(litellm, "completion", lambda **kw: _Resp(next(outputs)))
    provider = LiteLLMProvider(model="fake", structured_mode="none")
    result = provider.generate_structured("q", response_model=Answer, retries=2)
    assert isinstance(result, Answer) and result.answer == 42


def test_gateway_extracts_embedded_json(monkeypatch):
    litellm = pytest.importorskip("litellm")
    from ai_gateway import LiteLLMProvider

    monkeypatch.setattr(litellm, "completion", lambda **kw: _Resp('blah {"answer": 7} trailing'))
    provider = LiteLLMProvider(model="fake", structured_mode="none")
    result = provider.generate_structured("q", response_model=Answer, retries=0)
    assert result.answer == 7


def test_gateway_raises_after_exhausting_retries(monkeypatch):
    litellm = pytest.importorskip("litellm")
    from ai_gateway import LiteLLMProvider, StructuredOutputError

    monkeypatch.setattr(litellm, "completion", lambda **kw: _Resp("still just prose"))
    provider = LiteLLMProvider(model="fake", structured_mode="none")
    with pytest.raises(StructuredOutputError):
        provider.generate_structured("q", response_model=Answer, retries=1)


def test_gateway_wrapper_uses_configured_provider():
    import ai_gateway
    from ai_gateway import LLMProvider, generate_structured_response

    class FixedProvider(LLMProvider):
        def name(self):
            return "fixed"

        def generate_structured(self, prompt, response_model, **kw):
            return response_model(answer=99)

        async def generate_structured_async(self, prompt, response_model, **kw):
            return response_model(answer=99)

    ai_gateway.configure(FixedProvider())
    try:
        assert generate_structured_response("q", schema=Answer).answer == 99
    finally:
        ai_gateway._default_provider = None


def test_get_provider_raises_when_unconfigured(monkeypatch):
    import ai_gateway
    from ai_gateway import GatewayError

    monkeypatch.delenv("LLM_MODEL", raising=False)
    ai_gateway._default_provider = None
    with pytest.raises(GatewayError):
        ai_gateway.get_provider()


# --------------------------------------------------------------------------- #
# 3. Skills
# --------------------------------------------------------------------------- #
async def test_read_codebase_signatures(tmp_path):
    from agent_swarm.skills import read_codebase, ReadDepth

    (tmp_path / "app.py").write_text(
        "def foo():\n    pass\nclass Bar:\n    def baz(self):\n        pass\n",
        encoding="utf-8",
    )
    view = await read_codebase(str(tmp_path), ReadDepth.SIGNATURES)
    assert view["languages"].get("python") == 1
    assert view["files"] and "signatures" in view["files"][0]


async def test_find_function_references(tmp_path):
    from agent_swarm.skills import find_function_references

    (tmp_path / "m.py").write_text(
        "def foo():\n    pass\n\ndef caller():\n    foo()\n    obj.foo()\n",
        encoding="utf-8",
    )
    rep = await find_function_references("foo", search_root=str(tmp_path))
    assert rep["total"] >= 2
    assert all("snippet" in r for r in rep["references"])


async def test_execute_sandbox_script_uses_client():
    from agent_swarm import skills

    captured = {}

    class FakeClient:
        async def run_script(self, *, script_code, env_vars, timeout_s, network):
            captured.update(script_code=script_code, env_vars=env_vars)
            return {"stdout": "ok", "stderr": "", "exit_code": 0,
                    "duration_ms": 1, "container_id": "c", "timed_out": False}

    skills.set_sandbox_client(FakeClient())
    try:
        res = await skills.execute_sandbox_script("print(1)", env_vars={"A": "b"})
    finally:
        skills._sandbox_client = None
    assert res["stdout"] == "ok"
    assert captured["script_code"] == "print(1)"
    assert captured["env_vars"]["A"] == "b"


async def test_run_sast_missing_binary(tmp_path):
    import shutil
    if shutil.which("semgrep"):
        pytest.skip("semgrep installed")
    from agent_swarm.skills import run_sast_scanner, ToolError

    with pytest.raises(ToolError):
        await run_sast_scanner(str(tmp_path))


# --------------------------------------------------------------------------- #
# 4. SandboxManager (fake Docker client)
# --------------------------------------------------------------------------- #
class _FakeImages:
    def get(self, name):
        return object()

    def pull(self, name):
        return object()


class _FakeContainer:
    def __init__(self, *, stdout=b"POV_SUCCESS\n", stderr=b"", exit_code=0, hang=False):
        self.id = "ctr-123"
        self.status = "created"
        self._stdout, self._stderr, self._exit_code, self._hang = (
            stdout, stderr, exit_code, hang,
        )
        self.killed = False
        self.removed = False
        self.create_kwargs = None

    def start(self):
        self.status = "running"

    def wait(self):
        if self._hang:
            while self.status == "running":
                time.sleep(0.01)
            return {"StatusCode": 137}
        self.status = "exited"
        return {"StatusCode": self._exit_code}

    def logs(self, stdout=True, stderr=True, demux=False):
        if demux:
            return self._stdout, self._stderr
        return self._stdout + self._stderr

    def reload(self):
        pass

    def kill(self):
        if self.status != "running":
            raise Exception("not running")  # mimic docker raising on a stopped container
        self.killed = True
        self.status = "exited"

    def remove(self, force=False):
        self.removed = True


class _FakeContainers:
    def __init__(self, container):
        self._c = container

    def create(self, **kwargs):
        self._c.create_kwargs = kwargs
        return self._c


class _FakeClient:
    def __init__(self, container):
        self.images = _FakeImages()
        self.containers = _FakeContainers(container)

    def close(self):
        pass


def test_run_pov_success(tmp_path):
    from execution_engine import SandboxManager

    ctr = _FakeContainer(stdout=b"POV_SUCCESS\n", stderr=b"", exit_code=0)
    mgr = SandboxManager(_FakeClient(ctr), target_resolver=lambda tid: str(tmp_path))
    try:
        res = mgr.run_pov(1, "print('POV_SUCCESS')")
        assert res["exit_code"] == 0
        assert res["stdout"] == "POV_SUCCESS\n"
        assert res["timed_out"] is False
        assert ctr.removed is True
        kw = ctr.create_kwargs
        assert kw["cap_drop"] == ["ALL"]
        assert kw["network_mode"] == "none"
        assert kw["command"] == ["python3", "-u", "/srv/pov/pov.py"]
        assert any(v["mode"] == "ro" and v["bind"] == "/srv/target"
                   for v in kw["volumes"].values())
    finally:
        mgr.close()


def test_run_pov_timeout_kills_and_removes(tmp_path):
    from execution_engine import SandboxManager

    ctr = _FakeContainer(hang=True)
    mgr = SandboxManager(_FakeClient(ctr), target_resolver=lambda tid: str(tmp_path))
    try:
        res = mgr.run_pov(1, "while True: pass", timeout_s=1)
        assert res["timed_out"] is True
        assert ctr.killed is True
        assert ctr.removed is True
    finally:
        mgr.close()


def test_run_pov_nonzero_exit(tmp_path):
    from execution_engine import SandboxManager

    ctr = _FakeContainer(stdout=b"", stderr=b"boom\n", exit_code=1)
    mgr = SandboxManager(_FakeClient(ctr), target_resolver=lambda tid: str(tmp_path))
    try:
        res = mgr.run_pov(1, "raise SystemExit(1)")
        assert res["exit_code"] == 1
        assert "boom" in res["stderr"]
        assert ctr.removed is True
    finally:
        mgr.close()


def test_run_pov_missing_target_raises(tmp_path):
    from execution_engine import SandboxManager, SandboxError

    mgr = SandboxManager(_FakeClient(_FakeContainer()),
                         target_resolver=lambda tid: str(tmp_path / "missing"))
    try:
        with pytest.raises(SandboxError):
            mgr.run_pov(1, "print(1)")
    finally:
        mgr.close()


# --------------------------------------------------------------------------- #
# 5. Swarm loop: actor -> critic (scripted provider + fake sandbox)
# --------------------------------------------------------------------------- #
async def test_actor_critic_loop_graduates_finding(tmp_path):
    import ai_gateway
    from ai_gateway import LLMProvider
    from agent_swarm import skills
    from agent_swarm.nodes import actor_node, critic_node
    from agent_swarm.state import HuntState, ActorPlan, CriticVerdict, Route

    class ScriptedProvider(LLMProvider):
        def name(self):
            return "scripted"

        async def generate_structured_async(self, prompt, response_model, **kw):
            if response_model is ActorPlan:
                return ActorPlan(pov_script="print('POV_SUCCESS')", explanation="e",
                                 expected_signal="POV_SUCCESS")
            if response_model is CriticVerdict:
                return CriticVerdict(verified=True, confidence=0.9, diagnosis="triggered",
                                     severity="high", cwe="CWE-89")
            raise AssertionError(response_model)

        def generate_structured(self, prompt, response_model, **kw):
            raise AssertionError("sync path not expected here")

    class FakeSandbox:
        async def run_script(self, *, script_code, env_vars, timeout_s, network):
            return {"stdout": "POV_SUCCESS\n", "stderr": "", "exit_code": 0,
                    "duration_ms": 5, "container_id": "c", "timed_out": False}

    ai_gateway.configure(ScriptedProvider())
    skills.set_sandbox_client(FakeSandbox())
    try:
        state: HuntState = {
            "target_id": "t1",
            "target_path": str(tmp_path),
            "iteration": 0,
            "max_iterations": 5,
            "hypotheses": [{
                "id": "H-001", "cwe": "CWE-89", "title": "SQLi",
                "target_path": "db.py", "rationale": "r", "confidence": 0.8,
                "status": "pending",
            }],
            "current_hypothesis_id": "H-001",
            "findings": [],
            "status": "running",
        }

        actor_delta = await actor_node(state)
        state.update(actor_delta)
        assert state["pending_pov"]
        assert state["last_result"]["stdout"] == "POV_SUCCESS\n"

        critic_delta = await critic_node(state)
        state.update(critic_delta)
        assert state["findings"], "finding should graduate"
        finding = state["findings"][-1]
        assert finding["verified"] is True
        assert finding["cwe"] == "CWE-89"
        # verified + source target present -> routes to PATCHER
        assert state["route"] == Route.PATCHER
    finally:
        ai_gateway._default_provider = None
        skills._sandbox_client = None
