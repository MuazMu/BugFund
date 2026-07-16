"""Tests for the AI gateway router/budget guard and the observability layer."""
from __future__ import annotations

import pytest


# --------------------------------------------------------------------------- #
# ModelRouter
# --------------------------------------------------------------------------- #
def test_router_primary_and_chain():
    from ai_gateway import ModelRouter

    config = {
        "default": {"model": "m-default"},
        "roles": {"critic": {"model": "m-strong"}},
        "fallbacks": {"m-strong": ["m-backup", "m-strong"]},
    }
    r = ModelRouter(config)
    assert r.primary("critic") == "m-strong"
    assert r.primary("supervisor") == "m-default"  # unlisted role → default
    assert r.chain("critic") == ["m-strong", "m-backup"]  # de-duped
    assert r.role_models()["critic"] == "m-strong"


def test_router_loads_yaml_config():
    pytest.importorskip("yaml")
    from ai_gateway import load_routing_config

    config = load_routing_config()
    assert "default" in config
    assert "roles" in config


# --------------------------------------------------------------------------- #
# BudgetGuard
# --------------------------------------------------------------------------- #
def test_budget_guard_enforces_token_cap():
    from control_plane.core.exceptions import BudgetExceeded
    from ai_gateway import BudgetGuard

    g = BudgetGuard(max_tokens=100, max_usd=10.0, label="t")
    g.consume(50)
    assert g.tokens_used == 50
    assert g.remaining_tokens == 50
    with pytest.raises(BudgetExceeded):
        g.consume(60)  # 50 + 60 > 100


def test_budget_guard_enforces_usd_cap():
    from control_plane.core.exceptions import BudgetExceeded
    from ai_gateway import BudgetGuard

    g = BudgetGuard(max_tokens=10_000, max_usd=0.0, label="t")
    with pytest.raises(BudgetExceeded):
        g.consume(1, usd=0.01)


def test_estimate_cost():
    from ai_gateway import estimate_cost

    # 1M prompt tokens of claude-3-5-sonnet @ $3/1M == $3.
    assert estimate_cost("claude-3-5-sonnet", 1_000_000, 0) == pytest.approx(3.0)
    # Unknown models never block (cost 0).
    assert estimate_cost("does-not-exist", 9_999_999, 9_999_999) == 0.0


def test_consume_call_accounts_cost():
    from ai_gateway import BudgetGuard

    g = BudgetGuard(max_tokens=10_000, max_usd=10.0)
    cost = g.consume_call("claude-3-5-sonnet", prompt_tokens=1000, completion_tokens=500)
    assert cost > 0
    assert g.tokens_used == 1500


# --------------------------------------------------------------------------- #
# Observability — metrics
# --------------------------------------------------------------------------- #
def test_metrics_counters_and_histograms():
    from observability import inc, observe, snapshot
    from observability.metrics import reset

    reset()
    inc("findings_verified_total", 2)
    inc("findings_verified_total")
    observe("sandbox_duration_ms", 12.0)
    observe("sandbox_duration_ms", 30.0)

    snap = snapshot()
    assert snap["counters"]["findings_verified_total"] == 3
    h = snap["histograms"]["sandbox_duration_ms"]
    assert h["count"] == 2
    assert h["min"] == 12.0 and h["max"] == 30.0
    reset()


# --------------------------------------------------------------------------- #
# Observability — tracing + langfuse no-op when unconfigured
# --------------------------------------------------------------------------- #
def test_tracing_span_noop_when_disabled():
    from observability import span, tracing_enabled

    assert tracing_enabled() is False
    with span("unit-test", role="critic") as s:
        assert s is None  # no OTel endpoint configured


def test_langfuse_trace_yields_record():
    from observability import langfuse_enabled, trace_generation

    assert langfuse_enabled() is False
    with trace_generation("gen", model="m", prompt="hi") as rec:
        rec["output"] = "ok"
        rec["usage"] = {"prompt_tokens": 2, "completion_tokens": 1}
    assert rec["output"] == "ok"
    assert "latency_ms" in rec  # always populated, even without a client
