"""Phase-1 control-plane tests: config, graph compilation, budget, Celery, FastAPI."""
from __future__ import annotations

import pytest


def test_settings_defaults():
    from control_plane.core.config import get_settings

    s = get_settings()
    assert s.api_prefix == "/api/v1"
    assert s.sandbox_image == "ubuntu:22.04"
    assert s.campaign_max_steps > 0


def test_budget_enforcement():
    from control_plane.core.config import BudgetExceeded
    from control_plane.orchestrator.graph import Budget

    b = Budget(max_steps=2, max_tokens=100, max_usd=1.0)
    b.check_step(1)
    with pytest.raises(BudgetExceeded):
        b.check_step(2)
    with pytest.raises(BudgetExceeded):
        b.consume_tokens(101)


def test_build_graph_compiles():
    from control_plane.orchestrator.graph import build_graph

    compiled = build_graph()
    assert compiled is not None


def test_build_initial_state():
    from control_plane.orchestrator.graph import build_initial_state

    s = build_initial_state(7, "/tmp/t", max_iterations=3)
    assert s["target_id"] == "7"
    assert s["max_iterations"] == 3
    assert s["status"] == "running"


def test_celery_task_registered():
    from control_plane.tasks.celery_app import app, run_campaign_task

    assert "bugfund.campaigns.run_campaign_task" in app.tasks
    assert callable(run_campaign_task)


def test_api_health_and_campaigns():
    from fastapi.testclient import TestClient

    from control_plane.api.main import app

    client = TestClient(app)
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"

    r = client.post("/api/v1/campaigns", json={"target_id": 1, "target_path": "/tmp/x"})
    assert r.status_code == 200
    assert r.json()["status"] in {"queued", "queued_no_broker"}
