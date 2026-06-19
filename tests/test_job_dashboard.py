"""Unit tests for the Background Job Dashboard service (PLATFORM-008).

These exercise the pure-logic portions (static registry, health
classification, run-now safety) by loading the module in isolation and
monkeypatching the DDB-backed query helpers. The full DDB read/write path is
covered end-to-end by frontend/e2e/job-dashboard.spec.ts against the live stack.
"""
import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _load_module(mod_name: str, rel_path: str):
    spec = importlib.util.spec_from_file_location(
        mod_name, ROOT / rel_path, submodule_search_locations=[str(ROOT / "app")]
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def svc():
    return _load_module("job_dashboard_under_test", "app/services/job_dashboard.py")


def test_known_jobs_registry(svc):
    jobs = svc.list_known_jobs()
    names = {j["name"] for j in jobs}
    assert "unified_scheduler" in names
    assert "webhook_dispatcher" in names
    # Each entry exposes required metadata fields.
    for j in jobs:
        assert set(["name", "label", "poll_interval_seconds", "run_now_safe"]).issubset(j)


def test_is_known_job(svc):
    assert svc.is_known_job("unified_scheduler") is True
    assert svc.is_known_job("does_not_exist") is False


def test_run_now_safe_flags(svc):
    assert svc.KNOWN_JOBS["unified_scheduler"]["run_now_safe"] is True
    assert svc.KNOWN_JOBS["billing_dunning"]["run_now_safe"] is False


def test_health_unknown_when_no_runs(svc, monkeypatch):
    monkeypatch.setattr(svc, "latest_run", lambda name: None)
    health = {h["name"]: h for h in svc.job_health()}
    assert health["unified_scheduler"]["health"] == "unknown"
    assert health["unified_scheduler"]["last_run_at"] is None


def test_health_ok_for_success_run(svc, monkeypatch):
    def fake_latest(name):
        return {
            "job_name": name, "run_id": "r", "status": "success",
            "started_at": 1000, "finished_at": 1000, "duration_ms": 5.0,
            "items_processed": 3, "items_failed": 0, "error": None,
            "triggered_by": "scheduler",
        }
    monkeypatch.setattr(svc, "latest_run", fake_latest)
    health = {h["name"]: h for h in svc.job_health()}
    us = health["unified_scheduler"]
    assert us["health"] == "ok"
    assert us["last_run_at"] == 1000
    # next_run_at = started + interval (15s for unified_scheduler)
    assert us["next_run_at"] == 1000 + 15


def test_health_failed_and_degraded(svc, monkeypatch):
    def fake_latest(name):
        if name == "unified_scheduler":
            return {"job_name": name, "run_id": "r", "status": "failed",
                    "started_at": 1, "finished_at": 1, "duration_ms": 0.0,
                    "items_processed": 0, "items_failed": 1, "error": "boom",
                    "triggered_by": "scheduler"}
        return {"job_name": name, "run_id": "r", "status": "success",
                "started_at": 1, "finished_at": 1, "duration_ms": 0.0,
                "items_processed": 1, "items_failed": 2, "error": None,
                "triggered_by": "scheduler"}
    monkeypatch.setattr(svc, "latest_run", fake_latest)
    health = {h["name"]: h for h in svc.job_health()}
    assert health["unified_scheduler"]["health"] == "failed"
    # success status but item failures -> degraded
    assert health["webhook_dispatcher"]["health"] == "degraded"


async def _run(coro):
    return await coro


def test_trigger_run_now_rejects_unsafe(svc):
    import asyncio

    with pytest.raises(svc.RunNowNotAllowed):
        asyncio.run(
            svc.trigger_run_now("billing_dunning", triggered_by="manual:x")
        )


def test_trigger_run_now_rejects_unknown(svc):
    import asyncio

    with pytest.raises(svc.RunNowNotAllowed):
        asyncio.run(
            svc.trigger_run_now("nope", triggered_by="manual:x")
        )
