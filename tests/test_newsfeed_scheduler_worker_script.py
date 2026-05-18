import json
import runpy
import sys
import types


SCRIPT_PATH = "scripts/newsfeed-scheduler-worker.py"


def _load_script(monkeypatch, *, summaries):
    captured = {"kwargs": None}

    def _run_scheduler_loop(**kwargs):
        captured["kwargs"] = kwargs
        return summaries

    def _summary_has_failures(summary):
        return bool(
            int(summary.get("run_exception", 0))
            or int(summary.get("error", 0))
            or int(summary.get("retry_exhausted", 0))
            or int(summary.get("conflict", 0))
            or int(summary.get("meter_errors", 0))
        )

    fake_scheduler = types.SimpleNamespace(
        run_scheduler_loop=_run_scheduler_loop,
        scheduler_summary_has_failures=_summary_has_failures,
    )
    monkeypatch.setitem(sys.modules, "app.services.newsfeed_scheduler", fake_scheduler)
    ns = runpy.run_path(SCRIPT_PATH, run_name="__scheduler_worker_test__")
    return ns, captured


def test_worker_script_returns_success_when_fail_on_errors_disabled(monkeypatch, capsys) -> None:
    ns, _ = _load_script(monkeypatch, summaries=[{"run_exception": 1, "error": 0, "retry_exhausted": 0}])
    monkeypatch.delenv("NEWSFEED_SCHEDULER_FAIL_ON_ERRORS", raising=False)

    rc = ns["main"]()

    assert rc == 0
    out = json.loads(capsys.readouterr().out.strip())
    assert out["has_failures"] is True


def test_worker_script_returns_nonzero_when_fail_on_errors_enabled(monkeypatch, capsys) -> None:
    ns, _ = _load_script(monkeypatch, summaries=[{"run_exception": 0, "error": 1, "retry_exhausted": 0}])
    monkeypatch.setenv("NEWSFEED_SCHEDULER_FAIL_ON_ERRORS", "true")

    rc = ns["main"]()

    assert rc == 2
    out = json.loads(capsys.readouterr().out.strip())
    assert out["has_failures"] is True


def test_worker_script_treats_conflicts_as_failures_in_fail_fast_mode(monkeypatch, capsys) -> None:
    ns, _ = _load_script(monkeypatch, summaries=[{"run_exception": 0, "error": 0, "retry_exhausted": 0, "conflict": 1, "meter_errors": 0}])
    monkeypatch.setenv("NEWSFEED_SCHEDULER_FAIL_ON_ERRORS", "1")

    rc = ns["main"]()

    assert rc == 2
    out = json.loads(capsys.readouterr().out.strip())
    assert out["has_failures"] is True


def test_worker_script_falls_back_to_default_float_env(monkeypatch, capsys) -> None:
    ns, captured = _load_script(monkeypatch, summaries=[{"run_exception": 0, "error": 0, "retry_exhausted": 0}])
    monkeypatch.setenv("NEWSFEED_SCHEDULER_INTERVAL_SECONDS", "not-a-float")

    rc = ns["main"]()

    assert rc == 0
    assert captured["kwargs"]["interval_seconds"] == 5.0
    out = json.loads(capsys.readouterr().out.strip())
    assert out["config"]["interval_seconds"] == 5.0


def test_worker_script_clamps_invalid_runtime_bounds(monkeypatch, capsys) -> None:
    ns, captured = _load_script(monkeypatch, summaries=[{"run_exception": 0, "error": 0, "retry_exhausted": 0}])
    monkeypatch.setenv("NEWSFEED_SCHEDULER_INTERVAL_SECONDS", "-5")
    monkeypatch.setenv("NEWSFEED_SCHEDULER_ITERATIONS", "-1")
    monkeypatch.setenv("NEWSFEED_SCHEDULER_PAGE_LIMIT", "0")
    monkeypatch.setenv("NEWSFEED_SCHEDULER_MAX_BATCHES", "-10")
    monkeypatch.setenv("NEWSFEED_SCHEDULER_PUBLISH_RETRY_MAX", "-4")
    monkeypatch.setenv("NEWSFEED_SCHEDULER_RETRY_BACKOFF_SECONDS", "0")

    rc = ns["main"]()

    assert rc == 0
    assert captured["kwargs"]["interval_seconds"] == 0.1
    assert captured["kwargs"]["iterations"] == 1
    assert captured["kwargs"]["page_limit"] == 1
    assert captured["kwargs"]["max_batches"] == 1
    assert captured["kwargs"]["publish_retry_max"] == 0
    assert captured["kwargs"]["retry_backoff_seconds"] == 0.01
    out = json.loads(capsys.readouterr().out.strip())
    assert out["config"]["interval_seconds"] == 0.1
    assert out["config"]["iterations"] == 1
    assert out["config"]["page_limit"] == 1
    assert out["config"]["max_batches"] == 1
    assert out["config"]["publish_retry_max"] == 0
    assert out["config"]["retry_backoff_seconds"] == 0.01
