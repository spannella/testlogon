from __future__ import annotations

import datetime as dt
import subprocess
from unittest.mock import patch
from pathlib import Path

from scripts import release_gate_broadcast


def test_summarize_controls_collects_failed_and_waived() -> None:
    checks = {
        "metrics_wired": {"ok": True, "detail": "ok"},
        "critical_alerts": {"ok": False, "detail": "missing"},
        "api_contracts": {"ok": True, "waived": True, "detail": "waived"},
        "security_checks": {"ok": False, "detail": "failed"},
    }
    failed_controls, waived_controls = release_gate_broadcast.summarize_controls(checks)
    assert failed_controls == ["critical_alerts", "security_checks"]
    assert waived_controls == ["api_contracts"]


def test_apply_exceptions_waives_only_active_exceptions() -> None:
    future = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=1)).isoformat().replace("+00:00", "Z")
    past = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=1)).isoformat().replace("+00:00", "Z")
    checks = {
        "api_contracts": {"ok": False, "detail": "failed"},
        "security_checks": {"ok": False, "detail": "failed"},
    }
    exceptions = {
        "api_contracts": {"expires_at": future},
        "security_checks": {"expires_at": past},
    }
    out = release_gate_broadcast.apply_exceptions(checks, exceptions)
    assert out["api_contracts"]["ok"] is True
    assert out["api_contracts"]["waived"] is True
    assert out["security_checks"]["ok"] is False
    assert "waived" not in out["security_checks"]


def test_run_pytest_timeout_returns_failure_message() -> None:
    with patch.object(release_gate_broadcast.subprocess, "run", side_effect=subprocess.TimeoutExpired(cmd="pytest", timeout=5)):
        ok, detail = release_gate_broadcast._run_pytest(["tests/contract"], timeout_seconds=5)
    assert ok is False
    assert "timeout after 5s" in detail


def test_run_gate_skip_exec_does_not_call_pytest_runner() -> None:
    with patch.object(release_gate_broadcast, "_run_pytest") as run_pytest:
        checks = release_gate_broadcast.run_gate(skip_test_exec=True, pytest_timeout_seconds=5)
    run_pytest.assert_not_called()
    assert checks["api_contracts"]["ok"] is True
    assert checks["security_checks"]["ok"] is True


def test_load_exceptions_safe_returns_error_for_invalid_json(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("{invalid json", encoding="utf-8")
    out, err = release_gate_broadcast._load_exceptions_safe(bad)
    assert out == {}
    assert err is not None
    assert "invalid exceptions JSON" in err
