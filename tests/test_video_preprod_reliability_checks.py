from __future__ import annotations

import json
import subprocess
from pathlib import Path


def _write_report(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload), encoding="utf-8")


def _passing_payload() -> dict:
    return {
        "input_failover": {"recover_ms": 8000, "max_rebuffer_ms": 1200, "dropped_segments": 1},
        "key_outage": {"recover_ms": 15000, "license_5xx_rate": 0.02, "stale_key_serve_seconds": 30},
        "cdn_behavior": {"recover_ms": 20000, "origin_5xx_rate": 0.01, "edge_hit_ratio": 0.9, "manifest_stale_seconds": 10},
    }


def test_preprod_reliability_checks_pass_for_baseline(tmp_path: Path) -> None:
    report = tmp_path / "report.json"
    _write_report(report, _passing_payload())

    subprocess.run(["python", "scripts/video/preprod_reliability_checks.py", "--report", str(report)], check=True)


def test_preprod_reliability_checks_fail_on_threshold_breach(tmp_path: Path) -> None:
    report = tmp_path / "report.json"
    payload = _passing_payload()
    payload["input_failover"]["recover_ms"] = 20001
    _write_report(report, payload)

    result = subprocess.run(
        ["python", "scripts/video/preprod_reliability_checks.py", "--report", str(report)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1
    assert "input_failover recovery exceeded threshold" in result.stdout


def test_preprod_reliability_checks_fail_on_missing_section(tmp_path: Path) -> None:
    report = tmp_path / "report.json"
    _write_report(report, {"input_failover": {"recover_ms": 1, "max_rebuffer_ms": 1, "dropped_segments": 0}})

    result = subprocess.run(
        ["python", "scripts/video/preprod_reliability_checks.py", "--report", str(report)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 2
    assert "missing scenario section: key_outage" in result.stderr
