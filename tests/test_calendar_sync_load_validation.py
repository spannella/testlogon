from __future__ import annotations

import json
import subprocess
from pathlib import Path


def test_load_validation_script_generates_report_and_targets() -> None:
    out_path = Path("/tmp/calendar_sync_load_validation_test.json")
    if out_path.exists():
        out_path.unlink()

    cmd = [
        "python",
        "scripts/load/calendar_sync_resilience_load.py",
        "--events",
        "500",
        "--output",
        str(out_path),
    ]
    completed = subprocess.run(cmd, check=True, capture_output=True, text=True)
    summary = json.loads(completed.stdout.strip())

    assert out_path.exists()
    report = json.loads(out_path.read_text(encoding="utf-8"))

    assert "baseline" in report
    assert "hardened" in report
    assert "target_results" in report
    assert report["hardened"]["throughput_events_per_sec"] > 0
    assert "throughput_ok" in report["target_results"]
    assert "p95_ok" in report["target_results"]
    assert summary["output"] == str(out_path)
