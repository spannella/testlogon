#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import json
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

REQUIRED_METRICS = [
    "broadcast_provision_latency_seconds",
    "broadcast_session_actions_total",
    "broadcast_input_loss_total",
    "broadcast_output_errors_total",
    "broadcast_drift_incidents_total",
]
REQUIRED_ALERTS = [
    "BroadcastProvisioningLatencyHigh",
    "BroadcastStartFailuresHigh",
    "BroadcastDriftIncidentsDetected",
]


def _load_exceptions(path: Path | None) -> dict:
    if not path or not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def _load_exceptions_safe(path: Path | None) -> tuple[dict, str | None]:
    try:
        return _load_exceptions(path), None
    except json.JSONDecodeError as exc:
        return {}, f"invalid exceptions JSON: {exc.msg}"


def _exception_active(exceptions: dict, check_name: str) -> bool:
    item = exceptions.get(check_name)
    if not item:
        return False
    exp = str(item.get("expires_at") or "")
    try:
        return dt.datetime.fromisoformat(exp.replace("Z", "+00:00")) > dt.datetime.now(dt.timezone.utc)
    except Exception:
        return False


def check_metrics() -> tuple[bool, str]:
    text = (ROOT / "app/metrics.py").read_text(encoding="utf-8")
    missing = [m for m in REQUIRED_METRICS if m not in text]
    if missing:
        return False, f"missing metrics: {', '.join(missing)}"
    return True, "all required broadcast metrics present"


def check_alerts() -> tuple[bool, str]:
    text = (ROOT / "docs/alerts/broadcast-health-alerts.yml").read_text(encoding="utf-8")
    missing = [a for a in REQUIRED_ALERTS if a not in text]
    route_ok = "route: nonprod-oncall" in text
    if missing or not route_ok:
        return False, f"alerts check failed missing={missing} route_ok={route_ok}"
    return True, "critical alerts and routing labels present"


def _run_pytest(args: list[str], *, timeout_seconds: int) -> tuple[bool, str]:
    try:
        proc = subprocess.run(["pytest", "-q", *args], capture_output=True, text=True, timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        return False, f"timeout after {timeout_seconds}s running pytest -q {' '.join(args)}"
    if proc.returncode == 0:
        return True, "passed"
    return False, (proc.stdout + "\n" + proc.stderr)[-4000:]


def run_gate(*, skip_test_exec: bool, pytest_timeout_seconds: int) -> dict:
    checks: dict[str, dict] = {}
    ok, msg = check_metrics()
    checks["metrics_wired"] = {"ok": ok, "detail": msg}
    ok, msg = check_alerts()
    checks["critical_alerts"] = {"ok": ok, "detail": msg}

    if skip_test_exec:
        checks["api_contracts"] = {"ok": True, "detail": "skipped (--skip-test-exec)"}
        checks["security_checks"] = {"ok": True, "detail": "skipped (--skip-test-exec)"}
    else:
        ok, msg = _run_pytest(["tests/contract"], timeout_seconds=pytest_timeout_seconds)
        checks["api_contracts"] = {"ok": ok, "detail": msg}
        ok, msg = _run_pytest(["tests/test_broadcast_secrets.py", "tests/test_broadcast_cloudfront.py"], timeout_seconds=pytest_timeout_seconds)
        checks["security_checks"] = {"ok": ok, "detail": msg}

    return checks


def apply_exceptions(checks: dict, exceptions: dict) -> dict:
    for name, result in checks.items():
        if result["ok"]:
            continue
        if _exception_active(exceptions, name):
            result["waived"] = True
            result["ok"] = True
    return checks


def summarize_controls(checks: dict) -> tuple[list[str], list[str]]:
    failed_controls: list[str] = []
    waived_controls: list[str] = []
    for name, result in checks.items():
        if result.get("waived"):
            waived_controls.append(name)
        if not result.get("ok"):
            failed_controls.append(name)
    return failed_controls, waived_controls


def main() -> int:
    parser = argparse.ArgumentParser(description="Broadcast release gate")
    parser.add_argument("--exceptions-file", default=".release-gate-exceptions/broadcast.json")
    parser.add_argument("--skip-test-exec", action="store_true")
    parser.add_argument("--pytest-timeout-seconds", type=int, default=900)
    args = parser.parse_args()

    checks = run_gate(skip_test_exec=args.skip_test_exec, pytest_timeout_seconds=max(1, args.pytest_timeout_seconds))
    exceptions, load_error = _load_exceptions_safe(ROOT / args.exceptions_file)
    if load_error:
        checks["exceptions_file_valid"] = {"ok": False, "detail": load_error}
    checks = apply_exceptions(checks, exceptions)
    failed_controls, waived_controls = summarize_controls(checks)
    overall_ok = all(item.get("ok") for item in checks.values())
    report = {
        "ok": overall_ok,
        "checks": checks,
        "failed_controls": failed_controls,
        "waived_controls": waived_controls,
    }
    print(json.dumps(report, indent=2))
    return 0 if overall_ok else 2


if __name__ == "__main__":
    raise SystemExit(main())
