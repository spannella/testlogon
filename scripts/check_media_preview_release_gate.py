#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any


@dataclass
class GateFailure:
    message: str


def _parse_iso_date(value: str) -> date:
    try:
        return datetime.fromisoformat(value).date()
    except ValueError as exc:
        raise ValueError(f"invalid ISO date: {value}") from exc


def _load_checklist(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def _validate_success_threshold(data: dict[str, Any], *, min_success_rate: float) -> list[GateFailure]:
    failures: list[GateFailure] = []
    success = data.get("derivative_generation") or {}
    threshold = success.get("success_rate_threshold")
    observed = success.get("success_rate_observed")
    if threshold is None or observed is None:
        failures.append(GateFailure("derivative_generation success_rate_threshold and success_rate_observed are required"))
        return failures

    try:
        threshold_val = float(threshold)
        observed_val = float(observed)
    except (TypeError, ValueError):
        failures.append(GateFailure("derivative_generation success_rate values must be numeric"))
        return failures

    if threshold_val < min_success_rate:
        failures.append(
            GateFailure(
                f"derivative_generation.success_rate_threshold must be >= {min_success_rate:.2f} (found {threshold_val:.2f})"
            )
        )
    if observed_val < threshold_val:
        failures.append(
            GateFailure(
                f"derivative_generation.success_rate_observed {observed_val:.2f} is below threshold {threshold_val:.2f}"
            )
        )

    return failures


def _validate_checklist(
    data: dict[str, Any],
    *,
    max_age_days: int,
    min_success_rate: float,
    today: date,
) -> list[GateFailure]:
    failures: list[GateFailure] = []

    gate = data.get("release_gate") or {}
    if gate.get("required_for_release") is not True:
        failures.append(GateFailure("release_gate.required_for_release must be true"))

    if not (data.get("feature_flag_strategy") or {}).get("validated"):
        failures.append(GateFailure("feature_flag_strategy.validated must be true"))

    failures.extend(_validate_success_threshold(data, min_success_rate=min_success_rate))

    slo = data.get("slo") or {}
    if slo.get("queue_slo_met") is not True:
        failures.append(GateFailure("slo.queue_slo_met must be true"))
    if slo.get("latency_slo_met") is not True:
        failures.append(GateFailure("slo.latency_slo_met must be true"))

    sec = data.get("security_review") or {}
    if sec.get("sign_off") is not True:
        failures.append(GateFailure("security_review.sign_off must be true"))

    approver = str(sec.get("approver") or "").strip()
    if not approver:
        failures.append(GateFailure("security_review.approver is required"))

    suites = data.get("test_suites") or {}
    if suites.get("all_green") is not True:
        failures.append(GateFailure("test_suites.all_green must be true"))
    suites_list = suites.get("required")
    if not isinstance(suites_list, list) or not suites_list:
        failures.append(GateFailure("test_suites.required must be a non-empty array"))

    reviewed_raw = gate.get("last_reviewed")
    if not reviewed_raw:
        failures.append(GateFailure("release_gate.last_reviewed is required"))
    else:
        try:
            reviewed = _parse_iso_date(str(reviewed_raw))
            age_days = (today - reviewed).days
            if age_days > max_age_days:
                failures.append(
                    GateFailure(
                        f"release_gate.last_reviewed is stale ({age_days} days old, max allowed {max_age_days})"
                    )
                )
        except ValueError as exc:
            failures.append(GateFailure(str(exc)))

    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate media preview release-gate checklist completion.")
    parser.add_argument(
        "--checklist",
        default="docs/media-preview-release-gate.json",
        help="Path to release-gate checklist JSON file.",
    )
    parser.add_argument("--max-age-days", type=int, default=30, help="Maximum allowed age for release_gate.last_reviewed.")
    parser.add_argument(
        "--min-success-rate",
        type=float,
        default=0.95,
        help="Minimum allowed derivative generation success threshold.",
    )
    args = parser.parse_args()

    path = Path(args.checklist)
    if not path.exists():
        print(f"[FAIL] checklist file not found: {path}")
        return 1

    try:
        data = _load_checklist(path)
    except json.JSONDecodeError as exc:
        print(f"[FAIL] invalid JSON in checklist: {exc}")
        return 1

    failures = _validate_checklist(
        data,
        max_age_days=args.max_age_days,
        min_success_rate=args.min_success_rate,
        today=datetime.now(timezone.utc).date(),
    )
    if failures:
        for failure in failures:
            print(f"[FAIL] {failure.message}")
        return 1

    print(f"[OK] media preview release gate passed: {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
