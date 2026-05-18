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


def _validate_checklist(
    data: dict[str, Any],
    *,
    max_age_days: int,
    today: date,
) -> list[GateFailure]:
    failures: list[GateFailure] = []

    gate = data.get("release_gate") or {}
    if gate.get("required_for_ga") is not True:
        failures.append(GateFailure("release_gate.required_for_ga must be true"))

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

    review = data.get("privacy_security_review") or {}
    if review.get("sign_off") is not True:
        failures.append(GateFailure("privacy_security_review.sign_off must be true"))

    approver = str(review.get("approver") or "").strip()
    if not approver:
        failures.append(GateFailure("privacy_security_review.approver is required"))

    if str(review.get("scope") or "").strip() == "":
        failures.append(GateFailure("privacy_security_review.scope is required"))

    remediations = data.get("remediations") or {}
    items = remediations.get("required")
    if not isinstance(items, list) or not items:
        failures.append(GateFailure("remediations.required must be a non-empty array"))
    else:
        for item in items:
            ticket_id = str(item.get("id") or "<unknown>")
            status = str(item.get("status") or "").strip().lower()
            if status != "closed":
                failures.append(GateFailure(f"remediation {ticket_id} is not closed (status={status or 'missing'})"))
    if remediations.get("all_closed_before_ga") is not True:
        failures.append(GateFailure("remediations.all_closed_before_ga must be true"))

    pentest = data.get("pen_test") or {}
    if pentest.get("executed") is not True:
        failures.append(GateFailure("pen_test.executed must be true"))
    if pentest.get("passed") is not True:
        failures.append(GateFailure("pen_test.passed must be true"))

    scenarios = pentest.get("scenarios") or []
    if not isinstance(scenarios, list) or not scenarios:
        failures.append(GateFailure("pen_test.scenarios must be a non-empty array"))
    else:
        normalized = {str(item).strip().lower() for item in scenarios if str(item).strip()}
        required = {"enumeration", "data_leakage"}
        missing = sorted(required - normalized)
        for item in missing:
            failures.append(GateFailure(f"pen_test.scenarios missing required item: {item}"))

    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate profile privacy/security GA release-gate checklist completion.")
    parser.add_argument(
        "--checklist",
        default="docs/profile-privacy-security-release-gate-upr021.json",
        help="Path to profile privacy/security release-gate checklist JSON file.",
    )
    parser.add_argument(
        "--max-age-days",
        type=int,
        default=45,
        help="Maximum allowed age for release_gate.last_reviewed.",
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
        today=datetime.now(timezone.utc).date(),
    )
    if failures:
        for failure in failures:
            print(f"[FAIL] {failure.message}")
        return 1

    print(f"[OK] profile privacy/security release gate passed: {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
