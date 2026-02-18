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


def _validate_checklist(data: dict[str, Any], *, max_age_days: int, today: date) -> list[GateFailure]:
    failures: list[GateFailure] = []

    tickets = data.get("required_tickets")
    if not isinstance(tickets, list) or not tickets:
        return [GateFailure("required_tickets must be a non-empty array")]

    for ticket in tickets:
        ticket_id = ticket.get("id", "<unknown>")
        status = str(ticket.get("status", "")).lower()
        if status != "closed":
            failures.append(GateFailure(f"ticket {ticket_id} is not closed (status={status or 'missing'})"))

    gate = data.get("release_gate") or {}
    if gate.get("all_required_closed") is not True:
        failures.append(GateFailure("release_gate.all_required_closed must be true"))

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

    cadence = str(gate.get("cadence", "")).strip()
    if not cadence:
        failures.append(GateFailure("release_gate.cadence is required"))

    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate security release-gate checklist completion.")
    parser.add_argument(
        "--checklist",
        default="docs/security-release-gate.json",
        help="Path to release-gate checklist JSON file.",
    )
    parser.add_argument(
        "--max-age-days",
        type=int,
        default=120,
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

    failures = _validate_checklist(data, max_age_days=args.max_age_days, today=datetime.now(timezone.utc).date())
    if failures:
        for failure in failures:
            print(f"[FAIL] {failure.message}")
        return 1

    print(f"[OK] security release gate passed: {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
