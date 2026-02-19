#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class GateFailure:
    message: str


def _load_checklist(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def _validate_checklist(data: dict[str, Any]) -> list[GateFailure]:
    failures: list[GateFailure] = []

    required_tickets = data.get("required_tickets")
    if not isinstance(required_tickets, list) or not required_tickets:
        failures.append(GateFailure("required_tickets must be a non-empty array"))
    else:
        for t in required_tickets:
            ticket_id = t.get("id", "<unknown>")
            if str(t.get("status", "")).lower() != "closed":
                failures.append(GateFailure(f"ticket {ticket_id} is not closed"))

    dod = data.get("definition_of_done")
    if not isinstance(dod, list) or not dod:
        failures.append(GateFailure("definition_of_done must be a non-empty array"))
    else:
        for entry in dod:
            criterion = entry.get("criterion", "<unknown>")
            if entry.get("passed") is not True:
                failures.append(GateFailure(f"DoD criterion not passed: {criterion}"))

    gate = data.get("release_gate") or {}
    if gate.get("approved") is not True:
        failures.append(GateFailure("release_gate.approved must be true"))
    if not str(gate.get("approver", "")).strip():
        failures.append(GateFailure("release_gate.approver is required"))
    if not str(gate.get("evidence_bundle", "")).strip():
        failures.append(GateFailure("release_gate.evidence_bundle is required"))

    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate metering/billing DoD release checklist.")
    parser.add_argument(
        "--checklist",
        default="docs/metering-billing-release-gate.json",
        help="Path to metering/billing release gate checklist JSON file.",
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

    failures = _validate_checklist(data)
    if failures:
        for failure in failures:
            print(f"[FAIL] {failure.message}")
        return 1

    print(f"[OK] metering/billing release gate passed: {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
