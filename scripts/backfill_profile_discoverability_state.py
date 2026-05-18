#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.core.aws import ddb
from app.core.settings import S
from app.services.profile_discoverability import (
    DISCOVERABILITY_FIELD,
    DiscoverabilityState,
    resolve_discoverability_state,
)


@dataclass
class BackfillStats:
    scanned_users: int = 0
    candidates: int = 0
    updated: int = 0
    skipped_already_initialized: int = 0
    skipped_missing_user_sub: int = 0
    errors: int = 0
    target_state_counts: Dict[str, int] = field(default_factory=dict)


@dataclass
class BackfillError:
    user_sub: str
    error: str


@dataclass
class Candidate:
    user_sub: str
    current_discoverability_status: Optional[str]
    desired_discoverability_status: str
    reason: str


def _users_table() -> Any:
    if not S.users_table_name:
        raise RuntimeError("USERS_TABLE_NAME is not configured")
    return ddb.Table(S.users_table_name)


def _account_state_table() -> Any:
    if not S.account_state_table_name:
        raise RuntimeError("ACCOUNT_STATE_TABLE_NAME is not configured")
    return ddb.Table(S.account_state_table_name)


def _needs_update(account_item: Dict[str, Any], desired: DiscoverabilityState) -> tuple[bool, Optional[str], str]:
    raw = account_item.get(DISCOVERABILITY_FIELD)
    if raw is None:
        return True, None, "missing_discoverability_status"

    current = str(raw).strip().lower()
    if current != desired.value:
        return True, current, "stale_or_malformed_discoverability_status"

    return False, current, "already_initialized"


def run_backfill(
    *,
    scan_limit: int,
    dry_run: bool,
    report_file: Optional[str],
    users_table: Any = None,
    account_state_table: Any = None,
) -> Dict[str, Any]:
    users = users_table or _users_table()
    account_state = account_state_table or _account_state_table()

    stats = BackfillStats()
    target_state_counts: Counter[str] = Counter()
    candidates: List[Candidate] = []
    errors: List[BackfillError] = []
    last_evaluated_key: Optional[Dict[str, Any]] = None

    while True:
        kwargs: Dict[str, Any] = {
            "Limit": max(1, min(scan_limit, 1000)),
            "ProjectionExpression": "user_sub",
        }
        if last_evaluated_key is not None:
            kwargs["ExclusiveStartKey"] = last_evaluated_key

        resp = users.scan(**kwargs)
        items = list(resp.get("Items", []))
        stats.scanned_users += len(items)

        for user in items:
            user_sub = str(user.get("user_sub") or "").strip()
            if not user_sub:
                stats.skipped_missing_user_sub += 1
                continue

            account_item = account_state.get_item(Key={"user_sub": user_sub}).get("Item") or {}
            desired = resolve_discoverability_state(account_item)
            should_update, current_state, reason = _needs_update(account_item, desired)
            target_state_counts[desired.value] += 1

            if not should_update:
                stats.skipped_already_initialized += 1
                continue

            candidate = Candidate(
                user_sub=user_sub,
                current_discoverability_status=current_state,
                desired_discoverability_status=desired.value,
                reason=reason,
            )
            candidates.append(candidate)
            stats.candidates += 1

            if dry_run:
                continue

            try:
                account_state.update_item(
                    Key={"user_sub": user_sub},
                    UpdateExpression="SET #discoverability=:discoverability, updated_at=:ts",
                    ExpressionAttributeNames={"#discoverability": DISCOVERABILITY_FIELD},
                    ExpressionAttributeValues={
                        ":discoverability": desired.value,
                        ":ts": int(datetime.now(timezone.utc).timestamp()),
                    },
                )
                stats.updated += 1
            except Exception as exc:  # pragma: no cover - defensive for operational script
                stats.errors += 1
                errors.append(BackfillError(user_sub=user_sub, error=str(exc)))

        last_evaluated_key = resp.get("LastEvaluatedKey")
        if not last_evaluated_key:
            break

    stats.target_state_counts = dict(sorted(target_state_counts.items()))

    report = {
        "dry_run": dry_run,
        "stats": asdict(stats),
        "candidates": [asdict(c) for c in candidates],
        "errors": [asdict(e) for e in errors],
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }

    if report_file:
        with open(report_file, "w", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2, sort_keys=True)

    return report


def main() -> None:
    parser = argparse.ArgumentParser(
        description="UPR-003 backfill: initialize discoverability_status for existing account_state records.",
    )
    parser.add_argument("--scan-limit", type=int, default=500, help="DynamoDB scan page size")
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Apply writes. If omitted, script runs in dry-run mode.",
    )
    parser.add_argument("--report-file", default=None, help="Optional path to write JSON report")
    args = parser.parse_args()

    report = run_backfill(
        scan_limit=args.scan_limit,
        dry_run=not args.apply,
        report_file=args.report_file,
    )
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
