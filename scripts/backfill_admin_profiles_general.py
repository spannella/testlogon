#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.auth.roles import AdminProfileType, Role, normalize_admin_profile, normalize_role
from app.core.aws import ddb
from app.core.settings import S


@dataclass
class BackfillStats:
    scanned: int = 0
    admin_users_seen: int = 0
    candidates: int = 0
    updated: int = 0
    skipped_already_general: int = 0
    skipped_non_admin: int = 0


@dataclass
class Candidate:
    user_sub: str
    current_admin_profile: Dict[str, Any]
    desired_admin_profile: Dict[str, Any]
    reason: str


def _users_table():
    if not S.users_table_name:
        raise RuntimeError("USERS_TABLE_NAME is not configured")
    return ddb.Table(S.users_table_name)


def _should_backfill(item: Dict[str, Any]) -> tuple[bool, str, Dict[str, Any], Dict[str, Any]]:
    role = normalize_role(item.get("role"))
    normalized = normalize_admin_profile(item.get("admin_profile"))
    current_profile = normalized.to_dict()
    desired_profile = {"type": AdminProfileType.GENERAL.value}

    if role is not Role.ADMIN:
        return False, "non_admin", current_profile, desired_profile

    if normalized.type is AdminProfileType.SCOPED:
        return False, "already_scoped", current_profile, desired_profile

    raw_profile = item.get("admin_profile")
    if isinstance(raw_profile, dict) and raw_profile.get("type") == AdminProfileType.GENERAL.value:
        return False, "already_general", current_profile, desired_profile

    return True, "missing_or_malformed_profile", current_profile, desired_profile


def run_backfill(*, scan_limit: int, dry_run: bool, report_file: Optional[str]) -> Dict[str, Any]:
    table = _users_table()
    stats = BackfillStats()
    candidates: List[Candidate] = []
    last_evaluated_key = None

    while True:
        kwargs: Dict[str, Any] = {
            "Limit": max(1, min(scan_limit, 1000)),
            "ProjectionExpression": "user_sub, #role, admin_profile",
            "ExpressionAttributeNames": {"#role": "role"},
        }
        if last_evaluated_key is not None:
            kwargs["ExclusiveStartKey"] = last_evaluated_key

        resp = table.scan(**kwargs)
        items = resp.get("Items", [])
        stats.scanned += len(items)

        for item in items:
            should_update, reason, current_profile, desired_profile = _should_backfill(item)
            if reason == "non_admin":
                stats.skipped_non_admin += 1
                continue

            stats.admin_users_seen += 1
            if not should_update:
                if reason == "already_general":
                    stats.skipped_already_general += 1
                continue

            candidate = Candidate(
                user_sub=str(item.get("user_sub") or ""),
                current_admin_profile=current_profile,
                desired_admin_profile=desired_profile,
                reason=reason,
            )
            candidates.append(candidate)
            stats.candidates += 1

            if dry_run:
                continue

            table.update_item(
                Key={"user_sub": candidate.user_sub},
                UpdateExpression="SET admin_profile=:profile, role_updated_at=:ts, role_reason=:reason",
                ConditionExpression="#role=:admin_role",
                ExpressionAttributeNames={"#role": "role"},
                ExpressionAttributeValues={
                    ":profile": desired_profile,
                    ":admin_role": Role.ADMIN.value,
                    ":ts": int(datetime.now(timezone.utc).timestamp()),
                    ":reason": "ap015_admin_profile_general_backfill",
                },
            )
            stats.updated += 1

        last_evaluated_key = resp.get("LastEvaluatedKey")
        if not last_evaluated_key:
            break

    report = {
        "dry_run": dry_run,
        "stats": asdict(stats),
        "candidates": [asdict(c) for c in candidates],
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }

    if report_file:
        with open(report_file, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, sort_keys=True)

    return report


def main() -> None:
    parser = argparse.ArgumentParser(
        description="AP-015 backfill: set admin_profile.type=general for existing admin users missing/malformed profiles.",
    )
    parser.add_argument("--scan-limit", type=int, default=500, help="DynamoDB scan page size")
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Apply writes. If omitted, script runs in dry-run mode.",
    )
    parser.add_argument("--report-file", default=None, help="Optional path to write JSON report")
    args = parser.parse_args()

    report = run_backfill(scan_limit=args.scan_limit, dry_run=not args.apply, report_file=args.report_file)
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
