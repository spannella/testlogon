from __future__ import annotations

import json
from pathlib import Path

from scripts.backfill_profile_discoverability_state import run_backfill


class _UsersTable:
    def __init__(self, users: list[dict]):
        self._users = list(users)

    def scan(self, **kwargs):
        return {"Items": list(self._users)}


class _AccountStateTable:
    def __init__(self, items: dict[str, dict]):
        self._items = dict(items)
        self.update_calls: list[dict] = []

    def get_item(self, *, Key: dict):
        user_sub = Key["user_sub"]
        item = self._items.get(user_sub)
        return {"Item": dict(item)} if item is not None else {}

    def update_item(self, **kwargs):
        self.update_calls.append(kwargs)
        user_sub = kwargs["Key"]["user_sub"]
        attrs = kwargs["ExpressionAttributeValues"]
        existing = dict(self._items.get(user_sub, {}))
        existing["user_sub"] = user_sub
        existing["discoverability_status"] = attrs[":discoverability"]
        existing["updated_at"] = attrs[":ts"]
        self._items[user_sub] = existing


def test_backfill_supports_dry_run_and_emits_machine_readable_report(tmp_path: Path) -> None:
    users = _UsersTable([{"user_sub": "u1"}, {"user_sub": "u2"}, {"user_sub": "u3"}])
    account_state = _AccountStateTable(
        {
            "u1": {"user_sub": "u1", "discoverability_status": "active"},
            "u2": {"user_sub": "u2", "status": "deactivated"},
        }
    )

    report_path = tmp_path / "backfill-report.json"
    report = run_backfill(
        scan_limit=500,
        dry_run=True,
        report_file=str(report_path),
        users_table=users,
        account_state_table=account_state,
    )

    assert report["dry_run"] is True
    assert report["stats"]["scanned_users"] == 3
    assert report["stats"]["candidates"] == 2  # u2 missing discoverability_status, u3 missing account_state row
    assert report["stats"]["updated"] == 0
    assert report["stats"]["target_state_counts"] == {"active": 2, "deactivated": 1}
    assert report["stats"]["errors"] == 0
    assert len(account_state.update_calls) == 0

    raw = json.loads(report_path.read_text(encoding="utf-8"))
    assert raw["stats"]["candidates"] == 2
    assert isinstance(raw["errors"], list)


def test_backfill_apply_is_idempotent_on_rerun() -> None:
    users = _UsersTable([{"user_sub": "u1"}, {"user_sub": "u2"}, {"user_sub": "u3"}])
    account_state = _AccountStateTable(
        {
            "u1": {"user_sub": "u1", "discoverability_status": "active"},
            "u2": {"user_sub": "u2", "status": "deactivated"},
        }
    )

    first = run_backfill(
        scan_limit=500,
        dry_run=False,
        report_file=None,
        users_table=users,
        account_state_table=account_state,
    )
    assert first["stats"]["updated"] == 2

    second = run_backfill(
        scan_limit=500,
        dry_run=False,
        report_file=None,
        users_table=users,
        account_state_table=account_state,
    )
    assert second["stats"]["updated"] == 0
    assert second["stats"]["skipped_already_initialized"] == 3
