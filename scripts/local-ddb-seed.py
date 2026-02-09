#!/usr/bin/env python3
from __future__ import annotations

import time

from app.core.aws_clients import ddb_resource
from app.core.settings import S


def _now_ts() -> int:
    return int(time.time())


def _table(ddb, name: str):
    return ddb.Table(name)


def main() -> None:
    ddb = ddb_resource()
    ts = _now_ts()
    user_sub = "dev-user"

    tables = {
        "sessions": S.ddb_sessions_table,
        "users": S.users_table_name,
        "profile": S.profile_table_name,
        "account_state": S.account_state_table_name,
        "alert_prefs": S.alert_prefs_table_name,
        "alerts": S.alerts_table_name,
    }

    if tables["sessions"]:
        _table(ddb, tables["sessions"]).put_item(
            Item={
                "user_sub": user_sub,
                "session_id": "dev-session",
                "created_at": ts,
                "updated_at": ts,
                "revoked": False,
            }
        )

    if tables["users"]:
        _table(ddb, tables["users"]).put_item(
            Item={
                "user_sub": user_sub,
                "email": "dev-user@example.com",
                "created_at": ts,
                "updated_at": ts,
            }
        )

    if tables["profile"]:
        _table(ddb, tables["profile"]).put_item(
            Item={
                "user_sub": user_sub,
                "profile": {"display_name": "Dev User", "bio": "Local seed user"},
                "created_at": ts,
                "updated_at": ts,
            }
        )

    if tables["account_state"]:
        _table(ddb, tables["account_state"]).put_item(
            Item={
                "user_sub": user_sub,
                "status": "active",
                "reason": "seed",
                "requested_by": user_sub,
                "created_at": ts,
            }
        )

    if tables["alert_prefs"]:
        _table(ddb, tables["alert_prefs"]).put_item(
            Item={
                "user_sub": user_sub,
                "email_event_types": [],
                "sms_event_types": [],
                "toast_event_types": [],
                "push_event_types": [],
                "updated_at": ts,
            }
        )

    if tables["alerts"]:
        _table(ddb, tables["alerts"]).put_item(
            Item={
                "user_sub": user_sub,
                "alert_id": f"{ts:010d}#seed",
                "event": "seed",
                "title": "Local seed alert",
                "created_at": ts,
            }
        )

    print("Seeded minimal local data.")


if __name__ == "__main__":
    main()
