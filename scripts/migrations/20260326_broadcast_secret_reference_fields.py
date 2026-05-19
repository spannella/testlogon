#!/usr/bin/env python3
from __future__ import annotations

from app.core.aws import ddb
from app.core.settings import S


DEFAULT_ROTATION = int(S.broadcast_secret_rotation_interval_seconds or 86400)


def _backfill_profiles() -> None:
    table = ddb.Table(S.broadcast_profiles_table_name)
    items = table.scan().get("Items", [])
    for item in items:
        profile_id = item.get("profile_id")
        if not profile_id:
            continue
        updates = {}
        if "drm_credentials_ref" not in item:
            updates["drm_credentials_ref"] = None
        if "drm_credentials_last_rotated_at" not in item:
            updates["drm_credentials_last_rotated_at"] = None
        if not item.get("drm_credentials_rotation_interval_seconds"):
            updates["drm_credentials_rotation_interval_seconds"] = DEFAULT_ROTATION
        if not updates:
            continue

        expr, names, values = _build_update_expression(updates)
        table.update_item(
            Key={"profile_id": profile_id},
            UpdateExpression=expr,
            ExpressionAttributeNames=names,
            ExpressionAttributeValues=values,
        )


def _backfill_sessions() -> None:
    table = ddb.Table(S.broadcast_sessions_table_name)
    items = table.scan().get("Items", [])
    for item in items:
        session_id = item.get("session_id")
        if not session_id:
            continue
        updates = {}
        if "stream_key_last_rotated_at" not in item:
            updates["stream_key_last_rotated_at"] = None
        if not item.get("stream_key_rotation_interval_seconds"):
            updates["stream_key_rotation_interval_seconds"] = DEFAULT_ROTATION
        if not updates:
            continue

        expr, names, values = _build_update_expression(updates)
        table.update_item(
            Key={"session_id": session_id},
            UpdateExpression=expr,
            ExpressionAttributeNames=names,
            ExpressionAttributeValues=values,
        )


def _build_update_expression(updates: dict) -> tuple[str, dict, dict]:
    names = {}
    values = {}
    assignments = []
    for idx, (key, val) in enumerate(updates.items(), start=1):
        nk = f"#k{idx}"
        vk = f":v{idx}"
        names[nk] = key
        values[vk] = val
        assignments.append(f"{nk} = {vk}")
    return "SET " + ", ".join(assignments), names, values


def migrate() -> None:
    _backfill_profiles()
    _backfill_sessions()


if __name__ == "__main__":
    migrate()
    print("broadcast secret reference metadata migration complete")
