from __future__ import annotations

import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from app.core.settings import S
from app.services.calendar_integrations.logging_safety import redacted_log_payload
from app.services.calendar_integrations.secret_adapter import get_calendar_secret_adapter

logger = logging.getLogger(__name__)


def _ddb_table(name: str):
    from app.core.aws import ddb

    return ddb.Table(name)


def _connections_table():
    return _ddb_table(S.calendar_connections_table_name)

def _external_calendars_table():
    return _ddb_table(S.external_calendars_table_name)

def _sync_runs_table():
    return _ddb_table(S.calendar_sync_runs_table_name)

def _external_event_links_table():
    return _ddb_table(S.external_event_links_table_name)

def _external_calendar_item_key(*, connection_id: str, external_calendar_id: str) -> str:
    return f"{connection_id}#calendar#{external_calendar_id.strip()}"

def _connection_uid_key(*, connection_id: str, external_calendar_id: str, remote_uid: str) -> str:
    return f"{connection_id}#calendar#{external_calendar_id.strip()}#uid#{remote_uid.strip()}"

def _connection_internal_event_key(*, connection_id: str, external_calendar_id: str, internal_event_id: str) -> str:
    return f"{connection_id}#calendar#{external_calendar_id.strip()}#event#{internal_event_id.strip()}"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _connection_id(user_sub: str) -> str:
    normalized = (user_sub or "").strip()
    if not normalized:
        raise ValueError("user_sub is required")
    return f"apple_caldav#user#{normalized}"


def _sanitize_username(username: str) -> str:
    normalized = (username or "").strip()
    if not normalized:
        raise ValueError("username is required")
    return normalized


def _sanitize_secret(secret: str) -> str:
    normalized = (secret or "").strip()
    if not normalized:
        raise ValueError("app-specific password is required")
    return normalized


def _redacted_connection(item: dict[str, Any]) -> dict[str, Any]:
    credential_ref = str(item.get("credential_ref") or "")
    return {
        "connection_id": item["connection_id"],
        "provider": item["provider"],
        "user_sub": item["user_sub"],
        "status": item["status"],
        "credential_ref": credential_ref,
        "credential_validation_status": item.get("credential_validation_status", "unknown"),
        "credential_last_validated_at": item.get("credential_last_validated_at"),
        "credential_rotated_at": item.get("credential_rotated_at"),
        "created_at": item["created_at"],
        "updated_at": item["updated_at"],
        "has_secret": bool(credential_ref),
    }


def upsert_apple_caldav_credential(
    *,
    user_sub: str,
    username: str,
    app_specific_password: str,
    credential_validation_status: str = "pending",
) -> dict[str, Any]:
    connection_id = _connection_id(user_sub)
    username_norm = _sanitize_username(username)
    secret_norm = _sanitize_secret(app_specific_password)
    now = _now_iso()

    table = _connections_table()
    existing = table.get_item(Key={"connection_id": connection_id}).get("Item")
    created_at = now if not existing else str(existing.get("created_at") or now)

    adapter = get_calendar_secret_adapter()
    secret_write = adapter.put_secret(
        provider="apple_caldav",
        credential_ref=str(existing.get("credential_ref") or "").strip() if existing else None,
        secret_payload={
            "username": username_norm,
            "app_specific_password": secret_norm,
        },
        tags={
            "integration": "calendar",
            "provider": "apple_caldav",
            "user_sub": (user_sub or "").strip(),
        },
    )

    item = {
        "connection_id": connection_id,
        "entity_type": "calendar_connection",
        "provider": "apple_caldav",
        "user_sub": (user_sub or "").strip(),
        "user_provider_key": f"USER#{(user_sub or '').strip()}#PROVIDER#apple_caldav",
        "status": "connected",
        "status_key": "STATUS#connected",
        "credential_ref": secret_write["credential_ref"],
        "credential_validation_status": (credential_validation_status or "pending").strip().lower(),
        "credential_last_validated_at": now if credential_validation_status == "valid" else existing.get("credential_last_validated_at") if existing else None,
        "credential_rotated_at": now if existing else None,
        "created_at": created_at,
        "updated_at": now,
    }

    table.put_item(Item=item)
    logger.info(
        "calendar credential upserted",
        extra={
            "calendar": redacted_log_payload(
                connection_id=connection_id,
                provider="apple_caldav",
                user_sub=(user_sub or "").strip(),
                credential_ref=item["credential_ref"],
                credential_validation_status=item["credential_validation_status"],
                app_specific_password=app_specific_password,
                auth_header="Basic ...",
            )
        },
    )
    return _redacted_connection(item)


def get_apple_caldav_connection(*, user_sub: str, include_secret: bool = False) -> dict[str, Any]:
    connection_id = _connection_id(user_sub)
    return get_apple_caldav_connection_by_connection_id(connection_id=connection_id, include_secret=include_secret)


def get_apple_caldav_connection_by_connection_id(*, connection_id: str, include_secret: bool = False) -> dict[str, Any]:
    normalized_connection_id = str(connection_id or "").strip()
    if not normalized_connection_id:
        raise ValueError("connection_id is required")
    table = _connections_table()
    item = table.get_item(Key={"connection_id": normalized_connection_id}).get("Item")
    if not item or item.get("entity_type") != "calendar_connection" or item.get("provider") != "apple_caldav":
        raise KeyError("apple caldav connection not found")

    out = _redacted_connection(item)
    if include_secret:
        secret = get_calendar_secret_adapter().get_secret(credential_ref=str(item.get("credential_ref") or ""))
        if not secret:
            raise KeyError("apple caldav credential secret not found")
        payload = dict(secret.get("secret_payload") or {})
        out["username"] = str(payload.get("username") or "")
        out["app_specific_password"] = str(payload.get("app_specific_password") or "")
    logger.info(
        "calendar credential fetched",
        extra={
            "calendar": redacted_log_payload(
                connection_id=normalized_connection_id,
                include_secret=include_secret,
                credential_ref=str(item.get("credential_ref") or ""),
                app_specific_password=out.get("app_specific_password"),
            )
        },
    )
    return out


def rotate_apple_caldav_credential(
    *,
    user_sub: str,
    username: str,
    app_specific_password: str,
    credential_validation_status: str = "pending",
) -> dict[str, Any]:
    return upsert_apple_caldav_credential(
        user_sub=user_sub,
        username=username,
        app_specific_password=app_specific_password,
        credential_validation_status=credential_validation_status,
    )


def delete_apple_caldav_credential(*, user_sub: str) -> dict[str, bool]:
    connection_id = _connection_id(user_sub)
    table = _connections_table()
    existing = table.get_item(Key={"connection_id": connection_id}).get("Item")
    if not existing:
        return {"deleted": False}

    credential_ref = str(existing.get("credential_ref") or "").strip()
    if credential_ref:
        get_calendar_secret_adapter().delete_secret(credential_ref=credential_ref)
    table.delete_item(Key={"connection_id": connection_id})
    logger.info(
        "calendar credential deleted",
        extra={
            "calendar": redacted_log_payload(
                connection_id=connection_id,
                credential_ref=credential_ref,
                token="deleted",
            )
        },
    )
    return {"deleted": True}


def disconnect_apple_caldav_credential(*, user_sub: str) -> dict[str, Any]:
    connection_id = _connection_id(user_sub)
    table = _connections_table()
    now = _now_iso()
    existing = table.get_item(Key={"connection_id": connection_id}).get("Item")
    if not existing:
        return {
            "connection_id": connection_id,
            "provider": "apple_caldav",
            "user_sub": user_sub,
            "status": "disconnected",
            "credential_ref": "",
            "credential_validation_status": "disconnected",
            "credential_last_validated_at": None,
            "credential_rotated_at": None,
            "created_at": now,
            "updated_at": now,
            "has_secret": False,
        }

    credential_ref = str(existing.get("credential_ref") or "").strip()
    if credential_ref:
        get_calendar_secret_adapter().delete_secret(credential_ref=credential_ref)

    disconnected = dict(existing)
    disconnected["status"] = "disconnected"
    disconnected["status_key"] = "STATUS#disconnected"
    disconnected["credential_ref"] = ""
    disconnected["credential_validation_status"] = "disconnected"
    disconnected["updated_at"] = now
    disconnected["disconnected_at"] = now
    disconnected["last_error"] = "integration_disconnected"
    table.put_item(Item=disconnected)

    logger.info(
        "calendar credential disconnected",
        extra={
            "calendar": redacted_log_payload(
                connection_id=connection_id,
                previous_credential_ref=credential_ref,
                status="disconnected",
                token="deleted",
            )
        },
    )
    return _redacted_connection(disconnected)


def assert_apple_caldav_connection_active(*, connection_id: str) -> None:
    connection = _connections_table().get_item(Key={"connection_id": connection_id}).get("Item")
    if not connection:
        raise ValueError("calendar connection not found")
    if str(connection.get("status") or "").strip().lower() != "connected":
        raise ValueError("calendar connection is disconnected")
    if not str(connection.get("credential_ref") or "").strip():
        raise ValueError("calendar connection has no active credential reference")


def get_apple_caldav_status(*, user_sub: str) -> dict[str, Any]:
    connection_id = _connection_id(user_sub)
    connection = _connections_table().get_item(Key={"connection_id": connection_id}).get("Item")
    if not connection:
        return {
            "provider": "apple_caldav",
            "connection_state": "disconnected",
            "is_connected": False,
            "connection_id": None,
            "credential_validation_status": None,
            "last_successful_sync_at": None,
            "last_error_snapshot": None,
            "selected_calendar_count": 0,
            "conflict_count": 0,
            "recent_conflicts": [],
            "updated_at": None,
        }

    selected_calendar_count = 0
    calendars_table = _external_calendars_table()
    resp = calendars_table.scan().get("Items", [])
    selected_calendar_count = len(
        [
            it
            for it in resp
            if str(it.get("connection_id") or "") == connection_id and bool(it.get("sync_enabled", True))
        ]
    )

    runs = _sync_runs_table().scan().get("Items", [])
    runs_for_connection = [it for it in runs if str(it.get("connection_id") or "") == connection_id]
    runs_for_connection.sort(key=lambda item: str(item.get("started_at") or ""), reverse=True)

    last_successful_sync_at = None
    last_error_snapshot = None
    for run in runs_for_connection:
        status_key = str(run.get("status_key") or "").lower()
        status = str(run.get("status") or "").lower()
        if (status == "success") or ("success" in status_key):
            last_successful_sync_at = str(run.get("finished_at") or run.get("started_at") or "")
            break

    if runs_for_connection:
        latest = runs_for_connection[0]
        latest_status = str(latest.get("status") or latest.get("status_key") or "").lower()
        if any(marker in latest_status for marker in ("fail", "error", "degraded")):
            last_error_snapshot = {
                "status": latest.get("status") or latest.get("status_key"),
                "error": latest.get("error") or latest.get("last_error"),
                "started_at": latest.get("started_at"),
                "finished_at": latest.get("finished_at"),
            }

    if last_error_snapshot is None:
        dead_letters = list_apple_push_dead_letters(connection_id=connection_id)
        if dead_letters:
            latest_dead_letter = dead_letters[0]
            last_error_snapshot = {
                "status": "dead_letter",
                "error": latest_dead_letter.get("last_error"),
                "outbox_id": latest_dead_letter.get("outbox_id"),
                "operation": latest_dead_letter.get("operation"),
                "updated_at": latest_dead_letter.get("updated_at"),
            }

    raw_state = str(connection.get("status") or "connected").strip().lower()
    if raw_state not in {"connected", "degraded", "disconnected"}:
        raw_state = "connected"
    if raw_state == "connected" and last_error_snapshot and not last_successful_sync_at:
        raw_state = "degraded"

    conflict_audits = list_apple_conflict_audits(connection_id=connection_id, limit=200)
    recent_conflicts = [_serialize_conflict_for_ui(it) for it in conflict_audits[:10]]

    return {
        "provider": "apple_caldav",
        "connection_state": raw_state,
        "is_connected": raw_state != "disconnected",
        "connection_id": connection_id,
        "credential_validation_status": connection.get("credential_validation_status"),
        "last_successful_sync_at": last_successful_sync_at or None,
        "last_error_snapshot": last_error_snapshot,
        "selected_calendar_count": selected_calendar_count,
        "conflict_count": len(conflict_audits),
        "recent_conflicts": recent_conflicts,
        "updated_at": connection.get("updated_at"),
    }


def _serialize_conflict_for_ui(audit: dict[str, Any]) -> dict[str, Any]:
    details = dict(audit.get("details") or {})
    operation = str(details.get("operation") or "").strip().lower() or "update"
    operation_label = "updated" if operation == "update" else "deleted" if operation == "delete" else "changed"
    event_ref = str(audit.get("internal_event_id") or audit.get("remote_uid") or "").strip() or "Unknown event"
    resolution = str(audit.get("resolution") or "").strip().lower()
    if resolution == "remote_wins_etag_conflict":
        message = f"We found overlapping edits for event {event_ref}. We kept the version from Apple Calendar."
        guidance = "Review the event details in Apple Calendar and re-apply changes here if needed."
    else:
        message = f"Event {event_ref} had a sync conflict."
        guidance = "Review the event details and retry your changes if something looks off."
    return {
        "audit_id": audit.get("audit_id"),
        "event_ref": event_ref,
        "calendar_id": audit.get("external_calendar_id"),
        "operation": operation_label,
        "message": message,
        "guidance": guidance,
        "occurred_at": audit.get("updated_at") or audit.get("created_at"),
    }


def list_apple_caldav_calendars(*, user_sub: str) -> list[dict[str, Any]]:
    connection = get_apple_caldav_connection(user_sub=user_sub, include_secret=True)
    from app.services.calendar_integrations.registry import get_provider_services

    provider = get_provider_services("apple_caldav")
    if provider is None:
        return []

    discovered = provider.connection.discover_calendars(
        username=str(connection.get("username") or ""),
        secret=str(connection.get("app_specific_password") or ""),
    )
    connection_id = str(connection.get("connection_id") or "")

    persisted_items = _external_calendars_table().scan().get("Items", [])
    persisted_by_external_id: dict[str, dict[str, Any]] = {}
    for item in persisted_items:
        if str(item.get("connection_id") or "") != connection_id:
            continue
        external_id = str(item.get("external_calendar_raw_id") or item.get("external_calendar_id") or "").strip()
        if external_id:
            persisted_by_external_id[external_id] = item

    out: list[dict[str, Any]] = []
    for raw in discovered:
        external_id = str(raw.get("calendar_id") or raw.get("external_calendar_id") or "").strip()
        if not external_id:
            continue
        persisted = persisted_by_external_id.get(external_id, {})
        out.append(
            {
                "external_calendar_id": external_id,
                "calendar_url": str(raw.get("calendar_url") or ""),
                "display_name": str(raw.get("display_name") or external_id),
                "sync_enabled": bool(persisted.get("sync_enabled", False)),
                "sync_direction": str(persisted.get("sync_direction") or "two_way"),
                "timezone": persisted.get("timezone"),
            }
        )
    return out


def select_apple_caldav_calendars(*, user_sub: str, calendars: list[dict[str, Any]]) -> list[dict[str, Any]]:
    connection = get_apple_caldav_connection(user_sub=user_sub, include_secret=False)
    connection_id = str(connection.get("connection_id") or "")
    now = _now_iso()
    table = _external_calendars_table()

    for selection in calendars:
        external_id = str(selection.get("external_calendar_id") or "").strip()
        if not external_id:
            continue
        key = _external_calendar_item_key(connection_id=connection_id, external_calendar_id=external_id)
        existing = table.get_item(Key={"external_calendar_id": key}).get("Item")
        created_at = now if not existing else str(existing.get("created_at") or now)
        item = {
            "external_calendar_id": key,
            "connection_id": connection_id,
            "external_calendar_raw_id": external_id,
            "calendar_url": str(selection.get("calendar_url") or existing.get("calendar_url") or "").strip() if existing else str(selection.get("calendar_url") or "").strip(),
            "sync_enabled": bool(selection.get("sync_enabled", True)),
            "sync_direction": str(selection.get("sync_direction") or "two_way"),
            "timezone": selection.get("timezone"),
            "updated_at": now,
            "created_at": created_at,
        }
        table.put_item(Item=item)

    return list_apple_caldav_calendars(user_sub=user_sub)


def enqueue_apple_caldav_initial_import(
    *,
    user_sub: str,
    external_calendar_ids: list[str] | None = None,
    lookback_days: int | None = None,
    lookahead_days: int | None = None,
) -> list[dict[str, Any]]:
    connection = get_apple_caldav_connection(user_sub=user_sub, include_secret=False)
    connection_id = str(connection.get("connection_id") or "")
    if not connection_id:
        return []

    selected_calendar_rows = _external_calendars_table().scan().get("Items", [])
    enabled_calendar_ids = [
        str(row.get("external_calendar_raw_id") or "").strip()
        for row in selected_calendar_rows
        if str(row.get("connection_id") or "") == connection_id
        and bool(row.get("sync_enabled", False))
        and str(row.get("external_calendar_raw_id") or "").strip()
    ]
    enabled_set = set(enabled_calendar_ids)
    requested_ids = {
        str(external_calendar_id or "").strip()
        for external_calendar_id in (external_calendar_ids or [])
        if str(external_calendar_id or "").strip()
    }
    target_ids = sorted(enabled_set if not requested_ids else enabled_set.intersection(requested_ids))

    now = datetime.now(timezone.utc)
    now_iso = now.isoformat()
    history_lookback = max(
        int(lookback_days if lookback_days is not None else S.apple_caldav_initial_import_lookback_days),
        0,
    )
    history_lookahead = max(
        int(lookahead_days if lookahead_days is not None else S.apple_caldav_initial_import_lookahead_days),
        0,
    )
    history_start = (now - timedelta(days=history_lookback)).isoformat()
    history_end = (now + timedelta(days=history_lookahead)).isoformat()

    runs_table = _sync_runs_table()
    run_rows: list[dict[str, Any]] = []
    for external_calendar_id in target_ids:
        run_item = {
            "run_id": f"run_{uuid.uuid4().hex}",
            "connection_id": connection_id,
            "provider": "apple_caldav",
            "run_type": "initial_import",
            "status": "queued",
            "status_key": "STATUS#queued",
            "external_calendar_id": external_calendar_id,
            "historical_window_start": history_start,
            "historical_window_end": history_end,
            "started_at": now_iso,
            "created_at": now_iso,
            "updated_at": now_iso,
        }
        runs_table.put_item(Item=run_item)
        run_rows.append(run_item)
    return run_rows


def upsert_apple_caldav_event_link(
    *,
    connection_id: str,
    external_calendar_id: str,
    remote_uid: str,
    internal_event_id: str,
    run_id: str,
    resource_url: str | None = None,
    etag: str | None = None,
) -> tuple[dict[str, Any], bool]:
    normalized_calendar = str(external_calendar_id or "").strip()
    normalized_uid = str(remote_uid or "").strip()
    normalized_internal_event_id = str(internal_event_id or "").strip()
    if not normalized_calendar or not normalized_uid or not normalized_internal_event_id:
        raise ValueError("connection_id, external_calendar_id, remote_uid, and internal_event_id are required")

    table = _external_event_links_table()
    key = _connection_uid_key(
        connection_id=connection_id,
        external_calendar_id=normalized_calendar,
        remote_uid=normalized_uid,
    )
    existing = table.get_item(Key={"connection_uid_key": key}).get("Item")
    now = _now_iso()
    item = {
        "connection_uid_key": key,
        "connection_internal_event_key": _connection_internal_event_key(
            connection_id=connection_id,
            external_calendar_id=normalized_calendar,
            internal_event_id=normalized_internal_event_id,
        ),
        "connection_id": connection_id,
        "external_calendar_id": normalized_calendar,
        "remote_uid": normalized_uid,
        "internal_event_id": normalized_internal_event_id,
        "resource_url": resource_url if resource_url is not None else existing.get("resource_url") if existing else None,
        "etag": etag if etag is not None else existing.get("etag") if existing else None,
        "last_seen_run_id": str(run_id or ""),
        "updated_at": now,
        "created_at": now if not existing else str(existing.get("created_at") or now),
    }
    table.put_item(Item=item)
    return item, bool(existing)


def register_apple_caldav_imported_links(
    *,
    run_id: str,
    connection_id: str,
    external_calendar_id: str,
    imported_events: list[dict[str, Any]],
) -> dict[str, int]:
    created = 0
    updated = 0
    for event in imported_events:
        _, existed = upsert_apple_caldav_event_link(
            connection_id=connection_id,
            external_calendar_id=external_calendar_id,
            remote_uid=str(event.get("remote_uid") or event.get("uid") or ""),
            internal_event_id=str(event.get("internal_event_id") or event.get("event_id") or ""),
            run_id=run_id,
            resource_url=event.get("resource_url"),
            etag=event.get("etag"),
        )
        if existed:
            updated += 1
        else:
            created += 1
    return {"created": created, "updated": updated}


def get_apple_caldav_calendar_sync_state(*, connection_id: str, external_calendar_id: str) -> dict[str, Any]:
    key = _external_calendar_item_key(connection_id=connection_id, external_calendar_id=external_calendar_id)
    row = _external_calendars_table().get_item(Key={"external_calendar_id": key}).get("Item") or {}
    return {
        "sync_token": row.get("sync_token"),
        "ctag": row.get("ctag"),
        "last_synced_at": row.get("last_synced_at"),
        "calendar_url": row.get("calendar_url"),
    }


def get_apple_caldav_event_link(*, connection_id: str, external_calendar_id: str, remote_uid: str) -> dict[str, Any] | None:
    key = _connection_uid_key(connection_id=connection_id, external_calendar_id=external_calendar_id, remote_uid=remote_uid)
    return _external_event_links_table().get_item(Key={"connection_uid_key": key}).get("Item")


def get_apple_caldav_event_link_by_internal_event(
    *,
    connection_id: str,
    external_calendar_id: str,
    internal_event_id: str,
) -> dict[str, Any] | None:
    normalized_internal_event_id = str(internal_event_id or "").strip()
    if not normalized_internal_event_id:
        return None

    key = _connection_internal_event_key(
        connection_id=connection_id,
        external_calendar_id=external_calendar_id,
        internal_event_id=normalized_internal_event_id,
    )
    direct = _external_event_links_table().get_item(Key={"connection_uid_key": key}).get("Item")
    if direct:
        return direct

    # Backward-compatibility path for rows created before
    # `connection_internal_event_key` was introduced.
    rows = _external_event_links_table().scan().get("Items", [])
    for row in rows:
        if str(row.get("connection_id") or "") != connection_id:
            continue
        if str(row.get("external_calendar_id") or "") != external_calendar_id:
            continue
        if str(row.get("internal_event_id") or "").strip() == normalized_internal_event_id:
            return row
    return None


def get_apple_caldav_event_link_by_resource_url(
    *,
    connection_id: str,
    external_calendar_id: str,
    resource_url: str,
) -> dict[str, Any] | None:
    target_url = str(resource_url or "").strip()
    if not target_url:
        return None
    rows = _external_event_links_table().scan().get("Items", [])
    for row in rows:
        if str(row.get("connection_id") or "") != connection_id:
            continue
        if str(row.get("external_calendar_id") or "") != external_calendar_id:
            continue
        if str(row.get("resource_url") or "").strip() == target_url:
            return row
    return None


def mark_apple_caldav_event_link_deleted(
    *,
    connection_id: str,
    external_calendar_id: str,
    remote_uid: str,
    run_id: str,
) -> bool:
    existing = get_apple_caldav_event_link(
        connection_id=connection_id,
        external_calendar_id=external_calendar_id,
        remote_uid=remote_uid,
    )
    if not existing:
        return False
    now = _now_iso()
    item = dict(existing)
    item["sync_state"] = "deleted"
    item["last_seen_run_id"] = str(run_id or "")
    item["deleted_at"] = now
    item["updated_at"] = now
    _external_event_links_table().put_item(Item=item)
    return True


def record_apple_caldav_sync_run_result(
    *,
    run_id: str,
    connection_id: str,
    external_calendar_id: str,
    status: str,
    sync_token: str | None = None,
    ctag: str | None = None,
    started_at: str | None = None,
    finished_at: str | None = None,
    error: str | None = None,
) -> dict[str, Any]:
    now = _now_iso()
    normalized_status = str(status or "unknown").strip().lower() or "unknown"
    normalized_calendar_id = str(external_calendar_id or "").strip()
    runs_table = _sync_runs_table()

    existing_run = runs_table.get_item(Key={"run_id": run_id}).get("Item")
    created_at = now if not existing_run else str(existing_run.get("created_at") or now)
    started_at_value = str(started_at or existing_run.get("started_at") or now) if existing_run else str(started_at or now)
    finished_at_value = str(finished_at or now)

    run_item = {
        "run_id": run_id,
        "connection_id": connection_id,
        "provider": "apple_caldav",
        "external_calendar_id": normalized_calendar_id,
        "run_type": str(existing_run.get("run_type") or "incremental_pull") if existing_run else "incremental_pull",
        "status": normalized_status,
        "status_key": f"STATUS#{normalized_status}",
        "started_at": started_at_value,
        "finished_at": finished_at_value,
        "error": error,
        "created_at": created_at,
        "updated_at": now,
    }
    runs_table.put_item(Item=run_item)

    if normalized_status == "success" and normalized_calendar_id:
        calendars_table = _external_calendars_table()
        calendar_key = _external_calendar_item_key(
            connection_id=connection_id,
            external_calendar_id=normalized_calendar_id,
        )
        existing_calendar = calendars_table.get_item(Key={"external_calendar_id": calendar_key}).get("Item")
        created_calendar_at = now if not existing_calendar else str(existing_calendar.get("created_at") or now)
        calendar_row = {
            "external_calendar_id": calendar_key,
            "connection_id": connection_id,
            "external_calendar_raw_id": normalized_calendar_id,
            "sync_enabled": bool(existing_calendar.get("sync_enabled", True)) if existing_calendar else True,
            "sync_direction": str(existing_calendar.get("sync_direction") or "two_way") if existing_calendar else "two_way",
            "timezone": existing_calendar.get("timezone") if existing_calendar else None,
            "sync_token": sync_token if sync_token is not None else existing_calendar.get("sync_token") if existing_calendar else None,
            "ctag": ctag if ctag is not None else existing_calendar.get("ctag") if existing_calendar else None,
            "last_synced_at": finished_at_value,
            "created_at": created_calendar_at,
            "updated_at": now,
        }
        calendars_table.put_item(Item=calendar_row)
    return run_item


def list_connected_apple_caldav_connections() -> list[str]:
    rows = _connections_table().scan().get("Items", [])
    out: list[str] = []
    for row in rows:
        if str(row.get("provider") or "") != "apple_caldav":
            continue
        if str(row.get("status") or "").strip().lower() != "connected":
            continue
        connection_id = str(row.get("connection_id") or "").strip()
        if connection_id:
            out.append(connection_id)
    return out


def list_enabled_apple_caldav_external_calendar_ids(*, connection_id: str) -> list[str]:
    rows = _external_calendars_table().scan().get("Items", [])
    out: list[str] = []
    for row in rows:
        if str(row.get("connection_id") or "") != connection_id:
            continue
        if not bool(row.get("sync_enabled", False)):
            continue
        raw_id = str(row.get("external_calendar_raw_id") or "").strip()
        if raw_id:
            out.append(raw_id)
    return sorted(set(out))


def acquire_apple_caldav_pull_lock(*, connection_id: str, lease_seconds: int = 900) -> bool:
    run_id = f"lock#{connection_id}"
    now = datetime.now(timezone.utc)
    now_iso = now.isoformat()
    existing = _sync_runs_table().get_item(Key={"run_id": run_id}).get("Item")
    if existing:
        existing_expires = str(existing.get("lock_expires_at") or "").strip()
        if existing_expires:
            try:
                expires_dt = datetime.fromisoformat(existing_expires.replace("Z", "+00:00"))
            except ValueError:
                expires_dt = None
            if expires_dt and expires_dt > now:
                return False

    item = {
        "run_id": run_id,
        "connection_id": connection_id,
        "provider": "apple_caldav",
        "run_type": "pull_lock",
        "status": "running",
        "status_key": "STATUS#running",
        "started_at": now_iso,
        "created_at": now_iso if not existing else str(existing.get("created_at") or now_iso),
        "updated_at": now_iso,
        "lock_expires_at": (now + timedelta(seconds=max(int(lease_seconds), 30))).isoformat(),
    }
    _sync_runs_table().put_item(Item=item)
    return True


def release_apple_caldav_pull_lock(*, connection_id: str) -> None:
    run_id = f"lock#{connection_id}"
    row = _sync_runs_table().get_item(Key={"run_id": run_id}).get("Item")
    if not row:
        return
    updated = dict(row)
    updated["status"] = "released"
    updated["status_key"] = "STATUS#released"
    updated["updated_at"] = _now_iso()
    updated["lock_expires_at"] = _now_iso()
    _sync_runs_table().put_item(Item=updated)


def should_run_apple_caldav_pull(*, connection_id: str, poll_interval_seconds: int, now: datetime | None = None) -> bool:
    current = now or datetime.now(timezone.utc)
    runs = _sync_runs_table().scan().get("Items", [])
    started_candidates: list[datetime] = []
    for row in runs:
        if str(row.get("connection_id") or "") != connection_id:
            continue
        if str(row.get("run_type") or "") != "incremental_pull":
            continue
        started_at = str(row.get("started_at") or "").strip()
        if not started_at:
            continue
        try:
            started_candidates.append(datetime.fromisoformat(started_at.replace("Z", "+00:00")))
        except ValueError:
            continue
    if not started_candidates:
        return True
    latest = max(started_candidates)
    return (current - latest).total_seconds() >= max(int(poll_interval_seconds), 1)


def enqueue_apple_push_outbox(
    *,
    connection_id: str,
    external_calendar_id: str,
    operation: str,
    payload: dict[str, Any],
    max_attempts: int = 5,
) -> dict[str, Any]:
    now = _now_iso()
    outbox_id = f"outbox_{uuid.uuid4().hex}"
    item = {
        "run_id": f"outbox#{outbox_id}",
        "outbox_id": outbox_id,
        "connection_id": connection_id,
        "provider": "apple_caldav",
        "run_type": "push_outbox",
        "status": "pending",
        "status_key": "STATUS#pending",
        "external_calendar_id": external_calendar_id,
        "operation": str(operation or "upsert").strip().lower(),
        "payload": dict(payload or {}),
        "attempts": 0,
        "max_attempts": max(int(max_attempts), 1),
        "next_attempt_at": now,
        "last_error": None,
        "dead_letter": False,
        "created_at": now,
        "updated_at": now,
    }
    _sync_runs_table().put_item(Item=item)
    return item


def list_due_apple_push_outbox(*, now: datetime | None = None, limit: int = 50) -> list[dict[str, Any]]:
    current = now or datetime.now(timezone.utc)
    rows = _sync_runs_table().scan().get("Items", [])
    due: list[dict[str, Any]] = []
    for row in rows:
        if str(row.get("run_type") or "") != "push_outbox":
            continue
        if bool(row.get("dead_letter")):
            continue
        status = str(row.get("status") or "").strip().lower()
        if status not in {"pending", "retry"}:
            continue
        next_attempt_at = str(row.get("next_attempt_at") or "").strip()
        if not next_attempt_at:
            continue
        try:
            next_dt = datetime.fromisoformat(next_attempt_at.replace("Z", "+00:00"))
        except ValueError:
            continue
        if next_dt <= current:
            due.append(row)
    due.sort(key=lambda it: str(it.get("next_attempt_at") or ""))
    return due[: max(int(limit), 1)]


def finalize_apple_push_outbox_attempt(
    *,
    outbox_id: str,
    success: bool,
    transient: bool,
    error: str | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    row = _sync_runs_table().get_item(Key={"run_id": f"outbox#{outbox_id}"}).get("Item")
    if not row:
        raise KeyError("push outbox record not found")
    current = now or datetime.now(timezone.utc)
    attempts = int(row.get("attempts") or 0) + 1
    max_attempts = max(int(row.get("max_attempts") or 5), 1)

    updated = dict(row)
    updated["attempts"] = attempts
    updated["updated_at"] = current.isoformat()
    updated["last_error"] = error

    if success:
        updated["status"] = "delivered"
        updated["status_key"] = "STATUS#delivered"
        updated["dead_letter"] = False
        updated["delivered_at"] = current.isoformat()
    elif transient and attempts < max_attempts:
        backoff_seconds = min(300, 2 ** attempts)
        jitter = (attempts * 17) % 7
        next_dt = current + timedelta(seconds=backoff_seconds + jitter)
        updated["status"] = "retry"
        updated["status_key"] = "STATUS#retry"
        updated["next_attempt_at"] = next_dt.isoformat()
        updated["dead_letter"] = False
    else:
        updated["status"] = "dead_letter"
        updated["status_key"] = "STATUS#dead_letter"
        updated["dead_letter"] = True
        updated["dead_lettered_at"] = current.isoformat()

    _sync_runs_table().put_item(Item=updated)
    return updated


def list_apple_push_dead_letters(*, connection_id: str) -> list[dict[str, Any]]:
    rows = _sync_runs_table().scan().get("Items", [])
    out: list[dict[str, Any]] = []
    for row in rows:
        if str(row.get("run_type") or "") != "push_outbox":
            continue
        if str(row.get("connection_id") or "") != connection_id:
            continue
        if not bool(row.get("dead_letter")):
            continue
        out.append(row)
    out.sort(key=lambda it: str(it.get("updated_at") or ""), reverse=True)
    return out


def record_apple_conflict_audit(
    *,
    connection_id: str,
    external_calendar_id: str,
    internal_event_id: str | None,
    remote_uid: str | None,
    resolution: str,
    local_updated_at: str | None,
    remote_updated_at: str | None,
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    now = _now_iso()
    audit_id = f"conflict_{uuid.uuid4().hex}"
    item = {
        "run_id": f"conflict#{audit_id}",
        "audit_id": audit_id,
        "connection_id": connection_id,
        "provider": "apple_caldav",
        "run_type": "conflict_audit",
        "status": "recorded",
        "status_key": "STATUS#recorded",
        "external_calendar_id": external_calendar_id,
        "internal_event_id": internal_event_id,
        "remote_uid": remote_uid,
        "resolution": resolution,
        "local_updated_at": local_updated_at,
        "remote_updated_at": remote_updated_at,
        "details": dict(details or {}),
        "created_at": now,
        "updated_at": now,
    }
    _sync_runs_table().put_item(Item=item)
    return item


def list_apple_conflict_audits(*, connection_id: str, limit: int = 100) -> list[dict[str, Any]]:
    rows = _sync_runs_table().scan().get("Items", [])
    audits: list[dict[str, Any]] = []
    for row in rows:
        if str(row.get("run_type") or "") != "conflict_audit":
            continue
        if str(row.get("connection_id") or "") != connection_id:
            continue
        audits.append(row)
    audits.sort(key=lambda it: str(it.get("updated_at") or ""), reverse=True)
    return audits[: max(int(limit), 1)]


def list_apple_sync_runs(*, connection_id: str, limit: int = 100) -> list[dict[str, Any]]:
    rows = _sync_runs_table().scan().get("Items", [])
    runs: list[dict[str, Any]] = []
    for row in rows:
        if str(row.get("connection_id") or "") != connection_id:
            continue
        runs.append(row)
    runs.sort(key=lambda it: str(it.get("started_at") or it.get("updated_at") or ""), reverse=True)
    return runs[: max(int(limit), 1)]


def admin_get_apple_caldav_troubleshooting_bundle(*, user_sub: str, limit: int = 25) -> dict[str, Any]:
    safe_user_sub = str(user_sub or "").strip()
    if not safe_user_sub:
        raise ValueError("user_sub is required")

    try:
        connection = get_apple_caldav_connection(user_sub=safe_user_sub, include_secret=False)
    except KeyError:
        return {
            "user_sub": safe_user_sub,
            "connection": None,
            "status": {
                "provider": "apple_caldav",
                "connection_state": "disconnected",
                "is_connected": False,
            },
            "selected_calendars": [],
            "run_history": [],
            "dead_letters": [],
            "recent_conflicts": [],
            "recommendations": [
                "Connection not found. Ask the user to reconnect Apple Calendar.",
            ],
        }

    connection_id = str(connection.get("connection_id") or "")
    status = get_apple_caldav_status(user_sub=safe_user_sub)
    selected_calendars = [
        row
        for row in _external_calendars_table().scan().get("Items", [])
        if str(row.get("connection_id") or "") == connection_id and bool(row.get("sync_enabled", True))
    ]
    selected_calendars.sort(key=lambda it: str(it.get("external_calendar_raw_id") or ""))
    run_history = list_apple_sync_runs(connection_id=connection_id, limit=limit)
    dead_letters = list_apple_push_dead_letters(connection_id=connection_id)[: max(limit, 1)]
    recent_conflicts = list_apple_conflict_audits(connection_id=connection_id, limit=limit)

    recommendations: list[str] = []
    if not selected_calendars:
        recommendations.append("No calendars are selected for sync. Review calendar selection.")
    if dead_letters:
        recommendations.append("Dead-letter push events exist. Review conflict/error details before retrying.")
    if str(status.get("connection_state") or "") == "degraded":
        recommendations.append("Connection is degraded. Validate credentials and run a manual sync.")
    if not recommendations:
        recommendations.append("No immediate issues detected from current status and run history.")

    return {
        "user_sub": safe_user_sub,
        "connection": connection,
        "status": status,
        "selected_calendars": selected_calendars,
        "run_history": run_history,
        "dead_letters": dead_letters,
        "recent_conflicts": recent_conflicts,
        "recommendations": recommendations,
    }


def admin_safe_relink_apple_event(
    *,
    user_sub: str,
    external_calendar_id: str,
    remote_uid: str,
    internal_event_id: str,
    resource_url: str | None = None,
    etag: str | None = None,
) -> dict[str, Any]:
    connection = get_apple_caldav_connection(user_sub=user_sub, include_secret=False)
    connection_id = str(connection.get("connection_id") or "")
    link, existed = upsert_apple_caldav_event_link(
        connection_id=connection_id,
        external_calendar_id=external_calendar_id,
        remote_uid=remote_uid,
        internal_event_id=internal_event_id,
        run_id=f"admin_relink_{uuid.uuid4().hex}",
        resource_url=resource_url,
        etag=etag,
    )
    return {
        "updated_existing": existed,
        "link": link,
    }


def trigger_apple_caldav_sync_now(*, user_sub: str) -> dict[str, Any]:
    connection = get_apple_caldav_connection(user_sub=user_sub, include_secret=False)
    connection_id = str(connection.get("connection_id") or "")
    calendars = list_enabled_apple_caldav_external_calendar_ids(connection_id=connection_id)

    from app.services.calendar_integrations.registry import get_provider_services

    provider = get_provider_services("apple_caldav")
    if provider is None:
        return {
            "triggered_calendar_count": 0,
            "success_count": 0,
            "failure_count": 0,
            "results": [],
        }

    success = 0
    failure = 0
    results: list[dict[str, Any]] = []
    for calendar_id in calendars:
        try:
            stats = provider.sync.pull_changes(connection_id=connection_id, calendar_id=calendar_id)
            success += 1
            results.append({"calendar_id": calendar_id, "status": "success", "stats": stats})
        except Exception as exc:
            failure += 1
            results.append({"calendar_id": calendar_id, "status": "error", "error": str(exc)})

    return {
        "triggered_calendar_count": len(calendars),
        "success_count": success,
        "failure_count": failure,
        "results": results,
    }
