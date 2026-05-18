from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List

from boto3.dynamodb.conditions import Key
from fastapi import HTTPException

from app.core.tables import T
from app.services.google_calendar_audit import emit_google_calendar_audit_event
from app.services.google_calendar_token_vault import (
    decrypt_token_payload,
    encrypt_token_payload,
    redact_token_payload,
    rotate_encrypted_token_payload,
)


CONNECTION_TYPE = "calendar_provider_connection"
DEFAULT_SYNC_HEALTH = "unknown"
DEFAULT_SYNC_STATUS = "never_synced"


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _pk(user_sub: str) -> str:
    return f"gcal_conn#{user_sub}"


def _sk(connection_id: str) -> str:
    return f"meta#{connection_id}"


def _table():
    return T.calendar


def _sanitize_sync_health(value: str | None) -> str:
    v = (value or DEFAULT_SYNC_HEALTH).strip().lower()
    if v in {"healthy", "degraded", "error", "unknown"}:
        return v
    return DEFAULT_SYNC_HEALTH


def _sanitize_sync_status(value: str | None) -> str:
    v = (value or DEFAULT_SYNC_STATUS).strip().lower()
    if v in {"never_synced", "syncing", "success", "error"}:
        return v
    return DEFAULT_SYNC_STATUS


def _build_connection_item(
    *,
    user_sub: str,
    connection_id: str,
    account_email: str | None,
    token_payload: Dict[str, Any],
) -> Dict[str, Any]:
    encrypted = encrypt_token_payload(payload=token_payload, user_sub=user_sub, connection_id=connection_id)
    now = _utc_now_iso()
    return {
        "calendar_id": _pk(user_sub),
        "sk": _sk(connection_id),
        "type": CONNECTION_TYPE,
        "provider": "google",
        "connection_id": connection_id,
        "user_sub": user_sub,
        "account_email": account_email or "",
        "token_payload_redacted": redact_token_payload(token_payload),
        "token_redacted": True,
        "active": True,
        "sync_health": DEFAULT_SYNC_HEALTH,
        "last_sync_status": DEFAULT_SYNC_STATUS,
        "last_sync_at_utc": "",
        "last_sync_error": "",
        "sync_cursor": "",
        "reauth_required": False,
        "created_at_utc": now,
        **encrypted,
        "updated_at_utc": now,
    }


def upsert_calendar_provider_connection(
    *,
    user_sub: str,
    connection_id: str,
    account_email: str | None,
    token_payload: Dict[str, Any],
) -> Dict[str, Any]:
    existing = _table().get_item(Key={"calendar_id": _pk(user_sub), "sk": _sk(connection_id)}).get("Item")
    item = _build_connection_item(
        user_sub=user_sub,
        connection_id=connection_id,
        account_email=account_email,
        token_payload=token_payload,
    )
    if isinstance(existing, dict):
        # preserve sync and lifecycle metadata on reconnect/update
        for key in ("created_at_utc", "sync_health", "last_sync_status", "last_sync_at_utc", "last_sync_error", "sync_cursor", "reauth_required"):
            if key in existing:
                item[key] = existing[key]
        item["active"] = True
    _table().put_item(Item=item)
    emit_google_calendar_audit_event(
        event="google_calendar_connected",
        actor_user_sub=user_sub,
        outcome="success",
        target_type="connection",
        target_id=connection_id,
        account_email=account_email or "",
        token_redacted=True,
    )
    return _public_connection_fields(item)


def _load_connection_item(*, user_sub: str, connection_id: str) -> Dict[str, Any]:
    item = _table().get_item(Key={"calendar_id": _pk(user_sub), "sk": _sk(connection_id)}).get("Item")
    if not item or item.get("type") != CONNECTION_TYPE:
        raise HTTPException(status_code=404, detail="google calendar connection not found")
    return item


def _public_connection_fields(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "provider": "google",
        "connection_id": str(item.get("connection_id") or ""),
        "user_sub": str(item.get("user_sub") or ""),
        "account_email": str(item.get("account_email") or ""),
        "active": bool(item.get("active", True)),
        "sync_health": _sanitize_sync_health(str(item.get("sync_health") or DEFAULT_SYNC_HEALTH)),
        "last_sync_status": _sanitize_sync_status(str(item.get("last_sync_status") or DEFAULT_SYNC_STATUS)),
        "last_sync_at_utc": str(item.get("last_sync_at_utc") or ""),
        "last_sync_error": str(item.get("last_sync_error") or ""),
        "sync_cursor": str(item.get("sync_cursor") or ""),
        "reauth_required": bool(item.get("reauth_required", False)),
        "updated_at_utc": str(item.get("updated_at_utc") or ""),
        "token_redacted": True,
    }


def list_calendar_provider_connections(*, user_sub: str, include_inactive: bool = False) -> List[Dict[str, Any]]:
    resp = _table().query(
        KeyConditionExpression=Key("calendar_id").eq(_pk(user_sub)),
    )
    items = [it for it in (resp.get("Items") or []) if it.get("type") == CONNECTION_TYPE]
    if not include_inactive:
        items = [it for it in items if bool(it.get("active", True))]
    return [_public_connection_fields(it) for it in items]


def get_calendar_provider_connection(
    *,
    user_sub: str,
    connection_id: str,
    include_tokens: bool = False,
    include_inactive: bool = False,
) -> Dict[str, Any]:
    item = _load_connection_item(user_sub=user_sub, connection_id=connection_id)
    if not include_inactive and not bool(item.get("active", True)):
        raise HTTPException(status_code=404, detail="google calendar connection not found")

    out = _public_connection_fields(item)
    if include_tokens:
        out["token_payload"] = decrypt_token_payload(
            encrypted=item,
            user_sub=user_sub,
            connection_id=connection_id,
        )
    else:
        out["token_payload"] = dict(item.get("token_payload_redacted") or {})
    return out


def update_calendar_provider_connection_sync_status(
    *,
    user_sub: str,
    connection_id: str,
    sync_health: str | None = None,
    last_sync_status: str | None = None,
    last_sync_error: str | None = None,
    sync_cursor: str | None = None,
    reauth_required: bool | None = None,
    last_sync_at_utc: str | None = None,
) -> Dict[str, Any]:
    item = _load_connection_item(user_sub=user_sub, connection_id=connection_id)

    next_health = _sanitize_sync_health(sync_health or str(item.get("sync_health") or DEFAULT_SYNC_HEALTH))
    next_status = _sanitize_sync_status(last_sync_status or str(item.get("last_sync_status") or DEFAULT_SYNC_STATUS))
    next_error = (last_sync_error if last_sync_error is not None else str(item.get("last_sync_error") or ""))
    next_cursor = (sync_cursor if sync_cursor is not None else str(item.get("sync_cursor") or ""))
    next_reauth = bool(reauth_required) if reauth_required is not None else bool(item.get("reauth_required", False))
    next_sync_at = last_sync_at_utc if last_sync_at_utc is not None else str(item.get("last_sync_at_utc") or "")

    # idempotent no-op if no effective change
    if (
        next_health == str(item.get("sync_health") or DEFAULT_SYNC_HEALTH)
        and next_status == str(item.get("last_sync_status") or DEFAULT_SYNC_STATUS)
        and next_error == str(item.get("last_sync_error") or "")
        and next_cursor == str(item.get("sync_cursor") or "")
        and next_reauth == bool(item.get("reauth_required", False))
        and next_sync_at == str(item.get("last_sync_at_utc") or "")
    ):
        return _public_connection_fields(item)

    item["sync_health"] = next_health
    item["last_sync_status"] = next_status
    item["last_sync_error"] = next_error
    item["sync_cursor"] = next_cursor
    item["reauth_required"] = next_reauth
    item["last_sync_at_utc"] = next_sync_at
    item["updated_at_utc"] = _utc_now_iso()
    _table().put_item(Item=item)
    return _public_connection_fields(item)


def rotate_calendar_provider_connection_tokens(*, user_sub: str, connection_id: str) -> Dict[str, Any]:
    item = _load_connection_item(user_sub=user_sub, connection_id=connection_id)
    rotated = rotate_encrypted_token_payload(encrypted=item, user_sub=user_sub, connection_id=connection_id)
    item.update(rotated)
    item["updated_at_utc"] = _utc_now_iso()
    _table().put_item(Item=item)
    emit_google_calendar_audit_event(
        event="google_calendar_connection_tokens_rotated",
        actor_user_sub=user_sub,
        outcome="success",
        target_type="connection",
        target_id=connection_id,
        token_redacted=True,
    )
    return _public_connection_fields(item)


def disconnect_calendar_provider_connection(
    *,
    user_sub: str,
    connection_id: str,
    revoked: bool,
    revoke_status: str,
) -> Dict[str, Any]:
    item = _load_connection_item(user_sub=user_sub, connection_id=connection_id)
    item["active"] = False
    item["disconnected_at_utc"] = _utc_now_iso()
    item["revoke_status"] = revoke_status
    item["updated_at_utc"] = _utc_now_iso()
    _table().put_item(Item=item)
    emit_google_calendar_audit_event(
        event="google_calendar_disconnected",
        actor_user_sub=user_sub,
        outcome="success" if revoked else "error",
        target_type="connection",
        target_id=connection_id,
        account_email=str(item.get("account_email") or ""),
        revoked=revoked,
        revoke_status=revoke_status,
        token_redacted=True,
    )
    out = _public_connection_fields(item)
    out["revoked"] = revoked
    out["revoke_status"] = revoke_status
    out["disconnected_at_utc"] = item["disconnected_at_utc"]
    return out


# Backward-compatible aliases
def upsert_google_calendar_connection(*, user_sub: str, connection_id: str, account_email: str | None, token_payload: Dict[str, Any]) -> Dict[str, Any]:
    return upsert_calendar_provider_connection(user_sub=user_sub, connection_id=connection_id, account_email=account_email, token_payload=token_payload)


def list_google_calendar_connections(*, user_sub: str, include_inactive: bool = False) -> List[Dict[str, Any]]:
    return list_calendar_provider_connections(user_sub=user_sub, include_inactive=include_inactive)


def get_google_calendar_connection(*, user_sub: str, connection_id: str, include_tokens: bool = False) -> Dict[str, Any]:
    return get_calendar_provider_connection(user_sub=user_sub, connection_id=connection_id, include_tokens=include_tokens)


def update_google_calendar_connection_sync_status(
    *,
    user_sub: str,
    connection_id: str,
    sync_health: str | None = None,
    last_sync_status: str | None = None,
    last_sync_error: str | None = None,
    sync_cursor: str | None = None,
    reauth_required: bool | None = None,
    last_sync_at_utc: str | None = None,
) -> Dict[str, Any]:
    return update_calendar_provider_connection_sync_status(
        user_sub=user_sub,
        connection_id=connection_id,
        sync_health=sync_health,
        last_sync_status=last_sync_status,
        last_sync_error=last_sync_error,
        sync_cursor=sync_cursor,
        reauth_required=reauth_required,
        last_sync_at_utc=last_sync_at_utc,
    )


def rotate_google_calendar_connection_tokens(*, user_sub: str, connection_id: str) -> Dict[str, Any]:
    return rotate_calendar_provider_connection_tokens(user_sub=user_sub, connection_id=connection_id)
