from __future__ import annotations

from typing import Any, Dict, List

from boto3.dynamodb.conditions import Key

from app.core.settings import S
from app.core.tables import T
from app.services.billing_shared import ddb_del, ddb_query_pk, user_pk


def _delete_by_user(table: Any, key_fields: List[str], user_sub: str) -> int:
    deleted = 0
    last_key = None
    while True:
        kwargs: Dict[str, Any] = {
            "KeyConditionExpression": Key("user_sub").eq(user_sub),
            "Limit": 200,
        }
        if last_key:
            kwargs["ExclusiveStartKey"] = last_key
        resp = table.query(**kwargs)
        items = resp.get("Items", [])
        if items:
            with table.batch_writer() as batch:
                for it in items:
                    key = {field: it.get(field) for field in key_fields}
                    if all(key.values()):
                        batch.delete_item(Key=key)
                        deleted += 1
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break
    return deleted


def _delete_api_keys(user_sub: str) -> int:
    deleted = 0
    last_key = None
    while True:
        kwargs: Dict[str, Any] = {
            "IndexName": S.api_keys_user_index,
            "KeyConditionExpression": Key("user_sub").eq(user_sub),
            "Limit": 200,
        }
        if last_key:
            kwargs["ExclusiveStartKey"] = last_key
        resp = T.api_keys.query(**kwargs)
        items = resp.get("Items", [])
        if items:
            with T.api_keys.batch_writer() as batch:
                for it in items:
                    key_id = it.get("key_id") or it.get("api_key_id")
                    if key_id:
                        batch.delete_item(Key={"key_id": key_id})
                        deleted += 1
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break
    return deleted


def _delete_billing_rows(user_sub: str) -> int:
    pk = user_pk(user_sub)
    items = ddb_query_pk(T.billing, pk)
    for it in items:
        ddb_del(T.billing, pk, it.get("sk"))
    return len(items)


def delete_user_data(user_sub: str) -> None:
    errors: List[str] = []

    for name, fn in (
        ("sessions", lambda: _delete_by_user(T.sessions, ["user_sub", "session_id"], user_sub)),
        ("totp", lambda: _delete_by_user(T.totp, ["user_sub", "device_id"], user_sub)),
        ("sms", lambda: _delete_by_user(T.sms, ["user_sub", "sms_device_id"], user_sub)),
        ("recovery", lambda: _delete_by_user(T.recovery, ["user_sub", "code_hash"], user_sub)),
        ("email", lambda: _delete_by_user(T.email, ["user_sub", "email_device_id"], user_sub)),
        ("alerts", lambda: _delete_by_user(T.alerts, ["user_sub", "alert_id"], user_sub)),
        ("push_devices", lambda: _delete_by_user(T.push_devices, ["user_sub", "device_id"], user_sub)),
        ("api_keys", lambda: _delete_api_keys(user_sub)),
        ("billing", lambda: _delete_billing_rows(user_sub)),
    ):
        try:
            fn()
        except Exception as exc:  # pragma: no cover - best effort cleanup
            errors.append(f"{name}: {exc}")

    try:
        T.alert_prefs.delete_item(Key={"user_sub": user_sub})
    except Exception as exc:  # pragma: no cover
        errors.append(f"alert_prefs: {exc}")

    if errors:
        raise RuntimeError("Failed to delete some user data: " + "; ".join(errors))
