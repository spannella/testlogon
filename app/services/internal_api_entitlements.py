from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from time import perf_counter
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError
from fastapi import HTTPException

from app.core.aws import ddb
from app.core.settings import S
from app.core.tables import T
from app.services.internal_metering_contract import resolve_meter_binding
from app.metrics import record_entitlement_check, record_entitlement_check_latency


def _to_utc(value: Any) -> Optional[datetime]:
    if value is None:
        return None
    if isinstance(value, datetime):
        dt = value
    else:
        text = str(value).strip()
        if not text:
            return None
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        if text.isdigit():
            dt = datetime.fromtimestamp(int(text), tz=timezone.utc)
        else:
            dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _deny(*, reason: str, namespace: str, action: str, entitlement_id: Optional[str], user_id: str) -> None:
    raise HTTPException(
        status_code=403,
        detail={
            "code": "internal_api_entitlement_denied",
            "reason": reason,
            "namespace": namespace,
            "action": action,
            "entitlement_id": entitlement_id,
            "user_sub": user_id,
        },
    )


def _query_internal_entitlements(user_id: str) -> List[Dict[str, Any]]:
    resp = T.entitlements.query(KeyConditionExpression=Key("user_id").eq(user_id))
    return [row for row in resp.get("Items", []) if str(row.get("product_type") or "") == "internal_api_package"]


def _scope_allows_namespace_and_action(ent: Dict[str, Any], namespace: str, action: str) -> bool:
    scope = ent.get("scope") if isinstance(ent.get("scope"), dict) else {}
    namespaces = scope.get("internal_namespaces") or []
    if not namespaces:
        legacy_resource = scope.get("resource") if isinstance(scope.get("resource"), dict) else {}
        legacy_ns = legacy_resource.get("namespace")
        if legacy_ns:
            namespaces = [legacy_ns]

    normalized = {str(x).strip() for x in namespaces if str(x).strip()}
    if normalized:
        required = f"{namespace}.*"
        if required not in normalized and namespace not in normalized:
            return False

    allowed_actions = scope.get("allowed_actions") or []
    allowed = {str(x).strip() for x in allowed_actions if str(x).strip()}
    if allowed and action not in allowed:
        return False

    return True


def _is_active(ent: Dict[str, Any], *, now: datetime) -> bool:
    if str(ent.get("status") or "").lower() != "active":
        return False
    starts_at = _to_utc(ent.get("starts_at"))
    ends_at = _to_utc(ent.get("ends_at"))
    if starts_at and now < starts_at:
        return False
    if ends_at and now >= ends_at:
        return False
    return True


def _choose_entitlement(user_id: str, namespace: str, action: str) -> Dict[str, Any]:
    now = datetime.now(timezone.utc)
    matches = []
    saw_expired = False
    for ent in _query_internal_entitlements(user_id):
        if not _scope_allows_namespace_and_action(ent, namespace, action):
            continue
        if _is_active(ent, now=now):
            matches.append(ent)
            continue
        ends_at = _to_utc(ent.get("ends_at"))
        if ends_at and now >= ends_at:
            saw_expired = True

    if matches:
        matches.sort(key=lambda x: str(x.get("entitlement_id") or ""))
        return matches[0]

    if saw_expired:
        _deny(reason="expired_entitlement", namespace=namespace, action=action, entitlement_id=None, user_id=user_id)
    _deny(reason="no_entitlement", namespace=namespace, action=action, entitlement_id=None, user_id=user_id)


def enforce_internal_api_entitlement(
    *,
    user_id: str,
    namespace: str,
    action: str,
    request_id: str,
    amount: int = 1,
) -> Dict[str, Any]:
    started = perf_counter()
    if (not S.catalog_commercialization_enabled) or (not bool(getattr(S, "catalog_internal_api_package_enabled", True))):
        record_entitlement_check(product_family="internal_api_package", outcome="bypassed", reason="flag_disabled")
        record_entitlement_check_latency(product_family="internal_api_package", elapsed_seconds=perf_counter() - started)
        return {"enforced": False}
    if amount <= 0:
        raise ValueError("amount must be > 0")

    binding = resolve_meter_binding(namespace, action)
    ent = _choose_entitlement(user_id, namespace, action)
    entitlement_id = str(ent.get("entitlement_id") or "")
    if not entitlement_id:
        _deny(reason="no_entitlement", namespace=namespace, action=action, entitlement_id=None, user_id=user_id)

    usage_limit = int(ent.get("usage_limit") or 0)
    idem_src = f"internal_api|{entitlement_id}|{binding.meter}|{request_id}|{amount}"
    idempotency_key = hashlib.sha256(idem_src.encode("utf-8")).hexdigest()
    event_id = f"evt_{idempotency_key[:24]}"
    ts = datetime.now(timezone.utc).isoformat()

    transact_items = [
        {
            "Put": {
                "TableName": T.entitlement_usage_events.name,
                "Item": {
                    "entitlement_id": {"S": entitlement_id},
                    "event_id": {"S": event_id},
                    "idempotency_key": {"S": idempotency_key},
                    "user_id": {"S": user_id},
                    "meter": {"S": binding.meter},
                    "namespace": {"S": namespace},
                    "action": {"S": action},
                    "amount": {"N": str(amount)},
                    "timestamp": {"S": ts},
                    "event_date": {"S": datetime.now(timezone.utc).strftime("%Y-%m-%d")},
                    "event_ts": {"S": ts},
                },
                "ConditionExpression": "attribute_not_exists(entitlement_id) AND attribute_not_exists(event_id)",
            }
        }
    ]

    if usage_limit > 0:
        transact_items.append(
            {
                "Update": {
                    "TableName": T.entitlements.name,
                    "Key": {"user_id": {"S": user_id}, "entitlement_id": {"S": entitlement_id}},
                    "UpdateExpression": "SET usage_consumed = if_not_exists(usage_consumed, :z) + :amt, updated_at = :ts",
                    "ConditionExpression": "#st = :active AND (attribute_not_exists(usage_consumed) OR usage_consumed + :amt <= :limit)",
                    "ExpressionAttributeNames": {"#st": "status"},
                    "ExpressionAttributeValues": {
                        ":z": {"N": "0"},
                        ":amt": {"N": str(amount)},
                        ":limit": {"N": str(usage_limit)},
                        ":active": {"S": "active"},
                        ":ts": {"S": ts},
                    },
                }
            }
        )

    try:
        ddb.meta.client.transact_write_items(TransactItems=transact_items)
        record_entitlement_check(product_family="internal_api_package", outcome="allowed", reason="in_scope")
        record_entitlement_check_latency(product_family="internal_api_package", elapsed_seconds=perf_counter() - started)
        return {
            "enforced": True,
            "allowed": True,
            "entitlement_id": entitlement_id,
            "meter": binding.meter,
            "idempotency_key": idempotency_key,
            "replayed": False,
        }
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        msg = str(exc)
        if usage_limit > 0 and code == "TransactionCanceledException" and "ConditionalCheckFailed" in msg:
            record_entitlement_check(product_family="internal_api_package", outcome="denied", reason="exhausted")
            record_entitlement_check_latency(product_family="internal_api_package", elapsed_seconds=perf_counter() - started)
            _deny(reason="exhausted", namespace=namespace, action=action, entitlement_id=entitlement_id, user_id=user_id)
        if code in {"TransactionCanceledException", "ConditionalCheckFailedException"}:
            record_entitlement_check(product_family="internal_api_package", outcome="allowed", reason="idempotent_replay")
            record_entitlement_check_latency(product_family="internal_api_package", elapsed_seconds=perf_counter() - started)
            return {
                "enforced": True,
                "allowed": True,
                "entitlement_id": entitlement_id,
                "meter": binding.meter,
                "idempotency_key": idempotency_key,
                "replayed": True,
            }
        raise


def list_usage_events_for_entitlement(entitlement_id: str, *, limit: int = 100) -> List[Dict[str, Any]]:
    resp = T.entitlement_usage_events.query(
        KeyConditionExpression=Key("entitlement_id").eq(entitlement_id),
        Limit=limit,
        ScanIndexForward=False,
    )
    return list(resp.get("Items", []))
