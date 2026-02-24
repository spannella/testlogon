from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from time import perf_counter
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError
from fastapi import HTTPException, Request

from app.core.aws import ddb
from app.core.settings import S
from app.core.tables import T
from app.services.api_metering_contract import route_id_from_request
from app.services.api_usage_metering import _extract_api_key_id, _extract_request_id, _extract_user_sub
from app.services.api_package_usage import emit_usage_threshold_alerts
from app.metrics import record_api_usage_limit_deny, record_entitlement_check, record_entitlement_check_latency


def _to_utc(value: Any) -> Optional[datetime]:
    if value is None:
        return None
    if isinstance(value, datetime):
        dt = value
    else:
        text = str(value).strip()
        if not text:
            return None
        if text.isdigit():
            dt = datetime.fromtimestamp(int(text), tz=timezone.utc)
        else:
            if text.endswith("Z"):
                text = text[:-1] + "+00:00"
            dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _deny(*, reason: str, route_id: str, entitlement_id: Optional[str], user_sub: str) -> None:
    record_api_usage_limit_deny(route_id=route_id, limit_type=f"api_entitlement_{reason}")
    raise HTTPException(
        status_code=403,
        detail={
            "code": "api_entitlement_denied",
            "reason": reason,
            "route_id": route_id,
            "entitlement_id": entitlement_id,
            "user_sub": user_sub,
        },
    )


def _query_api_entitlements(user_sub: str) -> List[Dict[str, Any]]:
    resp = T.entitlements.query(KeyConditionExpression=Key("user_id").eq(user_sub))
    return [e for e in resp.get("Items", []) if str(e.get("product_type") or "") == "api_package"]


def _route_allowed(ent: Dict[str, Any], route_id: str) -> bool:
    scope = ent.get("scope") if isinstance(ent.get("scope"), dict) else {}
    access_template = ent.get("access_template") if isinstance(ent.get("access_template"), dict) else {}
    route_allow = access_template.get("route_allowlist")
    if route_allow is None:
        route_allow = scope.get("route_allowlist")
    if route_allow is None:
        return True
    if not isinstance(route_allow, list):
        return False
    return route_id in {str(x) for x in route_allow}


def _effective_active(ent: Dict[str, Any], now: datetime) -> bool:
    status = str(ent.get("status") or "").lower()
    if status != "active":
        return False
    starts_at = _to_utc(ent.get("starts_at"))
    ends_at = _to_utc(ent.get("ends_at"))
    if starts_at and now < starts_at:
        return False
    if ends_at and now >= ends_at:
        return False
    return True


def _limit_for_entitlement(ent: Dict[str, Any]) -> int:
    base = int(ent.get("usage_limit") or 0)
    limits = ent.get("limit_overrides") if isinstance(ent.get("limit_overrides"), dict) else {}
    monthly_calls = int(limits.get("monthly_call_limit") or 0)
    if base > 0 and monthly_calls > 0:
        return min(base, monthly_calls)
    return max(base, monthly_calls)


def _consume_atomic(*, ent: Dict[str, Any], route_id: str, user_sub: str, request_id: str, api_key_id: str) -> Dict[str, Any]:
    entitlement_id = str(ent.get("entitlement_id") or "")
    if not entitlement_id:
        _deny(reason="no_entitlement", route_id=route_id, entitlement_id=None, user_sub=user_sub)

    limit = _limit_for_entitlement(ent)
    idem_src = f"api_entitlement|{entitlement_id}|{route_id}|{request_id}|{api_key_id}"
    idem_key = hashlib.sha256(idem_src.encode("utf-8")).hexdigest()
    event_id = f"evt_{idem_key[:24]}"
    ts = datetime.now(timezone.utc).isoformat()

    client = ddb.meta.client
    try:
        transact_items = [
            {
                "Put": {
                    "TableName": T.entitlement_usage_events.name,
                    "Item": {
                        "entitlement_id": {"S": entitlement_id},
                        "event_id": {"S": event_id},
                        "idempotency_key": {"S": idem_key},
                        "user_id": {"S": user_sub},
                        "route_id": {"S": route_id},
                        "meter": {"S": "request_units"},
                        "amount": {"N": "1"},
                        "timestamp": {"S": ts},
                        "event_date": {"S": datetime.now(timezone.utc).strftime("%Y-%m-%d")},
                        "event_ts": {"S": ts},
                    },
                    "ConditionExpression": "attribute_not_exists(entitlement_id) AND attribute_not_exists(event_id)",
                }
            }
        ]
        if limit > 0:
            transact_items.append(
                {
                    "Update": {
                        "TableName": T.entitlements.name,
                        "Key": {"user_id": {"S": user_sub}, "entitlement_id": {"S": entitlement_id}},
                        "UpdateExpression": "SET usage_consumed = if_not_exists(usage_consumed, :z) + :one, updated_at = :ts",
                        "ConditionExpression": "#st = :active AND (attribute_not_exists(usage_consumed) OR usage_consumed < :limit)",
                        "ExpressionAttributeNames": {"#st": "status"},
                        "ExpressionAttributeValues": {
                            ":z": {"N": "0"},
                            ":one": {"N": "1"},
                            ":limit": {"N": str(limit)},
                            ":active": {"S": "active"},
                            ":ts": {"S": ts},
                        },
                    }
                }
            )
        client.transact_write_items(TransactItems=transact_items)
        if limit > 0:
            consumed = int(ent.get("usage_consumed") or 0) + 1
            emit_usage_threshold_alerts(
                user_id=user_sub,
                entitlement_id=entitlement_id,
                sku=str(ent.get("sku") or ""),
                usage_limit=limit,
                usage_consumed=consumed,
            )
        return {"idempotency_key": idem_key, "entitlement_id": entitlement_id, "limit": limit}
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        msg = str(exc)
        if code == "TransactionCanceledException" and "ConditionalCheckFailed" in msg and limit > 0:
            _deny(reason="quota_exceeded", route_id=route_id, entitlement_id=entitlement_id, user_sub=user_sub)
        # duplicate event idempotency -> allow deterministic replay
        if code in {"TransactionCanceledException", "ConditionalCheckFailedException"}:
            return {"idempotency_key": idem_key, "entitlement_id": entitlement_id, "limit": limit, "replayed": True}
        raise


def enforce_api_package_entitlement_pre_request(request: Request) -> dict[str, str]:
    started = perf_counter()
    if not bool(getattr(S, "catalog_api_package_enabled", True)):
        record_entitlement_check(product_family="api_package", outcome="bypassed", reason="flag_disabled")
        record_entitlement_check_latency(product_family="api_package", elapsed_seconds=perf_counter() - started)
        return {}

    route_id = route_id_from_request(request)
    if not route_id:
        record_entitlement_check(product_family="api_package", outcome="bypassed", reason="not_api_route")
        record_entitlement_check_latency(product_family="api_package", elapsed_seconds=perf_counter() - started)
        return {}
    user_sub = _extract_user_sub(request)
    if not user_sub:
        record_entitlement_check(product_family="api_package", outcome="bypassed", reason="missing_subject")
        record_entitlement_check_latency(product_family="api_package", elapsed_seconds=perf_counter() - started)
        return {}

    now = datetime.now(timezone.utc)
    ents = _query_api_entitlements(user_sub)
    if not ents:
        record_entitlement_check(product_family="api_package", outcome="denied", reason="no_entitlement")
        record_entitlement_check_latency(product_family="api_package", elapsed_seconds=perf_counter() - started)
        _deny(reason="no_entitlement", route_id=route_id, entitlement_id=None, user_sub=user_sub)

    chosen: Optional[Dict[str, Any]] = None
    saw_expired = False
    for ent in ents:
        if not _route_allowed(ent, route_id):
            continue
        if _effective_active(ent, now):
            chosen = ent
            break
        ends_at = _to_utc(ent.get("ends_at"))
        if ends_at and now >= ends_at:
            saw_expired = True

    if chosen is None:
        if saw_expired:
            record_entitlement_check(product_family="api_package", outcome="denied", reason="expired_entitlement")
            record_entitlement_check_latency(product_family="api_package", elapsed_seconds=perf_counter() - started)
            _deny(reason="expired_entitlement", route_id=route_id, entitlement_id=None, user_sub=user_sub)
        record_entitlement_check(product_family="api_package", outcome="denied", reason="unauthorized_route")
        record_entitlement_check_latency(product_family="api_package", elapsed_seconds=perf_counter() - started)
        _deny(reason="unauthorized_route", route_id=route_id, entitlement_id=None, user_sub=user_sub)

    request_id = _extract_request_id(request) or "<missing-request-id>"
    api_key_id = _extract_api_key_id(request)
    consumed = _consume_atomic(ent=chosen, route_id=route_id, user_sub=user_sub, request_id=request_id, api_key_id=api_key_id)

    record_entitlement_check(product_family="api_package", outcome="allowed", reason="in_scope")
    record_entitlement_check_latency(product_family="api_package", elapsed_seconds=perf_counter() - started)
    return {
        "x-api-entitlement-id": str(consumed.get("entitlement_id") or ""),
        "x-api-entitlement-route": route_id,
        "x-api-entitlement-idempotency": str(consumed.get("idempotency_key") or ""),
        "x-api-entitlement-replayed": "1" if consumed.get("replayed") else "0",
    }
