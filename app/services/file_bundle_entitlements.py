from __future__ import annotations

from datetime import datetime, timezone
from time import perf_counter
from typing import Any, Dict, List, Optional, Tuple

from boto3.dynamodb.conditions import Key
from fastapi import HTTPException

from app.core.settings import S
from app.core.tables import T
from app.metrics import record_entitlement_check, record_entitlement_check_latency


def _to_utc(raw: Any) -> Optional[datetime]:
    if raw is None:
        return None
    if isinstance(raw, datetime):
        dt = raw
    else:
        text = str(raw).strip()
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


def _file_timestamp(node: Dict[str, Any]) -> Optional[datetime]:
    # Prefer created_at for date-window bundle semantics; fallback to upload_at.
    return _to_utc(node.get("created_at")) or _to_utc(node.get("upload_at"))


def _deny(reason: str, message: str, *, status_code: int = 403, extra: Optional[Dict[str, Any]] = None) -> None:
    detail = {
        "code": "file_bundle_access_denied",
        "reason": reason,
        "message": message,
        "required_product_type": "file_bundle",
    }
    if extra:
        detail.update(extra)
    raise HTTPException(status_code=status_code, detail=detail)


def _query_user_entitlements(user_id: str) -> List[Dict[str, Any]]:
    resp = T.entitlements.query(KeyConditionExpression=Key("user_id").eq(user_id))
    return list(resp.get("Items", []))


def _is_matching_scope(ent: Dict[str, Any], file_dt: datetime) -> Tuple[bool, str]:
    scope = ent.get("scope") or {}
    if not isinstance(scope, dict):
        return False, "invalid_scope"
    date_start = _to_utc(scope.get("date_start"))
    date_end = _to_utc(scope.get("date_end"))
    if date_start is None or date_end is None:
        return False, "invalid_scope"
    if file_dt < date_start or file_dt > date_end:
        return False, "out_of_scope"
    return True, "ok"


def assert_file_bundle_access(user_id: str, node: Dict[str, Any]) -> None:
    started = perf_counter()
    if (not bool(getattr(S, "catalog_commercialization_enabled", False))) or (not bool(getattr(S, "catalog_file_bundle_enabled", True))):
        record_entitlement_check(product_family="file_bundle", outcome="bypassed", reason="flag_disabled")
        record_entitlement_check_latency(product_family="file_bundle", elapsed_seconds=perf_counter() - started)
        return

    file_dt = _file_timestamp(node)
    if file_dt is None:
        record_entitlement_check(product_family="file_bundle", outcome="denied", reason="missing_file_timestamp")
        record_entitlement_check_latency(product_family="file_bundle", elapsed_seconds=perf_counter() - started)
        _deny("missing_file_timestamp", "File metadata missing created/upload timestamp")

    entitlements = [
        e
        for e in _query_user_entitlements(user_id)
        if str(e.get("product_type") or "") == "file_bundle"
    ]
    if not entitlements:
        record_entitlement_check(product_family="file_bundle", outcome="denied", reason="no_entitlement")
        record_entitlement_check_latency(product_family="file_bundle", elapsed_seconds=perf_counter() - started)
        _deny("no_entitlement", "No active file bundle entitlement found")

    now = datetime.now(timezone.utc)
    saw_expired = False
    saw_scope_miss = False

    for ent in entitlements:
        status = str(ent.get("status") or "")
        starts_at = _to_utc(ent.get("starts_at"))
        ends_at = _to_utc(ent.get("ends_at"))

        if status not in {"active", "pending_payment", "expired", "revoked", "consumed"}:
            continue
        if status in {"revoked", "consumed", "pending_payment"}:
            continue

        if starts_at and now < starts_at:
            continue
        if status == "expired" or (ends_at and now >= ends_at):
            saw_expired = True
            continue

        ok_scope, reason = _is_matching_scope(ent, file_dt)
        if ok_scope:
            record_entitlement_check(product_family="file_bundle", outcome="allowed", reason="in_scope")
            record_entitlement_check_latency(product_family="file_bundle", elapsed_seconds=perf_counter() - started)
            return
        if reason == "out_of_scope":
            saw_scope_miss = True

    if saw_expired:
        record_entitlement_check(product_family="file_bundle", outcome="denied", reason="expired_entitlement")
        record_entitlement_check_latency(product_family="file_bundle", elapsed_seconds=perf_counter() - started)
        _deny("expired_entitlement", "File bundle entitlement has expired")
    if saw_scope_miss:
        record_entitlement_check(product_family="file_bundle", outcome="denied", reason="out_of_scope")
        record_entitlement_check_latency(product_family="file_bundle", elapsed_seconds=perf_counter() - started)
        _deny("out_of_scope", "File timestamp is outside entitled date range")
    record_entitlement_check(product_family="file_bundle", outcome="denied", reason="no_entitlement")
    record_entitlement_check_latency(product_family="file_bundle", elapsed_seconds=perf_counter() - started)
    _deny("no_entitlement", "No active in-scope file bundle entitlement found")
