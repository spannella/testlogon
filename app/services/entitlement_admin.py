from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

from boto3.dynamodb.conditions import Attr
from fastapi import HTTPException

from app.core.tables import T


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _scan_entitlement(entitlement_id: str) -> Dict[str, Any]:
    resp = T.entitlements.scan(FilterExpression=Attr("entitlement_id").eq(entitlement_id), Limit=1)
    items = list(resp.get("Items", []))
    if not items:
        raise HTTPException(status_code=404, detail={"code": "entitlement_not_found", "entitlement_id": entitlement_id})
    return dict(items[0])


def _parse_utc(ts: str | None) -> datetime | None:
    if not ts:
        return None
    try:
        dt = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except Exception:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _record_adjustment_event(*, entitlement: Dict[str, Any], action: str, amount: int, reason_code: str, audit_comment: str, actor_sub: str) -> Dict[str, Any]:
    ts = _utc_now_iso()
    entitlement_id = str(entitlement.get("entitlement_id") or "")
    event_id = f"admin_{action}_{int(datetime.now(timezone.utc).timestamp()*1000000)}"
    item = {
        "entitlement_id": entitlement_id,
        "event_id": event_id,
        "idempotency_key": f"admin:{action}:{event_id}",
        "meter": "admin.adjustment",
        "amount": int(amount),
        "user_id": entitlement.get("user_id"),
        "timestamp": ts,
        "action": action,
        "reason_code": reason_code,
        "audit_comment": audit_comment,
        "actor_sub": actor_sub,
    }
    T.entitlement_usage_events.put_item(Item=item)
    return item


def revoke_entitlement_admin(*, entitlement_id: str, reason_code: str, audit_comment: str, actor_sub: str) -> Dict[str, Any]:
    ent = _scan_entitlement(entitlement_id)
    key = {"user_id": ent.get("user_id"), "entitlement_id": entitlement_id}
    ts = _utc_now_iso()
    T.entitlements.update_item(
        Key=key,
        UpdateExpression="SET #st = :st, revoked_at = :ts, revoke_reason_code = :reason, revoke_audit_comment = :comment, revoked_by = :actor, updated_at = :ts",
        ExpressionAttributeNames={"#st": "status"},
        ExpressionAttributeValues={
            ":st": "revoked",
            ":ts": ts,
            ":reason": reason_code,
            ":comment": audit_comment,
            ":actor": actor_sub,
        },
    )
    evt = _record_adjustment_event(entitlement=ent, action="revoke", amount=0, reason_code=reason_code, audit_comment=audit_comment, actor_sub=actor_sub)
    return {"ok": True, "entitlement_id": entitlement_id, "status": "revoked", "audit_event_id": evt["event_id"]}


def extend_entitlement_admin(*, entitlement_id: str, extend_hours: int, reason_code: str, audit_comment: str, actor_sub: str) -> Dict[str, Any]:
    if extend_hours <= 0:
        raise HTTPException(status_code=400, detail={"code": "invalid_extend_hours"})
    ent = _scan_entitlement(entitlement_id)
    starts = _parse_utc(ent.get("starts_at")) or datetime.now(timezone.utc)
    base = _parse_utc(ent.get("ends_at")) or starts
    new_ends_at = (base + timedelta(hours=int(extend_hours))).isoformat()
    key = {"user_id": ent.get("user_id"), "entitlement_id": entitlement_id}
    ts = _utc_now_iso()
    T.entitlements.update_item(
        Key=key,
        UpdateExpression="SET ends_at = :ends_at, extension_hours_total = if_not_exists(extension_hours_total, :z) + :h, extension_reason_code = :reason, extension_audit_comment = :comment, extended_by = :actor, updated_at = :ts",
        ExpressionAttributeValues={
            ":ends_at": new_ends_at,
            ":h": int(extend_hours),
            ":z": 0,
            ":reason": reason_code,
            ":comment": audit_comment,
            ":actor": actor_sub,
            ":ts": ts,
        },
    )
    evt = _record_adjustment_event(entitlement=ent, action="extend", amount=int(extend_hours), reason_code=reason_code, audit_comment=audit_comment, actor_sub=actor_sub)
    return {"ok": True, "entitlement_id": entitlement_id, "extended_hours": int(extend_hours), "ends_at": new_ends_at, "audit_event_id": evt["event_id"]}


def credit_adjust_entitlement_admin(*, entitlement_id: str, credit_units: int, reason_code: str, audit_comment: str, actor_sub: str) -> Dict[str, Any]:
    if credit_units <= 0:
        raise HTTPException(status_code=400, detail={"code": "invalid_credit_units"})
    ent = _scan_entitlement(entitlement_id)
    key = {"user_id": ent.get("user_id"), "entitlement_id": entitlement_id}
    ts = _utc_now_iso()
    T.entitlements.update_item(
        Key=key,
        UpdateExpression="SET usage_limit = if_not_exists(usage_limit, :z) + :credits, credit_adjusted_units_total = if_not_exists(credit_adjusted_units_total, :z) + :credits, credit_reason_code = :reason, credit_audit_comment = :comment, credit_adjusted_by = :actor, updated_at = :ts",
        ExpressionAttributeValues={
            ":credits": int(credit_units),
            ":z": 0,
            ":reason": reason_code,
            ":comment": audit_comment,
            ":actor": actor_sub,
            ":ts": ts,
        },
    )
    evt = _record_adjustment_event(entitlement=ent, action="credit", amount=int(credit_units), reason_code=reason_code, audit_comment=audit_comment, actor_sub=actor_sub)
    prior_limit = int(ent.get("usage_limit") or 0)
    return {"ok": True, "entitlement_id": entitlement_id, "credited_units": int(credit_units), "usage_limit": prior_limit + int(credit_units), "audit_event_id": evt["event_id"]}
