from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Key

from app.core.tables import T


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


def _status_bucket(ent: Dict[str, Any], *, now: datetime) -> str:
    status = str(ent.get("status") or "").lower()
    starts_at = _to_utc(ent.get("starts_at"))
    ends_at = _to_utc(ent.get("ends_at"))

    if status in {"revoked", "consumed"}:
        return status
    if status == "expired":
        return "expired"
    if starts_at and now < starts_at:
        return "upcoming"
    if ends_at and now >= ends_at:
        return "expired"
    if status in {"active", "pending_payment"}:
        return "active" if status == "active" else "upcoming"
    return "unknown"


def _scope_metadata(ent: Dict[str, Any]) -> Dict[str, Any]:
    scope = ent.get("scope") if isinstance(ent.get("scope"), dict) else {}
    return {
        "selection_type": scope.get("selection_type"),
        "date_start": scope.get("date_start"),
        "date_end": scope.get("date_end"),
        "access_mode": scope.get("access_mode"),
        "resource": scope.get("resource"),
    }


def _source_attribution(ent: Dict[str, Any]) -> Dict[str, Any]:
    scope = ent.get("scope") if isinstance(ent.get("scope"), dict) else {}
    sub_scope = scope.get("subscription") if isinstance(scope.get("subscription"), dict) else {}

    subscription_id = ent.get("subscription_id") or sub_scope.get("subscription_id")
    source_system = ent.get("source_system") or sub_scope.get("source_system")
    if not source_system and subscription_id:
        source_system = "subscription_cycle"

    order_id = ent.get("order_id") or sub_scope.get("order_id")
    billing_metadata = {
        "invoice_id": ent.get("invoice_id") or sub_scope.get("invoice_id"),
        "provider_invoice_id": ent.get("provider_invoice_id") or sub_scope.get("provider_invoice_id"),
        "payment_provider": ent.get("payment_provider") or sub_scope.get("payment_provider"),
        "payment_event_id": ent.get("payment_event_id") or sub_scope.get("payment_event_id"),
    }

    return {
        "source_system": source_system,
        "order_id": order_id,
        "subscription_id": subscription_id,
        "billing_metadata": billing_metadata,
    }


def list_user_entitlements(
    user_id: str,
    *,
    product_type: Optional[str] = None,
    status: Optional[str] = None,
    source_system: Optional[str] = None,
    lifecycle_status: Optional[str] = None,
) -> Dict[str, Any]:
    resp = T.entitlements.query(KeyConditionExpression=Key("user_id").eq(user_id))
    items = list(resp.get("Items", []))
    now = datetime.now(timezone.utc)

    desired_status = lifecycle_status or status

    out: List[Dict[str, Any]] = []
    for ent in items:
        ent_product_type = str(ent.get("product_type") or "")
        if product_type and ent_product_type != product_type:
            continue

        bucket = _status_bucket(ent, now=now)
        if desired_status and bucket != desired_status:
            continue

        attribution = _source_attribution(ent)
        if source_system and str(attribution.get("source_system") or "") != source_system:
            continue

        denial_reason_hint = None
        if bucket == "expired":
            denial_reason_hint = "expired_entitlement"
        elif bucket in {"revoked", "consumed"}:
            denial_reason_hint = "no_entitlement"

        out.append(
            {
                "entitlement_id": ent.get("entitlement_id"),
                "sku": ent.get("sku"),
                "product_type": ent_product_type,
                "status": bucket,
                "starts_at": ent.get("starts_at"),
                "ends_at": ent.get("ends_at"),
                "usage_limit": int(ent.get("usage_limit") or 0),
                "usage_consumed": int(ent.get("usage_consumed") or 0),
                "scope": _scope_metadata(ent),
                "source_system": attribution.get("source_system"),
                "order_id": attribution.get("order_id"),
                "subscription_id": attribution.get("subscription_id"),
                "billing_metadata": attribution.get("billing_metadata"),
                "denial_reason_hint": denial_reason_hint,
            }
        )

    order = {"active": 0, "upcoming": 1, "expired": 2, "revoked": 3, "consumed": 4, "unknown": 5}
    out.sort(key=lambda e: (order.get(str(e.get("status")), 99), str(e.get("starts_at") or ""), str(e.get("entitlement_id") or "")))
    return {"items": out, "count": len(out), "generated_at": now.isoformat()}
