from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError

from app.core.settings import S
from app.core.tables import T
from app.services.alerts import write_alert


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


def _parse_thresholds(raw: str, *, clamp_min: float = 0.0, clamp_max: float = 1.0) -> List[float]:
    values: List[float] = []
    seen = set()
    for part in (raw or "").split(","):
        part = part.strip()
        if not part:
            continue
        try:
            value = float(part)
        except ValueError:
            continue
        if value < clamp_min or value > clamp_max:
            continue
        key = round(value, 6)
        if key in seen:
            continue
        seen.add(key)
        values.append(float(key))
    values.sort()
    return values


def _query_usage_events(entitlement_id: str, *, limit: int = 100) -> List[Dict[str, Any]]:
    resp = T.entitlement_usage_events.query(
        KeyConditionExpression=Key("entitlement_id").eq(entitlement_id),
        Limit=limit,
        ScanIndexForward=False,
    )
    return list(resp.get("Items", []))


def list_api_package_usage(user_id: str, *, status: Optional[str] = None) -> Dict[str, Any]:
    now = datetime.now(timezone.utc)
    ent_resp = T.entitlements.query(KeyConditionExpression=Key("user_id").eq(user_id))
    entitlements = [e for e in ent_resp.get("Items", []) if str(e.get("product_type") or "") == "api_package"]

    items: List[Dict[str, Any]] = []
    for ent in entitlements:
        entitlement_id = str(ent.get("entitlement_id") or "")
        if not entitlement_id:
            continue
        starts_at = _to_utc(ent.get("starts_at"))
        ends_at = _to_utc(ent.get("ends_at"))
        ent_status = str(ent.get("status") or "").lower() or "unknown"
        bucket = ent_status
        if ent_status == "active" and starts_at and now < starts_at:
            bucket = "upcoming"
        if ent_status == "active" and ends_at and now >= ends_at:
            bucket = "expired"
        if status and status != bucket:
            continue

        usage_limit = int(ent.get("usage_limit") or 0)
        usage_consumed = int(ent.get("usage_consumed") or 0)
        events = _query_usage_events(entitlement_id)
        ledger_consumed = sum(int(e.get("amount") or 0) for e in events)

        remaining = None if usage_limit <= 0 else max(0, usage_limit - usage_consumed)
        percent_used = None if usage_limit <= 0 else min(1.0, (usage_consumed / usage_limit if usage_limit else 0.0))

        items.append(
            {
                "entitlement_id": entitlement_id,
                "sku": ent.get("sku"),
                "status": bucket,
                "starts_at": ent.get("starts_at"),
                "ends_at": ent.get("ends_at"),
                "usage_limit": usage_limit,
                "usage_consumed": usage_consumed,
                "remaining": remaining,
                "percent_used": percent_used,
                "ledger_consumed": ledger_consumed,
                "ledger_matches": ledger_consumed == usage_consumed,
                "recent_usage_events": [
                    {
                        "event_id": e.get("event_id"),
                        "timestamp": e.get("timestamp") or e.get("event_ts"),
                        "meter": e.get("meter"),
                        "amount": int(e.get("amount") or 0),
                        "route_id": e.get("route_id"),
                        "idempotency_key": e.get("idempotency_key"),
                    }
                    for e in events
                ],
            }
        )

    items.sort(key=lambda x: str(x.get("entitlement_id") or ""))
    return {"items": items, "count": len(items), "generated_at": now.isoformat()}


def emit_usage_threshold_alerts(
    *,
    user_id: str,
    entitlement_id: str,
    sku: str,
    usage_limit: int,
    usage_consumed: int,
) -> None:
    if usage_limit <= 0:
        return

    used_ratio = max(0.0, min(1.0, usage_consumed / usage_limit))
    remaining_ratio = max(0.0, 1.0 - used_ratio)
    low_thresholds = sorted(_parse_thresholds(S.api_entitlement_low_balance_thresholds), reverse=True)
    near_cap_thresholds = _parse_thresholds(S.api_entitlement_near_cap_thresholds)

    candidates: List[str] = []
    for threshold in low_thresholds:
        if remaining_ratio <= threshold:
            candidates.append(f"low_balance:{threshold}")
    for threshold in near_cap_thresholds:
        if used_ratio >= threshold:
            candidates.append(f"near_cap:{threshold}")

    for marker in candidates:
        try:
            T.entitlements.update_item(
                Key={"user_id": user_id, "entitlement_id": entitlement_id},
                UpdateExpression="SET alert_markers = list_append(if_not_exists(alert_markers, :empty), :marker)",
                ConditionExpression="attribute_not_exists(alert_markers) OR NOT contains(alert_markers, :marker_val)",
                ExpressionAttributeValues={
                    ":empty": [],
                    ":marker": [marker],
                    ":marker_val": marker,
                },
            )
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code in {"ConditionalCheckFailedException", "TransactionCanceledException"}:
                continue
            raise

        write_alert(
            user_id,
            event="security_event",
            outcome="warning",
            title="API entitlement usage threshold reached",
            details={
                "entitlement_id": entitlement_id,
                "sku": sku,
                "marker": marker,
                "usage_limit": usage_limit,
                "usage_consumed": usage_consumed,
                "remaining": max(0, usage_limit - usage_consumed),
            },
        )
