"""MFG-005 — Work-center / routing service.

Owns CRUD for work centers (production stations). These are referenced by work
orders to associate a production run with a physical work center. The routing
cost estimate is used by MFG-008 for GL cost posting.
"""
from __future__ import annotations

import uuid
from typing import Any, Dict, List, Optional

from fastapi import HTTPException

from app.core.tables import T
from app.core.settings import S
from app.core.time import now_ts


def _flag_on() -> bool:
    return bool(getattr(S, "manufacturing_mrp_enabled", False))


def _require_enabled() -> None:
    if not _flag_on():
        raise HTTPException(status_code=404, detail="Manufacturing/MRP not enabled")


def _audit(event: str, user_sub: str, **fields: Any) -> None:
    try:
        from app.services.alerts import audit_event  # type: ignore
        audit_event(event, user_sub, None, **fields)
    except Exception:
        pass


def _item_to_work_center(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "work_center_id": item["work_center_id"],
        "name": item.get("name", ""),
        "capacity_per_hour": int(item.get("capacity_per_hour", 0)),
        "cost_per_hour_cents": int(item.get("cost_per_hour_cents", 0)),
        "status": item.get("status", "active"),
        "created_at": int(item.get("created_at", 0)),
        "updated_at": int(item.get("updated_at", 0)),
    }


def create_work_center(
    name: str,
    capacity_per_hour: int,
    cost_per_hour_cents: int,
    *,
    correlation_id: Optional[str] = None,
    user_sub: str = "system",
) -> Dict[str, Any]:
    _require_enabled()

    import hashlib
    if correlation_id:
        wc_id = hashlib.sha256(correlation_id.encode()).hexdigest()[:32]
    else:
        wc_id = uuid.uuid4().hex

    ts = now_ts()
    item = {
        "work_center_id": wc_id,
        "sk": "META",
        "name": name,
        "capacity_per_hour": capacity_per_hour,
        "cost_per_hour_cents": cost_per_hour_cents,
        "status": "active",
        "created_at": ts,
        "updated_at": ts,
        "created_by": user_sub,
    }
    if correlation_id:
        item["correlation_id"] = correlation_id

    from boto3.dynamodb.conditions import Attr  # type: ignore
    try:
        T.mfg_work_centers.put_item(
            Item=item,
            ConditionExpression=Attr("work_center_id").not_exists(),
        )
    except Exception as exc:
        code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
        if code == "ConditionalCheckFailedException":
            raise HTTPException(409, f"Work center already exists: {wc_id}")
        raise

    _audit("mfg_work_center.created", user_sub, work_center_id=wc_id)
    return _item_to_work_center(item)


def get_work_center(work_center_id: str) -> Optional[Dict[str, Any]]:
    _require_enabled()
    resp = T.mfg_work_centers.get_item(Key={"work_center_id": work_center_id, "sk": "META"})
    item = resp.get("Item")
    return _item_to_work_center(item) if item else None


def list_work_centers(status: str = "active") -> List[Dict[str, Any]]:
    _require_enabled()
    from boto3.dynamodb.conditions import Key  # type: ignore
    resp = T.mfg_work_centers.query(
        IndexName="GSI_STATUS",
        KeyConditionExpression=Key("status").eq(status),
        ScanIndexForward=False,
    )
    items = [it for it in resp.get("Items", []) if it.get("sk") == "META"]
    return [_item_to_work_center(it) for it in items]


def update_work_center(
    work_center_id: str,
    *,
    name: Optional[str] = None,
    capacity_per_hour: Optional[int] = None,
    cost_per_hour_cents: Optional[int] = None,
    status: Optional[str] = None,
    user_sub: str = "system",
) -> Dict[str, Any]:
    _require_enabled()

    existing = get_work_center(work_center_id)
    if not existing:
        raise HTTPException(404, f"Work center not found: {work_center_id}")

    ts = now_ts()
    parts = ["#ua = :ua"]
    names: Dict[str, str] = {"#ua": "updated_at"}
    vals: Dict[str, Any] = {":ua": ts}

    if name is not None:
        parts.append("#nm = :nm")
        names["#nm"] = "name"
        vals[":nm"] = name

    if capacity_per_hour is not None:
        parts.append("capacity_per_hour = :cap")
        vals[":cap"] = capacity_per_hour

    if cost_per_hour_cents is not None:
        parts.append("cost_per_hour_cents = :cph")
        vals[":cph"] = cost_per_hour_cents

    if status is not None:
        valid = {"active", "inactive"}
        if status not in valid:
            raise HTTPException(422, f"Invalid status: {status}")
        parts.append("#st = :st")
        names["#st"] = "status"
        vals[":st"] = status

    T.mfg_work_centers.update_item(
        Key={"work_center_id": work_center_id, "sk": "META"},
        UpdateExpression="SET " + ", ".join(parts),
        ExpressionAttributeNames=names,
        ExpressionAttributeValues=vals,
    )
    _audit("mfg_work_center.updated", user_sub, work_center_id=work_center_id)
    return get_work_center(work_center_id)  # type: ignore[return-value]


def estimate_routing_cost(work_center_id: str, build_qty: int) -> Dict[str, Any]:
    """Estimate labor cost for producing build_qty units at the given work center.

    Returns {total_minutes, total_cost_cents}. Capacity_per_hour of 0 means
    unlimited — cost defaults to cost_per_hour_cents per hour of production
    time at 1 unit/hour.
    """
    _require_enabled()
    wc = get_work_center(work_center_id)
    if not wc:
        raise HTTPException(404, f"Work center not found: {work_center_id}")

    cap = wc["capacity_per_hour"]
    if cap <= 0:
        cap = 1  # treat unlimited as 1 unit/hour for costing
    hours = build_qty / cap
    total_minutes = int(hours * 60)
    total_cost_cents = int(hours * wc["cost_per_hour_cents"])
    return {"total_minutes": total_minutes, "total_cost_cents": total_cost_cents}
