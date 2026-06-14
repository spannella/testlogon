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


# ---------------------------------------------------------------------------
# Per-BOM routing tasks (MFG-005)
#
# Routing-task rows live on the mfg_boms partition (PK = bom_id) under
# SK = TASK#{seq:03d}. Each task names a work center and declares fixed setup
# time + per-unit run time. Storing them under the BOM partition lets the
# task list for a BOM be fetched with a single begins_with("TASK#") query and
# requires NO new table / GSI / schema change.
# ---------------------------------------------------------------------------

def _task_sk(sequence: int) -> str:
    return f"TASK#{int(sequence):03d}"


def _item_to_routing_task(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "bom_id": item.get("bom_id", ""),
        "sequence": int(item.get("sequence", 0)),
        "work_center_id": item.get("work_center_id", ""),
        "description": item.get("description", ""),
        "setup_minutes": int(item.get("setup_minutes", 0)),
        "run_minutes_per_unit": int(item.get("run_minutes_per_unit", 0)),
        "created_at": int(item.get("created_at", 0)),
        "updated_at": int(item.get("updated_at", 0)),
    }


def add_routing_task(
    bom_id: str,
    work_center_id: str,
    *,
    sequence: int,
    setup_minutes: int = 0,
    run_minutes_per_unit: int = 0,
    description: str = "",
    user_sub: str = "system",
) -> Dict[str, Any]:
    """Add a routing task to a BOM at the given sequence.

    Idempotent on (bom_id, sequence): a conditional put with
    attribute_not_exists(sk) makes a duplicate (bom_id, sequence) a 409 rather
    than a silent overwrite. Validates that work_center_id exists (422 if not).
    """
    _require_enabled()

    wc = get_work_center(work_center_id)
    if not wc:
        raise HTTPException(422, f"Unknown work center: {work_center_id}")

    ts = now_ts()
    item = {
        "bom_id": bom_id,
        "sk": _task_sk(sequence),
        "sequence": int(sequence),
        "work_center_id": work_center_id,
        "description": description,
        "setup_minutes": int(setup_minutes),
        "run_minutes_per_unit": int(run_minutes_per_unit),
        "created_at": ts,
        "updated_at": ts,
    }

    from boto3.dynamodb.conditions import Attr  # type: ignore
    try:
        T.mfg_boms.put_item(
            Item=item,
            ConditionExpression=Attr("sk").not_exists(),
        )
    except Exception as exc:
        code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
        if code == "ConditionalCheckFailedException":
            raise HTTPException(409, f"Routing task already exists at sequence {sequence} for BOM {bom_id}")
        raise

    _audit("mfg_routing_task.created", user_sub, bom_id=bom_id, work_center_id=work_center_id, sequence=sequence)
    return _item_to_routing_task(item)


def list_routing_tasks(bom_id: str) -> List[Dict[str, Any]]:
    """Return the ordered routing task list for a BOM (ascending sequence)."""
    _require_enabled()
    from boto3.dynamodb.conditions import Key  # type: ignore
    resp = T.mfg_boms.query(
        KeyConditionExpression=Key("bom_id").eq(bom_id) & Key("sk").begins_with("TASK#"),
    )
    items = resp.get("Items", [])
    items.sort(key=lambda x: int(x.get("sequence", 0)))
    return [_item_to_routing_task(it) for it in items]


def delete_routing_task(bom_id: str, sequence: int, *, user_sub: str = "system") -> None:
    """Delete a single routing task. Raises 404 if it does not exist."""
    _require_enabled()
    from boto3.dynamodb.conditions import Attr  # type: ignore
    try:
        T.mfg_boms.delete_item(
            Key={"bom_id": bom_id, "sk": _task_sk(sequence)},
            ConditionExpression=Attr("sk").exists(),
        )
    except Exception as exc:
        code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
        if code == "ConditionalCheckFailedException":
            raise HTTPException(404, f"Routing task not found at sequence {sequence} for BOM {bom_id}")
        raise
    _audit("mfg_routing_task.deleted", user_sub, bom_id=bom_id, sequence=sequence)


def compute_routing_time(bom_id: str, quantity: int) -> Dict[str, Any]:
    """Sum total labor minutes for producing `quantity` units across all routing
    tasks of a BOM: setup_minutes + run_minutes_per_unit * quantity per task.

    Returns {total_setup_minutes, total_run_minutes, total_minutes, tasks}.
    """
    _require_enabled()
    if quantity < 1:
        raise HTTPException(422, "quantity must be >= 1")

    tasks = list_routing_tasks(bom_id)
    total_setup = 0
    total_run = 0
    for t in tasks:
        total_setup += t["setup_minutes"]
        total_run += t["run_minutes_per_unit"] * quantity
    return {
        "bom_id": bom_id,
        "quantity": quantity,
        "total_setup_minutes": total_setup,
        "total_run_minutes": total_run,
        "total_minutes": total_setup + total_run,
        "tasks": tasks,
    }


def compute_routing_cost(bom_id: str, quantity: int) -> Dict[str, Any]:
    """Compute total labor cost (cents) for producing `quantity` units of a BOM.

    For each routing task: task_minutes = setup_minutes + run_minutes_per_unit
    * quantity; task_cost = ceil(task_minutes / 60 * work_center.cost_per_hour_cents).
    The cost rate comes from the referenced work center (reused via
    get_work_center). Returns the per-task breakdown plus totals.
    """
    _require_enabled()
    if quantity < 1:
        raise HTTPException(422, "quantity must be >= 1")

    import math

    tasks = list_routing_tasks(bom_id)
    # Cache work-center cost rates so we look up each center once.
    wc_cache: Dict[str, int] = {}
    total_setup = 0
    total_run = 0
    total_cost = 0
    breakdown: List[Dict[str, Any]] = []
    for t in tasks:
        wc_id = t["work_center_id"]
        if wc_id not in wc_cache:
            wc = get_work_center(wc_id)
            if not wc:
                raise HTTPException(422, f"Unknown work center: {wc_id}")
            wc_cache[wc_id] = wc["cost_per_hour_cents"]
        rate = wc_cache[wc_id]
        task_minutes = t["setup_minutes"] + t["run_minutes_per_unit"] * quantity
        task_cost = int(math.ceil(task_minutes / 60 * rate))
        total_setup += t["setup_minutes"]
        total_run += t["run_minutes_per_unit"] * quantity
        total_cost += task_cost
        breakdown.append({
            "sequence": t["sequence"],
            "work_center_id": wc_id,
            "task_minutes": task_minutes,
            "cost_per_hour_cents": rate,
            "task_cost_cents": task_cost,
        })
    return {
        "bom_id": bom_id,
        "quantity": quantity,
        "total_setup_minutes": total_setup,
        "total_run_minutes": total_run,
        "total_minutes": total_setup + total_run,
        "total_labor_cost_cents": total_cost,
        "tasks": breakdown,
    }


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
