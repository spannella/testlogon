"""
ATS — Job Order service layer (JOB-002, JOB-004, JOB-005).

Implements:
  • CRUD: create_job_order, get_job_order, update_job_order, delete_job_order
  • Status state-machine: set_status (7-state machine)
  • List views: list_open, list_hot, list_mine (cursor-paginated)
  • Placement counter: adjust_placed_count, get_openings_summary

All functions call _require_flag() first; callers do NOT need to gate on flags
themselves (the router also calls it for defence-in-depth).

No if-S.dev_mode branches — same code path dev (DynamoDB Local) and prod (real DDB).
"""
from __future__ import annotations

import logging
from decimal import Decimal
from typing import Any, Dict, List, Optional, Tuple
from uuid import uuid4

from boto3.dynamodb.conditions import Attr, Key
from fastapi import HTTPException

from app.core.cursor import decode_cursor, encode_cursor
from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.models import (
    JOB_ORDER_STATUSES,
    JOB_ORDER_TERMINAL,
    JOB_ORDER_TYPES,
    JobOrderCreateIn,
    JobOrderOut,
    JobOrderUpdateIn,
)
from app.services.alerts import audit_event

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_OPEN_STATUSES: Tuple[str, ...] = tuple(
    s for s in JOB_ORDER_STATUSES if s not in JOB_ORDER_TERMINAL
)
_DEFAULT_LIST_LIMIT: int = 50
_MAX_LIST_LIMIT: int = 200

# Allowed transitions from each non-terminal, non-canceled status
_ALLOWED_FROM: Dict[str, Tuple[str, ...]] = {
    "lead":     ("active",),
    "upcoming": ("active",),
    "active":   ("on_hold", "full", "closed", "canceled"),
    "on_hold":  ("active", "closed", "canceled"),
    "full":     ("closed", "canceled"),
}


# ---------------------------------------------------------------------------
# Feature flag guard
# ---------------------------------------------------------------------------

def _require_flag() -> None:
    """Raise HTTP 503 when either the master ATS gate or the job-orders sub-gate is off."""
    if not (S.ats_enabled and S.job_orders_enabled):
        raise HTTPException(503, detail={"code": "job_orders_disabled"})


# ---------------------------------------------------------------------------
# Internal helper: DynamoDB item → JobOrderOut
# ---------------------------------------------------------------------------

def _item_to_out(item: Dict[str, Any]) -> JobOrderOut:
    """Convert a raw DynamoDB item (Decimal numerics from _safe_table) to JobOrderOut."""
    openings = int(item.get("openings", 0))
    placed_count = int(item.get("placed_count", 0))
    return JobOrderOut(
        job_id=item["job_id"],
        title=item["title"],
        type=item["type"],
        status=item["status"],
        openings=openings,
        placed_count=placed_count,
        openings_remaining=max(openings - placed_count, 0),
        client_company_id=item["client_company_id"],
        client_contact_id=item.get("client_contact_id"),
        recruiter_subs=list(item.get("recruiter_subs", [])),
        hot=bool(item.get("hot_flag") == "1"),
        public=bool(item.get("public_flag") == "1"),
        pay_rate_cents=int(item["pay_rate_cents"]) if item.get("pay_rate_cents") is not None else None,
        bill_rate_cents=int(item["bill_rate_cents"]) if item.get("bill_rate_cents") is not None else None,
        duration=item.get("duration"),
        city=item.get("city"),
        state=item.get("state"),
        description=item.get("description"),
        created_by=item["created_by"],
        created_at=int(item["created_at"]),
        updated_at=int(item["updated_at"]),
    )


# ---------------------------------------------------------------------------
# JOB-002: CRUD
# ---------------------------------------------------------------------------

def create_job_order(actor_sub: str, data: JobOrderCreateIn) -> JobOrderOut:
    """Create a new Job Order and all per-recruiter index rows."""
    _require_flag()
    if data.type not in JOB_ORDER_TYPES:
        raise HTTPException(422, detail={"code": "invalid_type", "value": data.type})
    if data.status not in JOB_ORDER_STATUSES:
        raise HTTPException(422, detail={"code": "invalid_status", "value": data.status})

    job_id = "job_" + uuid4().hex
    ts = now_ts()
    pk = f"COMPANY#{data.client_company_id}"
    sk = f"JOB#{job_id}"

    meta_item: Dict[str, Any] = {
        "pk": pk,
        "sk": sk,
        "job_id": job_id,
        "title": data.title,
        "type": data.type,
        "status": data.status,
        "openings": data.openings,
        "placed_count": 0,
        "client_company_id": data.client_company_id,
        "recruiter_subs": data.recruiter_subs,
        "hot": data.hot,
        "public": data.public,
        "created_by": actor_sub,
        "created_at": ts,
        "updated_at": ts,
    }
    if data.client_contact_id is not None:
        meta_item["client_contact_id"] = data.client_contact_id
    if data.pay_rate_cents is not None:
        meta_item["pay_rate_cents"] = data.pay_rate_cents
    if data.bill_rate_cents is not None:
        meta_item["bill_rate_cents"] = data.bill_rate_cents
    if data.duration is not None:
        meta_item["duration"] = data.duration
    if data.city is not None:
        meta_item["city"] = data.city
    if data.state is not None:
        meta_item["state"] = data.state
    if data.description is not None:
        meta_item["description"] = data.description

    # Sparse GSI flags — only write attribute when True
    if data.hot:
        meta_item["hot_flag"] = "1"
    if data.public:
        meta_item["public_flag"] = "1"

    T.job_orders.put_item(Item=meta_item)

    # Write per-recruiter index rows
    for sub in data.recruiter_subs:
        T.job_orders.put_item(Item={
            "pk": pk,
            "sk": f"RECRUITER#{sub}#JOB#{job_id}",
            "recruiter_sub": sub,
            "job_id": job_id,
            "created_at": ts,
        })

    audit_event(
        "job_order.created",
        actor_sub,
        None,
        job_id=job_id,
        client_company_id=data.client_company_id,
        status=data.status,
        type=data.type,
    )
    return _item_to_out(meta_item)


def get_job_order(job_id: str) -> JobOrderOut:
    """Fetch a Job Order by its ID using GSI_DIRECT."""
    _require_flag()
    resp = T.job_orders.query(
        IndexName="GSI_DIRECT",
        KeyConditionExpression=Key("job_id").eq(job_id),
        Limit=1,
    )
    items = resp.get("Items", [])
    if not items or "deleted_at" in items[0]:
        raise HTTPException(404, detail={"code": "job_order_not_found", "job_id": job_id})
    return _item_to_out(items[0])


def _get_meta_item(job_id: str) -> Dict[str, Any]:
    """
    Return the raw DDB META item for a job order (no _require_flag — caller must call it).
    Raises HTTPException(404) for unknown or deleted orders.
    """
    resp = T.job_orders.query(
        IndexName="GSI_DIRECT",
        KeyConditionExpression=Key("job_id").eq(job_id),
        Limit=1,
    )
    items = resp.get("Items", [])
    if not items or "deleted_at" in items[0]:
        raise HTTPException(404, detail={"code": "job_order_not_found", "job_id": job_id})
    return items[0]


def update_job_order(
    actor_sub: str,
    job_id: str,
    data: JobOrderUpdateIn,
) -> JobOrderOut:
    """Partial-update a Job Order. Status changes are delegated to set_status."""
    _require_flag()

    current_item = _get_meta_item(job_id)
    pk = current_item["pk"]
    sk = current_item["sk"]
    prev_updated_at = int(current_item["updated_at"])

    # Delegate status changes through the state-machine guard
    if data.status is not None and data.status != current_item["status"]:
        set_status(actor_sub, job_id, data.status)
        # Re-fetch after status change to get updated item
        current_item = _get_meta_item(job_id)
        prev_updated_at = int(current_item["updated_at"])

    # Build the update expression for non-status fields
    set_parts: List[str] = []
    remove_parts: List[str] = []
    expr_names: Dict[str, str] = {}
    expr_values: Dict[str, Any] = {}
    changed_fields: List[str] = []

    scalar_fields = [
        "title", "openings", "client_company_id", "client_contact_id",
        "pay_rate_cents", "bill_rate_cents", "duration", "city", "state", "description",
    ]
    for field in scalar_fields:
        val = getattr(data, field, None)
        if val is not None:
            safe = f"#{field}"
            expr_names[safe] = field
            expr_values[f":{field}"] = val
            set_parts.append(f"{safe} = :{field}")
            changed_fields.append(field)

    # recruiter_subs reconciliation
    if data.recruiter_subs is not None:
        old_set = set(current_item.get("recruiter_subs", []))
        new_set = set(data.recruiter_subs)
        added = new_set - old_set
        removed = old_set - new_set
        ts_now = now_ts()
        for sub in added:
            T.job_orders.put_item(Item={
                "pk": pk,
                "sk": f"RECRUITER#{sub}#JOB#{job_id}",
                "recruiter_sub": sub,
                "job_id": job_id,
                "created_at": ts_now,
            })
        for sub in removed:
            T.job_orders.delete_item(Key={
                "pk": pk,
                "sk": f"RECRUITER#{sub}#JOB#{job_id}",
            })
        expr_values[":recruiter_subs"] = data.recruiter_subs
        set_parts.append("#recruiter_subs = :recruiter_subs")
        expr_names["#recruiter_subs"] = "recruiter_subs"
        changed_fields.append("recruiter_subs")

    # hot flag handling (sparse GSI_HOT)
    if data.hot is not None:
        if data.hot:
            set_parts.append("hot_flag = :hot_flag_val")
            expr_values[":hot_flag_val"] = "1"
            set_parts.append("#hot = :hot_bool")
            expr_names["#hot"] = "hot"
            expr_values[":hot_bool"] = True
        else:
            remove_parts.append("hot_flag")
            set_parts.append("#hot = :hot_bool")
            expr_names["#hot"] = "hot"
            expr_values[":hot_bool"] = False
        changed_fields.append("hot")

    # public flag handling (sparse GSI_PUBLIC)
    if data.public is not None:
        if data.public:
            set_parts.append("public_flag = :public_flag_val")
            expr_values[":public_flag_val"] = "1"
            set_parts.append("#public = :public_bool")
            expr_names["#public"] = "public"
            expr_values[":public_bool"] = True
        else:
            remove_parts.append("public_flag")
            set_parts.append("#public = :public_bool")
            expr_names["#public"] = "public"
            expr_values[":public_bool"] = False
        changed_fields.append("public")

    # Always bump updated_at
    new_ts = now_ts()
    set_parts.append("updated_at = :updated_at")
    expr_values[":updated_at"] = new_ts
    # :prev_updated_at is used in ConditionExpression separately (not in UpdateExpression)

    if not set_parts and not remove_parts:
        # Nothing to update
        return get_job_order(job_id)

    update_expr = "SET " + ", ".join(set_parts)
    if remove_parts:
        update_expr += " REMOVE " + ", ".join(remove_parts)

    # Keep condition value in its own dict so DynamoDB doesn't complain about
    # an unused ExpressionAttributeValues key in the UpdateExpression.
    condition_values = {":prev_updated_at": prev_updated_at}
    # Merge — DynamoDB allows both sets in the same call as long as each
    # placeholder is referenced in either UpdateExpression OR ConditionExpression.
    # However some DynamoDB versions complain if a key appears in EVals but not
    # in UpdateExpression. Keep them separate using a single merged dict since
    # boto3 passes ExpressionAttributeValues to both expressions in one call.
    all_expr_values = {**expr_values, **condition_values}

    try:
        kwargs: Dict[str, Any] = {
            "Key": {"pk": pk, "sk": sk},
            "UpdateExpression": update_expr,
            "ConditionExpression": "updated_at = :prev_updated_at",
            "ExpressionAttributeValues": all_expr_values,
        }
        if expr_names:
            kwargs["ExpressionAttributeNames"] = expr_names
        T.job_orders.update_item(**kwargs)
    except T.job_orders.meta.client.exceptions.ConditionalCheckFailedException:
        raise HTTPException(409, detail={"code": "job_order_conflict"})

    audit_event(
        "job_order.updated",
        actor_sub,
        None,
        job_id=job_id,
        fields=changed_fields,
    )
    return get_job_order(job_id)


def set_status(
    actor_sub: str,
    job_id: str,
    new_status: str,
) -> JobOrderOut:
    """
    Transition a Job Order to a new status via the 7-state state-machine.

    Raises:
        HTTPException(422): unknown new_status value
        HTTPException(409): illegal transition or reopen disabled
        HTTPException(404): job not found
    """
    _require_flag()
    current_item = _get_meta_item(job_id)
    current_status = current_item["status"]

    # Same-status no-op
    if new_status == current_status:
        return _item_to_out(current_item)

    # Validate new_status is known
    if new_status not in JOB_ORDER_STATUSES:
        raise HTTPException(422, detail={"code": "invalid_status", "value": new_status})

    # Evaluate the transition
    if current_status == "canceled":
        raise HTTPException(409, detail={
            "code": "invalid_status_transition",
            "from": current_status,
            "to": new_status,
        })

    if current_status == "closed":
        if new_status != "active":
            raise HTTPException(409, detail={
                "code": "invalid_status_transition",
                "from": current_status,
                "to": new_status,
            })
        if not S.job_order_allow_reopen:
            raise HTTPException(409, detail={
                "code": "reopen_not_allowed",
                "from": current_status,
                "to": new_status,
            })
    elif new_status not in _ALLOWED_FROM.get(current_status, ()):
        raise HTTPException(409, detail={
            "code": "invalid_status_transition",
            "from": current_status,
            "to": new_status,
        })

    # Write the transition
    pk = current_item["pk"]
    sk = current_item["sk"]
    T.job_orders.update_item(
        Key={"pk": pk, "sk": sk},
        UpdateExpression="SET #status = :s, updated_at = :ts",
        ExpressionAttributeNames={"#status": "status"},
        ExpressionAttributeValues={":s": new_status, ":ts": now_ts()},
    )
    audit_event(
        "job_order.status_changed",
        actor_sub,
        None,
        job_id=job_id,
        from_status=current_status,
        to_status=new_status,
    )
    return get_job_order(job_id)


def delete_job_order(actor_sub: str, job_id: str) -> None:
    """Soft-delete a Job Order (sets deleted_at; removes recruiter index rows)."""
    _require_flag()
    current_item = _get_meta_item(job_id)
    pk = current_item["pk"]
    sk = current_item["sk"]
    client_company_id = current_item["client_company_id"]
    ts = now_ts()

    # Soft-delete META row
    T.job_orders.update_item(
        Key={"pk": pk, "sk": sk},
        UpdateExpression="SET deleted_at = :da, updated_at = :ts",
        ExpressionAttributeValues={":da": ts, ":ts": ts},
    )

    # Remove all per-recruiter index rows
    for sub in current_item.get("recruiter_subs", []):
        try:
            T.job_orders.delete_item(Key={
                "pk": pk,
                "sk": f"RECRUITER#{sub}#JOB#{job_id}",
            })
        except Exception:
            pass

    audit_event(
        "job_order.deleted",
        actor_sub,
        None,
        job_id=job_id,
        client_company_id=client_company_id,
    )


# ---------------------------------------------------------------------------
# JOB-004: List views
# ---------------------------------------------------------------------------

def list_open(
    cursor: Optional[str] = None,
    limit: int = _DEFAULT_LIST_LIMIT,
    *,
    company_id: Optional[str] = None,
    status: Optional[str] = None,
) -> Tuple[List[JobOrderOut], Optional[str]]:
    """Return non-terminal, non-deleted job orders, newest-first (cursor-paginated)."""
    _require_flag()
    limit = max(1, min(limit, _MAX_LIST_LIMIT))

    if status is not None:
        if status in JOB_ORDER_TERMINAL:
            raise HTTPException(400, detail={
                "code": "invalid_status_filter",
                "allowed": list(_OPEN_STATUSES),
            })
        if status not in _OPEN_STATUSES:
            raise HTTPException(400, detail={
                "code": "invalid_status_filter",
                "allowed": list(_OPEN_STATUSES),
            })

    # Single-status mode: straightforward cursor
    if status is not None:
        esk = decode_cursor(cursor) if cursor else None
        items: List[JobOrderOut] = []
        last_key: Optional[Dict[str, Any]] = None

        deleted_filter = Attr("deleted_at").not_exists()
        company_filter = Attr("client_company_id").eq(company_id) if company_id else None
        filter_expr = deleted_filter & company_filter if company_filter else deleted_filter

        query_kwargs: Dict[str, Any] = {
            "IndexName": "GSI_BY_STATUS",
            "KeyConditionExpression": Key("status").eq(status),
            "FilterExpression": filter_expr,
            "ScanIndexForward": False,
            "Limit": limit * 3,
        }
        if esk:
            query_kwargs["ExclusiveStartKey"] = esk

        while len(items) < limit:
            resp = T.job_orders.query(**query_kwargs)
            for raw in resp.get("Items", []):
                if len(items) >= limit:
                    break
                items.append(_item_to_out(raw))
            last_key = resp.get("LastEvaluatedKey")
            if not last_key:
                break
            query_kwargs["ExclusiveStartKey"] = last_key
            query_kwargs.pop("Limit", None)

        next_cursor = encode_cursor(last_key) if last_key and len(items) >= limit else None
        return items[:limit], next_cursor

    # Multi-status mode: query each non-terminal status, merge, re-sort
    # Decode per-status cursor dict from the cursor payload
    per_status_keys: Dict[str, Optional[Dict[str, Any]]] = {}
    if cursor:
        decoded = decode_cursor(cursor)
        if isinstance(decoded, dict) and "per_status" in decoded:
            per_status_keys = decoded["per_status"]

    all_items: List[JobOrderOut] = []

    deleted_filter = Attr("deleted_at").not_exists()
    company_filter = Attr("client_company_id").eq(company_id) if company_id else None
    filter_expr = deleted_filter & company_filter if company_filter else deleted_filter

    new_per_status_keys: Dict[str, Optional[Dict[str, Any]]] = {}

    for s in _OPEN_STATUSES:
        esk = per_status_keys.get(s)
        if esk is False:  # exhausted marker
            new_per_status_keys[s] = False
            continue

        q_kwargs: Dict[str, Any] = {
            "IndexName": "GSI_BY_STATUS",
            "KeyConditionExpression": Key("status").eq(s),
            "FilterExpression": filter_expr,
            "ScanIndexForward": False,
            "Limit": limit * 3,
        }
        if esk:
            q_kwargs["ExclusiveStartKey"] = esk

        last_k: Optional[Dict[str, Any]] = None
        status_items: List[JobOrderOut] = []
        while len(status_items) < limit:
            resp = T.job_orders.query(**q_kwargs)
            for raw in resp.get("Items", []):
                if len(status_items) >= limit:
                    break
                status_items.append(_item_to_out(raw))
            last_k = resp.get("LastEvaluatedKey")
            if not last_k:
                break
            q_kwargs["ExclusiveStartKey"] = last_k
            q_kwargs.pop("Limit", None)

        all_items.extend(status_items)
        new_per_status_keys[s] = last_k if last_k else False

    # Sort merged results by created_at descending
    all_items.sort(key=lambda o: o.created_at, reverse=True)
    page = all_items[:limit]

    has_more = any(v and v is not False for v in new_per_status_keys.values())
    next_cursor: Optional[str] = None
    if has_more or len(all_items) > limit:
        next_cursor = encode_cursor({"per_status": new_per_status_keys})

    return page, next_cursor


def list_hot(
    cursor: Optional[str] = None,
    limit: int = _DEFAULT_LIST_LIMIT,
) -> Tuple[List[JobOrderOut], Optional[str]]:
    """Return hot-flagged, non-deleted job orders, newest-first."""
    _require_flag()
    limit = max(1, min(limit, _MAX_LIST_LIMIT))

    esk = decode_cursor(cursor) if cursor else None
    items: List[JobOrderOut] = []
    last_key: Optional[Dict[str, Any]] = None

    query_kwargs: Dict[str, Any] = {
        "IndexName": "GSI_HOT",
        "KeyConditionExpression": Key("hot_flag").eq("1"),
        "FilterExpression": Attr("deleted_at").not_exists(),
        "ScanIndexForward": False,
        "Limit": limit * 3,
    }
    if esk:
        query_kwargs["ExclusiveStartKey"] = esk

    while len(items) < limit:
        resp = T.job_orders.query(**query_kwargs)
        for raw in resp.get("Items", []):
            if len(items) >= limit:
                break
            items.append(_item_to_out(raw))
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break
        query_kwargs["ExclusiveStartKey"] = last_key
        query_kwargs.pop("Limit", None)

    next_cursor: Optional[str] = encode_cursor(last_key) if (last_key and len(items) >= limit) else None
    return items[:limit], next_cursor


def list_mine(
    recruiter_sub: str,
    cursor: Optional[str] = None,
    limit: int = _DEFAULT_LIST_LIMIT,
) -> Tuple[List[JobOrderOut], Optional[str]]:
    """Return job orders assigned to recruiter_sub, newest-first."""
    _require_flag()
    limit = max(1, min(limit, _MAX_LIST_LIMIT))

    esk = decode_cursor(cursor) if cursor else None
    items: List[JobOrderOut] = []
    last_key: Optional[Dict[str, Any]] = None

    query_kwargs: Dict[str, Any] = {
        "IndexName": "GSI_BY_RECRUITER",
        "KeyConditionExpression": Key("recruiter_sub").eq(recruiter_sub),
        "ScanIndexForward": False,
        "Limit": limit * 2,
    }
    if esk:
        query_kwargs["ExclusiveStartKey"] = esk

    while len(items) < limit:
        resp = T.job_orders.query(**query_kwargs)
        for raw in resp.get("Items", []):
            if len(items) >= limit:
                break
            idx_job_id = raw.get("job_id")
            if not idx_job_id:
                continue
            try:
                out = get_job_order(idx_job_id)
                items.append(out)
            except HTTPException as exc:
                if exc.status_code == 404:
                    continue  # stale index row — skip
                raise
            except Exception:
                logger.warning("list_mine: failed to resolve job_id=%s", idx_job_id)
                continue
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break
        query_kwargs["ExclusiveStartKey"] = last_key
        query_kwargs.pop("Limit", None)

    next_cursor: Optional[str] = encode_cursor(last_key) if (last_key and len(items) >= limit) else None
    return items[:limit], next_cursor


# ---------------------------------------------------------------------------
# JOB-005: Placement counter
# ---------------------------------------------------------------------------

def adjust_placed_count(
    job_id: str,
    delta: int,
    *,
    actor_sub: str,
    candidate_ref: Optional[str] = None,
) -> JobOrderOut:
    """
    Atomically add delta (+1 or -1) to placed_count on the META row,
    clamped at >= 0. Auto-advances status to "full" when openings_remaining
    reaches 0 on an active order.

    Raises:
        HTTPException(404): job_id not found or soft-deleted
        HTTPException(409): delta would push placed_count below 0 (code: placed_count_underflow)
        HTTPException(503): either ATS flag is off
    """
    _require_flag()
    current_item = _get_meta_item(job_id)
    pk = current_item["pk"]
    sk = current_item["sk"]
    current_placed = int(current_item.get("placed_count", 0))

    # Pre-flight underflow guard
    if delta < 0 and current_placed + delta < 0:
        raise HTTPException(409, detail={
            "code": "placed_count_underflow",
            "placed_count": current_placed,
            "delta": delta,
        })

    # Atomic ADD with DynamoDB-level underflow protection for decrements
    if delta < 0:
        condition = Attr("placed_count").gte(-delta)
    else:
        condition = Attr("pk").exists()

    try:
        T.job_orders.update_item(
            Key={"pk": pk, "sk": sk},
            UpdateExpression="ADD placed_count :d SET updated_at = :ts",
            ConditionExpression=condition,
            ExpressionAttributeValues={":d": delta, ":ts": now_ts()},
        )
    except Exception as exc:
        err_code = getattr(getattr(exc, "response", {}), "get", lambda *a: None)(
            "Error", {}
        ).get("Code", "")
        # boto3 client exceptions
        if "ConditionalCheckFailedException" in str(type(exc).__name__) or err_code == "ConditionalCheckFailedException":
            raise HTTPException(409, detail={"code": "placed_count_underflow"})
        # Try the exception chain for moto
        resp = getattr(exc, "response", {})
        if isinstance(resp, dict) and resp.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            raise HTTPException(409, detail={"code": "placed_count_underflow"})
        raise

    # Re-read to get post-write values
    updated_out = get_job_order(job_id)

    # Auto-full side-effect: active + placed_count >= openings > 0
    if (
        updated_out.openings > 0
        and updated_out.placed_count >= updated_out.openings
        and current_item["status"] == "active"
    ):
        try:
            set_status(actor_sub, job_id, "full")
        except HTTPException:
            pass  # already full (same-status no-op) or transition rejected

    audit_event(
        "job_order.placement_adjusted",
        actor_sub,
        None,
        job_id=job_id,
        delta=delta,
        candidate_ref=candidate_ref,
        placed_count=updated_out.placed_count,
    )
    return get_job_order(job_id)


def get_openings_summary(job_id: str) -> Dict[str, int]:
    """
    Return lightweight openings summary dict.

    Returns:
        {"openings": int, "placed_count": int, "openings_remaining": int}
    """
    _require_flag()
    out = get_job_order(job_id)
    return {
        "openings": out.openings,
        "placed_count": out.placed_count,
        "openings_remaining": out.openings_remaining,
    }
