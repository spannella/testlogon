"""
Maintenance Work Orders service — WOV-001, WOV-002, WOV-003.

WOV-001: entity, table, flag, create+get
WOV-002: lifecycle (assign/schedule/transition/list) + board-column helper
WOV-003: optional escrowed paid maintenance (sub-flag MAINTENANCE_ORDERS_ESCROW_ENABLED)
"""
from __future__ import annotations

import hashlib
import logging
from decimal import Decimal
from typing import Any, Dict, Optional
from uuid import uuid4

from boto3.dynamodb.conditions import Attr, Key
from botocore.exceptions import ClientError
from fastapi import HTTPException

from app.core.tables import T
from app.core.time import now_ts
from app.core.cursor import encode_cursor, decode_cursor
from app.models import (
    MaintenanceOrderAssignIn,
    MaintenanceOrderIn,
    MaintenanceOrderOut,
    MaintenanceOrderScheduleIn,
    MaintenanceOrderTransitionIn,
    WoListOut,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

WO_PRIORITIES: frozenset[str] = frozenset({"urgent", "high", "normal", "low"})
WO_STATUSES: frozenset[str] = frozenset({"open", "assigned", "in_progress", "completed", "cancelled"})

VALID_TRANSITIONS: Dict[str, set] = {
    "open": {"assigned", "in_progress", "cancelled"},
    "assigned": {"in_progress", "open", "cancelled"},
    "in_progress": {"completed", "cancelled"},
    "completed": set(),
    "cancelled": set(),
}

_DEFAULT_WO_COLUMNS: tuple = (
    {"column_id": "wo_open", "title": "Open", "status_key": "open", "order": 0},
    {"column_id": "wo_assigned", "title": "Assigned", "status_key": "assigned", "order": 1},
    {"column_id": "wo_in_progress", "title": "In Progress", "status_key": "in_progress", "order": 2},
    {"column_id": "wo_completed", "title": "Completed", "status_key": "completed", "order": 3},
    {"column_id": "wo_cancelled", "title": "Cancelled", "status_key": "cancelled", "order": 4},
)

# WOV-003: reserved clearing account sub (never a real user)
MAINT_CLEARING_SUB = "CLEARING#maintenance"

# ---------------------------------------------------------------------------
# Flag helpers
# ---------------------------------------------------------------------------


def _flag_on() -> bool:
    from app.core.settings import S
    return bool(getattr(S, "maintenance_orders_enabled", False))


def _require_enabled() -> None:
    if not _flag_on():
        raise HTTPException(status_code=404, detail="Maintenance work orders are not enabled")


def _escrow_enabled() -> bool:
    from app.core.settings import S
    return bool(getattr(S, "maintenance_orders_escrow_enabled", False))


def _require_escrow_enabled() -> None:
    if not _escrow_enabled():
        raise HTTPException(status_code=404, detail="Maintenance order escrow is not enabled")


# ---------------------------------------------------------------------------
# Key helpers
# ---------------------------------------------------------------------------


def _wo_pk(property_id: str) -> str:
    return f"PROPERTY#{property_id}"


def _wo_sk(work_order_id: str) -> str:
    return f"WO#{work_order_id}"


def _escrow_pk(work_order_id: str) -> str:
    return f"MAINT_ESCROW#{work_order_id}"


# ---------------------------------------------------------------------------
# Utility helpers (WOV-001 §4.3 / inventory.py pattern)
# ---------------------------------------------------------------------------


def _to_int(value: Any, default: int = 0) -> int:
    try:
        if value is None:
            return default
        return int(value)
    except (TypeError, ValueError):
        return default


def _audit(event: str, user_sub: str, **fields: Any) -> None:
    try:
        from app.services.alerts import audit_event
        audit_event(event, user_sub or "system", None, **fields)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Item serialization
# ---------------------------------------------------------------------------


def _item_to_out(item: Dict[str, Any]) -> MaintenanceOrderOut:
    return MaintenanceOrderOut(
        work_order_id=item["work_order_id"],
        property_id=item["property_id"],
        unit_id=item.get("unit_id"),
        vendor_id=item.get("vendor_id"),
        assignee_sub=item.get("assignee_sub"),
        title=item["title"],
        description=item.get("description"),
        priority=item.get("priority", "normal"),
        wo_status=item["wo_status"],
        scheduled_for=_to_int(item["scheduled_for"]) if item.get("scheduled_for") is not None else None,
        cost_cents=_to_int(item["cost_cents"]) if item.get("cost_cents") is not None else None,
        created_at=_to_int(item.get("created_at", 0)),
        updated_at=_to_int(item.get("updated_at", 0)),
        completed_at=_to_int(item["completed_at"]) if item.get("completed_at") is not None else None,
        correlation_id=item["correlation_id"],
        actor_sub=item["actor_sub"],
        escrow_amount_cents=_to_int(item["escrow_amount_cents"]) if item.get("escrow_amount_cents") is not None else None,
        escrow_status=item.get("escrow_status"),
    )


# ---------------------------------------------------------------------------
# Board column helper (WOV-001 §5.7)
# ---------------------------------------------------------------------------


def default_wo_columns() -> list:
    return [dict(c) for c in _DEFAULT_WO_COLUMNS]


# ---------------------------------------------------------------------------
# WOV-001: create + get
# ---------------------------------------------------------------------------


def create_work_order(property_id: str, body: MaintenanceOrderIn, actor_sub: str) -> MaintenanceOrderOut:
    _require_enabled()

    if body.priority not in WO_PRIORITIES:
        raise HTTPException(status_code=422, detail={"code": "invalid_priority", "allowed": sorted(WO_PRIORITIES)})

    # Lazy property FK validation (PROP-001 may not be built yet)
    try:
        from app.services.property_mgmt import get_property  # type: ignore[import]
        prop = get_property(property_id)
        if prop is None:
            raise HTTPException(status_code=404, detail="property_not_found")
    except ImportError:
        logger.warning("property_mgmt not available; skipping property FK validation for WO create")

    corr = body.correlation_id or f"wo:{actor_sub}:{uuid4().hex}"
    work_order_id = hashlib.sha256(corr.encode()).hexdigest()[:32]

    ts = now_ts()
    item: Dict[str, Any] = {
        "pk": _wo_pk(property_id),
        "sk": _wo_sk(work_order_id),
        "work_order_id": work_order_id,
        "property_id": property_id,
        "title": body.title,
        "priority": body.priority,
        "wo_status": "open",
        "created_at": ts,
        "updated_at": ts,
        "correlation_id": corr,
        "actor_sub": actor_sub,
    }
    if body.description is not None:
        item["description"] = body.description
    if body.unit_id is not None:
        item["unit_id"] = body.unit_id
    if body.scheduled_for is not None:
        item["scheduled_for"] = body.scheduled_for

    try:
        T.maintenance_orders.put_item(
            Item=item,
            ConditionExpression="attribute_not_exists(sk)",
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
            existing = get_work_order(property_id, work_order_id)
            _audit("maintenance_order.create.idempotent", actor_sub, work_order_id=work_order_id)
            return existing  # type: ignore[return-value]
        raise

    _audit("maintenance_order.created", actor_sub, work_order_id=work_order_id, property_id=property_id)

    # WOV-003: optional escrow funding
    if body.amount_cents is not None:
        if not _escrow_enabled():
            raise HTTPException(status_code=422, detail="escrow_not_enabled")
        fund_work_order_escrow(
            work_order_id=work_order_id,
            property_id=property_id,
            poster_sub=actor_sub,
            amount_cents=body.amount_cents,
        )

    return _item_to_out(item)


def get_work_order(property_id: str, work_order_id: str) -> Optional[MaintenanceOrderOut]:
    _require_enabled()
    resp = T.maintenance_orders.get_item(Key={"pk": _wo_pk(property_id), "sk": _wo_sk(work_order_id)})
    if "Item" not in resp:
        return None
    return _item_to_out(resp["Item"])


# ---------------------------------------------------------------------------
# WOV-002: assign / schedule / transition / list
# ---------------------------------------------------------------------------


def assign_work_order(
    property_id: str,
    work_order_id: str,
    body: MaintenanceOrderAssignIn,
    actor_sub: str,
) -> MaintenanceOrderOut:
    _require_enabled()

    resp = T.maintenance_orders.get_item(Key={"pk": _wo_pk(property_id), "sk": _wo_sk(work_order_id)})
    if "Item" not in resp:
        raise HTTPException(status_code=404, detail="work_order_not_found")
    item = resp["Item"]

    if body.vendor_id is None and body.assignee_sub is None:
        raise HTTPException(status_code=422, detail="assign_requires_target")

    current_status = item.get("wo_status", "open")
    if current_status in ("completed", "cancelled"):
        raise HTTPException(status_code=409, detail="illegal_assignment_terminal")

    # Vendor guard (lazy import — WOV-004 may not be built yet)
    if body.vendor_id is not None:
        try:
            from app.services.maintenance_vendors import get_vendor  # type: ignore[import]
            vendor = get_vendor(body.vendor_id)
            if vendor is None:
                raise HTTPException(status_code=404, detail="vendor_not_found")
            if getattr(vendor, "status", "active") == "inactive":
                raise HTTPException(status_code=422, detail="vendor_inactive")
        except ImportError:
            pass  # WOV-004 not yet built; skip guard

    ts = now_ts()
    update_parts = ["updated_at = :ts"]
    expr_vals: Dict[str, Any] = {":ts": ts}

    if body.vendor_id is not None:
        update_parts.append("vendor_id = :vi")
        expr_vals[":vi"] = body.vendor_id
    if body.assignee_sub is not None:
        update_parts.append("assignee_sub = :as")
        expr_vals[":as"] = body.assignee_sub
    if body.unit_id is not None:
        update_parts.append("unit_id = :ui")
        expr_vals[":ui"] = body.unit_id

    # open → assigned auto-advance
    if current_status == "open":
        update_parts.append("wo_status = :ws")
        expr_vals[":ws"] = "assigned"

    T.maintenance_orders.update_item(
        Key={"pk": _wo_pk(property_id), "sk": _wo_sk(work_order_id)},
        UpdateExpression="SET " + ", ".join(update_parts),
        ExpressionAttributeValues=expr_vals,
    )

    updated = T.maintenance_orders.get_item(Key={"pk": _wo_pk(property_id), "sk": _wo_sk(work_order_id)})
    out = _item_to_out(updated["Item"])
    _audit("maintenance_order.assigned", actor_sub,
           work_order_id=work_order_id, property_id=property_id,
           vendor_id=body.vendor_id, assignee_sub=body.assignee_sub)
    return out


def schedule_work_order(
    property_id: str,
    work_order_id: str,
    body: MaintenanceOrderScheduleIn,
    actor_sub: str,
) -> MaintenanceOrderOut:
    _require_enabled()

    resp = T.maintenance_orders.get_item(Key={"pk": _wo_pk(property_id), "sk": _wo_sk(work_order_id)})
    if "Item" not in resp:
        raise HTTPException(status_code=404, detail="work_order_not_found")
    item = resp["Item"]

    if item.get("wo_status") in ("completed", "cancelled"):
        raise HTTPException(status_code=409, detail="cannot_schedule_terminal")

    ts = now_ts()
    T.maintenance_orders.update_item(
        Key={"pk": _wo_pk(property_id), "sk": _wo_sk(work_order_id)},
        UpdateExpression="SET scheduled_for = :sf, updated_at = :ts",
        ExpressionAttributeValues={":sf": body.scheduled_for, ":ts": ts},
    )

    updated = T.maintenance_orders.get_item(Key={"pk": _wo_pk(property_id), "sk": _wo_sk(work_order_id)})
    out = _item_to_out(updated["Item"])
    _audit("maintenance_order.scheduled", actor_sub,
           work_order_id=work_order_id, property_id=property_id,
           scheduled_for=body.scheduled_for)
    return out


def transition_work_order(
    property_id: str,
    work_order_id: str,
    body: MaintenanceOrderTransitionIn,
    actor_sub: str,
) -> MaintenanceOrderOut:
    _require_enabled()

    resp = T.maintenance_orders.get_item(Key={"pk": _wo_pk(property_id), "sk": _wo_sk(work_order_id)})
    if "Item" not in resp:
        raise HTTPException(status_code=404, detail="work_order_not_found")
    item = resp["Item"]

    current = item.get("wo_status", "open")
    target = body.target_status

    if target not in VALID_TRANSITIONS.get(current, set()):
        raise HTTPException(
            status_code=409,
            detail="illegal_transition",
            headers={"X-Current-Status": current, "X-Target-Status": target},
        )

    # WOV-003: handle escrow before committing status change
    if _escrow_enabled():
        es = item.get("escrow_status")
        if target == "completed" and es == "held":
            _release_escrow(work_order_id, property_id, item.get("vendor_id"), actor_sub)
        elif target == "cancelled" and es == "held":
            _refund_escrow(work_order_id, actor_sub)

    ts = now_ts()
    update_parts = ["wo_status = :s", "updated_at = :ts"]
    expr_vals: Dict[str, Any] = {":s": target, ":ts": ts, ":current": current}

    if target == "completed":
        update_parts.append("completed_at = :ts")
    if body.cost_cents is not None:
        update_parts.append("cost_cents = :cc")
        expr_vals[":cc"] = body.cost_cents
    if body.assignee_sub is not None:
        update_parts.append("assignee_sub = :as")
        expr_vals[":as"] = body.assignee_sub
    if body.vendor_id is not None:
        update_parts.append("vendor_id = :vi")
        expr_vals[":vi"] = body.vendor_id
    # Walk-back open: clear assignee_sub and vendor_id
    if target == "open":
        update_parts.append("REMOVE assignee_sub, vendor_id")

    # Build UpdateExpression (handle optional REMOVE clause)
    set_parts = [p for p in update_parts if not p.startswith("REMOVE")]
    remove_parts = [p for p in update_parts if p.startswith("REMOVE")]
    ue = "SET " + ", ".join(set_parts)
    if remove_parts:
        # remove_parts contains full "REMOVE attr1, attr2" string
        remove_clause = " ".join(remove_parts)
        ue = ue + " " + remove_clause

    try:
        T.maintenance_orders.update_item(
            Key={"pk": _wo_pk(property_id), "sk": _wo_sk(work_order_id)},
            UpdateExpression=ue,
            ExpressionAttributeValues=expr_vals,
            ConditionExpression="wo_status = :current",
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
            raise HTTPException(status_code=409, detail="concurrent_transition")
        raise

    updated = T.maintenance_orders.get_item(Key={"pk": _wo_pk(property_id), "sk": _wo_sk(work_order_id)})
    out = _item_to_out(updated["Item"])
    _audit(f"maintenance_order.{target}", actor_sub, work_order_id=work_order_id, property_id=property_id)
    return out


def list_work_orders(
    property_id: Optional[str] = None,
    wo_status: Optional[str] = None,
    assignee_sub: Optional[str] = None,
    cursor: Optional[str] = None,
    limit: int = 50,
) -> WoListOut:
    _require_enabled()
    if limit > 200:
        limit = 200

    kwargs: Dict[str, Any] = {"ScanIndexForward": False, "Limit": limit}
    if cursor:
        start_key = decode_cursor(cursor)
        if start_key:
            kwargs["ExclusiveStartKey"] = start_key

    if property_id:
        kwargs["KeyConditionExpression"] = Key("pk").eq(_wo_pk(property_id))
        if wo_status:
            kwargs["FilterExpression"] = Attr("wo_status").eq(wo_status)
        resp = T.maintenance_orders.query(**kwargs)
    elif wo_status:
        kwargs["IndexName"] = "GSI_WO_STATUS"
        kwargs["KeyConditionExpression"] = Key("wo_status").eq(wo_status)
        if assignee_sub:
            kwargs["FilterExpression"] = Attr("assignee_sub").eq(assignee_sub)
        resp = T.maintenance_orders.query(**kwargs)
    elif assignee_sub:
        kwargs["IndexName"] = "GSI_WO_ASSIGNEE"
        kwargs["KeyConditionExpression"] = Key("assignee_sub").eq(assignee_sub)
        if wo_status:
            kwargs["FilterExpression"] = Attr("wo_status").eq(wo_status)
        resp = T.maintenance_orders.query(**kwargs)
    else:
        raise HTTPException(status_code=400, detail="supply_filter")

    items = [_item_to_out(i) for i in resp.get("Items", [])]
    return WoListOut(
        items=items,
        count=len(items),
        cursor=encode_cursor(resp.get("LastEvaluatedKey")),
    )


# ---------------------------------------------------------------------------
# WOV-003: escrow primitives
# ---------------------------------------------------------------------------


def _resolve_payout_target(vendor_id: Optional[str]) -> tuple:
    """
    Returns (payout_sub, payout_target).
    Decision D2: never raises for missing/unlinked vendor.
    """
    if vendor_id:
        try:
            from app.services.maintenance_vendors import get_vendor  # type: ignore[import]
            vendor = get_vendor(vendor_id)
            sub = getattr(vendor, "user_sub", None) if vendor else None
            if sub:
                return sub, "wallet"
        except ImportError:
            pass  # WOV-004 not yet built → clearing fallback
    return MAINT_CLEARING_SUB, "clearing"


def _transact_client_billing():
    """Return a low-level DynamoDB client for T.billing transact_write_items."""
    import boto3
    resource_client = T.billing.meta.client
    endpoint = resource_client.meta.endpoint_url
    region = resource_client.meta.region_name
    creds = resource_client._request_signer._credentials
    kwargs: Dict[str, Any] = {"region_name": region, "endpoint_url": endpoint}
    if creds is not None:
        frozen = creds.get_frozen_credentials()
        kwargs["aws_access_key_id"] = frozen.access_key
        kwargs["aws_secret_access_key"] = frozen.secret_key
        if frozen.token:
            kwargs["aws_session_token"] = frozen.token
    return boto3.client("dynamodb", **kwargs)


def _to_ddb_item(item: Dict[str, Any]) -> Dict[str, Any]:
    from boto3.dynamodb.types import TypeSerializer
    s = TypeSerializer()
    return {k: s.serialize(v) for k, v in item.items() if v is not None}


def fund_work_order_escrow(
    work_order_id: str,
    property_id: str,
    poster_sub: str,
    amount_cents: int,
) -> None:
    """
    Debit poster's wallet, create escrow row, write ledger entry — atomically.
    WOV-003 §4.4 fund_work_order_escrow.
    """
    _require_enabled()
    _require_escrow_enabled()

    from app.core.settings import S
    from app.services.billing_shared import (
        new_ledger_entry,
        user_pk,
    )

    min_c = getattr(S, "maintenance_escrow_min_cents", 100)
    max_c = getattr(S, "maintenance_escrow_max_cents", 10_000_000)
    if amount_cents < min_c or amount_cents > max_c:
        raise HTTPException(status_code=422, detail="escrow_amount_out_of_range")

    escrow_pk = _escrow_pk(work_order_id)
    # Idempotency: already held?
    existing = T.billing.get_item(Key={"pk": escrow_pk, "sk": "ESCROW"}).get("Item")
    if existing and existing.get("escrow_status") == "held":
        return

    poster_upk = user_pk(poster_sub)
    lsk, ledger_item = new_ledger_entry(
        key_name="pk",
        key_value=poster_upk,
        entry_type="debit",
        amount_cents=amount_cents,
        state="pending",
        reason="maintenance_escrow",
        meta={"work_order_id": work_order_id, "property_id": property_id},
    )

    ts = now_ts()
    escrow_item = {
        "pk": escrow_pk,
        "sk": "ESCROW",
        "work_order_id": work_order_id,
        "property_id": property_id,
        "poster_sub": poster_sub,
        "amount_cents": amount_cents,
        "currency": "usd",
        "escrow_status": "held",
        "created_at": ts,
        "ledger_sk": lsk,
    }

    billing_table_name = T.billing.name

    try:
        _transact_client_billing().transact_write_items(TransactItems=[
            # (a) wallet debit (conditional on sufficient balance)
            {
                "Update": {
                    "TableName": billing_table_name,
                    "Key": _to_ddb_item({"pk": poster_upk, "sk": "WALLET"}),
                    "UpdateExpression": "SET wallet_balance_cents = wallet_balance_cents + :neg, updated_at = :t",
                    "ConditionExpression": "wallet_balance_cents >= :amount",
                    "ExpressionAttributeValues": _to_ddb_item({
                        ":neg": -amount_cents,
                        ":t": ts,
                        ":amount": amount_cents,
                    }),
                }
            },
            # (b) escrow sentinel row (idempotency guard)
            {
                "Put": {
                    "TableName": billing_table_name,
                    "Item": _to_ddb_item(escrow_item),
                    "ConditionExpression": "attribute_not_exists(pk)",
                }
            },
            # (c) ledger entry
            {
                "Put": {
                    "TableName": billing_table_name,
                    "Item": _to_ddb_item(ledger_item),
                    "ConditionExpression": "attribute_not_exists(sk)",
                }
            },
        ])
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code == "TransactionCanceledException":
            reasons = exc.response.get("CancellationReasons", [])
            # Index 0 = wallet debit condition → insufficient balance
            if reasons and reasons[0].get("Code") == "ConditionalCheckFailed":
                raise HTTPException(status_code=402, detail="insufficient_wallet_balance")
            # Index 1 = escrow put condition → idempotent (already exists)
            if len(reasons) > 1 and reasons[1].get("Code") == "ConditionalCheckFailed":
                # Already held — idempotent success, stamp WO row below
                pass
            else:
                raise
        else:
            raise

    # Step 7: stamp escrow fields on the WO row (best-effort; idempotent on retry)
    try:
        T.maintenance_orders.update_item(
            Key={"pk": _wo_pk(property_id), "sk": _wo_sk(work_order_id)},
            UpdateExpression="SET escrow_amount_cents = :a, escrow_status = :s",
            ExpressionAttributeValues={":a": amount_cents, ":s": "held"},
        )
    except Exception:
        pass  # non-fatal; escrow row is the source of truth

    _audit("maintenance_escrow.funded", poster_sub,
           work_order_id=work_order_id, amount_cents=amount_cents)


def _release_escrow(
    work_order_id: str,
    property_id: str,
    vendor_id: Optional[str],
    poster_sub: str,
) -> None:
    """
    Release held escrow to the vendor (or clearing account — decision D2).
    WOV-003 §4.4 _release_escrow.  MUST be atomic.
    """
    from app.core.settings import S
    from app.services.billing_shared import (
        new_ledger_entry,
        settle_or_reverse_ledger,
        user_pk,
    )

    escrow_pk_val = _escrow_pk(work_order_id)
    resp = T.billing.get_item(Key={"pk": escrow_pk_val, "sk": "ESCROW"})
    escrow = resp.get("Item")
    if not escrow or escrow.get("escrow_status") != "held":
        raise HTTPException(status_code=409, detail="escrow_not_held")

    amount_cents = _to_int(escrow["amount_cents"])
    fee_bps = getattr(S, "maintenance_escrow_fee_bps", 0)
    fee_cents = amount_cents * fee_bps // 10000
    net_cents = amount_cents - fee_cents

    payout_sub, payout_target = _resolve_payout_target(vendor_id)
    poster_upk = user_pk(poster_sub)
    payout_upk = user_pk(payout_sub)

    reason = "maintenance_payout" if payout_target == "wallet" else "maintenance_payout_clearing"
    payout_lsk, payout_item = new_ledger_entry(
        key_name="pk",
        key_value=payout_upk,
        entry_type="credit",
        amount_cents=net_cents,
        state="settled",
        reason=reason,
        meta={"work_order_id": work_order_id, "property_id": property_id, "payout_target": payout_target},
    )

    ts = now_ts()
    billing_table_name = T.billing.name

    escrow_update_expr = (
        "SET escrow_status = :rel, released_at = :ts, "
        "payout_ledger_sk = :plsk, payout_sub = :ps, payout_target = :pt"
    )
    escrow_expr_vals: Dict[str, Any] = {
        ":rel": "released",
        ":ts": ts,
        ":plsk": payout_lsk,
        ":ps": payout_sub,
        ":pt": payout_target,
        ":held": "held",
    }
    if vendor_id and payout_target == "wallet":
        escrow_update_expr += ", vendor_sub = :vs"
        escrow_expr_vals[":vs"] = payout_sub
    if payout_target == "clearing":
        escrow_update_expr += ", disbursement_status = :ds"
        escrow_expr_vals[":ds"] = "pending"

    try:
        _transact_client_billing().transact_write_items(TransactItems=[
            # (a) payout ledger Put
            {
                "Put": {
                    "TableName": billing_table_name,
                    "Item": _to_ddb_item(payout_item),
                }
            },
            # (b) payout wallet credit
            {
                "Update": {
                    "TableName": billing_table_name,
                    "Key": _to_ddb_item({"pk": payout_upk, "sk": "WALLET"}),
                    "UpdateExpression": "SET wallet_balance_cents = if_not_exists(wallet_balance_cents, :z) + :n, updated_at = :ts",
                    "ExpressionAttributeValues": _to_ddb_item({":z": 0, ":n": net_cents, ":ts": ts}),
                }
            },
            # (c) escrow row update — conditional guard prevents double-release
            {
                "Update": {
                    "TableName": billing_table_name,
                    "Key": _to_ddb_item({"pk": escrow_pk_val, "sk": "ESCROW"}),
                    "UpdateExpression": escrow_update_expr,
                    "ConditionExpression": "escrow_status = :held",
                    "ExpressionAttributeValues": _to_ddb_item(escrow_expr_vals),
                }
            },
        ])
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "TransactionCanceledException":
            reasons = exc.response.get("CancellationReasons", [])
            # escrow condition (index 2) failed → already released → idempotent
            if len(reasons) > 2 and reasons[2].get("Code") == "ConditionalCheckFailed":
                return
        raise

    # Settle the original poster-debit ledger entry
    try:
        settle_or_reverse_ledger(
            T.billing, "pk", user_pk(poster_sub), escrow["ledger_sk"], "settled_released"
        )
    except Exception:
        pass  # best-effort; audit trail still intact

    # Stamp WO row
    try:
        T.maintenance_orders.update_item(
            Key={"pk": _wo_pk(property_id), "sk": _wo_sk(work_order_id)},
            UpdateExpression="SET escrow_status = :s",
            ExpressionAttributeValues={":s": "released"},
        )
    except Exception:
        pass

    _audit("maintenance_escrow.released", payout_sub,
           work_order_id=work_order_id, net_cents=net_cents, payout_target=payout_target)


def _refund_escrow(work_order_id: str, poster_sub: str) -> None:
    """
    Refund held escrow to the poster.
    WOV-003 §4.4 _refund_escrow.
    """
    from app.services.billing_shared import (
        apply_wallet_delta,
        new_ledger_entry,
        settle_or_reverse_ledger,
        user_pk,
    )

    escrow_pk_val = _escrow_pk(work_order_id)
    resp = T.billing.get_item(Key={"pk": escrow_pk_val, "sk": "ESCROW"})
    escrow = resp.get("Item")
    if not escrow or escrow.get("escrow_status") != "held":
        # No escrow or already settled — safe no-op
        return

    amount_cents = _to_int(escrow["amount_cents"])
    poster_upk = user_pk(poster_sub)

    refund_lsk, refund_item = new_ledger_entry(
        key_name="pk",
        key_value=poster_upk,
        entry_type="adjustment",
        amount_cents=amount_cents,
        state="settled",
        reason="maintenance_escrow_refund",
        meta={"work_order_id": work_order_id},
    )

    # Write refund ledger entry
    T.billing.put_item(Item=refund_item)

    # Credit poster wallet
    try:
        apply_wallet_delta(T.billing, poster_upk, +amount_cents)
    except Exception:
        pass

    # Reverse original debit
    try:
        settle_or_reverse_ledger(T.billing, "pk", poster_upk, escrow["ledger_sk"], "reversed")
    except Exception:
        pass

    # Conditional update to prevent double-refund
    ts = now_ts()
    try:
        T.billing.update_item(
            Key={"pk": escrow_pk_val, "sk": "ESCROW"},
            UpdateExpression="SET escrow_status = :ref, refunded_at = :ts, refund_ledger_sk = :rlsk",
            ConditionExpression="escrow_status = :held",
            ExpressionAttributeValues={
                ":ref": "refunded",
                ":ts": ts,
                ":rlsk": refund_lsk,
                ":held": "held",
            },
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
            return  # already refunded — idempotent
        raise

    # Stamp WO row
    try:
        T.maintenance_orders.update_item(
            Key={"pk": _wo_pk(escrow.get("property_id", "")), "sk": _wo_sk(work_order_id)},
            UpdateExpression="SET escrow_status = :s",
            ExpressionAttributeValues={":s": "refunded"},
        )
    except Exception:
        pass

    _audit("maintenance_escrow.refunded", poster_sub,
           work_order_id=work_order_id, amount_cents=amount_cents)
