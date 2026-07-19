"""ORD-005/006/010/011 — order lifecycle state machine, history, read helpers.

Pure additive layer over the order header written by
``commerce_order_service.create_order``. Owns the 11-state transition graph,
version-gated (current-status CAS) conditional ``update_item``, the append-only
``HIST#`` audit trail, and the enriched ``get_order_lifecycle`` read.

No ``S.dev_mode`` branch (SECOPS-007 parity). All money-out flows delegate to
``billing.refund_payment`` / ``billing_shared`` — never a forked ledger.
"""
from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Set

from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.models import (
    OrderLifecycleOut,
    OrderLifecycleStatus,
    OrderLineItemOut,
    OrderTransitionResult,
)
from app.services.order_store import ORDER_SK, get_order_header

logger = logging.getLogger(__name__)

_S = OrderLifecycleStatus

# ── Transition graph (data, not logic) ───────────────────────────────────────
TRANSITIONS: Dict[str, Set[str]] = {
    _S.CREATED.value: {_S.APPROVED.value, _S.HELD.value, _S.CANCELLED.value},
    _S.APPROVED.value: {_S.ALLOCATED.value, _S.HELD.value, _S.BACKORDER.value, _S.CANCELLED.value},
    _S.ALLOCATED.value: {_S.PICKING.value, _S.HELD.value, _S.BACKORDER.value, _S.CANCELLED.value},
    _S.PICKING.value: {_S.PACKED.value, _S.HELD.value, _S.BACKORDER.value, _S.CANCELLED.value},
    _S.PACKED.value: {_S.SHIPPED.value, _S.HELD.value, _S.CANCELLED.value},
    _S.SHIPPED.value: {_S.COMPLETED.value, _S.RETURNED.value},
    _S.COMPLETED.value: {_S.RETURNED.value},
    _S.HELD.value: {
        _S.APPROVED.value,
        _S.ALLOCATED.value,
        _S.PICKING.value,
        _S.PACKED.value,
        _S.CANCELLED.value,
    },
    _S.BACKORDER.value: {_S.ALLOCATED.value, _S.CANCELLED.value},
    _S.CANCELLED.value: set(),
    _S.RETURNED.value: set(),
}

# Legacy `status` mirror — keeps GSI_STATUS consumers intact.
_LEGACY_MIRROR: Dict[str, str] = {
    _S.CREATED.value: "pending_payment",
    _S.APPROVED.value: "approved",
    _S.ALLOCATED.value: "processing",
    _S.PICKING.value: "processing",
    _S.PACKED.value: "processing",
    _S.SHIPPED.value: "shipped",
    _S.COMPLETED.value: "completed",
    _S.HELD.value: "on_hold",
    _S.BACKORDER.value: "backordered",
    _S.CANCELLED.value: "cancelled",
    _S.RETURNED.value: "returned",
}


# ── Typed exceptions ──────────────────────────────────────────────────────────
class OrderNotFoundError(Exception):
    def __init__(self, order_id: str) -> None:
        super().__init__(f"Order not found: {order_id}")
        self.order_id = order_id


class OrderTransitionError(Exception):
    def __init__(self, from_status: str, to_status: str) -> None:
        super().__init__(f"Illegal transition: {from_status!r} -> {to_status!r}")
        self.from_status = from_status
        self.to_status = to_status


class OrderConflictError(Exception):
    def __init__(self, order_id: str) -> None:
        super().__init__(f"Concurrent lifecycle update conflict on order {order_id}")
        self.order_id = order_id


# ── Helpers ──────────────────────────────────────────────────────────────────
def _is_conditional_conflict(exc: ClientError) -> bool:
    return (
        str(exc.response.get("Error", {}).get("Code", ""))
        == "ConditionalCheckFailedException"
    )


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _derive_event_id(
    order_id: str,
    from_status: Optional[str],
    to_status: str,
    idempotency_key: Optional[str],
) -> str:
    raw = f"{order_id}|{from_status or ''}|{to_status}|{idempotency_key or ''}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def _legacy_mirror(lifecycle_status: str) -> str:
    return _LEGACY_MIRROR.get(lifecycle_status, lifecycle_status)


def _audit_safe(event: str, actor: str, **fields: Any) -> None:
    """Emit an audit event without ever raising (mirrors ssh_key_manager._audit)."""
    try:
        from app.services.alerts import audit_event

        audit_event(event, actor, None, **fields)
    except Exception:
        logger.debug("order_audit_event_failed event=%s actor=%s", event, actor, exc_info=True)


# ── ORD-006: status history ──────────────────────────────────────────────────
def history_row_exists(order_id: str, event_id: str) -> bool:
    """Return True if a HIST row with the given event_id already exists.

    Best-effort: returns False on any error (never raises).
    """
    try:
        resp = T.orders.query(
            KeyConditionExpression=Key("order_id").eq(order_id)
            & Key("sk").begins_with("HIST#"),
            FilterExpression="event_id = :eid",
            ExpressionAttributeValues={":eid": event_id},
            Limit=1,
        )
        return bool(resp.get("Items"))
    except Exception:
        return False


def _append_history_row(
    order_id: str,
    *,
    from_status: Optional[str],
    to_status: str,
    actor: str,
    reason: str,
    event_id: str,
    ts: int,
) -> None:
    """Write one HIST#{ts:020d}#{event_id} row. Best-effort: never rolls back."""
    item: Dict[str, Any] = {
        "order_id": order_id,
        "sk": f"HIST#{ts:020d}#{event_id}",
        "event_id": event_id,
        "to_status": to_status,
        "actor": actor,
        "reason": reason,
        "ts": ts,
    }
    if from_status is not None:
        item["from_status"] = from_status
    try:
        T.orders.put_item(Item=item)
    except Exception:
        logger.warning(
            "order_hist_write_failed order_id=%s event_id=%s from=%s to=%s",
            order_id,
            event_id,
            from_status,
            to_status,
            exc_info=True,
        )


def list_status_history(order_id: str, *, limit: int = 100) -> List[Dict[str, Any]]:
    """Return status-history entries newest-first (DDB native descending SK)."""
    from app.models import OrderStatusHistoryEntry

    eff_limit = max(1, min(int(limit), 500))
    resp = T.orders.query(
        KeyConditionExpression=Key("order_id").eq(order_id)
        & Key("sk").begins_with("HIST#"),
        ScanIndexForward=False,
        Limit=eff_limit,
    )
    entries: List[Dict[str, Any]] = []
    for raw in resp.get("Items", []):
        entry = OrderStatusHistoryEntry(
            event_id=raw.get("event_id", ""),
            from_status=raw.get("from_status"),
            to_status=raw.get("to_status", ""),
            actor=raw.get("actor", ""),
            reason=raw.get("reason", ""),
            ts=int(raw.get("ts", 0)),
        )
        entries.append(entry.model_dump())
    return entries


# ── ORD-005: transition_order ────────────────────────────────────────────────
def transition_order(
    order_id: str,
    target_status: "str | OrderLifecycleStatus",
    *,
    actor: str,
    reason: str = "",
    idempotency_key: Optional[str] = None,
) -> OrderTransitionResult:
    """Validate and execute one state-machine transition on the order header."""
    target = (
        target_status.value
        if isinstance(target_status, OrderLifecycleStatus)
        else str(target_status)
    )

    header = get_order_header(order_id)
    if not header:
        raise OrderNotFoundError(order_id)

    current = str(header.get("lifecycle_status") or "")
    if not current:
        raise OrderNotFoundError(order_id)

    # Idempotency fast-path: header is already in the requested target state and
    # the caller supplied an idempotency_key → treat the replay as a no-op success
    # (the original transition already committed). The returned event_id is the
    # deterministic id for the requested edge so the caller can correlate.
    if current == target and idempotency_key:
        return OrderTransitionResult(
            order=_header_to_lifecycle_out(header),
            event_id=_derive_event_id(order_id, current, target, idempotency_key),
            from_status=current,
            to_status=target,
        )

    legal_targets = TRANSITIONS.get(current, set())
    if target not in legal_targets:
        raise OrderTransitionError(current, target)

    if target == _S.BACKORDER.value and not S.order_backorder_enabled:
        raise OrderTransitionError(current, target)

    event_id = _derive_event_id(order_id, current, target, idempotency_key)
    ts = now_ts()
    now_str = _now_iso()

    set_parts = [
        "lifecycle_status = :new_status",
        "#status = :legacy_status",
        "updated_ts = :updated_ts",
        "updated_at = :updated_at",
    ]
    expr_values: Dict[str, Any] = {
        ":new_status": target,
        ":legacy_status": _legacy_mirror(target),
        ":updated_ts": ts,
        ":updated_at": now_str,
        ":current_status": current,
    }
    expr_names: Dict[str, str] = {"#status": "status"}

    remove_parts: List[str] = []
    if target == _S.HELD.value:
        set_parts.append("pre_hold_status = :pre_hold")
        expr_values[":pre_hold"] = current
    elif current == _S.HELD.value:
        remove_parts.append("pre_hold_status")

    update_expr = "SET " + ", ".join(set_parts)
    if remove_parts:
        update_expr += " REMOVE " + ", ".join(remove_parts)

    try:
        T.orders.update_item(
            Key={"order_id": order_id, "sk": ORDER_SK},
            UpdateExpression=update_expr,
            ExpressionAttributeNames=expr_names,
            ExpressionAttributeValues=expr_values,
            ConditionExpression="lifecycle_status = :current_status",
            ReturnValues="ALL_NEW",
        )
    except ClientError as exc:
        if _is_conditional_conflict(exc):
            raise OrderConflictError(order_id) from exc
        raise

    _append_history_row(
        order_id,
        from_status=current,
        to_status=target,
        actor=actor,
        reason=reason,
        event_id=event_id,
        ts=ts,
    )

    _audit_safe(
        "order_status_changed",
        actor,
        order_id=order_id,
        from_status=current,
        to_status=target,
        event_id=event_id,
        reason=reason,
    )

    updated_header = get_order_header(order_id) or header
    return OrderTransitionResult(
        order=_header_to_lifecycle_out(updated_header),
        event_id=event_id,
        from_status=current,
        to_status=target,
    )


# ── ORD-011: read helpers ────────────────────────────────────────────────────
def _header_to_lifecycle_out(header: Dict[str, Any]) -> OrderLifecycleOut:
    ls_raw = header.get("lifecycle_status")
    ls: Optional[OrderLifecycleStatus] = None
    if ls_raw:
        try:
            ls = OrderLifecycleStatus(ls_raw)
        except ValueError:
            ls = None

    return OrderLifecycleOut(
        order_id=header["order_id"],
        status=str(header.get("status") or "pending_payment"),
        created_at=str(header.get("created_at") or ""),
        updated_at=str(header.get("updated_at") or ""),
        source_system=str(header.get("source_system") or ""),
        correlation_id=str(header.get("correlation_id") or ""),
        amount_cents=int(header.get("amount_cents") or 0),
        currency=str(header.get("currency") or "USD"),
        line_item_count=int(header.get("line_item_count") or 0),
        metadata=dict(header.get("metadata") or {}),
        lifecycle_status=ls,
        updated_ts=int(header["updated_ts"]) if header.get("updated_ts") is not None else None,
        pre_hold_status=header.get("pre_hold_status"),
    )


def _load_line_items(order_id: str) -> List[OrderLineItemOut]:
    resp = T.order_items.query(KeyConditionExpression=Key("order_id").eq(order_id))
    rows = sorted(resp.get("Items", []), key=lambda r: int(str(r.get("item_id") or "0") or 0))
    out: List[OrderLineItemOut] = []
    for row in rows:
        ref = dict(row.get("pricing_ref") or {})
        unit_price = ref.get("unit_price_cents")
        if unit_price is None:
            unit_price = ref.get("amount_cents")
        if unit_price is None:
            unit_price = ref.get("price_cents")
        out.append(
            OrderLineItemOut(
                item_id=str(row.get("item_id") or ""),
                sku=str(row.get("sku") or ""),
                name=str(row.get("name") or ref.get("name") or row.get("product_type") or ""),
                quantity=int(row.get("quantity") or 1),
                unit_price_cents=int(unit_price or 0),
                currency=str(ref.get("currency") or "USD").upper(),
                metadata={
                    "product_type": row.get("product_type"),
                    "billing_model": row.get("billing_model"),
                    "scope": dict(row.get("scope") or {}),
                },
            )
        )
    return out


def get_order_lifecycle(
    order_id: str,
    *,
    include: Optional[Iterable[str]] = None,
    buyer_sub: Optional[str] = None,
) -> OrderLifecycleOut:
    """Fetch the ORDER-SK header and return an enriched OrderLifecycleOut.

    Always populates ``allowed_transitions`` (from TRANSITIONS) and joined
    ``line_items`` when ``lifecycle_status`` is set. ``include`` may request
    ``history``, ``adjustments``, ``ship_groups`` sub-collections.
    """
    header = get_order_header(order_id)
    if not header:
        raise OrderNotFoundError(order_id)

    out = _header_to_lifecycle_out(header)
    include_set = {str(s).strip() for s in (include or []) if str(s).strip()}

    if out.lifecycle_status is not None:
        out.allowed_transitions = sorted(TRANSITIONS.get(out.lifecycle_status.value, set()))
        out.line_items = _load_line_items(order_id)

    # ── ECOMX-E1: surface the seller ship-group tracking INLINE on the buyer
    # order detail (carrier / tracking# / status / last-event) joined via the
    # fulfilment bridge. ``buyer_sub`` (when given) scopes to the buyer''s OWN
    # ship groups; admin/root pass None. Never blocks the read.
    try:
        from app.models import OrderShipmentOut
        from app.services import order_fulfillment_bridge as _bridge
        inline = _bridge.order_shipments_inline(order_id, buyer_sub=buyer_sub)
        out.fulfillment_status = inline.get("fulfillment_status") or header.get("fulfillment_status")
        out.shipments = [OrderShipmentOut(**sh) for sh in inline.get("shipments", [])]
    except Exception:
        logger.debug("get_order_lifecycle: inline shipments join failed order=%s", order_id, exc_info=True)

    if "history" in include_set:
        from app.models import OrderStatusHistoryEntry

        out.status_history = [
            OrderStatusHistoryEntry(**e) for e in list_status_history(order_id)
        ]
    if "adjustments" in include_set:
        out.adjustments = []
    if "ship_groups" in include_set:
        out.ship_groups = []

    return out


# ── ORD-010: cancel (refund delegated to billing.refund_payment) ─────────────
def cancel_order(
    order_id: str,
    *,
    reason: str = "",
    refund: bool = False,
    actor: str,
) -> OrderLifecycleOut:
    """Transition an order to ``cancelled`` and optionally issue a refund.

    The refund is delegated to ``billing.refund_payment`` (FIN-013 ledger /
    provider attribution) — never a forked ledger. Refund failures are
    best-effort and do not roll back the cancellation.
    """
    result = transition_order(
        order_id,
        _S.CANCELLED.value,
        actor=actor,
        reason=reason or "order_cancelled",
    )

    if refund:
        _maybe_refund(order_id, actor=actor)

    _audit_safe("order_cancelled", actor, order_id=order_id, reason=reason)
    return result.order


def _maybe_refund(order_id: str, *, actor: str) -> None:
    """ECOMX-12/13: reverse the REAL charge on an owner/admin cancel-refund.

    For a cart order we now carry the buyer-debit ledger txn on the header
    (``buyer_debit_txn_id``, stamped at purchase). Drive the refund through the
    refund_requests service (create + approve) so the SAME money mechanics run
    as an admin-approved refund: buyer credited, EVERY seller + the livecom host
    clawed back, atomic transact. A missing buyer-debit ref is a LOGGED ERROR —
    never a silent 200 (the A3 bug was owner-cancel no-op'ing on cart orders).
    """
    header = get_order_header(order_id) or {}
    metadata = dict(header.get("metadata") or {})
    buyer_debit_txn_id = (
        header.get("buyer_debit_txn_id")
        or header.get("buyer_debit_entry_id")
        or metadata.get("buyer_debit_txn_id")
    )
    buyer_id = header.get("user_id") or metadata.get("user_id")

    if buyer_debit_txn_id and buyer_id:
        try:
            from app.services import refund_requests as _rr
            req = _rr.create_refund_request(
                buyer_id,
                str(buyer_debit_txn_id),
                reason=f"Order {order_id} cancelled by {actor}",
            )
            _req_id = req.get("refund_request_id") or req.get("request_id")
            _rr.approve_request(
                _req_id,
                admin_id=actor,
                notes=f"Auto-approved on order {order_id} cancel-refund",
            )
            logger.info("order_cancel_refund_ok order_id=%s txn=%s", order_id, buyer_debit_txn_id)
            # ECOMX-52 (E8): a self-cancel-refund now fires an explicit,
            # tappable order_refunded confirmation to the buyer (previously the
            # buyer cancelled + was refunded with ZERO notification).
            try:
                from app.services.alerts import write_alert
                _rtitle = "Your order was cancelled and refunded"
                _rres = write_alert(
                    str(buyer_id),
                    event="order_refunded",
                    outcome="success",
                    title=_rtitle,
                    details={
                        "alert_type": "order_refunded",
                        "order_id": order_id,
                        "txn_id": str(buyer_debit_txn_id),
                    },
                )
                try:
                    from app.services.push import send_push_for_alert
                    _raid = (_rres or {}).get("alert_id", order_id) if isinstance(_rres, dict) else order_id
                    send_push_for_alert(
                        str(buyer_id), "order_refunded", _rtitle,
                        "Your refund is on its way.", _raid,
                        action_url=f"/orders?order={order_id}",
                    )
                except Exception:
                    logger.exception("order_refunded push failed order_id=%s", order_id)
            except Exception:
                logger.exception("order_refunded alert failed order_id=%s", order_id)
            return
        except Exception:
            logger.error("order_cancel_refund_failed order_id=%s txn=%s", order_id,
                         buyer_debit_txn_id, exc_info=True)
            return

    # Legacy provider-intent path (non-cart orders that carry a payment_intent_id).
    payment_intent_id = (
        header.get("payment_intent_id")
        or metadata.get("payment_intent_id")
        or metadata.get("ledger_sk")
    )
    if not payment_intent_id:
        logger.error(
            "order_cancel_refund_no_ref order_id=%s (no buyer_debit_txn_id and no "
            "payment_intent_id — refund could not be issued)", order_id)
        return
    try:
        from app.routers import billing as billing_router  # lazy import

        refund_fn = getattr(billing_router, "refund_payment", None)
        if refund_fn is None:
            return
        refund_fn(
            actor,
            payment_intent_id,
            extra={"provider": header.get("provider") or "stripe", "order_id": order_id},
        )
    except Exception:
        logger.warning("order_cancel_refund_failed order_id=%s", order_id, exc_info=True)
