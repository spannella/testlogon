"""ECOMX-20..24 — order-fulfilment BRIDGE: one reconciled order state model.

Before this module there were THREE unsynced state machines for a single order:

  (1) the ``T.orders`` lifecycle HEADER  (order_lifecycle.transition_order) —
      dead-ended at ``approved`` for every cart purchase; nothing advanced it;
  (2) the per-seller ``seller_ship_groups`` rows (approved→…→shipped), and
  (3) the ``shipment_tracking`` record (label_created→…→delivered).

Groups (2) and tracking (3) never wrote back to the header (1) — so
``/ui/orders/{id}/lifecycle`` (header) and ``/ui/orders/tracking/{sg}``
(tracking) openly contradicted each other, a delivered order never reached
``completed``, and a multi-seller order could show "shipped" while a second
seller had not shipped a thing.

This bridge makes the HEADER a DERIVED AGGREGATE of its ship groups + their
tracking records. It is the single write-back point:

  * ``reconcile_order(order_id)`` recomputes the header lifecycle_status +
    a fine-grained ``fulfillment_status`` (unfulfilled / partially_shipped /
    shipped / out_for_delivery / delivered / completed / returned) from the
    MIN progress across all groups, and advances the header through the
    canonical order_lifecycle state machine ONLY when *all* groups reach that
    stage — so header→``shipped`` iff every group shipped; a partial ship shows
    ``partially_shipped`` while lifecycle stays at the min group stage (ECOMX-20).
  * delivered→completed once every group is delivered, idempotent (ECOMX-21).
  * ``mark_returned(order_id)`` on an approved refund of a shipped/completed
    order + restock (ECOMX-22).
  * ``reconcile_stuck_orders`` promotes ``created`` headers that already carry a
    COMPLETED purchase_transactions row to ``approved`` — the crash-mid-purchase
    self-heal sweep (ECOMX-24).

Every write goes through ``order_lifecycle.transition_order`` (version-gated CAS
+ HIST# audit) so the aggregate can never make an illegal jump and replays are
no-ops. Nothing here raises into the caller — a bridge failure never blocks a
seller shipping or a buyer's tracking read.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Tuple

from app.core.settings import S
from app.core.tables import T

logger = logging.getLogger(__name__)

# ── ship-group lifecycle progress rank (shared enum with the header) ─────────
# Same vocab as order_lifecycle.TRANSITIONS; used to compute the MIN stage.
_GROUP_RANK: Dict[str, int] = {
    "created": 0,
    "approved": 1,
    "allocated": 2,
    "picking": 3,
    "packed": 4,
    "shipped": 5,
}
# tracking-record status → an extra post-shipped rank so a delivered tracking
# record ranks above a merely-shipped group.
_TRACK_RANK: Dict[str, int] = {
    "label_created": 5,
    "in_transit": 5,
    "out_for_delivery": 6,
    "delivered": 7,
    "exception": 5,
}
_RANK_TO_GROUP = {v: k for k, v in _GROUP_RANK.items()}

# The linear header advance path the bridge walks through (never skips a step —
# transition_order enforces the graph, but we feed it valid single steps).
_ADVANCE_PATH = ["approved", "allocated", "picking", "packed", "shipped", "completed"]


def _enabled() -> bool:
    return bool(S.order_lifecycle_enabled)


# ── aggregate computation ────────────────────────────────────────────────────

def _group_effective_rank(sg_row: Dict[str, Any]) -> int:
    """A group's effective progress rank = max(its ship-group status rank, its
    tracking record's post-ship rank). A group that has shipped AND whose
    tracking says delivered ranks as delivered (7)."""
    status = str(sg_row.get("status") or "")
    rank = _GROUP_RANK.get(status, 0)
    if rank >= _GROUP_RANK["shipped"]:
        try:
            from app.services import shipment_tracking as _st
            rec = _st.get_tracking(str(sg_row.get("ship_group_id") or ""))
            if rec:
                trank = _TRACK_RANK.get(str(rec.get("status") or ""), rank)
                rank = max(rank, trank)
        except Exception:
            logger.debug("bridge: tracking lookup failed for sg=%s",
                         sg_row.get("ship_group_id"), exc_info=True)
    return rank


def compute_aggregate(order_id: str) -> Optional[Tuple[str, str, List[Dict[str, Any]]]]:
    """Return (target_lifecycle_status, fulfillment_status, groups) for an order,
    or None when there are no seller ship groups (nothing to aggregate — the
    header keeps whatever it has, e.g. a self-purchase / digital-only order).

    ``target_lifecycle_status`` is the canonical order-lifecycle state the header
    should be at = the MIN group stage capped at ``shipped``/``completed``.
    ``fulfillment_status`` is the finer aggregate for the buyer surfaces.
    """
    try:
        from app.services import seller_ship_groups as _ssg
        groups = _ssg.list_by_order(order_id)
    except Exception:
        logger.exception("bridge: list_by_order failed order=%s", order_id)
        return None
    if not groups:
        return None

    ranks = [_group_effective_rank(g) for g in groups]
    min_rank = min(ranks)
    max_rank = max(ranks)
    all_shipped = min_rank >= _GROUP_RANK["shipped"]
    all_delivered = min_rank >= _TRACK_RANK["delivered"]
    any_shipped = max_rank >= _GROUP_RANK["shipped"]

    # ── canonical header lifecycle target (linear enum) ──────────────────────
    if all_delivered:
        target = "completed"
    elif all_shipped:
        target = "shipped"
    else:
        # header advances to the MIN group stage (allocated/picking/packed);
        # never past `packed` until EVERY group has shipped.
        capped = min(min_rank, _GROUP_RANK["packed"])
        target = _RANK_TO_GROUP.get(capped, "approved")

    # ── fine-grained fulfilment status (buyer surfaces) ──────────────────────
    if all_delivered:
        fulfillment = "delivered"
    elif min_rank >= _TRACK_RANK["out_for_delivery"]:
        fulfillment = "out_for_delivery"
    elif all_shipped:
        fulfillment = "shipped"
    elif any_shipped:
        fulfillment = "partially_shipped"
    elif max_rank >= _GROUP_RANK["allocated"]:
        fulfillment = "processing"
    else:
        fulfillment = "unfulfilled"

    return target, fulfillment, groups


# ── header write-back ────────────────────────────────────────────────────────

def _advance_header_to(order_id: str, target: str, *, actor: str, reason: str) -> str:
    """Walk the header lifecycle_status forward one legal step at a time until it
    reaches ``target`` (or can't advance further). Returns the reached status.
    Idempotent: if already at/after target it's a no-op. Never raises."""
    from app.services import order_lifecycle as _ol

    try:
        header = _ol.get_order_header(order_id)
    except Exception:
        logger.exception("bridge: get_order_header failed order=%s", order_id)
        return ""
    if not header:
        return ""
    current = str(header.get("lifecycle_status") or "")
    if current not in _ADVANCE_PATH or target not in _ADVANCE_PATH:
        return current

    # Never move a terminal/off-path order (cancelled/returned/held/backorder).
    cur_idx = _ADVANCE_PATH.index(current)
    tgt_idx = _ADVANCE_PATH.index(target)
    if tgt_idx <= cur_idx:
        return current  # already at or beyond the aggregate target (monotonic)

    reached = current
    for step in _ADVANCE_PATH[cur_idx + 1: tgt_idx + 1]:
        try:
            _ol.transition_order(
                order_id, step, actor=actor,
                reason=reason,
                idempotency_key=f"bridge:{order_id}:{step}",
            )
            reached = step
        except _ol.OrderConflictError:
            # A concurrent writer moved it — re-read and stop; next reconcile
            # will converge.
            logger.info("bridge: header advance conflict order=%s step=%s", order_id, step)
            break
        except _ol.OrderTransitionError:
            logger.info("bridge: header advance illegal order=%s %s->%s", order_id, reached, step)
            break
        except Exception:
            logger.exception("bridge: header advance failed order=%s step=%s", order_id, step)
            break
    return reached


def _stamp_fulfillment(order_id: str, fulfillment: str) -> None:
    """Persist the fine-grained aggregate on the header (a derived attribute the
    buyer surfaces read; does NOT touch lifecycle_status/CAS)."""
    try:
        from app.services.order_store import ORDER_SK
        T.orders.update_item(
            Key={"order_id": order_id, "sk": ORDER_SK},
            UpdateExpression="SET fulfillment_status = :f",
            ExpressionAttributeValues={":f": fulfillment},
        )
    except Exception:
        logger.debug("bridge: stamp fulfillment failed order=%s", order_id, exc_info=True)


def complete_txn_on_delivery(order_id: str, *, actor: str = "system:fulfilment-bridge") -> bool:
    """ECOMX-42 (B2): once an order's header reaches ``completed`` (every ship
    group delivered), flip the buyer's purchase_transactions row PENDING ->
    COMPLETED so the buyer app shows a REALISTIC terminal ("Completed") only on
    delivery, not at t=0. Keyed by the header's ``buyer_debit_txn_id`` (stamped in
    purchase_cart, ECOMX-12) + buyer sub. Idempotent (mark_completed CAS is a
    no-op once COMPLETED) and never raises. Returns True iff it completed the txn."""
    if not _enabled() or not order_id:
        return False
    from app.services import order_lifecycle as _ol
    try:
        header = _ol.get_order_header(order_id)
    except Exception:
        logger.debug("bridge: complete_txn get_header failed order=%s", order_id, exc_info=True)
        return False
    if not header or str(header.get("lifecycle_status") or "") != "completed":
        return False
    txn_id = str(header.get("buyer_debit_txn_id") or "")
    buyer = str(header.get("user_id") or (header.get("metadata") or {}).get("user_id") or "")
    if not txn_id or not buyer:
        return False
    from app.services import purchase_history as _ph
    try:
        txn = _ph.get_transaction_item(buyer, txn_id)
    except Exception:
        logger.debug("bridge: complete_txn load failed order=%s txn=%s", order_id, txn_id, exc_info=True)
        return False
    if not txn or str(txn.get("status") or "") == "COMPLETED":
        return False
    try:
        _ph.mark_completed(buyer, txn_id, header.get("payment_intent_id") or "", "Delivered")
        logger.info("bridge_complete_txn order=%s txn=%s -> COMPLETED", order_id, txn_id)
        return True
    except Exception:
        logger.debug("bridge: mark_completed failed order=%s txn=%s", order_id, txn_id, exc_info=True)
        return False


def reconcile_order(order_id: str, *, actor: str = "system:fulfilment-bridge",
                    reason: str = "fulfilment aggregate") -> Dict[str, Any]:
    """Recompute the header from its ship groups + tracking and write back.

    The single entry-point called after any ship-group transition or tracking
    advance. Returns a small summary dict (never raises)."""
    if not _enabled() or not order_id:
        return {"ok": False, "reason": "disabled_or_no_order"}
    agg = compute_aggregate(order_id)
    if agg is None:
        return {"ok": True, "no_groups": True}
    target, fulfillment, groups = agg
    reached = _advance_header_to(order_id, target, actor=actor, reason=reason)
    _stamp_fulfillment(order_id, fulfillment)
    # ECOMX-42 (B2): on delivery (header==completed) flip the buyer txn -> COMPLETED.
    if reached == "completed":
        complete_txn_on_delivery(order_id, actor=actor)
    logger.info("bridge_reconcile order=%s target=%s reached=%s fulfillment=%s groups=%s",
                order_id, target, reached, fulfillment, len(groups))
    return {"ok": True, "order_id": order_id, "target": target,
            "lifecycle_status": reached, "fulfillment_status": fulfillment,
            "group_count": len(groups)}


# ── ECOMX-21: buyer "confirm delivery" ───────────────────────────────────────

def confirm_delivery(order_id: str, *, actor: str) -> Dict[str, Any]:
    """Buyer-driven completion: force every group's tracking to delivered (so the
    aggregate reaches completed) then reconcile. Used by the buyer "Confirm
    delivery" affordance when the carrier feed is slow. Idempotent."""
    if not _enabled() or not order_id:
        return {"ok": False, "reason": "disabled_or_no_order"}
    try:
        from app.services import seller_ship_groups as _ssg
        from app.services import shipment_tracking as _st
        for g in _ssg.list_by_order(order_id):
            sg_id = str(g.get("ship_group_id") or "")
            rec = _st.get_tracking(sg_id)
            if rec and str(rec.get("status")) != _st.STATUS_DELIVERED:
                _st.advance(ship_group_id=sg_id, status=_st.STATUS_DELIVERED,
                            source="buyer_confirm", description="Buyer confirmed delivery")
    except Exception:
        logger.exception("bridge: confirm_delivery advance failed order=%s", order_id)
    return reconcile_order(order_id, actor=actor, reason="buyer confirmed delivery")


# ── ECOMX-22: return flow (post-ship refund) ─────────────────────────────────

def mark_returned(order_id: str, *, actor: str = "system:refund", restock: bool = True) -> Dict[str, Any]:
    """A refund was APPROVED on a shipped/completed order → transition the header
    to ``returned`` and (optionally) restock the returned inventory. If the order
    never shipped this is a no-op (a pre-ship refund cancels, it doesn't return).
    Idempotent + never raises."""
    if not _enabled() or not order_id:
        return {"ok": False, "reason": "disabled_or_no_order"}
    from app.services import order_lifecycle as _ol
    try:
        header = _ol.get_order_header(order_id)
    except Exception:
        logger.exception("bridge: mark_returned get_header failed order=%s", order_id)
        return {"ok": False, "reason": "header_error"}
    if not header:
        return {"ok": False, "reason": "no_header"}
    current = str(header.get("lifecycle_status") or "")
    if current not in ("shipped", "completed"):
        # Pre-ship refunds are handled by cancel_order; nothing to return.
        return {"ok": True, "returned": False, "current": current}
    try:
        _ol.transition_order(order_id, "returned", actor=actor,
                             reason="Refund approved on shipped order",
                             idempotency_key=f"bridge:return:{order_id}")
    except _ol.OrderTransitionError:
        return {"ok": True, "returned": False, "current": current}
    except Exception:
        logger.exception("bridge: mark_returned transition failed order=%s", order_id)
        return {"ok": False, "reason": "transition_error"}
    _stamp_fulfillment(order_id, "returned")
    restocked = _restock_order(order_id, header) if restock else 0
    logger.info("bridge_return order=%s restocked_items=%s", order_id, restocked)
    return {"ok": True, "returned": True, "restocked_items": restocked}


def _catalog_item_key(category_id: str, item_id: str) -> Dict[str, str]:
    return {"PK": f"CAT#{category_id}", "SK": f"ITEM#{item_id}"}


def _restock_order(order_id: str, header: Dict[str, Any]) -> int:
    """Add each purchased line's qty back onto its catalog item's stock_count.

    The catalog table is keyed ``{PK: CAT#<category_id>, SK: ITEM#<item_id>}`` and
    the T.order_items rows do NOT reliably carry category_id — so we source the
    restock list from the buyer-debit transaction's stored cart items (which DO
    carry category_id + item_id + quantity), the same shape purchase_cart
    decremented. Only items that TRACK stock (stock_count present) are restocked;
    unlimited-stock items are skipped (mirrors the decrement guard). Idempotency
    is provided by the caller (mark_returned only runs once per return via CAS)."""
    txn_id = str(header.get("buyer_debit_txn_id") or "")
    buyer = str(header.get("user_id") or (header.get("metadata") or {}).get("user_id") or "")
    cart_items: List[Dict[str, Any]] = []
    if txn_id and buyer:
        try:
            from app.services import purchase_history as _ph
            txn = _ph.get_transaction_item(buyer, txn_id)
            cart_items = list((txn.get("metadata") or {}).get("items") or [])
        except Exception:
            logger.debug("bridge: restock txn load failed order=%s", order_id, exc_info=True)
    restocked = 0
    for ci in cart_items:
        cat_id = str(ci.get("category_id") or "")
        item_id = str(ci.get("item_id") or "")
        qty = int(ci.get("quantity") or 0)
        if not cat_id or not item_id or qty <= 0:
            continue
        try:
            key = _catalog_item_key(cat_id, item_id)
            existing = T.catalog.get_item(Key=key).get("Item")
            if not existing or existing.get("stock_count") is None:
                continue  # unlimited stock — skip
            T.catalog.update_item(
                Key=key,
                UpdateExpression="SET stock_count = stock_count + :q, stock_updated_at = :now",
                ExpressionAttributeValues={":q": qty, ":now": _now()},
                ConditionExpression="attribute_exists(stock_count)",
            )
            restocked += 1
        except Exception:
            logger.debug("bridge: restock line failed order=%s item=%s", order_id, item_id, exc_info=True)
    return restocked


def _now() -> int:
    import time
    return int(time.time())


# ── ECOMX-24: orphan / stuck-order reconciliation sweep ──────────────────────

def reconcile_stuck_orders(*, limit: int = 200) -> Dict[str, Any]:
    """Self-heal sweep. Two passes:

      (1) Orphan promotion: a header stuck at ``created`` that ALREADY carries a
          buyer_debit_txn_id (payment captured mid-purchase, then a crash before
          the approve tail) → promote to ``approved`` + populate ship groups.
      (2) Aggregate drift: any order with ship groups whose header lags its
          groups → reconcile_order.

    Idempotent; safe to run on a schedule. Returns counts."""
    if not _enabled():
        return {"ok": False, "reason": "disabled"}
    from boto3.dynamodb.conditions import Attr
    promoted = 0
    reconciled = 0
    matched = 0
    scanned = 0
    # DDB Scan applies the FilterExpression AFTER reading a page, so on a large
    # T.orders table a single Limit-capped scan reads N raw rows and may match
    # ZERO orphans even when one exists deeper in the table. Paginate over the
    # FULL table (bounded page budget) and STOP once `limit` orphans are healed.
    filt = (Attr("sk").eq("ORDER")
            & Attr("lifecycle_status").eq("created")
            & Attr("buyer_debit_txn_id").exists())
    lek = None
    pages = 0
    max_pages = 200  # safety bound
    target = max(1, min(int(limit), 1000))
    try:
        while pages < max_pages:
            pages += 1
            kwargs = {"FilterExpression": filt}
            if lek:
                kwargs["ExclusiveStartKey"] = lek
            resp = T.orders.scan(**kwargs)
            scanned += int(resp.get("ScannedCount", 0) or 0)
            for header in resp.get("Items", []):
                matched += 1
                order_id = str(header.get("order_id") or "")
                if not order_id:
                    continue
                if _promote_orphan(header):
                    promoted += 1
                    r = reconcile_order(order_id, actor="system:orphan-sweep",
                                        reason="orphan self-heal")
                    if r.get("ok"):
                        reconciled += 1
            lek = resp.get("LastEvaluatedKey")
            if not lek or promoted >= target:
                break
    except Exception:
        logger.exception("bridge: stuck-order scan failed")
    logger.info("bridge_orphan_sweep scanned=%s matched=%s promoted=%s reconciled=%s pages=%s",
                scanned, matched, promoted, reconciled, pages)
    return {"ok": True, "scanned": scanned, "matched": matched,
            "promoted": promoted, "reconciled": reconciled}


def _promote_orphan(header: Dict[str, Any]) -> bool:
    """Promote a paid-but-stuck ``created`` header to ``approved`` + populate its
    ship groups (the same tail purchase_cart runs post-charge). Returns True on a
    real promotion."""
    from app.services import order_lifecycle as _ol
    order_id = str(header.get("order_id") or "")
    txn_id = str(header.get("buyer_debit_txn_id") or "")
    if not order_id or not txn_id:
        return False
    # Confirm the transaction really captured payment before promoting. ECOMX-42
    # (B2) seeds a physical order's txn PENDING (it completes only on delivery),
    # so "paid" is now status in {PENDING, COMPLETED} — NOT a cancelled/reverted
    # txn. A missing txn (or an explicitly un-paid one) fails closed.
    try:
        buyer = str(header.get("user_id") or (header.get("metadata") or {}).get("user_id") or "")
        from app.services import purchase_history as _ph
        txn = _ph.get_transaction_item(buyer, txn_id) if buyer else None
        if not txn or str(txn.get("status") or "") not in ("PENDING", "COMPLETED"):
            return False
    except Exception:
        # If we can't confirm, do NOT promote (fail closed).
        logger.debug("bridge: orphan txn confirm failed order=%s", order_id, exc_info=True)
        return False
    try:
        _ol.transition_order(order_id, "approved", actor="system:orphan-sweep",
                             reason="Orphan promotion (paid txn, stuck created)",
                             idempotency_key=f"bridge:orphan:{order_id}")
    except _ol.OrderConflictError:
        return False
    except _ol.OrderTransitionError:
        return False
    except Exception:
        logger.exception("bridge: orphan promote failed order=%s", order_id)
        return False
    # Populate ship groups from the txn's stored cart items (idempotent).
    try:
        meta = dict(txn.get("metadata") or {})
        items = list(meta.get("items") or [])
        if items:
            from app.services import seller_ship_groups as _ssg
            _ssg.populate_on_approval(
                order_id=order_id, buyer_sub=buyer, cart_items=items,
                buyer=meta.get("buyer") or txn.get("buyer_profile"),
                currency=str(txn.get("currency") or "USD"),
            )
    except Exception:
        logger.exception("bridge: orphan populate ship-groups failed order=%s", order_id)
    return True


# ── canonical buyer read: order → all its ship-group tracking records ─────────

def order_tracking(order_id: str, buyer_sub: Optional[str] = None) -> Dict[str, Any]:
    """ECOMX-23: the ONE canonical buyer order-tracking read. Resolves ALL of an
    order's seller ship groups → their shipment_tracking records so the buyer's
    tracking populates off the ORDER (fixing the txn-vs-ship-group key mismatch).
    When ``buyer_sub`` is given it is enforced (a buyer only sees their order)."""
    from app.services import seller_ship_groups as _ssg
    from app.services import shipment_tracking as _st

    groups = _ssg.list_by_order(order_id)
    if buyer_sub is not None:
        groups = [g for g in groups if str(g.get("buyer_id")) == str(buyer_sub)]
    shipments: List[Dict[str, Any]] = []
    for g in groups:
        sg_id = str(g.get("ship_group_id") or "")
        rec = _st.get_tracking(sg_id)
        if rec:
            shipments.append(_st.to_public(rec))
        else:
            # shipped-but-no-tracking or not-yet-shipped: expose the group stage.
            shipments.append({
                "ship_group_id": sg_id, "order_id": order_id,
                "carrier": g.get("carrier") or "", "tracking_number": g.get("tracking_number") or "",
                "tracking_url": "", "status": g.get("status") or "", "events": [],
                "created_at": int(g.get("created_at") or 0),
                "updated_at": int(g.get("updated_at") or 0),
            })
    agg = compute_aggregate(order_id)
    fulfillment = agg[1] if agg else "unfulfilled"
    return {
        "order_id": order_id,
        "fulfillment_status": fulfillment,
        "shipment_count": len(shipments),
        "shipments": shipments,
    }


# ── ECOMX-E1: compact inline shipments for the buyer ORDER surfaces ──────────

def order_shipments_inline(order_id: str, buyer_sub: Optional[str] = None) -> Dict[str, Any]:
    """ECOMX-E1: the buyer discovery/inline join. Returns
    ``{"fulfillment_status", "shipments": [<compact>]}`` for an order so the
    buyers order LIST + DETAIL can surface the real carrier / tracking# /
    status the seller entered WITHOUT the buyer ever needing the ship_group_id.

    Delegates the actual order→ship-group→tracking join (and the buyer scope
    enforcement) to :func:`order_tracking` so there is exactly ONE join and the
    inline surfaces can never contradict the canonical ``/tracking`` read. Each
    shipment is flattened to the fields a buyer list/detail row needs plus a
    single ``last_event`` (the most-recent carrier event). Never raises — a
    bridge failure returns an empty inline block so the order still renders.
    """
    try:
        data = order_tracking(order_id, buyer_sub=buyer_sub)
    except Exception:
        logger.debug("bridge: order_shipments_inline failed order=%s", order_id, exc_info=True)
        return {"fulfillment_status": None, "shipment_count": 0, "shipments": []}
    compact: List[Dict[str, Any]] = []
    for s in data.get("shipments", []) or []:
        events = s.get("events") or []
        last = events[-1] if events else None
        compact.append({
            "ship_group_id": s.get("ship_group_id") or "",
            "carrier": s.get("carrier") or "",
            "tracking_number": s.get("tracking_number") or "",
            "tracking_url": s.get("tracking_url") or "",
            "status": s.get("status") or "",
            "last_event": ({
                "status": str(last.get("status") or ""),
                "description": str(last.get("description") or ""),
                "ts": int(last.get("ts") or 0),
            } if last else None),
            "updated_at": int(s.get("updated_at") or 0),
        })
    return {
        "fulfillment_status": data.get("fulfillment_status"),
        "shipment_count": len(compact),
        "shipments": compact,
    }
