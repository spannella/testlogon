"""OFBiz-inspired inventory & soft-reservation service (ADR-001, OFB-003/004).

Phase-1 / foundation slice of the OFBiz commerce/ERP cherry-pick. This is an
*additive*, **flag-gated** (``INVENTORY_RESERVATIONS_ENABLED``, default OFF)
service that re-models stock as a first-class record (SKU -> on_hand / reserved
/ available / reorder_point) with a soft-reservation lifecycle
(reserve -> commit -> release/expire), mapped onto DynamoDB.

It does NOT rewire the existing catalog/cart/billing decrement-at-purchase path
(``app/services/shoppingcart.py``); with the flag off this module is dormant and
existing behaviour is byte-for-byte unchanged. Hooking ``purchase_cart`` into the
reservation lifecycle is an explicit OFB-004-completion follow-up.

Design notes / invariants
--------------------------
* ``available = on_hand - reserved`` is recomputed and persisted on every
  mutation so the ``GSI_AVAILABLE`` (numeric ``available``) index stays correct
  for the low-stock filter.
* Reserve uses a single-writer conditional update on the inventory row
  (``available >= :qty``) so the oversell race resolves to exactly one winner —
  the loser gets a 409, mirroring the existing ``purchase_cart`` out-of-stock
  path (ADR "oversell race" mitigation).
* Commit / release / expire flip the reservation row's terminal ``status`` with
  a ``status = active`` guard so they are idempotent under replay/concurrency.
* Every mutation emits an ``alerts.audit_event`` (best-effort).

SECOPS-007 parity: identical code in dev (moto / local DDB) and prod (real DDB);
no ``dev_mode`` branch in the business logic.
"""
from __future__ import annotations

import uuid
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError
from fastapi import HTTPException

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

DEFAULT_LOCATION = "warehouse"
_ACTIVE_EXPIRY_PARTITION = "SCHED#ACTIVE"


# ───────────────────────────── helpers ─────────────────────────────


def _flag_on() -> bool:
    return bool(getattr(S, "inventory_reservations_enabled", False))


def _require_enabled() -> None:
    if not _flag_on():
        raise HTTPException(status_code=404, detail="Inventory reservations are not enabled")


def _location_sk(location_id: str) -> str:
    return f"LOC#{location_id}"


def _reservation_pk(reservation_id: str) -> str:
    return f"RES#{reservation_id}"


def _to_int(value: Any, default: int = 0) -> int:
    try:
        if value is None:
            return default
        return int(value)
    except (TypeError, ValueError):
        return default


def _default_reorder_point() -> int:
    return _to_int(getattr(S, "catalog_default_low_stock_threshold", 5), 5)


def _default_ttl() -> int:
    return _to_int(getattr(S, "inventory_reservation_ttl_seconds", 1800), 1800)


def _status_for(available: int, reorder_point: int) -> str:
    if available <= 0:
        return "out_of_stock"
    if available <= reorder_point:
        return "low_stock"
    return "in_stock"


def _audit(event: str, user_sub: str, **fields: Any) -> None:
    try:
        from app.services.alerts import audit_event

        audit_event(event, user_sub or "system", None, **fields)
    except Exception:
        pass


def _record_out(item: Dict[str, Any]) -> Dict[str, Any]:
    on_hand = _to_int(item.get("on_hand"))
    reserved = _to_int(item.get("reserved"))
    reorder_point = _to_int(item.get("reorder_point"), _default_reorder_point())
    available = on_hand - reserved
    return {
        "sku": item.get("sku"),
        "location_id": item.get("location_id", DEFAULT_LOCATION),
        "on_hand": on_hand,
        "reserved": reserved,
        "available": available,
        "reorder_point": reorder_point,
        "status": _status_for(available, reorder_point),
        "updated_at": _to_int(item.get("updated_at")),
    }


def _get_raw(sku: str, location_id: str) -> Optional[Dict[str, Any]]:
    resp = T.inventory.get_item(Key={"sku": sku, "location_sk": _location_sk(location_id)})
    return resp.get("Item")


def _persist(
    sku: str,
    location_id: str,
    *,
    on_hand: int,
    reserved: int,
    reorder_point: int,
) -> Dict[str, Any]:
    available = on_hand - reserved
    item = {
        "sku": sku,
        "location_sk": _location_sk(location_id),
        "location_id": location_id,
        "on_hand": int(on_hand),
        "reserved": int(reserved),
        "available": int(available),
        "reorder_point": int(reorder_point),
        "status": _status_for(available, reorder_point),
        "updated_at": now_ts(),
    }
    T.inventory.put_item(Item=item)
    return item


# ───────────────────────────── inventory CRUD (OFB-003) ─────────────────────────────


def get_inventory(sku: str, location_id: str = DEFAULT_LOCATION) -> Optional[Dict[str, Any]]:
    """Return the inventory record for a SKU (None if it does not exist)."""
    item = _get_raw(sku, location_id)
    if not item:
        return None
    return _record_out(item)


def get_or_zero(sku: str, location_id: str = DEFAULT_LOCATION) -> Dict[str, Any]:
    """Return the inventory record, or a zeroed virtual record if absent."""
    rec = get_inventory(sku, location_id)
    if rec is not None:
        return rec
    rp = _default_reorder_point()
    return {
        "sku": sku,
        "location_id": location_id,
        "on_hand": 0,
        "reserved": 0,
        "available": 0,
        "reorder_point": rp,
        "status": "out_of_stock",
        "updated_at": 0,
    }


def set_on_hand(
    sku: str,
    qty: int,
    *,
    reason: Optional[str] = None,
    location_id: str = DEFAULT_LOCATION,
    reorder_point: Optional[int] = None,
    user_sub: str = "system",
) -> Dict[str, Any]:
    """Set absolute on-hand quantity; preserves existing reservations."""
    if qty < 0:
        raise HTTPException(status_code=422, detail="on_hand must be >= 0")
    existing = _get_raw(sku, location_id)
    before_on_hand = _to_int(existing.get("on_hand")) if existing else 0
    reserved = _to_int(existing.get("reserved")) if existing else 0
    rp = (
        int(reorder_point)
        if reorder_point is not None
        else _to_int(existing.get("reorder_point"), _default_reorder_point()) if existing else _default_reorder_point()
    )
    item = _persist(sku, location_id, on_hand=qty, reserved=reserved, reorder_point=rp)
    _audit(
        "inventory.set_on_hand",
        user_sub,
        sku=sku,
        location_id=location_id,
        before=before_on_hand,
        after=qty,
        reason=reason or "set_on_hand",
    )
    return _record_out(item)


def adjust(
    sku: str,
    delta: int,
    reason: str,
    *,
    location_id: str = DEFAULT_LOCATION,
    user_sub: str = "system",
) -> Dict[str, Any]:
    """Atomically adjust on-hand by ``delta`` (may be negative).

    Negative adjustments are guarded so on_hand can never go below the currently
    reserved quantity (would make ``available`` negative).
    """
    existing = _get_raw(sku, location_id)
    reserved = _to_int(existing.get("reserved")) if existing else 0
    rp = _to_int(existing.get("reorder_point"), _default_reorder_point()) if existing else _default_reorder_point()
    if existing is None:
        # Create-on-adjust only makes sense for positive deltas.
        if delta < 0:
            raise HTTPException(status_code=409, detail="Cannot decrement nonexistent inventory")
        try:
            T.inventory.put_item(
                Item={
                    "sku": sku,
                    "location_sk": _location_sk(location_id),
                    "location_id": location_id,
                    "on_hand": int(delta),
                    "reserved": 0,
                    "available": int(delta),
                    "reorder_point": int(rp),
                    "status": _status_for(int(delta), rp),
                    "updated_at": now_ts(),
                },
                ConditionExpression="attribute_not_exists(sku)",
            )
        except ClientError as exc:
            if exc.response["Error"].get("Code") == "ConditionalCheckFailedException":
                # Lost a race — fall through to the increment path below.
                return adjust(sku, delta, reason, location_id=location_id, user_sub=user_sub)
            raise
        rec = get_inventory(sku, location_id) or get_or_zero(sku, location_id)
        _audit("inventory.adjust", user_sub, sku=sku, location_id=location_id, delta=delta, reason=reason, after=rec["on_hand"])
        return rec

    before = _to_int(existing.get("on_hand"))
    new_on_hand = before + int(delta)
    new_available = new_on_hand - reserved
    if new_available < 0:
        raise HTTPException(
            status_code=409,
            detail="Adjustment would drop on-hand below reserved quantity",
        )
    # Optimistic single-writer guard: the row must be unchanged since we read it
    # (DDB condition expressions don't support arithmetic, so we pin on_hand +
    # reserved). Concurrent mutation -> 409, caller retries.
    try:
        resp = T.inventory.update_item(
            Key={"sku": sku, "location_sk": _location_sk(location_id)},
            UpdateExpression=(
                "SET on_hand = :new_oh, available = :new_av, #status = :st, updated_at = :now"
            ),
            ConditionExpression="on_hand = :exp_oh AND reserved = :exp_res",
            ExpressionAttributeNames={"#status": "status"},
            ExpressionAttributeValues={
                ":new_oh": new_on_hand,
                ":new_av": new_available,
                ":st": _status_for(new_available, rp),
                ":now": now_ts(),
                ":exp_oh": before,
                ":exp_res": reserved,
            },
            ReturnValues="ALL_NEW",
        )
    except ClientError as exc:
        if exc.response["Error"].get("Code") == "ConditionalCheckFailedException":
            # Row moved under us — retry once against the fresh state.
            return adjust(sku, delta, reason, location_id=location_id, user_sub=user_sub)
        raise
    new_item = resp.get("Attributes", {})
    new_on_hand = _to_int(new_item.get("on_hand"))
    _audit(
        "inventory.adjust",
        user_sub,
        sku=sku,
        location_id=location_id,
        delta=delta,
        reason=reason,
        before=before,
        after=new_on_hand,
    )
    rec = get_inventory(sku, location_id)
    return rec or get_or_zero(sku, location_id)


def set_reorder_point(
    sku: str,
    reorder_point: int,
    *,
    location_id: str = DEFAULT_LOCATION,
    user_sub: str = "system",
) -> Dict[str, Any]:
    existing = _get_raw(sku, location_id)
    on_hand = _to_int(existing.get("on_hand")) if existing else 0
    reserved = _to_int(existing.get("reserved")) if existing else 0
    item = _persist(sku, location_id, on_hand=on_hand, reserved=reserved, reorder_point=int(reorder_point))
    _audit("inventory.set_reorder_point", user_sub, sku=sku, location_id=location_id, reorder_point=reorder_point)
    return _record_out(item)


def list_low_stock(location_status: str = "low_stock") -> List[Dict[str, Any]]:
    """List inventory records in a given derived status via GSI_AVAILABLE."""
    out: List[Dict[str, Any]] = []
    kwargs: Dict[str, Any] = {
        "IndexName": "GSI_AVAILABLE",
        "KeyConditionExpression": Key("status").eq(location_status),
    }
    while True:
        resp = T.inventory.query(**kwargs)
        for it in resp.get("Items", []):
            out.append(_record_out(it))
        lek = resp.get("LastEvaluatedKey")
        if not lek:
            break
        kwargs["ExclusiveStartKey"] = lek
    return out


# ───────────────────────────── reservation lifecycle (OFB-004) ─────────────────────────────


def reserve(
    sku: str,
    quantity: int,
    *,
    location_id: str = DEFAULT_LOCATION,
    user_sub: str = "system",
    cart_id: Optional[str] = None,
    ttl_seconds: Optional[int] = None,
) -> Dict[str, Any]:
    """Soft-reserve ``quantity`` units of ``sku``.

    Increments ``reserved`` (and decrements ``available``) on the inventory row
    via a single-writer conditional update (``available >= :qty``); writes a
    reservation row. Raises 409 if insufficient available stock — the loser of
    an oversell race lands here.
    """
    if quantity < 1:
        raise HTTPException(status_code=422, detail="quantity must be >= 1")
    existing = _get_raw(sku, location_id)
    if existing is None:
        raise HTTPException(status_code=409, detail=f"No inventory for SKU '{sku}'")
    rp = _to_int(existing.get("reorder_point"), _default_reorder_point())
    try:
        resp = T.inventory.update_item(
            Key={"sku": sku, "location_sk": _location_sk(location_id)},
            UpdateExpression="SET reserved = reserved + :q, available = available - :q, updated_at = :now",
            ConditionExpression="available >= :q",
            ExpressionAttributeValues={":q": int(quantity), ":now": now_ts()},
            ReturnValues="ALL_NEW",
        )
    except ClientError as exc:
        if exc.response["Error"].get("Code") == "ConditionalCheckFailedException":
            raise HTTPException(status_code=409, detail=f"Item '{sku}' is out of stock") from exc
        raise
    new_item = resp.get("Attributes", {})
    new_available = _to_int(new_item.get("available"))
    # Keep derived status in sync.
    T.inventory.update_item(
        Key={"sku": sku, "location_sk": _location_sk(location_id)},
        UpdateExpression="SET #status = :st",
        ExpressionAttributeNames={"#status": "status"},
        ExpressionAttributeValues={":st": _status_for(new_available, rp)},
    )

    reservation_id = uuid.uuid4().hex
    created = now_ts()
    ttl = int(ttl_seconds) if ttl_seconds else _default_ttl()
    expires_at = created + ttl
    res_item = {
        "reservation_pk": _reservation_pk(reservation_id),
        "sk": "META",
        "reservation_id": reservation_id,
        "sku": sku,
        "location_id": location_id,
        "quantity": int(quantity),
        "status": "active",
        "user_sub": user_sub,
        "created_at": created,
        "expires_at": expires_at,
        "gsi_expiry_pk": _ACTIVE_EXPIRY_PARTITION,
    }
    # cart_id is the hash key of the sparse GSI_CART index (type S). Only write it
    # when present — a None value is an invalid attribute type for an indexed key
    # and makes PutItem fail with ValidationException ("Invalid attribute value
    # type"). Omitting it simply leaves the row out of GSI_CART (sparse index).
    if cart_id:
        res_item["cart_id"] = cart_id
    T.reservations.put_item(Item=res_item)
    _audit(
        "inventory.reserve",
        user_sub,
        sku=sku,
        location_id=location_id,
        quantity=quantity,
        reservation_id=reservation_id,
        cart_id=cart_id,
    )
    return _reservation_out(res_item)


def _reservation_out(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "reservation_id": item.get("reservation_id"),
        "sku": item.get("sku"),
        "location_id": item.get("location_id", DEFAULT_LOCATION),
        "quantity": _to_int(item.get("quantity")),
        "status": item.get("status"),
        "cart_id": item.get("cart_id"),
        "user_sub": item.get("user_sub"),
        "created_at": _to_int(item.get("created_at")),
        "expires_at": _to_int(item.get("expires_at")),
    }


def get_reservation(reservation_id: str) -> Optional[Dict[str, Any]]:
    resp = T.reservations.get_item(Key={"reservation_pk": _reservation_pk(reservation_id), "sk": "META"})
    item = resp.get("Item")
    return _reservation_out(item) if item else None


def _close_reservation(reservation_id: str, terminal_status: str) -> Optional[Dict[str, Any]]:
    """Flip an *active* reservation to a terminal status (idempotent).

    Returns the reservation item (raw) on the first successful transition, or
    None if the reservation was already terminal / missing (no-op replay).
    """
    try:
        resp = T.reservations.update_item(
            Key={"reservation_pk": _reservation_pk(reservation_id), "sk": "META"},
            UpdateExpression="SET #status = :new, closed_at = :now REMOVE gsi_expiry_pk",
            ConditionExpression="#status = :active",
            ExpressionAttributeNames={"#status": "status"},
            ExpressionAttributeValues={":new": terminal_status, ":active": "active", ":now": now_ts()},
            ReturnValues="ALL_OLD",
        )
        return resp.get("Attributes")
    except ClientError as exc:
        if exc.response["Error"].get("Code") == "ConditionalCheckFailedException":
            return None  # already terminal — idempotent no-op
        raise


def commit_reservation(reservation_id: str, *, user_sub: str = "system") -> Dict[str, Any]:
    """Convert an active reservation into an on-hand decrement (sale).

    Decrements both ``on_hand`` and ``reserved`` by the reserved quantity;
    ``available`` is unchanged (the units were already removed from available at
    reserve time). Idempotent: replays after commit are no-ops.
    """
    old = _close_reservation(reservation_id, "committed")
    if old is None:
        rec = get_reservation(reservation_id)
        if rec is None:
            raise HTTPException(status_code=404, detail="Reservation not found")
        return rec
    sku = old.get("sku")
    location_id = old.get("location_id", DEFAULT_LOCATION)
    qty = _to_int(old.get("quantity"))
    existing = _get_raw(sku, location_id)
    rp = _to_int(existing.get("reorder_point"), _default_reorder_point()) if existing else _default_reorder_point()
    resp = T.inventory.update_item(
        Key={"sku": sku, "location_sk": _location_sk(location_id)},
        UpdateExpression="SET on_hand = on_hand - :q, reserved = reserved - :q, updated_at = :now",
        ExpressionAttributeValues={":q": qty, ":now": now_ts()},
        ReturnValues="ALL_NEW",
    )
    new_item = resp.get("Attributes", {})
    new_available = _to_int(new_item.get("on_hand")) - _to_int(new_item.get("reserved"))
    T.inventory.update_item(
        Key={"sku": sku, "location_sk": _location_sk(location_id)},
        UpdateExpression="SET #status = :st",
        ExpressionAttributeNames={"#status": "status"},
        ExpressionAttributeValues={":st": _status_for(new_available, rp)},
    )
    _audit("inventory.commit_reservation", user_sub, sku=sku, location_id=location_id, quantity=qty, reservation_id=reservation_id)
    return get_reservation(reservation_id) or _reservation_out(old)


def release_reservation(
    reservation_id: str,
    *,
    reason: str = "released",
    user_sub: str = "system",
    terminal_status: str = "released",
) -> Dict[str, Any]:
    """Release an active reservation back to available stock (idempotent)."""
    old = _close_reservation(reservation_id, terminal_status)
    if old is None:
        rec = get_reservation(reservation_id)
        if rec is None:
            raise HTTPException(status_code=404, detail="Reservation not found")
        return rec
    sku = old.get("sku")
    location_id = old.get("location_id", DEFAULT_LOCATION)
    qty = _to_int(old.get("quantity"))
    existing = _get_raw(sku, location_id)
    rp = _to_int(existing.get("reorder_point"), _default_reorder_point()) if existing else _default_reorder_point()
    resp = T.inventory.update_item(
        Key={"sku": sku, "location_sk": _location_sk(location_id)},
        UpdateExpression="SET reserved = reserved - :q, available = available + :q, updated_at = :now",
        ExpressionAttributeValues={":q": qty, ":now": now_ts()},
        ReturnValues="ALL_NEW",
    )
    new_item = resp.get("Attributes", {})
    new_available = _to_int(new_item.get("available"))
    T.inventory.update_item(
        Key={"sku": sku, "location_sk": _location_sk(location_id)},
        UpdateExpression="SET #status = :st",
        ExpressionAttributeNames={"#status": "status"},
        ExpressionAttributeValues={":st": _status_for(new_available, rp)},
    )
    _audit(
        "inventory.release_reservation",
        user_sub,
        sku=sku,
        location_id=location_id,
        quantity=qty,
        reservation_id=reservation_id,
        reason=reason,
        terminal_status=terminal_status,
    )
    return get_reservation(reservation_id) or _reservation_out(old)


def expire_due_reservations(*, now: Optional[int] = None, limit: int = 200) -> int:
    """Release all active reservations whose ``expires_at`` is in the past.

    Driven by the TTL-release background loop. Returns the count released.
    Reuses ``release_reservation`` (so available is restored + audited), with the
    conditional-update guard making concurrent runs safe.
    """
    cutoff = now if now is not None else now_ts()
    released = 0
    kwargs: Dict[str, Any] = {
        "IndexName": "GSI_EXPIRY",
        "KeyConditionExpression": Key("gsi_expiry_pk").eq(_ACTIVE_EXPIRY_PARTITION) & Key("expires_at").lte(cutoff),
        "Limit": limit,
    }
    resp = T.reservations.query(**kwargs)
    for it in resp.get("Items", []):
        rid = it.get("reservation_id")
        if not rid:
            continue
        try:
            release_reservation(rid, reason="ttl_expired", user_sub="system", terminal_status="expired")
            released += 1
        except Exception:
            continue
    return released
