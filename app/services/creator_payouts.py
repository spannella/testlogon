"""Creator Payout service (MON-004).

Manages payout requests, balance calculations, and admin approval workflow.
"""

from __future__ import annotations

import logging
import uuid
from decimal import Decimal
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Attr, Key
from botocore.exceptions import ClientError

from app.core.cursor import decode_cursor, encode_cursor
from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)

# Valid payout states
PAYOUT_STATES = {"requested", "approved", "processing", "completed", "rejected", "cancelled", "failed"}
ACTIVE_PAYOUT_STATES = {"requested", "approved", "processing"}

# GAP-0195 (FIN-009): payout destination methods.
# The CreatorPayouts table is keyed by a single HASH attribute (``payout_id``),
# so payout-method records are co-located in the same table keyed by their
# ``method_id`` (stored in ``payout_id``) and tagged with ``record_kind`` to
# distinguish them from real payout records. They carry ``user_id`` so the
# existing ``ByUserCreatedAt`` GSI can list a creator's methods.
PAYOUT_METHOD_TYPES = {"bank_ach", "bank_wire", "paypal", "check"}
PAYOUT_METHOD_KIND = "payout_method"

# GAP-0309 (MON-004): record_kind for the per-user active-payout sentinel row,
# co-located in the same single-key CreatorPayouts table.
PAYOUT_STATE_KIND = "payout_state"


def _is_payout_method(item: Dict[str, Any]) -> bool:
    return item.get("record_kind") == PAYOUT_METHOD_KIND


def _is_real_payout(item: Dict[str, Any]) -> bool:
    """True only for actual payout records (not co-located method / state rows).

    The CreatorPayouts table is single-table: it also holds ``payout_method``
    rows and the per-user ``payout_state`` sentinel (GAP-0309). Listing/scanning
    code must exclude both.
    """
    return item.get("record_kind") not in (PAYOUT_METHOD_KIND, PAYOUT_STATE_KIND)


def _to_int(val: Any) -> int:
    """Coerce DynamoDB Decimal or string to int."""
    if isinstance(val, Decimal):
        return int(val)
    if isinstance(val, (int, float)):
        return int(val)
    if isinstance(val, str) and val.isdigit():
        return int(val)
    return 0


def _payout_to_dict(item: Dict[str, Any]) -> Dict[str, Any]:
    """Convert a DDB payout item to a clean dict."""
    return {
        "payout_id": item.get("payout_id", ""),
        "user_id": item.get("user_id", ""),
        "amount_cents": _to_int(item.get("amount_cents", 0)),
        "method": item.get("method", "bank_transfer"),
        "method_id": item.get("method_id", ""),
        "status": item.get("status", ""),
        "created_at": _to_int(item.get("created_at", 0)),
        "updated_at": _to_int(item.get("updated_at", 0)),
        "notes": item.get("notes", ""),
        "reject_reason": item.get("reject_reason", ""),
        "approved_by": item.get("approved_by", ""),
        "completed_at": _to_int(item.get("completed_at", 0)) or None,
    }


def get_available_balance(user_id: str) -> dict:
    """Calculate available balance from billing ledger credits.

    Queries T.billing for pk=USER#{user_id}, sk begins_with LEDGER#,
    type=credit. Only includes entries where ts + hold_period <= now_ts().
    Subtracts any pending/approved/processing payout amounts.

    Returns: {available_cents, pending_cents, total_earned_cents, hold_cents}
    """
    pk = f"USER#{user_id}"
    now = now_ts()
    hold_period = S.payout_hold_period_seconds

    key_cond = Key("pk").eq(pk) & Key("sk").begins_with("LEDGER#")
    # GAP-0308 (MON-004): only sum *valid* credits. Exclude reversed/chargedback
    # credits (``state=reversed``) and zero-amount subscription-access entitlement
    # records (``amount_cents=0``) which would otherwise inflate the available
    # balance and let creators withdraw funds that were actually clawed back.
    # ``Attr("state").ne("reversed")`` is True on items with NO ``state`` attr in
    # DynamoDB, so legacy credit entries (written without ``state``) still count —
    # backward compatible.
    filter_expr = (
        Attr("type").eq("credit")
        & Attr("state").ne("reversed")
        & Attr("amount_cents").gt(0)
    )

    total_earned_cents = 0
    available_cents = 0
    hold_cents = 0

    query_kwargs: Dict[str, Any] = {
        "KeyConditionExpression": key_cond,
        "FilterExpression": filter_expr,
    }

    while True:
        resp = T.billing.query(**query_kwargs)
        items = resp.get("Items", [])

        for item in items:
            amount = _to_int(item.get("amount_cents", 0))
            ts = _to_int(item.get("ts", 0))
            total_earned_cents += amount

            if ts + hold_period <= now:
                available_cents += amount
            else:
                hold_cents += amount

        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break
        query_kwargs["ExclusiveStartKey"] = last_key

    # Subtract pending/approved/processing payouts
    pending_cents = _get_active_payout_total(user_id)
    available_cents = max(0, available_cents - pending_cents)

    return {
        "available_cents": available_cents,
        "pending_cents": pending_cents,
        "total_earned_cents": total_earned_cents,
        "hold_cents": hold_cents,
    }


def _get_active_payout_total(user_id: str) -> int:
    """Sum of amounts for all active payouts (requested/approved/processing)."""
    total = 0

    query_kwargs: Dict[str, Any] = {
        "IndexName": "ByUserCreatedAt",
        "KeyConditionExpression": Key("user_id").eq(user_id),
        "ScanIndexForward": False,
    }

    while True:
        resp = T.creator_payouts.query(**query_kwargs)
        items = resp.get("Items", [])

        for item in items:
            if _is_payout_method(item):
                continue
            status = item.get("status", "")
            if status in ACTIVE_PAYOUT_STATES:
                total += _to_int(item.get("amount_cents", 0))

        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break
        query_kwargs["ExclusiveStartKey"] = last_key

    return total


def _has_active_payout(user_id: str) -> bool:
    """Check if user has any active (requested/approved/processing) payout."""
    query_kwargs: Dict[str, Any] = {
        "IndexName": "ByUserCreatedAt",
        "KeyConditionExpression": Key("user_id").eq(user_id),
        "ScanIndexForward": False,
        "Limit": 50,
    }

    while True:
        resp = T.creator_payouts.query(**query_kwargs)
        items = resp.get("Items", [])

        for item in items:
            if _is_payout_method(item):
                continue
            status = item.get("status", "")
            if status in ACTIVE_PAYOUT_STATES:
                return True

        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break
        query_kwargs["ExclusiveStartKey"] = last_key

    return False


# ─── Atomic active-payout sentinel (GAP-0309 / MON-004) ────────────────────
#
# The CreatorPayouts table is keyed by a single HASH attribute (``payout_id``),
# so the per-user "active payout" sentinel is co-located in the same table under
# a reserved ``payout_id`` value. ``claim_payout_sentinel`` does a *conditional*
# write that only succeeds when no active payout is currently claimed for the
# user, giving us a single atomic gate: two concurrent ``request_payout`` calls
# can no longer both pass the ``_has_active_payout`` / balance checks and both
# write — exactly one wins the conditional claim, the other is rejected with the
# same DUPLICATE_PAYOUT error. The sentinel is released when the claimed payout
# reaches a terminal state (completed / cancelled / rejected / failed).


def _payout_state_id(user_id: str) -> str:
    return f"PAYOUT_STATE#{user_id}"


def claim_payout_sentinel(user_id: str, payout_id: str) -> None:
    """Atomically reserve the per-user active-payout slot for ``payout_id``.

    Raises ``ValueError("DUPLICATE_PAYOUT")`` if another active payout already
    holds the slot. Implemented as a conditional ``update_item`` so the
    read-check-write race in ``request_payout`` collapses to a single atomic op.
    The condition succeeds when the sentinel row is absent OR its
    ``active_payout_id`` attribute is absent (i.e. previously released).
    """
    now = now_ts()
    try:
        T.creator_payouts.update_item(
            Key={"payout_id": _payout_state_id(user_id)},
            UpdateExpression=(
                "SET active_payout_id = :pid, user_id = :uid, "
                "record_kind = :kind, updated_at = :now"
            ),
            ConditionExpression="attribute_not_exists(active_payout_id)",
            ExpressionAttributeValues={
                ":pid": payout_id,
                ":uid": user_id,
                ":kind": PAYOUT_STATE_KIND,
                ":now": now,
            },
        )
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            raise ValueError("DUPLICATE_PAYOUT") from exc
        raise


def release_payout_sentinel(user_id: str, payout_id: Optional[str] = None) -> None:
    """Release the per-user active-payout slot once a payout is terminal.

    Best-effort + idempotent: removing the ``active_payout_id`` attribute. When
    ``payout_id`` is supplied the release is guarded so we only clear the slot if
    it is still held by *that* payout (avoids a terminal transition of an old
    payout clobbering a freshly claimed one). Never raises.
    """
    kwargs: Dict[str, Any] = {
        "Key": {"payout_id": _payout_state_id(user_id)},
        "UpdateExpression": "REMOVE active_payout_id",
    }
    if payout_id is not None:
        kwargs["ConditionExpression"] = "active_payout_id = :pid"
        kwargs["ExpressionAttributeValues"] = {":pid": payout_id}
    try:
        T.creator_payouts.update_item(**kwargs)
    except ClientError as exc:
        # Slot already released / held by a different payout — nothing to do.
        if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            return
        logger.warning("payout_sentinel_release_failed user_id=%s: %s", user_id, exc)
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning("payout_sentinel_release_failed user_id=%s: %s", user_id, exc)


def request_payout(
    user_id: str,
    amount_cents: int,
    method: str = "bank_transfer",
    notes: str = "",
    method_id: Optional[str] = None,
) -> dict:
    """Create a payout request.

    Validates:
    - amount >= minimum (1000 cents / $10)
    - amount <= available_balance
    - No other active payout exists for user

    When ``method_id`` is supplied it must reference a payout method owned by the
    user; the stored ``method`` string is then derived from that method's type so
    admins have real routing context. If omitted, the creator's default payout
    method is used when one exists (GAP-0195 / FIN-009).

    Returns: {payout_id, amount_cents, status, created_at}
    """
    # FIN-018: prefer the runtime DB override (falls back to S.payout_minimum_cents).
    try:
        from app.services.billing_config import get_min_payout_cents

        minimum = get_min_payout_cents()
    except Exception:
        minimum = S.payout_minimum_cents
    if amount_cents < minimum:
        raise ValueError(f"Amount must be at least {minimum} cents (${minimum / 100:.2f})")

    # Fast pre-check (cheap, friendly error before claiming the atomic slot).
    if _has_active_payout(user_id):
        raise ValueError("DUPLICATE_PAYOUT")

    payout_id = f"payout_{uuid.uuid4().hex}"

    # GAP-0309: atomically claim the per-user active-payout slot. This collapses
    # the previous read-check-then-write race: two concurrent requests can no
    # longer both pass the checks above and both ``put_item``. Exactly one wins
    # the conditional claim; the loser surfaces the SAME DUPLICATE_PAYOUT error.
    claim_payout_sentinel(user_id, payout_id)

    try:
        # Check available balance (after the slot is claimed so a concurrent
        # request can't double-spend the same balance).
        balance = get_available_balance(user_id)
        if amount_cents > balance["available_cents"]:
            raise ValueError(f"Insufficient balance. Available: {balance['available_cents']} cents")

        # Resolve the payout destination (GAP-0195 / FIN-009).
        resolved_method = method
        resolved_method_id = ""
        if method_id:
            mitem = T.creator_payouts.get_item(Key={"payout_id": method_id}).get("Item")
            if (
                not mitem
                or not _is_payout_method(mitem)
                or mitem.get("user_id") != user_id
            ):
                raise ValueError("invalid_method_id:Payout method not found or not yours")
            resolved_method = mitem.get("method_type", method)
            resolved_method_id = method_id
        else:
            default = get_default_payout_method(user_id)
            if default:
                resolved_method = default["method_type"]
                resolved_method_id = default["method_id"]

        now = now_ts()
        item = {
            "payout_id": payout_id,
            "user_id": user_id,
            "amount_cents": amount_cents,
            "method": resolved_method,
            "method_id": resolved_method_id,
            "status": "requested",
            "created_at": now,
            "updated_at": now,
            "notes": notes,
            "reject_reason": "",
            "approved_by": "",
        }

        # ``attribute_not_exists(payout_id)`` guards against an accidental
        # overwrite of an existing record sharing this id (ids are unique, so
        # this is belt-and-braces).
        T.creator_payouts.put_item(
            Item=item,
            ConditionExpression="attribute_not_exists(payout_id)",
        )
    except Exception:
        # Validation / write failed — release the slot so the creator can retry.
        release_payout_sentinel(user_id, payout_id)
        raise

    return _payout_to_dict(item)


def cancel_payout(payout_id: str, user_id: str) -> dict:
    """Cancel a payout request (creator only, status must be requested or approved)."""
    resp = T.creator_payouts.get_item(Key={"payout_id": payout_id})
    item = resp.get("Item")
    if not item:
        raise LookupError("Payout not found")

    if item.get("user_id") != user_id:
        raise PermissionError("Not your payout")

    status = item.get("status", "")
    if status not in ("requested", "approved"):
        raise ValueError(f"Cannot cancel payout in '{status}' state")

    now = now_ts()
    T.creator_payouts.update_item(
        Key={"payout_id": payout_id},
        UpdateExpression="SET #s = :status, updated_at = :now",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={":status": "cancelled", ":now": now},
    )

    # GAP-0309: terminal state — release the per-user active-payout slot.
    release_payout_sentinel(user_id, payout_id)

    item["status"] = "cancelled"
    item["updated_at"] = now
    return _payout_to_dict(item)


def list_user_payouts(user_id: str, *, limit: int = 25, cursor: Optional[str] = None) -> dict:
    """List user's payout history (ByUserCreatedAt GSI)."""
    query_kwargs: Dict[str, Any] = {
        "IndexName": "ByUserCreatedAt",
        "KeyConditionExpression": Key("user_id").eq(user_id),
        "ScanIndexForward": False,
        "Limit": limit,
    }

    start_key = decode_cursor(cursor)
    if start_key:
        query_kwargs["ExclusiveStartKey"] = start_key

    resp = T.creator_payouts.query(**query_kwargs)
    items = [_payout_to_dict(item) for item in resp.get("Items", []) if _is_real_payout(item)]
    last_key = resp.get("LastEvaluatedKey")
    next_cursor = encode_cursor(last_key) if last_key else None

    return {"items": items, "next_cursor": next_cursor}


def list_payouts_admin(*, status: Optional[str] = None, limit: int = 25, cursor: Optional[str] = None) -> dict:
    """Admin: list payouts, optionally filtered by status (ByStatusCreatedAt GSI)."""
    if status:
        query_kwargs: Dict[str, Any] = {
            "IndexName": "ByStatusCreatedAt",
            "KeyConditionExpression": Key("status").eq(status),
            "ScanIndexForward": False,
            "Limit": limit,
        }
        start_key = decode_cursor(cursor)
        if start_key:
            query_kwargs["ExclusiveStartKey"] = start_key

        resp = T.creator_payouts.query(**query_kwargs)
        items = [_payout_to_dict(item) for item in resp.get("Items", [])]
        last_key = resp.get("LastEvaluatedKey")
        next_cursor = encode_cursor(last_key) if last_key else None
    else:
        # Scan all payouts (no status filter), sorted by created_at desc
        scan_kwargs: Dict[str, Any] = {
            "Limit": limit,
        }
        start_key = decode_cursor(cursor)
        if start_key:
            scan_kwargs["ExclusiveStartKey"] = start_key

        resp = T.creator_payouts.scan(**scan_kwargs)
        items = [_payout_to_dict(item) for item in resp.get("Items", []) if _is_real_payout(item)]
        # Sort by created_at desc since scan doesn't guarantee order
        items.sort(key=lambda x: x["created_at"], reverse=True)
        last_key = resp.get("LastEvaluatedKey")
        next_cursor = encode_cursor(last_key) if last_key else None

    return {"items": items, "next_cursor": next_cursor}


def approve_payout(payout_id: str, admin_user_id: str) -> dict:
    """Admin approves payout. status: requested -> approved."""
    resp = T.creator_payouts.get_item(Key={"payout_id": payout_id})
    item = resp.get("Item")
    if not item:
        raise LookupError("Payout not found")

    status = item.get("status", "")
    if status != "requested":
        raise ValueError(f"Cannot approve payout in '{status}' state (must be 'requested')")

    now = now_ts()
    T.creator_payouts.update_item(
        Key={"payout_id": payout_id},
        UpdateExpression="SET #s = :status, updated_at = :now, approved_by = :admin",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={
            ":status": "approved",
            ":now": now,
            ":admin": admin_user_id,
        },
    )

    item["status"] = "approved"
    item["updated_at"] = now
    item["approved_by"] = admin_user_id
    return _payout_to_dict(item)


def reject_payout(payout_id: str, admin_user_id: str, reason: str = "") -> dict:
    """Admin rejects payout. status: requested -> rejected."""
    resp = T.creator_payouts.get_item(Key={"payout_id": payout_id})
    item = resp.get("Item")
    if not item:
        raise LookupError("Payout not found")

    status = item.get("status", "")
    if status != "requested":
        raise ValueError(f"Cannot reject payout in '{status}' state (must be 'requested')")

    now = now_ts()
    T.creator_payouts.update_item(
        Key={"payout_id": payout_id},
        UpdateExpression="SET #s = :status, updated_at = :now, reject_reason = :reason, approved_by = :admin",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={
            ":status": "rejected",
            ":now": now,
            ":reason": reason,
            ":admin": admin_user_id,
        },
    )

    # GAP-0309: terminal state — release the per-user active-payout slot.
    release_payout_sentinel(item.get("user_id", ""), payout_id)

    item["status"] = "rejected"
    item["updated_at"] = now
    item["reject_reason"] = reason
    return _payout_to_dict(item)


def complete_payout(payout_id: str) -> dict:
    """Mark payout as completed (after external transfer).
    In dev mode, auto-transitions approved -> processing -> completed.
    Otherwise: processing -> completed.
    """
    resp = T.creator_payouts.get_item(Key={"payout_id": payout_id})
    item = resp.get("Item")
    if not item:
        raise LookupError("Payout not found")

    status = item.get("status", "")
    now = now_ts()

    if S.dev_mode and status == "approved":
        # Dev mode: auto-transition through processing
        T.creator_payouts.update_item(
            Key={"payout_id": payout_id},
            UpdateExpression="SET #s = :status, updated_at = :now, completed_at = :now",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={":status": "completed", ":now": now},
        )
        # GAP-0309: terminal state — release the per-user active-payout slot.
        release_payout_sentinel(item.get("user_id", ""), payout_id)
        item["status"] = "completed"
        item["updated_at"] = now
        item["completed_at"] = now
        return _payout_to_dict(item)

    if status not in ("approved", "processing"):
        raise ValueError(f"Cannot complete payout in '{status}' state")

    T.creator_payouts.update_item(
        Key={"payout_id": payout_id},
        UpdateExpression="SET #s = :status, updated_at = :now, completed_at = :now",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={":status": "completed", ":now": now},
    )

    # GAP-0309: terminal state — release the per-user active-payout slot.
    release_payout_sentinel(item.get("user_id", ""), payout_id)

    item["status"] = "completed"
    item["updated_at"] = now
    item["completed_at"] = now
    return _payout_to_dict(item)


def get_payout_stats() -> dict:
    """Admin: queue stats. Count of requested, total pending amount, etc."""
    stats = {
        "total_requested": 0,
        "total_requested_amount_cents": 0,
        "total_approved": 0,
        "total_processing": 0,
    }

    # Query requested payouts
    query_kwargs: Dict[str, Any] = {
        "IndexName": "ByStatusCreatedAt",
        "KeyConditionExpression": Key("status").eq("requested"),
    }
    while True:
        resp = T.creator_payouts.query(**query_kwargs)
        for item in resp.get("Items", []):
            stats["total_requested"] += 1
            stats["total_requested_amount_cents"] += _to_int(item.get("amount_cents", 0))
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break
        query_kwargs["ExclusiveStartKey"] = last_key

    # Query approved payouts
    query_kwargs2: Dict[str, Any] = {
        "IndexName": "ByStatusCreatedAt",
        "KeyConditionExpression": Key("status").eq("approved"),
    }
    while True:
        resp = T.creator_payouts.query(**query_kwargs2)
        stats["total_approved"] += len(resp.get("Items", []))
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break
        query_kwargs2["ExclusiveStartKey"] = last_key

    # Query processing payouts
    query_kwargs3: Dict[str, Any] = {
        "IndexName": "ByStatusCreatedAt",
        "KeyConditionExpression": Key("status").eq("processing"),
    }
    while True:
        resp = T.creator_payouts.query(**query_kwargs3)
        stats["total_processing"] += len(resp.get("Items", []))
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break
        query_kwargs3["ExclusiveStartKey"] = last_key

    return stats


# ─── Payout Methods CRUD (GAP-0195 / FIN-009) ──────────────────────────────


def _method_id() -> str:
    return f"pmth_{uuid.uuid4().hex}"


def _method_to_dict(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "method_id": item.get("method_id", item.get("payout_id", "")),
        "method_type": item.get("method_type", ""),
        "account_last4": item.get("account_last4", ""),
        "routing_last4": item.get("routing_last4", ""),
        "paypal_email": item.get("paypal_email", ""),
        "nickname": item.get("nickname", ""),
        "is_default": bool(item.get("is_default", False)),
        "created_at": _to_int(item.get("created_at", 0)),
        "updated_at": _to_int(item.get("updated_at", 0)),
    }


def list_payout_methods(user_id: str) -> List[Dict[str, Any]]:
    """List all payout methods for a creator (via the ByUserCreatedAt GSI)."""
    methods: List[Dict[str, Any]] = []
    query_kwargs: Dict[str, Any] = {
        "IndexName": "ByUserCreatedAt",
        "KeyConditionExpression": Key("user_id").eq(user_id),
        "ScanIndexForward": False,
    }
    while True:
        resp = T.creator_payouts.query(**query_kwargs)
        for item in resp.get("Items", []):
            if _is_payout_method(item):
                methods.append(_method_to_dict(item))
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break
        query_kwargs["ExclusiveStartKey"] = last_key
    return methods


def add_payout_method(
    user_id: str,
    *,
    method_type: str,
    account_last4: str = "",
    routing_last4: str = "",
    paypal_email: str = "",
    nickname: str = "",
    set_as_default: bool = False,
) -> Dict[str, Any]:
    """Add a payout method. Only last-4 digits are persisted for bank accounts (SEC-004)."""
    if method_type not in PAYOUT_METHOD_TYPES:
        raise ValueError(f"invalid_method_type:Must be one of {sorted(PAYOUT_METHOD_TYPES)}")
    if method_type in ("bank_ach", "bank_wire") and (not account_last4 or not routing_last4):
        raise ValueError("bank_details_required:account_last4 and routing_last4 are required for bank methods")
    if method_type == "paypal" and not paypal_email:
        raise ValueError("paypal_email_required:paypal_email is required for PayPal methods")

    # First method becomes default automatically.
    existing = list_payout_methods(user_id)
    make_default = set_as_default or not existing

    ts = now_ts()
    mid = _method_id()
    item = {
        "payout_id": mid,
        "method_id": mid,
        "user_id": user_id,
        "record_kind": PAYOUT_METHOD_KIND,
        "method_type": method_type,
        "account_last4": account_last4,
        "routing_last4": routing_last4,
        "paypal_email": paypal_email,
        "nickname": nickname,
        "is_default": False,
        "created_at": ts,
        "updated_at": ts,
    }
    T.creator_payouts.put_item(Item=item)

    if make_default:
        set_default_payout_method(user_id, mid)
        item["is_default"] = True

    logger.info("payout_method_added user_id=%s method_type=%s", user_id, method_type)
    return _method_to_dict(item)


def _get_method_item(user_id: str, method_id: str) -> Optional[Dict[str, Any]]:
    item = T.creator_payouts.get_item(Key={"payout_id": method_id}).get("Item")
    if not item or not _is_payout_method(item) or item.get("user_id") != user_id:
        return None
    return item


def update_payout_method(user_id: str, method_id: str, *, nickname: str) -> Dict[str, Any]:
    """Update mutable fields (currently only nickname)."""
    if _get_method_item(user_id, method_id) is None:
        raise LookupError("payout_method_not_found:Payout method not found")
    ts = now_ts()
    resp = T.creator_payouts.update_item(
        Key={"payout_id": method_id},
        UpdateExpression="SET nickname = :n, updated_at = :ts",
        ExpressionAttributeValues={":n": nickname, ":ts": ts},
        ReturnValues="ALL_NEW",
    )
    return _method_to_dict(resp["Attributes"])


def set_default_payout_method(user_id: str, method_id: str) -> Dict[str, Any]:
    """Mark a method as default; clears the flag on the creator's other methods."""
    target = _get_method_item(user_id, method_id)
    if target is None:
        raise LookupError("payout_method_not_found:Payout method not found")
    ts = now_ts()
    for m in list_payout_methods(user_id):
        desired = m["method_id"] == method_id
        if m["is_default"] != desired:
            T.creator_payouts.update_item(
                Key={"payout_id": m["method_id"]},
                UpdateExpression="SET is_default = :d, updated_at = :ts",
                ExpressionAttributeValues={":d": desired, ":ts": ts},
            )
    target["is_default"] = True
    target["updated_at"] = ts
    logger.info("payout_method_default_set user_id=%s method_id=%s", user_id, method_id)
    return _method_to_dict(target)


def get_default_payout_method(user_id: str) -> Optional[Dict[str, Any]]:
    """Return the creator's default payout method dict, or None if none set."""
    for m in list_payout_methods(user_id):
        if m["is_default"]:
            return m
    return None


def delete_payout_method(user_id: str, method_id: str) -> None:
    """Delete a payout method. Refuses to delete the default while others remain."""
    existing = list_payout_methods(user_id)
    target = next((m for m in existing if m["method_id"] == method_id), None)
    if not target:
        raise LookupError("payout_method_not_found:Payout method not found")
    if target["is_default"] and len(existing) > 1:
        raise ValueError(
            "cannot_delete_default:Set another method as default before deleting this one"
        )
    T.creator_payouts.delete_item(Key={"payout_id": method_id})
    logger.info("payout_method_deleted user_id=%s method_id=%s", user_id, method_id)
