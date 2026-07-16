"""Creator Payout service (MON-004).

Manages payout requests, balance calculations, and admin approval workflow.
"""

from __future__ import annotations

import logging
import os
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
PAYOUT_STATES = {"requested", "approved", "processing", "completed", "rejected", "cancelled", "failed", "returned"}
ACTIVE_PAYOUT_STATES = {"requested", "approved", "processing"}

# GAP-0195 (FIN-009): payout destination methods.
# The CreatorPayouts table is keyed by a single HASH attribute (``payout_id``),
# so payout-method records are co-located in the same table keyed by their
# ``method_id`` (stored in ``payout_id``) and tagged with ``record_kind`` to
# distinguish them from real payout records. They carry ``user_id`` so the
# existing ``ByUserCreatedAt`` GSI can list a creator's methods.
PAYOUT_METHOD_TYPES = {"bank_ach", "bank_wire", "paypal", "check", "stripe_connect"}
PAYOUT_METHOD_KIND = "payout_method"

# PAY-10 (PAY-B): a routable method's verification lifecycle. A payout can only
# target a method in the "verified" state (enforced in request_payout).
PAYOUT_METHOD_STATUSES = {"unverified", "verifying", "verified", "failed"}

# PAY-11 (PAY-B): record_kind + key for the per-creator Stripe Connect account
# row, co-located in the single-key CreatorPayouts table under
# payout_id=CONNECT#{user_id}. Stores the connect_account_id the transfer targets.
CONNECT_ACCOUNT_KIND = "connect_account"

# GAP-0309 (MON-004): record_kind for the per-user active-payout sentinel row,
# co-located in the same single-key CreatorPayouts table.
PAYOUT_STATE_KIND = "payout_state"

# PAY-01 (PAY-A): record_kind for the per-payout idempotency marker that gates
# the honest type="debit" ledger write (exactly one debit per payout). Co-located
# in the same single-key CreatorPayouts table under payout_id=PAYOUTDEBIT#{id}.
PAYOUT_DEBIT_KIND = "payout_debit_marker"

# Billing-ledger reason tag for the money-OUT debit that permanently reduces the
# withdrawable balance (PAY-A). A reversal flips that debit to state="reversed"
# (funds return) on a failed/returned payout.
PAYOUT_DEBIT_REASON = "payout"


def _is_payout_method(item: Dict[str, Any]) -> bool:
    return item.get("record_kind") == PAYOUT_METHOD_KIND


def _is_real_payout(item: Dict[str, Any]) -> bool:
    """True only for actual payout records (not co-located method / state rows).

    The CreatorPayouts table is single-table: it also holds ``payout_method``
    rows and the per-user ``payout_state`` sentinel (GAP-0309). Listing/scanning
    code must exclude both.
    """
    return item.get("record_kind") not in (
        PAYOUT_METHOD_KIND,
        PAYOUT_STATE_KIND,
        PAYOUT_DEBIT_KIND,
    )


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
        "transfer_provider": item.get("transfer_provider", ""),
        "transfer_ref": item.get("transfer_ref", ""),
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

    # PAY-01 (the P0 double-spend fix): money already paid out to the creator now
    # lives as ``type="debit", reason="payout"`` rows in this SAME ledger, so a
    # completed payout PERMANENTLY reduces the withdrawable balance (the earnings
    # can never be re-withdrawn). CONTINUITY: while a payout is still active it has
    # no debit row yet and is subtracted via the ``_get_active_payout_total``
    # reservation below; the debit row is written at completion (BEFORE the status
    # flips out of the active set), so the amount is always subtracted by exactly
    # one of {reservation, debit} — there is no window where the balance reverts.
    paid_out_cents = _sum_payout_debits(user_id)

    # Subtract in-flight (requested/approved/processing) payouts not yet debited.
    pending_cents = _get_active_payout_total(user_id)
    available_cents = max(0, available_cents - paid_out_cents - pending_cents)

    return {
        "available_cents": available_cents,
        "pending_cents": pending_cents,
        "paid_out_cents": paid_out_cents,
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


def _sum_payout_debits(user_id: str) -> int:
    """Sum SETTLED creator-payout debit rows (money already paid out).

    PAY-01: only ``type="debit", reason="payout"`` rows that are NOT reversed are
    summed. Other debits in the user's ledger (e.g. tip charges funded by a card)
    are deliberately ignored so withdrawable earnings are never reduced by money
    the creator *spent* — only by money paid OUT to them via a payout.
    """
    pk = f"USER#{user_id}"
    total = 0
    query_kwargs: Dict[str, Any] = {
        "KeyConditionExpression": Key("pk").eq(pk) & Key("sk").begins_with("LEDGER#"),
        "FilterExpression": (
            Attr("type").eq("debit")
            & Attr("reason").eq(PAYOUT_DEBIT_REASON)
            & Attr("state").ne("reversed")
        ),
    }
    while True:
        resp = T.billing.query(**query_kwargs)
        for item in resp.get("Items", []):
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


class PayoutGateError(Exception):
    """PAY-20/21: payout blocked by the verified-before-any-payout gate.

    Carries a machine-readable code (kyc_required | tax_info_required)
    plus the caller's current kyc_status so the app can route the creator to
    the right step (KYC wizard or the W-9 form).
    """

    def __init__(self, code, message, *, kyc_status=""):
        super().__init__(message)
        self.code = code
        self.message = message
        self.kyc_status = kyc_status


def resolve_kyc_status(user_id):
    """Resolve overall KYC status from the EXISTING kyc_cases system (no rebuild).

    Returns "approved" when any owned KYC case is approved, else the most
    informative in-progress status, else "none".
    """
    try:
        from app.services.kyc_cases import STORE as KYC_STORE

        cases = KYC_STORE.list_cases_by_owner(user_sub=user_id, limit=25)
    except Exception:
        logger.warning("payout_gate_kyc_lookup_failed user_id=%s", user_id, exc_info=True)
        cases = []
    if not cases:
        return "none"
    statuses = {str(c.get("status") or "").strip() for c in cases}
    if "approved" in statuses:
        return "approved"
    for candidate in ("under_review", "disputed", "submitted", "needs_more_info", "rejected", "expired", "draft"):
        if candidate in statuses:
            return candidate
    return "none"


def has_tax_info_on_file(user_id):
    """True when a certified W-9 (TIN tokenized + masked to last-4) is on file."""
    try:
        from app.services import tax_info_w9

        tax = tax_info_w9.get_tax_info(user_id)
    except Exception:
        logger.warning("payout_gate_tax_lookup_failed user_id=%s", user_id, exc_info=True)
        return False
    return bool(tax and tax.get("tin_last4") and tax.get("certified"))


def _enforce_payout_gate(user_id):
    """PAY-20/21: block a withdrawal until KYC is APPROVED and a W-9 is on file."""
    if not S.payout_verification_gate_enabled:
        return
    kyc_status = resolve_kyc_status(user_id)
    if kyc_status != "approved":
        raise PayoutGateError(
            "kyc_required",
            "Verify your identity (KYC) before you can withdraw.",
            kyc_status=kyc_status,
        )
    if not has_tax_info_on_file(user_id):
        raise PayoutGateError(
            "tax_info_required",
            "A certified W-9 tax form must be on file before you can withdraw.",
            kyc_status=kyc_status,
        )


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

    # PAY-20/21 (PAY-C): verified-before-any-payout gate. Reuses the existing
    # KYC (kyc_cases) + W-9 (tax_info_w9) systems; blocks until BOTH satisfied.
    _enforce_payout_gate(user_id)

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

        # Resolve the payout destination (GAP-0195 / FIN-009 + PAY-10..12).
        resolved_method = method
        resolved_method_id = ""
        resolved_connect_id = ""
        resolved_ext_ref = ""
        resolved_paypal = ""
        mrec: Optional[Dict[str, Any]] = None
        if method_id:
            mitem = T.creator_payouts.get_item(Key={"payout_id": method_id}).get("Item")
            if (
                not mitem
                or not _is_payout_method(mitem)
                or mitem.get("user_id") != user_id
            ):
                raise ValueError("invalid_method_id:Payout method not found or not yours")
            mrec = _method_to_dict(mitem)
        else:
            mrec = get_default_payout_method(user_id)

        if mrec is not None:
            # PAY-12: a payout can only target a VERIFIED method.
            if mrec.get("method_status", "unverified") != "verified":
                raise ValueError(
                    "method_not_verified:Payout method must be verified before a payout"
                )
            resolved_method = mrec.get("method_type", method)
            resolved_method_id = mrec.get("method_id", "") or method_id or ""
            resolved_connect_id = mrec.get("connect_account_id", "")
            resolved_ext_ref = mrec.get("external_account_ref", "")
            resolved_paypal = mrec.get("paypal_email", "")

        now = now_ts()
        item = {
            "payout_id": payout_id,
            "user_id": user_id,
            "amount_cents": amount_cents,
            "method": resolved_method,
            "method_id": resolved_method_id,
            "connect_account_id": resolved_connect_id,
            "external_account_ref": resolved_ext_ref,
            "paypal_email": resolved_paypal,
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


# ─── Honest payout debit + reversal + transfer seam (PAY-A / PAY-01..03) ────
#
# On reaching a terminal PAID state a payout writes a REAL ``type="debit"`` row
# to the billing ledger (so the withdrawable balance actually drops — closing the
# P0 double-spend) and is "processed" through an honest transfer seam. Under the
# mock rail NO external money moves, but the debit is real and the record is
# honest about it (``transfer_provider="mock"``). When Stripe Connect / PayPal
# creds are configured the same seam performs a real off-platform transfer.


def _payout_debit_marker_id(payout_id: str) -> str:
    return f"PAYOUTDEBIT#{payout_id}"


def _write_payout_debit(payout: Dict[str, Any]) -> Optional[str]:
    """Idempotently write exactly ONE ``type="debit"`` ledger row for a paid payout.

    Guarded by a conditional ``PAYOUTDEBIT#{payout_id}`` marker row in the payouts
    table: the first caller to create the marker writes the debit; any retried
    completion finds the marker and skips (never double-debits). Returns the debit
    ledger ``sk`` (fresh or pre-existing), or ``None`` when there is nothing to
    debit (amount <= 0 / malformed record).
    """
    payout_id = str(payout.get("payout_id", ""))
    user_id = str(payout.get("user_id", ""))
    amount = _to_int(payout.get("amount_cents", 0))
    if not payout_id or not user_id or amount <= 0:
        return None

    marker_id = _payout_debit_marker_id(payout_id)
    try:
        T.creator_payouts.put_item(
            Item={
                "payout_id": marker_id,
                "record_kind": PAYOUT_DEBIT_KIND,
                "user_id": user_id,
                "ref_payout_id": payout_id,
                "amount_cents": amount,
                "created_at": now_ts(),
            },
            ConditionExpression="attribute_not_exists(payout_id)",
        )
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            # Already debited — idempotent no-op; return the recorded debit sk.
            existing = T.creator_payouts.get_item(Key={"payout_id": marker_id}).get("Item") or {}
            return existing.get("debit_sk")
        raise

    # We won the marker: write the REAL debit to the billing ledger. ``debit`` maps
    # to sign -1 in billing_shared.LEDGER_ENTRY_SIGN, so it reduces the balance.
    from app.services.billing_shared import new_ledger_entry

    sk, entry = new_ledger_entry(
        key_name="pk",
        key_value=f"USER#{user_id}",
        entry_type="debit",
        amount_cents=amount,
        state="settled",
        reason=PAYOUT_DEBIT_REASON,
        meta={"payout_id": payout_id, "kind": "creator_payout"},
    )
    T.billing.put_item(Item=entry)

    # Record the debit sk on the marker so a later reversal can locate it.
    try:
        T.creator_payouts.update_item(
            Key={"payout_id": marker_id},
            UpdateExpression="SET debit_sk = :sk",
            ExpressionAttributeValues={":sk": sk},
        )
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning("payout_debit_marker_update_failed payout_id=%s: %s", payout_id, exc)

    logger.info(
        "payout_debit_written payout_id=%s user_id=%s amount_cents=%d sk=%s",
        payout_id, user_id, amount, sk,
    )
    return sk


def reverse_payout_debit(payout_id: str) -> bool:
    """Reverse a paid payout's debit so the funds return to withdrawable balance.

    PAY-02: idempotently flips the payout-debit ledger row ``state`` settled ->
    reversed via a conditional update (so ``_sum_payout_debits`` stops subtracting
    it and the balance goes back up). Returns True if it reversed now, False if
    there was no settled debit to reverse (never debited, or already reversed).
    """
    marker = T.creator_payouts.get_item(
        Key={"payout_id": _payout_debit_marker_id(payout_id)}
    ).get("Item")
    if not marker:
        return False  # never debited (e.g. failed before it ever completed)
    debit_sk = marker.get("debit_sk")
    user_id = str(marker.get("user_id", ""))
    if not debit_sk or not user_id:
        return False
    try:
        T.billing.update_item(
            Key={"pk": f"USER#{user_id}", "sk": debit_sk},
            UpdateExpression="SET #s = :rev",
            ConditionExpression="#s = :settled",
            ExpressionAttributeNames={"#s": "state"},
            ExpressionAttributeValues={":rev": "reversed", ":settled": "settled"},
        )
        logger.info(
            "payout_debit_reversed payout_id=%s user_id=%s sk=%s",
            payout_id, user_id, debit_sk,
        )
        return True
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            return False  # already reversed / not settled — idempotent no-op
        raise


def payout_transfer(payout: Dict[str, Any]) -> Dict[str, Any]:
    """Honest outbound-transfer seam (PAY-03).

    Real rail (only when explicitly keyed): ``STRIPE_CONNECT_ENABLED=1`` +
    ``stripe_secret_key`` performs a Stripe Connect Transfer; ``PAYOUT_USE_REAL_PROVIDER=1``
    + PayPal creds performs a PayPal Payout. Otherwise (today, on prod) records a
    MOCK transfer — no external money moves — but the caller still writes the REAL
    ``type="debit"`` ledger row, so the platform balance honestly drops either way.

    NOTE: the gate is a DEDICATED flag, not the mere presence of ``stripe_secret_key``
    (which is already set for the money-IN stripe-mock rail), so enabling money-OUT
    real transfers is an explicit, separate opt-in.

    Returns ``{transfer_provider, transfer_ref, real}``.
    """
    payout_id = str(payout.get("payout_id", ""))
    amount = _to_int(payout.get("amount_cents", 0))

    stripe_connect_on = os.environ.get("STRIPE_CONNECT_ENABLED", "0") not in ("0", "false", "False")
    paypal_real_on = os.environ.get("PAYOUT_USE_REAL_PROVIDER", "0") not in ("0", "false", "False")

    # Real Stripe Connect rail (seam — active only when explicitly enabled + keyed).
    if stripe_connect_on and getattr(S, "stripe_secret_key", ""):
        try:
            import stripe  # noqa: WPS433

            stripe.api_key = S.stripe_secret_key
            destination = (
                payout.get("connect_account_id")
                or payout.get("method_id")
                or payout.get("method")
            )
            transfer = stripe.Transfer.create(
                amount=amount,
                currency="usd",
                destination=destination,
                metadata={"payout_id": payout_id},
                idempotency_key=f"payout_{payout_id}",
            )
            ref = transfer.get("id") if isinstance(transfer, dict) else getattr(transfer, "id", "")
            return {"transfer_provider": "stripe_connect", "transfer_ref": ref or "", "real": True}
        except Exception as exc:
            logger.error("stripe_connect_transfer_failed payout_id=%s: %s", payout_id, exc)
            raise

    # Real PayPal Payouts rail (seam — active only when explicitly enabled + keyed).
    if paypal_real_on and getattr(S, "paypal_client_id", "") and getattr(S, "paypal_client_secret", ""):
        try:
            from app.services.paypal_payouts import create_payout as _paypal_create_payout  # type: ignore

            ref = _paypal_create_payout(payout)
            return {"transfer_provider": "paypal", "transfer_ref": str(ref or ""), "real": True}
        except Exception as exc:
            logger.error("paypal_payout_failed payout_id=%s: %s", payout_id, exc)
            raise

    # No real rail configured — honest mock. The type="debit" the caller writes is
    # real; only the external money movement is simulated.
    return {"transfer_provider": "mock", "transfer_ref": f"mock_transfer_{payout_id}", "real": False}


def _finalize_paid(item: Dict[str, Any], now: int) -> dict:
    """Shared terminal-PAID finalization: honest transfer + REAL debit + status.

    Ordering is deliberate: the debit is written BEFORE the status flips out of the
    active set so ``get_available_balance`` never has a window where neither the
    reservation nor the debit subtracts the amount (continuity / no revert).
    """
    payout_id = str(item.get("payout_id", ""))
    user_id = str(item.get("user_id", ""))

    # PAY-03: process via the honest transfer seam (mock now; real when keyed).
    transfer = payout_transfer(item)

    # PAY-01/02: write the REAL idempotent debit (exactly one per payout).
    debit_sk = _write_payout_debit(item)

    T.creator_payouts.update_item(
        Key={"payout_id": payout_id},
        UpdateExpression=(
            "SET #s = :status, updated_at = :now, completed_at = :now, "
            "transfer_provider = :tp, transfer_ref = :tr, debit_sk = :dsk"
        ),
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={
            ":status": "completed",
            ":now": now,
            ":tp": transfer["transfer_provider"],
            ":tr": transfer["transfer_ref"],
            ":dsk": debit_sk or "",
        },
    )

    # GAP-0309: terminal state — release the per-user active-payout slot. Safe now
    # that the debit permanently subtracts the amount (no reservation needed).
    release_payout_sentinel(user_id, payout_id)

    item["status"] = "completed"
    item["updated_at"] = now
    item["completed_at"] = now
    item["transfer_provider"] = transfer["transfer_provider"]
    item["transfer_ref"] = transfer["transfer_ref"]
    # PAY-34: default-on transactional "your withdrawal was paid" alert.
    try:
        _emit_payout_alert(
            "payout_paid",
            recipient=user_id,
            title="Your withdrawal was paid",
            action_url=f"/wallet/payouts/{payout_id}",
            details={"payout_id": payout_id, "amount_cents": _to_int(item.get("amount_cents", 0)), "transfer_provider": transfer["transfer_provider"]},
        )
    except Exception:
        pass
    return _payout_to_dict(item)


def complete_payout(payout_id: str) -> dict:
    """Mark a payout PAID: process the transfer + write the real balance debit.

    ``approved``/``processing`` -> ``completed``. Writes an idempotent
    ``type="debit"`` ledger row (PAY-01) so the withdrawable balance permanently
    drops, and processes the money via the honest transfer seam (PAY-03).
    Idempotent: completing an already-completed payout re-returns it without a
    second debit.
    """
    resp = T.creator_payouts.get_item(Key={"payout_id": payout_id})
    item = resp.get("Item")
    if not item:
        raise LookupError("Payout not found")

    status = item.get("status", "")
    now = now_ts()

    # Idempotent: an already-completed payout must NOT double-debit / double-pay.
    if status == "completed":
        return _payout_to_dict(item)

    if status not in ("approved", "processing"):
        raise ValueError(f"Cannot complete payout in '{status}' state")

    return _finalize_paid(item, now)


def fail_payout(payout_id: str, *, reason: str = "", returned: bool = False) -> dict:
    """Mark a payout failed/returned and REVERSE its debit if it was already paid.

    PAY-02:
    - A payout still active (requested/approved/processing) that was never debited
      just moves to the terminal failed/returned state and releases the reservation
      (nothing to reverse; the reservation already stops subtracting).
    - A payout that had COMPLETED (and thus wrote a debit) has that debit reversed
      so the funds return to the withdrawable balance. Idempotent.
    """
    resp = T.creator_payouts.get_item(Key={"payout_id": payout_id})
    item = resp.get("Item")
    if not item or not _is_real_payout(item):
        raise LookupError("Payout not found")

    new_status = "returned" if returned else "failed"
    now = now_ts()
    user_id = str(item.get("user_id", ""))

    # Reverse the debit if this payout had been paid (idempotent no-op otherwise).
    reversed_now = reverse_payout_debit(payout_id)

    T.creator_payouts.update_item(
        Key={"payout_id": payout_id},
        UpdateExpression="SET #s = :st, updated_at = :now, fail_reason = :r, debit_reversed = :dr",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={
            ":st": new_status,
            ":now": now,
            ":r": reason,
            ":dr": bool(reversed_now or item.get("debit_reversed", False)),
        },
    )

    # Terminal state — release the per-user active-payout slot.
    release_payout_sentinel(user_id, payout_id)

    item["status"] = new_status
    item["updated_at"] = now
    # PAY-34: default-on transactional failure/return alert.
    try:
        _emit_payout_alert(
            "payout_returned" if returned else "payout_failed",
            recipient=user_id,
            title=("Your withdrawal was returned" if returned else "Your withdrawal failed"),
            action_url=f"/wallet/payouts/{payout_id}",
            details={"payout_id": payout_id, "amount_cents": _to_int(item.get("amount_cents", 0)), "returned": bool(returned), "reason": reason},
        )
    except Exception:
        pass
    return _payout_to_dict(item)


# --- PAY-50 (PAY-F): app-facing money-OUT read surface ---------------------
# Wallet summary + per-payout statement/detail for the Android wallet. All are
# strictly user-scoped (own records only) and reconcile to the PAY-A ledger:
#   available/held/pending == get_available_balance; lifetime_paid == settled
#   (non-reversed) payout debits. NO new state; pure read over existing rows.

def _held_release_info(user_id: str):
    """(earliest_release_ts, held_count) over credits still inside the 7-day hold."""
    pk = f"USER#{user_id}"
    now = now_ts()
    hold_period = S.payout_hold_period_seconds
    key_cond = Key("pk").eq(pk) & Key("sk").begins_with("LEDGER#")
    filter_expr = (
        Attr("type").eq("credit")
        & Attr("state").ne("reversed")
        & Attr("amount_cents").gt(0)
    )
    next_release = None
    held_count = 0
    kwargs = {"KeyConditionExpression": key_cond, "FilterExpression": filter_expr}
    while True:
        resp = T.billing.query(**kwargs)
        for item in resp.get("Items", []):
            ts = _to_int(item.get("ts", 0))
            rel = ts + hold_period
            if rel > now:
                held_count += 1
                if next_release is None or rel < next_release:
                    next_release = rel
        lk = resp.get("LastEvaluatedKey")
        if not lk:
            break
        kwargs["ExclusiveStartKey"] = lk
    return next_release, held_count


def _count_active_payouts(user_id: str) -> int:
    """Count of the user's in-flight (requested/approved/processing) payouts."""
    count = 0
    kwargs = {
        "IndexName": "ByUserCreatedAt",
        "KeyConditionExpression": Key("user_id").eq(user_id),
        "ScanIndexForward": False,
    }
    while True:
        resp = T.creator_payouts.query(**kwargs)
        for item in resp.get("Items", []):
            if not _is_real_payout(item):
                continue
            if item.get("status", "") in ACTIVE_PAYOUT_STATES:
                count += 1
        lk = resp.get("LastEvaluatedKey")
        if not lk:
            break
        kwargs["ExclusiveStartKey"] = lk
    return count


def get_wallet_summary(user_id: str) -> dict:
    """PAY-50 wallet home: available / held(+release) / pending / lifetime-paid.

    Reconciles to the PAY-A ledger -- available/pending/held/paid_out all come
    from get_available_balance (single source of truth for the money-OUT math),
    plus the earliest hold-release timestamp and in-flight payout count."""
    bal = get_available_balance(user_id)
    next_release, held_count = _held_release_info(user_id)
    return {
        "available_cents": bal["available_cents"],
        "held_cents": bal["hold_cents"],
        "held_count": held_count,
        "held_release_at": next_release,
        "pending_cents": bal["pending_cents"],
        "pending_count": _count_active_payouts(user_id),
        "lifetime_paid_cents": bal["paid_out_cents"],
        "total_earned_cents": bal["total_earned_cents"],
        "currency": "USD",
    }


def _resolve_method_last4(item) -> str:
    """Best-effort last-4 for the destination a payout targeted (bank acct or
    a masked PayPal handle). Looks up the co-located payout_method row."""
    method_id = item.get("method_id", "")
    if method_id:
        mitem = T.creator_payouts.get_item(Key={"payout_id": method_id}).get("Item")
        if mitem and _is_payout_method(mitem):
            l4 = mitem.get("account_last4", "")
            if l4:
                return l4
            email = mitem.get("paypal_email", "")
            if email:
                return email
    return item.get("paypal_email", "") or ""


def _build_payout_timeline(item):
    """Honest lifecycle timeline from the record's real timestamps (best-effort;
    states without a dedicated timestamp carry ts=0 but still order correctly)."""
    events = []
    events.append({"status": "requested", "ts": _to_int(item.get("created_at", 0)), "note": ""})
    if item.get("approved_by"):
        events.append({"status": "approved", "ts": 0, "note": f"by {item.get('approved_by')}"})
    if item.get("held_at"):
        events.append({"status": "held", "ts": _to_int(item.get("held_at", 0)), "note": item.get("hold_reason", "")})
    if item.get("hold_released_at"):
        events.append({"status": "hold_released", "ts": _to_int(item.get("hold_released_at", 0)), "note": ""})
    status = item.get("status", "")
    attempts = _to_int(item.get("transfer_attempts", 0))
    completed_at = _to_int(item.get("completed_at", 0))
    if status in ("processing", "completed", "failed", "returned") or attempts:
        events.append({"status": "processing", "ts": 0, "note": (f"{attempts} transfer attempt(s)" if attempts else "")})
    if completed_at:
        events.append({"status": "paid", "ts": completed_at, "note": item.get("transfer_provider", "")})
    if status in ("failed", "returned"):
        events.append({"status": status, "ts": _to_int(item.get("updated_at", 0)), "note": item.get("fail_reason", "")})
    if status in ("cancelled", "rejected"):
        events.append({"status": status, "ts": _to_int(item.get("updated_at", 0)), "note": item.get("reject_reason", "")})
    return events


def get_payout_detail(user_id: str, payout_id: str) -> dict:
    """PAY-50 statement/detail for ONE payout (user-scoped; 403 if not owner)."""
    item = T.creator_payouts.get_item(Key={"payout_id": payout_id}).get("Item")
    if not item or not _is_real_payout(item):
        raise LookupError("Payout not found")
    if item.get("user_id") != user_id:
        raise PermissionError("Not your payout")
    d = _payout_to_dict(item)
    d["method_id"] = item.get("method_id", "")
    d["method_last4"] = _resolve_method_last4(item)
    d["fail_reason"] = item.get("fail_reason", "")
    d["manual_hold"] = bool(item.get("manual_hold", False))
    d["hold_reason"] = item.get("hold_reason", "")
    d["debit_reversed"] = bool(item.get("debit_reversed", False))
    d["transfer_provider"] = item.get("transfer_provider", "")
    d["transfer_ref"] = item.get("transfer_ref", "")
    d["transfer_attempts"] = _to_int(item.get("transfer_attempts", 0))
    d["timeline"] = _build_payout_timeline(item)
    return d


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
        "method_status": item.get("method_status", "unverified"),
        "connect_account_id": item.get("connect_account_id", ""),
        "external_account_ref": item.get("external_account_ref", ""),
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


def _tokenize_bank_ref(account_number: str, routing_number: str) -> Dict[str, str]:
    """SEC-004: exchange a raw bank account/routing for a NON-reversible routable
    reference. The raw number is NEVER stored — only an opaque token + last-4 for
    display. Real rail (when keyed) would swap the number for a processor token
    (Stripe bank-account token / Plaid processor token); the mock derives a salted
    hash so the destination is routable-shaped but no real account is linked.
    Returns {bank_token, account_last4, routing_last4}.
    """
    import hashlib

    acct = "".join(ch for ch in (account_number or "") if ch.isdigit())
    rout = "".join(ch for ch in (routing_number or "") if ch.isdigit())
    token = ""
    if acct:
        digest = hashlib.sha256(f"{rout}:{acct}:tl_bank_tok".encode()).hexdigest()[:24]
        token = f"btok_mock_{digest}"
    return {
        "bank_token": token,
        "account_last4": acct[-4:] if acct else "",
        "routing_last4": rout[-4:] if rout else "",
    }


def _connect_pk(user_id: str) -> str:
    return f"CONNECT#{user_id}"


def _connect_enabled() -> bool:
    """True only when Stripe Connect is explicitly keyed (dedicated flag + secret).
    Otherwise the Connect / verification rails run in honest mock mode.
    """
    on = os.environ.get("STRIPE_CONNECT_ENABLED", "0") not in ("0", "false", "False")
    return on and bool(getattr(S, "stripe_secret_key", ""))


def get_connect_account(user_id: str) -> Optional[Dict[str, Any]]:
    """Return the creator's stored Stripe Connect account record, or None."""
    item = T.creator_payouts.get_item(Key={"payout_id": _connect_pk(user_id)}).get("Item")
    if not item or item.get("record_kind") != CONNECT_ACCOUNT_KIND:
        return None
    return item


def create_connect_account(user_id: str) -> Dict[str, Any]:
    """PAY-11: create (or return) a Stripe Connect account id for a creator.

    Real rail (only when ``STRIPE_CONNECT_ENABLED`` keyed + secret): performs
    ``stripe.Account.create(type="express")``. Mock: a routable-shaped
    ``acct_mock_<hash>`` id with ``payouts_enabled=False`` until onboarding.
    Idempotent — returns the existing account when present. Honest: under the mock
    no real Connect account exists; only a routable reference is recorded.
    """
    existing = get_connect_account(user_id)
    if existing:
        return existing
    ts = now_ts()
    real = False
    if _connect_enabled():
        try:
            import stripe  # noqa: WPS433

            stripe.api_key = S.stripe_secret_key
            acct = stripe.Account.create(type="express", metadata={"user_id": user_id})
            acct_id = acct.get("id") if isinstance(acct, dict) else getattr(acct, "id", "")
            real = True
        except Exception as exc:
            logger.error("connect_account_create_failed user_id=%s: %s", user_id, exc)
            raise
    else:
        import hashlib

        acct_id = f"acct_mock_{hashlib.sha256((user_id + ':connect').encode()).hexdigest()[:16]}"
    item = {
        "payout_id": _connect_pk(user_id),
        "user_id": user_id,
        "record_kind": CONNECT_ACCOUNT_KIND,
        "connect_account_id": acct_id,
        "onboarding_status": "pending",
        "payouts_enabled": False,
        "provider": "stripe_connect" if real else "mock",
        "created_at": ts,
        "updated_at": ts,
    }
    try:
        T.creator_payouts.put_item(
            Item=item, ConditionExpression="attribute_not_exists(payout_id)"
        )
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            return get_connect_account(user_id) or item
        raise
    logger.info("connect_account_created user_id=%s real=%s", user_id, real)
    return item


def create_connect_onboarding_link(
    user_id: str, *, return_url: str = "", refresh_url: str = ""
) -> Dict[str, Any]:
    """PAY-11: a Connect onboarding-link seam.

    Real (keyed): ``stripe.AccountLink.create(type="account_onboarding")`` — the
    creator completes real onboarding, ``payouts_enabled`` follows the capability.
    Mock: NO real account link — marks the account onboarding-complete +
    payouts_enabled so a ``stripe_connect`` method can be verified (honest
    simulation, no real account linked). Returns {connect_account_id,
    onboarding_url, onboarding_status, payouts_enabled, real}.
    """
    acct = create_connect_account(user_id)
    acct_id = acct["connect_account_id"]
    ts = now_ts()
    if _connect_enabled():
        try:
            import stripe  # noqa: WPS433

            stripe.api_key = S.stripe_secret_key
            link = stripe.AccountLink.create(
                account=acct_id,
                type="account_onboarding",
                return_url=return_url or "https://testlogon.example/connect/return",
                refresh_url=refresh_url or "https://testlogon.example/connect/refresh",
            )
            url = link.get("url") if isinstance(link, dict) else getattr(link, "url", "")
            T.creator_payouts.update_item(
                Key={"payout_id": _connect_pk(user_id)},
                UpdateExpression="SET onboarding_status = :s, updated_at = :t",
                ExpressionAttributeValues={":s": "in_progress", ":t": ts},
            )
            return {
                "connect_account_id": acct_id,
                "onboarding_url": url or "",
                "onboarding_status": "in_progress",
                "payouts_enabled": False,
                "real": True,
            }
        except Exception as exc:
            logger.error("connect_onboarding_link_failed user_id=%s: %s", user_id, exc)
            raise
    # Mock onboarding-complete (no real account link).
    T.creator_payouts.update_item(
        Key={"payout_id": _connect_pk(user_id)},
        UpdateExpression="SET onboarding_status = :s, payouts_enabled = :p, updated_at = :t",
        ExpressionAttributeValues={":s": "complete", ":p": True, ":t": ts},
    )
    return {
        "connect_account_id": acct_id,
        "onboarding_url": f"https://mock.testlogon/connect/onboarding/{acct_id}",
        "onboarding_status": "complete",
        "payouts_enabled": True,
        "real": False,
    }


def verify_payout_method(user_id: str, method_id: str) -> Dict[str, Any]:
    """PAY-12: verify a routable payout method (verification seam).

    Real (keyed): a bank micro-deposit / instant-verify would move the method to
    ``verifying`` until confirmed; a ``stripe_connect`` method is ``verified`` once
    the Connect account's ``payouts_enabled`` capability is live. Mock: mark
    ``verified`` immediately (honest — nothing real is verified). A payout can only
    target a ``verified`` method (enforced in request_payout).
    """
    item = _get_method_item(user_id, method_id)
    if item is None:
        raise LookupError("payout_method_not_found:Payout method not found")
    ts = now_ts()
    mtype = item.get("method_type", "")
    status = "verified"
    if _connect_enabled():
        if mtype == "stripe_connect":
            acct = get_connect_account(user_id)
            status = "verified" if (acct and acct.get("payouts_enabled")) else "verifying"
        else:
            status = "verifying"  # real micro-deposit pending confirmation
    resp = T.creator_payouts.update_item(
        Key={"payout_id": method_id},
        UpdateExpression="SET #ms = :s, updated_at = :t",
        ExpressionAttributeNames={"#ms": "method_status"},
        ExpressionAttributeValues={":s": status, ":t": ts},
        ReturnValues="ALL_NEW",
    )
    logger.info(
        "payout_method_verify user_id=%s method_id=%s status=%s", user_id, method_id, status
    )
    return _method_to_dict(resp["Attributes"])


def add_payout_method(
    user_id: str,
    *,
    method_type: str,
    account_last4: str = "",
    routing_last4: str = "",
    account_number: str = "",
    routing_number: str = "",
    paypal_email: str = "",
    connect_account_id: str = "",
    nickname: str = "",
    set_as_default: bool = False,
) -> Dict[str, Any]:
    """Add a routable payout method (PAY-10).

    Stores a ROUTABLE DESTINATION REFERENCE the transfer can target — never a raw
    account number (SEC-004): bank -> a tokenized bank ref + last-4 for display;
    paypal -> the payout email; stripe_connect -> the creator's connect_account_id.
    Methods start ``unverified``; a payout can only target a ``verified`` method.
    """
    if method_type not in PAYOUT_METHOD_TYPES:
        raise ValueError(f"invalid_method_type:Must be one of {sorted(PAYOUT_METHOD_TYPES)}")

    ts = now_ts()
    mid = _method_id()
    bank_token = ""
    external_account_ref = ""
    conn_id = ""

    if method_type in ("bank_ach", "bank_wire"):
        # SEC-004: tokenize the full number server-side; store token + last-4 only.
        if account_number or routing_number:
            tok = _tokenize_bank_ref(account_number, routing_number)
            bank_token = tok["bank_token"]
            account_last4 = tok["account_last4"] or account_last4
            routing_last4 = tok["routing_last4"] or routing_last4
        if not account_last4 or not routing_last4:
            raise ValueError(
                "bank_details_required:account/routing (or their last-4) are required for bank methods"
            )
        if not bank_token:
            import hashlib

            bank_token = f"btok_mock_{hashlib.sha256((user_id + ':' + mid).encode()).hexdigest()[:24]}"
        external_account_ref = bank_token
    elif method_type == "paypal":
        if not paypal_email:
            raise ValueError("paypal_email_required:paypal_email is required for PayPal methods")
        external_account_ref = f"paypal:{paypal_email}"
    elif method_type == "stripe_connect":
        acct = get_connect_account(user_id) or create_connect_account(user_id)
        conn_id = connect_account_id or acct.get("connect_account_id", "")
        external_account_ref = conn_id

    # First method becomes default automatically.
    existing = list_payout_methods(user_id)
    make_default = set_as_default or not existing

    item = {
        "payout_id": mid,
        "method_id": mid,
        "user_id": user_id,
        "record_kind": PAYOUT_METHOD_KIND,
        "method_type": method_type,
        "account_last4": account_last4,
        "routing_last4": routing_last4,
        "paypal_email": paypal_email,
        "bank_token": bank_token,
        "connect_account_id": conn_id,
        "external_account_ref": external_account_ref,
        "method_status": "unverified",
        "nickname": nickname,
        "is_default": False,
        "created_at": ts,
        "updated_at": ts,
    }
    T.creator_payouts.put_item(Item=item)

    if make_default:
        set_default_payout_method(user_id, mid)
        item["is_default"] = True

    logger.info(
        "payout_method_added user_id=%s method_type=%s status=unverified", user_id, method_type
    )
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


# ===========================================================================
# PAY-D (PAY-30..34): scheduled payout RUNNER + lifecycle + manual holds +
# bounded retries + load-bearing notifications.
#
# The runner auto-progresses eligible payouts requested/approved -> processing
# -> paid via the PAY-A honest ``payout_transfer`` seam (mock now, real when
# keyed), writing the idempotent ``type="debit"`` on paid (balance drops). A
# transient transfer failure is retried on a bounded backoff schedule; once the
# attempts are exhausted (or a HARD failure) the payout goes ``failed`` and its
# debit is REVERSED (funds return -- never inflated). A manual admin HOLD pauses
# a payout so the runner SKIPS it until released. Idempotent PER PAYOUT: a
# payout is transferred+debited exactly once (the PAY-A debit marker guarantees
# it); a re-run of the runner never double-transfers or double-debits.
# ===========================================================================


class PayoutTransferError(Exception):
    """A transfer attempt failed. ``transient`` => retry on backoff; otherwise a
    HARD failure => fail immediately (+ reverse any debit)."""

    def __init__(self, message: str, *, transient: bool = True):
        super().__init__(message)
        self.transient = transient


def _emit_payout_alert(alert_type: str, *, recipient: str, title: str, details: Dict[str, Any], action_url: str = "/wallet/payouts") -> None:
    """PAY-34: emit a load-bearing payout alert as a default-ON transactional push.

    Reuses the shared ``emit_social_alert`` rail (the same mechanism SUB-E5 uses);
    ``payout_*`` events are registered in ``alerts.DEFAULT_PUSH_EVENT_TYPES`` so a
    creator receives them without opting in. A dedicated non-self ``system`` actor
    is used so the alert is not self-suppressed (the recipient == the creator)."""
    if not recipient:
        return
    try:
        from app.services.social_alerts import emit_social_alert

        emit_social_alert(
            recipient_user_id=recipient,
            alert_type=alert_type,
            actor_user_id="system",
            actor_display_name="Payouts",
            title=title,
            details=details,
            action_url=action_url,
        )
    except Exception:
        logger.warning("payout_alert_emit_failed type=%s recipient=%s", alert_type, recipient, exc_info=True)


# --- Manual admin hold (PAY-32) --------------------------------------------
#
# A ``manual_hold=True`` flag on the payout record pauses the runner from
# processing it (place/release are admin-only). Distinct from the 7-day BALANCE
# hold (unchanged -- that gates which credits are withdrawable at request time).

_HOLD_TERMINAL_STATES = {"completed", "failed", "returned", "rejected", "cancelled"}


def place_payout_hold(payout_id: str, admin_user_id: str, reason: str = "") -> dict:
    """Admin: place a manual hold so the runner SKIPS this payout until released."""
    item = T.creator_payouts.get_item(Key={"payout_id": payout_id}).get("Item")
    if not item or not _is_real_payout(item):
        raise LookupError("Payout not found")
    status = item.get("status", "")
    if status in _HOLD_TERMINAL_STATES:
        raise ValueError(f"Cannot hold payout in '{status}' state")
    now = now_ts()
    T.creator_payouts.update_item(
        Key={"payout_id": payout_id},
        UpdateExpression=(
            "SET manual_hold = :t, hold_reason = :r, held_by = :a, held_at = :now, updated_at = :now"
        ),
        ExpressionAttributeValues={":t": True, ":r": reason, ":a": admin_user_id, ":now": now},
    )
    logger.info("payout_hold_placed payout_id=%s by=%s reason=%s", payout_id, admin_user_id, reason)
    item["status"] = status
    return _payout_to_dict(item)


def release_payout_hold(payout_id: str, admin_user_id: str) -> dict:
    """Admin: release a manual hold so the runner may process the payout again."""
    item = T.creator_payouts.get_item(Key={"payout_id": payout_id}).get("Item")
    if not item or not _is_real_payout(item):
        raise LookupError("Payout not found")
    now = now_ts()
    T.creator_payouts.update_item(
        Key={"payout_id": payout_id},
        UpdateExpression=(
            "SET manual_hold = :f, hold_released_by = :a, hold_released_at = :now, updated_at = :now"
        ),
        ExpressionAttributeValues={":f": False, ":a": admin_user_id, ":now": now},
    )
    logger.info("payout_hold_released payout_id=%s by=%s", payout_id, admin_user_id)
    return _payout_to_dict(item)


# --- Runner: retry schedule + eligibility + single-payout processing --------


def _retry_backoff_schedule() -> List[int]:
    raw = getattr(S, "payout_retry_backoff_seconds", "60,300,900")
    out: List[int] = []
    for part in str(raw).split(","):
        part = part.strip()
        if part.isdigit():
            out.append(int(part))
    return out or [60, 300, 900]


def _simulate_forced_transfer_failure(item: Dict[str, Any]) -> None:
    """Honest TEST seam: a payout record may carry ``force_transfer_result`` to
    drive the retry/hard-fail paths in verification. REAL payouts never carry it,
    so production transfers are unaffected. ``transient_fail`` => retryable,
    ``hard_fail`` => immediate hard failure."""
    forced = str(item.get("force_transfer_result", "") or "")
    if forced == "transient_fail":
        raise PayoutTransferError("forced transient transfer failure", transient=True)
    if forced in ("hard_fail", "fail"):
        raise PayoutTransferError("forced hard transfer failure", transient=False)


def _payout_runner_eligible(item: Dict[str, Any], now: int) -> bool:
    """A payout is eligible for the runner iff it is a real payout, NOT on a manual
    hold, and either (a) requested/approved past the optional min-age settling
    window, or (b) processing whose retry backoff has elapsed."""
    if not _is_real_payout(item):
        return False
    if item.get("manual_hold"):
        return False
    status = item.get("status", "")
    if status in ("requested", "approved"):
        min_age = int(getattr(S, "payout_runner_min_age_seconds", 0) or 0)
        if min_age and _to_int(item.get("created_at", 0)) + min_age > now:
            return False
        return True
    if status == "processing":
        return _to_int(item.get("next_attempt_at", 0)) <= now
    return False


def process_one_payout(payout_id: str, now: Optional[int] = None) -> Dict[str, Any]:
    """Process a single payout exactly once through the honest transfer seam.

    requested/approved -> (atomic claim) processing -> ``payout_transfer`` ->
    paid (writes the idempotent PAY-A debit via ``_finalize_paid``) on success;
    transient failure -> schedule a bounded retry (status stays processing with a
    future ``next_attempt_at``); exhausted/HARD failure -> failed + reverse the
    debit (a no-op when never paid, so funds are never inflated). Idempotent: the
    atomic status claim + the PAY-A debit marker guarantee no double-transfer /
    double-debit even if two sweeps race the same payout."""
    now = now or now_ts()
    item = T.creator_payouts.get_item(Key={"payout_id": payout_id}).get("Item")
    if not item or not _payout_runner_eligible(item, now):
        return {"payout_id": payout_id, "action": "skipped"}

    prev_status = item.get("status", "")
    user_id = str(item.get("user_id", ""))
    amount = _to_int(item.get("amount_cents", 0))

    # Atomic claim: move to processing only from an eligible, un-held state. If a
    # concurrent sweep already claimed it the conditional fails and we skip.
    try:
        T.creator_payouts.update_item(
            Key={"payout_id": payout_id},
            UpdateExpression="SET #s = :proc, updated_at = :now",
            ConditionExpression=(
                "#s IN (:req, :appr, :proc) AND (attribute_not_exists(manual_hold) OR manual_hold = :f)"
            ),
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={
                ":proc": "processing", ":req": "requested", ":appr": "approved",
                ":now": now, ":f": False,
            },
        )
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            return {"payout_id": payout_id, "action": "skipped"}
        raise
    item["status"] = "processing"

    # Emit payout_initiated once, on the first entry into processing.
    if prev_status in ("requested", "approved"):
        _emit_payout_alert(
            "payout_initiated",
            recipient=user_id,
            title="Your withdrawal is processing",
            action_url=f"/wallet/payouts/{payout_id}",
            details={"payout_id": payout_id, "amount_cents": amount, "status": "processing"},
        )

    attempts = _to_int(item.get("transfer_attempts", 0)) + 1

    try:
        _simulate_forced_transfer_failure(item)
        # Success: honest transfer + idempotent debit + status completed (+ paid alert).
        _finalize_paid(item, now_ts())
        T.creator_payouts.update_item(
            Key={"payout_id": payout_id},
            UpdateExpression="SET transfer_attempts = :a REMOVE next_attempt_at, last_transfer_error",
            ExpressionAttributeValues={":a": attempts},
        )
        logger.info("payout_runner_paid payout_id=%s attempts=%d", payout_id, attempts)
        return {"payout_id": payout_id, "action": "paid", "attempts": attempts, "status": "completed"}
    except Exception as exc:  # transfer failed
        transient = getattr(exc, "transient", True)
        max_attempts = int(getattr(S, "payout_max_transfer_attempts", 4) or 4)
        backoff = _retry_backoff_schedule()
        if transient and attempts < max_attempts:
            delay = backoff[min(attempts - 1, len(backoff) - 1)]
            next_at = now + delay
            T.creator_payouts.update_item(
                Key={"payout_id": payout_id},
                UpdateExpression=(
                    "SET transfer_attempts = :a, next_attempt_at = :na, "
                    "last_transfer_error = :e, updated_at = :now"
                ),
                ExpressionAttributeValues={":a": attempts, ":na": next_at, ":e": str(exc)[:400], ":now": now},
            )
            logger.info(
                "payout_runner_retry payout_id=%s attempts=%d next_attempt_at=%d err=%s",
                payout_id, attempts, next_at, exc,
            )
            return {
                "payout_id": payout_id, "action": "retry_scheduled",
                "attempts": attempts, "next_attempt_at": next_at, "transient": True,
            }
        # Exhausted transient budget OR a hard failure -> terminal fail + reverse.
        if transient:
            reason = "transfer failed after %d attempts: %s" % (attempts, exc)
        else:
            reason = "hard transfer failure: %s" % exc
        fail_payout(payout_id, reason=reason, returned=False)
        T.creator_payouts.update_item(
            Key={"payout_id": payout_id},
            UpdateExpression="SET transfer_attempts = :a, last_transfer_error = :e",
            ExpressionAttributeValues={":a": attempts, ":e": str(exc)[:400]},
        )
        logger.info(
            "payout_runner_failed payout_id=%s attempts=%d transient=%s err=%s",
            payout_id, attempts, transient, exc,
        )
        return {
            "payout_id": payout_id, "action": "failed",
            "attempts": attempts, "transient": bool(transient), "status": "failed",
        }


def run_payout_sweep(now: Optional[int] = None, limit: int = 1000, payout_id: Optional[str] = None) -> Dict[str, Any]:
    """Scheduled runner (PAY-30): drain eligible payouts to paid (or retry/fail).

    Scans requested + approved + processing payouts via the ByStatusCreatedAt GSI
    and processes each once. ``now`` (unix ts override) lets a verifier fast-forward
    past a retry backoff; ``payout_id`` restricts to a single payout. Returns an
    action summary. Manual-held payouts are counted and SKIPPED."""
    now = now or now_ts()
    summary: Dict[str, Any] = {
        "scanned": 0, "paid": [], "retried": [], "failed": [], "skipped": 0, "held": 0, "now": now,
    }

    def _route(res: Dict[str, Any]) -> None:
        action = res.get("action")
        if action == "paid":
            summary["paid"].append(res)
        elif action == "retry_scheduled":
            summary["retried"].append(res)
        elif action == "failed":
            summary["failed"].append(res)
        else:
            summary["skipped"] += 1

    if payout_id:
        summary["scanned"] = 1
        _route(process_one_payout(payout_id, now))
        return summary

    for status in ("requested", "approved", "processing"):
        query_kwargs: Dict[str, Any] = {
            "IndexName": "ByStatusCreatedAt",
            "KeyConditionExpression": Key("status").eq(status),
            "ScanIndexForward": True,
        }
        while summary["scanned"] < limit:
            resp = T.creator_payouts.query(**query_kwargs)
            for it in resp.get("Items", []):
                if not _is_real_payout(it):
                    continue
                if summary["scanned"] >= limit:
                    break
                summary["scanned"] += 1
                if it.get("manual_hold"):
                    summary["held"] += 1
                    continue
                try:
                    _route(process_one_payout(str(it.get("payout_id", "")), now))
                except Exception:
                    logger.exception("payout_runner: failed payout=%s", it.get("payout_id"))
            last_key = resp.get("LastEvaluatedKey")
            if not last_key:
                break
            query_kwargs["ExclusiveStartKey"] = last_key

    logger.info(
        "payout_sweep done scanned=%d paid=%d retried=%d failed=%d held=%d",
        summary["scanned"], len(summary["paid"]), len(summary["retried"]),
        len(summary["failed"]), summary["held"],
    )
    return summary


# --- periodic task (mirrors subscription_renewal.start_subscription_renewal_task) --


async def _payout_runner_loop() -> None:
    import asyncio
    import time as _time

    from app.services.job_registry import register_task, report_error, report_poll

    interval = max(30, int(getattr(S, "payout_runner_interval_seconds", 300) or 300))
    register_task("payout_runner", interval, enabled=True, description="Scheduled payout processing runner (PAY-D)")
    logger.info("payout runner started (interval=%ds)", interval)
    while True:
        _start = _time.perf_counter()
        try:
            run_payout_sweep()
            report_poll("payout_runner", duration_ms=(_time.perf_counter() - _start) * 1000)
        except Exception as exc:
            try:
                report_error("payout_runner", str(exc))
            except Exception:
                pass
            logger.exception("payout runner loop failed")
        await asyncio.sleep(interval)


def start_payout_runner_task() -> None:
    """Register the scheduled payout runner on FastAPI startup (PAY-30)."""
    import asyncio

    if not getattr(S, "payout_runner_enabled", True):
        try:
            from app.services.job_registry import register_task

            register_task("payout_runner", 300, enabled=False, description="Scheduled payout processing runner (PAY-D)")
        except Exception:
            pass
        logger.info("payout runner disabled")
        return
    try:
        asyncio.get_event_loop().create_task(_payout_runner_loop())
    except RuntimeError:
        asyncio.ensure_future(_payout_runner_loop())


# --- Provider return webhook seam (PAY-31) ---------------------------------


def handle_payout_provider_webhook(event: str, payout_id: str, *, reason: str = "") -> dict:
    """Map a provider payout webhook to the lifecycle. A ``returned`` event
    reverses the debit (funds back); a ``failed`` event fails the payout. Seam:
    real signature verification is enforced at the router when a secret is set."""
    ev = (event or "").lower()
    if not payout_id:
        raise LookupError("Payout not found")
    if "return" in ev:
        return fail_payout(payout_id, reason=reason or "provider return", returned=True)
    if "fail" in ev:
        return fail_payout(payout_id, reason=reason or "provider failure", returned=False)
    raise ValueError(f"unsupported_webhook_event:{event}")
