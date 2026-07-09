"""Syndicate treasury and fund management (SYND-004).

Provides a shared treasury wallet for syndicates:
- Members deposit funds from their personal wallet into the syndicate treasury.
- Syndicate admins disburse/withdraw treasury funds to member wallets.
- Every fund movement is recorded as a paired ledger entry (treasury side in the
  dedicated ``syndicate_treasury`` table, member side in the shared billing table).
- Per-member contribution tracking + transaction history.

Mirrors the pattern in ``app/services/group_treasury.py``. Treasury balance,
transaction ledger, and per-member contribution trackers all live in the
dedicated ``syndicate_treasury`` DDB table (single-table design with
``pk = TREASURY#{syndicate_id}``). Member-facing wallet credits/debits use the
shared billing table via ``apply_wallet_delta`` + ledger entries.
"""

from __future__ import annotations

import base64
import json
import logging
import secrets
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError
from fastapi import HTTPException

from app.core.tables import T
from app.core.time import now_ts
from app.services import syndicates as syndicate_svc
from app.services.billing_shared import apply_wallet_delta, ledger_sk, ulidish, user_pk

logger = logging.getLogger(__name__)

BALANCE_SK = "BALANCE"

# Deposit bounds (cents): $1 - $10,000
MIN_DEPOSIT_CENTS = 100
MAX_DEPOSIT_CENTS = 1_000_000


def _treasury_pk(syndicate_id: str) -> str:
    return f"TREASURY#{syndicate_id}"


def _gen_id() -> str:
    return f"{int(now_ts() * 1000)}_{secrets.token_hex(8)}"


# ---------------------------------------------------------------------------
# Balance
# ---------------------------------------------------------------------------


def get_treasury_balance(syndicate_id: str) -> Dict[str, Any]:
    """Return the current treasury balance and lifetime totals."""
    pk = _treasury_pk(syndicate_id)
    resp = T.syndicate_treasury.get_item(Key={"pk": pk, "sk": BALANCE_SK})
    row = resp.get("Item")
    if not row:
        return {
            "syndicate_id": syndicate_id,
            "balance_cents": 0,
            "total_deposited_cents": 0,
            "total_disbursed_cents": 0,
            "currency": "usd",
            "updated_at": 0,
        }
    return {
        "syndicate_id": syndicate_id,
        "balance_cents": int(row.get("balance_cents", 0)),
        "total_deposited_cents": int(row.get("total_deposited_cents", 0)),
        "total_disbursed_cents": int(row.get("total_disbursed_cents", 0)),
        "currency": row.get("currency", "usd"),
        "updated_at": int(row.get("updated_at", 0)),
    }


def _write_treasury_ledger(
    syndicate_id: str,
    *,
    direction: str,
    amount_cents: int,
    reason: str,
    actor_user_id: str,
    counterparty_user_id: str = "",
    ts: Optional[int] = None,
) -> str:
    """Write a treasury-side ledger entry. Returns the entry id."""
    ts = ts or now_ts()
    entry_id = _gen_id()
    item = {
        "pk": _treasury_pk(syndicate_id),
        "sk": ledger_sk(ts, entry_id),
        "entry_id": entry_id,
        "ts": ts,
        "direction": direction,  # "credit" or "debit"
        "amount_cents": int(amount_cents),
        "reason": reason,
        "actor_user_id": actor_user_id,
        "counterparty_user_id": counterparty_user_id,
        "currency": "usd",
        "created_at": ts,
    }
    T.syndicate_treasury.put_item(Item=item)
    return entry_id


# ---------------------------------------------------------------------------
# Deposit (member → treasury)
# ---------------------------------------------------------------------------


def deposit(
    *,
    syndicate_id: str,
    user_id: str,
    amount_cents: int,
) -> Dict[str, Any]:
    """Member deposits funds from their personal wallet into the treasury."""
    if amount_cents < MIN_DEPOSIT_CENTS or amount_cents > MAX_DEPOSIT_CENTS:
        raise HTTPException(
            status_code=400,
            detail=f"Deposit must be between {MIN_DEPOSIT_CENTS} and {MAX_DEPOSIT_CENTS} cents",
        )

    # Must be a member of an active syndicate.
    syndicate = syndicate_svc._get_meta(syndicate_id)
    if syndicate.get("status") != "active":
        raise HTTPException(status_code=400, detail="Syndicate is not active")
    syndicate_svc._require_is_member(syndicate_id, user_id)

    pk_user = user_pk(user_id)
    pk_treasury = _treasury_pk(syndicate_id)
    ts = now_ts()

    # 1. Debit personal wallet (conditional overdraft check).
    try:
        new_personal_balance = apply_wallet_delta(T.billing, pk_user, -amount_cents)
    except ClientError as e:
        if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
            raise HTTPException(status_code=400, detail="Insufficient wallet balance")
        raise

    # 2. Credit treasury balance (atomic ADD, auto-create).
    T.syndicate_treasury.update_item(
        Key={"pk": pk_treasury, "sk": BALANCE_SK},
        UpdateExpression=(
            "SET balance_cents = if_not_exists(balance_cents, :z) + :amt, "
            "total_deposited_cents = if_not_exists(total_deposited_cents, :z) + :amt, "
            "total_disbursed_cents = if_not_exists(total_disbursed_cents, :z), "
            "currency = :c, updated_at = :t, syndicate_id = :sid"
        ),
        ExpressionAttributeValues={
            ":z": 0,
            ":amt": amount_cents,
            ":c": "usd",
            ":t": ts,
            ":sid": syndicate_id,
        },
    )

    # 3. Update contribution tracker.
    T.syndicate_treasury.update_item(
        Key={"pk": pk_treasury, "sk": f"CONTRIB#{user_id}"},
        UpdateExpression=(
            "SET user_id = :uid, "
            "total_contributed_cents = if_not_exists(total_contributed_cents, :z) + :amt, "
            "total_refunded_cents = if_not_exists(total_refunded_cents, :z), "
            "contribution_count = if_not_exists(contribution_count, :z) + :one, "
            "first_contributed_at = if_not_exists(first_contributed_at, :t), "
            "last_contribution_at = :t"
        ),
        ExpressionAttributeValues={
            ":uid": user_id,
            ":z": 0,
            ":amt": amount_cents,
            ":one": 1,
            ":t": ts,
        },
    )

    # 4. Treasury ledger entry (credit).
    treasury_entry_id = _write_treasury_ledger(
        syndicate_id,
        direction="credit",
        amount_cents=amount_cents,
        reason=f"Treasury deposit from {user_id}",
        actor_user_id=user_id,
        counterparty_user_id=user_id,
        ts=ts,
    )

    # 5. Member-side billing ledger entry (debit).
    user_entry_id = ulidish()
    T.billing.put_item(Item={
        "pk": pk_user,
        "sk": ledger_sk(ts, user_entry_id),
        "entry_id": user_entry_id,
        "ts": ts,
        "type": "syndicate_treasury_deposit",
        "amount_cents": amount_cents,
        "state": "settled",
        "reason": "Syndicate treasury deposit",
        "direction": "debit",
        "category": "syndicate_treasury",
        "syndicate_id": syndicate_id,
        "syndicate_name": syndicate.get("name", ""),
        "currency": "usd",
        "created_at": ts,
    })

    syndicate_svc._write_audit(
        syndicate_id, user_id, "treasury_deposit", "",
        {"amount_cents": amount_cents},
    )

    balance = get_treasury_balance(syndicate_id)
    logger.info(
        "syndicate_treasury.deposit",
        extra={"syndicate_id": syndicate_id, "user_id": user_id, "amount_cents": amount_cents},
    )

    return {
        "ok": True,
        "amount_cents": amount_cents,
        "new_personal_balance_cents": new_personal_balance,
        "new_treasury_balance_cents": balance["balance_cents"],
        "treasury_entry_id": treasury_entry_id,
        "user_entry_id": user_entry_id,
    }


# ---------------------------------------------------------------------------
# Disbursement / withdrawal (treasury → member, admin only)
# ---------------------------------------------------------------------------


def disburse(
    *,
    syndicate_id: str,
    admin_sub: str,
    recipient_user_id: str,
    amount_cents: int,
    note: str = "",
) -> Dict[str, Any]:
    """Admin disburses/withdraws treasury funds to a member's personal wallet."""
    # Admin-only.
    syndicate_svc._require_admin(syndicate_id, admin_sub)

    # SECURITY: No-withdrawal constraint (SYND-004 / GAP-0032).
    # The admin must not be able to disburse treasury funds to themselves.
    if admin_sub == recipient_user_id:
        raise HTTPException(
            status_code=400,
            detail="Admin cannot disburse treasury funds to themselves",
        )

    if amount_cents <= 0:
        raise HTTPException(status_code=400, detail="Disbursement amount must be positive")

    # Recipient must be a member of the syndicate.
    syndicate = syndicate_svc._get_meta(syndicate_id)
    syndicate_svc._require_is_member(syndicate_id, recipient_user_id)

    pk_treasury = _treasury_pk(syndicate_id)
    pk_recipient = user_pk(recipient_user_id)
    ts = now_ts()

    # 1. Debit treasury (conditional: balance >= amount → reject overdraw).
    try:
        T.syndicate_treasury.update_item(
            Key={"pk": pk_treasury, "sk": BALANCE_SK},
            UpdateExpression=(
                "SET balance_cents = balance_cents - :amt, "
                "total_disbursed_cents = if_not_exists(total_disbursed_cents, :z) + :amt, "
                "updated_at = :t"
            ),
            ConditionExpression="attribute_exists(balance_cents) AND balance_cents >= :amt",
            ExpressionAttributeValues={":amt": amount_cents, ":z": 0, ":t": ts},
        )
    except ClientError as e:
        if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
            raise HTTPException(status_code=409, detail="Insufficient treasury balance")
        raise

    # 2. Credit recipient's personal wallet.
    new_recipient_balance = apply_wallet_delta(T.billing, pk_recipient, amount_cents)

    reason = note.strip() or f"Treasury disbursement to {recipient_user_id}"

    # 3. Treasury ledger entry (debit).
    treasury_entry_id = _write_treasury_ledger(
        syndicate_id,
        direction="debit",
        amount_cents=amount_cents,
        reason=reason,
        actor_user_id=admin_sub,
        counterparty_user_id=recipient_user_id,
        ts=ts,
    )

    # 4. Member-side billing ledger entry (credit).
    user_entry_id = ulidish()
    T.billing.put_item(Item={
        "pk": pk_recipient,
        "sk": ledger_sk(ts, user_entry_id),
        "entry_id": user_entry_id,
        "ts": ts,
        "type": "syndicate_treasury_disbursement",
        "amount_cents": amount_cents,
        "state": "settled",
        "reason": "Syndicate treasury disbursement",
        "direction": "credit",
        "category": "syndicate_treasury",
        "syndicate_id": syndicate_id,
        "syndicate_name": syndicate.get("name", ""),
        "currency": "usd",
        "created_at": ts,
    })

    syndicate_svc._write_audit(
        syndicate_id, admin_sub, "treasury_disbursement", recipient_user_id,
        {"amount_cents": amount_cents},
    )

    balance = get_treasury_balance(syndicate_id)
    logger.info(
        "syndicate_treasury.disburse",
        extra={
            "syndicate_id": syndicate_id,
            "admin_sub": admin_sub,
            "recipient_user_id": recipient_user_id,
            "amount_cents": amount_cents,
        },
    )

    return {
        "ok": True,
        "amount_cents": amount_cents,
        "recipient_user_id": recipient_user_id,
        "new_treasury_balance_cents": balance["balance_cents"],
        "new_recipient_balance_cents": new_recipient_balance,
        "treasury_entry_id": treasury_entry_id,
        "user_entry_id": user_entry_id,
    }


# ---------------------------------------------------------------------------
# Advertising spend (treasury → ad campaign) — used by SYND-006
# ---------------------------------------------------------------------------


def spend_on_advertising(
    *,
    syndicate_id: str,
    admin_sub: str,
    amount_cents: int,
    campaign_id: str,
    campaign_name: str = "",
) -> Dict[str, Any]:
    """Debit the treasury to fund an advertising campaign budget.

    Reuses the conditional-debit pattern from ``disburse`` so an overspend is
    rejected atomically. Does NOT credit any member wallet — the funds leave the
    treasury to fund the campaign. Returns the treasury ledger entry id.
    """
    if amount_cents <= 0:
        raise HTTPException(status_code=400, detail="Spend amount must be positive")

    pk_treasury = _treasury_pk(syndicate_id)
    ts = now_ts()

    # Conditional debit: balance must exist and be >= amount → else reject.
    try:
        T.syndicate_treasury.update_item(
            Key={"pk": pk_treasury, "sk": BALANCE_SK},
            UpdateExpression=(
                "SET balance_cents = balance_cents - :amt, "
                "total_disbursed_cents = if_not_exists(total_disbursed_cents, :z) + :amt, "
                "updated_at = :t"
            ),
            ConditionExpression="attribute_exists(balance_cents) AND balance_cents >= :amt",
            ExpressionAttributeValues={":amt": amount_cents, ":z": 0, ":t": ts},
        )
    except ClientError as e:
        if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
            raise HTTPException(status_code=409, detail="Insufficient treasury balance")
        raise

    reason = f"Ad campaign budget: {campaign_name or campaign_id}"
    entry_id = _write_treasury_ledger(
        syndicate_id,
        direction="debit",
        amount_cents=amount_cents,
        reason=reason,
        actor_user_id=admin_sub,
        counterparty_user_id="",
        ts=ts,
    )

    balance = get_treasury_balance(syndicate_id)
    return {
        "ok": True,
        "amount_cents": amount_cents,
        "campaign_id": campaign_id,
        "ledger_entry_id": entry_id,
        "new_treasury_balance_cents": balance["balance_cents"],
    }


def credit_placement_earning(
    *,
    syndicate_id: str,
    amount_cents: int,
    member_user_id: str = "",
    account_id: str = "",
    campaign_id: str = "",
) -> Dict[str, Any]:
    """ADV2-705 (F7): credit the syndicate treasury its share of a syndicate-owned
    ad placement served in front of a member's content. Mirrors the credit half of
    refund_advertising (balance ADD + one treasury ledger row, type/direction
    'credit'). The MEMBER is credited separately by the ad-billing split; this only
    moves the treasury's cut. No-op for a non-positive amount."""
    if amount_cents <= 0:
        return {"ok": True, "amount_cents": 0, "ledger_entry_id": ""}
    pk_treasury = _treasury_pk(syndicate_id)
    ts = now_ts()
    T.syndicate_treasury.update_item(
        Key={"pk": pk_treasury, "sk": BALANCE_SK},
        UpdateExpression=(
            "SET balance_cents = if_not_exists(balance_cents, :z) + :amt, "
            "total_ad_earnings_cents = if_not_exists(total_ad_earnings_cents, :z) + :amt, "
            "updated_at = :t, syndicate_id = :sid"
        ),
        ExpressionAttributeValues={
            ":z": 0, ":amt": int(amount_cents), ":t": ts, ":sid": syndicate_id,
        },
    )
    entry_id = _gen_id()
    T.syndicate_treasury.put_item(Item={
        "pk": pk_treasury,
        "sk": ledger_sk(ts, entry_id),
        "entry_id": entry_id,
        "ts": ts,
        "direction": "credit",
        "type": "credit",
        "amount_cents": int(amount_cents),
        "reason": "Syndicate ad placement earnings",
        "actor_user_id": "",
        "counterparty_user_id": member_user_id,
        "account_id": account_id,
        "campaign_id": campaign_id,
        "source_type": "ad_placement",
        "currency": "usd",
        "created_at": ts,
    })
    balance = get_treasury_balance(syndicate_id)
    return {
        "ok": True,
        "amount_cents": int(amount_cents),
        "ledger_entry_id": entry_id,
        "new_treasury_balance_cents": balance["balance_cents"],
    }


def debit_placement_earning(
    *,
    syndicate_id: str,
    amount_cents: int,
    member_user_id: str = "",
    account_id: str = "",
    campaign_id: str = "",
    reversal_of: str = "",
) -> Dict[str, Any]:
    """ADV2-RES R1: reverse a syndicate ad-placement treasury credit. When the
    underlying syndicate-owned ad charge is reversed, debit the treasury the share
    it was credited by credit_placement_earning (balance SUBTRACT + one 'debit'
    treasury ledger row). Sign-flipped mirror of credit_placement_earning. No-op
    for a non-positive amount."""
    if amount_cents <= 0:
        return {"ok": True, "amount_cents": 0, "ledger_entry_id": ""}
    pk_treasury = _treasury_pk(syndicate_id)
    ts = now_ts()
    T.syndicate_treasury.update_item(
        Key={"pk": pk_treasury, "sk": BALANCE_SK},
        UpdateExpression=(
            "SET balance_cents = if_not_exists(balance_cents, :z) - :amt, "
            "total_ad_earnings_cents = if_not_exists(total_ad_earnings_cents, :z) - :amt, "
            "updated_at = :t, syndicate_id = :sid"
        ),
        ExpressionAttributeValues={
            ":z": 0, ":amt": int(amount_cents), ":t": ts, ":sid": syndicate_id,
        },
    )
    entry_id = _gen_id()
    T.syndicate_treasury.put_item(Item={
        "pk": pk_treasury,
        "sk": ledger_sk(ts, entry_id),
        "entry_id": entry_id,
        "ts": ts,
        "direction": "debit",
        "type": "debit",
        "amount_cents": int(amount_cents),
        "reason": "Syndicate ad placement reversal",
        "actor_user_id": "",
        "counterparty_user_id": member_user_id,
        "account_id": account_id,
        "campaign_id": campaign_id,
        "source_type": "ad_placement_reversal",
        "reversal_of": reversal_of,
        "currency": "usd",
        "created_at": ts,
    })
    balance = get_treasury_balance(syndicate_id)
    return {
        "ok": True,
        "amount_cents": int(amount_cents),
        "ledger_entry_id": entry_id,
        "new_treasury_balance_cents": balance["balance_cents"],
    }


def refund_advertising(
    *,
    syndicate_id: str,
    admin_sub: str,
    amount_cents: int,
    campaign_id: str,
) -> Dict[str, Any]:
    """Credit unspent advertising budget back to the treasury (not to a member)."""
    if amount_cents <= 0:
        return {"ok": True, "amount_cents": 0, "campaign_id": campaign_id}

    pk_treasury = _treasury_pk(syndicate_id)
    ts = now_ts()

    T.syndicate_treasury.update_item(
        Key={"pk": pk_treasury, "sk": BALANCE_SK},
        UpdateExpression=(
            "SET balance_cents = if_not_exists(balance_cents, :z) + :amt, "
            "total_disbursed_cents = if_not_exists(total_disbursed_cents, :z) - :amt, "
            "updated_at = :t, syndicate_id = :sid"
        ),
        ExpressionAttributeValues={
            ":z": 0,
            ":amt": amount_cents,
            ":t": ts,
            ":sid": syndicate_id,
        },
    )

    entry_id = _write_treasury_ledger(
        syndicate_id,
        direction="credit",
        amount_cents=amount_cents,
        reason=f"Cancelled campaign budget refund: {campaign_id}",
        actor_user_id=admin_sub,
        counterparty_user_id="",
        ts=ts,
    )

    balance = get_treasury_balance(syndicate_id)
    return {
        "ok": True,
        "amount_cents": amount_cents,
        "campaign_id": campaign_id,
        "ledger_entry_id": entry_id,
        "new_treasury_balance_cents": balance["balance_cents"],
    }


# ---------------------------------------------------------------------------
# Refunds (treasury → member) — member departure / syndicate dissolution
#
# SYND-004 §3.3: when a member leaves they receive their proportional share of
# the *current* treasury balance, computed from their net (unspent) contribution
# vs the total net contributions. When the syndicate dissolves (last member
# leaves), all remaining funds are returned proportionally to every contributor
# and the treasury is zeroed.
# ---------------------------------------------------------------------------


def _bump_contrib_refund(syndicate_id: str, user_id: str, refund_cents: int, ts: int) -> None:
    """Atomically increment a member's contribution-tracker refund total."""
    T.syndicate_treasury.update_item(
        Key={"pk": _treasury_pk(syndicate_id), "sk": f"CONTRIB#{user_id}"},
        UpdateExpression=(
            "SET user_id = if_not_exists(user_id, :uid), "
            "total_refunded_cents = if_not_exists(total_refunded_cents, :z) + :amt, "
            "last_refunded_at = :t"
        ),
        ExpressionAttributeValues={
            ":uid": user_id,
            ":z": 0,
            ":amt": int(refund_cents),
            ":t": ts,
        },
    )


def _debit_treasury_for_refund(syndicate_id: str, amount_cents: int, ts: int) -> None:
    """Atomically debit the treasury balance for a refund (conditional, no overdraw).

    Mirrors the conditional-debit pattern in ``disburse``. Also bumps a lifetime
    ``total_refunded_cents`` counter on the BALANCE row.
    """
    pk_treasury = _treasury_pk(syndicate_id)
    try:
        T.syndicate_treasury.update_item(
            Key={"pk": pk_treasury, "sk": BALANCE_SK},
            UpdateExpression=(
                "SET balance_cents = balance_cents - :amt, "
                "total_refunded_cents = if_not_exists(total_refunded_cents, :z) + :amt, "
                "updated_at = :t"
            ),
            ConditionExpression="attribute_exists(balance_cents) AND balance_cents >= :amt",
            ExpressionAttributeValues={":amt": int(amount_cents), ":z": 0, ":t": ts},
        )
    except ClientError as e:
        if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
            # Balance moved underneath us (concurrent leave/spend). Surface so the
            # caller does NOT credit the member wallet against funds that no longer
            # exist — refund integrity over best-effort.
            raise HTTPException(status_code=409, detail="Insufficient treasury balance for refund")
        raise


def refund_on_member_leave(syndicate_id: str, user_id: str) -> Dict[str, Any]:
    """Refund a leaving member their proportional share of the treasury.

    refund = floor(current_balance * member_net / total_net)

    Where ``member_net`` is the member's net (contributed - refunded) contribution
    and ``total_net`` is the sum of net contributions across all members. The
    treasury is debited and the member's personal wallet credited atomically;
    the member's contribution tracker ``total_refunded_cents`` is bumped so a
    later dissolution refund doesn't double-pay them.

    Returns ``{"refunded_cents": int}``. A member who never contributed (or whose
    net contribution is already fully refunded) gets ``0``.
    """
    current_balance = get_treasury_balance(syndicate_id)["balance_cents"]
    if current_balance <= 0:
        return {"refunded_cents": 0}

    contributors = list_contributions(syndicate_id)
    total_net = sum(c["net_contributed_cents"] for c in contributors)
    if total_net <= 0:
        return {"refunded_cents": 0}

    member = next((c for c in contributors if c["user_id"] == user_id), None)
    member_net = member["net_contributed_cents"] if member else 0
    if member_net <= 0:
        return {"refunded_cents": 0}

    refund_cents = (current_balance * member_net) // total_net
    # Never refund more than the balance (defensive — floor() guarantees this,
    # but clamp against rounding/concurrency).
    refund_cents = min(refund_cents, current_balance)
    if refund_cents <= 0:
        return {"refunded_cents": 0}

    ts = now_ts()

    # 1. Debit treasury balance (conditional, raises 409 if insufficient).
    _debit_treasury_for_refund(syndicate_id, refund_cents, ts)

    # 2. Credit member's personal wallet.
    new_member_balance = apply_wallet_delta(T.billing, user_pk(user_id), refund_cents)

    # 3. Update contribution tracker so net_contributed reflects the refund.
    _bump_contrib_refund(syndicate_id, user_id, refund_cents, ts)

    # 4. Treasury-side ledger entry (debit).
    self_entry_id = _write_treasury_ledger(
        syndicate_id,
        direction="debit",
        amount_cents=refund_cents,
        reason=f"Treasury refund to {user_id}: member departure",
        actor_user_id=user_id,
        counterparty_user_id=user_id,
        ts=ts,
    )

    # 5. Member-side billing ledger entry (credit).
    user_entry_id = ulidish()
    T.billing.put_item(Item={
        "pk": user_pk(user_id),
        "sk": ledger_sk(ts, user_entry_id),
        "entry_id": user_entry_id,
        "ts": ts,
        "type": "syndicate_treasury_refund",
        "amount_cents": refund_cents,
        "state": "settled",
        "reason": "Syndicate treasury refund: departure",
        "direction": "credit",
        "category": "syndicate_treasury",
        "syndicate_id": syndicate_id,
        "currency": "usd",
        "created_at": ts,
    })

    logger.info(
        "syndicate_treasury.refund_on_member_leave",
        extra={"syndicate_id": syndicate_id, "user_id": user_id, "refunded_cents": refund_cents},
    )
    return {
        "refunded_cents": refund_cents,
        "new_member_balance_cents": new_member_balance,
        "treasury_entry_id": self_entry_id,
        "user_entry_id": user_entry_id,
    }


def refund_on_dissolution(syndicate_id: str) -> Dict[str, Any]:
    """Refund ALL remaining treasury funds proportionally to contributors, then zero.

    Each contributor with a positive net contribution receives
    ``floor(current_balance * net / total_net)``; the largest contributor absorbs
    any rounding remainder so the treasury ends at exactly zero. Returns
    ``{"total_refunded": int, "refunds": [{"user_id", "refunded_cents"}, ...]}``.
    """
    current_balance = get_treasury_balance(syndicate_id)["balance_cents"]
    if current_balance <= 0:
        return {"total_refunded": 0, "refunds": []}

    contributors = [c for c in list_contributions(syndicate_id) if c["net_contributed_cents"] > 0]
    total_net = sum(c["net_contributed_cents"] for c in contributors)
    if total_net <= 0:
        return {"total_refunded": 0, "refunds": []}

    # Largest net contribution first → last one in the loop gets the remainder.
    contributors.sort(key=lambda c: (c["net_contributed_cents"], c["user_id"]), reverse=True)

    ts = now_ts()
    refunds: List[Dict[str, Any]] = []
    remaining = current_balance

    for i, contrib in enumerate(contributors):
        if i == len(contributors) - 1:
            refund = remaining  # last contributor absorbs the rounding remainder
        else:
            refund = (current_balance * contrib["net_contributed_cents"]) // total_net
        refund = min(refund, remaining)
        if refund <= 0:
            continue
        remaining -= refund
        uid = contrib["user_id"]

        apply_wallet_delta(T.billing, user_pk(uid), refund)
        _bump_contrib_refund(syndicate_id, uid, refund, ts)
        _write_treasury_ledger(
            syndicate_id,
            direction="debit",
            amount_cents=refund,
            reason=f"Treasury refund to {uid}: syndicate dissolved",
            actor_user_id=uid,
            counterparty_user_id=uid,
            ts=ts,
        )
        user_entry_id = ulidish()
        T.billing.put_item(Item={
            "pk": user_pk(uid),
            "sk": ledger_sk(ts, user_entry_id),
            "entry_id": user_entry_id,
            "ts": ts,
            "type": "syndicate_treasury_refund",
            "amount_cents": refund,
            "state": "settled",
            "reason": "Syndicate treasury refund: syndicate dissolved",
            "direction": "credit",
            "category": "syndicate_treasury",
            "syndicate_id": syndicate_id,
            "currency": "usd",
            "created_at": ts,
        })
        refunds.append({"user_id": uid, "refunded_cents": refund})

    # Zero out the treasury balance (whatever distributed; remaining should be 0).
    distributed = current_balance - remaining
    if distributed > 0:
        T.syndicate_treasury.update_item(
            Key={"pk": _treasury_pk(syndicate_id), "sk": BALANCE_SK},
            UpdateExpression=(
                "SET balance_cents = balance_cents - :amt, "
                "total_refunded_cents = if_not_exists(total_refunded_cents, :z) + :amt, "
                "updated_at = :t"
            ),
            ExpressionAttributeValues={":amt": distributed, ":z": 0, ":t": ts},
        )

    total = sum(r["refunded_cents"] for r in refunds)
    logger.info(
        "syndicate_treasury.refund_on_dissolution",
        extra={"syndicate_id": syndicate_id, "total_refunded": total, "count": len(refunds)},
    )
    return {"total_refunded": total, "refunds": refunds}


# ---------------------------------------------------------------------------
# Ledger & contributions
# ---------------------------------------------------------------------------


def list_treasury_ledger(
    syndicate_id: str,
    *,
    cursor: Optional[str] = None,
    limit: int = 50,
) -> Dict[str, Any]:
    """List treasury transaction history (newest first)."""
    pk = _treasury_pk(syndicate_id)
    kwargs: Dict[str, Any] = {
        "KeyConditionExpression": Key("pk").eq(pk) & Key("sk").begins_with("LEDGER#"),
        "ScanIndexForward": False,
        "Limit": limit,
    }
    if cursor:
        try:
            kwargs["ExclusiveStartKey"] = json.loads(base64.b64decode(cursor).decode())
        except Exception:
            pass

    resp = T.syndicate_treasury.query(**kwargs)
    items = resp.get("Items", [])

    entries = [
        {
            "entry_id": i.get("entry_id", ""),
            "ts": int(i.get("created_at", i.get("ts", 0))),
            "direction": i.get("direction", "credit"),
            "amount_cents": int(i.get("amount_cents", 0)),
            "reason": i.get("reason", ""),
            "actor_user_id": i.get("actor_user_id", ""),
            "counterparty_user_id": i.get("counterparty_user_id", ""),
            "currency": i.get("currency", "usd"),
        }
        for i in items
    ]

    next_cursor = None
    last_key = resp.get("LastEvaluatedKey")
    if last_key:
        next_cursor = base64.b64encode(json.dumps(last_key).encode()).decode()

    return {
        "entries": entries,
        "cursor": next_cursor,
        "has_more": next_cursor is not None,
    }


def list_contributions(syndicate_id: str) -> List[Dict[str, Any]]:
    """Per-member contribution breakdown (sorted by total contributed desc)."""
    pk = _treasury_pk(syndicate_id)
    resp = T.syndicate_treasury.query(
        KeyConditionExpression=Key("pk").eq(pk) & Key("sk").begins_with("CONTRIB#"),
    )
    items = resp.get("Items", [])
    contributors = [
        {
            "user_id": i.get("user_id", ""),
            "total_contributed_cents": int(i.get("total_contributed_cents", 0)),
            "total_refunded_cents": int(i.get("total_refunded_cents", 0)),
            "net_contributed_cents": int(i.get("total_contributed_cents", 0))
            - int(i.get("total_refunded_cents", 0)),
            "contribution_count": int(i.get("contribution_count", 0)),
            "last_contribution_at": int(i.get("last_contribution_at", 0)),
        }
        for i in items
    ]
    contributors.sort(key=lambda c: c["total_contributed_cents"], reverse=True)
    return contributors


def get_my_contributions(syndicate_id: str, user_id: str) -> Dict[str, Any]:
    """A single member's contribution summary."""
    pk = _treasury_pk(syndicate_id)
    resp = T.syndicate_treasury.get_item(Key={"pk": pk, "sk": f"CONTRIB#{user_id}"})
    item = resp.get("Item") or {}
    total_contributed = int(item.get("total_contributed_cents", 0))
    total_refunded = int(item.get("total_refunded_cents", 0))
    return {
        "user_id": user_id,
        "total_contributed_cents": total_contributed,
        "total_refunded_cents": total_refunded,
        "net_contributed_cents": total_contributed - total_refunded,
        "contribution_count": int(item.get("contribution_count", 0)),
        "last_contribution_at": int(item.get("last_contribution_at", 0)),
    }
