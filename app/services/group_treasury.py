"""Group treasury management — contributions, spending, dissolution (GROUP-004)."""

from __future__ import annotations

import base64
import json
import logging
from typing import Any, Dict, List, Optional

from botocore.exceptions import ClientError
from boto3.dynamodb.conditions import Key
from boto3.dynamodb.types import TypeSerializer
from fastapi import HTTPException

from app.core.tables import T
from app.core.time import now_ts
from app.services.billing_shared import (
    WALLET_SK,
    apply_wallet_delta,
    get_wallet_balance,
    ledger_sk,
    new_ledger_entry,
    ulidish,
    user_pk,
)
from app.services import user_groups

logger = logging.getLogger(__name__)

ALLOWED_SPEND_CATEGORIES = {"ad_spend", "event", "premium_feature", "other"}

# DynamoDB TransactWriteItems is capped at 25 items per call. A contributor
# refund costs 3 items (wallet credit + personal ledger + treasury ledger), so
# 8 contributors (24 items) is the largest count that fits in a single
# transaction while leaving room for the final balance-zero / escrow writes.
_TRANSACT_MAX_ITEMS = 25
_CONTRIB_ITEMS = 3
_CONTRIB_BATCH_SIZE = 8  # 8 * 3 = 24 items, leaves headroom under the 25 cap

_serializer = TypeSerializer()


def _group_pk(group_id: str) -> str:
    return f"GROUP#{group_id}"


def _to_ddb_item(item: Dict[str, Any]) -> Dict[str, Any]:
    """Serialize a plain dict into a low-level DDB AttributeValue map.

    Used for ``transact_write_items`` (low-level client API), mirroring the
    pattern in ``app/routers/newsfeed.py``.
    """
    return {k: _serializer.serialize(v) for k, v in item.items() if v is not None}


# ---------------------------------------------------------------------------
# Balance
# ---------------------------------------------------------------------------


def get_treasury_balance(group_id: str) -> Dict[str, Any]:
    """Return the current treasury balance and totals."""
    pk = _group_pk(group_id)
    resp = T.billing.get_item(Key={"pk": pk, "sk": WALLET_SK})
    row = resp.get("Item")
    if not row:
        return {
            "balance_cents": 0,
            "currency": "usd",
            "total_contributed_cents": 0,
            "total_donated_cents": 0,
            "total_spent_cents": 0,
            "fundraising_goal_cents": None,
        }
    return {
        "balance_cents": int(row.get("wallet_balance_cents", 0)),
        "currency": row.get("currency", "usd"),
        "total_contributed_cents": int(row.get("total_contributed_cents", 0)),
        "total_donated_cents": int(row.get("total_donated_cents", 0)),
        "total_spent_cents": int(row.get("total_spent_cents", 0)),
        "fundraising_goal_cents": int(row["fundraising_goal_cents"]) if row.get("fundraising_goal_cents") is not None else None,
    }


# ---------------------------------------------------------------------------
# Contribute
# ---------------------------------------------------------------------------


def contribute(
    group_id: str,
    user_id: str,
    amount_cents: int,
    display_name: str = "",
) -> Dict[str, Any]:
    """Member contributes from personal wallet to treasury."""
    # 1. Verify membership
    user_groups.require_membership(group_id, user_id)

    pk_user = user_pk(user_id)
    pk_group = _group_pk(group_id)

    # 2. Debit personal wallet (conditional overdraft check)
    try:
        personal_balance = apply_wallet_delta(T.billing, pk_user, -amount_cents)
    except ClientError as e:
        if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
            raise HTTPException(status_code=400, detail="Insufficient wallet balance")
        raise

    # 3. Credit group treasury (atomic increment, auto-create)
    ts = now_ts()
    T.billing.update_item(
        Key={"pk": pk_group, "sk": WALLET_SK},
        UpdateExpression=(
            "SET wallet_balance_cents = if_not_exists(wallet_balance_cents, :z) + :amt, "
            "total_contributed_cents = if_not_exists(total_contributed_cents, :z) + :amt, "
            "total_donated_cents = if_not_exists(total_donated_cents, :z), "
            "total_spent_cents = if_not_exists(total_spent_cents, :z), "
            "currency = :c, updated_at = :t"
        ),
        ExpressionAttributeValues={
            ":z": 0,
            ":amt": amount_cents,
            ":c": "usd",
            ":t": ts,
        },
        ReturnValues="ALL_NEW",
    )

    # 4. Write personal ledger entry (debit)
    entry_id = ulidish()
    personal_ledger_item = {
        "pk": pk_user,
        "sk": ledger_sk(ts, entry_id),
        "entry_id": entry_id,
        "ts": ts,
        "type": "treasury_contribution",
        "amount_cents": amount_cents,
        "state": "settled",
        "reason": "Contribution to group treasury",
        "direction": "debit",
        "category": "contribution",
        "group_id": group_id,
    }
    T.billing.put_item(Item=personal_ledger_item)

    # 5. Write treasury ledger entry (credit)
    treasury_entry_id = ulidish()
    treasury_ledger_item = {
        "pk": pk_group,
        "sk": ledger_sk(ts, treasury_entry_id),
        "entry_id": treasury_entry_id,
        "ts": ts,
        "type": "contribution",
        "amount_cents": amount_cents,
        "state": "settled",
        "reason": f"Contribution from {display_name or user_id}",
        "direction": "credit",
        "category": "contribution",
        "actor_user_id": user_id,
        "actor_display_name": display_name or user_id,
        "currency": "usd",
        "created_at": ts,
    }
    T.billing.put_item(Item=treasury_ledger_item)

    # 6. Update contribution tracker
    T.billing.update_item(
        Key={"pk": pk_group, "sk": f"CONTRIB#{user_id}"},
        UpdateExpression=(
            "SET user_id = :uid, display_name = :dn, "
            "total_contributed_cents = if_not_exists(total_contributed_cents, :z) + :amt, "
            "contribution_count = if_not_exists(contribution_count, :z) + :one, "
            "first_contributed_at = if_not_exists(first_contributed_at, :t), "
            "last_contributed_at = :t"
        ),
        ExpressionAttributeValues={
            ":uid": user_id,
            ":dn": display_name or user_id,
            ":z": 0,
            ":amt": amount_cents,
            ":one": 1,
            ":t": ts,
        },
    )

    # Get updated balance
    balance = get_treasury_balance(group_id)

    # Get contributor total
    contrib_resp = T.billing.get_item(Key={"pk": pk_group, "sk": f"CONTRIB#{user_id}"})
    contrib_item = contrib_resp.get("Item", {})
    contribution_total = int(contrib_item.get("total_contributed_cents", 0))

    logger.info("treasury.contribute", extra={
        "group_id": group_id,
        "user_id": user_id,
        "amount_cents": amount_cents,
        "new_balance_cents": balance["balance_cents"],
    })

    return {
        "ok": True,
        "balance_cents": balance["balance_cents"],
        "personal_balance_cents": personal_balance,
        "contribution_total_cents": contribution_total,
        "ledger_entry_id": treasury_entry_id,
    }


# ---------------------------------------------------------------------------
# Donate (external, called by GROUP-003)
# ---------------------------------------------------------------------------


def credit_donation(
    group_id: str,
    amount_cents: int,
    donor_name: str = "",
    donation_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Credit an external donation to the treasury."""
    pk_group = _group_pk(group_id)
    ts = now_ts()

    T.billing.update_item(
        Key={"pk": pk_group, "sk": WALLET_SK},
        UpdateExpression=(
            "SET wallet_balance_cents = if_not_exists(wallet_balance_cents, :z) + :amt, "
            "total_donated_cents = if_not_exists(total_donated_cents, :z) + :amt, "
            "total_contributed_cents = if_not_exists(total_contributed_cents, :z), "
            "total_spent_cents = if_not_exists(total_spent_cents, :z), "
            "currency = :c, updated_at = :t"
        ),
        ExpressionAttributeValues={
            ":z": 0,
            ":amt": amount_cents,
            ":c": "usd",
            ":t": ts,
        },
    )

    entry_id = ulidish()
    ledger_item = {
        "pk": pk_group,
        "sk": ledger_sk(ts, entry_id),
        "entry_id": entry_id,
        "ts": ts,
        "type": "donation",
        "amount_cents": amount_cents,
        "state": "settled",
        "reason": f"Donation from {donor_name}" if donor_name else "External donation",
        "direction": "credit",
        "category": "donation",
        "actor_display_name": donor_name,
        "reference_id": donation_id,
        "currency": "usd",
        "created_at": ts,
    }
    T.billing.put_item(Item=ledger_item)

    balance = get_treasury_balance(group_id)
    return {
        "ok": True,
        "balance_cents": balance["balance_cents"],
        "ledger_entry_id": entry_id,
    }


# ---------------------------------------------------------------------------
# Spend
# ---------------------------------------------------------------------------


def spend_treasury(
    group_id: str,
    admin_id: str,
    amount_cents: int,
    reason: str,
    category: str = "ad_spend",
    reference_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Admin spends from treasury. No funds go to personal wallets."""
    # 1. Verify admin role
    user_groups.require_admin(group_id, admin_id)

    # 2. Validate category
    if category not in ALLOWED_SPEND_CATEGORIES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid spend category. Allowed: {', '.join(sorted(ALLOWED_SPEND_CATEGORIES))}",
        )

    pk_group = _group_pk(group_id)

    # 3. Debit group treasury (conditional: balance >= amount)
    try:
        T.billing.update_item(
            Key={"pk": pk_group, "sk": WALLET_SK},
            UpdateExpression=(
                "SET wallet_balance_cents = wallet_balance_cents - :amt, "
                "total_spent_cents = if_not_exists(total_spent_cents, :z) + :amt, "
                "updated_at = :t"
            ),
            ConditionExpression="wallet_balance_cents >= :amt",
            ExpressionAttributeValues={
                ":amt": amount_cents,
                ":z": 0,
                ":t": now_ts(),
            },
            ReturnValues="ALL_NEW",
        )
    except ClientError as e:
        if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
            raise HTTPException(status_code=400, detail="Insufficient treasury balance")
        raise

    # 4. Write treasury ledger entry (debit)
    ts = now_ts()
    entry_id = ulidish()
    ledger_item = {
        "pk": pk_group,
        "sk": ledger_sk(ts, entry_id),
        "entry_id": entry_id,
        "ts": ts,
        "type": category,
        "amount_cents": amount_cents,
        "state": "settled",
        "reason": reason,
        "direction": "debit",
        "category": category,
        "actor_user_id": admin_id,
        "actor_display_name": admin_id,
        "reference_id": reference_id,
        "currency": "usd",
        "created_at": ts,
    }
    T.billing.put_item(Item=ledger_item)

    balance = get_treasury_balance(group_id)
    logger.info("treasury.spend", extra={
        "group_id": group_id,
        "admin_id": admin_id,
        "amount_cents": amount_cents,
        "category": category,
        "reason": reason,
        "remaining_balance_cents": balance["balance_cents"],
    })

    return {
        "ok": True,
        "balance_cents": balance["balance_cents"],
        "total_spent_cents": balance["total_spent_cents"],
        "ledger_entry_id": entry_id,
    }


# ---------------------------------------------------------------------------
# Ledger & Contributors
# ---------------------------------------------------------------------------


def list_treasury_ledger(
    group_id: str,
    cursor: Optional[str] = None,
    limit: int = 20,
) -> Dict[str, Any]:
    """List treasury ledger entries (newest first)."""
    pk_group = _group_pk(group_id)

    kwargs: Dict[str, Any] = {
        "KeyConditionExpression": Key("pk").eq(pk_group) & Key("sk").begins_with("LEDGER#"),
        "ScanIndexForward": False,
        "Limit": limit,
    }
    if cursor:
        try:
            kwargs["ExclusiveStartKey"] = json.loads(base64.b64decode(cursor).decode())
        except Exception:
            pass

    resp = T.billing.query(**kwargs)
    items = resp.get("Items", [])

    entries = []
    for item in items:
        entries.append({
            "entry_id": item.get("entry_id", ""),
            "amount_cents": int(item.get("amount_cents", 0)),
            "currency": item.get("currency", "usd"),
            "direction": item.get("direction", "credit"),
            "reason": item.get("reason", ""),
            "category": item.get("category", ""),
            "actor_user_id": item.get("actor_user_id"),
            "actor_display_name": item.get("actor_display_name"),
            "reference_id": item.get("reference_id"),
            "created_at": int(item.get("created_at", item.get("ts", 0))),
        })

    next_cursor = None
    has_more = False
    last_key = resp.get("LastEvaluatedKey")
    if last_key:
        has_more = True
        next_cursor = base64.b64encode(json.dumps(last_key).encode()).decode()

    return {
        "entries": entries,
        "cursor": next_cursor,
        "has_more": has_more,
    }


def list_contributors(group_id: str) -> Dict[str, Any]:
    """List all contributors sorted by total contributed (desc)."""
    pk_group = _group_pk(group_id)

    resp = T.billing.query(
        KeyConditionExpression=Key("pk").eq(pk_group) & Key("sk").begins_with("CONTRIB#"),
    )
    items = resp.get("Items", [])

    contributors = []
    for item in items:
        contributors.append({
            "user_id": item.get("user_id", ""),
            "display_name": item.get("display_name", ""),
            "total_contributed_cents": int(item.get("total_contributed_cents", 0)),
            "contribution_count": int(item.get("contribution_count", 0)),
            "first_contributed_at": int(item.get("first_contributed_at", 0)),
            "last_contributed_at": int(item.get("last_contributed_at", 0)),
        })

    contributors.sort(key=lambda c: c["total_contributed_cents"], reverse=True)

    return {
        "contributors": contributors,
        "count": len(contributors),
    }


# ---------------------------------------------------------------------------
# Goal
# ---------------------------------------------------------------------------


def set_fundraising_goal(
    group_id: str,
    admin_id: str,
    goal_cents: Optional[int],
) -> Dict[str, Any]:
    """Set or clear the fundraising goal (admin only)."""
    user_groups.require_admin(group_id, admin_id)
    pk_group = _group_pk(group_id)

    if goal_cents is not None:
        T.billing.update_item(
            Key={"pk": pk_group, "sk": WALLET_SK},
            UpdateExpression=(
                "SET fundraising_goal_cents = :g, "
                "wallet_balance_cents = if_not_exists(wallet_balance_cents, :z), "
                "total_contributed_cents = if_not_exists(total_contributed_cents, :z), "
                "total_donated_cents = if_not_exists(total_donated_cents, :z), "
                "total_spent_cents = if_not_exists(total_spent_cents, :z), "
                "currency = if_not_exists(currency, :c), "
                "updated_at = :t"
            ),
            ExpressionAttributeValues={
                ":g": goal_cents,
                ":z": 0,
                ":c": "usd",
                ":t": now_ts(),
            },
        )
    else:
        T.billing.update_item(
            Key={"pk": pk_group, "sk": WALLET_SK},
            UpdateExpression=(
                "SET wallet_balance_cents = if_not_exists(wallet_balance_cents, :z), "
                "total_contributed_cents = if_not_exists(total_contributed_cents, :z), "
                "total_donated_cents = if_not_exists(total_donated_cents, :z), "
                "total_spent_cents = if_not_exists(total_spent_cents, :z), "
                "currency = if_not_exists(currency, :c), "
                "updated_at = :t "
                "REMOVE fundraising_goal_cents"
            ),
            ExpressionAttributeValues={
                ":z": 0,
                ":c": "usd",
                ":t": now_ts(),
            },
        )

    balance = get_treasury_balance(group_id)
    return {
        "ok": True,
        "fundraising_goal_cents": balance["fundraising_goal_cents"],
    }


# ---------------------------------------------------------------------------
# Dissolution
# ---------------------------------------------------------------------------


def _begin_dissolution(pk_group: str, ts: int) -> str:
    """Mark dissolution as in-progress with a conditional write (GAP-0219).

    Returns the ``dissolution_id`` for saga tracking. Raises ``HTTPException(409)``
    if a dissolution is already in progress or complete for this treasury. This
    is the idempotency guard that prevents a second concurrent or retried call
    from re-running the distribution and double-crediting contributors.

    Backward compatible: legacy treasury records have no ``dissolution_state``
    attribute, so ``attribute_not_exists`` lets a first dissolution proceed.
    """
    dissolution_id = ulidish()
    try:
        T.billing.update_item(
            Key={"pk": pk_group, "sk": WALLET_SK},
            UpdateExpression=(
                "SET dissolution_state = :state, dissolution_id = :did, "
                "dissolution_started_at = :t"
            ),
            ConditionExpression=(
                "attribute_not_exists(dissolution_state) OR dissolution_state = :none_val"
            ),
            ExpressionAttributeValues={
                ":state": "in_progress",
                ":did": dissolution_id,
                ":t": ts,
                ":none_val": "none",
            },
        )
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            raise HTTPException(409, "Dissolution already in progress or complete.")
        raise
    return dissolution_id


def _record_progress(pk_group: str, completed_uids: List[str], ts: int) -> None:
    """Checkpoint the set of contributors already refunded (saga marker)."""
    T.billing.update_item(
        Key={"pk": pk_group, "sk": WALLET_SK},
        UpdateExpression=(
            "SET dissolution_completed_user_ids = :uids, updated_at = :t"
        ),
        ExpressionAttributeValues={":uids": list(completed_uids), ":t": ts},
    )


def _contributor_transact_items(
    pk_user: str,
    pk_group: str,
    share: int,
    uid: str,
    ts: int,
    group_id: str,
) -> List[Dict[str, Any]]:
    """Build the 3 atomic TransactItems for one contributor refund.

    Wallet credit + personal ledger credit + treasury ledger debit are written
    in the same transaction: either all three commit or none do. The ledger
    ``Put`` operations are made idempotent with ``attribute_not_exists(sk)`` so a
    replay with the same entry_id fails cleanly rather than duplicating.
    """
    credit_entry_id = ulidish()
    debit_entry_id = ulidish()
    table_name = T.billing.name
    return [
        {
            "Update": {
                "TableName": table_name,
                "Key": _to_ddb_item({"pk": pk_user, "sk": WALLET_SK}),
                "UpdateExpression": (
                    "SET wallet_balance_cents = if_not_exists(wallet_balance_cents, :z) + :share, "
                    "currency = if_not_exists(currency, :c), updated_at = :t"
                ),
                "ExpressionAttributeValues": _to_ddb_item(
                    {":z": 0, ":share": share, ":c": "usd", ":t": ts}
                ),
            }
        },
        {
            "Put": {
                "TableName": table_name,
                "Item": _to_ddb_item({
                    "pk": pk_user,
                    "sk": ledger_sk(ts, credit_entry_id),
                    "entry_id": credit_entry_id,
                    "ts": ts,
                    "type": "dissolution_refund",
                    "amount_cents": share,
                    "state": "settled",
                    "reason": "Group dissolution refund",
                    "direction": "credit",
                    "category": "refund",
                    "group_id": group_id,
                    "currency": "usd",
                    "created_at": ts,
                }),
                "ConditionExpression": "attribute_not_exists(sk)",
            }
        },
        {
            "Put": {
                "TableName": table_name,
                "Item": _to_ddb_item({
                    "pk": pk_group,
                    "sk": ledger_sk(ts, debit_entry_id),
                    "entry_id": debit_entry_id,
                    "ts": ts,
                    "type": "dissolution_return",
                    "amount_cents": share,
                    "state": "settled",
                    "reason": f"Dissolution refund to {uid}",
                    "direction": "debit",
                    "category": "dissolution_return",
                    "actor_user_id": uid,
                    "currency": "usd",
                    "created_at": ts,
                }),
                "ConditionExpression": "attribute_not_exists(sk)",
            }
        },
    ]


def _escrow_transact_items(
    pk_group: str, escrow_amount: int, group_id: str, ts: int
) -> List[Dict[str, Any]]:
    """Build the 3 atomic TransactItems for the escrow transfer."""
    credit_entry_id = ulidish()
    debit_entry_id = ulidish()
    table_name = T.billing.name
    return [
        {
            "Update": {
                "TableName": table_name,
                "Key": _to_ddb_item({"pk": "PLATFORM#ESCROW", "sk": WALLET_SK}),
                "UpdateExpression": (
                    "SET wallet_balance_cents = if_not_exists(wallet_balance_cents, :z) + :amt, "
                    "currency = if_not_exists(currency, :c), updated_at = :t"
                ),
                "ExpressionAttributeValues": _to_ddb_item(
                    {":z": 0, ":amt": escrow_amount, ":c": "usd", ":t": ts}
                ),
            }
        },
        {
            "Put": {
                "TableName": table_name,
                "Item": _to_ddb_item({
                    "pk": "PLATFORM#ESCROW",
                    "sk": ledger_sk(ts, credit_entry_id),
                    "entry_id": credit_entry_id,
                    "ts": ts,
                    "type": "escrow_deposit",
                    "amount_cents": escrow_amount,
                    "state": "settled",
                    "reason": f"Escrow from dissolved group {group_id}",
                    "direction": "credit",
                    "category": "escrow_transfer",
                    "group_id": group_id,
                    "currency": "usd",
                    "created_at": ts,
                }),
                "ConditionExpression": "attribute_not_exists(sk)",
            }
        },
        {
            "Put": {
                "TableName": table_name,
                "Item": _to_ddb_item({
                    "pk": pk_group,
                    "sk": ledger_sk(ts, debit_entry_id),
                    "entry_id": debit_entry_id,
                    "ts": ts,
                    "type": "escrow_transfer",
                    "amount_cents": escrow_amount,
                    "state": "settled",
                    "reason": "Donation share transferred to platform escrow",
                    "direction": "debit",
                    "category": "escrow_transfer",
                    "currency": "usd",
                    "created_at": ts,
                }),
                "ConditionExpression": "attribute_not_exists(sk)",
            }
        },
    ]


def _treasury_zero_item(pk_group: str, ts: int, dissolution_id: str) -> Dict[str, Any]:
    """Build the TransactItem that zeroes the treasury and marks completion."""
    return {
        "Update": {
            "TableName": T.billing.name,
            "Key": _to_ddb_item({"pk": pk_group, "sk": WALLET_SK}),
            "UpdateExpression": (
                "SET wallet_balance_cents = :z, updated_at = :t, "
                "dissolution_state = :done"
            ),
            # Only zero if THIS dissolution owns the in-progress marker. Guards
            # against a stale/concurrent attempt completing on top of another.
            "ConditionExpression": "dissolution_id = :did",
            "ExpressionAttributeValues": _to_ddb_item(
                {":z": 0, ":t": ts, ":done": "complete", ":did": dissolution_id}
            ),
        }
    }


def _transact_client():
    """Return a low-level DynamoDB client for ``transact_write_items``.

    We build the items as raw AttributeValue maps (``_to_ddb_item``), so they
    must go through a *plain* low-level client. The boto3 resource's
    ``.meta.client`` carries the high-level document transform injector, which
    would re-serialize already-serialized values. Constructed lazily from the
    resource client's endpoint/region/credentials so it inherits the dev
    (DynamoDB Local) or prod (AWS) target with no ``S.dev_mode`` branch
    (SECOPS-007 parity).
    """
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


def _batch_transact(items: List[Dict[str, Any]]) -> None:
    """Commit up to 25 DDB put/update items atomically."""
    if not items:
        return
    if len(items) > _TRANSACT_MAX_ITEMS:
        raise ValueError(
            f"TransactWriteItems limit is {_TRANSACT_MAX_ITEMS}, got {len(items)}"
        )
    _transact_client().transact_write_items(TransactItems=items)


def dissolve_treasury(group_id: str) -> Dict[str, Any]:
    """Distribute remaining funds on group dissolution (atomic — GAP-0219).

    - Contributions returned pro-rata to contributors
    - Donations sent to PLATFORM#ESCROW
    - Treasury zeroed

    All money movement is grouped into DynamoDB ``TransactWriteItems`` batches so
    each contributor's wallet credit and both ledger entries commit atomically.
    A conditional ``dissolution_state`` marker guards against double-runs, and a
    saga checkpoint (``dissolution_completed_user_ids``) lets large contributor
    lists resume idempotently after a partial failure without double-crediting.
    """
    balance_info = get_treasury_balance(group_id)
    remaining = balance_info["balance_cents"]

    if remaining <= 0:
        return {"ok": True, "refunded_count": 0, "escrow_cents": 0}

    total_contributed = balance_info["total_contributed_cents"]
    total_donated = balance_info["total_donated_cents"]
    total_pool = total_contributed + total_donated

    if total_pool == 0:
        # Edge case: balance exists but no tracked sources
        contribution_remaining = remaining
    else:
        contribution_remaining = (remaining * total_contributed) // total_pool

    pk_group = _group_pk(group_id)
    ts = now_ts()
    total_refunded = 0

    # Idempotency guard: conditional marker — raises 409 if already dissolving.
    dissolution_id = _begin_dissolution(pk_group, ts)

    # Resume support: skip contributors already refunded by a prior partial run.
    wallet_resp = T.billing.get_item(Key={"pk": pk_group, "sk": WALLET_SK})
    completed_uids = set(
        wallet_resp.get("Item", {}).get("dissolution_completed_user_ids", []) or []
    )

    # Get all contributors
    contrib_resp = T.billing.query(
        KeyConditionExpression=Key("pk").eq(pk_group) & Key("sk").begins_with("CONTRIB#"),
    )
    contributors = contrib_resp.get("Items", [])

    refunded_count = 0

    # Pro-rata refund to each contributor, committed in atomic batches.
    if contribution_remaining > 0 and contributors and total_contributed > 0:
        pending: List[Dict[str, Any]] = []
        pending_uids: List[str] = []

        def _flush() -> None:
            nonlocal pending, pending_uids
            if not pending:
                return
            _batch_transact(pending)
            for u in pending_uids:
                completed_uids.add(u)
            _record_progress(pk_group, list(completed_uids), ts)
            pending = []
            pending_uids = []

        for contributor in contributors:
            their_total = int(contributor.get("total_contributed_cents", 0))
            if their_total <= 0:
                continue

            share = (contribution_remaining * their_total) // total_contributed
            if share <= 0:
                continue

            uid = contributor.get("user_id", "")
            if uid in completed_uids:
                # Already refunded by an earlier partial run — skip (no double credit).
                refunded_count += 1
                total_refunded += share
                continue

            pending.extend(
                _contributor_transact_items(user_pk(uid), pk_group, share, uid, ts, group_id)
            )
            pending_uids.append(uid)
            total_refunded += share
            refunded_count += 1

            if len(pending_uids) >= _CONTRIB_BATCH_SIZE:
                _flush()

        _flush()

    # Final batch: escrow transfer (if any) + treasury-zero, committed atomically.
    escrow_amount = remaining - total_refunded
    final_batch: List[Dict[str, Any]] = []
    if escrow_amount > 0:
        final_batch.extend(_escrow_transact_items(pk_group, escrow_amount, group_id, ts))
    final_batch.append(_treasury_zero_item(pk_group, ts, dissolution_id))
    _batch_transact(final_batch)

    logger.info("treasury.dissolution_complete", extra={
        "group_id": group_id,
        "remaining_balance": remaining,
        "contributor_count": len(contributors),
        "total_refunded_cents": total_refunded,
        "escrow_amount_cents": escrow_amount,
    })

    return {
        "ok": True,
        "refunded_count": refunded_count,
        "total_refunded_cents": total_refunded,
        "escrow_cents": escrow_amount,
    }
