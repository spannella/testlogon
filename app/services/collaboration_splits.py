"""Collaboration revenue split logic (CREATOR-001).

TIPX-A4 (P0): tip-sourced collaboration splits now take the platform fee (the
NET is distributed, the fee is retained -- reconciling with the solo-tip net
formula) and the whole distribution (all collaborator credits + the payer debit)
is written as a SINGLE ``TransactWriteItems`` so it is all-or-nothing -- a partial
write can no longer credit collaborators without debiting the payer (or vice
versa). Non-tip sources (subscriptions / unlocks / the test split endpoint)
retain the previous full-amount, fee-free behavior.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any, Dict, Optional

from boto3.dynamodb.types import TypeSerializer
from botocore.exceptions import ClientError

from app.core.settings import S
from app.core.tables import T, _to_decimal
from app.core.aws_clients import ddb_transact_client
from app.core.time import now_ts
from app.services.billing_config import split_fee
from app.services.collaborations import get_collaboration

logger = logging.getLogger(__name__)

_SERIALIZER = TypeSerializer()


def _av(item: Dict[str, Any]) -> Dict[str, Any]:
    """Serialize a plain dict into the DynamoDB low-level attribute-value map used
    by TransactWriteItems (floats coerced to Decimal first)."""
    return {k: _SERIALIZER.serialize(v) for k, v in _to_decimal(item).items()}


def write_collaboration_split_ledger(
    *,
    collaboration_id: str,
    payer_user_id: str,
    amount_cents: int,
    currency: str = "USD",
    content_type: str = "collaboration",
    content_id: str = "",
    payment_method_id: Optional[str] = None,
    source: str = "",
) -> Dict[str, Any]:
    """Write split ledger entries for a collaboration.

    The payer is debited the full GROSS ``amount_cents``. When ``source == "tip"``
    the platform fee is retained (via ``split_fee("tip_debit", ...)``) and the NET
    is distributed among collaborators, so a collaboration tip reconciles to the
    same fee-net formula as a solo tip. For any other source the full amount is
    distributed (fee-free), preserving prior behavior.

    For each collaborator compute: floor(distributable * pct / 100).
    Remainder goes to initiator.

    Credits + debit are written atomically in one TransactWriteItems, so a failure
    writes NOTHING (no half-written credit-without-debit).

    Returns dict mapping user_id -> their credited cents.
    """
    collab = get_collaboration(collaboration_id)
    if not collab:
        raise KeyError(f"Collaboration {collaboration_id} not found")
    if collab.get("status") != "accepted":
        raise ValueError("Collaboration is not active")

    split = collab.get("split", {})
    initiator_id = collab["initiator_id"]

    # Revenue events may arrive with a float amount (e.g. dollars); DynamoDB
    # rejects float types, so normalize to integer cents before any math/writes.
    amount_cents = int(round(amount_cents))

    # TIPX-A4: tip splits take the platform fee. The payer is charged GROSS; only
    # the NET is distributed among collaborators (mirrors build_tip_ledger_items).
    is_tip = source == "tip"
    if is_tip:
        fee_cents, distributable_cents, fee_bps = split_fee("tip_debit", amount_cents)
    else:
        fee_cents, distributable_cents, fee_bps = 0, amount_cents, 0

    entries: Dict[str, int] = {}
    allocated = 0

    for user_id, pct in sorted(split.items()):
        share = distributable_cents * int(pct) // 100
        entries[user_id] = share
        allocated += share

    # Remainder to initiator
    remainder = distributable_cents - allocated
    if initiator_id in entries:
        entries[initiator_id] += remainder
    else:
        entries[initiator_id] = remainder

    now = now_ts()
    fee_meta = {"platform_fee_bps": fee_bps, "platform_fee_cents": fee_cents} if is_tip else {}

    # Build the atomic transaction: one credit per (positive) collaborator share +
    # a single payer debit for the GROSS amount.
    tx_items = []
    results: Dict[str, Any] = {}
    for user_id, share_cents in entries.items():
        if share_cents <= 0:
            continue
        entry_id = f"collab_split_{uuid.uuid4().hex}"
        credit_item = {
            "pk": f"USER#{user_id}",
            "sk": f"LEDGER#{now}#{entry_id}",
            "entry_id": entry_id,
            "ts": now,
            "type": "credit",
            "amount_cents": share_cents,
            "currency": currency,
            "state": "completed",
            "reason": f"Collaboration {content_type} split",
            "meta": {
                "collaboration_id": collaboration_id,
                "split_pct": int(split.get(user_id, 0)),
                "total_amount_cents": amount_cents,
                "payer_user_id": payer_user_id,
                "content_type": content_type,
                "content_id": content_id,
                "source": source,
                **fee_meta,
            },
        }
        tx_items.append({"Put": {"TableName": S.billing_table_name, "Item": _av(credit_item)}})
        results[user_id] = share_cents

    # Payer debit -- full GROSS amount.
    debit_id = f"collab_debit_{uuid.uuid4().hex}"
    debit_item = {
        "pk": f"USER#{payer_user_id}",
        "sk": f"LEDGER#{now}#{debit_id}",
        "entry_id": debit_id,
        "ts": now,
        "type": "debit",
        "amount_cents": amount_cents,
        "currency": currency,
        "state": "completed",
        "reason": f"Collaboration {content_type} split",
        "meta": {
            "collaboration_id": collaboration_id,
            "content_type": content_type,
            "content_id": content_id,
            "source": source,
            **fee_meta,
        },
    }
    tx_items.append({"Put": {"TableName": S.billing_table_name, "Item": _av(debit_item)}})

    # Atomic all-or-nothing write (credits + debit). A cancellation/error leaves
    # NO ledger rows rather than a half-written credit-without-debit orphan.
    try:
        ddb_transact_client().transact_write_items(TransactItems=tx_items)
    except ClientError:
        logger.warning(
            "collab split transact failed; no ledger rows written for collab %s",
            collaboration_id, exc_info=True,
        )
        raise

    # Update running total (best-effort; the money rows are already committed).
    _update_collab_revenue(collaboration_id, amount_cents)

    return results


def _update_collab_revenue(collaboration_id: str, amount_cents: int) -> None:
    """Atomically increment total_revenue_cents."""
    try:
        T.collaboration_agreements.update_item(
            Key={"collaboration_id": collaboration_id, "sk": "CURRENT"},
            UpdateExpression="SET total_revenue_cents = total_revenue_cents + :amt, updated_at = :now",
            ExpressionAttributeValues={
                ":amt": amount_cents,
                ":now": now_ts(),
            },
        )
    except Exception:
        logger.warning("Failed to update collab revenue total for %s", collaboration_id)
