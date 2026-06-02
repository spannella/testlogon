"""Collaboration revenue split logic (CREATOR-001)."""

from __future__ import annotations

import logging
import uuid
from typing import Any, Dict, Optional

from app.core.tables import T
from app.core.time import now_ts
from app.services.collaborations import get_collaboration

logger = logging.getLogger(__name__)


def write_collaboration_split_ledger(
    *,
    collaboration_id: str,
    payer_user_id: str,
    amount_cents: int,
    currency: str = "USD",
    content_type: str = "collaboration",
    content_id: str = "",
    payment_method_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Write split ledger entries for a collaboration.

    For each collaborator compute: floor(amount * pct / 100).
    Remainder goes to initiator.

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

    entries: Dict[str, int] = {}
    allocated = 0

    for user_id, pct in sorted(split.items()):
        share = amount_cents * int(pct) // 100
        entries[user_id] = share
        allocated += share

    # Remainder to initiator
    remainder = amount_cents - allocated
    if initiator_id in entries:
        entries[initiator_id] += remainder
    else:
        entries[initiator_id] = remainder

    # Write ledger entries
    now = now_ts()
    results: Dict[str, Any] = {}
    for user_id, share_cents in entries.items():
        if share_cents <= 0:
            continue
        entry_id = f"collab_split_{uuid.uuid4().hex}"
        try:
            T.billing.put_item(Item={
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
                },
            })
            results[user_id] = share_cents
        except Exception:
            logger.warning("Failed to write collab split credit for %s", user_id, exc_info=True)

    # Write debit for payer
    try:
        debit_id = f"collab_debit_{uuid.uuid4().hex}"
        T.billing.put_item(Item={
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
            },
        })
    except Exception:
        logger.warning("Failed to write collab split debit for %s", payer_user_id, exc_info=True)

    # Update running total
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
