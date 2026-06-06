"""Tip billing ledger integration.

Writes paired debit/credit entries for every tip transaction.
All four tipping surfaces (message attached, post-send message, post, comment)
call through this module.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any, Dict, Optional

from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)


class TipLedgerEntry:
    """Data required to write a tip ledger entry pair.

    Attributes:
        tipper_user_id: The user sending the tip (debited).
        recipient_user_id: The user receiving the tip (credited).
        amount_cents: Tip amount in cents. Must be > 0.
        currency: ISO 4217 currency code (default "USD").
        content_type: Type of content being tipped ("message", "post", "comment").
        content_id: Unique ID of the tipped content item.
        payment_method_id: Optional PM used for the tip.
        tip_payment_id: Unique tip transaction ID. Auto-generated if not provided.
        extra_meta: Additional metadata to include in both ledger entries.
    """

    def __init__(
        self,
        *,
        tipper_user_id: str,
        recipient_user_id: str,
        amount_cents: int,
        currency: str = "USD",
        content_type: str,
        content_id: str,
        payment_method_id: Optional[str] = None,
        tip_payment_id: Optional[str] = None,
        extra_meta: Optional[Dict[str, Any]] = None,
    ):
        if amount_cents <= 0:
            raise ValueError("amount_cents must be > 0")
        if content_type not in ("message", "post", "comment", "broadcast"):
            raise ValueError(f"Invalid content_type: {content_type}")
        self.tipper_user_id = tipper_user_id
        self.recipient_user_id = recipient_user_id
        self.amount_cents = amount_cents
        self.currency = currency
        self.content_type = content_type
        self.content_id = content_id
        self.payment_method_id = payment_method_id
        self.tip_payment_id = tip_payment_id or f"tip_{uuid.uuid4().hex}"
        self.extra_meta = extra_meta or {}


def _reason_for_content_type(content_type: str) -> str:
    """Map content type to a standardized reason string."""
    return {
        "message": "Tip: message",
        "post": "Tip: post",
        "comment": "Tip: comment",
        "broadcast": "Tip: broadcast",
    }.get(content_type, f"Tip: {content_type}")


def _build_meta(entry: TipLedgerEntry) -> Dict[str, Any]:
    """Build the unified metadata dict for a tip ledger entry."""
    meta: Dict[str, Any] = {
        "content_type": entry.content_type,
        "content_id": entry.content_id,
        "tipper_user_id": entry.tipper_user_id,
        "recipient_user_id": entry.recipient_user_id,
        "tip_payment_id": entry.tip_payment_id,
    }
    if entry.payment_method_id:
        meta["payment_method_id"] = entry.payment_method_id
    meta.update(entry.extra_meta)
    return meta


def write_tip_ledger(entry: TipLedgerEntry) -> Dict[str, str]:
    """Write paired debit + credit ledger entries for a tip.

    Writes two items to T.billing:
      1. DEBIT under USER#{tipper_user_id}
      2. CREDIT under USER#{recipient_user_id}

    Both writes are best-effort -- failure does not propagate to the caller.

    Returns:
        Dict with "debit_entry_id" and "credit_entry_id" keys.
    """
    # FIN-011: if the tipped content is assigned to an active collaboration,
    # split the revenue per the agreement instead of crediting a single creator.
    if entry.content_id:
        try:
            from app.services.collaboration_revenue import maybe_split_content_revenue

            split_record = maybe_split_content_revenue(
                content_id=entry.content_id,
                amount_cents=entry.amount_cents,
                source="tip",
                payer_user_id=entry.tipper_user_id,
                content_type=entry.content_type,
                currency=entry.currency,
            )
            if split_record is not None:
                # Collaboration split wrote its own paired ledger entries.
                return {
                    "debit_entry_id": "",
                    "credit_entry_id": "",
                    "collaboration_split_id": split_record.get("split_id", ""),
                }
        except Exception:
            logger.warning("collaboration split check failed; falling back to single credit", exc_info=True)

    ts = now_ts()
    debit_id = uuid.uuid4().hex
    credit_id = uuid.uuid4().hex
    reason = _reason_for_content_type(entry.content_type)
    meta = _build_meta(entry)

    result = {"debit_entry_id": debit_id, "credit_entry_id": credit_id}

    # 1. Write debit entry (charge to tipper)
    try:
        T.billing.put_item(Item={
            "pk": f"USER#{entry.tipper_user_id}",
            "sk": f"LEDGER#{ts}#{debit_id}",
            "entry_id": debit_id,
            "ts": ts,
            "type": "debit",
            "amount_cents": entry.amount_cents,
            "currency": entry.currency,
            "state": "settled",
            "reason": reason,
            "meta": meta,
        })
    except Exception:
        logger.warning(
            "tip_ledger_debit_write_failed",
            extra={"tipper": entry.tipper_user_id, "content_type": entry.content_type,
                   "content_id": entry.content_id, "amount": entry.amount_cents},
        )

    # 2. Write credit entry (income to recipient)
    try:
        T.billing.put_item(Item={
            "pk": f"USER#{entry.recipient_user_id}",
            "sk": f"LEDGER#{ts}#{credit_id}",
            "entry_id": credit_id,
            "ts": ts,
            "type": "credit",
            "amount_cents": entry.amount_cents,
            "currency": entry.currency,
            "state": "settled",
            "reason": reason,
            "meta": meta,
        })
    except Exception:
        logger.warning(
            "tip_ledger_credit_write_failed",
            extra={"recipient": entry.recipient_user_id, "content_type": entry.content_type,
                   "content_id": entry.content_id, "amount": entry.amount_cents},
        )

    # GAP-0152: notify recipient's dashboard stream (best-effort, fire-and-forget).
    # The ledger write is the source of truth; SSE delivery failures must never
    # propagate to the caller. Lazy import guards against circular imports.
    try:
        from app.services.dashboard_sse import dashboard_sse_publish
        dashboard_sse_publish(
            entry.recipient_user_id,
            {
                "type": "earnings:update",
                "amount_cents": entry.amount_cents,
                "currency": entry.currency,
                "content_type": entry.content_type,
                "content_id": entry.content_id,
                "tip_payment_id": entry.tip_payment_id,
            },
        )
    except Exception:
        logger.warning("dashboard_sse_publish failed for tip", exc_info=True)

    return result
