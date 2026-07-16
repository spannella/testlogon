"""Tip billing ledger integration.

Writes paired debit/credit entries for every tip transaction.
All tipping surfaces funnel through app.services.tips.charge_tip, which either
writes these rows atomically (TIP-501 TransactWriteItems) or, for the
collaboration-split branch, falls back to write_tip_ledger below.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any, Dict, Optional, Tuple

from app.core.tables import T
from app.core.time import now_ts
from app.services.billing_config import split_fee

logger = logging.getLogger(__name__)

_VALID_CONTENT_TYPES = (
    "message", "post", "comment", "broadcast", "video",
    "message_react", "post_react", "video_comment", "profile",
)


class TipLedgerEntry:
    """Data required to write a tip ledger entry pair.

    Attributes:
        tipper_user_id: The user sending the tip (debited).
        recipient_user_id: The user receiving the tip (credited).
        amount_cents: Tip amount in cents. Must be > 0.
        currency: ISO 4217 currency code (default "USD").
        content_type: Type of content being tipped.
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
        if content_type not in _VALID_CONTENT_TYPES:
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
        "video": "Tip: video",
        "message_react": "Tip: message reaction",
        "post_react": "Tip: post reaction",
        "video_comment": "Tip: video comment",
        "profile": "Tip: creator",
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


def maybe_collaboration_split(entry: TipLedgerEntry) -> Optional[Dict[str, str]]:
    """FIN-011: if the tipped content is assigned to an active collaboration,
    split the revenue per the agreement instead of crediting a single creator.

    Returns the split-ids dict when a split was written (the caller must NOT then
    write the single debit/credit pair), or None to proceed with the normal pair.
    Best-effort: any failure falls back to the single-credit path (returns None).
    """
    if not entry.content_id:
        return None
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
            return {
                "debit_entry_id": "",
                "credit_entry_id": "",
                "collaboration_split_id": split_record.get("split_id", ""),
            }
    except Exception:
        logger.warning("collaboration split check failed; falling back to single credit", exc_info=True)
    return None


def build_tip_ledger_items(entry: TipLedgerEntry) -> Tuple[Dict[str, Any], Dict[str, Any], Dict[str, str]]:
    """Build (but do NOT write) the paired debit + credit ledger item dicts.

    This is the SINGLE source of truth for the row shape shared by the legacy
    best-effort writer (write_tip_ledger) and the TIP-501 transactional writer in
    app.services.tips. The tipper is debited the full gross amount; the recipient
    is credited the net after the admin-configured platform fee (GAP-0214/FIN-018;
    net entry keeps type:"credit" -- ecom Bug#3). Debit and credit share the same
    ``ts`` so a pair is always co-timestamped.

    Returns (debit_item, credit_item, {"debit_entry_id", "credit_entry_id"}).
    """
    ts = now_ts()
    debit_id = uuid.uuid4().hex
    credit_id = uuid.uuid4().hex
    reason = _reason_for_content_type(entry.content_type)
    meta = _build_meta(entry)

    platform_fee_cents, net_cents, fee_bps = split_fee("tip_debit", entry.amount_cents)
    fee_meta = {"platform_fee_bps": fee_bps, "platform_fee_cents": platform_fee_cents}

    debit_item = {
        "pk": f"USER#{entry.tipper_user_id}",
        "sk": f"LEDGER#{ts}#{debit_id}",
        "entry_id": debit_id,
        "ts": ts,
        "type": "debit",
        "amount_cents": entry.amount_cents,
        "currency": entry.currency,
        "state": "settled",
        "reason": reason,
        "meta": {**meta, **fee_meta},
    }
    credit_item = {
        "pk": f"USER#{entry.recipient_user_id}",
        "sk": f"LEDGER#{ts}#{credit_id}",
        "entry_id": credit_id,
        "ts": ts,
        "type": "credit",
        "amount_cents": net_cents,
        "currency": entry.currency,
        "state": "settled",
        "reason": reason,
        "meta": {**meta, **fee_meta},
    }
    return debit_item, credit_item, {"debit_entry_id": debit_id, "credit_entry_id": credit_id}


def publish_tip_dashboard_sse(entry: TipLedgerEntry) -> None:
    """GAP-0152: notify the recipient's dashboard stream (best-effort, fire-and-forget).

    The ledger write is the source of truth; SSE delivery failures must never
    propagate to the caller.
    """
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


def write_tip_ledger(entry: TipLedgerEntry) -> Dict[str, str]:
    """Write paired debit + credit ledger entries for a tip (legacy best-effort).

    Retained for the collaboration-split fallback and any direct callers. The
    money-path (charge_tip) now writes the pair atomically via TransactWriteItems
    (TIP-501); this best-effort writer keeps an identical row shape via
    build_tip_ledger_items. Both writes are best-effort here -- failure does not
    propagate to the caller.

    Returns:
        Dict with "debit_entry_id" and "credit_entry_id" keys.
    """
    split = maybe_collaboration_split(entry)
    if split is not None:
        # Collaboration split wrote its own paired ledger entries.
        return split

    debit_item, credit_item, ids = build_tip_ledger_items(entry)

    # 1. Write debit entry (charge to tipper -- full gross amount)
    try:
        T.billing.put_item(Item=debit_item)
    except Exception:
        logger.warning(
            "tip_ledger_debit_write_failed",
            extra={"tipper": entry.tipper_user_id, "content_type": entry.content_type,
                   "content_id": entry.content_id, "amount": entry.amount_cents},
        )

    # 2. Write credit entry (income to recipient -- net after platform fee)
    try:
        T.billing.put_item(Item=credit_item)
    except Exception:
        logger.warning(
            "tip_ledger_credit_write_failed",
            extra={"recipient": entry.recipient_user_id, "content_type": entry.content_type,
                   "content_id": entry.content_id, "amount": entry.amount_cents},
        )

    publish_tip_dashboard_sse(entry)
    return ids
