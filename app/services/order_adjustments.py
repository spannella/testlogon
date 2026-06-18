"""ORD-008 — order adjustments service.

Adjustments are additional line items attached to an order header that represent
discounts, surcharges, tax, or shipping costs.  They live in the same
``T.orders`` single-table as the order header and HIST rows, keyed by
``SK=ADJ#{adjustment_id}``.

Schema (per row)
----------------
  order_id         : str  — partition key (same table as header)
  sk               : str  — ``ADJ#{adjustment_id}``
  adjustment_id    : str  — deterministic sha256(f"{order_id}:{adj_type}:{description}")[:16]
  adj_type         : str  — "discount" | "surcharge" | "tax" | "shipping"
  description      : str
  amount_cents     : int  — signed: negative = discount, positive = surcharge/tax/shipping
  percentage       : float | None  — optional percentage representation
  created_at       : int  — Unix seconds
  created_by       : str  — actor sub

No ``S.dev_mode`` branch (SECOPS-007 parity).
"""
from __future__ import annotations

import hashlib
import logging
from decimal import Decimal
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Key
from fastapi import HTTPException

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)

_VALID_ADJ_TYPES = {"discount", "surcharge", "tax", "shipping"}

_ADJ_SK_PREFIX = "ADJ#"


# ── Guard ─────────────────────────────────────────────────────────────────────

def _require_lifecycle_enabled() -> None:
    if not S.order_lifecycle_enabled:
        raise HTTPException(
            status_code=501,
            detail={"code": "order_lifecycle_not_enabled", "message": "Order lifecycle is not enabled"},
        )


# ── ID derivation ─────────────────────────────────────────────────────────────

def _adjustment_id(order_id: str, adj_type: str, description: str) -> str:
    """Deterministic 16-hex-char id so the same adjustment is idempotent."""
    raw = f"{order_id}:{adj_type}:{description}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


# ── Core CRUD ─────────────────────────────────────────────────────────────────

def add_adjustment(
    order_id: str,
    adj_type: str,
    description: str,
    amount_cents: int,
    percentage: Optional[float] = None,
    actor_sub: str = "system",
) -> Dict[str, Any]:
    """Add (or idempotently re-add) an adjustment row.

    Parameters
    ----------
    order_id    : target order
    adj_type    : one of "discount", "surcharge", "tax", "shipping"
    description : human-readable label (also seeds the deterministic id)
    amount_cents: signed integer — negative for discounts, positive for charges
    percentage  : optional percentage (e.g. 8.5 for 8.5%)
    actor_sub   : sub of the actor writing the adjustment

    Returns the adjustment dict as stored.
    """
    _require_lifecycle_enabled()

    if adj_type not in _VALID_ADJ_TYPES:
        raise HTTPException(
            status_code=422,
            detail={
                "code": "invalid_adj_type",
                "message": f"adj_type must be one of {sorted(_VALID_ADJ_TYPES)}",
            },
        )

    adjustment_id = _adjustment_id(order_id, adj_type, description)
    ts = now_ts()

    item: Dict[str, Any] = {
        "order_id": order_id,
        "sk": f"{_ADJ_SK_PREFIX}{adjustment_id}",
        "adjustment_id": adjustment_id,
        "adj_type": adj_type,
        "description": description,
        "amount_cents": amount_cents,
        "created_at": ts,
        "created_by": actor_sub,
    }
    if percentage is not None:
        item["percentage"] = Decimal(str(percentage))

    T.orders.put_item(Item=item)
    return item


def list_adjustments(order_id: str) -> List[Dict[str, Any]]:
    """Return all ADJ# rows for the given order, sorted by created_at asc."""
    _require_lifecycle_enabled()

    resp = T.orders.query(
        KeyConditionExpression=Key("order_id").eq(order_id)
        & Key("sk").begins_with(_ADJ_SK_PREFIX),
    )
    rows = resp.get("Items", [])
    return sorted(rows, key=lambda r: int(r.get("created_at", 0)))


def remove_adjustment(order_id: str, adjustment_id: str) -> None:
    """Delete an ADJ# row.  No-op when the row is missing."""
    _require_lifecycle_enabled()

    T.orders.delete_item(
        Key={"order_id": order_id, "sk": f"{_ADJ_SK_PREFIX}{adjustment_id}"},
    )


def compute_order_total(order_id: str) -> Dict[str, Any]:
    """Return the computed total for an order.

    Reads the ORDER header for ``amount_cents`` (base sub-total of line items),
    sums all ADJ# adjustments (signed), and returns:

      base_amount_cents        : int  — from the ORDER header
      total_adjustments_cents  : int  — algebraic sum of all ADJ rows
      total_cents              : int  — base + adjustments
      adjustment_count         : int
    """
    _require_lifecycle_enabled()

    from app.services.order_store import get_order_header

    header = get_order_header(order_id)
    base = int(header.get("amount_cents", 0)) if header else 0

    adj_rows = list_adjustments(order_id)
    total_adj = sum(int(r.get("amount_cents", 0)) for r in adj_rows)

    return {
        "order_id": order_id,
        "base_amount_cents": base,
        "total_adjustments_cents": total_adj,
        "total_cents": base + total_adj,
        "adjustment_count": len(adj_rows),
    }
