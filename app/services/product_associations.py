"""
OFBiz Catalog Depth — Product Associations service.
PRD-010: substitute / complement / upgrade / manufacture_source relationships.

Associations live on T.product_depth:
  PK: ASSOC#{from_item_id}
  SK: {assoc_type}#{to_item_id}   e.g. SUBSTITUTE#item_abc

All functions raise HTTPException on error so they compose with FastAPI.
"""

from __future__ import annotations

import hashlib
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Key
from fastapi import HTTPException

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_VALID_ASSOC_TYPES = {"substitute", "complement", "upgrade", "manufacture_source"}


# ---------------------------------------------------------------------------
# Flags
# ---------------------------------------------------------------------------

def _require_product_depth_enabled() -> None:
    """Raise 501 when product_depth feature flag is off."""
    if not bool(getattr(S, "product_depth_enabled", False)):
        raise HTTPException(status_code=501, detail="product_depth_not_enabled")


# ---------------------------------------------------------------------------
# Key helpers
# ---------------------------------------------------------------------------

def _assoc_pk(from_item_id: str) -> str:
    return f"ASSOC#{from_item_id}"


def _assoc_sk(assoc_type: str, to_item_id: str) -> str:
    return f"{assoc_type.upper()}#{to_item_id}"


def _assoc_id(from_item_id: str, assoc_type: str, to_item_id: str) -> str:
    """Deterministic 16-char hex id for an association triple."""
    return hashlib.sha256(
        f"{from_item_id}:{assoc_type}:{to_item_id}".encode()
    ).hexdigest()[:16]


# ---------------------------------------------------------------------------
# CRUD
# ---------------------------------------------------------------------------

def add_association(
    from_item_id: str,
    assoc_type: str,
    to_item_id: str,
) -> Dict[str, Any]:
    """Add a directed product association.

    Idempotent: the same (from, type, to) triple always produces the same
    assoc_id; a repeated call simply overwrites the row with a fresh
    updated_at (last-write-wins).

    Args:
        from_item_id: source product id.
        assoc_type:   one of substitute / complement / upgrade / manufacture_source.
        to_item_id:   target product id.

    Returns the written row dict.
    Raises HTTPException 422 for invalid assoc_type.
    Raises HTTPException 501 when product_depth feature flag is off.
    """
    _require_product_depth_enabled()

    if assoc_type not in _VALID_ASSOC_TYPES:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid assoc_type '{assoc_type}'. "
                   f"Valid values: {sorted(_VALID_ASSOC_TYPES)}.",
        )

    ts = now_ts()
    row: Dict[str, Any] = {
        "PK": _assoc_pk(from_item_id),
        "SK": _assoc_sk(assoc_type, to_item_id),
        "entity": "product_association",
        "assoc_id": _assoc_id(from_item_id, assoc_type, to_item_id),
        "from_item_id": from_item_id,
        "to_item_id": to_item_id,
        "assoc_type": assoc_type,
        "created_at": ts,
    }
    T.product_depth.put_item(Item=row)
    return row


def remove_association(
    from_item_id: str,
    assoc_type: str,
    to_item_id: str,
) -> None:
    """Delete an association row.  No-op if the row does not exist."""
    _require_product_depth_enabled()
    T.product_depth.delete_item(
        Key={
            "PK": _assoc_pk(from_item_id),
            "SK": _assoc_sk(assoc_type, to_item_id),
        }
    )


def list_associations(
    from_item_id: str,
    assoc_type: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Return all association rows originating from from_item_id.

    Args:
        from_item_id: source product.
        assoc_type:   optional filter; when provided only rows matching this
                      type are returned.

    Returns a list of association row dicts (may be empty).
    Raises HTTPException 501 when product_depth feature flag is off.
    """
    _require_product_depth_enabled()

    kwargs: Dict[str, Any] = {
        "KeyConditionExpression": Key("PK").eq(_assoc_pk(from_item_id)),
    }

    if assoc_type is not None:
        # Filter by SK prefix = assoc_type.upper() + "#"
        kwargs["KeyConditionExpression"] = (
            Key("PK").eq(_assoc_pk(from_item_id))
            & Key("SK").begins_with(f"{assoc_type.upper()}#")
        )

    resp = T.product_depth.query(**kwargs)
    return resp.get("Items", [])
