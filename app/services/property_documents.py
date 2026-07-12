"""PMD-002 — Property document link store (local implementation).

EVT-011 (file-manager CRM record-link) is not yet built.
This module provides a self-contained local store for linking
document metadata to property-domain records (property/unit/lease/tenant).

Storage layout (T.property_documents):
  pk  = "LINK#{record_type}#{record_id}"
  sk  = "DOC#{doc_id}"
  owner_sub = caller's user_sub (used by owner-index GSI for listing)

The owner-index GSI (pk=owner_sub, sk=sk) allows listing all
document links belonging to a caller without a full-table scan.

Sibling flag: PROPERTY_DASHBOARD_ENABLED gates all endpoints here.
"""
from __future__ import annotations

import uuid
from decimal import Decimal
from typing import Any, Dict, List, Optional, Tuple

from boto3.dynamodb.conditions import Key, Attr
from fastapi import HTTPException

from app.core.settings import S
from app.core.time import now_ts
from app.core.cursor import encode_cursor, decode_cursor

_VALID_RECORD_TYPES: frozenset[str] = frozenset({
    "property", "unit", "lease", "tenant",
})


def _flag_on() -> bool:
    return bool(getattr(S, "property_dashboard_enabled", False))


def _require_enabled() -> None:
    if not _flag_on():
        raise HTTPException(status_code=404, detail="Property dashboard is not enabled")


def _link_pk(record_type: str, record_id: str) -> str:
    return f"LINK#{record_type}#{record_id}"


def _doc_sk(doc_id: str) -> str:
    return f"DOC#{doc_id}"


def _audit(event: str, user_sub: str, **fields: Any) -> None:
    try:
        from app.services.alerts import audit_event
        audit_event(event, user_sub or "system", None, **fields)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Public service functions
# ---------------------------------------------------------------------------

def link_document(
    owner_sub: str,
    *,
    record_type: str,
    record_id: str,
    doc_id: str,
    file_path: str = "",
    crm_category: str = "",
    crm_description: str = "",
) -> Dict[str, Any]:
    """Create or replace a document link for a property-domain record.

    Returns the stored link item.
    """
    _require_enabled()
    if record_type not in _VALID_RECORD_TYPES:
        raise HTTPException(
            status_code=400,
            detail={
                "code": "invalid_record_type",
                "message": f"record_type must be one of {sorted(_VALID_RECORD_TYPES)}",
            },
        )

    from app.core.tables import T

    now = now_ts()
    item: Dict[str, Any] = {
        "pk":              _link_pk(record_type, record_id),
        "sk":              _doc_sk(doc_id),
        "owner_sub":       str(owner_sub),
        "record_type":     str(record_type),
        "record_id":       str(record_id),
        "doc_id":          str(doc_id),
        "file_path":       str(file_path),
        "crm_category":    str(crm_category),
        "crm_description": str(crm_description),
        "linked_at":       Decimal(str(now)),
    }
    T.property_documents.put_item(Item=item)
    _audit(
        "property_document.linked", owner_sub,
        record_type=record_type, record_id=record_id, doc_id=doc_id,
    )
    return _item_to_out(item)


def unlink_document(
    owner_sub: str,
    *,
    record_type: str,
    record_id: str,
    doc_id: str,
) -> bool:
    """Remove a document link. Returns True if found+deleted, False if not found."""
    _require_enabled()
    from app.core.tables import T

    pk = _link_pk(record_type, record_id)
    sk = _doc_sk(doc_id)
    # Enforce ownership before deleting
    resp = T.property_documents.get_item(Key={"pk": pk, "sk": sk})
    item = resp.get("Item")
    if item is None:
        return False
    if item.get("owner_sub") != owner_sub:
        raise HTTPException(status_code=403, detail="not found")

    T.property_documents.delete_item(Key={"pk": pk, "sk": sk})
    _audit(
        "property_document.unlinked", owner_sub,
        record_type=record_type, record_id=record_id, doc_id=doc_id,
    )
    return True


def list_documents(
    owner_sub: str,
    *,
    record_type: str,
    record_id: str,
    limit: int = 50,
    cursor: Optional[str] = None,
) -> Dict[str, Any]:
    """List document links for a specific record, scoped to owner_sub.

    Uses a query on the main table (pk = LINK#{type}#{id}) with a
    FilterExpression on owner_sub for cross-user isolation.
    DynamoDB FilterExpression does not reduce page size — we loop via
    LastEvaluatedKey to gather up to `limit` qualifying items.
    """
    _require_enabled()
    if record_type not in _VALID_RECORD_TYPES:
        raise HTTPException(
            status_code=400,
            detail={"code": "invalid_record_type", "message": "unknown record_type"},
        )

    from app.core.tables import T

    limit = max(1, min(int(limit), 200))
    pk = _link_pk(record_type, record_id)

    kwargs: Dict[str, Any] = {
        "KeyConditionExpression": Key("pk").eq(pk),
        "FilterExpression": Attr("owner_sub").eq(owner_sub),
        "Limit": limit,
    }
    decoded = decode_cursor(cursor) if cursor else None
    if decoded:
        kwargs["ExclusiveStartKey"] = decoded

    results: List[Dict[str, Any]] = []
    scans = 0
    last_lek: Optional[Dict[str, Any]] = None

    while len(results) < limit and scans < 20:
        resp = T.property_documents.query(**kwargs)
        for item in resp.get("Items", []):
            if len(results) < limit:
                results.append(_item_to_out(item))
        lek = resp.get("LastEvaluatedKey")
        scans += 1
        if not lek:
            last_lek = None
            break
        last_lek = lek
        kwargs["ExclusiveStartKey"] = lek

    next_cursor = encode_cursor(last_lek) if last_lek and len(results) >= limit else None

    return {
        "items": results,
        "count": len(results),
        "cursor": next_cursor,
    }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _item_to_out(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "doc_id":          str(item.get("doc_id", "")),
        "record_type":     str(item.get("record_type", "")),
        "record_id":       str(item.get("record_id", "")),
        "file_path":       str(item.get("file_path", "")),
        "crm_category":    str(item.get("crm_category", "")),
        "crm_description": str(item.get("crm_description", "")),
        "linked_at":       int(item["linked_at"]) if item.get("linked_at") is not None else None,
        "owner_sub":       str(item.get("owner_sub", "")),
    }
