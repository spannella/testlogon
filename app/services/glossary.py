"""PLT-003: Glossary service — DDB-backed admin-editable term/definition dictionary."""
from __future__ import annotations

import uuid
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Attr, Key
from fastapi import HTTPException

from app.core.cursor import decode_cursor, encode_cursor
from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

_GSI_PK_VALUE = "GLOSSARY#ALL"
_TERM_ID_PREFIX = "gloss_"


def _new_term_id() -> str:
    return f"{_TERM_ID_PREFIX}{uuid.uuid4().hex[:12]}"


def list_glossary(
    *,
    search: Optional[str] = None,
    cursor: Optional[str] = None,
    limit: int = 100,
) -> Dict[str, Any]:
    """Return a page of glossary terms ordered alphabetically (GSI_BY_TERM)."""
    lek = decode_cursor(cursor) if cursor else None
    limit = max(1, min(int(limit or 100), 500))
    kwargs: Dict[str, Any] = {
        "IndexName": "GSI_BY_TERM",
        "KeyConditionExpression": Key("GSI1PK").eq(_GSI_PK_VALUE),
        "ScanIndexForward": True,
        "Limit": limit,
    }
    if search:
        # Filter on GSI1SK (lowercased term) for case-insensitive substring match
        kwargs["FilterExpression"] = Attr("GSI1SK").contains(search.strip().lower())
    if lek:
        kwargs["ExclusiveStartKey"] = lek

    try:
        resp = T.glossary.query(**kwargs)
    except Exception:
        return {"terms": [], "next_cursor": None, "count": 0}

    items = resp.get("Items") or []
    next_lek = resp.get("LastEvaluatedKey")
    return {
        "terms": [_item_to_out(it) for it in items],
        "next_cursor": encode_cursor(next_lek) if next_lek else None,
        "count": len(items),
    }


def get_glossary_term(term_id: str) -> Optional[Dict[str, Any]]:
    """Fetch a single term by its term_id. Returns None if absent."""
    try:
        resp = T.glossary.get_item(Key={"term_id": term_id})
        item = resp.get("Item")
        if not item:
            return None
        return _item_to_out(item)
    except Exception:
        return None


def upsert_glossary_term(
    *,
    term: str,
    definition: str,
    tags: Optional[List[str]] = None,
    term_id: Optional[str] = None,
    updated_by: str,
) -> Dict[str, Any]:
    """Create (term_id=None) or replace (term_id supplied) a glossary entry."""
    max_chars = int(getattr(S, "glossary_definition_max_chars", 4096) or 4096)
    if len(definition) > max_chars:
        raise HTTPException(422, f"definition exceeds maximum length ({max_chars} chars)")

    now = now_ts()
    is_create = term_id is None

    if is_create:
        new_id = _new_term_id()
        item: Dict[str, Any] = {
            "term_id": new_id,
            "term": term.strip(),
            "definition": definition,
            "tags": tags or [],
            "created_at": now,
            "updated_at": now,
            "updated_by": updated_by,
            "GSI1PK": _GSI_PK_VALUE,
            "GSI1SK": term.strip().lower(),
        }
        T.glossary.put_item(Item=item)
        return _item_to_out(item)
    else:
        # Update: fetch existing, merge, put_item
        existing = get_glossary_term(term_id)
        if existing is None:
            raise HTTPException(404, "term not found")
        item = {
            "term_id": term_id,
            "term": term.strip(),
            "definition": definition,
            "tags": tags if tags is not None else (existing.get("tags") or []),
            "created_at": existing["created_at"],
            "updated_at": now,
            "updated_by": updated_by,
            "GSI1PK": _GSI_PK_VALUE,
            "GSI1SK": term.strip().lower(),
        }
        T.glossary.put_item(Item=item)
        return _item_to_out(item)


def delete_glossary_term(term_id: str) -> bool:
    """Delete a term. Returns True if existed and deleted, False if absent."""
    try:
        resp = T.glossary.delete_item(
            Key={"term_id": term_id},
            ReturnValues="ALL_OLD",
        )
        return bool(resp.get("Attributes"))
    except Exception:
        return False


def _item_to_out(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "term_id": str(item.get("term_id") or ""),
        "term": str(item.get("term") or ""),
        "definition": str(item.get("definition") or ""),
        "tags": list(item.get("tags") or []),
        "created_at": int(item.get("created_at") or 0),
        "updated_at": int(item.get("updated_at") or 0),
        "updated_by": str(item.get("updated_by") or ""),
    }
