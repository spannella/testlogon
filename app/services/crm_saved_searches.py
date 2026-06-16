"""RPT-008 — Saved searches as dashlets.

CRUD + run for saved search records stored in T.crm_saved_searches.
The _fetch_and_filter helper from crm_reports is reused for execution.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional, Tuple
from uuid import uuid4

from boto3.dynamodb.conditions import Key
from fastapi import HTTPException

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.core.cursor import encode_cursor, decode_cursor
from app.services.alerts import audit_event

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _item_to_out(item: Dict[str, Any]) -> Dict[str, Any]:
    from app.models import ReportCondition
    filters_raw = item.get("filters", "[]")
    if isinstance(filters_raw, str):
        filters = [ReportCondition(**c) for c in json.loads(filters_raw)]
    else:
        filters = [ReportCondition(**c) for c in list(filters_raw)]
    return {
        "saved_search_id": item["saved_search_id"],
        "name": item["name"],
        "module": item["module"],
        "filters": [f.model_dump() for f in filters],
        "owner_sub": item["owner_sub"],
        "created_at": int(item["created_at"]),
        "updated_at": int(item.get("updated_at", item["created_at"])),
    }


# ---------------------------------------------------------------------------
# CRUD
# ---------------------------------------------------------------------------

def create_saved_search(owner_sub: str, payload: Any) -> Dict[str, Any]:

    saved_search_id = f"SS#{uuid4().hex[:12]}"
    now = now_ts()
    filters = getattr(payload, "filters", []) or []
    item: Dict[str, Any] = {
        "saved_search_id": saved_search_id,
        "sk": "META",
        "GSI1PK": f"OWNER#{owner_sub}",
        "GSI1SK": now,
        "owner_sub": owner_sub,
        "name": payload.name,
        "module": payload.module,
        "filters": json.dumps([f.model_dump() for f in filters]),
        "created_at": now,
        "updated_at": now,
    }
    T.crm_saved_searches.put_item(Item=item)
    try:
        audit_event("saved_search.created", owner_sub, None, saved_search_id=saved_search_id, module=payload.module)
    except Exception:
        pass
    return _item_to_out(item)


def list_saved_searches(owner_sub: str, cursor: Optional[str] = None) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    kwargs: Dict[str, Any] = {
        "IndexName": "owner-searches-index",
        "KeyConditionExpression": Key("GSI1PK").eq(f"OWNER#{owner_sub}"),
        "ScanIndexForward": False,
        "Limit": 50,
    }
    lek = decode_cursor(cursor)
    if lek:
        kwargs["ExclusiveStartKey"] = lek
    resp = T.crm_saved_searches.query(**kwargs)
    items = resp.get("Items", [])
    next_cursor = encode_cursor(resp.get("LastEvaluatedKey"))
    return ([_item_to_out(i) for i in items], next_cursor)


def get_saved_search(saved_search_id: str, owner_sub: str) -> Dict[str, Any]:
    resp = T.crm_saved_searches.get_item(Key={"saved_search_id": saved_search_id, "sk": "META"})
    item = resp.get("Item")
    if not item:
        raise HTTPException(status_code=404, detail="Saved search not found")
    if item.get("owner_sub") != owner_sub:
        raise HTTPException(status_code=403, detail="Forbidden")
    return _item_to_out(item)


def update_saved_search(saved_search_id: str, owner_sub: str, patch: Any) -> Dict[str, Any]:

    get_saved_search(saved_search_id, owner_sub)  # ownership check

    update_parts = ["updated_at = :upd"]
    expr_vals: Dict[str, Any] = {":upd": now_ts(), ":sub": owner_sub}
    expr_names: Dict[str, str] = {}

    name = getattr(patch, "name", None)
    if name is not None:
        update_parts.append("#nm = :nm")
        expr_names["#nm"] = "name"
        expr_vals[":nm"] = name

    filters = getattr(patch, "filters", None)
    if filters is not None:
        update_parts.append("filters = :fil")
        expr_vals[":fil"] = json.dumps([f.model_dump() for f in filters])

    T.crm_saved_searches.update_item(
        Key={"saved_search_id": saved_search_id, "sk": "META"},
        UpdateExpression="SET " + ", ".join(update_parts),
        ExpressionAttributeNames=expr_names if expr_names else None,
        ExpressionAttributeValues=expr_vals,
        ConditionExpression="owner_sub = :sub",
    )
    try:
        audit_event("saved_search.updated", owner_sub, None, saved_search_id=saved_search_id)
    except Exception:
        pass
    return get_saved_search(saved_search_id, owner_sub)


def delete_saved_search(saved_search_id: str, owner_sub: str) -> None:

    item_out = get_saved_search(saved_search_id, owner_sub)  # ownership check

    try:
        T.crm_saved_searches.delete_item(
            Key={"saved_search_id": saved_search_id, "sk": "META"},
            ConditionExpression="owner_sub = :sub",
            ExpressionAttributeValues={":sub": owner_sub},
        )
    except T.crm_saved_searches.meta.client.exceptions.ConditionalCheckFailedException:
        raise HTTPException(status_code=404, detail="Saved search not found or already deleted")

    try:
        audit_event("saved_search.deleted", owner_sub, None, saved_search_id=saved_search_id)
    except Exception:
        pass


def run_saved_search(saved_search_id: str, owner_sub: str) -> Dict[str, Any]:
    from app.services.crm_reports import _fetch_and_filter, _eval_condition
    from app.models import ReportCondition

    ss_out = get_saved_search(saved_search_id, owner_sub)  # ownership check

    module = ss_out["module"]
    conditions_raw = ss_out["filters"]
    conditions = [ReportCondition(**c) for c in conditions_raw]

    max_rows = S.crm_saved_search_run_max_rows
    raw_rows = _fetch_and_filter(module, conditions, owner_sub, max_rows=max_rows)
    rows = raw_rows[:max_rows]

    # Derive columns from the union of keys across all rows, sorted
    all_keys: set = set()
    for r in rows:
        all_keys.update(r.keys())
    columns = sorted(all_keys)

    ran_at = now_ts()

    try:
        audit_event("saved_search.run", owner_sub, None, saved_search_id=saved_search_id, row_count=len(rows))
    except Exception:
        pass

    return {
        "saved_search_id": saved_search_id,
        "module": module,
        "columns": columns,
        "rows": rows,
        "row_count": len(rows),
        "ran_at": ran_at,
    }
