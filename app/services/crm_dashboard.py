"""RPT-006 — Per-user configurable home dashboard with dashlets.

Dashboard state lives in a single DynamoDB item on T.crm_dashboards:
  PK = DASH#{user_sub}#default
  SK = META

Dashlets are stored as a JSON list attribute on the item.
"""
from __future__ import annotations

import json
import logging
from decimal import Decimal
from typing import Any, Dict, List, Optional
from uuid import uuid4

from boto3.dynamodb.conditions import Attr
from fastapi import HTTPException

from app.core.tables import T
from app.core.time import now_ts
from app.services.alerts import audit_event

logger = logging.getLogger(__name__)

MAX_DASHLETS_PER_DASHBOARD = 20

VALID_DASHLET_TYPES = frozenset({
    "recent_tickets", "calendar_today", "my_contacts",
    "billing_summary", "report", "saved_search",
})


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _dashboard_id(user_sub: str) -> str:
    return f"DASH#{user_sub}#default"


def _coerce_decimals(obj: Any) -> Any:
    """Recursively convert Decimal to int or float."""
    if isinstance(obj, Decimal):
        i = int(obj)
        return i if obj == i else float(obj)
    if isinstance(obj, dict):
        return {k: _coerce_decimals(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_coerce_decimals(v) for v in obj]
    return obj


def _item_to_out(item: Dict[str, Any]) -> Dict[str, Any]:
    dashlets_raw = item.get("dashlets", "[]")
    if isinstance(dashlets_raw, str):
        dashlets = json.loads(dashlets_raw)
    else:
        dashlets = list(dashlets_raw)
    dashlets = [_coerce_decimals(d) for d in dashlets]
    return {
        "dashboard_id": item["dashboard_id"],
        "name": item.get("name", "Home"),
        "owner_sub": item["owner_sub"],
        "dashlets": dashlets,
        "created_at": int(item["created_at"]),
        "updated_at": int(item["updated_at"]),
    }


def _read_item(user_sub: str) -> Optional[Dict[str, Any]]:
    resp = T.crm_dashboards.get_item(Key={"dashboard_id": _dashboard_id(user_sub), "sk": "META"})
    return resp.get("Item")


# ---------------------------------------------------------------------------
# Public service functions
# ---------------------------------------------------------------------------

def get_or_create_default_dashboard(user_sub: str) -> Dict[str, Any]:
    """Return the default dashboard, creating it on first access."""
    item = _read_item(user_sub)
    if item:
        return _item_to_out(item)

    now = now_ts()
    new_item: Dict[str, Any] = {
        "dashboard_id": _dashboard_id(user_sub),
        "sk": "META",
        "GSI1PK": f"OWNER#{user_sub}",
        "GSI1SK": now,
        "owner_sub": user_sub,
        "name": "Home",
        "dashlets": json.dumps([]),
        "created_at": now,
        "updated_at": now,
    }
    try:
        T.crm_dashboards.put_item(
            Item=new_item,
            ConditionExpression=Attr("dashboard_id").not_exists(),
        )
    except T.crm_dashboards.meta.client.exceptions.ConditionalCheckFailedException:
        # Race: another request created it first
        item = _read_item(user_sub)
        if item:
            return _item_to_out(item)
    except Exception:
        # Fall back to reading in case of other errors
        item = _read_item(user_sub)
        if item:
            return _item_to_out(item)

    return _item_to_out(new_item)


def add_dashlet(user_sub: str, payload: Any) -> Dict[str, Any]:

    dash = get_or_create_default_dashboard(user_sub)
    current = list(dash["dashlets"])
    if len(current) >= MAX_DASHLETS_PER_DASHBOARD:
        raise HTTPException(status_code=422, detail="Maximum 20 dashlets per dashboard")

    dtype = getattr(payload, "dashlet_type", None) or (payload.get("dashlet_type") if isinstance(payload, dict) else None)
    if dtype not in VALID_DASHLET_TYPES:
        raise HTTPException(status_code=422, detail=f"Unknown dashlet_type: {dtype}")

    dashlet_id = f"dlt_{uuid4().hex[:8]}"
    title = getattr(payload, "title", None) or (payload.get("title") if isinstance(payload, dict) else "")
    config = getattr(payload, "config", {}) or (payload.get("config", {}) if isinstance(payload, dict) else {})

    new_dashlet = {
        "dashlet_id": dashlet_id,
        "dashlet_type": dtype,
        "title": title,
        "config": config,
    }
    current.append(new_dashlet)

    now = now_ts()
    T.crm_dashboards.update_item(
        Key={"dashboard_id": _dashboard_id(user_sub), "sk": "META"},
        UpdateExpression="SET dashlets = :d, updated_at = :t",
        ExpressionAttributeValues={":d": json.dumps(current), ":t": now},
    )

    try:
        audit_event("crm_dashboard.dashlet_added", user_sub, None, dashlet_id=dashlet_id, dashlet_type=dtype)
    except Exception:
        pass

    dash["dashlets"] = current
    dash["updated_at"] = now
    return dash


def remove_dashlet(user_sub: str, dashlet_id: str) -> Dict[str, Any]:

    dash = get_or_create_default_dashboard(user_sub)
    current = list(dash["dashlets"])
    new_list = [d for d in current if d.get("dashlet_id") != dashlet_id]
    if len(new_list) == len(current):
        raise HTTPException(status_code=404, detail="Dashlet not found")

    now = now_ts()
    T.crm_dashboards.update_item(
        Key={"dashboard_id": _dashboard_id(user_sub), "sk": "META"},
        UpdateExpression="SET dashlets = :d, updated_at = :t",
        ExpressionAttributeValues={":d": json.dumps(new_list), ":t": now},
    )

    try:
        audit_event("crm_dashboard.dashlet_removed", user_sub, None, dashlet_id=dashlet_id)
    except Exception:
        pass

    dash["dashlets"] = new_list
    dash["updated_at"] = now
    return dash


def reorder_dashlets(user_sub: str, ordered_dashlet_ids: List[str]) -> Dict[str, Any]:

    dash = get_or_create_default_dashboard(user_sub)
    current = list(dash["dashlets"])
    current_ids = {d["dashlet_id"] for d in current}

    if set(ordered_dashlet_ids) != current_ids or len(ordered_dashlet_ids) != len(current_ids):
        raise HTTPException(status_code=422, detail="dashlet_ids must be a permutation of the current dashlet IDs")

    id_to_dashlet = {d["dashlet_id"]: d for d in current}
    new_list = [id_to_dashlet[did] for did in ordered_dashlet_ids]

    now = now_ts()
    T.crm_dashboards.update_item(
        Key={"dashboard_id": _dashboard_id(user_sub), "sk": "META"},
        UpdateExpression="SET dashlets = :d, updated_at = :t",
        ExpressionAttributeValues={":d": json.dumps(new_list), ":t": now},
    )

    try:
        audit_event("crm_dashboard.reordered", user_sub, None)
    except Exception:
        pass

    dash["dashlets"] = new_list
    dash["updated_at"] = now
    return dash


def update_dashboard(user_sub: str, patch: Any) -> Dict[str, Any]:

    dash = get_or_create_default_dashboard(user_sub)
    update_parts = ["updated_at = :t"]
    expr_vals: Dict[str, Any] = {":t": now_ts()}

    name = getattr(patch, "name", None) or (patch.get("name") if isinstance(patch, dict) else None)
    if name is not None:
        update_parts.append("#nm = :nm")
        expr_vals[":nm"] = name

    dashlets = getattr(patch, "dashlets", None) or (patch.get("dashlets") if isinstance(patch, dict) else None)
    if dashlets is not None:
        if len(dashlets) > MAX_DASHLETS_PER_DASHBOARD:
            raise HTTPException(status_code=422, detail="Maximum 20 dashlets per dashboard")
        current = list(dash["dashlets"])
        new_list = []
        for i, d in enumerate(dashlets):
            dtype = getattr(d, "dashlet_type", None) or (d.get("dashlet_type") if isinstance(d, dict) else None)
            if dtype not in VALID_DASHLET_TYPES:
                raise HTTPException(status_code=422, detail=f"Unknown dashlet_type: {dtype}")
            # Preserve existing dashlet_id by position if available
            if i < len(current):
                did = current[i]["dashlet_id"]
            else:
                did = f"dlt_{uuid4().hex[:8]}"
            title = getattr(d, "title", None) or (d.get("title") if isinstance(d, dict) else "")
            config = getattr(d, "config", {}) or (d.get("config", {}) if isinstance(d, dict) else {})
            new_list.append({"dashlet_id": did, "dashlet_type": dtype, "title": title, "config": config})
        update_parts.append("dashlets = :d")
        expr_vals[":d"] = json.dumps(new_list)

    expr_names = {}
    if ":nm" in expr_vals:
        expr_names["#nm"] = "name"

    T.crm_dashboards.update_item(
        Key={"dashboard_id": _dashboard_id(user_sub), "sk": "META"},
        UpdateExpression="SET " + ", ".join(update_parts),
        ExpressionAttributeNames=expr_names if expr_names else None,
        ExpressionAttributeValues=expr_vals,
    )

    try:
        audit_event("crm_dashboard.updated", user_sub, None)
    except Exception:
        pass

    return get_or_create_default_dashboard(user_sub)
