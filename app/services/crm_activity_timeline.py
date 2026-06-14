"""
ACT-009 — CRM Activity History Timeline service.

Central write target for all ACT modules (calls, tasks, notes, calendar events).
Separate from the social activity_feed (app/services/activity_feed.py) which is a
per-user social stream; this table is a per-CRM-entity chronological feed.

Table: crm_activity_timeline
  PK = entity_key  = "{entity_type}#{entity_id}"
  SK = "{inverted_ts:013d}#{activity_type}#{activity_id}"
  GSI ByType: PK=GSI1PK="TYPE#{activity_type}", SK=GSI1SK=created_at (N)
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Key

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.core.cursor import encode_cursor, decode_cursor

logger = logging.getLogger(__name__)

_INVERTED_MAX = 9_999_999_999_999


def record_crm_activity(
    entity_type: str,
    entity_id: str,
    activity_type: str,
    activity_id: str,
    user_sub: str,
    *,
    summary: str = "",
    metadata: Optional[Dict[str, Any]] = None,
) -> None:
    """Write a timeline entry. No-op when CRM timeline is disabled. Never raises."""
    try:
        if not (S.crm_activities_enabled and S.crm_activity_timeline_enabled):
            return
        ts = now_ts()
        inverted = _INVERTED_MAX - ts
        entity_key = f"{entity_type}#{entity_id}"
        sk = f"{inverted:013d}#{activity_type}#{activity_id}"
        item: Dict[str, Any] = {
            "entity_key": entity_key,
            "sk": sk,
            "entity_type": entity_type,
            "entity_id": entity_id,
            "activity_type": activity_type,
            "activity_id": activity_id,
            "user_sub": user_sub,
            "summary": summary[:200] if summary else "",
            "metadata": metadata or {},
            "created_at": ts,
            # GSI ByType
            "GSI1PK": f"TYPE#{activity_type}",
            "GSI1SK": ts,
        }
        T.crm_activity_timeline.put_item(Item=item)
    except Exception:
        logger.warning("record_crm_activity failed", exc_info=True)


def list_entity_activities(
    entity_type: str,
    entity_id: str,
    limit: int = 20,
    cursor: Optional[str] = None,
    activity_type_filter: Optional[str] = None,
) -> Dict[str, Any]:
    """List timeline entries for a CRM entity, newest first."""
    entity_key = f"{entity_type}#{entity_id}"
    kw: Dict[str, Any] = dict(
        KeyConditionExpression=Key("entity_key").eq(entity_key),
        ScanIndexForward=True,  # inverted sk → newest first
        Limit=limit,
    )
    if activity_type_filter:
        from boto3.dynamodb.conditions import Attr
        kw["FilterExpression"] = Attr("activity_type").eq(activity_type_filter)
    if cursor:
        kw["ExclusiveStartKey"] = decode_cursor(cursor)
    resp = T.crm_activity_timeline.query(**kw)
    items = resp.get("Items", [])
    lek = resp.get("LastEvaluatedKey")
    return {
        "entity_type": entity_type,
        "entity_id": entity_id,
        "items": [_item_to_out(i) for i in items],
        "next_cursor": encode_cursor(lek) if lek else None,
    }


def delete_entity_activity(entity_type: str, entity_id: str, sk: str, user_sub: str) -> bool:
    """Hard-delete a single timeline row. Returns True if deleted."""
    entity_key = f"{entity_type}#{entity_id}"
    existing = T.crm_activity_timeline.get_item(
        Key={"entity_key": entity_key, "sk": sk}
    ).get("Item")
    if not existing:
        return False
    T.crm_activity_timeline.delete_item(Key={"entity_key": entity_key, "sk": sk})
    try:
        from app.services.alerts import audit_event
        audit_event(
            "crm_timeline_delete",
            user_sub,
            None,
            entity_key=entity_key,
            sk=sk,
        )
    except Exception:
        pass
    return True


def _item_to_out(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "activity_id": item.get("activity_id", ""),
        "entity_type": item.get("entity_type", ""),
        "entity_id": item.get("entity_id", ""),
        "activity_type": item.get("activity_type", ""),
        "user_sub": item.get("user_sub", ""),
        "summary": item.get("summary", ""),
        "metadata": item.get("metadata", {}),
        "created_at": int(item.get("created_at", 0)),
    }
