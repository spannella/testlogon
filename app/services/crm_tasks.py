"""
ACT-008 — CRM Tasks service.

Table: crm_tasks
  PK = user_sub
  SK = TASK#{inverted_due_ts:013d}#{task_id}
  GSI ByStatus: GSI1PK=STATUS#{status}, GSI1SK=due_date_ts (N)
  GSI ByAssignee: GSI2PK=ASSIGNEE#{assignee_sub}, GSI2SK=due_date_ts (N)
"""
from __future__ import annotations

import logging
import uuid
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Attr, Key

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.core.cursor import encode_cursor, decode_cursor

logger = logging.getLogger(__name__)

_INVERTED_MAX = 9_999_999_999_999

_VALID_TRANSITIONS: Dict[str, set] = {
    "not_started": {"in_progress", "deferred", "waiting", "completed"},
    "in_progress":  {"not_started", "deferred", "waiting", "completed"},
    "deferred":     {"not_started", "in_progress", "waiting"},
    "waiting":      {"not_started", "in_progress", "deferred", "completed"},
    "completed":    {"not_started", "in_progress"},
}


def _make_sk(due_ts: Optional[int], created_at: int, task_id: str) -> str:
    base_ts = due_ts if due_ts is not None else created_at
    inverted = _INVERTED_MAX - base_ts
    return f"TASK#{inverted:013d}#{task_id}"


def _item_to_out(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "task_id": item["task_id"],
        "user_sub": item["user_sub"],
        "subject": item.get("subject", ""),
        "description": item.get("description", ""),
        "status": item.get("status", "not_started"),
        "priority": item.get("priority", "medium"),
        "due_date_ts": int(item["due_date_ts"]) if item.get("due_date_ts") is not None else None,
        "assignee_sub": item.get("assignee_sub"),
        "linked_entity_type": item.get("linked_entity_type"),
        "linked_entity_id": item.get("linked_entity_id"),
        "created_at": int(item.get("created_at", 0)),
        "updated_at": int(item.get("updated_at", 0)),
    }


def _maybe_record_timeline(item: Dict[str, Any], event: str) -> None:
    """Fire-and-forget timeline write (ACT-009 dependency; soft)."""
    entity_type = item.get("linked_entity_type")
    entity_id = item.get("linked_entity_id")
    if not (entity_type and entity_id):
        return
    try:
        from app.services.crm_activity_timeline import record_crm_activity
        record_crm_activity(
            entity_type=entity_type,
            entity_id=entity_id,
            activity_type="task",
            activity_id=item["task_id"],
            user_sub=item["user_sub"],
            summary=f"{event}: {item.get('subject', '')}",
            metadata={"status": item.get("status"), "priority": item.get("priority")},
        )
    except Exception:
        logger.warning("crm_activity_timeline unavailable; skipping", exc_info=True)


def create_task(
    user_sub: str,
    subject: str,
    description: str = "",
    status: str = "not_started",
    priority: str = "medium",
    due_date_ts: Optional[int] = None,
    assignee_sub: Optional[str] = None,
    linked_entity_type: Optional[str] = None,
    linked_entity_id: Optional[str] = None,
) -> Dict[str, Any]:
    ts = now_ts()
    task_id = uuid.uuid4().hex
    sk = _make_sk(due_date_ts, ts, task_id)
    gsi1sk = due_date_ts if due_date_ts is not None else ts
    item: Dict[str, Any] = {
        "user_sub": user_sub,
        "sk": sk,
        "task_id": task_id,
        "subject": subject,
        "description": description or "",
        "status": status,
        "priority": priority,
        "created_at": ts,
        "updated_at": ts,
        # GSI ByStatus
        "GSI1PK": f"STATUS#{status}",
        "GSI1SK": gsi1sk,
    }
    if due_date_ts is not None:
        item["due_date_ts"] = due_date_ts
    if assignee_sub:
        item["assignee_sub"] = assignee_sub
        item["GSI2PK"] = f"ASSIGNEE#{assignee_sub}"
        item["GSI2SK"] = gsi1sk
    if linked_entity_type:
        item["linked_entity_type"] = linked_entity_type
    if linked_entity_id:
        item["linked_entity_id"] = linked_entity_id
    T.crm_tasks.put_item(Item=item)
    _maybe_record_timeline(item, "task_created")
    return _item_to_out(item)


def list_tasks(
    user_sub: str,
    limit: int = 20,
    cursor: Optional[str] = None,
    status_filter: Optional[str] = None,
) -> Dict[str, Any]:
    kw: Dict[str, Any] = dict(
        KeyConditionExpression=Key("user_sub").eq(user_sub) & Key("sk").begins_with("TASK#"),
        ScanIndexForward=True,
        Limit=limit,
    )
    if status_filter:
        kw["FilterExpression"] = Attr("status").eq(status_filter)
    if cursor:
        kw["ExclusiveStartKey"] = decode_cursor(cursor)
    resp = T.crm_tasks.query(**kw)
    items = resp.get("Items", [])
    lek = resp.get("LastEvaluatedKey")
    return {
        "items": [_item_to_out(i) for i in items],
        "next_cursor": encode_cursor(lek) if lek else None,
        "count": len(items),
    }


def get_task(user_sub: str, task_id: str) -> Optional[Dict[str, Any]]:
    resp = T.crm_tasks.query(
        KeyConditionExpression=Key("user_sub").eq(user_sub) & Key("sk").begins_with("TASK#"),
        FilterExpression=Attr("task_id").eq(task_id),
    )
    items = resp.get("Items", [])
    if not items:
        return None
    return _item_to_out(items[0])


def _get_raw(user_sub: str, task_id: str) -> Optional[Dict[str, Any]]:
    resp = T.crm_tasks.query(
        KeyConditionExpression=Key("user_sub").eq(user_sub) & Key("sk").begins_with("TASK#"),
        FilterExpression=Attr("task_id").eq(task_id),
    )
    items = resp.get("Items", [])
    return items[0] if items else None


def update_task(
    user_sub: str,
    task_id: str,
    subject: Optional[str] = None,
    description: Optional[str] = None,
    status: Optional[str] = None,
    priority: Optional[str] = None,
    due_date_ts: Optional[int] = None,
    assignee_sub: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    existing = _get_raw(user_sub, task_id)
    if not existing:
        return None
    ts = now_ts()
    updated = {**existing, "updated_at": ts}
    if subject is not None:
        updated["subject"] = subject
    if description is not None:
        updated["description"] = description
    if status is not None:
        updated["status"] = status
        updated["GSI1PK"] = f"STATUS#{status}"
    if priority is not None:
        updated["priority"] = priority
    if due_date_ts is not None:
        updated["due_date_ts"] = due_date_ts
    gsi_sk = updated.get("due_date_ts") or ts
    updated["GSI1SK"] = gsi_sk
    if assignee_sub is not None:
        updated["assignee_sub"] = assignee_sub
        if assignee_sub:
            updated["GSI2PK"] = f"ASSIGNEE#{assignee_sub}"
            updated["GSI2SK"] = gsi_sk
        else:
            updated.pop("GSI2PK", None)
            updated.pop("GSI2SK", None)
    # Re-key SK if due_date changed (affects SK inversion)
    old_sk = existing["sk"]
    new_sk = _make_sk(updated.get("due_date_ts"), int(existing["created_at"]), task_id)
    if new_sk != old_sk:
        T.crm_tasks.delete_item(Key={"user_sub": user_sub, "sk": old_sk})
        updated["sk"] = new_sk
    T.crm_tasks.put_item(Item=updated)
    if status == "completed":
        _maybe_record_timeline(updated, "task_completed")
    else:
        _maybe_record_timeline(updated, "task_updated")
    return _item_to_out(updated)


def delete_task(user_sub: str, task_id: str) -> bool:
    existing = _get_raw(user_sub, task_id)
    if not existing:
        return False
    T.crm_tasks.delete_item(Key={"user_sub": user_sub, "sk": existing["sk"]})
    return True
