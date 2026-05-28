"""
Unified Content Scheduling -- DynamoDB CRUD + claim/completion helpers.

Table: scheduled_actions
  PK: USER#{user_sub}
  SK: ACTION#{scheduled_at}#{action_id}
  GSI ByDue: GSI_DUE_PK="DUE"  GSI_DUE_SK=scheduled_at (N)
  GSI ByType: GSI_TYPE_PK="USER#{user_sub}#TYPE#{action_type}"  GSI_TYPE_SK=scheduled_at (N)
"""
from __future__ import annotations

import logging
import uuid
from decimal import Decimal
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Attr, Key
from botocore.exceptions import ClientError

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _new_action_id() -> str:
    return "sa_" + uuid.uuid4().hex


def _pk(user_sub: str) -> str:
    return f"USER#{user_sub}"


def _sk(scheduled_at: int, action_id: str) -> str:
    return f"ACTION#{scheduled_at}#{action_id}"


def _gsi_type_pk(user_sub: str, action_type: str) -> str:
    return f"USER#{user_sub}#TYPE#{action_type}"


def _ttl_epoch(ts: int) -> int:
    return ts + S.scheduled_actions_ttl_days * 86400


def _action_out(item: Dict[str, Any]) -> Dict[str, Any]:
    """Convert a DDB item to the API-facing dict."""
    def _int(v):
        if v is None:
            return None
        return int(v) if isinstance(v, (Decimal, float)) else v

    payload_raw = item.get("payload") or {}
    # Convert Decimal values in payload to int/float
    payload = {}
    for k, v in payload_raw.items():
        if isinstance(v, Decimal):
            payload[k] = int(v) if v == int(v) else float(v)
        elif isinstance(v, list):
            payload[k] = [int(x) if isinstance(x, Decimal) and x == int(x) else (float(x) if isinstance(x, Decimal) else x) for x in v]
        else:
            payload[k] = v

    return {
        "action_id": item["action_id"],
        "action_type": item.get("action_type", ""),
        "status": item.get("status", ""),
        "scheduled_at": _int(item.get("scheduled_at", 0)),
        "created_at": _int(item.get("created_at", 0)),
        "updated_at": _int(item.get("updated_at")),
        "completed_at": _int(item.get("completed_at")),
        "title": item.get("title", ""),
        "description": item.get("description", ""),
        "payload": payload,
        "error": item.get("error"),
        "retry_count": _int(item.get("retry_count", 0)),
        "max_retries": _int(item.get("max_retries", S.scheduled_actions_max_retries)),
        "notify_before_seconds": _int(item.get("notify_before_seconds", 0)),
        "reminder_sent": bool(item.get("reminder_sent", False)),
    }


# ---------------------------------------------------------------------------
# CRUD
# ---------------------------------------------------------------------------

def create_action(
    user_sub: str,
    action_type: str,
    scheduled_at: int,
    payload: dict,
    title: str = "",
    description: str = "",
    notify_before_seconds: int = 0,
) -> Dict[str, Any]:
    now = now_ts()

    # Validate lead time
    min_lead = S.scheduled_actions_min_lead_time_seconds
    if scheduled_at <= now + min_lead:
        raise ValueError(f"scheduled_at must be at least {min_lead} seconds in the future")

    # Check max pending per user
    pending_count = _count_pending(user_sub)
    if pending_count >= S.scheduled_actions_max_per_user:
        raise OverflowError(f"Maximum pending scheduled actions reached ({S.scheduled_actions_max_per_user})")

    action_id = _new_action_id()
    max_retries = S.scheduled_actions_max_retries

    item: Dict[str, Any] = {
        "pk": _pk(user_sub),
        "sk": _sk(scheduled_at, action_id),
        "action_id": action_id,
        "user_sub": user_sub,
        "action_type": action_type,
        "status": "pending",
        "scheduled_at": scheduled_at,
        "created_at": now,
        "updated_at": now,
        "title": title,
        "description": description,
        "payload": payload,
        "retry_count": 0,
        "max_retries": max_retries,
        "notify_before_seconds": notify_before_seconds,
        "reminder_sent": False,
        "GSI_DUE_PK": "DUE",
        "GSI_DUE_SK": scheduled_at,
        "GSI_TYPE_PK": _gsi_type_pk(user_sub, action_type),
        "GSI_TYPE_SK": scheduled_at,
        "ttl_epoch": _ttl_epoch(scheduled_at),
    }

    T.scheduled_actions.put_item(Item=item)
    return _action_out(item)


def get_action(user_sub: str, action_id: str) -> Optional[Dict[str, Any]]:
    """Get an action by scanning user's items (since SK includes scheduled_at we don't know)."""
    resp = T.scheduled_actions.query(
        KeyConditionExpression=Key("pk").eq(_pk(user_sub)),
        FilterExpression=Attr("action_id").eq(action_id),
        Limit=500,
    )
    items = resp.get("Items", [])
    if not items:
        return None
    return _action_out(items[0])


def _get_raw_action(user_sub: str, action_id: str) -> Optional[Dict[str, Any]]:
    """Get raw DDB item for an action."""
    resp = T.scheduled_actions.query(
        KeyConditionExpression=Key("pk").eq(_pk(user_sub)),
        FilterExpression=Attr("action_id").eq(action_id),
        Limit=500,
    )
    items = resp.get("Items", [])
    return items[0] if items else None


def list_actions(
    user_sub: str,
    *,
    types: Optional[str] = None,
    status_filter: Optional[str] = None,
    limit: int = 50,
) -> Dict[str, Any]:
    """List user's scheduled actions, optionally filtered."""
    kwargs: Dict[str, Any] = {
        "KeyConditionExpression": Key("pk").eq(_pk(user_sub)),
        "ScanIndexForward": False,
        "Limit": min(limit, 200),
    }

    filters = []
    if status_filter:
        statuses = [s.strip() for s in status_filter.split(",") if s.strip()]
        if len(statuses) == 1:
            filters.append(Attr("status").eq(statuses[0]))
        elif statuses:
            filters.append(Attr("status").is_in(statuses))

    if types:
        type_list = [t.strip() for t in types.split(",") if t.strip()]
        if len(type_list) == 1:
            filters.append(Attr("action_type").eq(type_list[0]))
        elif type_list:
            filters.append(Attr("action_type").is_in(type_list))

    if filters:
        combined = filters[0]
        for f in filters[1:]:
            combined = combined & f
        kwargs["FilterExpression"] = combined

    resp = T.scheduled_actions.query(**kwargs)
    items = resp.get("Items", [])
    return {
        "actions": [_action_out(it) for it in items],
        "cursor": None,
    }


def calendar_range(
    user_sub: str,
    from_date: int,
    to_date: int,
    types: Optional[str] = None,
) -> Dict[str, Any]:
    """Calendar view query using SK range."""
    kc = Key("pk").eq(_pk(user_sub)) & Key("sk").between(
        f"ACTION#{from_date}#",
        f"ACTION#{to_date}#~",
    )
    kwargs: Dict[str, Any] = {
        "KeyConditionExpression": kc,
        "ScanIndexForward": True,
    }
    if types:
        type_list = [t.strip() for t in types.split(",") if t.strip()]
        if len(type_list) == 1:
            kwargs["FilterExpression"] = Attr("action_type").eq(type_list[0])
        elif type_list:
            kwargs["FilterExpression"] = Attr("action_type").is_in(type_list)

    resp = T.scheduled_actions.query(**kwargs)
    items = resp.get("Items", [])
    actions = [_action_out(it) for it in items]
    return {"actions": actions, "total": len(actions)}


def cancel_action(user_sub: str, action_id: str) -> Optional[Dict[str, Any]]:
    """Cancel a pending action."""
    raw = _get_raw_action(user_sub, action_id)
    if not raw:
        return None

    if raw.get("status") not in ("pending",):
        raise ValueError(f"Cannot cancel action in status: {raw.get('status')}")

    now = now_ts()
    try:
        T.scheduled_actions.update_item(
            Key={"pk": raw["pk"], "sk": raw["sk"]},
            UpdateExpression="SET #status = :cancelled, updated_at = :now, completed_at = :now REMOVE GSI_DUE_PK, GSI_DUE_SK",
            ConditionExpression="#status = :pending",
            ExpressionAttributeNames={"#status": "status"},
            ExpressionAttributeValues={
                ":cancelled": "cancelled",
                ":pending": "pending",
                ":now": now,
            },
        )
    except ClientError as e:
        if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
            raise ValueError("Action already processed or cancelled")
        raise

    raw["status"] = "cancelled"
    raw["updated_at"] = now
    raw["completed_at"] = now
    return _action_out(raw)


def update_action(
    user_sub: str,
    action_id: str,
    scheduled_at: Optional[int] = None,
    title: Optional[str] = None,
    description: Optional[str] = None,
    payload: Optional[dict] = None,
    notify_before_seconds: Optional[int] = None,
) -> Optional[Dict[str, Any]]:
    """Update a pending action (reschedule)."""
    raw = _get_raw_action(user_sub, action_id)
    if not raw:
        return None

    if raw.get("status") != "pending":
        raise ValueError(f"Cannot update action in status: {raw.get('status')}")

    now = now_ts()

    if scheduled_at is not None:
        min_lead = S.scheduled_actions_min_lead_time_seconds
        if scheduled_at <= now + min_lead:
            raise ValueError(f"scheduled_at must be at least {min_lead} seconds in the future")

    # If scheduled_at changed, we need to delete old item and create new one (SK contains scheduled_at)
    if scheduled_at is not None and scheduled_at != int(raw.get("scheduled_at", 0)):
        # Delete old item
        T.scheduled_actions.delete_item(Key={"pk": raw["pk"], "sk": raw["sk"]})

        # Create new item with updated fields
        new_item = dict(raw)
        new_item["sk"] = _sk(scheduled_at, action_id)
        new_item["scheduled_at"] = scheduled_at
        new_item["updated_at"] = now
        new_item["GSI_DUE_SK"] = scheduled_at
        new_item["GSI_TYPE_SK"] = scheduled_at
        new_item["ttl_epoch"] = _ttl_epoch(scheduled_at)
        if title is not None:
            new_item["title"] = title
        if description is not None:
            new_item["description"] = description
        if payload is not None:
            new_item["payload"] = payload
        if notify_before_seconds is not None:
            new_item["notify_before_seconds"] = notify_before_seconds
            new_item["reminder_sent"] = False

        T.scheduled_actions.put_item(Item=new_item)
        return _action_out(new_item)
    else:
        # In-place update (no SK change)
        update_parts = ["updated_at = :now"]
        vals: Dict[str, Any] = {":now": now, ":pending": "pending"}
        names: Dict[str, str] = {"#status": "status"}

        if title is not None:
            update_parts.append("title = :title")
            vals[":title"] = title
        if description is not None:
            update_parts.append("description = :desc")
            vals[":desc"] = description
        if payload is not None:
            update_parts.append("payload = :payload")
            vals[":payload"] = payload
        if notify_before_seconds is not None:
            update_parts.append("notify_before_seconds = :nbs")
            update_parts.append("reminder_sent = :false")
            vals[":nbs"] = notify_before_seconds
            vals[":false"] = False

        T.scheduled_actions.update_item(
            Key={"pk": raw["pk"], "sk": raw["sk"]},
            UpdateExpression="SET " + ", ".join(update_parts),
            ConditionExpression="#status = :pending",
            ExpressionAttributeNames=names,
            ExpressionAttributeValues=vals,
        )
        return get_action(user_sub, action_id)


# ---------------------------------------------------------------------------
# Scheduler queries
# ---------------------------------------------------------------------------

def query_due_actions(now: int, limit: int = 25) -> List[Dict[str, Any]]:
    """Find actions where GSI_DUE_SK <= now (pending and due)."""
    resp = T.scheduled_actions.query(
        IndexName="ByDue",
        KeyConditionExpression=Key("GSI_DUE_PK").eq("DUE") & Key("GSI_DUE_SK").lte(now),
        FilterExpression=Attr("status").eq("pending"),
        Limit=limit,
    )
    return resp.get("Items", [])


def query_upcoming_reminders(now: int, lookahead: int = 300) -> List[Dict[str, Any]]:
    """Find pending actions that are due within lookahead seconds and have reminders configured."""
    resp = T.scheduled_actions.query(
        IndexName="ByDue",
        KeyConditionExpression=Key("GSI_DUE_PK").eq("DUE") & Key("GSI_DUE_SK").lte(now + lookahead),
        FilterExpression=Attr("status").eq("pending") & Attr("reminder_sent").eq(False) & Attr("notify_before_seconds").gt(0),
        Limit=50,
    )
    return resp.get("Items", [])


def claim_action(action_id: str, user_sub: str, sk: str) -> bool:
    """Atomically claim a due action. Returns True if this worker claimed it."""
    now = now_ts()
    try:
        T.scheduled_actions.update_item(
            Key={"pk": _pk(user_sub), "sk": sk},
            UpdateExpression="SET #status = :executing, updated_at = :now",
            ConditionExpression="#status = :pending",
            ExpressionAttributeNames={"#status": "status"},
            ExpressionAttributeValues={
                ":executing": "executing",
                ":pending": "pending",
                ":now": now,
            },
        )
        return True
    except ClientError as e:
        if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
            return False
        raise


def mark_action_completed(action: Dict[str, Any]) -> None:
    """Mark a claimed action as completed and remove from due GSI."""
    now = now_ts()
    T.scheduled_actions.update_item(
        Key={"pk": action["pk"], "sk": action["sk"]},
        UpdateExpression="SET #status = :completed, completed_at = :now, updated_at = :now REMOVE GSI_DUE_PK, GSI_DUE_SK",
        ExpressionAttributeNames={"#status": "status"},
        ExpressionAttributeValues={
            ":completed": "completed",
            ":now": now,
        },
    )


def mark_action_failed(action: Dict[str, Any], error: str = "") -> None:
    """Mark a claimed action as failed and remove from due GSI."""
    now = now_ts()
    T.scheduled_actions.update_item(
        Key={"pk": action["pk"], "sk": action["sk"]},
        UpdateExpression="SET #status = :failed, #error = :err, completed_at = :now, updated_at = :now REMOVE GSI_DUE_PK, GSI_DUE_SK",
        ExpressionAttributeNames={"#status": "status", "#error": "error"},
        ExpressionAttributeValues={
            ":failed": "failed",
            ":err": error,
            ":now": now,
        },
    )


def schedule_retry(action: Dict[str, Any], retry_count: int, delay_seconds: int) -> None:
    """Reschedule a failed action for retry."""
    now = now_ts()
    new_due = now + delay_seconds
    T.scheduled_actions.update_item(
        Key={"pk": action["pk"], "sk": action["sk"]},
        UpdateExpression="SET #status = :pending, retry_count = :rc, GSI_DUE_SK = :due, updated_at = :now",
        ExpressionAttributeNames={"#status": "status"},
        ExpressionAttributeValues={
            ":pending": "pending",
            ":rc": retry_count,
            ":due": new_due,
            ":now": now,
        },
    )


def mark_reminder_sent(action: Dict[str, Any]) -> None:
    """Mark reminder as sent on an action."""
    T.scheduled_actions.update_item(
        Key={"pk": action["pk"], "sk": action["sk"]},
        UpdateExpression="SET reminder_sent = :true",
        ConditionExpression="reminder_sent = :false",
        ExpressionAttributeValues={":true": True, ":false": False},
    )


# ---------------------------------------------------------------------------
# Admin query functions (PLATFORM-008)
# ---------------------------------------------------------------------------


def query_failed_actions(
    limit: int = 50, action_type: Optional[str] = None
) -> List[Dict[str, Any]]:
    """Query failed actions across all users (admin endpoint).

    Uses a table scan with FilterExpression. This is acceptable because:
    - Failed actions are rare (< 1% of total)
    - The scan is admin-only and infrequent
    - Items expire via TTL after scheduled_actions_ttl_days
    """
    filter_expr = Attr("status").eq("failed")
    if action_type:
        filter_expr = filter_expr & Attr("action_type").eq(action_type)

    try:
        resp = T.scheduled_actions.scan(
            FilterExpression=filter_expr,
            Limit=limit,
        )
        items = resp.get("Items", [])
        result = []
        for item in items:
            out = _action_out(item)
            out["user_sub"] = item.get("user_sub", "")
            result.append(out)
        return result
    except Exception:
        logger.exception("Failed to query failed actions")
        return []


def count_pending_actions() -> int:
    """Count pending actions in the due queue.

    Queries the ByDue GSI with a far-future cutoff to get all pending items.
    Uses SELECT COUNT to minimize read capacity.
    """
    try:
        far_future = now_ts() + 365 * 86400  # 1 year ahead
        resp = T.scheduled_actions.query(
            IndexName="ByDue",
            KeyConditionExpression=Key("GSI_DUE_PK").eq("DUE") & Key("GSI_DUE_SK").lte(far_future),
            FilterExpression=Attr("status").eq("pending"),
            Select="COUNT",
        )
        count = resp.get("Count", 0)
        # Handle pagination
        while resp.get("LastEvaluatedKey"):
            resp = T.scheduled_actions.query(
                IndexName="ByDue",
                KeyConditionExpression=Key("GSI_DUE_PK").eq("DUE") & Key("GSI_DUE_SK").lte(far_future),
                FilterExpression=Attr("status").eq("pending"),
                Select="COUNT",
                ExclusiveStartKey=resp["LastEvaluatedKey"],
            )
            count += resp.get("Count", 0)
        return count
    except Exception:
        return -1


def count_failed_actions() -> int:
    """Count permanently failed actions."""
    try:
        resp = T.scheduled_actions.scan(
            FilterExpression=Attr("status").eq("failed"),
            Select="COUNT",
        )
        count = resp.get("Count", 0)
        while resp.get("LastEvaluatedKey"):
            resp = T.scheduled_actions.scan(
                FilterExpression=Attr("status").eq("failed"),
                Select="COUNT",
                ExclusiveStartKey=resp["LastEvaluatedKey"],
            )
            count += resp.get("Count", 0)
        return count
    except Exception:
        return -1


def reschedule_failed_action(user_sub: str, action_id: str) -> bool:
    """Reschedule a permanently failed action (admin retry).

    Finds the action by scanning the user's items (since we don't
    know the SK without the scheduled_at). Resets status to pending,
    retry_count to 0, and sets a new due time (now + 5s).
    """
    try:
        resp = T.scheduled_actions.query(
            KeyConditionExpression=Key("pk").eq(_pk(user_sub)),
            FilterExpression=Attr("action_id").eq(action_id) & Attr("status").eq("failed"),
            Limit=1,
        )
        items = resp.get("Items", [])
        if not items:
            return False

        action = items[0]
        now = now_ts()

        T.scheduled_actions.update_item(
            Key={"pk": action["pk"], "sk": action["sk"]},
            UpdateExpression=(
                "SET #status = :pending, retry_count = :z, "
                "GSI_DUE_PK = :duekey, GSI_DUE_SK = :dueat, "
                "updated_at = :now "
                "REMOVE #error, completed_at"
            ),
            ExpressionAttributeNames={"#status": "status", "#error": "error"},
            ExpressionAttributeValues={
                ":pending": "pending",
                ":z": 0,
                ":duekey": "DUE",
                ":dueat": now + 5,  # Due in 5 seconds
                ":now": now,
            },
        )
        logger.info("Admin rescheduled failed action: user=%s, action=%s", user_sub, action_id)
        return True
    except Exception:
        logger.exception("Failed to reschedule action: user=%s, action=%s", user_sub, action_id)
        return False


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _count_pending(user_sub: str) -> int:
    """Count pending actions for a user."""
    resp = T.scheduled_actions.query(
        KeyConditionExpression=Key("pk").eq(_pk(user_sub)),
        FilterExpression=Attr("status").eq("pending"),
        Select="COUNT",
    )
    return resp.get("Count", 0)
