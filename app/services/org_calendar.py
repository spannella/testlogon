"""Organization team calendar service (ENTERPRISE-003)."""
from __future__ import annotations

import uuid
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Key
from fastapi import HTTPException

from app.core.tables import T
from app.core.time import now_ts
from app.services.org_service import assert_org_membership, get_org


def create_org_event(
    org_id: str,
    user_sub: str,
    title: str,
    start_time: str,
    end_time: str,
    description: str = "",
    all_day: bool = False,
    attendees: Optional[List[str]] = None,
) -> Dict[str, Any]:
    assert_org_membership(org_id, user_sub, min_role="member")
    org = get_org(org_id)
    if not org:
        raise HTTPException(404, "Organization not found")

    calendar_id = org.get("team_calendar_id", f"ORG#{org_id}#TEAM")
    event_id = f"evt_{uuid.uuid4().hex}"
    now = now_ts()

    event: Dict[str, Any] = {
        "calendar_id": calendar_id,
        "sk": f"EVENT#{event_id}",
        "event_id": event_id,
        "title": title,
        "description": description or "",
        "start_time": start_time,
        "end_time": end_time,
        "all_day": all_day,
        "created_by": user_sub,
        "org_id": org_id,
        "attendees": attendees or [],
        "created_at": now,
        "updated_at": now,
    }
    T.calendar.put_item(Item=event)
    return event


def list_org_events(
    org_id: str,
    user_sub: str,
    limit: int = 100,
) -> List[Dict[str, Any]]:
    assert_org_membership(org_id, user_sub, min_role="viewer")
    org = get_org(org_id)
    if not org:
        raise HTTPException(404, "Organization not found")

    calendar_id = org.get("team_calendar_id", f"ORG#{org_id}#TEAM")
    resp = T.calendar.query(
        KeyConditionExpression=Key("calendar_id").eq(calendar_id) & Key("sk").begins_with("EVENT#"),
        Limit=limit,
        ScanIndexForward=True,
    )
    return resp.get("Items", [])


def update_org_event(
    org_id: str,
    user_sub: str,
    event_id: str,
    title: Optional[str] = None,
    description: Optional[str] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
) -> Dict[str, Any]:
    membership = assert_org_membership(org_id, user_sub, min_role="member")
    org = get_org(org_id)
    if not org:
        raise HTTPException(404, "Organization not found")
    calendar_id = org.get("team_calendar_id", f"ORG#{org_id}#TEAM")

    resp = T.calendar.get_item(Key={"calendar_id": calendar_id, "sk": f"EVENT#{event_id}"})
    event = resp.get("Item")
    if not event:
        raise HTTPException(404, "Event not found")

    if event["created_by"] != user_sub and membership["org_role"] not in ("admin", "owner"):
        raise HTTPException(403, "Only the event creator or an admin can update this event")

    update_parts = ["updated_at = :now"]
    values: Dict[str, Any] = {":now": now_ts()}

    if title is not None:
        update_parts.append("title = :t")
        values[":t"] = title
    if description is not None:
        update_parts.append("description = :d")
        values[":d"] = description
    if start_time is not None:
        update_parts.append("start_time = :st")
        values[":st"] = start_time
    if end_time is not None:
        update_parts.append("end_time = :et")
        values[":et"] = end_time

    T.calendar.update_item(
        Key={"calendar_id": calendar_id, "sk": f"EVENT#{event_id}"},
        UpdateExpression="SET " + ", ".join(update_parts),
        ExpressionAttributeValues=values,
    )

    return {
        **event,
        **({"title": title} if title is not None else {}),
        **({"description": description} if description is not None else {}),
        **({"start_time": start_time} if start_time is not None else {}),
        **({"end_time": end_time} if end_time is not None else {}),
    }


def delete_org_event(org_id: str, user_sub: str, event_id: str) -> None:
    membership = assert_org_membership(org_id, user_sub, min_role="member")
    org = get_org(org_id)
    if not org:
        raise HTTPException(404, "Organization not found")
    calendar_id = org.get("team_calendar_id", f"ORG#{org_id}#TEAM")

    resp = T.calendar.get_item(Key={"calendar_id": calendar_id, "sk": f"EVENT#{event_id}"})
    event = resp.get("Item")
    if not event:
        raise HTTPException(404, "Event not found")

    if event["created_by"] != user_sub and membership["org_role"] not in ("admin", "owner"):
        raise HTTPException(403, "Only the event creator or an admin can delete this event")

    T.calendar.delete_item(Key={"calendar_id": calendar_id, "sk": f"EVENT#{event_id}"})
