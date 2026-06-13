"""CRM Project Status workflow and history — PRJ-009.

Uses T.alerts as audit store via audit_event primitive.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional
from uuid import uuid4

from boto3.dynamodb.conditions import Attr, Key
from fastapi import HTTPException

from app.core.cursor import decode_cursor, encode_cursor
from app.core.tables import T
from app.core.time import now_ts
from app.models import (
    CrmProjectStatus,
    CrmProjectStatusHistoryEntry,
    CrmProjectStatusHistoryResp,
)

# Status transition graph (finite state machine)
_STATUS_TRANSITIONS: Dict[str, tuple] = {
    CrmProjectStatus.draft.value: (
        CrmProjectStatus.in_review.value,
        CrmProjectStatus.underway.value,
        CrmProjectStatus.deferred.value,
    ),
    CrmProjectStatus.in_review.value: (
        CrmProjectStatus.draft.value,
        CrmProjectStatus.underway.value,
        CrmProjectStatus.deferred.value,
    ),
    CrmProjectStatus.underway.value: (
        CrmProjectStatus.completed.value,
        CrmProjectStatus.deferred.value,
        CrmProjectStatus.in_review.value,
    ),
    CrmProjectStatus.completed.value: (
        CrmProjectStatus.underway.value,  # re-open
    ),
    CrmProjectStatus.deferred.value: (
        CrmProjectStatus.draft.value,
        CrmProjectStatus.underway.value,
    ),
}


def validate_status_transition(current: str, requested: str) -> None:
    """Raise 400 if the requested transition is not allowed."""
    if requested == current:
        return  # no-op
    allowed = _STATUS_TRANSITIONS.get(current, ())
    if requested not in allowed:
        raise HTTPException(
            status_code=400,
            detail={
                "code": "invalid_project_status_transition",
                "from": current,
                "to": requested,
                "allowed": list(allowed),
            },
        )


def record_status_change(
    owner_sub: str,
    project_id: str,
    from_status: Optional[str],
    to_status: str,
) -> None:
    """Write a status-change audit row to T.alerts."""
    try:
        from app.services.alerts import audit_event
        audit_event(
            "crm_project.status_changed",
            owner_sub,
            None,
            project_id=project_id,
            from_status=from_status or "",
            to_status=to_status,
        )
    except Exception:
        pass


def get_status_history(
    owner_sub: str,
    project_id: str,
    *,
    limit: int = 50,
    cursor: Optional[str] = None,
) -> CrmProjectStatusHistoryResp:
    """Return status-change audit events for a project from T.alerts."""
    from app.services.crm_projects import get_crm_project
    get_crm_project(owner_sub, project_id)

    limit = max(1, min(limit, 200))
    last_key = decode_cursor(cursor) if cursor else None
    items: List[CrmProjectStatusHistoryEntry] = []

    # Scan alerts for this user + filter by project_id + event
    while len(items) < limit:
        kwargs: Dict[str, Any] = {
            "KeyConditionExpression": Key("user_sub").eq(owner_sub),
            "FilterExpression": (
                Attr("event").eq("crm_project.status_changed")
                & Attr("details").exists()
            ),
            "ScanIndexForward": False,
            "Limit": limit * 5,  # over-fetch since we filter
        }
        if last_key:
            kwargs["ExclusiveStartKey"] = last_key
        resp = T.alerts.query(**kwargs)
        for raw in resp.get("Items", []):
            details = raw.get("details") or {}
            if details.get("project_id") != project_id:
                continue
            items.append(CrmProjectStatusHistoryEntry(
                project_id=project_id,
                from_status=details.get("from_status") or None,
                to_status=details.get("to_status", ""),
                changed_by=raw.get("user_sub", owner_sub),
                changed_at=int(raw.get("ts", 0)),
                event_id=raw.get("alert_id", uuid4().hex),
            ))
            if len(items) >= limit:
                break
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break

    next_cursor = encode_cursor(last_key) if last_key else None
    return CrmProjectStatusHistoryResp(items=items, cursor=next_cursor)
