"""CRM Project Contact Links — PRJ-010.

Stores contact-link rows in crm_pm_members table using SK prefix CONTACT_LINK#.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Key
from fastapi import HTTPException

from app.core.cursor import decode_cursor, encode_cursor
from app.core.tables import T
from app.core.time import now_ts
from app.models import (
    CrmProjectContactLinkListResp,
    CrmProjectContactLinkOut,
)


def _pk(project_id: str) -> str:
    return f"PROJECT#{project_id}"


def _sk(linked_entity_id: str) -> str:
    return f"CONTACT_LINK#{linked_entity_id}"


def _item_to_link(item: Dict[str, Any]) -> CrmProjectContactLinkOut:
    return CrmProjectContactLinkOut(
        project_id=item["project_id"],
        linked_entity_id=item["linked_entity_id"],
        linked_entity_type=item.get("linked_entity_type", "contact_party"),
        added_by=item.get("added_by", ""),
        added_at=int(item.get("added_at", 0)),
        note=item.get("note"),
    )


def _assert_access(caller_sub: str, project_id: str) -> None:
    """Assert caller has at least viewer access to the project (via crm_projects)."""
    from app.services.crm_projects import get_crm_project
    get_crm_project(caller_sub, project_id)


def add_contact_link(
    caller_sub: str,
    project_id: str,
    linked_entity_id: str,
    *,
    linked_entity_type: str = "contact_party",
    note: Optional[str] = None,
) -> CrmProjectContactLinkOut:
    _assert_access(caller_sub, project_id)
    ts = now_ts()
    item: Dict[str, Any] = {
        "PK": _pk(project_id),
        "SK": _sk(linked_entity_id),
        "entity_type": "crm_contact_link",
        "project_id": project_id,
        "linked_entity_id": linked_entity_id,
        "linked_entity_type": linked_entity_type,
        "added_by": caller_sub,
        "added_at": ts,
    }
    if note is not None:
        item["note"] = note

    T.crm_pm_members.put_item(Item=item)

    try:
        from app.services.alerts import audit_event
        audit_event(
            "crm_project.account_linked",
            caller_sub,
            None,
            project_id=project_id,
            linked_entity_id=linked_entity_id,
            linked_entity_type=linked_entity_type,
        )
    except Exception:
        pass

    return _item_to_link(item)


def list_contact_links(
    caller_sub: str,
    project_id: str,
    *,
    limit: int = 50,
    cursor: Optional[str] = None,
) -> CrmProjectContactLinkListResp:
    _assert_access(caller_sub, project_id)
    limit = max(1, min(limit, 200))
    last_key = decode_cursor(cursor) if cursor else None
    items: List[CrmProjectContactLinkOut] = []

    while len(items) < limit:
        kwargs: Dict[str, Any] = {
            "KeyConditionExpression": (
                Key("PK").eq(_pk(project_id))
                & Key("SK").begins_with("CONTACT_LINK#")
            ),
            "Limit": limit,
        }
        if last_key:
            kwargs["ExclusiveStartKey"] = last_key
        resp = T.crm_pm_members.query(**kwargs)
        for raw in resp.get("Items", []):
            if raw.get("entity_type") == "crm_contact_link":
                items.append(_item_to_link(raw))
                if len(items) >= limit:
                    break
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break

    next_cursor = encode_cursor(last_key) if last_key else None
    return CrmProjectContactLinkListResp(items=items, cursor=next_cursor)


def remove_contact_link(
    caller_sub: str,
    project_id: str,
    linked_entity_id: str,
) -> Dict[str, bool]:
    _assert_access(caller_sub, project_id)
    try:
        T.crm_pm_members.delete_item(
            Key={"PK": _pk(project_id), "SK": _sk(linked_entity_id)},
            ConditionExpression="attribute_exists(PK) AND attribute_exists(SK)",
        )
    except Exception as e:
        if "ConditionalCheckFailed" in str(e):
            raise HTTPException(status_code=404, detail="contact_link_not_found")
        raise
    return {"ok": True}
