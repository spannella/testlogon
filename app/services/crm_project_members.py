"""CRM Project Members & access control — PRJ-007.

Tables: T.crm_pm_members, T.crm_pm_projects.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Key
from fastapi import HTTPException

from app.core.cursor import decode_cursor, encode_cursor
from app.core.tables import T
from app.core.time import now_ts
from app.models import (
    CrmProjectMemberListResp,
    CrmProjectMemberOut,
    CrmProjectMemberRole,
)

_ROLE_ORDER = {
    CrmProjectMemberRole.viewer: 0,
    CrmProjectMemberRole.member: 1,
    CrmProjectMemberRole.owner: 2,
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _member_pk(project_id: str) -> str:
    return f"PROJECT#{project_id}"


def _member_sk(user_sub: str) -> str:
    return f"MEMBER#{user_sub}"


def _item_to_member(item: Dict[str, Any]) -> CrmProjectMemberOut:
    return CrmProjectMemberOut(
        project_id=item["project_id"],
        user_sub=item["user_sub"],
        role=CrmProjectMemberRole(item["role"]),
        added_by=item.get("added_by", item["user_sub"]),
        added_at=int(item.get("added_at", 0)),
    )


# ---------------------------------------------------------------------------
# Access gate
# ---------------------------------------------------------------------------

def _assert_project_access(
    caller_sub: str,
    project_id: str,
    min_role: CrmProjectMemberRole = CrmProjectMemberRole.viewer,
) -> CrmProjectMemberOut:
    """Raise 403 if caller is not a member with at least min_role."""
    resp = T.crm_pm_members.get_item(
        Key={
            "PK": _member_pk(project_id),
            "SK": _member_sk(caller_sub),
        },
        ConsistentRead=True,
    )
    item = resp.get("Item")
    if not item or item.get("entity_type") != "crm_member":
        raise HTTPException(status_code=403, detail={"code": "not_a_project_member"})
    member = _item_to_member(item)
    if _ROLE_ORDER.get(member.role, -1) < _ROLE_ORDER.get(min_role, 0):
        raise HTTPException(status_code=403, detail={"code": "insufficient_project_role"})
    return member


# ---------------------------------------------------------------------------
# Member bootstrap — called after project creation
# ---------------------------------------------------------------------------

def bootstrap_owner(owner_sub: str, project_id: str) -> None:
    """Write the owner member row after project creation."""
    ts = now_ts()
    T.crm_pm_members.put_item(Item={
        "PK": _member_pk(project_id),
        "SK": _member_sk(owner_sub),
        "GSI1PK": f"MEMBER#{owner_sub}",
        "GSI1SK": f"PROJECT#{project_id}",
        "entity_type": "crm_member",
        "project_id": project_id,
        "user_sub": owner_sub,
        "role": CrmProjectMemberRole.owner.value,
        "added_by": owner_sub,
        "added_at": ts,
    })


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def add_member(
    caller_sub: str,
    project_id: str,
    user_sub: str,
    role: CrmProjectMemberRole = CrmProjectMemberRole.member,
) -> CrmProjectMemberOut:
    """Add a member to a project (caller must be owner)."""
    _assert_project_access(caller_sub, project_id, CrmProjectMemberRole.owner)
    if role == CrmProjectMemberRole.owner:
        raise HTTPException(status_code=400, detail={"code": "cannot_add_second_owner"})
    ts = now_ts()
    item = {
        "PK": _member_pk(project_id),
        "SK": _member_sk(user_sub),
        "GSI1PK": f"MEMBER#{user_sub}",
        "GSI1SK": f"PROJECT#{project_id}",
        "entity_type": "crm_member",
        "project_id": project_id,
        "user_sub": user_sub,
        "role": role.value,
        "added_by": caller_sub,
        "added_at": ts,
    }
    T.crm_pm_members.put_item(Item=item)
    return _item_to_member(item)


def update_member(
    caller_sub: str,
    project_id: str,
    user_sub: str,
    role: CrmProjectMemberRole,
) -> CrmProjectMemberOut:
    """Update a member's role (caller must be owner, cannot change owner role)."""
    _assert_project_access(caller_sub, project_id, CrmProjectMemberRole.owner)
    resp = T.crm_pm_members.get_item(
        Key={"PK": _member_pk(project_id), "SK": _member_sk(user_sub)},
        ConsistentRead=True,
    )
    item = resp.get("Item")
    if not item:
        raise HTTPException(status_code=404, detail="member_not_found")
    if item.get("role") == CrmProjectMemberRole.owner.value:
        raise HTTPException(status_code=400, detail={"code": "cannot_change_owner_role"})
    if role == CrmProjectMemberRole.owner:
        raise HTTPException(status_code=400, detail={"code": "cannot_promote_to_owner"})
    T.crm_pm_members.update_item(
        Key={"PK": _member_pk(project_id), "SK": _member_sk(user_sub)},
        UpdateExpression="SET #role = :role",
        ExpressionAttributeNames={"#role": "role"},
        ExpressionAttributeValues={":role": role.value},
    )
    item["role"] = role.value
    return _item_to_member(item)


def remove_member(
    caller_sub: str,
    project_id: str,
    user_sub: str,
) -> Dict[str, bool]:
    """Remove a member from a project (caller must be owner; owner row cannot be removed)."""
    _assert_project_access(caller_sub, project_id, CrmProjectMemberRole.owner)
    resp = T.crm_pm_members.get_item(
        Key={"PK": _member_pk(project_id), "SK": _member_sk(user_sub)},
    )
    item = resp.get("Item")
    if not item:
        raise HTTPException(status_code=404, detail="member_not_found")
    if item.get("role") == CrmProjectMemberRole.owner.value:
        raise HTTPException(status_code=400, detail={"code": "cannot_remove_owner"})
    T.crm_pm_members.delete_item(
        Key={"PK": _member_pk(project_id), "SK": _member_sk(user_sub)},
    )
    return {"ok": True}


def list_members(
    caller_sub: str,
    project_id: str,
    *,
    limit: int = 50,
    cursor: Optional[str] = None,
) -> CrmProjectMemberListResp:
    """List project members (caller must be at least viewer)."""
    _assert_project_access(caller_sub, project_id, CrmProjectMemberRole.viewer)
    limit = max(1, min(limit, 200))
    last_key = decode_cursor(cursor) if cursor else None
    items: List[CrmProjectMemberOut] = []

    while len(items) < limit:
        kwargs: Dict[str, Any] = {
            "KeyConditionExpression": (
                Key("PK").eq(_member_pk(project_id))
                & Key("SK").begins_with("MEMBER#")
            ),
            "Limit": limit,
        }
        if last_key:
            kwargs["ExclusiveStartKey"] = last_key
        resp = T.crm_pm_members.query(**kwargs)
        for raw in resp.get("Items", []):
            if raw.get("entity_type") == "crm_member":
                items.append(_item_to_member(raw))
                if len(items) >= limit:
                    break
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break

    next_cursor = encode_cursor(last_key) if last_key else None
    return CrmProjectMemberListResp(items=items, cursor=next_cursor)


def list_projects_for_user(
    user_sub: str,
    *,
    limit: int = 50,
    cursor: Optional[str] = None,
) -> Dict[str, Any]:
    """List all projects the user is a member of (via GSI1)."""
    limit = max(1, min(limit, 200))
    last_key = decode_cursor(cursor) if cursor else None
    project_ids: List[str] = []

    while len(project_ids) < limit:
        kwargs: Dict[str, Any] = {
            "IndexName": "GSI1",
            "KeyConditionExpression": Key("GSI1PK").eq(f"MEMBER#{user_sub}"),
            "Limit": limit,
        }
        if last_key:
            kwargs["ExclusiveStartKey"] = last_key
        resp = T.crm_pm_members.query(**kwargs)
        for raw in resp.get("Items", []):
            if raw.get("entity_type") == "crm_member":
                project_ids.append(raw["project_id"])
                if len(project_ids) >= limit:
                    break
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break

    next_cursor = encode_cursor(last_key) if last_key else None
    return {"project_ids": project_ids, "cursor": next_cursor}
