"""CRM Security Groups router.

STU-004: Record-level access control group management.

Registered in app/main.py inside `if _S.crm_acl_enabled:` block.
Prefix: /ui/admin/crm/security-groups
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from app.auth.deps import AuthenticatedUser
from app.auth.policy import (
    enforce_cookie_csrf,
    require_admin_or_root,
    require_root,
)
from app.models import (
    CrmSecurityGroupCreateIn,
    CrmSecurityGroupDetailOut,
    CrmSecurityGroupMemberAddIn,
    CrmSecurityGroupMemberOut,
    CrmSecurityGroupOut,
    CrmSecurityGroupRecordAssignIn,
    CrmSecurityGroupRecordOut,
)
import app.services.crm_security_groups as sg_svc

router = APIRouter(prefix="/ui/admin/crm/security-groups", tags=["crm-security-groups"])


def _meta_to_out(item: dict) -> CrmSecurityGroupOut:
    return CrmSecurityGroupOut(
        group_id=item.get("group_id", ""),
        name=item.get("name", ""),
        description=item.get("description", ""),
        owner_sub=item.get("owner_sub", ""),
        created_at=int(item.get("created_at", 0)),
        is_global=bool(item.get("is_global", False)),
        member_count=int(item.get("member_count", 0)),
        record_count=int(item.get("record_count", 0)),
    )


@router.post("/", response_model=CrmSecurityGroupOut, status_code=201)
async def create_group(
    request: Request,
    body: CrmSecurityGroupCreateIn,
    user: AuthenticatedUser = Depends(require_admin_or_root),
) -> CrmSecurityGroupOut:
    enforce_cookie_csrf(request)
    item = sg_svc.create_group(user.sub, body.name, body.description, body.is_global)
    return _meta_to_out(item)


@router.get("/", response_model=dict)
async def list_groups(
    cursor: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    is_global: Optional[bool] = Query(None),
    user: AuthenticatedUser = Depends(require_admin_or_root),
) -> dict:
    items, next_cursor = sg_svc.list_groups(limit=limit, cursor=cursor, is_global=is_global)
    return {
        "groups": [_meta_to_out(i) for i in items],
        "next_cursor": next_cursor,
    }


@router.get("/{group_id}", response_model=CrmSecurityGroupDetailOut)
async def get_group(
    group_id: str,
    user: AuthenticatedUser = Depends(require_admin_or_root),
) -> CrmSecurityGroupDetailOut:
    detail = sg_svc.get_group_with_detail(group_id)
    if not detail:
        raise HTTPException(404, {"code": "crm_sg_not_found", "group_id": group_id})

    meta = detail["meta"]
    members = [
        CrmSecurityGroupMemberOut(
            user_sub=m.get("user_sub", ""),
            added_by_sub=m.get("added_by_sub", ""),
            added_at=int(m.get("added_at", 0)),
            can_edit=bool(m.get("can_edit", False)),
        )
        for m in detail["members"]
    ]
    records = [
        CrmSecurityGroupRecordOut(
            entity_type=r.get("entity_type", ""),
            record_id=r.get("record_id", ""),
            record_ref=r.get("record_ref", ""),
            assigned_by_sub=r.get("assigned_by_sub", ""),
            created_at=int(r.get("created_at", 0)),
        )
        for r in detail["records"]
    ]
    return CrmSecurityGroupDetailOut(
        group=_meta_to_out(meta),
        members=members,
        records=records,
    )


@router.delete("/{group_id}", status_code=204)
async def delete_group(
    group_id: str,
    request: Request,
    user: AuthenticatedUser = Depends(require_root),
) -> None:
    enforce_cookie_csrf(request)
    sg_svc.delete_group(user.sub, group_id)


@router.post("/{group_id}/members", status_code=204)
async def add_member(
    group_id: str,
    request: Request,
    body: CrmSecurityGroupMemberAddIn,
    user: AuthenticatedUser = Depends(require_admin_or_root),
) -> None:
    enforce_cookie_csrf(request)
    sg_svc.add_member(user.sub, group_id, body.user_sub, body.can_edit)


@router.delete("/{group_id}/members/{user_sub}", status_code=204)
async def remove_member(
    group_id: str,
    user_sub: str,
    request: Request,
    user: AuthenticatedUser = Depends(require_admin_or_root),
) -> None:
    enforce_cookie_csrf(request)
    sg_svc.remove_member(user.sub, group_id, user_sub)


@router.post("/{group_id}/records", status_code=204)
async def assign_record(
    group_id: str,
    request: Request,
    body: CrmSecurityGroupRecordAssignIn,
    user: AuthenticatedUser = Depends(require_admin_or_root),
) -> None:
    enforce_cookie_csrf(request)
    sg_svc.assign_record(user.sub, group_id, body.entity_type, body.record_id)


@router.delete("/{group_id}/records/{entity_type}/{record_id}", status_code=204)
async def unassign_record(
    group_id: str,
    entity_type: str,
    record_id: str,
    request: Request,
    user: AuthenticatedUser = Depends(require_admin_or_root),
) -> None:
    enforce_cookie_csrf(request)
    sg_svc.unassign_record(user.sub, group_id, entity_type, record_id)
