"""CRM ACL Role management router.

STU-002: ACL role matrix CRUD + user assignment.
STU-003: Group assignment endpoints.

Registered in app/main.py inside `if _S.crm_acl_enabled:` block.
Prefix: /ui/admin/crm/acl-roles
"""
from __future__ import annotations

from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from app.auth.deps import AuthenticatedUser, get_authenticated_user
from app.auth.policy import (
    enforce_cookie_csrf,
    require_admin_or_root,
    require_root,
)
from app.models import (
    CrmAclAssignmentIn,
    CrmAclAssignmentOut,
    CrmAclGroupAssignmentIn,
    CrmAclGroupAssignmentOut,
    CrmAclRoleAssignmentsOut,
    CrmAclRoleCreateIn,
    CrmAclRoleOut,
    CrmAclRoleUpdateIn,
    CrmEffectivePermissionsOut,
)
import app.services.crm_acl as crm_acl_svc
from app.core.time import now_ts

router = APIRouter(prefix="/ui/admin/crm/acl-roles", tags=["crm-acl"])


# ---------------------------------------------------------------------------
# Static routes declared BEFORE dynamic /{role_id} to prevent capture
# ---------------------------------------------------------------------------

@router.get("/my-permissions", response_model=CrmEffectivePermissionsOut)
async def get_my_permissions(
    user: AuthenticatedUser = Depends(get_authenticated_user),
) -> CrmEffectivePermissionsOut:
    """Return the effective permission union for the calling user."""
    admin_profile = getattr(user, "admin_profile", None)
    roles = crm_acl_svc.get_effective_roles_for_user(user.sub, admin_profile)

    # Merge permissions via union
    merged: dict[str, Any] = {}
    for role in roles:
        perms = role.get("permissions", {})
        for module, matrix in perms.items():
            if module not in merged:
                merged[module] = {}
            for action, val in (matrix or {}).items():
                if val:
                    merged[module][action] = True

    return CrmEffectivePermissionsOut(user_sub=user.sub, permissions=merged)


# ---------------------------------------------------------------------------
# Role CRUD
# ---------------------------------------------------------------------------

@router.post("/", response_model=CrmAclRoleOut, status_code=201)
async def create_role(
    request: Request,
    body: CrmAclRoleCreateIn,
    user: AuthenticatedUser = Depends(require_root),
) -> CrmAclRoleOut:
    enforce_cookie_csrf(request)
    item = crm_acl_svc.create_acl_role(
        user.sub,
        body.name,
        body.description,
        body.permissions,
    )
    return _role_item_to_out(item)


@router.get("/", response_model=dict)
async def list_roles(
    cursor: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    user: AuthenticatedUser = Depends(require_admin_or_root),
) -> dict:
    items, next_cursor = crm_acl_svc.list_acl_roles(limit=limit, cursor=cursor)
    return {
        "roles": [_role_item_to_out(i) for i in items],
        "next_cursor": next_cursor,
    }


@router.get("/{role_id}", response_model=CrmAclRoleOut)
async def get_role(
    role_id: str,
    user: AuthenticatedUser = Depends(require_admin_or_root),
) -> CrmAclRoleOut:
    item = crm_acl_svc.get_acl_role(role_id)
    return _role_item_to_out(item)


@router.patch("/{role_id}", response_model=CrmAclRoleOut)
async def update_role(
    role_id: str,
    request: Request,
    body: CrmAclRoleUpdateIn,
    user: AuthenticatedUser = Depends(require_root),
) -> CrmAclRoleOut:
    enforce_cookie_csrf(request)
    item = crm_acl_svc.update_acl_role(
        user.sub,
        role_id,
        name=body.name,
        description=body.description,
        permissions=body.permissions,
    )
    return _role_item_to_out(item)


@router.delete("/{role_id}", status_code=204)
async def delete_role(
    role_id: str,
    request: Request,
    user: AuthenticatedUser = Depends(require_root),
) -> None:
    enforce_cookie_csrf(request)
    crm_acl_svc.delete_acl_role(user.sub, role_id)


# ---------------------------------------------------------------------------
# User assignments
# ---------------------------------------------------------------------------

@router.get("/{role_id}/assignments", response_model=CrmAclRoleAssignmentsOut)
async def list_assignments(
    role_id: str,
    user: AuthenticatedUser = Depends(require_admin_or_root),
) -> CrmAclRoleAssignmentsOut:
    result = crm_acl_svc.list_role_assignments(role_id)
    return CrmAclRoleAssignmentsOut(
        role_id=result["role_id"],
        user_assignments=result["user_assignments"],
        group_assignments=[
            CrmAclGroupAssignmentOut(**ga) for ga in result["group_assignments"]
        ],
    )


@router.post("/{role_id}/assignments", response_model=CrmAclAssignmentOut, status_code=201)
async def assign_user(
    role_id: str,
    request: Request,
    body: CrmAclAssignmentIn,
    user: AuthenticatedUser = Depends(require_root),
) -> CrmAclAssignmentOut:
    enforce_cookie_csrf(request)
    crm_acl_svc.assign_role_to_user(user.sub, role_id, body.user_sub)
    return CrmAclAssignmentOut(
        role_id=role_id,
        user_sub=body.user_sub,
        assigned_by_sub=user.sub,
        assigned_at=now_ts(),
    )


@router.delete("/{role_id}/assignments/{user_sub}", status_code=204)
async def revoke_user(
    role_id: str,
    user_sub: str,
    request: Request,
    user: AuthenticatedUser = Depends(require_root),
) -> None:
    enforce_cookie_csrf(request)
    crm_acl_svc.revoke_role_from_user(user.sub, role_id, user_sub)


# ---------------------------------------------------------------------------
# STU-003: Group assignments
# ---------------------------------------------------------------------------

@router.post("/{role_id}/group-assignments", response_model=CrmAclGroupAssignmentOut)
async def assign_group(
    role_id: str,
    request: Request,
    body: CrmAclGroupAssignmentIn,
    user: AuthenticatedUser = Depends(require_root),
) -> CrmAclGroupAssignmentOut:
    enforce_cookie_csrf(request)
    crm_acl_svc.assign_role_to_group(user.sub, role_id, body.group_key)
    return CrmAclGroupAssignmentOut(
        role_id=role_id,
        group_key=body.group_key,
        assigned_by_sub=user.sub,
        assigned_at=now_ts(),
    )


@router.delete("/{role_id}/group-assignments/{group_key}", status_code=204)
async def revoke_group(
    role_id: str,
    group_key: str,
    request: Request,
    user: AuthenticatedUser = Depends(require_root),
) -> None:
    enforce_cookie_csrf(request)
    crm_acl_svc.revoke_role_from_group(user.sub, role_id, group_key)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _role_item_to_out(item: dict) -> CrmAclRoleOut:
    return CrmAclRoleOut(
        role_id=item.get("role_id", ""),
        name=item.get("name", ""),
        description=item.get("description", ""),
        permissions=item.get("permissions", {}),
        created_at=int(item.get("created_at", 0)),
        created_by_sub=item.get("created_by_sub", ""),
        updated_at=int(item["updated_at"]) if item.get("updated_at") is not None else None,
        updated_by_sub=item.get("updated_by_sub"),
    )
