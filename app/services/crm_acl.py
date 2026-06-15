"""CRM ACL Role matrix — per-module CRUD permission store & evaluation.

STU-002: Core role management + assignment.
STU-003: Multi-role + user-group propagation via AdminProfile.scopes.
"""
from __future__ import annotations

import re
from typing import Any
from uuid import uuid4

from fastapi import Depends, HTTPException

from app.core.time import now_ts
from app.core.cursor import encode_cursor, decode_cursor

# Lazy import to avoid circular deps
_GROUP_KEY_RE = re.compile(r"^[a-z][a-z0-9_]*$")

# ---------------------------------------------------------------------------
# Module-level permission cache (mirrors billing_config.py:46–58)
# ---------------------------------------------------------------------------
_perm_cache: dict[str, tuple[list[dict], int]] = {}  # user_sub -> (roles, fetched_ts)
_CACHE_TTL = 60  # seconds


def _invalidate_user_cache(user_sub: str) -> None:
    _perm_cache.pop(user_sub, None)


def _invalidate_permission_cache() -> None:
    """Invalidate the entire permission cache (used when group assignments change)."""
    _perm_cache.clear()


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _role_pk(role_id: str) -> str:
    return f"ROLE#{role_id}"


def _get_table():
    from app.core.tables import T
    return T.crm_acl_roles


def _get_alerts():
    from app.services.alerts import audit_event
    return audit_event


def _get_settings():
    from app.core.settings import S
    return S


def _permissions_to_dict(permissions: dict) -> dict:
    """Serialise the permissions dict to plain Python booleans for DDB storage."""
    result = {}
    for module, matrix in permissions.items():
        if hasattr(matrix, "model_dump"):
            # Pydantic model
            d = matrix.model_dump(by_alias=False)
        elif isinstance(matrix, dict):
            d = matrix
        else:
            d = dict(matrix)
        result[module] = d
    return result


# ---------------------------------------------------------------------------
# STU-002: Role CRUD
# ---------------------------------------------------------------------------

def create_acl_role(
    actor_sub: str,
    name: str,
    description: str,
    permissions: dict,
) -> dict:
    """Create a named ACL role with a module permission map."""
    table = _get_table()
    audit_event = _get_alerts()

    role_id = uuid4().hex
    ts = now_ts()
    item = {
        "pk": _role_pk(role_id),
        "sk": "META",
        "role_id": role_id,
        "name": name,
        "description": description,
        "permissions": _permissions_to_dict(permissions),
        "created_at": ts,
        "created_by_sub": actor_sub,
        "updated_at": ts,
        "updated_by_sub": actor_sub,
    }
    table.put_item(Item=item)
    audit_event("crm_acl_role.created", actor_sub, role_id=role_id, name=name)
    return item


def get_acl_role(role_id: str) -> dict:
    """Return the role META item. Raises HTTPException(404) if missing."""
    table = _get_table()
    resp = table.get_item(Key={"pk": _role_pk(role_id), "sk": "META"})
    item = resp.get("Item")
    if not item:
        raise HTTPException(404, {"code": "acl_role_not_found", "role_id": role_id})
    return item


def list_acl_roles(limit: int = 50, cursor: str | None = None) -> tuple[list[dict], str | None]:
    """Scan for META rows. Returns (items, next_cursor)."""
    from boto3.dynamodb.conditions import Attr
    table = _get_table()

    kwargs: dict[str, Any] = {
        "FilterExpression": Attr("sk").eq("META"),
        "Limit": limit,
    }
    if cursor:
        lek = decode_cursor(cursor)
        if lek:
            kwargs["ExclusiveStartKey"] = lek

    resp = table.scan(**kwargs)
    items = resp.get("Items", [])
    lek = resp.get("LastEvaluatedKey")
    next_cursor = encode_cursor(lek) if lek else None
    return items, next_cursor


def update_acl_role(
    actor_sub: str,
    role_id: str,
    *,
    name: str | None = None,
    description: str | None = None,
    permissions: dict | None = None,
) -> dict:
    """Partially update role attributes. Returns the updated role dict."""
    from boto3.dynamodb.conditions import Key as DKey
    from botocore.exceptions import ClientError

    table = _get_table()
    audit_event = _get_alerts()

    # Verify existence
    existing = get_acl_role(role_id)

    ts = now_ts()
    update_parts = ["#ua = :ua", "#ubs = :ubs"]
    attr_names = {"#ua": "updated_at", "#ubs": "updated_by_sub"}
    attr_values: dict[str, Any] = {":ua": ts, ":ubs": actor_sub}

    if name is not None:
        update_parts.append("#n = :n")
        attr_names["#n"] = "name"
        attr_values[":n"] = name

    if description is not None:
        update_parts.append("#d = :d")
        attr_names["#d"] = "description"
        attr_values[":d"] = description

    if permissions is not None:
        update_parts.append("#p = :p")
        attr_names["#p"] = "permissions"
        attr_values[":p"] = _permissions_to_dict(permissions)

    table.update_item(
        Key={"pk": _role_pk(role_id), "sk": "META"},
        UpdateExpression="SET " + ", ".join(update_parts),
        ExpressionAttributeNames=attr_names,
        ExpressionAttributeValues=attr_values,
    )
    audit_event("crm_acl_role.updated", actor_sub, role_id=role_id)
    return get_acl_role(role_id)


def delete_acl_role(actor_sub: str, role_id: str) -> None:
    """Delete role META and all ASSIGNMENT#/GROUP_ASSIGNMENT# rows."""
    from boto3.dynamodb.conditions import Key as DKey

    table = _get_table()
    audit_event = _get_alerts()

    # Verify existence
    existing = get_acl_role(role_id)

    # Collect all non-META rows
    items_to_delete = []
    kwargs: dict[str, Any] = {
        "KeyConditionExpression": DKey("pk").eq(_role_pk(role_id)),
    }
    while True:
        resp = table.query(**kwargs)
        for item in resp.get("Items", []):
            if item["sk"] != "META":
                items_to_delete.append({"pk": item["pk"], "sk": item["sk"]})
                # Invalidate cache for direct user assignments
                if item["sk"].startswith("ASSIGNMENT#"):
                    user_sub = item["sk"].split("#", 1)[1]
                    _invalidate_user_cache(user_sub)
        lek = resp.get("LastEvaluatedKey")
        if not lek:
            break
        kwargs["ExclusiveStartKey"] = lek

    # Batch delete assignments/group-assignments
    with table.batch_writer() as batch:
        for key in items_to_delete:
            batch.delete_item(Key=key)

    # Delete META
    table.delete_item(Key={"pk": _role_pk(role_id), "sk": "META"})

    # Invalidate full cache if group assignments were deleted
    _invalidate_permission_cache()
    audit_event("crm_acl_role.deleted", actor_sub, role_id=role_id)


def assign_role_to_user(actor_sub: str, role_id: str, user_sub: str) -> None:
    """Assign a role to a user. Idempotent (put_item upsert)."""
    table = _get_table()
    audit_event = _get_alerts()

    # Verify role exists
    get_acl_role(role_id)

    ts = now_ts()
    table.put_item(Item={
        "pk": _role_pk(role_id),
        "sk": f"ASSIGNMENT#{user_sub}",
        "user_sub": user_sub,
        "assignee_id": user_sub,
        "role_id": role_id,
        "assigned_by_sub": actor_sub,
        "assigned_at": ts,
    })
    _invalidate_user_cache(user_sub)
    audit_event("crm_acl_role.assigned", actor_sub, role_id=role_id, target_user_sub=user_sub)


def revoke_role_from_user(actor_sub: str, role_id: str, user_sub: str) -> None:
    """Revoke a role from a user. No-op if not assigned."""
    table = _get_table()
    audit_event = _get_alerts()

    table.delete_item(Key={"pk": _role_pk(role_id), "sk": f"ASSIGNMENT#{user_sub}"})
    _invalidate_user_cache(user_sub)
    audit_event("crm_acl_role.revoked", actor_sub, role_id=role_id, target_user_sub=user_sub)


def get_roles_for_user(user_sub: str) -> list[dict]:
    """Query by-assignee GSI; return list of role META dicts."""
    from boto3.dynamodb.conditions import Key as DKey

    table = _get_table()

    # Query GSI for all assignment rows
    resp = table.query(
        IndexName="by-assignee",
        KeyConditionExpression=DKey("assignee_id").eq(user_sub),
    )
    role_ids = [item["role_id"] for item in resp.get("Items", [])]

    if not role_ids:
        return []

    # Batch-get META rows
    roles = []
    for role_id in role_ids:
        try:
            role = get_acl_role(role_id)
            roles.append(role)
        except HTTPException:
            # Orphaned assignment row — skip
            pass
    return roles


def list_assignments_for_role(role_id: str) -> list[dict]:
    """List all direct user assignment rows for a role."""
    from boto3.dynamodb.conditions import Key as DKey

    table = _get_table()
    items = []
    kwargs: dict[str, Any] = {
        "KeyConditionExpression": DKey("pk").eq(_role_pk(role_id))
        & DKey("sk").begins_with("ASSIGNMENT#"),
    }
    while True:
        resp = table.query(**kwargs)
        items.extend(resp.get("Items", []))
        lek = resp.get("LastEvaluatedKey")
        if not lek:
            break
        kwargs["ExclusiveStartKey"] = lek
    return items


# ---------------------------------------------------------------------------
# STU-003: Group assignment
# ---------------------------------------------------------------------------

def assign_role_to_group(actor_sub: str, role_id: str, group_key: str) -> None:
    """Assign an ACL role to a platform group. Idempotent."""
    table = _get_table()
    audit_event = _get_alerts()

    # Validate group_key
    if not _GROUP_KEY_RE.match(group_key):
        raise HTTPException(400, {"code": "invalid_group_key", "group_key": group_key})

    # Verify role exists
    get_acl_role(role_id)

    ts = now_ts()
    table.put_item(Item={
        "pk": _role_pk(role_id),
        "sk": f"GROUP_ASSIGNMENT#{group_key}",
        "group_key": group_key,
        "assigned_by_sub": actor_sub,
        "assigned_at": ts,
    })
    _invalidate_permission_cache()
    audit_event("crm_acl_role.group_assigned", actor_sub, role_id=role_id, group_key=group_key)


def revoke_role_from_group(actor_sub: str, role_id: str, group_key: str) -> None:
    """Revoke an ACL role from a platform group. No-op if not assigned."""
    table = _get_table()
    audit_event = _get_alerts()

    table.delete_item(Key={"pk": _role_pk(role_id), "sk": f"GROUP_ASSIGNMENT#{group_key}"}),
    _invalidate_permission_cache()
    audit_event("crm_acl_role.group_revoked", actor_sub, role_id=role_id, group_key=group_key)


def list_group_assignments_for_role(role_id: str) -> list[dict]:
    """List all group assignment rows for a role."""
    from boto3.dynamodb.conditions import Key as DKey

    table = _get_table()
    items = []
    kwargs: dict[str, Any] = {
        "KeyConditionExpression": DKey("pk").eq(_role_pk(role_id))
        & DKey("sk").begins_with("GROUP_ASSIGNMENT#"),
    }
    while True:
        resp = table.query(**kwargs)
        items.extend(resp.get("Items", []))
        lek = resp.get("LastEvaluatedKey")
        if not lek:
            break
        kwargs["ExclusiveStartKey"] = lek
    return items


def list_role_assignments(role_id: str) -> dict:
    """Return all direct user and group assignments for a role."""
    # Verify role exists
    get_acl_role(role_id)

    user_rows = list_assignments_for_role(role_id)
    group_rows = list_group_assignments_for_role(role_id)

    user_assignments = [
        {
            "user_sub": r.get("user_sub", ""),
            "assigned_by_sub": r.get("assigned_by_sub", ""),
            "assigned_at": r.get("assigned_at", 0),
        }
        for r in user_rows
    ]
    group_assignments = [
        {
            "role_id": role_id,
            "group_key": r.get("group_key", ""),
            "assigned_by_sub": r.get("assigned_by_sub", ""),
            "assigned_at": r.get("assigned_at", 0),
        }
        for r in group_rows
    ]
    return {
        "role_id": role_id,
        "user_assignments": user_assignments,
        "group_assignments": group_assignments,
    }


def get_effective_roles_for_user(user_sub: str, admin_profile: Any = None) -> list[dict]:
    """
    Return all ACL role dicts applicable to a user (direct + group-propagated).

    admin_profile: AdminProfile dataclass from app.auth.roles.
    """
    from app.auth.roles import AdminProfile, AdminProfileType, CANONICAL_ADMIN_SCOPES

    if admin_profile is None:
        from app.auth.roles import AdminProfile as _AP
        admin_profile = _AP()

    # Direct assignments
    direct = get_roles_for_user(user_sub)
    seen_role_ids = {r["role_id"] for r in direct}

    # Determine group keys to evaluate
    if admin_profile.type == AdminProfileType.GENERAL:
        group_keys = [scope.value for scope in CANONICAL_ADMIN_SCOPES]
    else:
        group_keys = [scope.value for scope in (admin_profile.scopes or [])]

    if not group_keys:
        return direct

    # For each group key, find roles that have GROUP_ASSIGNMENT for that key.
    # Approach: scan all roles and check per-role.
    # This is O(roles × group_keys) DDB reads but roles are small (< 100).
    table = _get_table()
    from boto3.dynamodb.conditions import Attr

    all_meta_roles, _ = list_acl_roles(limit=1000)

    group_roles = []
    for role_item in all_meta_roles:
        rid = role_item.get("role_id", "")
        if rid in seen_role_ids:
            continue
        # Check if this role has any matching GROUP_ASSIGNMENT
        for gk in group_keys:
            resp = table.get_item(Key={"pk": _role_pk(rid), "sk": f"GROUP_ASSIGNMENT#{gk}"})
            if resp.get("Item"):
                group_roles.append(role_item)
                seen_role_ids.add(rid)
                break

    return direct + group_roles


# ---------------------------------------------------------------------------
# STU-002/003: Permission evaluation
# ---------------------------------------------------------------------------

def check_permission(
    user_sub: str,
    module: str,
    action: str,
    admin_profile: Any = None,
) -> bool:
    """
    Returns True if the user has the given action on the module.
    Short-circuits to True when crm_acl_enabled is False.
    ROOT/ADMIN bypass: returns True for admins/roots.
    """
    S = _get_settings()
    if not S.crm_acl_enabled:
        return True

    ts = now_ts()
    cache_key = user_sub
    cached = _perm_cache.get(cache_key)
    if cached:
        roles_list, fetched_ts = cached
        if ts - fetched_ts < _CACHE_TTL:
            return _eval_permission(roles_list, module, action)

    # Cache miss: fetch
    roles = get_effective_roles_for_user(user_sub, admin_profile)
    _perm_cache[cache_key] = (roles, ts)
    return _eval_permission(roles, module, action)


def _eval_permission(roles: list[dict], module: str, action: str) -> bool:
    """Union permission evaluation across a list of role dicts."""
    for role in roles:
        perms = role.get("permissions", {})
        if isinstance(perms, dict):
            module_perms = perms.get(module, {})
            if isinstance(module_perms, dict):
                # Handle alias: 'import_' stored as 'import_' or 'import'
                if action in ("import_", "import"):
                    if module_perms.get("import_", False) or module_perms.get("import", False):
                        return True
                elif module_perms.get(action, False):
                    return True
    return False


def require_crm_permission(module: str, action: str):
    """FastAPI Depends factory for CRM module-action permission enforcement."""

    async def _check(
        user: Any = Depends(_get_authenticated_user_dep()),
    ) -> None:
        S = _get_settings()
        if not S.crm_acl_enabled:
            return
        # ROOT and ADMIN always pass
        from app.auth.roles import Role
        from app.auth.roles import normalize_role
        role = normalize_role(getattr(user, "role", None))
        if role in (Role.ROOT, Role.ADMIN):
            return
        admin_profile = getattr(user, "admin_profile", None)
        if not check_permission(user.sub, module, action, admin_profile):
            raise HTTPException(403, {
                "code": "crm_permission_denied",
                "module": module,
                "action": action,
            })

    return Depends(_check)


def _get_authenticated_user_dep():
    from app.auth.deps import get_authenticated_user
    return get_authenticated_user
