"""CRM Security Groups — record-level access control.

STU-004: Group CRUD, membership management, record assignment, enforcement.
"""
from __future__ import annotations

import logging
from typing import Any
from uuid import uuid4

from fastapi import HTTPException

from app.auth.roles import Role
from app.core.cursor import encode_cursor, decode_cursor
from app.core.time import now_ts

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Cache
# ---------------------------------------------------------------------------
_MEMBER_CACHE_TTL_SECONDS = 30
_member_cache: dict[str, tuple[list[str], int]] = {}  # user_sub -> (group_ids, fetched_ts)


def _invalidate_member_cache(user_sub: str) -> None:
    _member_cache[user_sub] = ([], 0)


# ---------------------------------------------------------------------------
# DDB key helpers
# ---------------------------------------------------------------------------

def _group_pk(group_id: str) -> str:
    return f"GROUP#{group_id}"


def _meta_key(group_id: str) -> dict:
    return {"pk": _group_pk(group_id), "sk": "META"}


def _member_sk(user_sub: str) -> str:
    return f"MEMBER#{user_sub}"


def _record_sk(entity_type: str, record_id: str) -> str:
    return f"RECORD#{entity_type}#{record_id}"


def _record_ref(entity_type: str, record_id: str) -> str:
    return f"{entity_type}#{record_id}"


def _get_table():
    from app.core.tables import T
    return T.crm_security_groups


def _audit(event: str, actor_sub: str, **kwargs: Any) -> None:
    try:
        from app.services.alerts import audit_event
        audit_event(event, actor_sub, **kwargs)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Group CRUD
# ---------------------------------------------------------------------------

def create_group(
    actor_sub: str,
    name: str,
    description: str,
    is_global: bool = False,
) -> dict:
    """Create a CRM security group. Returns the group dict."""
    table = _get_table()
    group_id = "grp_" + uuid4().hex[:12]
    ts = now_ts()
    item = {
        "pk": _group_pk(group_id),
        "sk": "META",
        "group_id": group_id,
        "name": name,
        "description": description,
        "owner_sub": actor_sub,
        "created_at": ts,
        "is_global": is_global,
    }
    from boto3.dynamodb.conditions import Attr
    table.put_item(
        Item=item,
        ConditionExpression=Attr("pk").not_exists(),
    )
    _audit("crm_sg.group.created", actor_sub, group_id=group_id, name=name)
    return item


def get_group(group_id: str) -> dict | None:
    """Return the META item or None if absent."""
    table = _get_table()
    resp = table.get_item(Key=_meta_key(group_id))
    return resp.get("Item")


def list_groups(
    *,
    limit: int = 50,
    cursor: str | None = None,
    is_global: bool | None = None,
) -> tuple[list[dict], str | None]:
    """Scan for META rows. Returns (items, next_cursor)."""
    from boto3.dynamodb.conditions import Attr

    table = _get_table()
    filter_expr = Attr("sk").eq("META")
    kwargs: dict[str, Any] = {
        "FilterExpression": filter_expr,
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

    # Apply is_global filter in-process
    if is_global is not None:
        items = [i for i in items if bool(i.get("is_global", False)) == is_global]

    return items, next_cursor


def delete_group(actor_sub: str, group_id: str) -> None:
    """Delete group META + all MEMBER# + RECORD# rows."""
    from boto3.dynamodb.conditions import Key as DKey

    table = _get_table()

    # Verify existence
    meta = get_group(group_id)
    if not meta:
        raise HTTPException(404, {"code": "crm_sg_not_found", "group_id": group_id})

    # Collect all rows
    pk = _group_pk(group_id)
    items_to_delete = []
    kwargs: dict[str, Any] = {
        "KeyConditionExpression": DKey("pk").eq(pk),
    }
    while True:
        resp = table.query(**kwargs)
        for item in resp.get("Items", []):
            items_to_delete.append({"pk": item["pk"], "sk": item["sk"]})
        lek = resp.get("LastEvaluatedKey")
        if not lek:
            break
        kwargs["ExclusiveStartKey"] = lek

    with table.batch_writer() as batch:
        for key in items_to_delete:
            batch.delete_item(Key=key)

    _audit("crm_sg.group.deleted", actor_sub, group_id=group_id)


# ---------------------------------------------------------------------------
# Membership
# ---------------------------------------------------------------------------

def add_member(
    actor_sub: str,
    group_id: str,
    user_sub: str,
    can_edit: bool = False,
) -> None:
    """Add a member to a group. Idempotent."""
    table = _get_table()
    ts = now_ts()
    table.put_item(Item={
        "pk": _group_pk(group_id),
        "sk": _member_sk(user_sub),
        "user_sub": user_sub,
        "added_by_sub": actor_sub,
        "added_at": ts,
        "can_edit": can_edit,
    })
    _invalidate_member_cache(user_sub)
    _audit("crm_sg.member.added", actor_sub, group_id=group_id, user_sub=user_sub)


def remove_member(actor_sub: str, group_id: str, user_sub: str) -> None:
    """Remove a member from a group. No-op if absent."""
    table = _get_table()
    table.delete_item(Key={"pk": _group_pk(group_id), "sk": _member_sk(user_sub)})
    _invalidate_member_cache(user_sub)
    _audit("crm_sg.member.removed", actor_sub, group_id=group_id, user_sub=user_sub)


# ---------------------------------------------------------------------------
# Record assignment
# ---------------------------------------------------------------------------

def assign_record(
    actor_sub: str,
    group_id: str,
    entity_type: str,
    record_id: str,
) -> None:
    """Assign a CRM record to a security group. Idempotent."""
    table = _get_table()
    ts = now_ts()
    table.put_item(Item={
        "pk": _group_pk(group_id),
        "sk": _record_sk(entity_type, record_id),
        "entity_type": entity_type,
        "record_id": record_id,
        "record_ref": _record_ref(entity_type, record_id),
        "assigned_by_sub": actor_sub,
        "created_at": ts,
    })
    _audit("crm_sg.record.assigned", actor_sub, group_id=group_id, entity_type=entity_type, record_id=record_id)


def unassign_record(
    actor_sub: str,
    group_id: str,
    entity_type: str,
    record_id: str,
) -> None:
    """Remove a CRM record from a security group. No-op if absent."""
    table = _get_table()
    table.delete_item(Key={"pk": _group_pk(group_id), "sk": _record_sk(entity_type, record_id)})
    _audit("crm_sg.record.unassigned", actor_sub, group_id=group_id, entity_type=entity_type, record_id=record_id)


# ---------------------------------------------------------------------------
# Lookups
# ---------------------------------------------------------------------------

def get_groups_for_record(entity_type: str, record_id: str) -> list[str]:
    """
    Query by-record GSI. Returns list of group_ids.
    Empty list → open access.
    """
    from boto3.dynamodb.conditions import Key as DKey

    table = _get_table()
    ref = _record_ref(entity_type, record_id)
    resp = table.query(
        IndexName="by-record",
        KeyConditionExpression=DKey("record_ref").eq(ref),
    )
    group_ids = []
    for item in resp.get("Items", []):
        # Extract group_id from pk "GROUP#{group_id}"
        pk = item.get("pk", "")
        if pk.startswith("GROUP#"):
            group_ids.append(pk[6:])
    return group_ids


def get_member_group_ids(user_sub: str) -> list[str]:
    """
    Scan for all MEMBER#{user_sub} rows. Cached per-user for 30s.
    Returns list of group_ids.
    """
    ts = now_ts()
    cached = _member_cache.get(user_sub)
    if cached:
        ids, fetched_ts = cached
        if ts - fetched_ts < _MEMBER_CACHE_TTL_SECONDS and fetched_ts > 0:
            return ids

    # DDB scan (acceptable for low group counts)
    from boto3.dynamodb.conditions import Attr
    table = _get_table()

    target_sk = f"MEMBER#{user_sub}"
    group_ids = []
    kwargs: dict[str, Any] = {
        "FilterExpression": Attr("sk").eq(target_sk),
    }
    while True:
        resp = table.scan(**kwargs)
        for item in resp.get("Items", []):
            pk = item.get("pk", "")
            if pk.startswith("GROUP#"):
                group_ids.append(pk[6:])
        lek = resp.get("LastEvaluatedKey")
        if not lek:
            break
        kwargs["ExclusiveStartKey"] = lek

    _member_cache[user_sub] = (group_ids, ts)
    return group_ids


# ---------------------------------------------------------------------------
# Enforcement
# ---------------------------------------------------------------------------

def user_can_access_record(
    user_sub: str,
    entity_type: str,
    record_id: str,
    *,
    role: Role = Role.USER,
) -> bool:
    """
    Core enforcement predicate. Fail-open on DDB error.

    Returns True when ANY of:
    (a) S.crm_acl_enabled is False
    (b) role is ADMIN or ROOT
    (c) get_groups_for_record(...) is empty (open access)
    (d) any group_id from get_groups_for_record is in get_member_group_ids(user_sub)
    """
    from app.core.settings import S as _S
    if not _S.crm_acl_enabled:
        return True

    from app.auth.roles import normalize_role, Role as R
    normalized_role = normalize_role(role)
    if normalized_role in (R.ADMIN, R.ROOT):
        return True

    try:
        group_ids = get_groups_for_record(entity_type, record_id)
        if not group_ids:
            return True  # open access

        member_ids = set(get_member_group_ids(user_sub))
        return bool(set(group_ids) & member_ids)
    except Exception as exc:
        logger.warning("crm_sg: fail-open on DDB error: %s", exc)
        return True


def filter_records_by_access(
    user_sub: str,
    entity_type: str,
    records: list[dict],
    *,
    role: Role = Role.USER,
    record_id_field: str = "ticket_id",
) -> list[dict]:
    """
    Post-filter a list of records by CRM security group membership.
    When crm_acl_enabled is False, returns records unmodified.
    """
    from app.core.settings import S as _S
    if not _S.crm_acl_enabled:
        return records

    return [
        r for r in records
        if user_can_access_record(
            user_sub, entity_type, r.get(record_id_field, ""), role=role
        )
    ]


# ---------------------------------------------------------------------------
# Detail view helper
# ---------------------------------------------------------------------------

def get_group_with_detail(group_id: str) -> dict | None:
    """
    Return group META + members + records.
    Returns None if META missing.
    """
    from boto3.dynamodb.conditions import Key as DKey

    table = _get_table()
    pk = _group_pk(group_id)

    all_items = []
    kwargs: dict[str, Any] = {"KeyConditionExpression": DKey("pk").eq(pk)}
    while True:
        resp = table.query(**kwargs)
        all_items.extend(resp.get("Items", []))
        lek = resp.get("LastEvaluatedKey")
        if not lek:
            break
        kwargs["ExclusiveStartKey"] = lek

    meta = None
    members = []
    records = []
    for item in all_items:
        sk = item.get("sk", "")
        if sk == "META":
            meta = item
        elif sk.startswith("MEMBER#"):
            members.append(item)
        elif sk.startswith("RECORD#"):
            records.append(item)

    if not meta:
        return None

    meta["member_count"] = len(members)
    meta["record_count"] = len(records)
    return {"meta": meta, "members": members, "records": records}
