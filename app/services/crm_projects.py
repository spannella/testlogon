"""CRM Project header CRUD — PRJ-002.

Owners: CRM project header entity.  Tables: T.crm_pm_projects.
"""
from __future__ import annotations

from decimal import Decimal
from typing import Any, Dict, List, Optional
from uuid import uuid4

from boto3.dynamodb.conditions import Attr, Key
from fastapi import HTTPException

from app.core.cursor import decode_cursor, encode_cursor
from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.models import (
    CrmProjectCreateIn,
    CrmProjectListResp,
    CrmProjectOut,
    CrmProjectStatus,
    CrmProjectUpdateIn,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _item_to_project(item: Dict[str, Any]) -> CrmProjectOut:
    """Convert a raw DynamoDB item to CrmProjectOut."""
    return CrmProjectOut(
        id=item["project_id"],
        owner_sub=item["owner_sub"],
        name=item["name"],
        description=item.get("description"),
        status=CrmProjectStatus(item["status"]),
        priority=int(item.get("priority", 0)),
        start_date=int(item["start_date"]) if item.get("start_date") is not None else None,
        end_date=int(item["end_date"]) if item.get("end_date") is not None else None,
        assigned_user_sub=item.get("assigned_user_sub"),
        account_id=item.get("account_id"),
        created_at=int(item["created_at"]),
        updated_at=int(item["updated_at"]),
    )


def _project_pk(owner_sub: str) -> str:
    return f"OWNER#{owner_sub}"


def _project_sk(project_id: str) -> str:
    return f"PROJECT#{project_id}"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def create_crm_project(
    owner_sub: str,
    name: str,
    *,
    description: Optional[str] = None,
    status: CrmProjectStatus = CrmProjectStatus.draft,
    priority: int = 0,
    start_date: Optional[int] = None,
    end_date: Optional[int] = None,
    assigned_user_sub: Optional[str] = None,
    account_id: Optional[str] = None,
) -> CrmProjectOut:
    """Create a new CRM project header."""
    # Date validation
    if start_date is not None and end_date is not None and end_date < start_date:
        raise HTTPException(status_code=400, detail={"code": "end_before_start"})

    project_id = uuid4().hex
    ts = now_ts()

    item: Dict[str, Any] = {
        "PK": _project_pk(owner_sub),
        "SK": _project_sk(project_id),
        "GSI1PK": f"PROJECT#{project_id}",
        "GSI1SK": f"OWNER#{owner_sub}",
        "GSI2PK": f"STATUS#{status.value}",
        "GSI2SK": ts,  # numeric — declared attr_types={"GSI2SK": "N"}
        "entity_type": "crm_project",
        "project_id": project_id,
        "owner_sub": owner_sub,
        "name": name.strip(),
        "status": status.value,
        "priority": priority,
        "created_at": ts,
        "updated_at": ts,
    }
    # Only store optional fields when non-None
    if description is not None:
        item["description"] = description
    if start_date is not None:
        item["start_date"] = start_date
    if end_date is not None:
        item["end_date"] = end_date
    if assigned_user_sub is not None:
        item["assigned_user_sub"] = assigned_user_sub
    if account_id is not None:
        item["account_id"] = account_id
        item["GSI3PK"] = f"ACCOUNT#{account_id}"
        item["GSI3SK"] = ts

    T.crm_pm_projects.put_item(
        Item=item,
        ConditionExpression="attribute_not_exists(PK) AND attribute_not_exists(SK)",
    )
    # Register the creator as the project owner member so they can manage
    # members / contact-links (membership-gated operations).
    from app.services.crm_project_members import bootstrap_owner
    bootstrap_owner(owner_sub, project_id)
    return _item_to_project(item)


def get_crm_project(owner_sub: str, project_id: str) -> CrmProjectOut:
    """Fetch a single CRM project, enforcing ownership."""
    resp = T.crm_pm_projects.query(
        IndexName="GSI1",
        KeyConditionExpression=Key("GSI1PK").eq(f"PROJECT#{project_id}"),
        Limit=1,
    )
    items = resp.get("Items", [])
    if not items:
        raise HTTPException(status_code=404, detail="crm_project_not_found")
    item = items[0]
    if item.get("owner_sub") != owner_sub:
        raise HTTPException(status_code=404, detail="crm_project_not_found")
    return _item_to_project(item)


def update_crm_project(
    owner_sub: str,
    project_id: str,
    updates: CrmProjectUpdateIn,
) -> CrmProjectOut:
    """Partial update of a CRM project header."""
    existing = get_crm_project(owner_sub, project_id)

    changed_fields = updates.model_fields_set
    if not changed_fields:
        return existing

    # Merge dates for end_before_start validation
    merged_start = updates.start_date if "start_date" in changed_fields else existing.start_date
    merged_end = updates.end_date if "end_date" in changed_fields else existing.end_date
    if merged_start is not None and merged_end is not None and merged_end < merged_start:
        raise HTTPException(status_code=400, detail={"code": "end_before_start"})

    ts = now_ts()
    set_parts: List[str] = ["#updated_at = :updated_at"]
    names: Dict[str, str] = {"#updated_at": "updated_at"}
    values: Dict[str, Any] = {":updated_at": ts}
    remove_parts: List[str] = []

    old_status = existing.status.value

    field_map = {
        "name": ("name", lambda v: v.strip() if v else v),
        "description": ("description", None),
        "status": ("status", lambda v: v.value if v else v),
        "priority": ("priority", None),
        "start_date": ("start_date", None),
        "end_date": ("end_date", None),
        "assigned_user_sub": ("assigned_user_sub", None),
        "account_id": ("account_id", None),
    }

    for field_name, (attr_name, transform) in field_map.items():
        if field_name not in changed_fields:
            continue
        val = getattr(updates, field_name)
        if transform:
            val = transform(val)
        safe_name = f"#{attr_name}"
        if val is None:
            remove_parts.append(safe_name)
            names[safe_name] = attr_name
        else:
            set_parts.append(f"{safe_name} = :{attr_name}")
            names[safe_name] = attr_name
            values[f":{attr_name}"] = val

    # When status changes, update GSI2PK
    new_status = updates.status.value if "status" in changed_fields and updates.status else old_status
    if "status" in changed_fields and updates.status and updates.status.value != old_status:
        set_parts.append("#gsi2pk = :gsi2pk")
        names["#gsi2pk"] = "GSI2PK"
        values[":gsi2pk"] = f"STATUS#{new_status}"
        # Emit audit event (best-effort)
        try:
            from app.services.alerts import audit_event  # local import avoids circular
            audit_event(
                "crm_project.updated",
                owner_sub,
                None,
                project_id=project_id,
                field="status",
                old_value=old_status,
                new_value=new_status,
            )
        except Exception:
            pass

    # GSI3 for account_id
    if "account_id" in changed_fields:
        new_account_id = updates.account_id
        if new_account_id:
            set_parts.append("#gsi3pk = :gsi3pk")
            set_parts.append("#gsi3sk = :gsi3sk")
            names["#gsi3pk"] = "GSI3PK"
            names["#gsi3sk"] = "GSI3SK"
            values[":gsi3pk"] = f"ACCOUNT#{new_account_id}"
            values[":gsi3sk"] = ts
        else:
            remove_parts.append("#gsi3pk")
            remove_parts.append("#gsi3sk")
            names["#gsi3pk"] = "GSI3PK"
            names["#gsi3sk"] = "GSI3SK"

    update_expr = "SET " + ", ".join(set_parts)
    if remove_parts:
        update_expr += " REMOVE " + ", ".join(remove_parts)

    T.crm_pm_projects.update_item(
        Key={"PK": _project_pk(owner_sub), "SK": _project_sk(project_id)},
        UpdateExpression=update_expr,
        ExpressionAttributeNames=names,
        ExpressionAttributeValues=values,
        ConditionExpression="attribute_exists(PK)",
    )
    return get_crm_project(owner_sub, project_id)


def delete_crm_project(owner_sub: str, project_id: str) -> Dict[str, bool]:
    """Delete a CRM project header (tasks cascade is handled by caller)."""
    existing = get_crm_project(owner_sub, project_id)  # enforces ownership
    T.crm_pm_projects.delete_item(
        Key={"PK": _project_pk(existing.owner_sub), "SK": _project_sk(project_id)},
        ConditionExpression="attribute_exists(PK) AND attribute_exists(SK)",
    )
    return {"ok": True}


def list_crm_projects(
    owner_sub: str,
    *,
    limit: int = 20,
    cursor: Optional[str] = None,
    status_filter: Optional[CrmProjectStatus] = None,
    name_query: Optional[str] = None,
) -> CrmProjectListResp:
    """List CRM projects owned by the caller."""
    limit = max(1, min(limit, 100))
    decoded_cursor = decode_cursor(cursor) if cursor else None

    items: List[CrmProjectOut] = []
    last_key = decoded_cursor

    if status_filter is not None:
        # GSI2 path: status-filtered
        while len(items) < limit:
            kwargs: Dict[str, Any] = {
                "IndexName": "GSI2",
                "KeyConditionExpression": Key("GSI2PK").eq(f"STATUS#{status_filter.value}"),
                "FilterExpression": Attr("owner_sub").eq(owner_sub),
                "Limit": limit * 3,
            }
            if last_key:
                kwargs["ExclusiveStartKey"] = last_key
            resp = T.crm_pm_projects.query(**kwargs)
            for raw in resp.get("Items", []):
                if raw.get("entity_type") == "crm_project":
                    if name_query and name_query.lower() not in raw.get("name", "").lower():
                        continue
                    items.append(_item_to_project(raw))
                    if len(items) >= limit:
                        break
            last_key = resp.get("LastEvaluatedKey")
            if not last_key:
                break
    else:
        # Primary index path: owner's projects
        while len(items) < limit:
            kwargs = {
                "KeyConditionExpression": (
                    Key("PK").eq(_project_pk(owner_sub))
                    & Key("SK").begins_with("PROJECT#")
                ),
                "ScanIndexForward": False,
                "Limit": limit,
            }
            if name_query:
                kwargs["FilterExpression"] = Attr("name").contains(name_query)
            if last_key:
                kwargs["ExclusiveStartKey"] = last_key
            resp = T.crm_pm_projects.query(**kwargs)
            for raw in resp.get("Items", []):
                if raw.get("entity_type") == "crm_project":
                    items.append(_item_to_project(raw))
                    if len(items) >= limit:
                        break
            last_key = resp.get("LastEvaluatedKey")
            if not last_key:
                break

    next_cursor = encode_cursor(last_key) if last_key else None
    return CrmProjectListResp(items=items, cursor=next_cursor)
