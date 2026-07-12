"""CRM Project Templates — PRJ-006.

Tables: T.crm_pm_templates, T.crm_pm_projects (via crm_projects), T.crm_pm_tasks (via crm_project_tasks).
"""
from __future__ import annotations

from decimal import Decimal
from typing import Any, Dict, List, Optional
from uuid import uuid4

from fastapi import HTTPException

from app.core.cursor import decode_cursor, encode_cursor
from app.core.tables import T
from app.core.time import now_ts
from app.models import (
    CrmProjectTemplateModel,
    CrmTemplateTaskDef,
    CrmTemplateListOut,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _template_pk(owner_sub: str) -> str:
    return f"OWNER#{owner_sub}"


def _template_sk(template_id: str) -> str:
    return f"TEMPLATE#{template_id}"


def _item_to_template(item: Dict[str, Any]) -> CrmProjectTemplateModel:
    raw_defs = item.get("task_defs") or []
    task_defs: List[CrmTemplateTaskDef] = []
    for td in raw_defs:
        task_defs.append(CrmTemplateTaskDef(
            template_task_id=td.get("template_task_id", ""),
            name=td.get("name", ""),
            description=td.get("description"),
            task_order=int(td.get("task_order", 0)),
            duration_days=int(td.get("duration_days", 1)),
            is_milestone=bool(td.get("is_milestone", False)),
            predecessor_template_task_ids=list(td.get("predecessor_template_task_ids") or []),
        ))
    return CrmProjectTemplateModel(
        id=item["template_id"],
        owner_sub=item["owner_sub"],
        name=item["name"],
        description=item.get("description"),
        task_defs=task_defs,
        created_at=int(item["created_at"]),
        updated_at=int(item["updated_at"]),
    )


def _task_def_to_dict(td: CrmTemplateTaskDef) -> Dict[str, Any]:
    d: Dict[str, Any] = {
        "template_task_id": td.template_task_id,
        "name": td.name,
        "task_order": td.task_order,
        "duration_days": td.duration_days,
        "is_milestone": td.is_milestone,
        "predecessor_template_task_ids": td.predecessor_template_task_ids,
    }
    if td.description is not None:
        d["description"] = td.description
    return d


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def create_template(
    owner_sub: str,
    name: str,
    *,
    description: Optional[str] = None,
    task_defs: Optional[List[CrmTemplateTaskDef]] = None,
) -> CrmProjectTemplateModel:
    """Create a new project template."""
    if task_defs is None:
        task_defs = []

    stripped_name = name.strip()
    if not stripped_name:
        raise HTTPException(status_code=422, detail="name cannot be blank")

    template_id = uuid4().hex
    ts = now_ts()

    item: Dict[str, Any] = {
        "PK": _template_pk(owner_sub),
        "SK": _template_sk(template_id),
        "GSI1PK": f"TEMPLATE#{template_id}",
        "GSI1SK": f"OWNER#{owner_sub}",
        "entity_type": "crm_template",
        "template_id": template_id,
        "owner_sub": owner_sub,
        "name": stripped_name,
        "task_defs": [_task_def_to_dict(td) for td in task_defs],
        "created_at": ts,
        "updated_at": ts,
    }
    if description is not None:
        item["description"] = description

    T.crm_pm_templates.put_item(
        Item=item,
        ConditionExpression="attribute_not_exists(PK) AND attribute_not_exists(SK)",
    )

    try:
        from app.services.alerts import audit_event
        audit_event(
            "crm_template.created",
            owner_sub,
            None,
            template_id=template_id,
            task_count=len(task_defs),
        )
    except Exception:
        pass

    return _item_to_template(item)


def get_template(owner_sub: str, template_id: str) -> CrmProjectTemplateModel:
    """Fetch a template by ID, enforcing ownership."""
    resp = T.crm_pm_templates.get_item(
        Key={
            "PK": _template_pk(owner_sub),
            "SK": _template_sk(template_id),
        },
        ConsistentRead=True,
    )
    item = resp.get("Item")
    if not item or item.get("entity_type") != "crm_template":
        raise HTTPException(status_code=404, detail="crm_template_not_found")
    return _item_to_template(item)


def list_templates(
    owner_sub: str,
    *,
    limit: int = 50,
    cursor: Optional[str] = None,
) -> CrmTemplateListOut:
    """List templates owned by the caller, newest first."""
    from boto3.dynamodb.conditions import Key
    limit = max(1, min(limit, 200))
    last_key = decode_cursor(cursor) if cursor else None

    items: List[CrmProjectTemplateModel] = []
    while len(items) < limit:
        kwargs: Dict[str, Any] = {
            "KeyConditionExpression": (
                Key("PK").eq(_template_pk(owner_sub))
                & Key("SK").begins_with("TEMPLATE#")
            ),
            "ScanIndexForward": False,
            "Limit": limit,
        }
        if last_key:
            kwargs["ExclusiveStartKey"] = last_key
        resp = T.crm_pm_templates.query(**kwargs)
        for raw in resp.get("Items", []):
            if raw.get("entity_type") == "crm_template":
                items.append(_item_to_template(raw))
                if len(items) >= limit:
                    break
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break

    next_cursor = encode_cursor(last_key) if last_key else None
    return CrmTemplateListOut(items=items, cursor=next_cursor)


def delete_template(owner_sub: str, template_id: str) -> Dict[str, bool]:
    """Delete a template."""
    # Check ownership first
    get_template(owner_sub, template_id)
    try:
        T.crm_pm_templates.delete_item(
            Key={
                "PK": _template_pk(owner_sub),
                "SK": _template_sk(template_id),
            },
            ConditionExpression="attribute_exists(PK) AND attribute_exists(SK)",
        )
    except Exception as e:
        if "ConditionalCheckFailed" in str(e):
            raise HTTPException(status_code=404, detail="crm_template_not_found")
        raise
    return {"ok": True}


def create_template_from_project(
    owner_sub: str,
    project_id: str,
    name: str,
    *,
    description: Optional[str] = None,
) -> CrmProjectTemplateModel:
    """Capture a project's task structure as a template."""
    from app.services.crm_projects import get_crm_project
    from app.services.crm_project_tasks import list_tasks

    get_crm_project(owner_sub, project_id)  # ownership check

    # Collect all tasks (loop through pagination)
    all_live_tasks = []
    cursor = None
    while True:
        result = list_tasks(owner_sub, project_id, limit=500, cursor=cursor)
        all_live_tasks.extend(result["items"])
        cursor = result["cursor"]
        if not cursor:
            break

    # Build live_task_id → template_task_id mapping
    id_map: Dict[str, str] = {t.id: uuid4().hex for t in all_live_tasks}

    # Sort by task_order
    all_live_tasks.sort(key=lambda t: t.task_order)

    task_defs: List[CrmTemplateTaskDef] = []
    for task in all_live_tasks:
        template_task_id = id_map[task.id]
        # Translate predecessor IDs to template IDs (silently drop cross-project refs)
        pred_template_ids = [
            id_map[pid] for pid in (task.predecessor_task_ids or [])
            if pid in id_map
        ]
        task_defs.append(CrmTemplateTaskDef(
            template_task_id=template_task_id,
            name=task.name,
            description=task.description,
            task_order=task.task_order,
            duration_days=task.duration_days,
            is_milestone=task.is_milestone,
            predecessor_template_task_ids=pred_template_ids,
        ))

    return create_template(owner_sub, name, description=description, task_defs=task_defs)


def instantiate_from_template(
    owner_sub: str,
    template_id: str,
    project_name: str,
    *,
    start_date: Optional[int] = None,
) -> Any:
    """Create a new CRM project from a template."""
    from app.services.crm_projects import create_crm_project
    from app.services.crm_project_tasks import create_task
    from app.models import CrmProjectStatus

    template = get_template(owner_sub, template_id)

    # Create the project header
    project = create_crm_project(
        owner_sub,
        project_name.strip(),
        status=CrmProjectStatus.draft,
    )

    # Sort task_defs by task_order
    sorted_defs = sorted(template.task_defs, key=lambda td: td.task_order)

    # Allocate new task IDs; build mapping template_task_id → new_task_id
    task_id_map: Dict[str, str] = {td.template_task_id: uuid4().hex for td in sorted_defs}

    # Compute sequential date offsets
    offset_days = 0
    for i, td in enumerate(sorted_defs):
        if i == 0:
            offset_days = 0
        else:
            offset_days += sorted_defs[i - 1].duration_days

        task_start = (start_date + offset_days * 86400) if start_date is not None else None

        # Translate predecessor template IDs to new task IDs
        pred_ids = [
            task_id_map[pid]
            for pid in td.predecessor_template_task_ids
            if pid in task_id_map
        ]

        create_task(
            owner_sub,
            project.id,
            td.name,
            task_id=task_id_map[td.template_task_id],
            task_order=td.task_order if td.task_order > 0 else (i + 1),
            duration_days=td.duration_days,
            start_date=task_start,
            description=td.description,
            is_milestone=td.is_milestone,
            predecessor_task_ids=pred_ids,
            skip_date_validation=True,  # allow date offsets that may not satisfy predecessor constraints
        )

    try:
        from app.services.alerts import audit_event
        audit_event(
            "crm_template.instantiated",
            owner_sub,
            None,
            template_id=template_id,
            project_id=project.id,
            task_count=len(sorted_defs),
        )
    except Exception:
        pass

    return project
