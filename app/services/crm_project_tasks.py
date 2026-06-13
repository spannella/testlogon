"""CRM Project Task CRUD, dependency validation, workload — PRJ-003/004/005.

Tables: T.crm_pm_tasks, T.crm_pm_projects (ownership check via crm_projects).
"""
from __future__ import annotations

from decimal import Decimal
from typing import Any, Dict, List, Optional
from uuid import uuid4

from boto3.dynamodb.conditions import Attr, Key
from fastapi import HTTPException

from app.core.cursor import decode_cursor, encode_cursor
from app.core.tables import T
from app.core.time import now_ts
from app.models import (
    CrmMilestoneSummaryItem,
    CrmMilestoneSummaryResp,
    CrmProjectResourceType,
    CrmProjectTaskModel,
    CrmProjectTaskListResp,
    CrmProjectWorkloadResp,
    CrmTaskWorkloadEntry,
)

_MILESTONE_SCAN_MULTIPLIER = 3


# ---------------------------------------------------------------------------
# Key helpers
# ---------------------------------------------------------------------------

def _task_pk(project_id: str) -> str:
    return f"PROJECT#{project_id}"


def _task_sk(task_order: int, task_id: str) -> str:
    return f"TASK#{task_order:06d}#{task_id}"


# ---------------------------------------------------------------------------
# Item conversion
# ---------------------------------------------------------------------------

def _item_to_task(item: Dict[str, Any]) -> CrmProjectTaskModel:
    """Convert raw DDB item → CrmProjectTaskModel."""
    pred_ids = item.get("predecessor_task_ids") or []
    # DDB may return a Set or List
    if hasattr(pred_ids, "__iter__") and not isinstance(pred_ids, (str, bytes)):
        pred_ids = list(pred_ids)
    else:
        pred_ids = []

    resource_type_raw = item.get("project_resource_type", "user")
    try:
        resource_type = CrmProjectResourceType(resource_type_raw)
    except ValueError:
        resource_type = CrmProjectResourceType.user

    return CrmProjectTaskModel(
        id=item["task_id"],
        project_id=item["project_id"],
        owner_sub=item["owner_sub"],
        name=item["name"],
        description=item.get("description"),
        task_order=int(item.get("task_order", 0)),
        duration_days=int(item.get("duration_days", 1)),
        start_date=int(item["start_date"]) if item.get("start_date") is not None else None,
        end_date=int(item["end_date"]) if item.get("end_date") is not None else None,
        percent_complete=int(item.get("percent_complete", 0)),
        is_milestone=bool(item.get("is_milestone", False)),
        assigned_user_sub=item.get("assigned_user_sub"),
        predecessor_task_ids=pred_ids,
        project_resource_type=resource_type,
        linked_contact_id=item.get("linked_contact_id"),
        created_at=int(item["created_at"]),
        updated_at=int(item["updated_at"]),
    )


def _task_to_item(
    task: CrmProjectTaskModel,
    project_id: str,
    owner_sub: str,
) -> Dict[str, Any]:
    """Build full DDB item (with GSI keys) from task model."""
    end_date_val = task.end_date if task.end_date is not None else 0
    if task.linked_contact_id and task.project_resource_type == CrmProjectResourceType.contact:
        gsi2pk = f"ASSIGNEE#contact#{task.linked_contact_id}"
    elif task.assigned_user_sub:
        gsi2pk = f"ASSIGNEE#{task.assigned_user_sub}"
    else:
        gsi2pk = "ASSIGNEE#unassigned"

    item: Dict[str, Any] = {
        "PK": _task_pk(project_id),
        "SK": _task_sk(task.task_order, task.id),
        "GSI1PK": f"TASK#{task.id}",
        "GSI1SK": f"PROJECT#{project_id}",
        "GSI2PK": gsi2pk,
        "GSI2SK": end_date_val,
        "entity_type": "crm_task",
        "task_id": task.id,
        "project_id": project_id,
        "owner_sub": owner_sub,
        "name": task.name,
        "task_order": task.task_order,
        "duration_days": task.duration_days,
        "percent_complete": task.percent_complete,
        "is_milestone": task.is_milestone,
        "predecessor_task_ids": task.predecessor_task_ids,
        "project_resource_type": task.project_resource_type.value,
        "created_at": task.created_at,
        "updated_at": task.updated_at,
    }
    # Optional fields: only store when set
    if task.description is not None:
        item["description"] = task.description
    if task.start_date is not None:
        item["start_date"] = task.start_date
    if task.end_date is not None:
        item["end_date"] = task.end_date
    if task.assigned_user_sub is not None:
        item["assigned_user_sub"] = task.assigned_user_sub
    if task.linked_contact_id is not None:
        item["linked_contact_id"] = task.linked_contact_id
    return item


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _max_task_order(project_id: str) -> int:
    """Return the highest existing task_order for the project (0 if none)."""
    resp = T.crm_pm_tasks.query(
        KeyConditionExpression=(
            Key("PK").eq(_task_pk(project_id))
            & Key("SK").begins_with("TASK#")
        ),
        ScanIndexForward=False,
        Limit=1,
    )
    items = resp.get("Items", [])
    if not items:
        return 0
    sk = items[0]["SK"]  # e.g. "TASK#000003#abc123"
    parts = sk.split("#")
    try:
        return int(parts[1])
    except (IndexError, ValueError):
        return 0


def _load_all_project_tasks(project_id: str) -> Dict[str, Dict[str, Any]]:
    """Load all tasks for a project (loop over LastEvaluatedKey)."""
    result: Dict[str, Dict[str, Any]] = {}
    last_key = None
    while True:
        kwargs: Dict[str, Any] = {
            "KeyConditionExpression": (
                Key("PK").eq(_task_pk(project_id))
                & Key("SK").begins_with("TASK#")
            ),
            "Limit": 1000,
        }
        if last_key:
            kwargs["ExclusiveStartKey"] = last_key
        resp = T.crm_pm_tasks.query(**kwargs)
        for item in resp.get("Items", []):
            tid = item.get("task_id")
            if tid:
                result[tid] = item
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break
    return result


def _detect_cycle(
    task_id: str,
    new_predecessors: List[str],
    all_tasks: Dict[str, Dict[str, Any]],
) -> Optional[str]:
    """DFS cycle detection. Returns cycle root task_id or None."""
    pred_map: Dict[str, List[str]] = {}
    for tid, item in all_tasks.items():
        preds = item.get("predecessor_task_ids") or []
        if hasattr(preds, "__iter__") and not isinstance(preds, (str, bytes)):
            pred_map[tid] = list(preds)
        else:
            pred_map[tid] = []
    pred_map[task_id] = list(new_predecessors)

    for start in new_predecessors:
        visited: set = set()
        stack = [start]
        while stack:
            current = stack.pop()
            if current == task_id:
                return start
            if current in visited:
                continue
            visited.add(current)
            stack.extend(pred_map.get(current) or [])
    return None


def _max_predecessor_end_date(
    predecessor_ids: List[str],
    all_tasks: Dict[str, Dict[str, Any]],
) -> Optional[tuple]:
    """Return (max_end_date, blocking_task_id) or None if no predecessor has end_date."""
    max_end: Optional[int] = None
    blocking_id: Optional[str] = None
    for pid in predecessor_ids:
        item = all_tasks.get(pid)
        if item and item.get("end_date") is not None:
            ed = int(item["end_date"])
            if max_end is None or ed > max_end:
                max_end = ed
                blocking_id = pid
    if max_end is None:
        return None
    return (max_end, blocking_id)


def _validate_predecessors(
    task_id: str,
    project_id: str,
    predecessor_task_ids: List[str],
    start_date: Optional[int],
    is_new_task: bool,
) -> None:
    """Validate predecessor constraints (same project, no cycle, date conflict)."""
    if not predecessor_task_ids:
        return
    all_tasks = _load_all_project_tasks(project_id)
    # Self-check included in cycle detection
    for pid in predecessor_task_ids:
        if pid not in all_tasks:
            raise HTTPException(
                status_code=400,
                detail={"code": "predecessor_not_found", "task_id": pid},
            )
    cycle_root = _detect_cycle(task_id, predecessor_task_ids, all_tasks)
    if cycle_root is not None:
        raise HTTPException(
            status_code=400,
            detail={"code": "circular_dependency", "cycle_root": cycle_root},
        )
    if start_date is not None:
        result = _max_predecessor_end_date(predecessor_task_ids, all_tasks)
        if result is not None:
            max_end, blocking_id = result
            if start_date < max_end:
                raise HTTPException(
                    status_code=400,
                    detail={
                        "code": "predecessor_date_conflict",
                        "blocking_task_id": blocking_id,
                    },
                )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def create_task(
    owner_sub: str,
    project_id: str,
    name: str,
    *,
    task_id: Optional[str] = None,
    task_order: int = 0,
    duration_days: int = 1,
    start_date: Optional[int] = None,
    end_date: Optional[int] = None,
    description: Optional[str] = None,
    assigned_user_sub: Optional[str] = None,
    is_milestone: bool = False,
    percent_complete: int = 0,
    predecessor_task_ids: Optional[List[str]] = None,
    project_resource_type: Optional[CrmProjectResourceType] = None,
    linked_contact_id: Optional[str] = None,
    skip_date_validation: bool = False,
) -> CrmProjectTaskModel:
    """Create a task in a CRM project."""
    from app.services.crm_projects import get_crm_project  # avoid circular at module level
    get_crm_project(owner_sub, project_id)  # ownership check / 404

    if predecessor_task_ids is None:
        predecessor_task_ids = []

    if task_order == 0:
        task_order = _max_task_order(project_id) + 1

    # Derive end_date from start_date + duration when not explicitly set
    if start_date is not None and end_date is None:
        end_date = start_date + duration_days * 86400

    # end_before_start validation (when not bypassed for template instantiation)
    if not skip_date_validation:
        if start_date is not None and end_date is not None and end_date < start_date:
            raise HTTPException(status_code=400, detail={"code": "end_before_start"})

    new_task_id = task_id if task_id else uuid4().hex
    ts = now_ts()

    # Resolve resource type
    if linked_contact_id and (project_resource_type is None or project_resource_type == CrmProjectResourceType.contact):
        resolved_resource_type = CrmProjectResourceType.contact
    else:
        resolved_resource_type = project_resource_type or CrmProjectResourceType.user

    task = CrmProjectTaskModel(
        id=new_task_id,
        project_id=project_id,
        owner_sub=owner_sub,
        name=name.strip(),
        description=description,
        task_order=task_order,
        duration_days=duration_days,
        start_date=start_date,
        end_date=end_date,
        percent_complete=percent_complete,
        is_milestone=is_milestone,
        assigned_user_sub=assigned_user_sub,
        predecessor_task_ids=predecessor_task_ids,
        project_resource_type=resolved_resource_type,
        linked_contact_id=linked_contact_id,
        created_at=ts,
        updated_at=ts,
    )

    # Predecessor validation (PRJ-004)
    if not skip_date_validation:
        _validate_predecessors(new_task_id, project_id, predecessor_task_ids, start_date, is_new_task=True)

    item = _task_to_item(task, project_id, owner_sub)
    T.crm_pm_tasks.put_item(
        Item=item,
        ConditionExpression="attribute_not_exists(PK) AND attribute_not_exists(SK)",
    )

    # Audit events (best-effort)
    if assigned_user_sub or linked_contact_id:
        assigned_id = linked_contact_id if resolved_resource_type == CrmProjectResourceType.contact else assigned_user_sub
        try:
            from app.services.alerts import audit_event
            audit_event(
                "crm_task.assigned",
                owner_sub,
                None,
                project_id=project_id,
                task_id=new_task_id,
                resource_type=resolved_resource_type.value,
                assigned_id=assigned_id,
            )
        except Exception:
            pass

    return task


def get_task(owner_sub: str, task_id: str, project_id: Optional[str] = None) -> CrmProjectTaskModel:
    """Fetch a single task by task_id, verifying ownership."""
    resp = T.crm_pm_tasks.query(
        IndexName="GSI1",
        KeyConditionExpression=Key("GSI1PK").eq(f"TASK#{task_id}"),
        Limit=1,
    )
    items = resp.get("Items", [])
    if not items or items[0].get("entity_type") != "crm_task":
        raise HTTPException(status_code=404, detail="crm_task_not_found")
    item = items[0]
    if item.get("owner_sub") != owner_sub:
        raise HTTPException(status_code=403, detail="crm_task_access_denied")
    # If project_id is provided, validate it matches
    if project_id and item.get("GSI1SK") != f"PROJECT#{project_id}":
        raise HTTPException(status_code=404, detail="crm_task_not_found")
    return _item_to_task(item)


def list_tasks(
    owner_sub: str,
    project_id: str,
    *,
    limit: int = 50,
    cursor: Optional[str] = None,
    milestones_only: bool = False,
) -> Dict[str, Any]:
    """List tasks for a project in ascending task_order."""
    from app.services.crm_projects import get_crm_project
    get_crm_project(owner_sub, project_id)  # authorization

    limit = max(1, min(limit, 200))
    last_key = decode_cursor(cursor) if cursor else None
    items: List[CrmProjectTaskModel] = []
    scan_limit = limit * _MILESTONE_SCAN_MULTIPLIER if milestones_only else limit

    while len(items) < limit:
        kwargs: Dict[str, Any] = {
            "KeyConditionExpression": (
                Key("PK").eq(_task_pk(project_id))
                & Key("SK").begins_with("TASK#")
            ),
            "ScanIndexForward": True,
            "Limit": scan_limit,
        }
        if milestones_only:
            kwargs["FilterExpression"] = Attr("is_milestone").eq(True)
        if last_key:
            kwargs["ExclusiveStartKey"] = last_key
        resp = T.crm_pm_tasks.query(**kwargs)
        for raw in resp.get("Items", []):
            if raw.get("entity_type") != "crm_task":
                continue
            items.append(_item_to_task(raw))
            if len(items) >= limit:
                break
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break

    next_cursor = encode_cursor(last_key) if last_key else None
    return {"items": items, "cursor": next_cursor}


def update_task(
    owner_sub: str,
    task_id: str,
    project_id: str,
    *,
    name: Optional[str] = None,
    description: Optional[str] = None,
    task_order: Optional[int] = None,
    duration_days: Optional[int] = None,
    start_date: Optional[int] = None,
    end_date: Optional[int] = None,
    percent_complete: Optional[int] = None,
    is_milestone: Optional[bool] = None,
    assigned_user_sub: Optional[str] = None,
    predecessor_task_ids: Optional[List[str]] = None,
    project_resource_type: Optional[CrmProjectResourceType] = None,
    linked_contact_id: Optional[str] = None,
    _fields_set: Optional[set] = None,
) -> CrmProjectTaskModel:
    """Partial update of a task."""
    existing = get_task(owner_sub, task_id, project_id)

    # Merge fields
    merged_name = name.strip() if name is not None else existing.name
    merged_description = description if (_fields_set and "description" in _fields_set) else existing.description
    merged_duration = duration_days if duration_days is not None else existing.duration_days
    merged_start = start_date if (_fields_set and "start_date" in _fields_set) else existing.start_date
    merged_end = end_date if (_fields_set and "end_date" in _fields_set) else existing.end_date
    merged_pc = percent_complete if percent_complete is not None else existing.percent_complete
    merged_milestone = is_milestone if is_milestone is not None else existing.is_milestone
    merged_assigned = assigned_user_sub if (_fields_set and "assigned_user_sub" in _fields_set) else existing.assigned_user_sub
    merged_preds = predecessor_task_ids if (_fields_set and "predecessor_task_ids" in _fields_set) else existing.predecessor_task_ids
    merged_resource_type = project_resource_type if project_resource_type is not None else existing.project_resource_type
    merged_contact = linked_contact_id if (_fields_set and "linked_contact_id" in _fields_set) else existing.linked_contact_id
    merged_order = task_order if task_order is not None else existing.task_order

    # Derive end_date from start/duration when not explicitly given
    if (_fields_set and ("start_date" in _fields_set or "duration_days" in _fields_set)) and "end_date" not in (_fields_set or set()):
        if merged_start is not None:
            merged_end = merged_start + merged_duration * 86400

    # end_before_start
    if merged_start is not None and merged_end is not None and merged_end < merged_start:
        raise HTTPException(status_code=400, detail={"code": "end_before_start"})

    # Predecessor validation
    if _fields_set and "predecessor_task_ids" in _fields_set and merged_preds is not None:
        _validate_predecessors(task_id, existing.project_id, merged_preds, merged_start, is_new_task=False)
        if merged_preds != existing.predecessor_task_ids:
            try:
                from app.services.alerts import audit_event
                audit_event(
                    "crm_task.dependency_set",
                    owner_sub,
                    None,
                    project_id=existing.project_id,
                    task_id=task_id,
                    predecessor_count=len(merged_preds),
                )
            except Exception:
                pass

    ts = now_ts()

    # Detect completion transition
    was_complete = existing.percent_complete >= 100
    now_complete = merged_pc >= 100

    if merged_order != existing.task_order:
        # SK rewrite via TransactWriteItems
        old_sk = _task_sk(existing.task_order, task_id)
        new_sk = _task_sk(merged_order, task_id)
        if old_sk != new_sk:
            end_date_val = merged_end if merged_end is not None else 0
            if merged_contact and merged_resource_type == CrmProjectResourceType.contact:
                gsi2pk = f"ASSIGNEE#contact#{merged_contact}"
            elif merged_assigned:
                gsi2pk = f"ASSIGNEE#{merged_assigned}"
            else:
                gsi2pk = "ASSIGNEE#unassigned"

            new_item: Dict[str, Any] = {
                "PK": _task_pk(existing.project_id),
                "SK": new_sk,
                "GSI1PK": f"TASK#{task_id}",
                "GSI1SK": f"PROJECT#{existing.project_id}",
                "GSI2PK": gsi2pk,
                "GSI2SK": end_date_val,
                "entity_type": "crm_task",
                "task_id": task_id,
                "project_id": existing.project_id,
                "owner_sub": owner_sub,
                "name": merged_name,
                "task_order": merged_order,
                "duration_days": merged_duration,
                "percent_complete": merged_pc,
                "is_milestone": merged_milestone,
                "predecessor_task_ids": merged_preds or [],
                "project_resource_type": merged_resource_type.value,
                "created_at": existing.created_at,
                "updated_at": ts,
            }
            if merged_description is not None:
                new_item["description"] = merged_description
            if merged_start is not None:
                new_item["start_date"] = merged_start
            if merged_end is not None:
                new_item["end_date"] = merged_end
            if merged_assigned is not None:
                new_item["assigned_user_sub"] = merged_assigned
            if merged_contact is not None:
                new_item["linked_contact_id"] = merged_contact

            try:
                # Two-phase: delete old then put new (avoids transact_write_items raw DDB JSON complexity)
                T.crm_pm_tasks.delete_item(
                    Key={"PK": _task_pk(existing.project_id), "SK": old_sk},
                    ConditionExpression="attribute_exists(PK) AND attribute_exists(SK)",
                )
                T.crm_pm_tasks.put_item(
                    Item=new_item,
                    ConditionExpression="attribute_not_exists(PK) AND attribute_not_exists(SK)",
                )
            except Exception as e:
                if "ConditionalCheckFailed" in str(e):
                    raise HTTPException(status_code=409, detail="task_order_conflict")
                raise

            # Emit audit event if just completed
            if not was_complete and now_complete:
                try:
                    from app.services.alerts import audit_event
                    audit_event(
                        "crm_task.completed",
                        owner_sub,
                        None,
                        task_id=task_id,
                        project_id=existing.project_id,
                    )
                except Exception:
                    pass

            return get_task(owner_sub, task_id)
    else:
        # Standard update_item
        end_date_val = merged_end if merged_end is not None else 0
        if merged_contact and merged_resource_type == CrmProjectResourceType.contact:
            gsi2pk = f"ASSIGNEE#contact#{merged_contact}"
        elif merged_assigned:
            gsi2pk = f"ASSIGNEE#{merged_assigned}"
        else:
            gsi2pk = "ASSIGNEE#unassigned"

        set_parts = [
            "#name = :name",
            "#task_order = :task_order",
            "#duration_days = :duration_days",
            "#percent_complete = :percent_complete",
            "#is_milestone = :is_milestone",
            "#predecessor_task_ids = :predecessor_task_ids",
            "#project_resource_type = :project_resource_type",
            "#gsi2pk = :gsi2pk",
            "#gsi2sk = :gsi2sk",
            "#updated_at = :updated_at",
        ]
        names: Dict[str, str] = {
            "#name": "name",
            "#task_order": "task_order",
            "#duration_days": "duration_days",
            "#percent_complete": "percent_complete",
            "#is_milestone": "is_milestone",
            "#predecessor_task_ids": "predecessor_task_ids",
            "#project_resource_type": "project_resource_type",
            "#gsi2pk": "GSI2PK",
            "#gsi2sk": "GSI2SK",
            "#updated_at": "updated_at",
        }
        values: Dict[str, Any] = {
            ":name": merged_name,
            ":task_order": merged_order,
            ":duration_days": merged_duration,
            ":percent_complete": merged_pc,
            ":is_milestone": merged_milestone,
            ":predecessor_task_ids": merged_preds or [],
            ":project_resource_type": merged_resource_type.value,
            ":gsi2pk": gsi2pk,
            ":gsi2sk": end_date_val,
            ":updated_at": ts,
        }
        remove_parts: List[str] = []

        # Description
        if merged_description is not None:
            set_parts.append("#description = :description")
            names["#description"] = "description"
            values[":description"] = merged_description
        elif _fields_set and "description" in _fields_set:
            remove_parts.append("#description")
            names["#description"] = "description"

        # start_date
        if merged_start is not None:
            set_parts.append("#start_date = :start_date")
            names["#start_date"] = "start_date"
            values[":start_date"] = merged_start
        elif _fields_set and "start_date" in _fields_set:
            remove_parts.append("#start_date")
            names["#start_date"] = "start_date"

        # end_date
        if merged_end is not None:
            set_parts.append("#end_date = :end_date")
            names["#end_date"] = "end_date"
            values[":end_date"] = merged_end
        elif _fields_set and "end_date" in _fields_set:
            remove_parts.append("#end_date")
            names["#end_date"] = "end_date"

        # assigned_user_sub
        if merged_assigned is not None:
            set_parts.append("#assigned_user_sub = :assigned_user_sub")
            names["#assigned_user_sub"] = "assigned_user_sub"
            values[":assigned_user_sub"] = merged_assigned
        elif _fields_set and "assigned_user_sub" in _fields_set:
            remove_parts.append("#assigned_user_sub")
            names["#assigned_user_sub"] = "assigned_user_sub"

        # linked_contact_id
        if merged_contact is not None:
            set_parts.append("#linked_contact_id = :linked_contact_id")
            names["#linked_contact_id"] = "linked_contact_id"
            values[":linked_contact_id"] = merged_contact
        elif _fields_set and "linked_contact_id" in _fields_set:
            remove_parts.append("#linked_contact_id")
            names["#linked_contact_id"] = "linked_contact_id"

        update_expr = "SET " + ", ".join(set_parts)
        if remove_parts:
            update_expr += " REMOVE " + ", ".join(remove_parts)

        T.crm_pm_tasks.update_item(
            Key={
                "PK": _task_pk(existing.project_id),
                "SK": _task_sk(existing.task_order, task_id),
            },
            UpdateExpression=update_expr,
            ExpressionAttributeNames=names,
            ExpressionAttributeValues=values,
            ConditionExpression="attribute_exists(PK)",
        )

        # Emit audit event if just completed
        if not was_complete and now_complete:
            try:
                from app.services.alerts import audit_event
                audit_event(
                    "crm_task.completed",
                    owner_sub,
                    None,
                    task_id=task_id,
                    project_id=existing.project_id,
                )
            except Exception:
                pass

        return get_task(owner_sub, task_id)


def delete_task(owner_sub: str, task_id: str, project_id: str) -> Dict[str, bool]:
    """Delete a task."""
    task = get_task(owner_sub, task_id, project_id)
    T.crm_pm_tasks.delete_item(
        Key={
            "PK": _task_pk(task.project_id),
            "SK": _task_sk(task.task_order, task_id),
        },
        ConditionExpression="attribute_exists(PK) AND attribute_exists(SK)",
    )
    try:
        from app.services.alerts import audit_event
        audit_event(
            "crm_task.deleted",
            owner_sub,
            None,
            task_id=task_id,
            project_id=task.project_id,
            name=task.name,
        )
    except Exception:
        pass
    return {"ok": True}


def reorder_tasks(
    owner_sub: str,
    project_id: str,
    task_ids: List[str],
) -> List[CrmProjectTaskModel]:
    """Reorder tasks by re-assigning task_order from position in task_ids list."""
    from app.services.crm_projects import get_crm_project
    get_crm_project(owner_sub, project_id)

    # Load all current tasks
    all_tasks_resp = list_tasks(owner_sub, project_id, limit=1000)
    existing_tasks = {t.id: t for t in all_tasks_resp["items"]}

    if set(task_ids) != set(existing_tasks.keys()):
        raise HTTPException(status_code=400, detail="reorder_task_ids_mismatch")

    ts = now_ts()

    # Two-phase: first delete all old SKs, then put all new items
    # (avoids SK conflicts when two tasks swap positions)
    rewrites: List[tuple] = []
    for new_index, tid in enumerate(task_ids):
        new_order = new_index + 1
        task = existing_tasks[tid]
        if task.task_order != new_order:
            rewrites.append((task, new_order))

    # Phase 1: delete old items
    for task, new_order in rewrites:
        old_sk = _task_sk(task.task_order, task.id)
        T.crm_pm_tasks.delete_item(
            Key={"PK": _task_pk(project_id), "SK": old_sk}
        )

    # Phase 2: put new items
    for task, new_order in rewrites:
        new_sk = _task_sk(new_order, task.id)
        end_date_val = task.end_date if task.end_date is not None else 0
        if task.linked_contact_id and task.project_resource_type == CrmProjectResourceType.contact:
            gsi2pk = f"ASSIGNEE#contact#{task.linked_contact_id}"
        elif task.assigned_user_sub:
            gsi2pk = f"ASSIGNEE#{task.assigned_user_sub}"
        else:
            gsi2pk = "ASSIGNEE#unassigned"

        new_item: Dict[str, Any] = {
            "PK": _task_pk(project_id),
            "SK": new_sk,
            "GSI1PK": f"TASK#{task.id}",
            "GSI1SK": f"PROJECT#{project_id}",
            "GSI2PK": gsi2pk,
            "GSI2SK": end_date_val,
            "entity_type": "crm_task",
            "task_id": task.id,
            "project_id": project_id,
            "owner_sub": owner_sub,
            "name": task.name,
            "task_order": new_order,
            "duration_days": task.duration_days,
            "percent_complete": task.percent_complete,
            "is_milestone": task.is_milestone,
            "predecessor_task_ids": task.predecessor_task_ids,
            "project_resource_type": task.project_resource_type.value,
            "created_at": task.created_at,
            "updated_at": ts,
        }
        if task.description is not None:
            new_item["description"] = task.description
        if task.start_date is not None:
            new_item["start_date"] = task.start_date
        if task.end_date is not None:
            new_item["end_date"] = task.end_date
        if task.assigned_user_sub is not None:
            new_item["assigned_user_sub"] = task.assigned_user_sub
        if task.linked_contact_id is not None:
            new_item["linked_contact_id"] = task.linked_contact_id

        T.crm_pm_tasks.put_item(Item=new_item)

    # Return tasks in new order
    result_resp = list_tasks(owner_sub, project_id, limit=1000)
    return result_resp["items"]


def get_project_workload(owner_sub: str, project_id: str) -> CrmProjectWorkloadResp:
    """Aggregate per-assignee task counts and overdue counts."""
    from app.services.crm_projects import get_crm_project
    get_crm_project(owner_sub, project_id)

    all_tasks_map = _load_all_project_tasks(project_id)
    ts = now_ts()

    groups: Dict[str, Dict[str, Any]] = {}
    for item in all_tasks_map.values():
        gsi2pk = item.get("GSI2PK", "ASSIGNEE#unassigned")
        if gsi2pk == "ASSIGNEE#unassigned":
            continue
        if gsi2pk not in groups:
            groups[gsi2pk] = {"task_count": 0, "overdue_count": 0}
        groups[gsi2pk]["task_count"] += 1
        end_date = item.get("end_date")
        pc = int(item.get("percent_complete", 0))
        if end_date is not None and int(end_date) <= ts and pc < 100:
            groups[gsi2pk]["overdue_count"] += 1

    entries: List[CrmTaskWorkloadEntry] = []
    for gsi2pk, counts in groups.items():
        # Parse prefix
        if gsi2pk.startswith("ASSIGNEE#contact#"):
            contact_id = gsi2pk[len("ASSIGNEE#contact#"):]
            entries.append(CrmTaskWorkloadEntry(
                assignee_key=gsi2pk,
                resource_type=CrmProjectResourceType.contact,
                assigned_id=contact_id,
                task_count=counts["task_count"],
                overdue_count=counts["overdue_count"],
            ))
        elif gsi2pk.startswith("ASSIGNEE#"):
            user_sub = gsi2pk[len("ASSIGNEE#"):]
            entries.append(CrmTaskWorkloadEntry(
                assignee_key=gsi2pk,
                resource_type=CrmProjectResourceType.user,
                assigned_id=user_sub,
                task_count=counts["task_count"],
                overdue_count=counts["overdue_count"],
            ))

    entries.sort(key=lambda e: e.task_count, reverse=True)
    return CrmProjectWorkloadResp(project_id=project_id, entries=entries)


def get_milestone_summary(
    owner_sub: str,
    project_id: str,
    *,
    limit: int = 50,
    cursor: Optional[str] = None,
) -> Dict[str, Any]:
    """Return milestone tasks enriched with on_track/overdue flags."""
    from app.services.crm_projects import get_crm_project
    get_crm_project(owner_sub, project_id)

    limit = max(1, min(limit, 200))
    tasks_resp = list_tasks(owner_sub, project_id, limit=limit, cursor=cursor, milestones_only=True)
    milestone_tasks: List[CrmProjectTaskModel] = tasks_resp["items"]
    next_cursor = tasks_resp["cursor"]

    ts = now_ts()
    items: List[CrmMilestoneSummaryItem] = []
    overdue_count = 0
    on_track_count = 0
    no_date_count = 0

    for task in milestone_tasks:
        has_end_date = task.end_date is not None
        completed = task.percent_complete >= 100

        if not has_end_date:
            on_track = False
            overdue = False
            no_date_count += 1
        elif completed:
            on_track = False
            overdue = False
        elif task.end_date > ts:
            on_track = True
            overdue = False
            on_track_count += 1
        else:
            on_track = False
            overdue = True
            overdue_count += 1

        items.append(CrmMilestoneSummaryItem(
            id=task.id,
            project_id=task.project_id,
            name=task.name,
            task_order=task.task_order,
            start_date=task.start_date,
            end_date=task.end_date,
            percent_complete=task.percent_complete,
            on_track=on_track,
            overdue=overdue,
            created_at=task.created_at,
            updated_at=task.updated_at,
        ))

    # Audit event (best-effort)
    try:
        from app.services.alerts import audit_event
        audit_event(
            "crm_milestone.summary_viewed",
            owner_sub,
            None,
            project_id=project_id,
            page_size=len(items),
        )
    except Exception:
        pass

    return {
        "items": items,
        "cursor": next_cursor,
        "total_milestones": len(items),
        "overdue_count": overdue_count,
        "on_track_count": on_track_count,
        "no_date_count": no_date_count,
    }


# ---------------------------------------------------------------------------
# DDB type serialization helper for transact_write_items raw API calls
# ---------------------------------------------------------------------------

def _python_to_ddb(value: Any) -> Dict[str, Any]:
    """Convert a Python value to a DynamoDB attribute value dict."""
    if isinstance(value, bool):
        return {"BOOL": value}
    if isinstance(value, int):
        return {"N": str(value)}
    if isinstance(value, float):
        return {"N": str(value)}
    if isinstance(value, Decimal):
        return {"N": str(value)}
    if isinstance(value, str):
        return {"S": value}
    if isinstance(value, list):
        if not value:
            return {"L": []}
        return {"L": [_python_to_ddb(v) for v in value]}
    if isinstance(value, dict):
        return {"M": {k: _python_to_ddb(v) for k, v in value.items()}}
    if value is None:
        return {"NULL": True}
    return {"S": str(value)}
