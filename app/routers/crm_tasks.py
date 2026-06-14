"""
ACT-008 — CRM Tasks router.

Mounted at /ui/crm/tasks. Gated by S.crm_activities_enabled AND S.crm_tasks_enabled.
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from app.core.settings import S
from app.models import CrmTaskCreateIn, CrmTaskUpdateIn, CrmTaskOut, CrmTaskListOut
from app.services.crm_tasks import (
    create_task,
    list_tasks,
    get_task,
    update_task,
    delete_task,
)
from app.services.sessions import require_ui_session
from app.services.alerts import audit_event, write_alert

router = APIRouter(prefix="/ui/crm/tasks", tags=["crm-tasks"])


def _gate():
    if not (S.crm_activities_enabled and S.crm_tasks_enabled):
        raise HTTPException(status_code=404, detail="Not found")


@router.post("", response_model=CrmTaskOut, status_code=201)
async def create_crm_task(
    body: CrmTaskCreateIn,
    ctx=Depends(require_ui_session),
) -> CrmTaskOut:
    _gate()
    result = create_task(
        user_sub=ctx["user_sub"],
        subject=body.subject,
        description=body.description or "",
        status=body.status.value,
        priority=body.priority.value,
        due_date_ts=body.due_date_ts,
        assignee_sub=body.assignee_sub,
        linked_entity_type=body.linked_entity_type,
        linked_entity_id=body.linked_entity_id,
    )
    audit_event("crm_task_create", ctx["user_sub"], None, task_id=result["task_id"])
    # Notify assignee (best-effort)
    if body.assignee_sub and body.assignee_sub != ctx["user_sub"]:
        try:
            write_alert(
                body.assignee_sub,
                event="crm_task_assigned",
                outcome="info",
                title=f"You have been assigned a task: {body.subject}",
                details={"task_id": result["task_id"]},
            )
        except Exception:
            pass
    return CrmTaskOut(**result)


@router.get("", response_model=CrmTaskListOut)
async def list_crm_tasks(
    limit: int = Query(20, ge=1, le=100),
    cursor: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    ctx=Depends(require_ui_session),
) -> CrmTaskListOut:
    _gate()
    result = list_tasks(ctx["user_sub"], limit=limit, cursor=cursor, status_filter=status)
    return CrmTaskListOut(
        items=[CrmTaskOut(**i) for i in result["items"]],
        next_cursor=result.get("next_cursor"),
        count=result.get("count", len(result["items"])),
    )


@router.get("/{task_id}", response_model=CrmTaskOut)
async def get_crm_task(
    task_id: str,
    ctx=Depends(require_ui_session),
) -> CrmTaskOut:
    _gate()
    item = get_task(ctx["user_sub"], task_id)
    if not item:
        raise HTTPException(404, "Task not found")
    return CrmTaskOut(**item)


@router.patch("/{task_id}", response_model=CrmTaskOut)
async def update_crm_task(
    task_id: str,
    body: CrmTaskUpdateIn,
    ctx=Depends(require_ui_session),
) -> CrmTaskOut:
    _gate()
    result = update_task(
        user_sub=ctx["user_sub"],
        task_id=task_id,
        subject=body.subject,
        description=body.description,
        status=body.status.value if body.status else None,
        priority=body.priority.value if body.priority else None,
        due_date_ts=body.due_date_ts,
        assignee_sub=body.assignee_sub,
    )
    if not result:
        raise HTTPException(404, "Task not found")
    audit_event("crm_task_update", ctx["user_sub"], None, task_id=task_id)
    return CrmTaskOut(**result)


@router.delete("/{task_id}")
async def delete_crm_task(
    task_id: str,
    ctx=Depends(require_ui_session),
):
    _gate()
    deleted = delete_task(ctx["user_sub"], task_id)
    if not deleted:
        raise HTTPException(404, "Task not found")
    audit_event("crm_task_delete", ctx["user_sub"], None, task_id=task_id)
    return {"ok": True}
