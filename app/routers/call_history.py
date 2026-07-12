"""
Call History router — GET / DELETE for user call log records.
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from app.models import CallRecordIn, CallRecordOut, CallHistoryResponse, CallStatsOut
from app.services.call_history import (
    record_call,
    list_call_history,
    get_call_detail,
    delete_call_record,
    get_call_stats,
)
from app.services.sessions import require_ui_session

router = APIRouter(prefix="/ui/calls", tags=["call-history"])


@router.get("/history", response_model=CallHistoryResponse)
async def ui_list_call_history(
    cursor: Optional[str] = Query(None),
    limit: int = Query(20, ge=1, le=100),
    ctx=Depends(require_ui_session),
):
    result = list_call_history(ctx["user_sub"], cursor=cursor, limit=limit)
    return result


@router.get("/history/{call_id}", response_model=CallRecordOut)
async def ui_get_call_detail(
    call_id: str,
    ctx=Depends(require_ui_session),
):
    record = get_call_detail(ctx["user_sub"], call_id)
    if not record:
        raise HTTPException(status_code=404, detail="Call record not found")
    return record


@router.delete("/history/{call_id}")
async def ui_delete_call_record(
    call_id: str,
    ctx=Depends(require_ui_session),
):
    deleted = delete_call_record(ctx["user_sub"], call_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Call record not found")
    return {"ok": True}


@router.get("/stats", response_model=CallStatsOut)
async def ui_get_call_stats(ctx=Depends(require_ui_session)):
    return get_call_stats(ctx["user_sub"])


@router.post("/record", response_model=CallRecordOut)
async def ui_record_call(
    body: CallRecordIn,
    ctx=Depends(require_ui_session),
):
    """Internal/test endpoint to record a call."""
    try:
        result = record_call(
            caller_id=body.caller_id,
            callee_id=body.callee_id,
            call_type=body.call_type,
            duration_seconds=body.duration_seconds,
            status=body.status,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return result


# ─── ACT-006 / ACT-007: CRM Call Log endpoints ───────────────────────────────

from app.core.settings import S
from app.models import CallLogCreateIn, CallLogUpdateIn, CallLogOut, CallLogListResponse
from app.services.call_history import (
    create_crm_call_log,
    list_crm_call_logs,
    get_crm_call_log,
    update_crm_call_log,
    delete_crm_call_log,
    list_crm_call_logs_for_entity,
)
from app.services.alerts import audit_event


def _flag_guard():
    if not S.crm_activities_enabled:
        raise HTTPException(status_code=404, detail="Not found")


# GET /by-entity must be declared BEFORE /{call_id} to avoid path collision
@router.get("/logs/by-entity", response_model=CallLogListResponse)
async def ui_list_crm_call_logs_by_entity(
    entity_type: str = Query(...),
    entity_id: str = Query(...),
    limit: int = Query(20, ge=1, le=100),
    cursor: Optional[str] = Query(None),
    ctx=Depends(require_ui_session),
):
    _flag_guard()
    result = list_crm_call_logs_for_entity(
        ctx["user_sub"], entity_type, entity_id, limit=limit, cursor=cursor
    )
    return result


@router.post("/logs", response_model=CallLogOut, status_code=201)
async def ui_create_crm_call_log(
    body: CallLogCreateIn,
    ctx=Depends(require_ui_session),
):
    _flag_guard()
    result = create_crm_call_log(
        user_sub=ctx["user_sub"],
        subject=body.subject,
        description=body.description or "",
        direction=body.direction,
        duration_seconds=body.duration_seconds,
        outcome=body.outcome.value,
        call_type=body.call_type,
        contact_user_sub=body.contact_user_sub,
        linked_entity_type=body.linked_entity_type,
        linked_entity_id=body.linked_entity_id,
    )
    audit_event("crm_call_log_create", ctx["user_sub"], None, call_id=result["call_id"])
    return result


@router.get("/logs", response_model=CallLogListResponse)
async def ui_list_crm_call_logs(
    limit: int = Query(20, ge=1, le=100),
    cursor: Optional[str] = Query(None),
    ctx=Depends(require_ui_session),
):
    _flag_guard()
    return list_crm_call_logs(ctx["user_sub"], limit=limit, cursor=cursor)


@router.get("/logs/{call_id}", response_model=CallLogOut)
async def ui_get_crm_call_log(
    call_id: str,
    ctx=Depends(require_ui_session),
):
    _flag_guard()
    item = get_crm_call_log(ctx["user_sub"], call_id)
    if not item:
        raise HTTPException(404, "Call log not found")
    return item


@router.patch("/logs/{call_id}", response_model=CallLogOut)
async def ui_update_crm_call_log(
    call_id: str,
    body: CallLogUpdateIn,
    ctx=Depends(require_ui_session),
):
    _flag_guard()
    result = update_crm_call_log(
        ctx["user_sub"],
        call_id,
        subject=body.subject,
        description=body.description,
        outcome=body.outcome.value if body.outcome else None,
    )
    if not result:
        raise HTTPException(404, "Call log not found")
    audit_event("crm_call_log_update", ctx["user_sub"], None, call_id=call_id)
    return result


@router.delete("/logs/{call_id}")
async def ui_delete_crm_call_log(
    call_id: str,
    ctx=Depends(require_ui_session),
):
    _flag_guard()
    deleted = delete_crm_call_log(ctx["user_sub"], call_id)
    if not deleted:
        raise HTTPException(404, "Call log not found")
    audit_event("crm_call_log_delete", ctx["user_sub"], None, call_id=call_id)
    return {"ok": True}
