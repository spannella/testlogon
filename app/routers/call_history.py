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
