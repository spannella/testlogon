"""
ACT-009 — CRM Activity History Timeline router.

Mounted at /ui/crm/timeline.  All routes require crm_activities_enabled AND
crm_activity_timeline_enabled.
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from app.core.settings import S
from app.models import CrmActivityOut, CrmActivityTimelineOut
from app.services.crm_activity_timeline import list_entity_activities, delete_entity_activity
from app.services.sessions import require_ui_session

router = APIRouter(prefix="/ui/crm/timeline", tags=["crm-activity-timeline"])


def _gate():
    if not (S.crm_activities_enabled and S.crm_activity_timeline_enabled):
        raise HTTPException(status_code=404, detail="Not found")


@router.get("/{entity_type}/{entity_id}", response_model=CrmActivityTimelineOut)
async def get_entity_timeline(
    entity_type: str,
    entity_id: str,
    limit: int = Query(20, ge=1, le=100),
    cursor: Optional[str] = Query(None),
    activity_type: Optional[str] = Query(None),
    ctx=Depends(require_ui_session),
) -> CrmActivityTimelineOut:
    _gate()
    result = list_entity_activities(
        entity_type=entity_type,
        entity_id=entity_id,
        limit=limit,
        cursor=cursor,
        activity_type_filter=activity_type,
    )
    return CrmActivityTimelineOut(**result)


@router.delete("/{entity_type}/{entity_id}/{sk:path}")
async def delete_timeline_entry(
    entity_type: str,
    entity_id: str,
    sk: str,
    ctx=Depends(require_ui_session),
):
    _gate()
    deleted = delete_entity_activity(entity_type, entity_id, sk, ctx["user_sub"])
    if not deleted:
        raise HTTPException(404, "Timeline entry not found")
    return {"ok": True}
