"""Marketing Agent router (AGENT-017).

User-scoped endpoints for marketing content lifecycle (draft -> review ->
approved -> scheduled -> published -> archived), a content calendar, engagement
analytics, Marketing Agent configuration, and deterministic content generation
from feature tickets.

Auth: ``require_ui_session`` (cookie session + CSRF for non-GET). All operations
are scoped to the authenticated ``user_sub`` — cross-tenant access is impossible
because the partition key embeds the user id.
"""

from __future__ import annotations

from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException, Query

from app.models import (
    CalendarEntryOut,
    CreateMarketingContentIn,
    EngagementStatsOut,
    EngagementSummaryOut,
    GenerateMarketingContentIn,
    MarketingConfigOut,
    MarketingContentListOut,
    MarketingContentOut,
    MarketingGenerateResultOut,
    ScheduleMarketingContentIn,
    UpdateMarketingConfigIn,
    UpdateMarketingContentIn,
)
from app.services import agent_marketing as svc
from app.services.sessions import require_ui_session

agent_marketing_router = APIRouter(prefix="/ui/agents/marketing", tags=["agent-marketing"])

# Backwards-compatible alias used by some registration conventions.
router = agent_marketing_router


def _uid(session: Dict[str, Any]) -> str:
    sub = str(session.get("user_sub") or "").strip()
    if not sub:
        raise HTTPException(status_code=401, detail="Missing user")
    return sub


def _not_found() -> HTTPException:
    return HTTPException(
        status_code=404,
        detail={"code": "content_not_found", "message": "Marketing content not found"},
    )


# ---------------------------------------------------------------------------
# Content CRUD
# ---------------------------------------------------------------------------


@agent_marketing_router.get("/content", response_model=MarketingContentListOut)
async def list_content(
    type: str | None = Query(default=None),
    status: str | None = Query(default=None),
    limit: int = Query(default=25, ge=1, le=100),
    cursor: str | None = Query(default=None),
    session=Depends(require_ui_session),
):
    try:
        result = svc.list_content(
            user_id=_uid(session),
            content_type=type,
            status=status,
            limit=limit,
            cursor=cursor,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return MarketingContentListOut(
        items=[MarketingContentOut(**it) for it in result["items"]],
        cursor=result.get("cursor"),
        count=result["count"],
    )


@agent_marketing_router.post("/content", response_model=MarketingContentOut, status_code=201)
async def create_content(
    body: CreateMarketingContentIn,
    session=Depends(require_ui_session),
):
    try:
        content = svc.create_content(user_id=_uid(session), **body.model_dump(exclude_none=True))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return MarketingContentOut(**content)


@agent_marketing_router.get("/content/{content_id}", response_model=MarketingContentOut)
async def get_content(content_id: str, session=Depends(require_ui_session)):
    content = svc.get_content(user_id=_uid(session), content_id=content_id)
    if content is None:
        raise _not_found()
    return MarketingContentOut(**content)


@agent_marketing_router.put("/content/{content_id}", response_model=MarketingContentOut)
async def update_content(
    content_id: str,
    body: UpdateMarketingContentIn,
    session=Depends(require_ui_session),
):
    try:
        content = svc.update_content(
            user_id=_uid(session), content_id=content_id, **body.model_dump(exclude_none=True)
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    if content is None:
        raise _not_found()
    return MarketingContentOut(**content)


@agent_marketing_router.post("/content/{content_id}/approve", response_model=MarketingContentOut)
async def approve_content(content_id: str, session=Depends(require_ui_session)):
    try:
        content = svc.approve_content(user_id=_uid(session), content_id=content_id)
    except PermissionError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    if content is None:
        raise _not_found()
    return MarketingContentOut(**content)


@agent_marketing_router.post("/content/{content_id}/schedule", response_model=MarketingContentOut)
async def schedule_content(
    content_id: str,
    body: ScheduleMarketingContentIn,
    session=Depends(require_ui_session),
):
    try:
        content = svc.schedule_content(
            user_id=_uid(session), content_id=content_id, publish_at=body.publish_at
        )
    except PermissionError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    if content is None:
        raise _not_found()
    return MarketingContentOut(**content)


@agent_marketing_router.post("/content/{content_id}/publish", response_model=MarketingContentOut)
async def publish_content(content_id: str, session=Depends(require_ui_session)):
    try:
        content = svc.publish_content(user_id=_uid(session), content_id=content_id)
    except PermissionError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    if content is None:
        raise _not_found()
    return MarketingContentOut(**content)


@agent_marketing_router.post("/content/{content_id}/archive", response_model=MarketingContentOut)
async def archive_content(content_id: str, session=Depends(require_ui_session)):
    content = svc.archive_content(user_id=_uid(session), content_id=content_id)
    if content is None:
        raise _not_found()
    return MarketingContentOut(**content)


@agent_marketing_router.delete("/content/{content_id}")
async def delete_content(content_id: str, session=Depends(require_ui_session)):
    try:
        result = svc.delete_content(user_id=_uid(session), content_id=content_id)
    except PermissionError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    if result is None:
        raise _not_found()
    return result


# ---------------------------------------------------------------------------
# Calendar
# ---------------------------------------------------------------------------


@agent_marketing_router.get("/calendar")
async def get_calendar(
    month: str = Query(...),
    session=Depends(require_ui_session),
):
    try:
        entries = svc.get_calendar(user_id=_uid(session), month=month)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return [CalendarEntryOut(**e) for e in entries]


# ---------------------------------------------------------------------------
# Engagement
# ---------------------------------------------------------------------------


@agent_marketing_router.get("/content/{content_id}/engagement", response_model=EngagementStatsOut)
async def get_engagement(
    content_id: str,
    days: int = Query(default=30, ge=1, le=365),
    session=Depends(require_ui_session),
):
    stats = svc.get_engagement_stats(user_id=_uid(session), content_id=content_id, days=days)
    if stats is None:
        raise _not_found()
    return EngagementStatsOut(**stats)


@agent_marketing_router.get("/engagement/summary", response_model=EngagementSummaryOut)
async def get_engagement_summary(
    days: int = Query(default=30, ge=1, le=365),
    session=Depends(require_ui_session),
):
    summary = svc.get_engagement_summary(user_id=_uid(session), days=days)
    return EngagementSummaryOut(**summary)


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------


@agent_marketing_router.get("/config", response_model=MarketingConfigOut)
async def get_config(session=Depends(require_ui_session)):
    config = svc.get_marketing_config(user_id=_uid(session)) or svc.default_marketing_config()
    return MarketingConfigOut(**config)


@agent_marketing_router.put("/config", response_model=MarketingConfigOut)
async def put_config(
    body: UpdateMarketingConfigIn,
    session=Depends(require_ui_session),
):
    config = svc.update_marketing_config(
        user_id=_uid(session), config=body.model_dump(exclude_none=True)
    )
    return MarketingConfigOut(**config)


# ---------------------------------------------------------------------------
# Generation
# ---------------------------------------------------------------------------


@agent_marketing_router.post(
    "/generate", response_model=MarketingGenerateResultOut, status_code=201
)
async def generate(
    body: GenerateMarketingContentIn,
    session=Depends(require_ui_session),
):
    result = svc.generate_content_for_feature(
        user_id=_uid(session),
        agent_id=None,
        feature_ticket_ids=body.feature_ticket_ids,
        content_types=body.content_types,
        tone_override=body.tone_override,
        target_audience_override=body.target_audience_override,
    )
    return MarketingGenerateResultOut(
        status=result["status"],
        executed=result["executed"],
        content_types_requested=result["content_types_requested"],
        feature_ticket_ids=result["feature_ticket_ids"],
        missing_ticket_ids=result["missing_ticket_ids"],
        contents=[MarketingContentOut(**c) for c in result["contents"]],
        count=result["count"],
    )
