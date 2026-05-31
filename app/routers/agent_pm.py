"""Product Manager Agent router (AGENT-013).

Owner-scoped endpoints (require_ui_session) for the PM Agent: feature idea CRUD,
the approval/rejection/archive lifecycle (approval mints a product_request
ticket), per-category preference learning, review session artifacts, PM config,
and a deterministic mock review trigger.

All idea operations are scoped to the authenticated user's ``user_sub`` so users
can only view / act on their own ideas (security §9).
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from app.models import (
    CreateFeatureIdeaIn,
    FeatureIdeaListOut,
    FeatureIdeaOut,
    PmAgentConfigOut,
    PreferenceSummaryListOut,
    RejectIdeaIn,
    ReviewScreenshotListOut,
    ReviewSessionListOut,
    TriggerReviewIn,
    TriggerReviewOut,
    UpdatePmConfigIn,
)
from app.services import agent_pm as svc
from app.services.sessions import require_ui_session

router = APIRouter(prefix="/ui/agents/pm", tags=["agent-pm"])


def _err(exc: svc.PmValidationError) -> HTTPException:
    status_map = {
        "IDEA_NOT_FOUND": 404,
        "PM_NOT_CONFIGURED": 404,
        "INVALID_STATUS_TRANSITION": 409,
        "REVIEW_IN_PROGRESS": 409,
        "REASON_REQUIRED": 422,
        "INVALID_CATEGORY": 422,
        "INVALID_PRIORITY": 422,
        "INVALID_TITLE": 422,
        "INVALID_DESCRIPTION": 422,
        "INVALID_USER_IMPACT": 422,
        "INVALID_STATUS": 422,
        "CONFIG_INVALID": 422,
        "MAX_IDEAS_EXCEEDED": 400,
    }
    code = status_map.get(exc.code, 400)
    return HTTPException(status_code=code, detail={"code": exc.code, "message": exc.message})


# ---------------------------------------------------------------------------
# Feature idea CRUD
# ---------------------------------------------------------------------------


@router.post("/ideas", response_model=FeatureIdeaOut, status_code=201)
async def create_idea(body: CreateFeatureIdeaIn, session: Dict[str, str] = Depends(require_ui_session)):
    """Create a feature idea (simulates PM Agent review output)."""
    try:
        idea = svc.create_feature_idea(
            user_id=session["user_sub"],
            agent_id=body.agent_id,
            worker_id=body.worker_id,
            title=body.title,
            description=body.description,
            category=body.category.value,
            priority_suggestion=body.priority_suggestion.value,
            user_impact=body.user_impact,
            mockup_description=body.mockup_description,
            evidence=[e.model_dump() for e in body.evidence] if body.evidence else None,
            competitor_refs=[c.model_dump() for c in body.competitor_refs] if body.competitor_refs else None,
            support_ticket_refs=body.support_ticket_refs,
            enforce_max=True,
        )
    except svc.PmValidationError as exc:
        raise _err(exc)
    return FeatureIdeaOut(**idea)


@router.get("/ideas", response_model=FeatureIdeaListOut)
async def list_ideas(
    status: Optional[str] = Query(default=None),
    limit: int = Query(default=25, ge=1, le=100),
    cursor: Optional[str] = Query(default=None),
    session: Dict[str, str] = Depends(require_ui_session),
):
    try:
        result = svc.list_feature_ideas(
            user_id=session["user_sub"], status=status, limit=limit, cursor=cursor
        )
    except svc.PmValidationError as exc:
        raise _err(exc)
    return FeatureIdeaListOut(**result)


@router.get("/ideas/{idea_id}", response_model=FeatureIdeaOut)
async def get_idea(idea_id: str, session: Dict[str, str] = Depends(require_ui_session)):
    idea = svc.get_feature_idea(user_id=session["user_sub"], idea_id=idea_id)
    if idea is None:
        raise HTTPException(
            status_code=404,
            detail={"code": "IDEA_NOT_FOUND", "message": "Feature idea not found"},
        )
    return FeatureIdeaOut(**idea)


@router.post("/ideas/{idea_id}/approve", response_model=FeatureIdeaOut)
async def approve_idea(idea_id: str, session: Dict[str, str] = Depends(require_ui_session)):
    try:
        idea = svc.approve_idea(user_id=session["user_sub"], idea_id=idea_id)
    except svc.PmValidationError as exc:
        raise _err(exc)
    return FeatureIdeaOut(**idea)


@router.post("/ideas/{idea_id}/reject", response_model=FeatureIdeaOut)
async def reject_idea(
    idea_id: str, body: RejectIdeaIn, session: Dict[str, str] = Depends(require_ui_session)
):
    try:
        idea = svc.reject_idea(user_id=session["user_sub"], idea_id=idea_id, reason=body.reason)
    except svc.PmValidationError as exc:
        raise _err(exc)
    return FeatureIdeaOut(**idea)


@router.post("/ideas/{idea_id}/archive", response_model=FeatureIdeaOut)
async def archive_idea(idea_id: str, session: Dict[str, str] = Depends(require_ui_session)):
    try:
        idea = svc.archive_idea(user_id=session["user_sub"], idea_id=idea_id)
    except svc.PmValidationError as exc:
        raise _err(exc)
    return FeatureIdeaOut(**idea)


# ---------------------------------------------------------------------------
# Preference learning
# ---------------------------------------------------------------------------


@router.get("/preferences", response_model=PreferenceSummaryListOut)
async def get_preferences(session: Dict[str, str] = Depends(require_ui_session)):
    prefs = svc.get_preference_summary(user_id=session["user_sub"])
    return PreferenceSummaryListOut(preferences=prefs)


# ---------------------------------------------------------------------------
# Review sessions + artifacts
# ---------------------------------------------------------------------------


@router.get("/reviews", response_model=ReviewSessionListOut)
async def list_reviews(session: Dict[str, str] = Depends(require_ui_session)):
    reviews = svc.list_review_sessions(user_id=session["user_sub"])
    return ReviewSessionListOut(reviews=reviews)


@router.get("/reviews/{review_id}/screenshots", response_model=ReviewScreenshotListOut)
async def get_review_screenshots(review_id: str, session: Dict[str, str] = Depends(require_ui_session)):
    shots = svc.get_review_screenshots(user_id=session["user_sub"], review_id=review_id)
    return ReviewScreenshotListOut(screenshots=shots)


# ---------------------------------------------------------------------------
# Config + manual trigger
# ---------------------------------------------------------------------------


@router.get("/config", response_model=PmAgentConfigOut)
async def get_config(session: Dict[str, str] = Depends(require_ui_session)):
    config = svc.get_pm_config(user_id=session["user_sub"])
    return PmAgentConfigOut(**config)


@router.put("/config", response_model=PmAgentConfigOut)
async def put_config(body: UpdatePmConfigIn, session: Dict[str, str] = Depends(require_ui_session)):
    payload = {k: v for k, v in body.model_dump().items() if v is not None}
    try:
        config = svc.update_pm_config(user_id=session["user_sub"], config=payload)
    except svc.PmValidationError as exc:
        raise _err(exc)
    return PmAgentConfigOut(**config)


@router.post("/trigger-review", response_model=TriggerReviewOut)
async def trigger_review(
    body: TriggerReviewIn | None = None, session: Dict[str, str] = Depends(require_ui_session)
):
    payload = body or TriggerReviewIn()
    try:
        result = svc.trigger_review(
            user_id=session["user_sub"], agent_id=payload.agent_id, count=payload.count
        )
    except svc.PmValidationError as exc:
        raise _err(exc)
    return TriggerReviewOut(**result)
