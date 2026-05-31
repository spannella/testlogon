"""Stylist / UI Agent router (AGENT-016).

Per-owner endpoints (``require_ui_session``) for UI review results, per-page and
overall design scores, issue -> ticket promotion, design-rule CRUD, agent config,
and a deterministic mock review trigger. All data is scoped to the authenticated
``user_sub``.
"""

from __future__ import annotations

from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException, Query

from app.models import (
    CreateDesignRuleIn,
    CreateIssueTicketOut,
    CreateUIReviewIn,
    DesignRuleOut,
    OverallDesignScoreOut,
    PageDesignScoreOut,
    StylistConfigOut,
    TriggerUIReviewIn,
    TriggerUIReviewOut,
    UIReviewListOut,
    UIReviewOut,
    UpdateDesignRuleIn,
    UpdateStylistConfigIn,
)
from app.services import agent_stylist as svc
from app.services.sessions import require_ui_session

agent_stylist_router = APIRouter(prefix="/ui/agents/stylist", tags=["agent-stylist"])

# Backwards-compat alias so either name works at registration time.
router = agent_stylist_router


def _uid(session: Dict[str, Any]) -> str:
    return str(session.get("user_sub") or "")


# ---------------------------------------------------------------------------
# Reviews
# ---------------------------------------------------------------------------


@agent_stylist_router.post("/reviews", response_model=UIReviewOut, status_code=201)
async def create_review(body: CreateUIReviewIn, session=Depends(require_ui_session)):
    review = svc.create_review(
        user_id=_uid(session),
        agent_id=body.agent_id,
        worker_id=body.worker_id,
        page_url=body.page_url,
        page_name=body.page_name,
        review_type=body.review_type,
        screenshots=[s.model_dump() for s in body.screenshots],
        design_score=body.design_score,
        accessibility_score=body.accessibility_score,
        issues=[i.model_dump() for i in body.issues],
        annotations=[a.model_dump() for a in body.annotations],
        source_ref=body.source_ref,
    )
    return UIReviewOut(**review)


@agent_stylist_router.get("/reviews", response_model=UIReviewListOut)
async def list_reviews(
    page_url: str | None = Query(default=None),
    review_type: str | None = Query(default=None),
    limit: int = Query(default=25, ge=1, le=100),
    cursor: str | None = Query(default=None),
    session=Depends(require_ui_session),
):
    result = svc.list_reviews(
        user_id=_uid(session),
        page_url=page_url,
        review_type=review_type,
        limit=limit,
        cursor=cursor,
    )
    return UIReviewListOut(**result)


@agent_stylist_router.get("/reviews/{review_id}", response_model=UIReviewOut)
async def get_review(review_id: str, session=Depends(require_ui_session)):
    review = svc.get_review(user_id=_uid(session), review_id=review_id)
    if review is None:
        raise HTTPException(status_code=404, detail="UI review not found")
    return UIReviewOut(**review)


@agent_stylist_router.post(
    "/reviews/{review_id}/issues/{issue_id}/ticket", response_model=CreateIssueTicketOut
)
async def create_issue_ticket(review_id: str, issue_id: str, session=Depends(require_ui_session)):
    try:
        result = svc.create_issue_ticket(
            user_id=_uid(session), review_id=review_id, issue_id=issue_id
        )
    except LookupError as exc:
        if str(exc) == "issue":
            raise HTTPException(status_code=404, detail="Issue not found in review")
        raise HTTPException(status_code=404, detail="UI review not found")
    except ValueError:
        raise HTTPException(status_code=409, detail="Ticket already created for this issue")
    return CreateIssueTicketOut(**result)


# ---------------------------------------------------------------------------
# Scores
# ---------------------------------------------------------------------------


@agent_stylist_router.get("/scores", response_model=list[PageDesignScoreOut])
async def get_page_scores(session=Depends(require_ui_session)):
    scores = svc.get_page_scores(user_id=_uid(session))
    return [PageDesignScoreOut(**s) for s in scores]


@agent_stylist_router.get("/scores/overall", response_model=OverallDesignScoreOut)
async def get_overall_score(session=Depends(require_ui_session)):
    return OverallDesignScoreOut(**svc.get_overall_score(user_id=_uid(session)))


# ---------------------------------------------------------------------------
# Design rules
# ---------------------------------------------------------------------------


@agent_stylist_router.get("/rules", response_model=list[DesignRuleOut])
async def list_rules(
    category: str | None = Query(default=None),
    session=Depends(require_ui_session),
):
    rules = svc.list_design_rules(user_id=_uid(session), category=category)
    return [DesignRuleOut(**r) for r in rules]


@agent_stylist_router.post("/rules", response_model=DesignRuleOut, status_code=201)
async def create_rule(body: CreateDesignRuleIn, session=Depends(require_ui_session)):
    rule = svc.create_design_rule(
        user_id=_uid(session),
        name=body.name,
        category=body.category,
        description=body.description,
        severity=body.severity,
        config=body.config,
    )
    return DesignRuleOut(**rule)


@agent_stylist_router.put("/rules/{rule_id}", response_model=DesignRuleOut)
async def update_rule(rule_id: str, body: UpdateDesignRuleIn, session=Depends(require_ui_session)):
    rule = svc.update_design_rule(
        user_id=_uid(session), rule_id=rule_id, **body.model_dump(exclude_none=True)
    )
    if rule is None:
        raise HTTPException(status_code=404, detail="Design rule not found")
    return DesignRuleOut(**rule)


@agent_stylist_router.delete("/rules/{rule_id}")
async def delete_rule(rule_id: str, session=Depends(require_ui_session)):
    ok = svc.delete_design_rule(user_id=_uid(session), rule_id=rule_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Design rule not found")
    return {"ok": True, "rule_id": rule_id}


# ---------------------------------------------------------------------------
# Config + trigger
# ---------------------------------------------------------------------------


@agent_stylist_router.get("/config", response_model=StylistConfigOut)
async def get_config(session=Depends(require_ui_session)):
    config = svc.get_stylist_config(user_id=_uid(session))
    if config is None:
        config = svc.update_stylist_config(user_id=_uid(session), fields={})
    return StylistConfigOut(**config)


@agent_stylist_router.put("/config", response_model=StylistConfigOut)
async def put_config(body: UpdateStylistConfigIn, session=Depends(require_ui_session)):
    config = svc.update_stylist_config(
        user_id=_uid(session), fields=body.model_dump(exclude_none=True)
    )
    return StylistConfigOut(**config)


@agent_stylist_router.post("/trigger-review", response_model=TriggerUIReviewOut)
async def trigger_review(body: TriggerUIReviewIn, session=Depends(require_ui_session)):
    if len(body.pages) > 20:
        raise HTTPException(status_code=422, detail="Maximum 20 pages per review trigger")
    errs = svc.validate_viewports([dict(v) for v in (body.viewports or [])])
    if errs:
        raise HTTPException(status_code=422, detail=errs[0])
    result = svc.trigger_review(
        user_id=_uid(session),
        pages=body.pages,
        review_type=body.review_type,
        viewports=[dict(v) for v in body.viewports] if body.viewports else None,
    )
    return TriggerUIReviewOut(ok=result["ok"], reviews=result["reviews"], count=result["count"])
