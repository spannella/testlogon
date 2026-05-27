"""
Unified Content Scheduling API -- SCHED-001

Endpoints:
  POST   /ui/scheduler/actions             Create a scheduled action
  GET    /ui/scheduler/actions             List user's scheduled actions
  GET    /ui/scheduler/actions/{action_id} Get action detail
  PATCH  /ui/scheduler/actions/{action_id} Update/reschedule
  DELETE /ui/scheduler/actions/{action_id} Cancel
  GET    /ui/scheduler/calendar            Calendar view
  POST   /ui/feed/posts/schedule           Convenience: schedule a post
  POST   /ui/catalog/products/{product_id}/sale  Schedule a catalog sale
"""
from __future__ import annotations

import logging
from typing import Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from app.core.time import now_ts
from app.core.settings import S
from app.models import (
    CatalogSaleIn,
    CatalogSaleOut,
    ScheduledActionCreateIn,
    ScheduledActionListOut,
    ScheduledActionOut,
    ScheduledActionUpdateIn,
    ScheduledCalendarOut,
    ScheduledPostIn,
)
from app.services.scheduled_actions import (
    cancel_action,
    calendar_range,
    create_action,
    get_action,
    list_actions,
    update_action,
)
from app.services.sessions import require_ui_session

logger = logging.getLogger(__name__)

router = APIRouter(tags=["scheduler"])


def _user_sub(ctx: Dict = Depends(require_ui_session)) -> str:
    return ctx["user_sub"]


# ---------------------------------------------------------------------------
# CRUD
# ---------------------------------------------------------------------------


@router.post("/ui/scheduler/actions", status_code=201, response_model=ScheduledActionOut)
def create_scheduled_action(
    body: ScheduledActionCreateIn,
    user_sub: str = Depends(_user_sub),
):
    try:
        return create_action(
            user_sub=user_sub,
            action_type=body.action_type,
            scheduled_at=body.scheduled_at,
            payload=body.payload,
            title=body.title,
            description=body.description,
            notify_before_seconds=body.notify_before_seconds,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except OverflowError as e:
        raise HTTPException(status_code=409, detail=str(e))


@router.get("/ui/scheduler/actions", response_model=ScheduledActionListOut)
def list_scheduled_actions(
    types: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    user_sub: str = Depends(_user_sub),
):
    return list_actions(user_sub, types=types, status_filter=status)


@router.get("/ui/scheduler/actions/{action_id}", response_model=ScheduledActionOut)
def get_scheduled_action(
    action_id: str,
    user_sub: str = Depends(_user_sub),
):
    result = get_action(user_sub, action_id)
    if not result:
        raise HTTPException(status_code=404, detail="Action not found")
    return result


@router.patch("/ui/scheduler/actions/{action_id}", response_model=ScheduledActionOut)
def update_scheduled_action(
    action_id: str,
    body: ScheduledActionUpdateIn,
    user_sub: str = Depends(_user_sub),
):
    try:
        result = update_action(
            user_sub=user_sub,
            action_id=action_id,
            scheduled_at=body.scheduled_at,
            title=body.title,
            description=body.description,
            payload=body.payload,
            notify_before_seconds=body.notify_before_seconds,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    if not result:
        raise HTTPException(status_code=404, detail="Action not found")
    return result


@router.delete("/ui/scheduler/actions/{action_id}")
def cancel_scheduled_action(
    action_id: str,
    user_sub: str = Depends(_user_sub),
):
    try:
        result = cancel_action(user_sub, action_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    if not result:
        raise HTTPException(status_code=404, detail="Action not found")
    return {"ok": True, "action_id": action_id, "status": "cancelled"}


# ---------------------------------------------------------------------------
# Calendar view
# ---------------------------------------------------------------------------


@router.get("/ui/scheduler/calendar", response_model=ScheduledCalendarOut)
def scheduler_calendar(
    from_date: int = Query(...),
    to_date: int = Query(...),
    types: Optional[str] = Query(None),
    user_sub: str = Depends(_user_sub),
):
    return calendar_range(user_sub, from_date, to_date, types=types)


# ---------------------------------------------------------------------------
# Convenience: schedule a post
# ---------------------------------------------------------------------------


@router.post("/ui/feed/posts/schedule", status_code=201, response_model=ScheduledActionOut)
def schedule_post(
    body: ScheduledPostIn,
    user_sub: str = Depends(_user_sub),
):
    payload = {
        "text": body.text,
        "image_urls": body.image_urls,
        "lock_price_cents": body.lock_price_cents,
        "visibility": body.visibility,
    }
    title = (body.text[:60] + "...") if len(body.text) > 60 else body.text
    try:
        return create_action(
            user_sub=user_sub,
            action_type="post",
            scheduled_at=body.scheduled_at,
            payload=payload,
            title=title or "Scheduled Post",
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except OverflowError as e:
        raise HTTPException(status_code=409, detail=str(e))


# ---------------------------------------------------------------------------
# Convenience: schedule a catalog sale
# ---------------------------------------------------------------------------


@router.post("/ui/catalog/products/{product_id}/sale", status_code=201, response_model=CatalogSaleOut)
def schedule_catalog_sale(
    product_id: str,
    body: CatalogSaleIn,
    user_sub: str = Depends(_user_sub),
):
    # Create activation action
    start_payload = {
        "product_id": product_id,
        "sale_price_cents": body.sale_price_cents,
        "sale_label": body.sale_label,
        "activate": True,
    }
    try:
        start_action = create_action(
            user_sub=user_sub,
            action_type="catalog_sale",
            scheduled_at=body.sale_starts_at,
            payload=start_payload,
            title=f"Sale Start: {body.sale_label or product_id}",
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except OverflowError as e:
        raise HTTPException(status_code=409, detail=str(e))

    # Create deactivation action
    end_payload = {
        "product_id": product_id,
        "sale_price_cents": None,
        "sale_label": None,
        "activate": False,
    }
    try:
        end_action = create_action(
            user_sub=user_sub,
            action_type="catalog_sale",
            scheduled_at=body.sale_ends_at,
            payload=end_payload,
            title=f"Sale End: {body.sale_label or product_id}",
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except OverflowError as e:
        raise HTTPException(status_code=409, detail=str(e))

    return CatalogSaleOut(
        start_action_id=start_action["action_id"],
        end_action_id=end_action["action_id"],
        sale_starts_at=body.sale_starts_at,
        sale_ends_at=body.sale_ends_at,
    )
