"""VOD-019 rental / view-once access router.

Buyer-scoped endpoints layered on top of the existing VOD purchase + playback
systems. Provides:

  POST  /ui/vod/rental/{video_id}/start            — start a rental/view-once
  GET   /ui/vod/rental/{video_id}/access           — check current access state
  POST  /ui/vod/rental/{video_id}/playback         — issue a gated playback URL
  POST  /ui/vod/rental/{video_id}/playback-complete — consume a view-once view
  GET   /ui/vod/rental/{video_id}/status           — rental status for a video
  GET   /ui/vod/rental/list                         — viewer's rental history

The window/consumption clock is server-driven via ``now_ts()``. To make the
time-window + consumption lifecycle deterministically testable, a ``now``
override query parameter is honored ONLY in dev mode.
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, Query

from app.core.settings import S
from app.models import (
    VodRentalAccessOut,
    VodRentalConsumeOut,
    VodRentalListOut,
    VodRentalPlaybackOut,
    VodRentalStartIn,
    VodRentalStartOut,
    VodRentalStatusOut,
)
from app.services import vod_rental as svc
from app.services.sessions import require_ui_session

vod_rental_router = APIRouter(prefix="/ui/vod/rental", tags=["vod-rental"])


def _now_override(now: Optional[int]) -> Optional[int]:
    """Allow deterministic time injection in dev mode only."""
    if now is not None and S.dev_mode:
        return now
    return None


@vod_rental_router.post("/{video_id}/start", response_model=VodRentalStartOut)
def start_rental_endpoint(
    video_id: str,
    body: VodRentalStartIn,
    now: Optional[int] = Query(default=None),
    user=Depends(require_ui_session),
):
    result = svc.start_rental(
        buyer_id=user["user_sub"],
        video_id=video_id,
        tier=body.tier,
        payment_method_id=body.payment_method_id,
        rental_duration_hours=body.rental_duration_hours,
        now=_now_override(now),
    )
    return VodRentalStartOut(**result)


@vod_rental_router.get("/{video_id}/access", response_model=VodRentalAccessOut)
def rental_access_endpoint(
    video_id: str,
    now: Optional[int] = Query(default=None),
    user=Depends(require_ui_session),
):
    access = svc.check_access(
        user_id=user["user_sub"], video_id=video_id, now=_now_override(now)
    )
    return VodRentalAccessOut(**access.to_dict())


@vod_rental_router.post("/{video_id}/playback", response_model=VodRentalPlaybackOut)
def rental_playback_endpoint(
    video_id: str,
    now: Optional[int] = Query(default=None),
    user=Depends(require_ui_session),
):
    result = svc.issue_playback(
        user_id=user["user_sub"], video_id=video_id, now=_now_override(now)
    )
    return VodRentalPlaybackOut(**result)


@vod_rental_router.post("/{video_id}/playback-complete", response_model=VodRentalConsumeOut)
def rental_playback_complete_endpoint(
    video_id: str,
    now: Optional[int] = Query(default=None),
    user=Depends(require_ui_session),
):
    result = svc.consume_view(
        user_id=user["user_sub"], video_id=video_id, now=_now_override(now)
    )
    return VodRentalConsumeOut(**result)


@vod_rental_router.get("/{video_id}/status", response_model=VodRentalStatusOut)
def rental_status_endpoint(
    video_id: str,
    now: Optional[int] = Query(default=None),
    user=Depends(require_ui_session),
):
    result = svc.get_status(
        user_id=user["user_sub"], video_id=video_id, now=_now_override(now)
    )
    return VodRentalStatusOut(**result)


@vod_rental_router.get("/list", response_model=VodRentalListOut)
def rental_list_endpoint(
    limit: int = Query(default=50, ge=1, le=200),
    now: Optional[int] = Query(default=None),
    user=Depends(require_ui_session),
):
    items = svc.list_rentals(
        user_id=user["user_sub"], limit=limit, now=_now_override(now)
    )
    return VodRentalListOut(items=[VodRentalStatusOut(**i) for i in items])
