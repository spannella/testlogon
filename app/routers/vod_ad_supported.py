"""VOD-018 ad-supported viewing router.

REST surface for the ad-supported VOD tier: a viewer can watch an
``ad_supported`` video for free in exchange for watching ad breaks, as an
alternative to paying (purchase / rental).

Mounted under ``/ui/vod/ad-supported`` (distinct from the ``/ui/vod/rental``
router and the ``/ui/videos`` listing router). All endpoints require a UI
session; the viewer identity comes from the session, never the request body.

  GET  /ui/vod/ad-supported/{video_id}/session  — current session state
  POST /ui/vod/ad-supported/{video_id}/start    — start session + free grant
  POST /ui/vod/ad-supported/{video_id}/break    — report an ad-break event
"""

from __future__ import annotations

from fastapi import APIRouter, Depends

from app.models import (
    VodAdSupportedStartIn,
    VodAdSupportedStartOut,
    VodAdSupportedSessionOut,
    VodAdBreakReportIn,
    VodAdBreakReportOut,
)
from app.services import vod_ad_supported as ad_svc
from app.services.sessions import require_ui_session

vod_ad_supported_router = APIRouter(
    prefix="/ui/vod/ad-supported", tags=["vod-ad-supported"]
)


@vod_ad_supported_router.get(
    "/{video_id}/session", response_model=VodAdSupportedSessionOut
)
def get_ad_supported_session(
    video_id: str,
    user=Depends(require_ui_session),
) -> VodAdSupportedSessionOut:
    """Return the caller's ad-supported viewing session state for a video."""
    return VodAdSupportedSessionOut(
        **ad_svc.get_session_status(user_id=user["user_sub"], video_id=video_id)
    )


@vod_ad_supported_router.post(
    "/{video_id}/start", response_model=VodAdSupportedStartOut
)
def start_ad_supported_session(
    video_id: str,
    body: VodAdSupportedStartIn,
    user=Depends(require_ui_session),
) -> VodAdSupportedStartOut:
    """Start (or resume) an ad-supported viewing session.

    Returns the ad schedule plus a free playback grant. Continued playback past
    each gating ad break is unlocked by reporting that break complete.
    """
    result = ad_svc.start_session(user_id=user["user_sub"], video_id=video_id)
    return VodAdSupportedStartOut(**result)


@vod_ad_supported_router.post(
    "/{video_id}/break", response_model=VodAdBreakReportOut
)
def report_ad_break(
    video_id: str,
    body: VodAdBreakReportIn,
    user=Depends(require_ui_session),
) -> VodAdBreakReportOut:
    """Report an ad-break viewed/completed/skipped event.

    A ``complete`` event unlocks continued playback past that break's position
    and credits creator ad revenue via the shared ad-placement service.
    """
    result = ad_svc.report_break(
        user_id=user["user_sub"],
        video_id=video_id,
        break_id=body.break_id,
        event_type=body.event_type,
    )
    return VodAdBreakReportOut(**result)
