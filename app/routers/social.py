"""Social graph router — follow/unfollow, follower/following lists, counts, mutual detection."""

from __future__ import annotations

import logging
from typing import List, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from app.services.sessions import require_ui_session
from app.services import social as social_service
from app.services import blocking as blocking_service
from app.core.tables import T
from app.core.time import now_ts
from app.models import (
    SnoozeFollowingIn,
    SnoozeFollowingOut,
    UnsnoozeFollowingOut,
    SnoozedFollowingOut,
    SnoozedFollowingListOut,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ui/social", tags=["social"])


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class FollowRequest(BaseModel):
    target_user_id: str = Field(..., min_length=1, max_length=128)


class FollowResponse(BaseModel):
    ok: bool
    status: Literal["followed", "already_following"]
    follower_count: int = Field(ge=0)
    following_count: int = Field(ge=0)


class UnfollowResponse(BaseModel):
    ok: bool
    status: Literal["unfollowed", "not_following"]


class FollowUser(BaseModel):
    user_id: str
    display_name: Optional[str] = None
    profile_photo_url: Optional[str] = None
    is_following: bool = False
    is_mutual: bool = False
    # SOCIAL-007: snooze state (only meaningful for the viewer's own followings)
    snoozed_until: Optional[int] = None
    is_snoozed: bool = False


class FollowListResponse(BaseModel):
    items: List[FollowUser]
    next_cursor: Optional[str] = None
    total_count: int = Field(ge=0)


class FollowCountsResponse(BaseModel):
    follower_count: int = Field(ge=0)
    following_count: int = Field(ge=0)


class FollowStatusResponse(BaseModel):
    is_following: bool
    is_followed_by: bool
    is_mutual: bool
    is_blocked_by_me: bool = False
    is_blocking_me: bool = False


class BlockRequest(BaseModel):
    target_user_id: str = Field(..., min_length=1, max_length=256)
    reason: Optional[str] = Field(default=None, max_length=500)


class UnblockRequest(BaseModel):
    target_user_id: str = Field(..., min_length=1, max_length=256)


class BlockActionResponse(BaseModel):
    ok: bool = True
    status: str
    target_user_id: str


class BlockedUserItem(BaseModel):
    user_id: str
    display_name: Optional[str] = None
    profile_photo_url: Optional[str] = None
    blocked_at: str


class BlockedUsersListResponse(BaseModel):
    blocked_users: List[BlockedUserItem]
    next_cursor: Optional[str] = None
    total_count: int


class BlockStatusResponse(BaseModel):
    is_blocked_by_me: bool
    is_blocking_me: bool


# ---------------------------------------------------------------------------
# Helper: enrich follow items with profile data + viewer follow status
# ---------------------------------------------------------------------------

def _enrich_follow_items(
    items: list,
    viewer_id: str,
    key_field: str = "user_id",
) -> List[FollowUser]:
    """Enrich raw follow records with profile data and viewer's follow status."""
    results: List[FollowUser] = []
    for item in items:
        uid = item.get(key_field, "")
        if not uid:
            continue

        # Fetch profile
        profile = T.profile.get_item(Key={"user_sub": uid}).get("Item") or {}
        display_name = profile.get("display_name") or uid
        photo_url = profile.get("profile_photo_url")

        # Check if viewer follows this person
        viewer_status = social_service.get_follow_status(viewer_id, uid)

        # SOCIAL-007: surface snooze state. When the enriched item IS the viewer's
        # own follow record (following list), snoozed_until lives on the raw item.
        snoozed_until_raw = item.get("snoozed_until")
        snoozed_until = int(snoozed_until_raw) if snoozed_until_raw is not None else None
        is_snoozed = snoozed_until is not None and snoozed_until > now_ts()

        results.append(FollowUser(
            user_id=uid,
            display_name=display_name,
            profile_photo_url=photo_url,
            is_following=viewer_status["is_following"],
            is_mutual=viewer_status["is_mutual"],
            snoozed_until=snoozed_until,
            is_snoozed=is_snoozed,
        ))
    return results


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/follow", response_model=FollowResponse)
def follow_user(req: FollowRequest, session=Depends(require_ui_session)):
    user_id = session["user_sub"]
    try:
        result = social_service.follow_user(user_id, req.target_user_id)
    except ValueError as exc:
        msg = str(exc)
        if msg == "self_follow":
            raise HTTPException(status_code=400, detail="You cannot follow yourself")
        if msg == "blocked":
            raise HTTPException(status_code=403, detail="Unable to follow this user")
        if msg == "user_not_found":
            raise HTTPException(status_code=404, detail="User not found")
        if msg == "rate_limited":
            raise HTTPException(status_code=429, detail="Too many follow actions. Try again in a minute.")
        raise HTTPException(status_code=400, detail=str(exc))
    try:
        from app.services.activity_feed import record_social_interaction
        record_social_interaction(recipient_id=req.target_user_id, actor_id=user_id, kind="follow", target_type="user", target_id=req.target_user_id)
    except Exception:
        pass
    return result


@router.post("/unfollow", response_model=UnfollowResponse)
def unfollow_user(req: FollowRequest, session=Depends(require_ui_session)):
    user_id = session["user_sub"]
    result = social_service.unfollow_user(user_id, req.target_user_id)
    return result


@router.get("/{user_id}/followers", response_model=FollowListResponse)
def get_followers(
    user_id: str,
    session=Depends(require_ui_session),
    cursor: Optional[str] = Query(default=None),
    limit: int = Query(default=20, ge=1, le=100),
):
    viewer_id = session["user_sub"]
    items, next_cursor = social_service.get_followers(user_id, limit=limit, cursor=cursor)
    enriched = _enrich_follow_items(items, viewer_id, key_field="user_id")
    counts = social_service.get_follow_counts(user_id)
    return FollowListResponse(
        items=enriched,
        next_cursor=next_cursor,
        total_count=counts["follower_count"],
    )


@router.get("/{user_id}/following", response_model=FollowListResponse)
def get_following(
    user_id: str,
    session=Depends(require_ui_session),
    cursor: Optional[str] = Query(default=None),
    limit: int = Query(default=20, ge=1, le=100),
):
    viewer_id = session["user_sub"]
    items, next_cursor = social_service.get_following(user_id, limit=limit, cursor=cursor)
    enriched = _enrich_follow_items(items, viewer_id, key_field="target_user_id")
    counts = social_service.get_follow_counts(user_id)
    return FollowListResponse(
        items=enriched,
        next_cursor=next_cursor,
        total_count=counts["following_count"],
    )


@router.get("/{user_id}/counts", response_model=FollowCountsResponse)
def get_follow_counts(
    user_id: str,
    session=Depends(require_ui_session),
):
    counts = social_service.get_follow_counts(user_id)
    return counts


@router.get("/status/{target_user_id}", response_model=FollowStatusResponse)
def get_follow_status(
    target_user_id: str,
    session=Depends(require_ui_session),
):
    viewer_id = session["user_sub"]
    status = social_service.get_follow_status(viewer_id, target_user_id)
    block_status = blocking_service.get_block_status(viewer_id, target_user_id)
    return {**status, **block_status}


@router.get("/mutual/{target_user_id}", response_model=FollowListResponse)
def get_mutual_followers(
    target_user_id: str,
    session=Depends(require_ui_session),
    cursor: Optional[str] = Query(default=None),
    limit: int = Query(default=20, ge=1, le=100),
):
    viewer_id = session["user_sub"]
    items, next_cursor = social_service.get_mutual_followers(
        viewer_id, target_user_id, limit=limit, cursor=cursor,
    )
    enriched = _enrich_follow_items(items, viewer_id)
    return FollowListResponse(
        items=enriched,
        next_cursor=next_cursor,
        total_count=len(enriched),
    )


# ---------------------------------------------------------------------------
# Snooze Following endpoints (SOCIAL-007)
# ---------------------------------------------------------------------------


@router.get("/following/snoozed", response_model=SnoozedFollowingListOut)
def list_snoozed_following(session=Depends(require_ui_session)):
    """List all of the viewer's currently-snoozed followings."""
    viewer_id = session["user_sub"]
    rows = social_service.list_snoozed_followings(viewer_id)
    return SnoozedFollowingListOut(
        snoozed=[SnoozedFollowingOut(**r) for r in rows],
        total=len(rows),
    )


@router.post("/following/{user_id}/snooze", response_model=SnoozeFollowingOut)
def snooze_following(
    user_id: str,
    body: SnoozeFollowingIn,
    session=Depends(require_ui_session),
):
    """Snooze a followed user's content for N days (1-90)."""
    viewer_id = session["user_sub"]
    try:
        result = social_service.snooze_following(viewer_id, user_id, body.days)
    except ValueError as exc:
        msg = str(exc)
        if msg == "self_snooze":
            raise HTTPException(status_code=400, detail="Cannot snooze yourself")
        if msg == "not_following":
            raise HTTPException(status_code=404, detail="Not following this user")
        if msg == "invalid_duration":
            raise HTTPException(status_code=422, detail="Invalid snooze duration")
        raise HTTPException(status_code=400, detail=msg)
    return result


@router.delete("/following/{user_id}/snooze", response_model=UnsnoozeFollowingOut)
def unsnooze_following(user_id: str, session=Depends(require_ui_session)):
    """Remove snooze from a followed user (idempotent)."""
    viewer_id = session["user_sub"]
    return social_service.unsnooze_following(viewer_id, user_id)


# ---------------------------------------------------------------------------
# Block / Unblock endpoints
# ---------------------------------------------------------------------------


@router.post("/block", response_model=BlockActionResponse)
def block_user(req: BlockRequest, session=Depends(require_ui_session)):
    user_id = session["user_sub"]
    try:
        result = blocking_service.block_user(user_id, req.target_user_id, reason=req.reason)
    except ValueError as exc:
        msg = str(exc)
        if msg == "self_block":
            raise HTTPException(status_code=400, detail="Cannot block yourself")
        if msg == "already_blocked":
            raise HTTPException(status_code=409, detail="Already blocked")
        raise HTTPException(status_code=400, detail=str(exc))
    return result


@router.post("/unblock", response_model=BlockActionResponse)
def unblock_user(req: UnblockRequest, session=Depends(require_ui_session)):
    user_id = session["user_sub"]
    result = blocking_service.unblock_user(user_id, req.target_user_id)
    return result


@router.get("/blocked", response_model=BlockedUsersListResponse)
def get_blocked_users(
    session=Depends(require_ui_session),
    limit: int = Query(default=20, ge=1, le=100),
    cursor: Optional[str] = Query(default=None),
):
    user_id = session["user_sub"]
    # Decode cursor from string to DDB key if provided
    from app.core.cursor import decode_cursor, encode_cursor
    eks = decode_cursor(cursor)
    items, last_key, count = blocking_service.get_blocked_users(user_id, limit=limit, cursor=eks)
    return BlockedUsersListResponse(
        blocked_users=[BlockedUserItem(**it) for it in items],
        next_cursor=encode_cursor(last_key),
        total_count=count,
    )


@router.get("/block-status/{target_user_id}", response_model=BlockStatusResponse)
def get_block_status(
    target_user_id: str,
    session=Depends(require_ui_session),
):
    user_id = session["user_sub"]
    status = blocking_service.get_block_status(user_id, target_user_id)
    return status
