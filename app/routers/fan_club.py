"""Fan Club router — tier management, channels, badges, public tiers."""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from app.services.sessions import require_ui_session
from app.core.settings import S
from app.core.time import now_ts
from app.models import (
    ChannelCreateIn,
    ChannelMessageIn,
    ChannelMessageOut,
    ChannelOut,
    MemberBadgeOut,
    TierCreateIn,
    TierOut,
    TierReorderIn,
    TierUpdateIn,
)
from app.services.fan_club_badges import (
    get_creator_tiers,
    invalidate_badge_cache,
    resolve_member_badge,
)
from app.services.fan_club_channels import (
    add_reaction,
    create_channel,
    delete_channel_message,
    enforce_channel_access,
    get_channel,
    get_channel_messages,
    list_channels_for_user,
    pin_message,
    send_channel_message,
)
from app.services.fan_club_tiers import (
    create_tier,
    delete_tier,
    get_tier,
    get_tier_members,
    list_tiers,
    reorder_tiers,
    update_tier,
)
from app.services.fan_club_access import get_early_access_status

def _check_enabled() -> None:
    """Enforce FAN_CLUBS_ENABLED feature flag (GAP-0151)."""
    if not S.fan_clubs_enabled:
        raise HTTPException(503, "Fan club feature is disabled")


router = APIRouter(tags=["fan-club"], dependencies=[Depends(_check_enabled)])
public_router = APIRouter(tags=["fan-club-public"], dependencies=[Depends(_check_enabled)])


# ─── Tier Management ──────────────────────────────────────────────────────────

@router.post("/ui/fan-club/tiers", status_code=201)
def api_create_tier(body: TierCreateIn, session=Depends(require_ui_session)):
    user_id = session["user_sub"]
    tier = create_tier(
        creator_id=user_id,
        plan_id=body.plan_id,
        name=body.name,
        level=body.level,
        color=body.color,
        badge_emoji=body.badge_emoji,
        description=body.description,
        benefits=[b.model_dump(exclude_none=True) for b in body.benefits],
        welcome_message=body.welcome_message,
        sort_order=body.sort_order,
    )
    return _tier_out(tier)


@router.get("/ui/fan-club/tiers")
def api_list_tiers(session=Depends(require_ui_session)):
    user_id = session["user_sub"]
    tiers = list_tiers(user_id)
    return [_tier_out(t) for t in tiers if t.get("active", True)]


@router.patch("/ui/fan-club/tiers/reorder")
def api_reorder_tiers(body: TierReorderIn, session=Depends(require_ui_session)):
    user_id = session["user_sub"]
    tiers = reorder_tiers(user_id, body.tier_ids)
    return [_tier_out(t) for t in tiers if t.get("active", True)]


@router.get("/ui/fan-club/tiers/{tier_id}")
def api_get_tier(tier_id: str, session=Depends(require_ui_session)):
    user_id = session["user_sub"]
    tier = get_tier(user_id, tier_id)
    if not tier:
        raise HTTPException(status_code=404, detail="Tier not found")
    return _tier_out(tier)


@router.patch("/ui/fan-club/tiers/{tier_id}")
def api_update_tier(tier_id: str, body: TierUpdateIn, session=Depends(require_ui_session)):
    user_id = session["user_sub"]
    updates = body.model_dump(exclude_none=True)
    if "benefits" in updates and updates["benefits"] is not None:
        updates["benefits"] = [b if isinstance(b, dict) else b.model_dump(exclude_none=True) for b in updates["benefits"]]
    tier = update_tier(user_id, tier_id, updates)
    return _tier_out(tier)


@router.delete("/ui/fan-club/tiers/{tier_id}")
def api_delete_tier(tier_id: str, session=Depends(require_ui_session)):
    user_id = session["user_sub"]
    delete_tier(user_id, tier_id)
    return {"ok": True}


@router.get("/ui/fan-club/tiers/{tier_id}/members")
def api_tier_members(
    tier_id: str,
    limit: int = Query(50, ge=1, le=200),
    cursor: Optional[str] = None,
    session=Depends(require_ui_session),
):
    user_id = session["user_sub"]
    return get_tier_members(user_id, tier_id, limit=limit, cursor=cursor)


# ─── Channel Endpoints ────────────────────────────────────────────────────────

@router.post("/ui/fan-club/channels", status_code=201)
def api_create_channel(body: ChannelCreateIn, session=Depends(require_ui_session)):
    user_id = session["user_sub"]
    ch = create_channel(
        creator_id=user_id,
        name=body.name,
        description=body.description,
        min_tier_level=body.min_tier_level,
        slowmode_seconds=body.slowmode_seconds,
        max_message_length=body.max_message_length,
    )
    return _channel_out(ch)


@router.get("/ui/fan-club/channels")
def api_list_channels(
    creator_id: Optional[str] = None,
    session=Depends(require_ui_session),
):
    user_id = session["user_sub"]
    cid = creator_id or user_id
    channels = list_channels_for_user(cid, user_id)
    return [_channel_out(c) for c in channels]


@router.get("/ui/fan-club/channels/{channel_id}")
def api_get_channel(channel_id: str, session=Depends(require_ui_session)):
    ch = get_channel(channel_id)
    if not ch:
        raise HTTPException(status_code=404, detail="Channel not found")
    return _channel_out(ch)


@router.post("/ui/fan-club/channels/{channel_id}/messages", status_code=201)
def api_send_channel_message(
    channel_id: str,
    body: ChannelMessageIn,
    session=Depends(require_ui_session),
):
    user_id = session["user_sub"]
    ch = get_channel(channel_id)
    if not ch:
        raise HTTPException(status_code=404, detail="Channel not found")

    msg = send_channel_message(
        channel_id=channel_id,
        sender_id=user_id,
        sender_display_name=user_id,
        text=body.text,
        creator_id=ch["creator_id"],
        reply_to_message_id=body.reply_to_message_id,
    )
    return _message_out(msg)


@router.get("/ui/fan-club/channels/{channel_id}/messages")
def api_get_channel_messages(
    channel_id: str,
    limit: int = Query(50, ge=1, le=200),
    before: Optional[str] = None,
    session=Depends(require_ui_session),
):
    user_id = session["user_sub"]
    ch = get_channel(channel_id)
    if not ch:
        raise HTTPException(status_code=404, detail="Channel not found")

    enforce_channel_access(ch, user_id, ch["creator_id"])

    messages = get_channel_messages(channel_id, limit=limit, before_sort_key=before)
    return [_message_out(m) for m in messages]


@router.delete("/ui/fan-club/channels/{channel_id}/messages/{message_id}")
def api_delete_channel_message(
    channel_id: str,
    message_id: str,
    session=Depends(require_ui_session),
):
    user_id = session["user_sub"]
    ch = get_channel(channel_id)
    if not ch:
        raise HTTPException(status_code=404, detail="Channel not found")
    # Only creator can delete messages
    if user_id != ch["creator_id"]:
        raise HTTPException(status_code=403, detail="Only the channel creator can delete messages")
    delete_channel_message(channel_id, message_id, user_id)
    return {"ok": True}


@router.post("/ui/fan-club/channels/{channel_id}/messages/{message_id}/react")
def api_add_reaction(
    channel_id: str,
    message_id: str,
    body: dict,
    session=Depends(require_ui_session),
):
    user_id = session["user_sub"]
    ch = get_channel(channel_id)
    if not ch:
        raise HTTPException(status_code=404, detail="Channel not found")
    enforce_channel_access(ch, user_id, ch["creator_id"])
    emoji = body.get("emoji", "")
    if not emoji:
        raise HTTPException(status_code=400, detail="emoji is required")
    add_reaction(channel_id, message_id, user_id, emoji)
    return {"ok": True}


@router.put("/ui/fan-club/channels/{channel_id}/pin/{message_id}")
def api_pin_message(
    channel_id: str,
    message_id: str,
    session=Depends(require_ui_session),
):
    user_id = session["user_sub"]
    ch = get_channel(channel_id)
    if not ch:
        raise HTTPException(status_code=404, detail="Channel not found")
    if user_id != ch["creator_id"]:
        raise HTTPException(status_code=403, detail="Only the channel creator can pin messages")
    pin_message(channel_id, message_id)
    return {"ok": True}


# ─── Badge Endpoints ──────────────────────────────────────────────────────────

@router.get("/ui/fan-club/badge/{creator_id}")
def api_get_badge(creator_id: str, session=Depends(require_ui_session)):
    user_id = session["user_sub"]
    badge = resolve_member_badge(user_id, creator_id)
    if not badge:
        return None
    return badge


@router.post("/ui/fan-club/badge/{creator_id}/invalidate")
def api_invalidate_badge(creator_id: str, session=Depends(require_ui_session)):
    user_id = session["user_sub"]
    invalidate_badge_cache(user_id, creator_id)
    return {"ok": True}


# ─── Early Access ─────────────────────────────────────────────────────────────

@router.post("/ui/fan-club/early-access-check")
def api_early_access_check(body: dict, session=Depends(require_ui_session)):
    user_id = session["user_sub"]
    creator_id = body.get("creator_id", "")
    content = body.get("content", {})
    return get_early_access_status(user_id, creator_id, content)


# ─── Public Tier Listing ─────────────────────────────────────────────────────

@public_router.get("/api/creators/{creator_id}/tiers")
def api_public_tiers(creator_id: str):
    tiers = get_creator_tiers(creator_id)
    return [_tier_out(t) for t in tiers]


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _tier_out(t: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "tier_id": t.get("tier_id"),
        "creator_id": t.get("creator_id"),
        "plan_id": t.get("plan_id"),
        "name": t.get("name"),
        "level": int(t.get("level", 0)),
        "color": t.get("color"),
        "badge_emoji": t.get("badge_emoji"),
        "badge_image_url": t.get("badge_image_url"),
        "description": t.get("description"),
        "benefits": t.get("benefits", []),
        "welcome_message": t.get("welcome_message"),
        "member_count": int(t.get("member_count", 0)),
        "sort_order": int(t.get("sort_order", 0)),
        "active": bool(t.get("active", True)),
        "created_at": int(t.get("created_at", 0)),
        "updated_at": int(t.get("updated_at", 0)),
    }


def _channel_out(c: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "channel_id": c.get("channel_id"),
        "creator_id": c.get("creator_id"),
        "name": c.get("name"),
        "description": c.get("description"),
        "min_tier_level": int(c.get("min_tier_level", 1)),
        "message_count": int(c.get("message_count", 0)),
        "last_message_at": int(c.get("last_message_at", 0)),
        "last_message_preview": c.get("last_message_preview"),
        "pinned_message_id": c.get("pinned_message_id"),
        "slowmode_seconds": int(c.get("slowmode_seconds", 0)),
        "max_message_length": int(c.get("max_message_length", 500)),
        "created_at": int(c.get("created_at", 0)),
        "updated_at": int(c.get("updated_at", 0)),
    }


def _message_out(m: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "message_id": m.get("message_id"),
        "channel_id": m.get("channel_id"),
        "sender_id": m.get("sender_id"),
        "sender_display_name": m.get("sender_display_name"),
        "sender_badge": m.get("sender_badge"),
        "text": m.get("text"),
        "kind": m.get("kind", "text"),
        "reply_to_message_id": m.get("reply_to_message_id"),
        "reactions": m.get("reactions", {}),
        "created_at": int(m.get("created_at", 0)),
        "deleted": bool(m.get("deleted", False)),
    }
