"""Achievement & gamification API endpoints.

ENGAGE-001: Achievements & Gamification System.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from app.auth.deps import require_root_session
from app.services.sessions import require_ui_session
from app.core.settings import S

logger = logging.getLogger(__name__)

router = APIRouter(tags=["achievements"])


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------

class CreateAchievementDefinitionIn(BaseModel):
    achievement_id: str = Field(..., min_length=4, max_length=64)
    category: str = Field(...)
    subcategory: str = Field(..., min_length=1, max_length=32)
    label: str = Field(..., min_length=1, max_length=100)
    description: str = Field(..., min_length=1, max_length=500)
    icon_url: str = Field(..., min_length=1, max_length=256)
    rarity: str = Field(...)
    threshold: int = Field(..., ge=1)
    points: int = Field(..., ge=1, le=10000)
    metric_key: str = Field(..., min_length=1, max_length=64)
    sort_order: int = Field(default=0, ge=0)


class UpdateAchievementDefinitionIn(BaseModel):
    label: Optional[str] = Field(default=None, min_length=1, max_length=100)
    description: Optional[str] = Field(default=None, min_length=1, max_length=500)
    icon_url: Optional[str] = Field(default=None, min_length=1, max_length=256)
    rarity: Optional[str] = None
    threshold: Optional[int] = Field(default=None, ge=1)
    points: Optional[int] = Field(default=None, ge=1, le=10000)
    active: Optional[bool] = None
    sort_order: Optional[int] = Field(default=None, ge=0)
    subcategory: Optional[str] = Field(default=None, min_length=1, max_length=32)


class SetDisplayBadgesIn(BaseModel):
    achievement_ids: List[str] = Field(default_factory=list)


class AdvanceProgressIn(BaseModel):
    metric_key: str = Field(..., min_length=1, max_length=64)
    delta: int = Field(default=1, ge=0)


# ---------------------------------------------------------------------------
# Admin definition endpoints
# ---------------------------------------------------------------------------

@router.post("/ui/achievements/admin/definitions", status_code=201)
async def create_definition(req: CreateAchievementDefinitionIn, ctx: dict = Depends(require_root_session)):
    from app.services.achievement_definitions import create_definition as _create
    return _create(
        achievement_id=req.achievement_id,
        category=req.category,
        subcategory=req.subcategory,
        label=req.label,
        description=req.description,
        icon_url=req.icon_url,
        rarity=req.rarity,
        threshold=req.threshold,
        points=req.points,
        metric_key=req.metric_key,
        sort_order=req.sort_order,
    )


@router.put("/ui/achievements/admin/definitions/{achievement_id}")
async def update_definition(
    achievement_id: str,
    req: UpdateAchievementDefinitionIn,
    ctx: dict = Depends(require_root_session),
):
    from app.services.achievement_definitions import update_definition as _update
    return _update(achievement_id, **req.model_dump(exclude_none=True))


@router.delete("/ui/achievements/admin/definitions/{achievement_id}")
async def delete_definition(
    achievement_id: str,
    ctx: dict = Depends(require_root_session),
):
    from app.services.achievement_definitions import delete_definition as _delete
    _delete(achievement_id)
    return {"ok": True}


@router.get("/ui/achievements/definitions")
async def list_definitions(
    active_only: bool = Query(True),
    ctx: dict = Depends(require_ui_session),
):
    from app.services.achievement_definitions import list_definitions as _list
    return {"definitions": _list(active_only=active_only)}


@router.post("/ui/achievements/admin/seed")
async def seed_default_achievements(ctx: dict = Depends(require_root_session)):
    """Seed a set of default achievement definitions."""
    from app.services.achievement_definitions import create_definition as _create
    defaults = _get_default_achievements()
    created = []
    for defn in defaults:
        try:
            result = _create(**defn)
            created.append(result["achievement_id"])
        except HTTPException:
            pass  # skip duplicates
    return {"ok": True, "created": created, "count": len(created)}


# ---------------------------------------------------------------------------
# User achievement endpoints
# ---------------------------------------------------------------------------

@router.get("/ui/achievements")
async def get_my_achievements(
    displayed: Optional[bool] = None,
    category: Optional[str] = None,
    ctx: dict = Depends(require_ui_session),
):
    user_sub = ctx["user_sub"]
    from app.services.achievement_progress import get_user_achievements
    achievements = get_user_achievements(user_sub)

    if displayed is not None:
        achievements = [a for a in achievements if a["displayed"] == displayed]
    if category is not None:
        achievements = [a for a in achievements if a.get("category") == category]

    total_points = sum(a["points"] for a in achievements)
    return {
        "achievements": achievements,
        "total_points": total_points,
        "achievement_count": len(achievements),
    }


@router.get("/ui/achievements/progress")
async def get_all_progress(ctx: dict = Depends(require_ui_session)):
    user_sub = ctx["user_sub"]
    from app.services.achievement_progress import list_all_progress
    from app.services.achievement_definitions import list_achievements_for_metric
    progress = list_all_progress(user_sub)

    # Enrich with next_threshold and next_achievement
    for p in progress:
        metric_key = p["metric_key"]
        current = p["current_value"]
        defs = list_achievements_for_metric(metric_key)
        # Find next unmet threshold
        next_def = None
        for d in sorted(defs, key=lambda x: x["threshold"]):
            if d["threshold"] > current:
                next_def = d
                break
        if next_def:
            p["next_threshold"] = next_def["threshold"]
            p["next_achievement"] = {
                "achievement_id": next_def["achievement_id"],
                "label": next_def["label"],
                "rarity": next_def["rarity"],
                "points": next_def["points"],
            }
        else:
            p["next_threshold"] = None
            p["next_achievement"] = None

    return {"progress": progress}


@router.get("/ui/achievements/progress/{metric_key}")
async def get_progress_for_metric(metric_key: str, ctx: dict = Depends(require_ui_session)):
    user_sub = ctx["user_sub"]
    from app.services.achievement_progress import get_progress
    p = get_progress(user_sub, metric_key)
    if not p:
        p = {
            "metric_key": metric_key,
            "current_value": 0,
            "last_updated_at": 0,
            "last_updated_date": "",
            "highest_value": 0,
        }
    return p


@router.get("/ui/achievements/earned")
async def get_earned_achievements(ctx: dict = Depends(require_ui_session)):
    user_sub = ctx["user_sub"]
    from app.services.achievement_progress import get_user_achievements
    achievements = get_user_achievements(user_sub)
    total_points = sum(a["points"] for a in achievements)
    return {
        "achievements": achievements,
        "total_points": total_points,
        "achievement_count": len(achievements),
    }


# ---------------------------------------------------------------------------
# Display badges
# ---------------------------------------------------------------------------

@router.post("/ui/achievements/display-badges")
async def set_display_badges_endpoint(req: SetDisplayBadgesIn, ctx: dict = Depends(require_ui_session)):
    user_sub = ctx["user_sub"]
    from app.services.achievement_badges import set_display_badges
    badges = set_display_badges(user_sub, req.achievement_ids)
    return {"ok": True, "display_badges": badges}


@router.get("/ui/achievements/display-badges/{user_sub}")
async def get_display_badges_endpoint(user_sub: str, ctx: dict = Depends(require_ui_session)):
    from app.services.achievement_badges import get_display_badges
    from app.services.achievement_progress import get_user_achievements
    badges = get_display_badges(user_sub)
    achievements = get_user_achievements(user_sub)
    total_points = sum(a["points"] for a in achievements)
    return {
        "user_sub": user_sub,
        "display_badges": badges,
        "total_points": total_points,
        "achievement_count": len(achievements),
    }


# ---------------------------------------------------------------------------
# Leaderboard
# ---------------------------------------------------------------------------

@router.get("/ui/achievements/leaderboard")
async def get_leaderboard_endpoint(
    period: str = Query("weekly"),
    limit: int = Query(50, ge=1, le=100),
    cursor: Optional[str] = None,
    ctx: dict = Depends(require_ui_session),
):
    from app.services.achievement_leaderboard import get_leaderboard
    entries, next_cursor = get_leaderboard(period=period, limit=limit, cursor=cursor)
    return {
        "period": period,
        "entries": entries,
        "next_cursor": next_cursor,
    }


@router.get("/ui/achievements/leaderboard/me")
async def get_my_rank_endpoint(
    period: str = Query("weekly"),
    ctx: dict = Depends(require_ui_session),
):
    user_sub = ctx["user_sub"]
    from app.services.achievement_leaderboard import get_my_rank
    return get_my_rank(user_sub, period=period)


# ---------------------------------------------------------------------------
# Admin progress advance (for testing)
# ---------------------------------------------------------------------------

@router.post("/ui/achievements/admin/advance")
async def admin_advance_progress(req: AdvanceProgressIn, ctx: dict = Depends(require_ui_session)):
    """Advance progress for the authenticated user (dev/test helper)."""
    user_sub = ctx["user_sub"]
    from app.services.achievement_progress import advance_progress
    unlocked = advance_progress(user_sub, req.metric_key, delta=req.delta)
    return {"ok": True, "newly_unlocked": unlocked}


# ---------------------------------------------------------------------------
# Default achievement definitions for seeding
# ---------------------------------------------------------------------------

def _get_default_achievements() -> List[Dict[str, Any]]:
    return [
        {"achievement_id": "ach_first_post", "category": "creator", "subcategory": "posting", "label": "First Post", "description": "Create your first post", "icon_url": "/assets/badges/first-post.svg", "rarity": "common", "threshold": 1, "points": 10, "metric_key": "post_count", "sort_order": 0},
        {"achievement_id": "ach_regular_poster", "category": "creator", "subcategory": "posting", "label": "Regular Poster", "description": "Create 10 posts", "icon_url": "/assets/badges/regular-poster.svg", "rarity": "common", "threshold": 10, "points": 25, "metric_key": "post_count", "sort_order": 1},
        {"achievement_id": "ach_prolific_creator", "category": "creator", "subcategory": "posting", "label": "Prolific Creator", "description": "Create 100 posts", "icon_url": "/assets/badges/prolific-creator.svg", "rarity": "uncommon", "threshold": 100, "points": 100, "metric_key": "post_count", "sort_order": 2},
        {"achievement_id": "ach_posting_streak_7", "category": "creator", "subcategory": "posting", "label": "Week Warrior", "description": "Post every day for 7 consecutive days", "icon_url": "/assets/badges/week-warrior.svg", "rarity": "uncommon", "threshold": 7, "points": 50, "metric_key": "posting_streak", "sort_order": 10},
        {"achievement_id": "ach_first_tip", "category": "viewer", "subcategory": "tipping", "label": "First Tip", "description": "Send your first tip", "icon_url": "/assets/badges/first-tip.svg", "rarity": "common", "threshold": 1, "points": 10, "metric_key": "tip_count", "sort_order": 0},
        {"achievement_id": "ach_generous_tipper", "category": "viewer", "subcategory": "tipping", "label": "Generous Tipper", "description": "Send 50 tips", "icon_url": "/assets/badges/generous-tipper.svg", "rarity": "uncommon", "threshold": 50, "points": 100, "metric_key": "tip_count", "sort_order": 1},
        {"achievement_id": "ach_first_reaction", "category": "viewer", "subcategory": "reactions", "label": "First Reaction", "description": "React to content for the first time", "icon_url": "/assets/badges/first-reaction.svg", "rarity": "common", "threshold": 1, "points": 5, "metric_key": "reaction_count", "sort_order": 0},
    ]
