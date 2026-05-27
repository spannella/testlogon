"""Stories / Ephemeral Content router (FEED-002)."""
from __future__ import annotations

import logging
from typing import Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.core.settings import S
from app.services.sessions import require_ui_session
from app.services.stories import (
    _story_out,
    count_stories_today,
    create_highlight_group,
    create_story,
    delete_highlight_group,
    delete_story,
    get_story,
    get_story_bar,
    get_story_viewers,
    get_user_highlights,
    get_user_stories,
    highlight_story,
    record_view,
    unhighlight_story,
)

router = APIRouter(prefix="/ui/stories", tags=["stories"])
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------

class CreateStoryRequest(BaseModel):
    media_type: str = Field(..., pattern="^(image|video)$")
    media_url: str = Field(..., min_length=1)
    text_overlay: Optional[str] = Field(None, max_length=200)
    link_url: Optional[str] = None
    link_label: Optional[str] = Field(None, max_length=100)
    duration_seconds: Optional[int] = Field(None, ge=1, le=300)


class HighlightRequest(BaseModel):
    group_id: Optional[str] = None


class CreateHighlightGroupRequest(BaseModel):
    title: str = Field(..., min_length=1, max_length=100)
    cover_url: Optional[str] = None


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

def _ensure_stories_enabled():
    if not S.stories_enabled:
        raise HTTPException(status_code=404, detail="stories feature is disabled")


# --- Fixed-path routes (must come BEFORE /{story_id} to avoid path collision) ---

@router.post("", status_code=201)
def create_story_endpoint(
    req: CreateStoryRequest,
    ctx: Dict = Depends(require_ui_session),
):
    _ensure_stories_enabled()
    user_id = ctx["user_sub"]

    # Validate video duration
    if req.media_type == "video" and req.duration_seconds and req.duration_seconds > S.story_max_duration_seconds:
        raise HTTPException(
            status_code=400,
            detail=f"video stories must be {S.story_max_duration_seconds} seconds or less",
        )

    # Rate limit: max stories per day
    today_count = count_stories_today(user_id)
    if today_count >= S.story_max_per_day:
        raise HTTPException(
            status_code=429,
            detail=f"maximum {S.story_max_per_day} stories per day",
        )

    item = create_story(
        user_id=user_id,
        media_type=req.media_type,
        media_url=req.media_url,
        text_overlay=req.text_overlay,
        link_url=req.link_url,
        link_label=req.link_label,
        duration_seconds=req.duration_seconds,
    )

    return {
        "story_id": item["story_id"],
        "expires_at": item["expires_at"],
        "media_url": item["media_url"],
        "created_at": item["created_at"],
    }


@router.get("/bar")
def get_story_bar_endpoint(
    ctx: Dict = Depends(require_ui_session),
):
    _ensure_stories_enabled()
    user_id = ctx["user_sub"]
    bar = get_story_bar(user_id)
    return {"bar": bar}


@router.get("/user/{user_id}")
def get_user_stories_endpoint(
    user_id: str,
    ctx: Dict = Depends(require_ui_session),
):
    _ensure_stories_enabled()
    stories = get_user_stories(user_id)
    return {"stories": [_story_out(s) for s in stories]}


@router.get("/highlights/{user_id}")
def get_highlights_endpoint(
    user_id: str,
    ctx: Dict = Depends(require_ui_session),
):
    _ensure_stories_enabled()
    return get_user_highlights(user_id)


@router.post("/highlights/groups", status_code=201)
def create_highlight_group_endpoint(
    body: CreateHighlightGroupRequest,
    ctx: Dict = Depends(require_ui_session),
):
    _ensure_stories_enabled()
    user_id = ctx["user_sub"]
    item = create_highlight_group(user_id, body.title, body.cover_url)
    return {
        "highlight_group_id": item["highlight_group_id"],
        "title": item["title"],
        "created_at": item["created_at"],
    }


@router.delete("/highlights/groups/{group_id}")
def delete_highlight_group_endpoint(
    group_id: str,
    ctx: Dict = Depends(require_ui_session),
):
    _ensure_stories_enabled()
    user_id = ctx["user_sub"]
    deleted = delete_highlight_group(user_id, group_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="highlight group not found")
    return {"ok": True}


# --- Parameterized routes (/{story_id} pattern) ---

@router.get("/{story_id}")
def get_story_endpoint(
    story_id: str,
    ctx: Dict = Depends(require_ui_session),
):
    _ensure_stories_enabled()
    story = get_story(story_id)
    if not story:
        raise HTTPException(status_code=404, detail="story not found")
    return _story_out(story)


@router.delete("/{story_id}")
def delete_story_endpoint(
    story_id: str,
    ctx: Dict = Depends(require_ui_session),
):
    _ensure_stories_enabled()
    user_id = ctx["user_sub"]
    story = get_story(story_id)
    if not story:
        raise HTTPException(status_code=404, detail="story not found")
    if story.get("author_id") != user_id:
        raise HTTPException(status_code=403, detail="forbidden")
    delete_story(story_id, user_id)
    return {"ok": True}


@router.post("/{story_id}/view")
def record_view_endpoint(
    story_id: str,
    ctx: Dict = Depends(require_ui_session),
):
    _ensure_stories_enabled()
    viewer_id = ctx["user_sub"]
    result = record_view(story_id, viewer_id)
    if result.get("error") == "not_found":
        raise HTTPException(status_code=404, detail="story not found")
    return result


@router.get("/{story_id}/viewers")
def get_viewers_endpoint(
    story_id: str,
    ctx: Dict = Depends(require_ui_session),
):
    _ensure_stories_enabled()
    user_id = ctx["user_sub"]
    story = get_story(story_id)
    if not story:
        raise HTTPException(status_code=404, detail="story not found")
    if story.get("author_id") != user_id:
        raise HTTPException(status_code=403, detail="only the story owner can view the viewers list")
    viewers = get_story_viewers(story_id)
    return {"viewers": viewers, "total_count": len(viewers)}


@router.post("/{story_id}/highlight")
def highlight_story_endpoint(
    story_id: str,
    body: HighlightRequest,
    ctx: Dict = Depends(require_ui_session),
):
    _ensure_stories_enabled()
    user_id = ctx["user_sub"]
    result = highlight_story(story_id, user_id, group_id=body.group_id)
    if result.get("error") == "forbidden":
        raise HTTPException(status_code=403, detail="forbidden")
    return result


@router.delete("/{story_id}/highlight")
def unhighlight_story_endpoint(
    story_id: str,
    ctx: Dict = Depends(require_ui_session),
):
    _ensure_stories_enabled()
    user_id = ctx["user_sub"]
    result = unhighlight_story(story_id, user_id)
    if result.get("error") == "forbidden":
        raise HTTPException(status_code=403, detail="forbidden")
    return result
