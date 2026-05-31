"""
Media Preferences router — GET / PUT for user media device preferences.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends

from app.models import MediaPreferencesIn, MediaPreferencesOut
from app.services.media_preferences import get_preferences, save_preferences
from app.services.sessions import require_ui_session

router = APIRouter(prefix="/ui/media/preferences", tags=["media-preferences"])


@router.get("", response_model=MediaPreferencesOut)
async def ui_get_media_preferences(ctx=Depends(require_ui_session)):
    prefs = get_preferences(ctx["user_sub"])
    if prefs is None:
        # Return defaults
        return MediaPreferencesOut(user_sub=ctx["user_sub"])
    return prefs


@router.put("", response_model=MediaPreferencesOut)
async def ui_save_media_preferences(
    body: MediaPreferencesIn,
    ctx=Depends(require_ui_session),
):
    result = save_preferences(ctx["user_sub"], body.model_dump())
    return result
