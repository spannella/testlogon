from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from app.auth.deps import AuthenticatedUser, get_authenticated_user
from app.services.discovery import (
    search_users,
    get_suggested_users,
    get_trending_creators,
    get_discovery_profile,
    index_user_for_discovery,
)

router = APIRouter(prefix="/ui/discover", tags=["discovery"])


@router.get("/search")
async def discover_search(
    q: str = Query(..., min_length=1, max_length=64),
    limit: int = Query(default=20, ge=1, le=50),
    cursor: Optional[str] = Query(default=None),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    items, next_cursor = search_users(q, viewer_id=user.sub, limit=limit, cursor=cursor)
    return {"items": items, "next_cursor": next_cursor, "total_estimate": len(items)}


@router.get("/suggested")
async def discover_suggested(
    limit: int = Query(default=12, ge=1, le=50),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    items = get_suggested_users(user.sub, limit=limit)
    return {"items": items, "next_cursor": None, "total_estimate": len(items)}


@router.get("/trending")
async def discover_trending(
    limit: int = Query(default=20, ge=1, le=50),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    items = get_trending_creators(viewer_id=user.sub, limit=limit)
    return {"items": items, "next_cursor": None, "total_estimate": len(items)}


@router.get("/profile/{user_id}")
async def discover_profile(
    user_id: str,
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    result = get_discovery_profile(user_id, viewer_id=user.sub)
    if not result:
        raise HTTPException(status_code=404, detail="User not found")
    return result


@router.post("/reindex")
async def discover_reindex_user(
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    count = index_user_for_discovery(user.sub)
    return {"ok": True, "tokens_indexed": count}
