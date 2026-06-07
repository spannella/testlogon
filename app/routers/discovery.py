from __future__ import annotations

import logging
import os
import re
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Key
from fastapi import APIRouter, Depends, HTTPException, Query

from app.auth.deps import AuthenticatedUser, get_authenticated_user
from app.auth.policy import require_admin_or_root
from app.core.aws import ddb
from app.services.discovery import (
    search_users,
    get_suggested_users,
    get_trending_creators,
    get_discovery_profile,
    index_user_for_discovery,
    reindex_all_users,
)

logger = logging.getLogger(__name__)

_APP_TABLE = os.environ.get("APP_TABLE", "app_single_table")
_tbl = ddb.Table(_APP_TABLE)
_TAG_PATH_RE = re.compile(r"^[a-z][a-z0-9_]{0,49}$")

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


@router.post("/admin/reindex-all")
async def discover_reindex_all(
    user: AuthenticatedUser = Depends(require_admin_or_root),
):
    """Admin/root-gated bulk reindex of ALL users for discovery."""
    summary = reindex_all_users()
    return {"ok": True, **summary}


# ─── SOCIAL-006: Hashtag/Tag Discovery ────────────────────���───────────────────


@router.get("/trending-tags")
async def discover_trending_tags(
    limit: int = Query(default=20, ge=1, le=50),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    """Get trending tags sorted by usage count (most-used first)."""
    try:
        resp = _tbl.query(
            KeyConditionExpression=Key("pk").eq("TAG_STATS") & Key("sk").begins_with("TAG#"),
            ScanIndexForward=False,
        )
        items = resp.get("Items", [])
    except Exception:
        logger.exception("Failed to query TAG_STATS")
        items = []

    # Sort by count descending, then take top N
    tags = []
    for item in items:
        tag_name = (item.get("sk") or "").replace("TAG#", "", 1)
        count = int(item.get("count", 0))
        last_used_at = item.get("last_used_at", "")
        if tag_name and count > 0:
            tags.append({"tag": tag_name, "count": count, "last_used_at": last_used_at})

    tags.sort(key=lambda t: t["count"], reverse=True)
    return {"tags": tags[:limit]}


@router.get("/tags/{tag}")
async def discover_tag(
    tag: str,
    limit: int = Query(default=20, ge=1, le=50),
    cursor: Optional[str] = Query(default=None),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    """Get posts tagged with a specific hashtag, newest first."""
    tag_lower = tag.lower().lstrip("#").strip()
    if not _TAG_PATH_RE.match(tag_lower):
        return {"tag": tag_lower, "posts": [], "next_cursor": None}

    query_kwargs: Dict[str, Any] = {
        "KeyConditionExpression": Key("pk").eq(f"TAG#{tag_lower}"),
        "ScanIndexForward": False,
        "Limit": limit,
    }
    if cursor:
        import json, base64
        try:
            eks = json.loads(base64.b64decode(cursor).decode())
            query_kwargs["ExclusiveStartKey"] = eks
        except Exception:
            raise HTTPException(status_code=400, detail="invalid cursor")

    try:
        resp = _tbl.query(**query_kwargs)
    except Exception:
        logger.exception("Failed to query TAG#%s", tag_lower)
        return {"tag": tag_lower, "posts": [], "next_cursor": None}

    tag_items = resp.get("Items", [])
    next_cursor = None
    if resp.get("LastEvaluatedKey"):
        import json, base64
        next_cursor = base64.b64encode(json.dumps(resp["LastEvaluatedKey"]).encode()).decode()

    # Fetch actual post items
    from app.routers.newsfeed import _post_to_dict

    posts: List[Dict[str, Any]] = []
    for tag_item in tag_items:
        post_id = tag_item.get("post_id")
        if not post_id:
            continue
        try:
            post_resp = _tbl.get_item(Key={"pk": f"POST#{post_id}", "sk": "META"})
            post_item = post_resp.get("Item")
            if not post_item:
                continue
            # Only include published posts
            if post_item.get("status", "published") != "published":
                continue
            posts.append(_post_to_dict(post_item, viewer_id=user.sub))
        except Exception:
            continue

    return {"tag": tag_lower, "posts": posts, "next_cursor": next_cursor}
