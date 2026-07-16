"""Stories / Ephemeral Content service (FEED-002).

Stories are 24-hour ephemeral posts stored in app_single_table with DynamoDB TTL.
"""
from __future__ import annotations

import logging
import os
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from boto3.dynamodb.conditions import Attr, Key
from botocore.exceptions import ClientError

from app.core.aws import ddb
from app.core.settings import S
from app.core.tables import T

logger = logging.getLogger(__name__)

APP_TABLE = os.environ.get("APP_TABLE", "app_single_table")
tbl = ddb.Table(APP_TABLE)


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _now_ts() -> int:
    return int(time.time())


# ---------------------------------------------------------------------------
# Story CRUD
# ---------------------------------------------------------------------------

def create_story(
    user_id: str,
    media_type: str,
    media_url: str,
    text_overlay: Optional[str] = None,
    link_url: Optional[str] = None,
    link_label: Optional[str] = None,
    duration_seconds: Optional[int] = None,
) -> Dict[str, Any]:
    """Create a new story. Returns the created item dict."""
    story_id = f"st_{uuid.uuid4().hex}"
    created_at = _now_iso()
    now = _now_ts()
    expires_at = now + S.story_expiry_seconds

    item: Dict[str, Any] = {
        "pk": f"STORY#{story_id}",
        "sk": "META",
        "Entity": "Story",
        "story_id": story_id,
        "author_id": user_id,
        "media_type": media_type,
        "media_url": media_url,
        "created_at": created_at,
        "expires_at": expires_at,
        "ttl_epoch": expires_at,
        "view_count": 0,
        "highlighted": False,
        "GSI1PK": f"STORIES#{user_id}",
        "GSI1SK": f"{created_at}#STORY#{story_id}",
    }
    if text_overlay:
        item["text_overlay"] = text_overlay
    if link_url:
        item["link_url"] = link_url
    if link_label:
        item["link_label"] = link_label
    if duration_seconds is not None:
        item["duration_seconds"] = duration_seconds

    tbl.put_item(Item=item)
    return item


def get_story(story_id: str) -> Optional[Dict[str, Any]]:
    """Get a single story by ID."""
    resp = tbl.get_item(Key={"pk": f"STORY#{story_id}", "sk": "META"})
    return resp.get("Item")


def get_user_stories(user_id: str, include_expired: bool = False) -> List[Dict[str, Any]]:
    """Get all active stories for a user via GSI1."""
    resp = tbl.query(
        IndexName="GSI1",
        KeyConditionExpression=Key("GSI1PK").eq(f"STORIES#{user_id}"),
        ScanIndexForward=False,
    )
    items = resp.get("Items", [])
    if not include_expired:
        now = _now_ts()
        items = [
            it for it in items
            if int(it.get("expires_at", 0)) > now or it.get("highlighted") is True
        ]
    # MODX-12: drop moderation-hidden stories from listings (reversible on reinstate).
    items = [it for it in items if not (it.get("moderation_hidden") or it.get("moderation_removed"))]
    return items


def delete_story(story_id: str, user_id: str) -> bool:
    """Delete own story. Returns True if deleted, False if not found/not owner."""
    story = get_story(story_id)
    if not story:
        return False
    if story.get("author_id") != user_id:
        return False
    tbl.delete_item(Key={"pk": f"STORY#{story_id}", "sk": "META"})
    return True


def count_stories_today(user_id: str) -> int:
    """Count stories created by user in the last 24 hours."""
    stories = get_user_stories(user_id, include_expired=True)
    cutoff_ts = _now_ts() - 86400
    count = 0
    for s in stories:
        # Parse created_at ISO to check if within last 24h
        try:
            created = datetime.strptime(s["created_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
            if created.timestamp() > cutoff_ts:
                count += 1
        except (KeyError, ValueError):
            pass
    return count


# ---------------------------------------------------------------------------
# View Tracking
# ---------------------------------------------------------------------------

def record_view(story_id: str, viewer_id: str) -> Dict[str, Any]:
    """Record a view on a story. Idempotent per viewer."""
    story = get_story(story_id)
    if not story:
        return {"ok": False, "error": "not_found"}

    view_key = {"pk": f"STORYVIEW#{story_id}", "sk": f"VIEWER#{viewer_id}"}
    existing = tbl.get_item(Key=view_key).get("Item")
    if existing:
        return {"ok": True, "already_viewed": True}

    view_item = {
        **view_key,
        "Entity": "StoryView",
        "viewed_at": _now_iso(),
        "ttl_epoch": int(story.get("expires_at", 0)) + 86400,
    }
    tbl.put_item(Item=view_item)

    # Increment view_count on the story
    try:
        tbl.update_item(
            Key={"pk": f"STORY#{story_id}", "sk": "META"},
            UpdateExpression="ADD view_count :one",
            ExpressionAttributeValues={":one": 1},
        )
    except ClientError:
        logger.exception("Failed to increment view count for story %s", story_id)

    return {"ok": True, "already_viewed": False}


def has_viewed(story_id: str, viewer_id: str) -> bool:
    """Check if viewer has viewed a story."""
    view_key = {"pk": f"STORYVIEW#{story_id}", "sk": f"VIEWER#{viewer_id}"}
    return bool(tbl.get_item(Key=view_key).get("Item"))


def get_story_viewers(story_id: str) -> List[Dict[str, Any]]:
    """List all viewers of a story."""
    resp = tbl.query(
        KeyConditionExpression=Key("pk").eq(f"STORYVIEW#{story_id}"),
    )
    items = resp.get("Items", [])
    viewers = []
    for it in items:
        viewer_id = it.get("sk", "").replace("VIEWER#", "")
        viewers.append({
            "user_id": viewer_id,
            "viewed_at": it.get("viewed_at", ""),
        })
    return viewers


# ---------------------------------------------------------------------------
# Story Bar (feed of followed creators' stories)
# ---------------------------------------------------------------------------

def get_story_bar(user_id: str) -> List[Dict[str, Any]]:
    """Get story bar entries for followed creators with active stories."""
    from app.services.social import get_following

    bar: List[Dict[str, Any]] = []
    now = _now_ts()

    # Paginate through followed users (up to story_bar_max_followed)
    followed_ids: List[str] = []
    cursor = None
    while len(followed_ids) < S.story_bar_max_followed:
        remaining = S.story_bar_max_followed - len(followed_ids)
        items, cursor = get_following(user_id, limit=min(remaining, 200), cursor=cursor)
        for it in items:
            target = it.get("target_user_id") or it.get("sk", "").replace("FOLLOWING#", "")
            if target:
                followed_ids.append(target)
        if not cursor:
            break

    # Also include the user's own stories in the bar
    all_ids = [user_id] + followed_ids

    for creator_id in all_ids:
        resp = tbl.query(
            IndexName="GSI1",
            KeyConditionExpression=Key("GSI1PK").eq(f"STORIES#{creator_id}"),
            ScanIndexForward=False,
            Limit=10,
        )
        items = resp.get("Items", [])
        active = [it for it in items if (int(it.get("expires_at", 0)) > now or it.get("highlighted") is True) and not (it.get("moderation_hidden") or it.get("moderation_removed"))]
        if not active:
            continue

        latest = active[0]
        # Check if viewer has seen the latest story
        has_unseen = not has_viewed(latest["story_id"], user_id)

        bar.append({
            "user_id": creator_id,
            "latest_story_id": latest["story_id"],
            "latest_media_url": latest.get("media_url", ""),
            "story_count": len(active),
            "has_unseen": has_unseen,
            "is_own": creator_id == user_id,
        })

    # Sort: own first, then unseen, then seen
    bar.sort(key=lambda x: (not x.get("is_own", False), not x.get("has_unseen", False)))
    return bar


# ---------------------------------------------------------------------------
# Highlights
# ---------------------------------------------------------------------------

def highlight_story(story_id: str, user_id: str, group_id: Optional[str] = None) -> Dict[str, Any]:
    """Pin a story to highlights (remove TTL)."""
    story = get_story(story_id)
    if not story or story.get("author_id") != user_id:
        return {"ok": False, "error": "forbidden"}

    update_expr = "SET highlighted = :t"
    expr_values: Dict[str, Any] = {":t": True}
    remove_parts = ["ttl_epoch"]

    if group_id:
        update_expr += ", highlight_group_id = :g"
        expr_values[":g"] = group_id

    update_expr += " REMOVE " + ", ".join(remove_parts)

    tbl.update_item(
        Key={"pk": f"STORY#{story_id}", "sk": "META"},
        UpdateExpression=update_expr,
        ExpressionAttributeValues=expr_values,
    )
    return {"ok": True}


def unhighlight_story(story_id: str, user_id: str) -> Dict[str, Any]:
    """Unpin a story from highlights (re-apply TTL from original creation time)."""
    story = get_story(story_id)
    if not story or story.get("author_id") != user_id:
        return {"ok": False, "error": "forbidden"}

    # Re-apply TTL based on original expires_at
    expires_at = int(story.get("expires_at", _now_ts() + S.story_expiry_seconds))

    tbl.update_item(
        Key={"pk": f"STORY#{story_id}", "sk": "META"},
        UpdateExpression="SET highlighted = :f, ttl_epoch = :ttl REMOVE highlight_group_id",
        ExpressionAttributeValues={":f": False, ":ttl": expires_at},
    )
    return {"ok": True}


def create_highlight_group(user_id: str, title: str, cover_url: Optional[str] = None) -> Dict[str, Any]:
    """Create a highlight group for a user's profile."""
    group_id = f"hg_{uuid.uuid4().hex[:12]}"
    item: Dict[str, Any] = {
        "pk": f"USER#{user_id}",
        "sk": f"HIGHLIGHT#{group_id}",
        "Entity": "StoryHighlightGroup",
        "highlight_group_id": group_id,
        "title": title,
        "created_at": _now_iso(),
    }
    if cover_url:
        item["cover_url"] = cover_url
    tbl.put_item(Item=item)
    return item


def delete_highlight_group(user_id: str, group_id: str) -> bool:
    """Delete a highlight group."""
    key = {"pk": f"USER#{user_id}", "sk": f"HIGHLIGHT#{group_id}"}
    existing = tbl.get_item(Key=key).get("Item")
    if not existing:
        return False
    tbl.delete_item(Key=key)
    return True


def get_user_highlights(user_id: str) -> Dict[str, Any]:
    """Get all highlight groups and their stories for a user."""
    # Get highlight groups
    resp = tbl.query(
        KeyConditionExpression=Key("pk").eq(f"USER#{user_id}") & Key("sk").begins_with("HIGHLIGHT#"),
    )
    groups = resp.get("Items", [])

    # Get all highlighted stories for this user
    stories_resp = tbl.query(
        IndexName="GSI1",
        KeyConditionExpression=Key("GSI1PK").eq(f"STORIES#{user_id}"),
        FilterExpression=Attr("highlighted").eq(True),
    )
    highlighted_stories = stories_resp.get("Items", [])

    # Organize stories by group
    result_groups = []
    for g in groups:
        gid = g.get("highlight_group_id", "")
        group_stories = [s for s in highlighted_stories if s.get("highlight_group_id") == gid]
        result_groups.append({
            "highlight_group_id": gid,
            "title": g.get("title", ""),
            "cover_url": g.get("cover_url"),
            "created_at": g.get("created_at", ""),
            "stories": [_story_out(s) for s in group_stories],
        })

    return {"groups": result_groups}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _story_out(item: Dict[str, Any]) -> Dict[str, Any]:
    """Convert a raw DDB story item to API response format."""
    out: Dict[str, Any] = {
        "story_id": item["story_id"],
        "author_id": item["author_id"],
        "media_type": item.get("media_type", "image"),
        "media_url": item.get("media_url", ""),
        "created_at": item.get("created_at", ""),
        "expires_at": int(item.get("expires_at", 0)),
        "view_count": int(item.get("view_count", 0)),
        "highlighted": bool(item.get("highlighted", False)),
    }
    if item.get("text_overlay"):
        out["text_overlay"] = item["text_overlay"]
    if item.get("link_url"):
        out["link_url"] = item["link_url"]
    if item.get("link_label"):
        out["link_label"] = item["link_label"]
    if item.get("duration_seconds") is not None:
        out["duration_seconds"] = int(item["duration_seconds"])
    if item.get("highlight_group_id"):
        out["highlight_group_id"] = item["highlight_group_id"]
    return out
