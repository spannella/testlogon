"""Feed fan-out on write — populate follower feed indexes when a post is created/deleted (SOC-002)."""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, List

from boto3.dynamodb.conditions import Key

from app.core.aws import ddb

logger = logging.getLogger(__name__)

APP_TABLE = os.environ.get("APP_TABLE", "app_single_table")
tbl = ddb.Table(APP_TABLE)

MAX_SYNC_FOLLOWERS = 500


def _get_all_follower_ids(user_id: str, limit: int = MAX_SYNC_FOLLOWERS) -> List[str]:
    """Get all follower user IDs via GSI5 (FOLLOWERS#{user_id})."""
    follower_ids: List[str] = []
    kwargs: Dict[str, Any] = {
        "IndexName": "GSI5",
        "KeyConditionExpression": Key("GSI5PK").eq(f"FOLLOWERS#{user_id}"),
        "Limit": 500,
    }
    while len(follower_ids) < limit:
        resp = tbl.query(**kwargs)
        for item in resp.get("Items", []):
            if item.get("state", "following") == "following":
                fid = item.get("user_id")
                if fid:
                    follower_ids.append(fid)
        lek = resp.get("LastEvaluatedKey")
        if not lek:
            break
        kwargs["ExclusiveStartKey"] = lek
    return follower_ids[:limit]


def fan_out_post_to_followers(
    *,
    author_id: str,
    post_id: str,
    created_at: str,
) -> int:
    """Write FEEDREF items for all followers so the post appears in their feed.

    Returns the number of follower feed refs written.
    """
    follower_ids = _get_all_follower_ids(author_id)
    if not follower_ids:
        return 0

    written = 0
    for fid in follower_ids:
        try:
            item = {
                "pk": f"POST#{post_id}",
                "sk": f"FEEDREF#{fid}",
                "Entity": "FeedRef",
                "post_id": post_id,
                "owner_user_id": author_id,
                "created_at": created_at,
                "fanout": True,
                "GSI1PK": f"FEED#{fid}",
                "GSI1SK": f"{created_at}#POST#{post_id}",
            }
            tbl.put_item(Item=item)
            written += 1
        except Exception:
            logger.exception("Failed to write feed ref for post %s to follower %s", post_id, fid)
    return written


def fan_out_delete_post(*, post_id: str) -> int:
    """Remove all FEEDREF items (both author and fan-out) for a deleted post."""
    deleted = 0
    kwargs: Dict[str, Any] = {
        "KeyConditionExpression": Key("pk").eq(f"POST#{post_id}") & Key("sk").begins_with("FEEDREF#"),
        "Limit": 1000,
    }
    while True:
        resp = tbl.query(**kwargs)
        items = resp.get("Items", [])
        for item in items:
            try:
                tbl.delete_item(Key={"pk": item["pk"], "sk": item["sk"]})
                deleted += 1
            except Exception:
                logger.exception("Failed to delete feed ref pk=%s sk=%s", item["pk"], item["sk"])
        lek = resp.get("LastEvaluatedKey")
        if not lek:
            break
        kwargs["ExclusiveStartKey"] = lek
    return deleted


def backfill_feed_on_follow(
    *,
    follower_id: str,
    followed_id: str,
    max_posts: int = 50,
) -> int:
    """When a user follows someone, backfill their recent posts into the follower's feed."""
    kwargs: Dict[str, Any] = {
        "IndexName": "GSI1",
        "KeyConditionExpression": Key("GSI1PK").eq(f"FEED#{followed_id}"),
        "ScanIndexForward": False,
        "Limit": max_posts,
    }
    resp = tbl.query(**kwargs)
    refs = resp.get("Items", [])

    written = 0
    for ref in refs:
        post_id = ref.get("post_id")
        if not post_id:
            continue
        if ref.get("sk") == f"FEEDREF#{follower_id}":
            continue

        try:
            tbl.put_item(
                Item={
                    "pk": f"POST#{post_id}",
                    "sk": f"FEEDREF#{follower_id}",
                    "Entity": "FeedRef",
                    "post_id": post_id,
                    "owner_user_id": ref.get("owner_user_id", followed_id),
                    "created_at": ref.get("created_at", ""),
                    "fanout": True,
                    "GSI1PK": f"FEED#{follower_id}",
                    "GSI1SK": ref.get("GSI1SK", ""),
                },
                ConditionExpression="attribute_not_exists(pk)",
            )
            written += 1
        except Exception:
            pass
    return written


def remove_feed_on_unfollow(
    *,
    follower_id: str,
    followed_id: str,
) -> int:
    """Remove fan-out feed refs when a user unfollows someone."""
    kwargs: Dict[str, Any] = {
        "IndexName": "GSI1",
        "KeyConditionExpression": Key("GSI1PK").eq(f"FEED#{follower_id}"),
        "ScanIndexForward": False,
        "Limit": 500,
    }
    removed = 0
    while True:
        resp = tbl.query(**kwargs)
        items = resp.get("Items", [])
        for item in items:
            if item.get("owner_user_id") == followed_id and item.get("fanout"):
                try:
                    tbl.delete_item(Key={"pk": item["pk"], "sk": item["sk"]})
                    removed += 1
                except Exception:
                    pass
        lek = resp.get("LastEvaluatedKey")
        if not lek:
            break
        kwargs["ExclusiveStartKey"] = lek
    return removed
