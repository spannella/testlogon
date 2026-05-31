"""Newsfeed delegation service (DELEGATE-003).

Enables delegates to create, edit, and delete posts on a creator's newsfeed,
moderate comments, and view analytics. Includes a draft/approval workflow.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional
from uuid import uuid4

from boto3.dynamodb.conditions import Key
from fastapi import HTTPException

from app.core.aws import ddb
from app.core.tables import T
from app.core.time import now_ts
from app.services.delegates import (
    require_delegate_permission,
    _write_audit,
)
from app.services.profile import get_profile

logger = logging.getLogger(__name__)

APP_TABLE = os.environ.get("APP_TABLE", "app_single_table")
tbl = ddb.Table(APP_TABLE)


# DDB key helpers (mirror newsfeed.py patterns)
def _pk_post(post_id: str) -> str:
    return f"POST#{post_id}"


def _sk_post() -> str:
    return "META"


def _pk_post_comments(post_id: str) -> str:
    return f"POST#{post_id}#COMMENTS"


def _new_post_id() -> str:
    return f"post_{uuid4().hex}"


def _now_iso() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Feed delegation settings (stored in delegates table)
# ---------------------------------------------------------------------------


def get_feed_delegation_settings(creator_id: str) -> Dict[str, Any]:
    """Get creator's feed delegation settings."""
    resp = T.delegates.get_item(
        Key={"pk": f"CREATOR#{creator_id}", "sk": "FEED_SETTINGS"}
    )
    item = resp.get("Item")
    if item:
        return item
    return {
        "require_post_approval": False,
        "allow_delegate_scheduling": True,
        "allow_delegate_locking": False,
        "delegate_tag_on_posts": False,
        "delegate_tag_format": "[posted by @{delegate_name}]",
    }


def update_feed_delegation_settings(
    *,
    creator_id: str,
    settings: Dict[str, Any],
) -> Dict[str, Any]:
    """Update creator's feed delegation settings."""
    item: Dict[str, Any] = {
        "pk": f"CREATOR#{creator_id}",
        "sk": "FEED_SETTINGS",
        "require_post_approval": bool(settings.get("require_post_approval", False)),
        "allow_delegate_scheduling": bool(settings.get("allow_delegate_scheduling", True)),
        "allow_delegate_locking": bool(settings.get("allow_delegate_locking", False)),
        "delegate_tag_on_posts": bool(settings.get("delegate_tag_on_posts", False)),
        "delegate_tag_format": str(settings.get("delegate_tag_format", "[posted by @{delegate_name}]")),
        "updated_at": now_ts(),
    }
    T.delegates.put_item(Item=item)
    return item


# ---------------------------------------------------------------------------
# Delegated post CRUD
# ---------------------------------------------------------------------------


def create_post_as_creator(
    *,
    creator_id: str,
    delegate_id: str,
    text: str,
    image_url: Optional[str] = None,
    lock_price_cents: int = 0,
    tags: Optional[List[str]] = None,
    scheduled_at: Optional[int] = None,
) -> Dict[str, Any]:
    """Create a newsfeed post on behalf of a creator.

    If the creator has require_post_approval enabled, the post
    is saved as a draft with approval_status=pending.
    """
    delegate_item = require_delegate_permission(
        creator_id=creator_id,
        delegate_id=delegate_id,
        required_permission="feed_post",
    )

    delegate_profile = get_profile(delegate_id) or {}
    delegate_display_name = delegate_profile.get("display_name") or delegate_id
    feed_settings = get_feed_delegation_settings(creator_id)

    # Enforce locking permission
    if lock_price_cents and lock_price_cents > 0:
        if not feed_settings.get("allow_delegate_locking", False):
            raise HTTPException(403, "Delegate is not allowed to lock posts")

    requires_approval = feed_settings.get("require_post_approval", False)

    # Build delegate tag if configured
    delegate_tag = None
    if feed_settings.get("delegate_tag_on_posts", False):
        fmt = feed_settings.get("delegate_tag_format", "[posted by @{delegate_name}]")
        delegate_tag = fmt.replace("{delegate_name}", delegate_display_name)

    post_id = _new_post_id()
    created_at = _now_iso()
    ts = now_ts()

    locked = lock_price_cents is not None and lock_price_cents > 0

    if requires_approval:
        status = "draft"
        approval_status = "pending"
    else:
        status = "published"
        approval_status = "approved"

    post_item: Dict[str, Any] = {
        "pk": _pk_post(post_id),
        "sk": _sk_post(),
        "Entity": "Post",
        "post_id": post_id,
        "user_id": creator_id,
        "created_at": created_at,
        "published_at": None if requires_approval else created_at,
        "status": status,
        "body": text,
        "body_plain": text,
        "body_format": "plain",
        "body_version": 1,
        "image_urls": [image_url] if image_url else [],
        "visibility": "followers",
        "locked": locked,
        "lock_type": "fixed_price" if locked else None,
        "unlock_price_cents": lock_price_cents if locked else None,
        "like_count": 0,
        "comment_count": 0,
        "tags": tags or [],
        "GSI2PK": f"POST_AUTHOR#{creator_id}",
        "GSI2SK": f"{created_at}#POST#{post_id}",
        # Delegate metadata
        "posted_by_delegate": delegate_id,
        "delegate_display_name": delegate_display_name,
        "approval_status": approval_status,
    }
    if delegate_tag:
        post_item["delegate_tag"] = delegate_tag
    if requires_approval:
        post_item["GSI5PK"] = f"DRAFT_QUEUE#{creator_id}"
        post_item["GSI5SK"] = ts

    tbl.put_item(Item=post_item)

    # Write author self-feed ref if published immediately
    if not requires_approval:
        _write_feed_ref(creator_id=creator_id, post_id=post_id, created_at=created_at)
        _fan_out(creator_id=creator_id, post_id=post_id, created_at=created_at)

    _write_audit(
        creator_id,
        delegate_id,
        "delegate",
        "feed_post_created",
        post_id,
        {"text_preview": text[:100], "status": status, "approval_status": approval_status},
    )

    return _post_item_to_out(post_item)


def edit_post_as_creator(
    *,
    creator_id: str,
    delegate_id: str,
    post_id: str,
    text: Optional[str] = None,
    image_url: Optional[str] = None,
    lock_price_cents: Optional[int] = None,
    tags: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Edit a creator's post on their behalf."""
    require_delegate_permission(
        creator_id=creator_id,
        delegate_id=delegate_id,
        required_permission="feed_post",
    )

    post = _get_post_or_404(post_id)
    if post.get("user_id") != creator_id:
        raise HTTPException(403, "Post does not belong to this creator")

    feed_settings = get_feed_delegation_settings(creator_id)
    if lock_price_cents is not None and lock_price_cents > 0:
        if not feed_settings.get("allow_delegate_locking", False):
            raise HTTPException(403, "Delegate is not allowed to lock posts")

    delegate_profile = get_profile(delegate_id) or {}
    delegate_display_name = delegate_profile.get("display_name") or delegate_id

    update_parts = [
        "posted_by_delegate = :del_id",
        "delegate_display_name = :del_name",
        "updated_at = :upd",
    ]
    expr_vals: Dict[str, Any] = {
        ":del_id": delegate_id,
        ":del_name": delegate_display_name,
        ":upd": _now_iso(),
    }

    if text is not None:
        update_parts.append("#body = :body")
        update_parts.append("body_plain = :body_plain")
        expr_vals[":body"] = text
        expr_vals[":body_plain"] = text

    if image_url is not None:
        update_parts.append("image_urls = :imgs")
        expr_vals[":imgs"] = [image_url] if image_url else []

    if lock_price_cents is not None:
        locked = lock_price_cents > 0
        update_parts.append("locked = :lk")
        update_parts.append("lock_type = :lt")
        update_parts.append("unlock_price_cents = :upc")
        expr_vals[":lk"] = locked
        expr_vals[":lt"] = "fixed_price" if locked else None
        expr_vals[":upc"] = lock_price_cents if locked else None

    if tags is not None:
        update_parts.append("tags = :tags")
        expr_vals[":tags"] = tags

    expr_names = {}
    if text is not None:
        expr_names["#body"] = "body"

    key = {"pk": _pk_post(post_id), "sk": _sk_post()}
    kwargs: Dict[str, Any] = {
        "Key": key,
        "UpdateExpression": "SET " + ", ".join(update_parts),
        "ExpressionAttributeValues": expr_vals,
        "ReturnValues": "ALL_NEW",
    }
    if expr_names:
        kwargs["ExpressionAttributeNames"] = expr_names

    resp = tbl.update_item(**kwargs)
    updated = resp.get("Attributes", {})

    _write_audit(
        creator_id,
        delegate_id,
        "delegate",
        "feed_post_edited",
        post_id,
        {"text_preview": (text or "")[:100]},
    )

    return _post_item_to_out(updated)


def delete_post_as_creator(
    *,
    creator_id: str,
    delegate_id: str,
    post_id: str,
) -> None:
    """Delete a creator's post on their behalf."""
    require_delegate_permission(
        creator_id=creator_id,
        delegate_id=delegate_id,
        required_permission="feed_post",
    )

    post = _get_post_or_404(post_id)
    if post.get("user_id") != creator_id:
        raise HTTPException(403, "Post does not belong to this creator")

    tbl.delete_item(Key={"pk": _pk_post(post_id), "sk": _sk_post()})

    _write_audit(
        creator_id,
        delegate_id,
        "delegate",
        "feed_post_deleted",
        post_id,
    )


def list_creator_posts(
    *,
    creator_id: str,
    delegate_id: str,
    limit: int = 50,
) -> List[Dict[str, Any]]:
    """List a creator's posts for the delegate (feed_read permission)."""
    require_delegate_permission(
        creator_id=creator_id,
        delegate_id=delegate_id,
        required_permission="feed_read",
    )

    resp = tbl.query(
        IndexName="GSI2",
        KeyConditionExpression=Key("GSI2PK").eq(f"POST_AUTHOR#{creator_id}"),
        ScanIndexForward=False,
        Limit=limit,
    )

    items = resp.get("Items", [])
    return [_post_item_to_out(item) for item in items]


# ---------------------------------------------------------------------------
# Draft approval workflow
# ---------------------------------------------------------------------------


def list_pending_drafts(
    *,
    creator_id: str,
    limit: int = 50,
) -> List[Dict[str, Any]]:
    """List posts pending creator approval (creator-only).

    Queries GSI5 with GSI5PK = DRAFT_QUEUE#{creator_id}.
    """
    resp = tbl.query(
        IndexName="GSI5",
        KeyConditionExpression=Key("GSI5PK").eq(f"DRAFT_QUEUE#{creator_id}"),
        ScanIndexForward=False,
        Limit=limit,
    )
    items = resp.get("Items", [])
    return [_post_item_to_out(item) for item in items]


def approve_draft(
    *,
    creator_id: str,
    post_id: str,
    note: str = "",
) -> Dict[str, Any]:
    """Creator approves a delegate's draft post, publishing it."""
    post = _get_post_or_404(post_id)
    if post.get("user_id") != creator_id:
        raise HTTPException(403, "Not your post")
    if post.get("approval_status") == "approved":
        raise HTTPException(409, "Draft already approved")
    if post.get("approval_status") == "rejected":
        raise HTTPException(409, "Draft already rejected")
    if post.get("approval_status") != "pending":
        raise HTTPException(400, "Post is not pending approval")

    ts = now_ts()
    created_at = post.get("created_at", _now_iso())

    # Remove GSI5 keys (draft queue), set published
    resp = tbl.update_item(
        Key={"pk": _pk_post(post_id), "sk": _sk_post()},
        UpdateExpression=(
            "SET #st = :pub, approval_status = :appr, approved_at = :ts, "
            "approved_by = :cid, approval_note = :note, published_at = :pub_at "
            "REMOVE GSI5PK, GSI5SK"
        ),
        ExpressionAttributeNames={"#st": "status"},
        ExpressionAttributeValues={
            ":pub": "published",
            ":appr": "approved",
            ":ts": ts,
            ":cid": creator_id,
            ":note": note,
            ":pub_at": _now_iso(),
        },
        ReturnValues="ALL_NEW",
    )
    updated = resp.get("Attributes", {})

    # Write feed ref + fan-out
    _write_feed_ref(creator_id=creator_id, post_id=post_id, created_at=created_at)
    _fan_out(creator_id=creator_id, post_id=post_id, created_at=created_at)

    _write_audit(
        creator_id,
        creator_id,
        "creator",
        "feed_draft_approved",
        post_id,
        {"note": note},
    )

    return _post_item_to_out(updated)


def reject_draft(
    *,
    creator_id: str,
    post_id: str,
    note: str = "",
) -> Dict[str, Any]:
    """Creator rejects a delegate's draft post."""
    post = _get_post_or_404(post_id)
    if post.get("user_id") != creator_id:
        raise HTTPException(403, "Not your post")
    if post.get("approval_status") == "approved":
        raise HTTPException(409, "Draft already approved")
    if post.get("approval_status") == "rejected":
        raise HTTPException(409, "Draft already rejected")
    if post.get("approval_status") != "pending":
        raise HTTPException(400, "Post is not pending approval")

    resp = tbl.update_item(
        Key={"pk": _pk_post(post_id), "sk": _sk_post()},
        UpdateExpression=(
            "SET approval_status = :rej, approval_note = :note "
            "REMOVE GSI5PK, GSI5SK"
        ),
        ExpressionAttributeValues={
            ":rej": "rejected",
            ":note": note,
        },
        ReturnValues="ALL_NEW",
    )
    updated = resp.get("Attributes", {})

    _write_audit(
        creator_id,
        creator_id,
        "creator",
        "feed_draft_rejected",
        post_id,
        {"note": note},
    )

    return _post_item_to_out(updated)


# ---------------------------------------------------------------------------
# Comment moderation
# ---------------------------------------------------------------------------


def moderate_comment(
    *,
    creator_id: str,
    delegate_id: str,
    post_id: str,
    comment_id: str,
    action: str,
) -> Dict[str, Any]:
    """Delegate moderates a comment on creator's post."""
    if action not in ("hide", "pin", "unpin", "delete"):
        raise HTTPException(400, f"Invalid moderation action: {action}")

    require_delegate_permission(
        creator_id=creator_id,
        delegate_id=delegate_id,
        required_permission="feed_moderate",
    )

    # Verify post belongs to creator
    post = _get_post_or_404(post_id)
    if post.get("user_id") != creator_id:
        raise HTTPException(403, "Post does not belong to this creator")

    # Find the comment
    resp = tbl.query(
        KeyConditionExpression=Key("pk").eq(_pk_post_comments(post_id)),
        ScanIndexForward=False,
        Limit=500,
    )
    target = None
    for item in resp.get("Items", []):
        if item.get("comment_id") == comment_id:
            target = item
            break

    if not target:
        raise HTTPException(404, "Comment not found")

    key = {"pk": target["pk"], "sk": target["sk"]}
    ts = now_ts()

    if action == "delete":
        tbl.update_item(
            Key=key,
            UpdateExpression=(
                "SET deleted = :t, #body = :null, body_plain = :null, "
                "body_markdown = :null, body_rich = :null, "
                "moderated_by = :mod, moderation_action = :act, moderated_at = :ts"
            ),
            ExpressionAttributeNames={"#body": "body"},
            ExpressionAttributeValues={
                ":t": True,
                ":null": None,
                ":mod": delegate_id,
                ":act": "deleted",
                ":ts": ts,
            },
        )
    elif action == "hide":
        tbl.update_item(
            Key=key,
            UpdateExpression=(
                "SET hidden = :t, moderated_by = :mod, "
                "moderation_action = :act, moderated_at = :ts"
            ),
            ExpressionAttributeValues={
                ":t": True,
                ":mod": delegate_id,
                ":act": "hidden",
                ":ts": ts,
            },
        )
    elif action == "pin":
        tbl.update_item(
            Key=key,
            UpdateExpression=(
                "SET pinned = :t, moderated_by = :mod, "
                "moderation_action = :act, moderated_at = :ts"
            ),
            ExpressionAttributeValues={
                ":t": True,
                ":mod": delegate_id,
                ":act": "pinned",
                ":ts": ts,
            },
        )
    elif action == "unpin":
        tbl.update_item(
            Key=key,
            UpdateExpression=(
                "SET pinned = :f, moderated_by = :mod, "
                "moderation_action = :act, moderated_at = :ts"
            ),
            ExpressionAttributeValues={
                ":f": False,
                ":mod": delegate_id,
                ":act": "unpinned",
                ":ts": ts,
            },
        )

    _write_audit(
        creator_id,
        delegate_id,
        "delegate",
        f"feed_comment_{action}",
        comment_id,
        {"post_id": post_id, "action": action},
    )

    return {
        "ok": True,
        "comment_id": comment_id,
        "moderation_action": action,
        "moderated_by": delegate_id,
        "moderated_at": ts,
    }


# ---------------------------------------------------------------------------
# Analytics
# ---------------------------------------------------------------------------


def get_creator_feed_analytics(
    *,
    creator_id: str,
    delegate_id: str,
    period: str = "30d",
) -> Dict[str, Any]:
    """Get feed analytics for a creator (delegate with feed_read)."""
    require_delegate_permission(
        creator_id=creator_id,
        delegate_id=delegate_id,
        required_permission="feed_read",
    )

    # Query creator's posts
    resp = tbl.query(
        IndexName="GSI2",
        KeyConditionExpression=Key("GSI2PK").eq(f"POST_AUTHOR#{creator_id}"),
        ScanIndexForward=False,
        Limit=200,
    )
    items = resp.get("Items", [])

    total_posts = len(items)
    total_likes = sum(int(i.get("like_count", 0)) for i in items)
    total_comments = sum(int(i.get("comment_count", 0)) for i in items)
    delegate_post_count = sum(1 for i in items if i.get("posted_by_delegate"))
    locked_revenue = sum(
        int(i.get("unlock_price_cents", 0) or 0) * int(i.get("unlock_count", 0) or 0)
        for i in items
        if i.get("locked")
    )

    return {
        "period": period,
        "total_posts": total_posts,
        "total_views": 0,
        "total_likes": total_likes,
        "total_comments": total_comments,
        "engagement_rate": 0.0,
        "locked_post_revenue_cents": locked_revenue,
        "delegate_post_count": delegate_post_count,
        "top_posts": [],
    }


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------


def list_delegate_feed_actions(
    *,
    creator_id: str,
    limit: int = 50,
) -> List[Dict[str, Any]]:
    """List delegate feed actions from the audit log (creator-only)."""
    resp = T.delegates.query(
        KeyConditionExpression=Key("pk").eq(f"CREATOR#{creator_id}")
        & Key("sk").begins_with("AUDIT#"),
        ScanIndexForward=False,
        Limit=limit * 2,
    )

    feed_actions = {
        "feed_post_created",
        "feed_post_edited",
        "feed_post_deleted",
        "feed_draft_approved",
        "feed_draft_rejected",
        "feed_comment_hide",
        "feed_comment_pin",
        "feed_comment_unpin",
        "feed_comment_delete",
    }

    entries = []
    for item in resp.get("Items", []):
        if item.get("action") in feed_actions:
            entries.append({
                "event_id": item.get("event_id", ""),
                "delegate_id": item.get("actor_id", ""),
                "delegate_display_name": "",
                "action": item.get("action", ""),
                "target_id": item.get("target_id", ""),
                "details": item.get("details"),
                "ts": int(item.get("ts", 0)),
            })
            if len(entries) >= limit:
                break

    return entries


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _get_post_or_404(post_id: str) -> Dict[str, Any]:
    """Fetch a post by ID or raise 404."""
    resp = tbl.get_item(Key={"pk": _pk_post(post_id), "sk": _sk_post()})
    item = resp.get("Item")
    if not item:
        raise HTTPException(404, "Post not found")
    return item


def _post_item_to_out(item: Dict[str, Any]) -> Dict[str, Any]:
    """Convert a raw DDB post item to an output dict."""
    return {
        "post_id": item.get("post_id", ""),
        "author_id": item.get("user_id", ""),
        "text": item.get("body") or item.get("body_plain") or "",
        "image_url": (item.get("image_urls") or [None])[0] if item.get("image_urls") else None,
        "lock_price_cents": int(item.get("unlock_price_cents", 0) or 0),
        "tags": item.get("tags", []),
        "status": item.get("status", "published"),
        "posted_by_delegate": item.get("posted_by_delegate"),
        "delegate_display_name": item.get("delegate_display_name"),
        "delegate_tag": item.get("delegate_tag"),
        "approval_status": item.get("approval_status"),
        "approval_note": item.get("approval_note"),
        "approved_at": int(item.get("approved_at", 0)) if item.get("approved_at") else None,
        "created_at": item.get("created_at", ""),
        "updated_at": item.get("updated_at", ""),
        "view_count": 0,
        "like_count": int(item.get("like_count", 0)),
        "comment_count": int(item.get("comment_count", 0)),
    }


def _write_feed_ref(*, creator_id: str, post_id: str, created_at: str) -> None:
    """Write author's own feed reference item."""
    feed_item = {
        "pk": _pk_post(post_id),
        "sk": f"FEEDREF#{creator_id}",
        "Entity": "FeedRef",
        "post_id": post_id,
        "owner_user_id": creator_id,
        "created_at": created_at,
        "GSI1PK": f"FEED#{creator_id}",
        "GSI1SK": f"{created_at}#POST#{post_id}",
    }
    tbl.put_item(Item=feed_item)


def _fan_out(*, creator_id: str, post_id: str, created_at: str) -> None:
    """Fan out post to followers."""
    try:
        from app.services.newsfeed_fanout import fan_out_post_to_followers
        fan_out_post_to_followers(
            author_id=creator_id,
            post_id=post_id,
            created_at=created_at,
        )
    except Exception:
        logger.exception("Fan-out failed for delegated post %s", post_id)
