"""Syndicate page & newsfeed service (SYND-005).

A syndicate gets its own scoped newsfeed.  Posts are stored in a dedicated
``syndicate_posts`` DDB table with a GSI (``GSSYND``) keyed by the syndicate id
and sorted by ``created_at`` (numeric) for chronological, newest-first feed
queries.  This mirrors the group-feed pattern (``app/services/group_feed.py``)
but uses a dedicated table rather than the shared single table.

Visibility:
  - ``public``        -- visible to anyone (members + non-members).
  - ``members_only``  -- visible only to active syndicate members.

Membership / admin authorization is delegated to ``app/services/syndicates.py``
(SYND-001): ``_require_is_member`` and ``_require_admin``.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional
from uuid import uuid4

from boto3.dynamodb.conditions import Key

from app.core.cursor import decode_cursor, encode_cursor
from app.core.tables import T
from app.core.time import now_ts
from app.services import syndicates as syndicate_svc

logger = logging.getLogger(__name__)

VALID_VISIBILITIES = ("public", "members_only")

MAX_TEXT_LEN = 5000
MAX_TAGS = 10
MAX_TAG_LEN = 30
MAX_DESCRIPTION_LEN = 500
DEFAULT_LIMIT = 20
MAX_LIMIT = 50


# ---------------------------------------------------------------------------
# Membership helpers (delegate to syndicates service)
# ---------------------------------------------------------------------------

def _is_member(syndicate_id: str, user_id: Optional[str]) -> bool:
    if not user_id:
        return False
    resp = T.syndicates.get_item(
        Key={"pk": f"SYND#{syndicate_id}", "sk": f"MEMBER#{user_id}"}
    )
    return bool(resp.get("Item"))


def _is_admin(syndicate_id: str, user_id: Optional[str]) -> bool:
    if not user_id:
        return False
    meta = syndicate_svc.get_syndicate(syndicate_id)
    return bool(meta) and meta.get("admin_user_id") == user_id


# ---------------------------------------------------------------------------
# Post serialization
# ---------------------------------------------------------------------------

def _post_out(item: Dict[str, Any]) -> Dict[str, Any]:
    """Map a DDB syndicate post item to the SyndicatePostOut shape."""
    reaction_counts = item.get("reaction_counts") or {}
    return {
        "post_id": item.get("post_id", ""),
        "author_id": item.get("author_id", ""),
        "author_name": item.get("author_name", ""),
        "author_avatar": item.get("author_avatar", ""),
        "text": item.get("text", ""),
        "image_url": item.get("image_url", ""),
        "syndicate_id": item.get("syndicate_id", ""),
        "visibility": item.get("visibility", "public"),
        "created_at": int(item.get("created_at", 0) or 0),
        "comment_count": int(item.get("comment_count", 0) or 0),
        "reaction_counts": {k: int(v) for k, v in reaction_counts.items()},
        "tip_total_cents": int(item.get("tip_total_cents", 0) or 0),
    }


# ---------------------------------------------------------------------------
# Create
# ---------------------------------------------------------------------------

def create_syndicate_post(
    *,
    syndicate_id: str,
    author_sub: str,
    text: str,
    visibility: str = "public",
    image_url: Optional[str] = None,
    author_name: str = "",
) -> Dict[str, Any]:
    """Create a post in the syndicate newsfeed (members only)."""
    # Ensure syndicate exists (raises 404 via HTTPException if missing).
    meta = syndicate_svc.get_syndicate(syndicate_id)
    if not meta:
        raise ValueError("Syndicate not found")

    # Members only.
    if not _is_member(syndicate_id, author_sub):
        raise PermissionError("Only syndicate members can post")

    if visibility not in VALID_VISIBILITIES:
        raise ValueError("visibility must be 'public' or 'members_only'")

    text = (text or "").strip()
    if not text:
        raise ValueError("Post text must be at least 1 character")
    if len(text) > MAX_TEXT_LEN:
        raise ValueError("Post text must be under 5000 characters")

    post_id = f"sp_{uuid4().hex}"
    ts = now_ts()

    item: Dict[str, Any] = {
        "pk": f"SYND#{syndicate_id}",
        "sk": f"POST#{post_id}",
        "post_id": post_id,
        "author_id": author_sub,
        "author_name": author_name or author_sub,
        "author_avatar": "",
        "text": text,
        "image_url": image_url or "",
        "syndicate_id": syndicate_id,
        "visibility": visibility,
        "created_at": ts,
        "updated_at": ts,
        "comment_count": 0,
        "reaction_counts": {},
        "tip_total_cents": 0,
        # GSI for syndicate-scoped feed queries (newest-first by created_at).
        "GSSYND_PK": f"SYNDFEED#{syndicate_id}",
        "GSSYND_SK": ts,
    }
    T.syndicate_posts.put_item(Item=item)

    # Increment denormalized post counter on the syndicate META item.
    try:
        T.syndicates.update_item(
            Key={"pk": f"SYND#{syndicate_id}", "sk": "META"},
            UpdateExpression="SET post_count = if_not_exists(post_count, :z) + :one",
            ExpressionAttributeValues={":z": 0, ":one": 1},
        )
    except Exception:  # pragma: no cover - counter is best-effort
        logger.warning("syndicate_feed.post_count_increment_failed", extra={"syndicate_id": syndicate_id})

    logger.info(
        "syndicate_post.created",
        extra={"syndicate_id": syndicate_id, "post_id": post_id, "author_id": author_sub, "visibility": visibility},
    )
    return _post_out(item)


# ---------------------------------------------------------------------------
# List feed
# ---------------------------------------------------------------------------

def list_syndicate_posts(
    syndicate_id: str,
    *,
    viewer_sub: Optional[str] = None,
    limit: int = DEFAULT_LIMIT,
    cursor: Optional[str] = None,
) -> Dict[str, Any]:
    """List posts in a syndicate's newsfeed, respecting visibility.

    Members see all posts; non-members see only ``public`` posts.
    """
    meta = syndicate_svc.get_syndicate(syndicate_id)
    if not meta:
        raise ValueError("Syndicate not found")

    limit = max(1, min(int(limit or DEFAULT_LIMIT), MAX_LIMIT))
    is_member = _is_member(syndicate_id, viewer_sub)

    query_kwargs: Dict[str, Any] = {
        "IndexName": "GSSYND",
        "KeyConditionExpression": Key("GSSYND_PK").eq(f"SYNDFEED#{syndicate_id}"),
        "ScanIndexForward": False,  # newest first
        # Over-fetch to account for post-query visibility filtering.
        "Limit": limit * 2 if not is_member else limit,
    }
    if cursor:
        query_kwargs["ExclusiveStartKey"] = decode_cursor(cursor)

    resp = T.syndicate_posts.query(**query_kwargs)
    items = resp.get("Items", [])

    filtered_count = 0
    if not is_member:
        before = len(items)
        items = [p for p in items if p.get("visibility") != "members_only"]
        filtered_count = before - len(items)

    # MOD-SYND: owner-aware moderation hide — reported/hidden syndicate posts
    # vanish for everyone except their author (admins use the board). Applied
    # BEFORE the limit trim so a hidden row does not consume a page slot.
    def _mod_hidden_syndicate(p: Dict[str, Any]) -> bool:
        if not (p.get("moderation_hidden") or p.get("moderation_removed") or p.get("moderation_removed_at")):
            return False
        return not (viewer_sub and str(p.get("author_id")) == str(viewer_sub))

    items = [p for p in items if not _mod_hidden_syndicate(p)]

    # Trim to requested limit.
    visible = items[:limit]
    posts = [_post_out(p) for p in visible]

    next_cursor = None
    last_key = resp.get("LastEvaluatedKey")
    if last_key:
        next_cursor = encode_cursor(last_key)

    if filtered_count:
        logger.debug(
            "syndicate_feed.visibility_filtered",
            extra={"syndicate_id": syndicate_id, "viewer_id": viewer_sub, "filtered_count": filtered_count},
        )

    if viewer_sub:
        try:
            from app.services.sponsored_feed import inject_sponsored_syndicate
            posts = inject_sponsored_syndicate(
                posts, viewer_sub, syndicate_id=syndicate_id
            )
        except Exception:
            pass
    return {
        "posts": posts,
        "next_cursor": next_cursor,
        "is_member": is_member,
    }


# ---------------------------------------------------------------------------
# Delete
# ---------------------------------------------------------------------------

def _get_post(syndicate_id: str, post_id: str) -> Optional[Dict[str, Any]]:
    resp = T.syndicate_posts.get_item(
        Key={"pk": f"SYND#{syndicate_id}", "sk": f"POST#{post_id}"}
    )
    return resp.get("Item")


def delete_syndicate_post(
    *,
    syndicate_id: str,
    post_id: str,
    user_sub: str,
) -> Dict[str, Any]:
    """Delete a syndicate post. Author or syndicate admin can delete."""
    post = _get_post(syndicate_id, post_id)
    if not post:
        raise LookupError("Post not found")

    if post.get("syndicate_id") != syndicate_id:
        raise ValueError("Post does not belong to this syndicate")

    is_author = post.get("author_id") == user_sub
    is_admin = _is_admin(syndicate_id, user_sub)

    if not is_author and not is_admin:
        raise PermissionError("Only the author or syndicate admin can delete this post")

    T.syndicate_posts.delete_item(
        Key={"pk": f"SYND#{syndicate_id}", "sk": f"POST#{post_id}"}
    )

    try:
        T.syndicates.update_item(
            Key={"pk": f"SYND#{syndicate_id}", "sk": "META"},
            UpdateExpression="SET post_count = if_not_exists(post_count, :z) - :one",
            ExpressionAttributeValues={":z": 0, ":one": 1},
        )
    except Exception:  # pragma: no cover - counter is best-effort
        logger.warning("syndicate_feed.post_count_decrement_failed", extra={"syndicate_id": syndicate_id})

    logger.info(
        "syndicate_post.deleted",
        extra={"syndicate_id": syndicate_id, "post_id": post_id, "deleted_by": user_sub, "was_author": is_author},
    )
    return {"ok": True, "post_id": post_id}


# ---------------------------------------------------------------------------
# Profile (page metadata)
# ---------------------------------------------------------------------------

def get_syndicate_profile(
    syndicate_id: str,
    *,
    viewer_sub: Optional[str] = None,
) -> Dict[str, Any]:
    """Build the public syndicate profile (metadata + members + bundle plans)."""
    meta = syndicate_svc.get_syndicate(syndicate_id)
    if not meta:
        raise ValueError("Syndicate not found")

    members_raw = syndicate_svc.list_members(syndicate_id)
    members = [
        {
            "user_id": m.get("user_id", ""),
            "display_name": m.get("display_name", m.get("user_id", "")),
            "role": m.get("role", "member"),
            "joined_at": int(m.get("joined_at", 0) or 0),
        }
        for m in members_raw
    ]

    bundle_plans: List[Dict[str, Any]] = []
    try:
        from app.services import syndicate_subscriptions as bundle_svc

        for p in bundle_svc.list_bundle_plans(syndicate_id):
            bundle_plans.append(
                {
                    "plan_id": p.get("plan_id", ""),
                    "plan_type": p.get("plan_type", "syndicate_bundle"),
                    "syndicate_id": syndicate_id,
                    "name": p.get("name", ""),
                    "description": p.get("description", ""),
                    "price_cents": int(p.get("price_cents", 0) or 0),
                    "interval": p.get("interval", "month"),
                    "status": p.get("status", "active"),
                    "included_creator_ids": p.get("included_creator_ids", []) or [],
                    "current_members": [],
                    "created_at": int(p.get("created_at", 0) or 0),
                }
            )
    except Exception:  # pragma: no cover - bundle plans are optional
        logger.debug("syndicate_feed.bundle_plans_unavailable", extra={"syndicate_id": syndicate_id})

    return {
        "syndicate_id": syndicate_id,
        "name": meta.get("name", ""),
        "description": meta.get("description", ""),
        "avatar_url": meta.get("avatar_url", ""),
        "banner_url": meta.get("banner_url", ""),
        "website_url": meta.get("website_url", ""),
        "tags": meta.get("tags", []) or [],
        "admin_user_id": meta.get("admin_user_id", ""),
        "status": meta.get("status", "active"),
        "member_count": int(meta.get("member_count", 0) or 0),
        "post_count": int(meta.get("post_count", 0) or 0),
        "members": members,
        "bundle_plans": bundle_plans,
        "is_member": _is_member(syndicate_id, viewer_sub),
        "created_at": int(meta.get("created_at", 0) or 0),
    }


def update_syndicate_profile(
    *,
    syndicate_id: str,
    admin_sub: str,
    avatar_url: Optional[str] = None,
    banner_url: Optional[str] = None,
    website_url: Optional[str] = None,
    tags: Optional[List[str]] = None,
    description: Optional[str] = None,
) -> Dict[str, Any]:
    """Update syndicate profile fields (admin only)."""
    meta = syndicate_svc.get_syndicate(syndicate_id)
    if not meta:
        raise ValueError("Syndicate not found")

    # Admin only.
    syndicate_svc._require_admin(syndicate_id, admin_sub)

    updates: Dict[str, Any] = {}
    if avatar_url is not None:
        updates["avatar_url"] = avatar_url
    if banner_url is not None:
        updates["banner_url"] = banner_url
    if website_url is not None:
        updates["website_url"] = website_url
    if tags is not None:
        clean_tags = [t.strip()[:MAX_TAG_LEN] for t in tags if t and t.strip()][:MAX_TAGS]
        updates["tags"] = clean_tags
    if description is not None:
        updates["description"] = description[:MAX_DESCRIPTION_LEN]

    if updates:
        ts = now_ts()
        expr_parts = []
        expr_names: Dict[str, str] = {}
        expr_values: Dict[str, Any] = {}
        for i, (k, v) in enumerate(updates.items()):
            alias = f"#k{i}"
            val_alias = f":v{i}"
            expr_parts.append(f"{alias} = {val_alias}")
            expr_names[alias] = k
            expr_values[val_alias] = v
        expr_parts.append("updated_at = :ts")
        expr_values[":ts"] = ts

        T.syndicates.update_item(
            Key={"pk": f"SYND#{syndicate_id}", "sk": "META"},
            UpdateExpression="SET " + ", ".join(expr_parts),
            ExpressionAttributeNames=expr_names,
            ExpressionAttributeValues=expr_values,
        )
        logger.info(
            "syndicate_profile.updated",
            extra={"syndicate_id": syndicate_id, "admin_id": admin_sub, "changed_fields": list(updates.keys())},
        )

    return get_syndicate_profile(syndicate_id, viewer_sub=admin_sub)
