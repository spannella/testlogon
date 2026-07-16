"""Group Feed router (GROUP-002).

Authenticated endpoints under ``/ui/groups`` and public feed under ``/public/groups``.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from app.services.api_key_policy_enforcement import maybe_enforce_api_key_route_policy

from app.services.sessions import require_ui_session
from app.models import CreateGroupPostIn
from app.core.settings import S

router = APIRouter(tags=["group-feed"], dependencies=[Depends(maybe_enforce_api_key_route_policy)])
public_group_feed_router = APIRouter(tags=["group-feed-public"])


def _require_feed_enabled():
    if not S.group_feed_enabled:
        raise HTTPException(404, "Group feed is not enabled")


# ── Create group post ─────────────────────────────────────────────────────────

@router.post("/ui/groups/{group_id}/posts", status_code=201)
def create_post(group_id: str, body: CreateGroupPostIn, session=Depends(require_ui_session)):
    _require_feed_enabled()
    from app.services.group_feed import create_group_post
    try:
        return create_group_post(
            group_id=group_id,
            user_id=session["user_sub"],
            text=body.text,
            body_format=body.body_format,
            image_url=body.image_url,
            audience=body.audience,
            unlock_price_cents=body.unlock_price_cents,
        )
    except PermissionError as e:
        raise HTTPException(403, str(e))
    except ValueError as e:
        msg = str(e)
        if "dissolved" in msg:
            raise HTTPException(410, msg)
        raise HTTPException(404, msg)


# ── Group feed (authenticated) ────────────────────────────────────────────────

@router.get("/ui/groups/{group_id}/feed")
def get_feed(
    group_id: str,
    cursor: str | None = Query(default=None),
    limit: int = Query(default=20, ge=1, le=100),
    session=Depends(require_ui_session),
):
    _require_feed_enabled()
    from app.services.group_feed import list_group_feed
    try:
        return list_group_feed(
            group_id=group_id,
            viewer_id=session["user_sub"],
            cursor=cursor,
            limit=limit,
        )
    except ValueError as e:
        msg = str(e)
        if "dissolved" in msg:
            raise HTTPException(410, msg)
        raise HTTPException(404, msg)


# ── Pin / unpin ───────────────────────────────────────────────────────────────

@router.post("/ui/groups/{group_id}/posts/{post_id}/pin")
def pin_post(group_id: str, post_id: str, session=Depends(require_ui_session)):
    _require_feed_enabled()
    from app.services.group_feed import pin_post as _pin
    try:
        return _pin(group_id=group_id, post_id=post_id, user_id=session["user_sub"])
    except PermissionError as e:
        raise HTTPException(403, str(e))
    except ValueError as e:
        msg = str(e)
        if "already pinned" in msg.lower():
            raise HTTPException(409, msg)
        if "Maximum" in msg:
            raise HTTPException(409, msg)
        raise HTTPException(404, msg)


@router.delete("/ui/groups/{group_id}/posts/{post_id}/pin")
def unpin_post(group_id: str, post_id: str, session=Depends(require_ui_session)):
    _require_feed_enabled()
    from app.services.group_feed import unpin_post as _unpin
    try:
        return _unpin(group_id=group_id, post_id=post_id, user_id=session["user_sub"])
    except PermissionError as e:
        raise HTTPException(403, str(e))
    except ValueError as e:
        raise HTTPException(404, str(e))


# ── Delete group post ─────────────────────────────────────────────────────────

@router.delete("/ui/groups/{group_id}/posts/{post_id}")
def delete_post(group_id: str, post_id: str, session=Depends(require_ui_session)):
    _require_feed_enabled()
    from app.services.group_feed import delete_group_post
    try:
        return delete_group_post(group_id=group_id, post_id=post_id, user_id=session["user_sub"])
    except PermissionError as e:
        raise HTTPException(403, str(e))
    except ValueError as e:
        raise HTTPException(404, str(e))


# ── Public feed (no auth) ────────────────────────────────────────────────────

@public_group_feed_router.get("/public/groups/{group_id}/feed")
def public_feed(
    group_id: str,
    cursor: str | None = Query(default=None),
    limit: int = Query(default=20, ge=1, le=100),
):
    _require_feed_enabled()
    from app.services.group_feed import list_group_feed
    try:
        return list_group_feed(
            group_id=group_id,
            viewer_id=None,
            cursor=cursor,
            limit=limit,
        )
    except ValueError as e:
        msg = str(e)
        if "dissolved" in msg:
            raise HTTPException(410, msg)
        raise HTTPException(404, msg)
