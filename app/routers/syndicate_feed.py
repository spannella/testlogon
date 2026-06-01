"""Syndicate page & newsfeed router (SYND-005).

Endpoints live under the distinct prefix ``/ui/syndicates/feed`` so they do not
collide with the SYND-001 management router (``/ui/syndicates``).  The syndicate
id is the first path segment after the prefix.

| Method | Path                                          | Auth | Description |
|--------|-----------------------------------------------|------|-------------|
| GET    | /ui/syndicates/feed/{syndicate_id}/profile    | session | Public profile (metadata + members + plans) |
| PUT    | /ui/syndicates/feed/{syndicate_id}/profile    | session | Update profile (admin only) |
| GET    | /ui/syndicates/feed/{syndicate_id}            | session | List syndicate newsfeed (visibility filtered) |
| POST   | /ui/syndicates/feed/{syndicate_id}            | session | Create post (members only) |
| DELETE | /ui/syndicates/feed/{syndicate_id}/{post_id}  | session | Delete post (author or admin) |
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query

from app.models import (
    SyndicateFeedOut,
    SyndicatePostCreateIn,
    SyndicatePostOut,
    SyndicateProfileOut,
    SyndicateProfileUpdateIn,
)
from app.services import syndicate_feed as svc
from app.services.sessions import require_ui_session

syndicate_feed_router = APIRouter(prefix="/ui/syndicates/feed", tags=["syndicate-feed"])


# ---------------------------------------------------------------------------
# Profile
# ---------------------------------------------------------------------------

@syndicate_feed_router.get("/{syndicate_id}/profile", response_model=SyndicateProfileOut)
def get_profile(syndicate_id: str, session=Depends(require_ui_session)):
    try:
        return svc.get_syndicate_profile(syndicate_id, viewer_sub=session["user_sub"])
    except ValueError as e:
        raise HTTPException(404, str(e))


@syndicate_feed_router.put("/{syndicate_id}/profile", response_model=SyndicateProfileOut)
def update_profile(
    syndicate_id: str,
    body: SyndicateProfileUpdateIn,
    session=Depends(require_ui_session),
):
    try:
        return svc.update_syndicate_profile(
            syndicate_id=syndicate_id,
            admin_sub=session["user_sub"],
            avatar_url=body.avatar_url,
            banner_url=body.banner_url,
            website_url=body.website_url,
            tags=body.tags,
            description=body.description,
        )
    except HTTPException:
        raise
    except ValueError as e:
        raise HTTPException(404, str(e))


# ---------------------------------------------------------------------------
# Feed
# ---------------------------------------------------------------------------

@syndicate_feed_router.get("/{syndicate_id}", response_model=SyndicateFeedOut)
def get_feed(
    syndicate_id: str,
    cursor: str | None = Query(default=None),
    limit: int = Query(default=20, ge=1, le=50),
    session=Depends(require_ui_session),
):
    try:
        return svc.list_syndicate_posts(
            syndicate_id,
            viewer_sub=session["user_sub"],
            limit=limit,
            cursor=cursor,
        )
    except ValueError as e:
        raise HTTPException(404, str(e))


@syndicate_feed_router.post("/{syndicate_id}", response_model=SyndicatePostOut, status_code=201)
def create_post(
    syndicate_id: str,
    body: SyndicatePostCreateIn,
    session=Depends(require_ui_session),
):
    try:
        return svc.create_syndicate_post(
            syndicate_id=syndicate_id,
            author_sub=session["user_sub"],
            text=body.text,
            visibility=body.visibility,
            image_url=body.image_url,
            author_name=session.get("display_name") or "",
        )
    except PermissionError as e:
        raise HTTPException(403, str(e))
    except ValueError as e:
        msg = str(e)
        if "not found" in msg.lower():
            raise HTTPException(404, msg)
        raise HTTPException(422, msg)


@syndicate_feed_router.delete("/{syndicate_id}/{post_id}")
def delete_post(syndicate_id: str, post_id: str, session=Depends(require_ui_session)):
    try:
        return svc.delete_syndicate_post(
            syndicate_id=syndicate_id,
            post_id=post_id,
            user_sub=session["user_sub"],
        )
    except PermissionError as e:
        raise HTTPException(403, str(e))
    except LookupError as e:
        raise HTTPException(404, str(e))
    except ValueError as e:
        raise HTTPException(400, str(e))
