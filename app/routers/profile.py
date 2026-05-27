from __future__ import annotations

import importlib.util
import hashlib
import json
import logging
import os
import re
import time
from typing import Any, Dict, List, Literal, Optional

from boto3.dynamodb.conditions import Attr, Key
from fastapi import APIRouter, Depends, HTTPException, File, Query, Request, UploadFile
from fastapi.responses import JSONResponse, Response

from app.models import ProfilePatchReq, ProfilePutReq
from app.core.aws import ddb
from app.core.cursor import decode_cursor, encode_cursor
from app.core.tables import T
from app.services.alerts import audit_event
from app.services.profile import (
    PROFILE_READ_NOT_FOUND_DETAIL,
    apply_profile_update,
    get_audit_log,
    get_profile,
    get_profile_for_requester,
    resolve_profile_audience,
    store_profile_photo,
)
from app.services.profile_discoverability import (
    get_profile_discoverability_state,
    DiscoverabilityState,
)
from app.services.rate_limit import rate_limit_profile_lookup
from app.auth.deps import get_authenticated_user
from app.services.sessions import require_ui_session
from app.core.normalize import client_ip_from_request
from app.core.settings import S
from app.metrics import record_profile_lookup, record_profile_lookup_identifier_resolution

router = APIRouter(prefix="/ui", tags=["profile"])
logger = logging.getLogger(__name__)

_MULTIPART_AVAILABLE = importlib.util.find_spec("multipart") is not None
_MAX_PROFILE_IDENTIFIER_LEN = 256
_PROFILE_IDENTIFIER_CACHE_TTL_SECONDS = 30.0
_PROFILE_IDENTIFIER_NEGATIVE_CACHE_TTL_SECONDS = 5.0
_PROFILE_IDENTIFIER_CACHE_MAX_ENTRIES = 2048
_PROFILE_IDENTIFIER_CACHE: dict[str, tuple[str | None, float]] = {}
_PROFILE_IDENTIFIER_CACHE_MISS = object()
_ALIAS_IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,64}$")

@router.get("/profile")
async def ui_get_profile(ctx=Depends(require_ui_session)):
    return {"profile": get_profile(ctx["user_sub"])}

@router.get("/profiles/{identifier}")
async def ui_get_profile_by_identifier(identifier: str, req: Request):
    started = time.perf_counter()
    correlation_id = (
        req.headers.get("x-request-id")
        or req.headers.get("x-correlation-id")
        or req.headers.get("x-amzn-trace-id")
        or ""
    ).strip()
    audience = "public"
    result = "error"
    suppression_reason = "none"
    status_code = 500

    requested_identifier = (identifier or "").strip()
    if (
        not requested_identifier
        or len(requested_identifier) > _MAX_PROFILE_IDENTIFIER_LEN
        or any(ord(ch) < 32 for ch in requested_identifier)
    ):
        status_code = 404
        result = "not_found"
        raise HTTPException(status_code=404, detail=PROFILE_READ_NOT_FOUND_DETAIL)
    try:
        target_user_sub = _resolve_profile_identifier_to_user_sub(requested_identifier)

        requester_user_sub = None
        try:
            auth_user = await get_authenticated_user(req)
            ctx = await require_ui_session(req, auth_user=auth_user)
            requester_user_sub = ctx.get("user_sub")
        except HTTPException as exc:
            if exc.status_code not in {401, 403}:
                raise

        rate_limit_profile_lookup(requester_user_sub, client_ip_from_request(req))

        audience = resolve_profile_audience(
            requester_user_sub=requester_user_sub,
            target_user_sub=target_user_sub,
        )

        if bool(getattr(S, "profile_lookup_audience_filtering_enabled", False)):
            discoverability = str(
                get_profile_discoverability_state(target_user_sub).get("discoverability_status", "active")
            ).strip().lower()
            if discoverability == "deleted":
                suppression_reason = "deleted"
            elif discoverability in {"hidden", "deactivated"} and audience != "owner":
                suppression_reason = discoverability

            filtered = get_profile_for_requester(
                target_user_sub=target_user_sub,
                requester_user_sub=requester_user_sub,
            )
        else:
            # Backward-compatible behavior: no discoverability suppression and no audience field filtering.
            filtered = get_profile(target_user_sub)
        body = {
            "identifier": requested_identifier,
            "canonical_identifier": _resolve_canonical_identifier_for_user_sub(target_user_sub),
            "user_sub": target_user_sub,
            "audience": audience,
            "profile": filtered,
        }
        etag = _profile_lookup_etag(body)
        if _request_if_none_match_contains(req.headers.get("if-none-match"), etag):
            status_code = 304
            result = "success"
            return Response(status_code=304, headers=_profile_lookup_response_headers(etag))

        status_code = 200
        result = "success"
        return JSONResponse(content=body, headers=_profile_lookup_response_headers(etag))
    except HTTPException as exc:
        status_code = int(exc.status_code or 500)
        if status_code == 429:
            result = "denied"
            suppression_reason = "rate_limited"
        elif status_code == 404:
            result = "denied" if suppression_reason != "none" else "not_found"
        else:
            result = "error"
        raise
    finally:
        elapsed = time.perf_counter() - started
        record_profile_lookup(
            audience=audience,
            result=result,
            suppression_reason=suppression_reason,
            elapsed_seconds=elapsed,
        )
        logger.info(
            "profile_lookup",
            extra={
                "event": "profile_lookup",
                "correlation_id": correlation_id or "<none>",
                "audience": audience,
                "result": result,
                "suppression_reason": suppression_reason,
                "status_code": status_code,
            },
        )


@router.get("/profile/audit")
async def ui_get_profile_audit(ctx=Depends(require_ui_session)):
    return {"audit": get_audit_log(ctx["user_sub"])}

@router.patch("/profile")
async def ui_patch_profile(req: Request, body: ProfilePatchReq, ctx=Depends(require_ui_session)):
    updates = body.model_dump(exclude_unset=True)
    profile = apply_profile_update(ctx["user_sub"], updates, replace=False)
    audit_event("profile_update", ctx["user_sub"], req, outcome="success", mode="patch")
    return {"profile": profile}

@router.put("/profile")
async def ui_put_profile(req: Request, body: ProfilePutReq, ctx=Depends(require_ui_session)):
    updates = body.model_dump()
    profile = apply_profile_update(ctx["user_sub"], updates, replace=True)
    audit_event("profile_update", ctx["user_sub"], req, outcome="success", mode="replace")
    return {"profile": profile}

async def ui_upload_profile_photo_unavailable(ctx=Depends(require_ui_session)):
    raise HTTPException(501, "python-multipart is required for uploads")


def _resolve_profile_identifier_to_user_sub(identifier: str) -> str:
    cache_key = (identifier or "").strip()
    cached = _profile_identifier_cache_get(cache_key)
    if cached is not _PROFILE_IDENTIFIER_CACHE_MISS:
        if cached:
            record_profile_lookup_identifier_resolution(source="cache", outcome="hit")
            return cached
        record_profile_lookup_identifier_resolution(source="cache", outcome="negative_hit")
        raise HTTPException(status_code=404, detail=PROFILE_READ_NOT_FOUND_DETAIL)

    direct = T.users.get_item(Key={"user_sub": identifier}).get("Item") or {}
    if direct:
        resolved = str(direct.get("user_sub") or identifier)
        _profile_identifier_cache_set(cache_key, resolved)
        record_profile_lookup_identifier_resolution(source="direct", outcome="resolved")
        return resolved

    if not _is_alias_lookup_candidate(identifier):
        _profile_identifier_cache_set(cache_key, None, ttl_seconds=_PROFILE_IDENTIFIER_NEGATIVE_CACHE_TTL_SECONDS)
        record_profile_lookup_identifier_resolution(source="alias_scan", outcome="skipped_invalid_identifier")
        raise HTTPException(status_code=404, detail=PROFILE_READ_NOT_FOUND_DETAIL)

    # Fallback alias lookup (e.g., username/handle) if present.
    scanned = T.users.scan(
        ProjectionExpression="user_sub, username, #h",
        ExpressionAttributeNames={"#h": "handle"},
        FilterExpression=Attr("username").eq(identifier) | Attr("handle").eq(identifier),
        Limit=1,
    ).get("Items", [])
    if scanned:
        user_sub = str((scanned[0] or {}).get("user_sub") or "").strip()
        if user_sub:
            _profile_identifier_cache_set(cache_key, user_sub)
            record_profile_lookup_identifier_resolution(source="alias_scan", outcome="resolved")
            return user_sub

    _profile_identifier_cache_set(cache_key, None, ttl_seconds=_PROFILE_IDENTIFIER_NEGATIVE_CACHE_TTL_SECONDS)
    record_profile_lookup_identifier_resolution(source="alias_scan", outcome="not_found")
    raise HTTPException(status_code=404, detail=PROFILE_READ_NOT_FOUND_DETAIL)


def _profile_identifier_cache_get(identifier: str) -> str | None | object:
    if not identifier:
        return _PROFILE_IDENTIFIER_CACHE_MISS
    item = _PROFILE_IDENTIFIER_CACHE.get(identifier)
    if not item:
        return _PROFILE_IDENTIFIER_CACHE_MISS
    cached_value, expires_at = item
    if time.monotonic() >= expires_at:
        _PROFILE_IDENTIFIER_CACHE.pop(identifier, None)
        return _PROFILE_IDENTIFIER_CACHE_MISS
    return cached_value


def _is_alias_lookup_candidate(identifier: str) -> bool:
    candidate = (identifier or "").strip()
    if not candidate:
        return False
    return bool(_ALIAS_IDENTIFIER_PATTERN.fullmatch(candidate))


def _profile_identifier_cache_set(identifier: str, user_sub: str | None, *, ttl_seconds: float | None = None) -> None:
    if not identifier:
        return
    if len(_PROFILE_IDENTIFIER_CACHE) >= _PROFILE_IDENTIFIER_CACHE_MAX_ENTRIES:
        try:
            _PROFILE_IDENTIFIER_CACHE.pop(next(iter(_PROFILE_IDENTIFIER_CACHE)))
        except StopIteration:
            pass
    effective_ttl = _PROFILE_IDENTIFIER_CACHE_TTL_SECONDS if ttl_seconds is None else max(0.0, float(ttl_seconds))
    _PROFILE_IDENTIFIER_CACHE[identifier] = (user_sub, time.monotonic() + effective_ttl)


def _clear_profile_identifier_cache() -> None:
    _PROFILE_IDENTIFIER_CACHE.clear()


if _MULTIPART_AVAILABLE:
    @router.post("/profile/photos/{kind}/upload")
    async def ui_upload_profile_photo(
        req: Request,
        kind: str,
        file: UploadFile = File(...),
        ctx=Depends(require_ui_session),
    ):
        content = await file.read()
        url = store_profile_photo(
            ctx["user_sub"],
            kind,
            file.filename or "upload.bin",
            content,
            content_type=file.content_type,
        )
        updates = {"profile_photo_url": url} if kind == "profile" else {"cover_photo_url": url}
        profile = apply_profile_update(ctx["user_sub"], updates, replace=False)
        audit_event("profile_photo_upload", ctx["user_sub"], req, outcome="success", kind=kind)
        return {"profile": profile, "url": url}
else:
    router.post("/profile/photos/{kind}/upload")(ui_upload_profile_photo_unavailable)


# ---------------------------------------------------------------------------
# SOC-005: Public profile endpoints
# ---------------------------------------------------------------------------

_APP_TABLE = os.environ.get("APP_TABLE", "app_single_table")
_newsfeed_tbl = ddb.Table(_APP_TABLE)


@router.get("/profile/public/{identifier}")
async def get_public_profile(identifier: str, req: Request):
    """Public profile with social metrics and follow status.

    Auth is optional -- unauthenticated callers get follow fields as False.
    """
    requested_identifier = (identifier or "").strip()
    if (
        not requested_identifier
        or len(requested_identifier) > _MAX_PROFILE_IDENTIFIER_LEN
        or any(ord(ch) < 32 for ch in requested_identifier)
    ):
        raise HTTPException(status_code=404, detail="Profile not found")

    try:
        user_sub = _resolve_profile_identifier_to_user_sub(requested_identifier)
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=404, detail="Profile not found")

    if not user_sub:
        raise HTTPException(status_code=404, detail="Profile not found")

    # Check discoverability
    disc_result = get_profile_discoverability_state(user_sub)
    disc_status = disc_result.get("discoverability_status", "active")
    if disc_status in (DiscoverabilityState.DEACTIVATED.value, DiscoverabilityState.DELETED.value):
        raise HTTPException(status_code=404, detail="Profile not found")

    # Fetch profile
    profile = get_profile(user_sub)
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")

    # Canonical identifier
    canonical = _resolve_canonical_identifier_for_user_sub(user_sub)
    canonical_identifier = canonical if canonical != requested_identifier else None

    # Follow status (optional auth)
    viewer_sub: Optional[str] = None
    is_following = False
    is_followed_by = False
    try:
        auth_user = await get_authenticated_user(req)
        ctx = await require_ui_session(req, auth_user=auth_user)
        viewer_sub = ctx.get("user_sub")
    except Exception:
        pass

    if viewer_sub and viewer_sub != user_sub:
        try:
            from app.services.social import get_follow_status
            status = get_follow_status(viewer_sub, user_sub)
            is_following = status.get("is_following", False)
            is_followed_by = status.get("is_followed_by", False)
        except Exception:
            pass

    # Check subscription plans
    has_subscription_plans = False
    try:
        plans_resp = T.subscriptions.query(
            KeyConditionExpression=Key("pk").eq(f"CREATOR#{user_sub}"),
            Select="COUNT",
            Limit=1,
        )
        has_subscription_plans = plans_resp.get("Count", 0) > 0
    except Exception:
        pass

    return {
        "user_id": user_sub,
        "identifier": requested_identifier,
        "canonical_identifier": canonical_identifier,
        "display_name": profile.get("display_name") or "User",
        "title": profile.get("title"),
        "description": profile.get("description"),
        "location": profile.get("location"),
        "profile_photo_url": profile.get("profile_photo_url"),
        "cover_photo_url": profile.get("cover_photo_url"),
        "follower_count": int(profile.get("follower_count", 0)),
        "following_count": int(profile.get("following_count", 0)),
        "post_count": int(profile.get("post_count", 0)),
        "is_following": is_following,
        "is_followed_by": is_followed_by,
        "is_mutual": is_following and is_followed_by,
        "has_subscription_plans": has_subscription_plans,
        "created_at": profile.get("created_at"),
        "discoverability": disc_status if disc_status == DiscoverabilityState.HIDDEN.value else None,
    }


@router.get("/profile/public/{identifier}/posts")
async def get_public_profile_posts(
    identifier: str,
    req: Request,
    limit: int = Query(default=12, ge=1, le=50),
    cursor: Optional[str] = Query(default=None),
    filter: Optional[Literal["all", "text", "image", "video", "locked"]] = Query(default="all"),
):
    """Paginated posts for a public profile.

    Auth is optional. Authenticated viewers see followers-only posts
    if they follow the author.
    """
    requested_identifier = (identifier or "").strip()
    if not requested_identifier or len(requested_identifier) > _MAX_PROFILE_IDENTIFIER_LEN:
        raise HTTPException(status_code=404, detail="Profile not found")

    try:
        user_sub = _resolve_profile_identifier_to_user_sub(requested_identifier)
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=404, detail="Profile not found")

    if not user_sub:
        raise HTTPException(status_code=404, detail="Profile not found")

    # Discoverability check
    disc_result = get_profile_discoverability_state(user_sub)
    disc_status = disc_result.get("discoverability_status", "active")
    if disc_status in (DiscoverabilityState.DEACTIVATED.value, DiscoverabilityState.DELETED.value):
        raise HTTPException(status_code=404, detail="Profile not found")

    # Determine viewer follow status
    viewer_sub: Optional[str] = None
    viewer_follows_author = False
    try:
        auth_user = await get_authenticated_user(req)
        ctx = await require_ui_session(req, auth_user=auth_user)
        viewer_sub = ctx.get("user_sub")
        if viewer_sub and viewer_sub == user_sub:
            viewer_follows_author = True  # Author sees own posts
        elif viewer_sub:
            from app.services.social import is_following as _is_following
            viewer_follows_author = _is_following(viewer_sub, user_sub)
    except Exception:
        pass

    # Query posts via GSI2
    lek = decode_cursor(cursor) if cursor else None
    kwargs: Dict[str, Any] = {
        "IndexName": "GSI2",
        "KeyConditionExpression": Key("GSI2PK").eq(f"POST_AUTHOR#{user_sub}"),
        "ScanIndexForward": False,
        "Limit": limit * 2,  # Over-fetch to account for filtered posts
    }
    if lek:
        kwargs["ExclusiveStartKey"] = lek

    resp = _newsfeed_tbl.query(**kwargs)
    raw_items = resp.get("Items", [])
    next_lek = resp.get("LastEvaluatedKey")

    # Filter and transform posts
    items: List[Dict[str, Any]] = []
    for item in raw_items:
        if len(items) >= limit:
            break

        # Skip non-published posts
        if str(item.get("status", "published")).strip().lower() != "published":
            continue

        visibility = item.get("visibility", "public")
        is_locked = item.get("locked", False)

        # Visibility check
        if visibility == "followers" and not viewer_follows_author:
            continue

        # Apply type filter
        has_image = bool(item.get("image_urls"))
        has_video = bool(item.get("video_id"))
        if filter == "image" and not has_image:
            continue
        if filter == "video" and not has_video:
            continue
        if filter == "text" and (has_image or has_video):
            continue
        if filter == "locked" and not is_locked:
            continue

        # Build post summary
        body = item.get("body") or ""
        post_summary: Dict[str, Any] = {
            "post_id": item.get("post_id") or str(item.get("sk", "")).replace("POST#", ""),
            "created_at": str(item.get("created_at", "")),
            "body_preview": body[:200] if not is_locked else None,
            "image_urls": (item.get("image_urls") or [])[:1] if not is_locked else [],
            "video_id": item.get("video_id") if not is_locked else None,
            "has_video": has_video,
            "locked": is_locked,
            "unlock_price_cents": int(item.get("unlock_price_cents") or item.get("lock_price_cents") or 0) if is_locked else None,
            "like_count": int(item.get("like_count", 0)),
            "comment_count": int(item.get("comment_count", 0)),
            "tip_total_cents": int(item.get("tip_total_cents", 0)),
        }
        items.append(post_summary)

    # Get total from profile
    profile = get_profile(user_sub)
    total_count = int(profile.get("post_count", 0)) if profile else 0

    return {
        "items": items,
        "next_cursor": encode_cursor(next_lek) if next_lek and len(items) == limit else None,
        "total_count": total_count,
    }


@router.get("/profile/meta/{identifier}")
async def profile_meta_tags(identifier: str):
    """Lightweight meta tag data for SEO. No auth required."""
    try:
        user_sub = _resolve_profile_identifier_to_user_sub(identifier)
    except Exception:
        return {"title": "Profile", "description": "", "image": ""}

    if not user_sub:
        return {"title": "Profile", "description": "", "image": ""}

    disc_result = get_profile_discoverability_state(user_sub)
    disc_status = disc_result.get("discoverability_status", "active")
    if disc_status in (DiscoverabilityState.DEACTIVATED.value, DiscoverabilityState.DELETED.value):
        return {"title": "Profile", "description": "", "image": ""}

    profile = get_profile(user_sub)
    if not profile:
        return {"title": "Profile", "description": "", "image": ""}

    display_name = profile.get("display_name") or "User"
    description = (profile.get("description") or profile.get("title") or "")[:160]
    photo_url = profile.get("profile_photo_url") or ""
    follower_count = int(profile.get("follower_count", 0))

    return {
        "title": f"{display_name} - Profile",
        "description": f"{description} | {follower_count:,} followers",
        "image": photo_url,
        "url": f"/u/{identifier}",
    }


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _profile_lookup_etag(body: dict) -> str:
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return f'W/"{digest}"'


def _request_if_none_match_contains(if_none_match: str | None, expected_etag: str) -> bool:
    if not if_none_match:
        return False
    values = [item.strip() for item in if_none_match.split(",") if item.strip()]
    if "*" in values:
        return True
    normalized_expected = expected_etag.replace("W/", "", 1)
    for value in values:
        if value == expected_etag:
            return True
        if value.replace("W/", "", 1) == normalized_expected:
            return True
    return False


def _profile_lookup_response_headers(etag: str) -> dict[str, str]:
    return {
        "ETag": etag,
        "Cache-Control": "private, no-store",
        "Pragma": "no-cache",
        "Vary": "Authorization, Cookie",
    }


def _resolve_canonical_identifier_for_user_sub(user_sub: str) -> str:
    candidate_user_sub = (user_sub or "").strip()
    if not candidate_user_sub:
        return ""
    try:
        item = T.users.get_item(Key={"user_sub": candidate_user_sub}).get("Item") or {}
    except Exception:
        return candidate_user_sub
    for key in ("username", "handle", "user_sub"):
        candidate = str(item.get(key) or "").strip()
        if candidate and _is_alias_lookup_candidate(candidate):
            return candidate
    return candidate_user_sub
