from __future__ import annotations

import importlib.util
import hashlib
import json
import logging
import re
import time

from boto3.dynamodb.conditions import Attr
from fastapi import APIRouter, Depends, HTTPException, File, Request, UploadFile
from fastapi.responses import JSONResponse, Response

from app.models import ProfilePatchReq, ProfilePutReq
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
from app.services.profile_discoverability import get_profile_discoverability_state
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
