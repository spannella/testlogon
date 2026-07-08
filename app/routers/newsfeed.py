from __future__ import annotations

import asyncio
import threading
from collections import deque
import hashlib
import json
import logging
import re
from html import escape
import os
import time
import uuid
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
from typing import Annotated, Any, Dict, List, Literal, Optional, Set, Tuple

from urllib.parse import parse_qs, quote, urlparse

from botocore.exceptions import ClientError
from boto3.dynamodb.types import TypeSerializer
from fastapi import APIRouter, Depends, File, Header, HTTPException, Query, Request, UploadFile
from pydantic import BaseModel, Field, ValidationError, model_validator
from starlette.responses import StreamingResponse

from app.core.aws import ddb
from app.core.aws_clients import s3_client, sqs_client
from app.core.cursor import decode_cursor, encode_cursor
from app.metrics import (
    record_newsfeed_feed_budget_hit,
    record_newsfeed_feed_error,
    record_newsfeed_feed_filter_usage,
    record_newsfeed_feed_latency,
    record_newsfeed_feed_page_depth,
    record_newsfeed_feed_request,
)
from app.core.settings import S
from app.metrics import record_newsfeed_schedule_operation
from app.services.filemanager import download_file, get_node, get_usage_summary, norm_path
from app.services.newsfeed_feed_query import FeedFilterParams, parse_filter_window, post_matches_filters, sort_posts_deterministically
from app.services.rate_limit import rate_limit_feed_query
from app.services.api_key_policy_enforcement import maybe_enforce_api_key_route_policy
from app.services.sessions import require_ui_session
from app.auth.deps import require_kyc_tier
from app.services import post_interesting as _post_interesting_svc
from app.services.analytics_events import (
    record_engagement_event,
    record_revenue_event,
)
from app.services.subscription_access import can_access_creator
from app.services.social_alerts import (
    BATCH_KEY_PATTERNS,
    emit_mention_alerts,
    emit_social_alert,
)
from app.services.usage_metering import (
    build_usage_event,
    build_usage_source_idempotency_key,
    record_usage_event_and_aggregates,
)

# -----------------------------
# Config
# -----------------------------
APP_TABLE = os.environ.get("APP_TABLE", "app_single_table")
AWS_REGION = S.aws_region or os.environ.get("AWS_REGION", "us-east-1")
UPLOAD_BUCKET = os.environ.get("UPLOAD_BUCKET")
EVENTS_SQS_URL = os.environ.get("EVENTS_SQS_URL")

tbl = ddb.Table(APP_TABLE)
_ddb_type_serializer = TypeSerializer()

from app.core.tables import T  # noqa: E402  (FEED-003: calendar table for FADT post polls)

s3 = s3_client() if UPLOAD_BUCKET else None
sqs = sqs_client() if EVENTS_SQS_URL else None

router = APIRouter(tags=["newsfeed"], dependencies=[Depends(maybe_enforce_api_key_route_policy)])
logger = logging.getLogger(__name__)
_SCHEDULED_LOCAL_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$")
_ddb_serializer = TypeSerializer()
_UNLOCK_ATTEMPT_THROTTLE: Dict[str, deque] = {}
_UNLOCK_ATTEMPT_THROTTLE_LOCK = threading.Lock()


def _inject_sponsored_posts(
    posts: List[Dict[str, Any]],
    viewer_id: str,
    interval: Optional[int] = None,
    max_sponsored: Optional[int] = None,
) -> List[Dict[str, Any]]:
    """Inject sponsored posts into the feed at regular intervals (ADS-005)."""
    if not posts:
        return posts
    if not getattr(S, "sponsored_posts_enabled", False):
        return posts

    _interval = interval or int(getattr(S, "sponsored_post_interval", 5))
    _max = max_sponsored or int(getattr(S, "sponsored_post_max_per_page", 3))

    # Load hidden ad IDs once for this request
    from app.services.ad_feedback import get_hidden_ad_ids
    hidden_ids = get_hidden_ad_ids(viewer_id)

    result: List[Dict[str, Any]] = []
    sponsored_count = 0

    for i, post in enumerate(posts):
        result.append(post)
        # Inject after every `_interval` organic posts
        if (i + 1) % _interval == 0 and sponsored_count < _max:
            # Check if the post allows ads near it
            if not post.get("allow_ads_near", True):
                logger.debug(
                    "sponsored_injection_skipped",
                    extra={"viewer_id": viewer_id, "reason": "allow_ads_near_false"},
                )
                continue
            sponsored = _fetch_sponsored_post(viewer_id, i, hidden_ids)
            if sponsored:
                result.append(sponsored)
                sponsored_count += 1

    return result


def _fetch_sponsored_post(
    viewer_id: str,
    position: int,
    hidden_ids: Set[str],
) -> Optional[Dict[str, Any]]:
    """Fetch a sponsored post from the ad serving engine."""
    try:
        from app.services.ad_serving import serve_ad
        ad = serve_ad(
            surface="newsfeed",
            content_type="post",
            creator_id="platform",
            content_id=f"feed_slot_{position}",
            slot_type="sponsored_post",
            user_id=viewer_id,
        )
        if not ad.get("filled") or ad.get("is_house_ad"):
            return None

        creative_id = ad.get("creative_id", "")
        if creative_id in hidden_ids:
            logger.debug(
                "sponsored_injection_skipped",
                extra={"viewer_id": viewer_id, "reason": "hidden", "creative_id": creative_id},
            )
            return None

        ts = int(time.time())
        sponsored = {
            "post_id": f"sponsored_{creative_id}_{position}",
            "is_sponsored": True,
            "sponsor_account_id": ad.get("campaign_id", ""),
            "sponsor_label": ad.get("title", "Sponsored"),
            "headline": ad.get("headline"),
            "body": ad.get("body_text", ""),
            "cta_text": ad.get("cta_text"),
            "cta_url": ad.get("cta_url"),
            "ctas": ad.get("ctas") or [],
            "image_urls": [ad["image_url"]] if ad.get("image_url") else [],
            "impression_url": ad.get("impression_url"),
            "click_url": ad.get("click_url"),
            "creative_id": creative_id,
            "campaign_id": ad.get("campaign_id"),
            "account_id": ad.get("account_id", ""),
            "ad_click_id": ad.get("ad_click_id", ""),
            "content_owner_id": ad.get("content_owner_id", ""),
            "reactions_counts": {},
            "comment_count": 0,
            "comments_enabled": False,
            "created_at": ts,
            "author_id": "",
            "like_count": 0,
            "tip_total_cents": 0,
            "liked_by_me": False,
            "my_reactions": [],
            "tags": [],
            "allow_ads_near": False,
        }
        logger.info(
            "sponsored_injected",
            extra={
                "viewer_id": viewer_id,
                "creative_id": creative_id,
                "position": position,
                "campaign_id": ad.get("campaign_id"),
            },
        )
        return sponsored
    except Exception:
        logger.debug(
            "sponsored_injection_skipped",
            extra={"viewer_id": viewer_id, "reason": "serve_error"},
        )
        return None


def _csv_values(raw: Optional[str]) -> Set[str]:
    if not raw:
        return set()
    return {v.strip() for v in str(raw).split(",") if v.strip()}


def _is_unlock_limit_enabled_for_user(user_id: Optional[str]) -> bool:
    if not bool(getattr(S, "newsfeed_unlock_limit_enabled", True)):
        return False

    mode = str(getattr(S, "newsfeed_unlock_limit_rollout_mode", "broad") or "broad").strip().lower()
    if mode in {"broad", "ga", "all", "on"}:
        return True
    if mode in {"off", "disabled"}:
        return False

    internal_users = _csv_values(getattr(S, "newsfeed_unlock_limit_internal_user_ids", ""))
    if mode == "internal":
        return bool(user_id and user_id in internal_users)

    cohort_users = _csv_values(getattr(S, "newsfeed_unlock_limit_cohort_user_ids", ""))
    if mode == "cohort":
        if not user_id:
            return False
        return user_id in internal_users or user_id in cohort_users

    # Unknown mode: fail open to avoid accidental outage.
    return True


def _emit_newsfeed_content_metric(event: str, **fields: Any) -> None:
    logger.info("newsfeed content metric", extra={"event": event, **fields})


def _emit_newsfeed_draft_metric(
    event: str,
    *,
    outcome: Literal["success", "fail"],
    source: Literal["backend", "frontend"] = "backend",
    reason_code: Optional[str] = None,
    **fields: Any,
) -> None:
    payload = {"event": event, "outcome": outcome, "source": source, **fields}
    if reason_code:
        payload["reason_code"] = reason_code
    if outcome == "success":
        logger.info("newsfeed draft lifecycle metric", extra=payload)
    else:
        logger.warning("newsfeed draft lifecycle metric", extra=payload)


def _emit_newsfeed_content_reject(reason_code: str, *, source: str, body_format: Optional[str] = None) -> None:
    logger.warning(
        "newsfeed content reject",
        extra={"event": "newsfeed_content_reject", "source": source, "reason_code": reason_code, "body_format": body_format or "unknown"},
    )


def _schedule_payload_error(
    *,
    code: str,
    message: str,
    field: Optional[str] = None,
    extra: Optional[Dict[str, Any]] = None,
    operation: Optional[str] = None,
) -> HTTPException:
    if operation:
        record_newsfeed_schedule_operation(operation=operation, outcome="validation_error")
        logger.warning(
            "newsfeed schedule validation failed",
            extra={"event": "newsfeed_schedule_validation_failed", "operation": operation, "code": code, "field": field or "unknown"},
        )
    detail: Dict[str, Any] = {"code": code, "message": message}
    if field:
        detail["field"] = field
    if extra:
        detail.update(extra)
    return HTTPException(status_code=400, detail=detail)


def _require_newsfeed_scheduling_api_enabled() -> None:
    if bool(getattr(S, "newsfeed_scheduling_api_enabled", True)):
        return
    raise HTTPException(
        status_code=404,
        detail={
            "code": "schedule_feature_disabled",
            "message": "scheduled posting is currently disabled",
        },
    )


def _emit_unlock_lifecycle_event(
    event: str,
    *,
    user_id: Optional[str],
    post_id: Optional[str],
    reason_code: Optional[str] = None,
    payment_status: Optional[str] = None,
    unlock_limit: Optional[int] = None,
    unlock_count: Optional[int] = None,
    replayed: Optional[bool] = None,
) -> None:
    logger.info(
        "newsfeed unlock lifecycle",
        extra={
            "event": event,
            "user_id": user_id or "",
            "post_id": post_id or "",
            "reason_code": reason_code or "",
            "payment_status": payment_status or "",
            "unlock_limit": unlock_limit,
            "unlock_count": unlock_count,
            "replayed": replayed,
        },
    )


def _schedule_min_lead_seconds() -> int:
    try:
        return max(1, int(getattr(S, "newsfeed_scheduling_min_lead_seconds", 5)))
    except Exception:
        return 5


def _schedule_max_horizon_seconds() -> int:
    min_lead = _schedule_min_lead_seconds()
    try:
        return max(min_lead + 1, int(getattr(S, "newsfeed_scheduling_max_horizon_seconds", 31536000)))
    except Exception:
        return 31536000


def _ddb_serialize_map(values: Dict[str, Any]) -> Dict[str, Any]:
    return {key: _ddb_serializer.serialize(value) for key, value in values.items()}


def _emit_unlock_replay_event(
    *,
    user_id: Optional[str],
    post_id: str,
    replay_state: str,
    reason_code: str,
    replayed: bool,
) -> None:
    _emit_unlock_lifecycle_event(
        "unlock_replay",
        user_id=user_id,
        post_id=post_id,
        reason_code=reason_code,
        payment_status=replay_state,
        replayed=replayed,
    )


def _unlock_attempt_throttled_error(*, retry_after_seconds: int) -> HTTPException:
    return HTTPException(
        status_code=429,
        detail={
            "code": "unlock_attempt_throttled",
            "message": "too many unlock attempts; try again shortly",
            "retry_after_seconds": max(1, int(retry_after_seconds)),
        },
    )


def _emit_newsfeed_lock_validation_reject(
    reason_code: str,
    *,
    lock_type: Optional[str],
    has_unlock_price: bool,
    has_lottery_fields: bool,
) -> None:
    logger.warning(
        "newsfeed lock validation reject",
        extra={
            "event": "newsfeed_lock_validation_reject",
            "reason_code": reason_code,
            "lock_type": lock_type or "none",
            "has_unlock_price": has_unlock_price,
            "has_lottery_fields": has_lottery_fields,
        },
    )


def _enforce_unlock_attempt_throttle(user_id: str, post_id: str) -> None:
    window_seconds = max(1, int(getattr(S, "newsfeed_unlock_throttle_window_seconds", 10) or 10))
    max_attempts = max(1, int(getattr(S, "newsfeed_unlock_throttle_max_attempts", 6) or 6))
    now_ts = int(time.time())
    key = f"{user_id}:{post_id}"
    with _UNLOCK_ATTEMPT_THROTTLE_LOCK:
        dq = _UNLOCK_ATTEMPT_THROTTLE.setdefault(key, deque())
        cutoff = now_ts - window_seconds
        while dq and dq[0] <= cutoff:
            dq.popleft()
        if len(dq) >= max_attempts:
            retry_after = max(1, window_seconds - (now_ts - dq[0]))
            raise _unlock_attempt_throttled_error(retry_after_seconds=retry_after)
        dq.append(now_ts)



# -----------------------------
# Helpers
# -----------------------------
def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex}"


# ─── Hashtag extraction (SOCIAL-006) ────────────────────────────────────────
_HASHTAG_RE = re.compile(r"#([a-zA-Z][a-zA-Z0-9_]{0,49})\b")
_TAG_VALID_RE = re.compile(r"^[a-z][a-z0-9_]{0,49}$")
_MAX_TAGS_PER_POST = 20


def _extract_hashtags(text: str) -> List[str]:
    """Extract unique hashtags from text, lowercased, preserving order."""
    seen: Set[str] = set()
    tags: List[str] = []
    for match in _HASHTAG_RE.finditer(text):
        tag = match.group(1).lower()
        if tag not in seen:
            seen.add(tag)
            tags.append(tag)
    return tags[:_MAX_TAGS_PER_POST]


def _normalize_tags(raw_tags: List[str]) -> List[str]:
    """Normalize and validate explicit tags: lowercase, strip #, filter invalid."""
    out: List[str] = []
    for raw in raw_tags:
        tag = raw.lower().lstrip("#").strip()
        if _TAG_VALID_RE.match(tag):
            out.append(tag)
    return out


def _write_tag_index(post_id: str, user_id: str, created_at: str, tags: List[str]) -> None:
    """Write TAG#{tag} index items and update TAG_STATS for each tag."""
    if not tags:
        return
    with tbl.batch_writer() as batch:
        for tag in tags:
            batch.put_item(Item={
                "pk": f"TAG#{tag}",
                "sk": f"{created_at}#POST#{post_id}",
                "post_id": post_id,
                "author_id": user_id,
                "created_at": created_at,
            })
    for tag in tags:
        try:
            tbl.update_item(
                Key={"pk": "TAG_STATS", "sk": f"TAG#{tag}"},
                UpdateExpression="SET #n = if_not_exists(#n, :z) + :one, last_used_at = :now",
                ExpressionAttributeNames={"#n": "count"},
                ExpressionAttributeValues={":one": 1, ":z": 0, ":now": created_at},
            )
        except Exception:
            logger.warning("Failed to update TAG_STATS for tag %s", tag)


def decode_cursor_or_400(cursor: Optional[str]) -> Optional[Dict[str, Any]]:
    if not cursor:
        return None
    raw = str(cursor).strip()
    max_chars = max(1, int(getattr(S, "newsfeed_feed_max_cursor_chars", 2048) or 2048))
    if len(raw) > max_chars:
        raise HTTPException(
            status_code=400,
            detail={
                "code": "invalid_cursor",
                "message": "cursor exceeds maximum length",
                "max_cursor_chars": max_chars,
            },
        )
    decoded = decode_cursor(raw)
    if decoded is None:
        raise HTTPException(
            status_code=400,
            detail={
                "code": "invalid_cursor",
                "message": "Invalid cursor",
            },
        )
    return decoded


async def _get_user_id(ctx: Dict[str, str] = Depends(require_ui_session)) -> str:
    return ctx["user_sub"]


UserIdDep = Annotated[str, Depends(_get_user_id)]


def ensure_uploads_enabled() -> None:
    if not UPLOAD_BUCKET or not s3:
        raise HTTPException(status_code=500, detail="UPLOAD_BUCKET not configured")


def _newsfeed_post_quota_error(*, period_id: str, limit_count: int, used_count: int) -> HTTPException:
    remaining_count = max(0, int(limit_count) - int(used_count))
    return HTTPException(
        status_code=403,
        detail={
            "code": "newsfeed_post_quota_exceeded",
            "message": "newsfeed post quota exceeded",
            "quota_type": "newsfeed_post",
            "period_id": period_id,
            "limit_count": int(limit_count),
            "used_count": int(used_count),
            "remaining_count": remaining_count,
        },
    )


def _draft_retention_days() -> int:
    raw = int(getattr(S, "newsfeed_draft_retention_days", 0) or 0)
    return max(0, min(raw, 3650))


def _draft_max_per_user() -> int:
    raw = int(getattr(S, "newsfeed_draft_max_per_user", 50) or 50)
    return max(1, min(raw, 1000))


def _draft_max_payload_bytes() -> int:
    raw = int(getattr(S, "newsfeed_draft_max_payload_bytes", 65536) or 65536)
    return max(1024, min(raw, 1_048_576))


def _draft_quota_bypass_user_ids() -> Set[str]:
    raw = str(getattr(S, "newsfeed_draft_quota_bypass_user_ids", "") or "")
    return {token.strip() for token in raw.split(",") if token.strip()}


def _drafts_enabled_user_ids() -> Set[str]:
    raw = str(getattr(S, "newsfeed_drafts_enabled_user_ids", "") or "")
    return {token.strip() for token in raw.split(",") if token.strip()}


def _drafts_disabled_user_ids() -> Set[str]:
    raw = str(getattr(S, "newsfeed_drafts_disabled_user_ids", "") or "")
    return {token.strip() for token in raw.split(",") if token.strip()}


def _is_drafts_feature_enabled_for_user(user_id: str) -> bool:
    if user_id in _drafts_enabled_user_ids():
        return True
    if user_id in _drafts_disabled_user_ids():
        return False
    return bool(getattr(S, "newsfeed_drafts_enabled", True))


def _ensure_drafts_feature_enabled(user_id: str) -> None:
    if _is_drafts_feature_enabled_for_user(user_id):
        return
    raise HTTPException(status_code=404, detail="Drafts feature is disabled")


def _draft_quota_error(*, limit_count: int, used_count: int) -> HTTPException:
    remaining_count = max(0, int(limit_count) - int(used_count))
    return HTTPException(
        status_code=403,
        detail={
            "code": "newsfeed_draft_quota_exceeded",
            "message": "newsfeed draft quota exceeded",
            "quota_type": "newsfeed_draft",
            "limit_count": int(limit_count),
            "used_count": int(used_count),
            "remaining_count": remaining_count,
        },
    )


def _draft_payload_too_large_error(*, max_payload_bytes: int, payload_bytes: int) -> HTTPException:
    return HTTPException(
        status_code=413,
        detail={
            "code": "newsfeed_draft_payload_too_large",
            "message": "newsfeed draft payload exceeds max size",
            "max_payload_bytes": int(max_payload_bytes),
            "payload_bytes": int(payload_bytes),
        },
    )


def _draft_conflict_error(*, expected_updated_at: str, actual_updated_at: Optional[str]) -> HTTPException:
    return HTTPException(
        status_code=409,
        detail={
            "code": "newsfeed_draft_version_conflict",
            "message": "draft has changed since last read",
            "expected_updated_at": expected_updated_at,
            "actual_updated_at": actual_updated_at,
        },
    )


def _enforce_draft_expected_updated_at(
    *,
    expected_updated_at: Optional[str],
    existing_item: Dict[str, Any],
) -> None:
    if not expected_updated_at:
        return
    actual_updated_at = str(existing_item.get("updated_at") or "")
    if actual_updated_at != expected_updated_at:
        raise _draft_conflict_error(
            expected_updated_at=expected_updated_at,
            actual_updated_at=actual_updated_at or None,
        )


def _draft_payload_bytes(payload: Dict[str, Any]) -> int:
    def _default(o: Any) -> Any:  # noqa: ANN401
        from decimal import Decimal as _D
        if isinstance(o, _D):
            return int(o) if o == int(o) else float(o)
        raise TypeError(f"Object of type {type(o).__name__} is not JSON serializable")

    return len(json.dumps(payload, separators=(",", ":"), ensure_ascii=False, default=_default).encode("utf-8"))


def _maybe_draft_ttl_epoch(updated_at_iso: str) -> Optional[int]:
    retention_days = _draft_retention_days()
    if retention_days <= 0:
        return None
    dt = datetime.fromisoformat(updated_at_iso)
    return int(dt.timestamp()) + (retention_days * 86400)


def _enforce_draft_payload_size(payload: Dict[str, Any]) -> None:
    payload_bytes = _draft_payload_bytes(payload)
    max_payload_bytes = _draft_max_payload_bytes()
    if payload_bytes > max_payload_bytes:
        raise _draft_payload_too_large_error(max_payload_bytes=max_payload_bytes, payload_bytes=payload_bytes)


def _enforce_draft_count_quota(user_id: str) -> None:
    if user_id in _draft_quota_bypass_user_ids():
        return
    limit_count = _draft_max_per_user()
    q = ddb_query(
        **build_draft_list_query(user_id=user_id, cursor=None, limit=limit_count + 1),
        ProjectionExpression="draft_id",
    )
    used_count = len(q.get("Items") or [])
    if used_count >= limit_count:
        raise _draft_quota_error(limit_count=limit_count, used_count=used_count)


def _unlock_limit_error(*, status_code: int, code: str, message: str) -> HTTPException:
    return HTTPException(status_code=status_code, detail={"code": code, "message": message})


def _unlock_limit_validation_error(code: str, message: str) -> HTTPException:
    return _unlock_limit_error(status_code=400, code=code, message=message)


def _unlock_limit_reached_error() -> HTTPException:
    return _unlock_limit_error(
        status_code=409,
        code="unlock_limit_reached",
        message="unlock limit reached",
    )


def _unlock_idempotency_conflict_error() -> HTTPException:
    return _unlock_limit_error(
        status_code=409,
        code="unlock_idempotency_conflict",
        message="idempotency_key does not match existing unlock attempt",
    )


def _unlock_idempotency_payload_mismatch_error() -> HTTPException:
    return _unlock_limit_error(
        status_code=409,
        code="unlock_idempotency_payload_mismatch",
        message="idempotency_key replay payload does not match original request",
    )


def _post_lock_expired_error() -> HTTPException:
    return _unlock_limit_error(
        status_code=409,
        code="post_lock_expired",
        message="post lock expired",
    )


def _parse_newsfeed_post_warning_thresholds() -> List[int]:
    raw = str(getattr(S, "newsfeed_post_quota_warning_thresholds", "80,95") or "80,95").strip()
    out: List[int] = []
    for token in raw.split(','):
        t = token.strip()
        if not t:
            continue
        try:
            value = int(t)
        except ValueError:
            continue
        if 1 <= value <= 100 and value not in out:
            out.append(value)
    out.sort()
    return out or [80, 95]


def _emit_newsfeed_post_quota_warning(
    *,
    threshold_percent: int,
    user_id: str,
    period_id: str,
    limit_count: int,
    projected_count: int,
) -> None:
    logger.warning(
        "newsfeed post quota warning threshold crossed",
        extra={
            "user_id": user_id,
            "period_id": period_id,
            "threshold_percent": threshold_percent,
            "limit_count": int(limit_count),
            "projected_count": int(projected_count),
        },
    )


def _enforce_newsfeed_post_quota_precheck(*, user_id: str) -> None:
    table_name = getattr(S, "filemgr_table_name", None)
    if not table_name:
        return
    try:
        usage = get_usage_summary(user_id)
    except Exception:
        logger.exception("failed to load usage summary for newsfeed post quota pre-check", extra={"user_id": user_id})
        return

    post_usage = usage.get("post_publish") or {}
    used_count = int(post_usage.get("used_count") or 0)
    limit_count = int(post_usage.get("limit_count") or 0)
    period_id = str(usage.get("period_id") or "")

    if limit_count > 0 and used_count >= limit_count:
        overage_mode = str(getattr(S, "newsfeed_post_quota_overage_mode", "block") or "block").strip().lower()
        if overage_mode != "allow":
            raise _newsfeed_post_quota_error(period_id=period_id, limit_count=limit_count, used_count=used_count)

    if not bool(getattr(S, "newsfeed_post_quota_soft_warnings_enabled", False)):
        return
    if limit_count <= 0:
        return

    projected_count = used_count + 1
    for threshold in _parse_newsfeed_post_warning_thresholds():
        trigger_at = max(1, int((limit_count * threshold + 99) // 100))
        if used_count < trigger_at <= projected_count:
            _emit_newsfeed_post_quota_warning(
                threshold_percent=threshold,
                user_id=user_id,
                period_id=period_id,
                limit_count=limit_count,
                projected_count=projected_count,
            )


def ddb_put_item(item: Dict[str, Any]) -> None:
    try:
        tbl.put_item(Item=item)
    except ClientError as exc:
        raise HTTPException(status_code=500, detail=f"DynamoDB error: {exc.response['Error'].get('Message','unknown')}") from exc


def ddb_update_item(
    *,
    key: Dict[str, Any],
    update_expr: str,
    expr_vals: Dict[str, Any],
    expr_names: Optional[Dict[str, str]] = None,
    condition_expr: Optional[str] = None,
    return_values: str = "ALL_NEW",
) -> Dict[str, Any]:
    try:
        kwargs = dict(
            Key=key,
            UpdateExpression=update_expr,
            ExpressionAttributeValues=expr_vals,
            ReturnValues=return_values,
        )
        if expr_names:
            kwargs["ExpressionAttributeNames"] = expr_names
        if condition_expr:
            kwargs["ConditionExpression"] = condition_expr
        resp = tbl.update_item(**kwargs)
        return resp.get("Attributes", {})
    except ClientError as exc:
        code = exc.response["Error"].get("Code", "")
        if code == "ConditionalCheckFailedException":
            raise HTTPException(status_code=409, detail="Conflict / conditional check failed") from exc
        raise HTTPException(status_code=500, detail=f"DynamoDB error: {exc.response['Error'].get('Message','unknown')}") from exc


def ddb_get_item(key: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    try:
        resp = tbl.get_item(Key=key)
        return resp.get("Item")
    except ClientError as exc:
        raise HTTPException(status_code=500, detail=f"DynamoDB error: {exc.response['Error'].get('Message','unknown')}") from exc


def ddb_query(**kwargs) -> Dict[str, Any]:
    # Strip None-valued kwargs so DynamoDB doesn't choke on e.g. ExclusiveStartKey=None
    kwargs = {k: v for k, v in kwargs.items() if v is not None}
    try:
        return tbl.query(**kwargs)
    except ClientError as exc:
        raise HTTPException(status_code=500, detail=f"DynamoDB error: {exc.response['Error'].get('Message','unknown')}") from exc


def ddb_delete_item(key: Dict[str, Any]) -> None:
    try:
        tbl.delete_item(Key=key)
    except ClientError as exc:
        raise HTTPException(status_code=500, detail=f"DynamoDB error: {exc.response['Error'].get('Message','unknown')}") from exc


def _meter_newsfeed_post_publish(*, user_id: str, post_id: str) -> None:
    table_name = getattr(S, "filemgr_table_name", None)
    if not table_name:
        return
    try:
        idempotency_key = build_usage_source_idempotency_key(
            "newsfeed_post",
            user_id=user_id,
            post_id=post_id,
        )
        event = build_usage_event(
            user_id=user_id,
            event_type="upload",
            bytes_count=0,
            source="newsfeed_post",
            resource_path=f"/newsfeed/posts/{post_id}",
            idempotency_key=idempotency_key,
        )
        record_usage_event_and_aggregates(ddb.Table(table_name), event)
    except Exception:
        logger.exception("newsfeed post publish usage metering failed", extra={"user_id": user_id, "post_id": post_id})


def _record_newsfeed_attachment_download(
    *,
    user_id: str,
    post_id: str,
    attachment_key: str,
    bytes_count: int,
    idempotency_operation_id: Optional[str] = None,
) -> None:
    table_name = getattr(S, "filemgr_table_name", None)
    if not table_name or bytes_count <= 0:
        return
    try:
        idempotency_key = build_usage_source_idempotency_key(
            "newsfeed_attachment_download",
            user_id=user_id,
            attachment_key=attachment_key,
            operation_id=idempotency_operation_id or post_id,
        )
        event = build_usage_event(
            user_id=user_id,
            event_type="download",
            bytes_count=bytes_count,
            source="newsfeed_attachment_download",
            resource_path=f"/newsfeed/posts/{post_id}/attachments/{attachment_key}",
            idempotency_key=idempotency_key,
        )
        record_usage_event_and_aggregates(ddb.Table(table_name), event)
    except Exception:
        logger.exception(
            "newsfeed attachment download usage metering failed",
            extra={"user_id": user_id, "post_id": post_id, "attachment_key": attachment_key, "bytes_count": bytes_count},
        )


# -----------------------------
# DynamoDB Key builders
# -----------------------------
def pk_user(user_id: str) -> str:
    return f"USER#{user_id}"


def pk_post(post_id: str) -> str:
    return f"POST#{post_id}"


SCHEDULED_POST_REF_PREFIX = "SCHEDULEDPOST"
SCHEDULE_DUE_INDEX_PK_ATTR = "GSI_SCHEDULE_PK"
SCHEDULE_DUE_INDEX_SK_ATTR = "GSI_SCHEDULE_SK"
SCHEDULE_DUE_INDEX_PK_VALUE = "SCHEDULED"


def _scheduled_publish_sort_key(publish_at: int) -> str:
    # Zero-pad to keep lexicographic sort aligned with numeric timestamp order.
    return f"{int(publish_at):012d}"


def schedule_due_index_values(publish_at: int, post_id: str) -> Dict[str, str]:
    return {
        SCHEDULE_DUE_INDEX_PK_ATTR: SCHEDULE_DUE_INDEX_PK_VALUE,
        SCHEDULE_DUE_INDEX_SK_ATTR: f"{_scheduled_publish_sort_key(publish_at)}#POST#{post_id}",
    }


def sk_scheduled_post_ref(publish_at: int, post_id: str) -> str:
    return f"{SCHEDULED_POST_REF_PREFIX}#{_scheduled_publish_sort_key(publish_at)}#{post_id}"


def parse_scheduled_post_ref_sk(sk: str) -> Optional[Tuple[int, str]]:
    raw = str(sk or "").strip()
    parts = raw.split("#", 2)
    if len(parts) != 3:
        return None
    prefix, publish_at_token, post_id = parts
    if prefix != SCHEDULED_POST_REF_PREFIX or not publish_at_token.isdigit() or not post_id:
        return None
    try:
        return int(publish_at_token), post_id
    except ValueError:
        return None


def sk_post() -> str:
    return "META"


def pk_post_comments(post_id: str) -> str:
    return f"POST#{post_id}#COMMENTS"


def pk_notif(user_id: str) -> str:
    return f"NOTIF#{user_id}"


def pk_hide(user_id: str) -> str:
    return f"HIDE#{user_id}"


def pk_unlock(user_id: str) -> str:
    return f"UNLOCK#{user_id}"


def pk_like(user_id: str) -> str:
    return f"LIKE#{user_id}"


def sk_draft(draft_id: str) -> str:
    return f"DRAFT#{draft_id}"


def gsi_drafts_pk(user_id: str) -> str:
    return f"DRAFTS#{user_id}"


def gsi_drafts_sk(updated_at: str, draft_id: str) -> str:
    return f"{updated_at}#DRAFT#{draft_id}"


def drafts_index_name() -> str:
    return str(getattr(S, "newsfeed_drafts_index_name", "GSI4"))


def build_draft_item(
    *,
    user_id: str,
    draft_id: str,
    payload: Dict[str, Any],
    created_at: Optional[str] = None,
    updated_at: Optional[str] = None,
) -> Dict[str, Any]:
    created = created_at or now_iso()
    updated = updated_at or created
    item = {
        "pk": pk_user(user_id),
        "sk": sk_draft(draft_id),
        "entity_type": "draft_post",
        "status": "draft",
        "draft_id": draft_id,
        "author_id": user_id,
        "created_at": created,
        "updated_at": updated,
        "payload": payload,
        # Draft list index (descending by setting ScanIndexForward=False)
        "GSI4PK": gsi_drafts_pk(user_id),
        "GSI4SK": gsi_drafts_sk(updated, draft_id),
    }
    ttl_epoch = _maybe_draft_ttl_epoch(updated)
    if ttl_epoch is not None:
        item["ttl_epoch"] = ttl_epoch
    return item


def build_draft_list_query(
    *,
    user_id: str,
    cursor: Optional[str],
    limit: int = 20,
) -> Dict[str, Any]:
    query: Dict[str, Any] = {
        "IndexName": drafts_index_name(),
        "KeyConditionExpression": "GSI4PK = :pk",
        "ExpressionAttributeValues": {":pk": gsi_drafts_pk(user_id)},
        "Limit": max(1, min(int(limit), 100)),
        "ScanIndexForward": False,
    }
    eks = decode_cursor_or_400(cursor)
    if eks:
        query["ExclusiveStartKey"] = eks
    return query


# -----------------------------
# Payment Provider (stub)
# -----------------------------
class PaymentProvider:
    """
    Replace with Stripe/CCBill/etc. This stub pretends payments succeed.
    """

    def create_payment_intent(
        self,
        *,
        user_id: str,
        amount_cents: int,
        currency: str,
        metadata: Dict[str, str],
    ) -> Dict[str, Any]:
        intent_id = new_id("pi")
        return {
            "provider": "stub",
            "payment_intent_id": intent_id,
            "client_secret": f"stub_secret_{intent_id}",
            "status": "requires_confirmation",
            "amount_cents": amount_cents,
            "currency": currency,
            "metadata": metadata,
        }

    def confirm_payment_intent(self, *, payment_intent_id: str) -> Dict[str, Any]:
        return {"payment_intent_id": payment_intent_id, "status": "succeeded"}


payments = PaymentProvider()


# -----------------------------
# Models
# -----------------------------
class Attachment(BaseModel):
    attachment_id: str
    filename: str
    content_type: str
    size_bytes: Optional[int] = None
    s3_key: str
    url: Optional[str] = None


BodyFormat = Literal["plain", "markdown", "rich"]

ALLOWED_MARKDOWN_HTML_TAGS: Set[str] = {"p", "br", "strong", "em", "code", "pre", "blockquote", "ul", "ol", "li", "a"}
ALLOWED_MARKDOWN_HTML_ATTRS: Dict[str, Set[str]] = {"a": {"href", "rel", "target"}}
ALLOWED_MARKDOWN_URL_PROTOCOLS: Set[str] = {"https", "mailto"}

ALLOWED_RICH_NODE_TYPES: Set[str] = {
    "doc", "paragraph", "text", "heading", "blockquote", "bulletList", "orderedList", "listItem", "codeBlock", "hardBreak",
}
ALLOWED_RICH_MARK_TYPES: Set[str] = {"bold", "italic", "code", "link"}
ALLOWED_RICH_NODE_ATTRS: Dict[str, Set[str]] = {
    "heading": {"level"},
}
ALLOWED_RICH_MARK_ATTRS: Dict[str, Set[str]] = {
    "link": {"href", "title", "target", "rel"},
}


def _is_safe_rich_link_url(url: str) -> bool:
    return _is_safe_markdown_url(url)


def _raise_rich_schema_error(reason_code: str, message: str) -> None:
    logger.warning("newsfeed rich schema validation failed", extra={"reason_code": reason_code, "detail": message})
    raise ValueError(f"invalid_content_schema:{reason_code}: {message}")


def _validate_rich_node_or_error(node: Any, *, path: str = "doc") -> int:
    if not isinstance(node, dict):
        _raise_rich_schema_error("node_not_object", f"{path} must be a JSON object")

    node_type = node.get("type")
    if not isinstance(node_type, str):
        _raise_rich_schema_error("node_missing_type", f"{path}.type must be a string")
    if node_type not in ALLOWED_RICH_NODE_TYPES:
        _raise_rich_schema_error("unsupported_node_type", f"{path}.type '{node_type}' is not allowed")
    if node_type in {"html", "raw", "rawHtml", "script"}:
        _raise_rich_schema_error("raw_html_not_allowed", f"{path}.type '{node_type}' is not allowed")

    attrs = node.get("attrs")
    if attrs is not None:
        if not isinstance(attrs, dict):
            _raise_rich_schema_error("invalid_node_attrs", f"{path}.attrs must be an object")
        allowed_attrs = ALLOWED_RICH_NODE_ATTRS.get(node_type, set())
        extra_attrs = set(attrs.keys()) - allowed_attrs
        if extra_attrs:
            _raise_rich_schema_error("unsupported_node_attr", f"{path}.attrs contains unsupported keys: {sorted(extra_attrs)}")

    if node_type == "text":
        if not isinstance(node.get("text"), str):
            _raise_rich_schema_error("invalid_text_node", f"{path}.text must be a string")

    marks = node.get("marks")
    if marks is not None:
        if not isinstance(marks, list):
            _raise_rich_schema_error("invalid_marks", f"{path}.marks must be an array")
        for i, mark in enumerate(marks):
            mark_path = f"{path}.marks[{i}]"
            if not isinstance(mark, dict):
                _raise_rich_schema_error("mark_not_object", f"{mark_path} must be an object")
            mark_type = mark.get("type")
            if mark_type not in ALLOWED_RICH_MARK_TYPES:
                _raise_rich_schema_error("unsupported_mark_type", f"{mark_path}.type '{mark_type}' is not allowed")
            mark_attrs = mark.get("attrs")
            if mark_attrs is not None:
                if not isinstance(mark_attrs, dict):
                    _raise_rich_schema_error("invalid_mark_attrs", f"{mark_path}.attrs must be an object")
                allowed_mark_attrs = ALLOWED_RICH_MARK_ATTRS.get(mark_type, set())
                extra_mark_attrs = set(mark_attrs.keys()) - allowed_mark_attrs
                if extra_mark_attrs:
                    _raise_rich_schema_error("unsupported_mark_attr", f"{mark_path}.attrs contains unsupported keys: {sorted(extra_mark_attrs)}")
                if mark_type == "link" and "href" in mark_attrs and not _is_safe_rich_link_url(str(mark_attrs.get("href") or "")):
                    _raise_rich_schema_error("unsafe_link_protocol", f"{mark_path}.attrs.href uses a blocked protocol")

    children = node.get("content")
    count = 1
    if children is not None:
        if not isinstance(children, list):
            _raise_rich_schema_error("invalid_content_children", f"{path}.content must be an array")
        for idx, child in enumerate(children):
            count += _validate_rich_node_or_error(child, path=f"{path}.content[{idx}]")
    return count


def _is_safe_markdown_url(url: str) -> bool:
    candidate = (url or "").strip()
    if not candidate or any(ch in candidate for ch in ['"', "'", " ", "\n", "\r", "\t"]):
        return False
    parsed = urlparse(candidate)
    scheme = (parsed.scheme or "").lower()
    if not (scheme and scheme in ALLOWED_MARKDOWN_URL_PROTOCOLS):
        return False
    if scheme == "https" and not parsed.netloc:
        return False
    if scheme == "mailto" and not parsed.path:
        return False
    return True


def _sanitize_markdown_inline(text: str) -> str:
    safe = escape(text or "")
    safe = re.sub(r"`([^`]+)`", lambda m: f"<code>{m.group(1)}</code>", safe)
    safe = re.sub(r"\*\*([^*]+)\*\*", lambda m: f"<strong>{m.group(1)}</strong>", safe)
    safe = re.sub(r"\*([^*]+)\*", lambda m: f"<em>{m.group(1)}</em>", safe)

    def _link_sub(match: re.Match[str]) -> str:
        label = match.group(1)
        href = match.group(2).strip()
        if not _is_safe_markdown_url(href):
            _emit_newsfeed_content_reject("unsafe_link_protocol", source="markdown_sanitizer", body_format="markdown")
            return label
        return f'<a href="{escape(href, quote=True)}" rel="nofollow noopener noreferrer" target="_blank">{label}</a>'

    safe = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", _link_sub, safe)
    return safe


def render_markdown_sanitized_html(markdown_text: str) -> str:
    text = (markdown_text or "").strip()
    if not text:
        return ""

    lines = text.splitlines()
    html_parts: List[str] = []
    in_ul = False
    in_ol = False

    def _close_lists() -> None:
        nonlocal in_ul, in_ol
        if in_ul:
            html_parts.append("</ul>")
            in_ul = False
        if in_ol:
            html_parts.append("</ol>")
            in_ol = False

    for raw in lines:
        line = raw.rstrip()
        stripped = line.strip()
        if not stripped:
            _close_lists()
            continue

        if stripped.startswith("- "):
            if in_ol:
                html_parts.append("</ol>")
                in_ol = False
            if not in_ul:
                html_parts.append("<ul>")
                in_ul = True
            html_parts.append(f"<li>{_sanitize_markdown_inline(stripped[2:].strip())}</li>")
            continue

        if re.match(r"^\d+\.\s+", stripped):
            if in_ul:
                html_parts.append("</ul>")
                in_ul = False
            if not in_ol:
                html_parts.append("<ol>")
                in_ol = True
            item_text = re.sub(r"^\d+\.\s+", "", stripped, count=1)
            html_parts.append(f"<li>{_sanitize_markdown_inline(item_text)}</li>")
            continue

        _close_lists()
        if stripped.startswith(">"):
            html_parts.append(f"<blockquote>{_sanitize_markdown_inline(stripped[1:].strip())}</blockquote>")
            continue
        html_parts.append(f"<p>{_sanitize_markdown_inline(stripped)}</p>")

    _close_lists()
    return "".join(html_parts)


def _content_limit_int(name: str, default: int) -> int:
    raw = getattr(S, name, default)
    try:
        value = int(raw)
    except (TypeError, ValueError):
        value = default
    return value if value > 0 else default


def _content_max_plain_chars() -> int:
    return _content_limit_int("newsfeed_content_max_plain_chars", 10000)


def _content_max_markdown_chars() -> int:
    return _content_limit_int("newsfeed_content_max_markdown_chars", 20000)


def _content_max_rich_nodes() -> int:
    return _content_limit_int("newsfeed_content_max_rich_nodes", 500)


def _content_max_rich_depth() -> int:
    return _content_limit_int("newsfeed_content_max_rich_depth", 20)


def _walk_rich_tree_stats(node: Any, *, depth: int = 1) -> tuple[int, int]:
    if not isinstance(node, (dict, list)):
        return (0, depth)
    if isinstance(node, list):
        count = 0
        max_depth = depth
        for child in node:
            c_count, c_depth = _walk_rich_tree_stats(child, depth=depth)
            count += c_count
            max_depth = max(max_depth, c_depth)
        return count, max_depth

    count = 1
    max_depth = depth
    for child in node.get("content") or []:
        c_count, c_depth = _walk_rich_tree_stats(child, depth=depth + 1)
        count += c_count
        max_depth = max(max_depth, c_depth)
    return count, max_depth


def _validate_rich_schema_or_error(doc: Any) -> None:
    if not isinstance(doc, dict):
        _raise_rich_schema_error("root_not_object", "body_rich must be a JSON object")
    if doc.get("type") != "doc":
        _raise_rich_schema_error("root_not_doc", "body_rich.type must be 'doc'")
    content = doc.get("content")
    if not isinstance(content, list):
        _raise_rich_schema_error("root_content_not_array", "body_rich.content must be a JSON array")

    node_count = _validate_rich_node_or_error(doc, path="doc")
    _legacy_node_count, max_depth = _walk_rich_tree_stats(doc)
    max_nodes = _content_max_rich_nodes()
    max_allowed_depth = _content_max_rich_depth()
    if node_count > max_nodes:
        _raise_rich_schema_error("node_limit_exceeded", f"body_rich node count exceeds max ({max_nodes})")
    if max_depth > max_allowed_depth:
        _raise_rich_schema_error("depth_limit_exceeded", f"body_rich depth exceeds max ({max_allowed_depth})")


class ContentFieldsMixin(BaseModel):
    # Legacy compatibility field kept for older clients.
    body: Optional[str] = None
    # Canonical content envelope fields.
    body_plain: Optional[str] = None
    body_markdown: Optional[str] = None
    body_markdown_html: Optional[str] = None
    body_rich: Optional[Dict[str, Any]] = None
    body_format: Optional[BodyFormat] = None
    body_version: Optional[int] = Field(default=1, ge=1)

    @model_validator(mode="after")
    def validate_content_fields(self):
        # FEED-004: media comments (kind=gif/sticker) carry no body content;
        # skip the text-content requirement for them. Subclasses without a
        # `kind` field (e.g. posts) default to "text" and validate as before.
        if getattr(self, "kind", "text") != "text":
            return self
        # FEED-005: content-less post kinds (e.g. countdown) are title+metadata
        # only and carry no body; exempt them from the text-content requirement.
        if getattr(self, "post_kind", "text") not in (None, "text"):
            return self
        has_legacy = bool((self.body or "").strip())
        has_plain = bool((self.body_plain or "").strip())
        has_markdown = bool((self.body_markdown or "").strip())
        has_rich = bool(self.body_rich)

        if not (has_legacy or has_plain or has_markdown or has_rich):
            raise ValueError("invalid_content_payload: one of body/body_plain/body_markdown/body_rich is required")

        chosen_format = self.body_format or (
            "rich" if has_rich else "markdown" if has_markdown else "plain"
        )
        if chosen_format == "rich" and not has_rich:
            raise ValueError("invalid_content_payload: body_rich is required when body_format is rich")
        if chosen_format == "markdown" and not has_markdown:
            raise ValueError("invalid_content_payload: body_markdown is required when body_format is markdown")

        if chosen_format == "markdown" and not bool(getattr(S, "newsfeed_markdown_enabled", False)):
            _emit_newsfeed_content_reject("markdown_feature_disabled", source="validator", body_format="markdown")
            raise ValueError("feature_disabled: markdown format is disabled")
        if chosen_format == "rich" and not bool(getattr(S, "newsfeed_richtext_enabled", False)):
            _emit_newsfeed_content_reject("rich_feature_disabled", source="validator", body_format="rich")
            raise ValueError("feature_disabled: rich format is disabled")

        if chosen_format == "rich" and not (has_plain or has_legacy):
            raise ValueError("invalid_content_payload: body_plain (or legacy body) is required when body_rich is provided")

        plain_text = (self.body_plain or self.body or "").strip()
        markdown_text = (self.body_markdown or "").strip()
        if plain_text and len(plain_text) > _content_max_plain_chars():
            raise ValueError(
                f"invalid_content_payload: body_plain/body exceeds max length ({_content_max_plain_chars()})"
            )
        if markdown_text and len(markdown_text) > _content_max_markdown_chars():
            raise ValueError(
                f"invalid_content_payload: body_markdown exceeds max length ({_content_max_markdown_chars()})"
            )
        if has_rich:
            _validate_rich_schema_or_error(self.body_rich)
        return self


def _content_from_payload(req: ContentFieldsMixin) -> Dict[str, Any]:
    body_plain = (req.body_plain or req.body or "").strip()
    body_markdown = (req.body_markdown or "").strip() or None
    body_rich = req.body_rich or None
    body_format: BodyFormat = req.body_format or (
        "rich" if body_rich else "markdown" if body_markdown else "plain"
    )
    if body_format == "markdown" and not body_plain:
        body_plain = body_markdown or ""
    body_markdown_html = render_markdown_sanitized_html(body_markdown or "") if body_markdown else None
    return {
        "body": body_plain,
        "body_plain": body_plain,
        "body_markdown": body_markdown,
        "body_markdown_html": body_markdown_html,
        "body_rich": body_rich,
        "body_format": body_format,
        "body_version": int(req.body_version or 1),
    }


class PollOptionIn(BaseModel):
    text: str = Field(..., min_length=1, max_length=200)

class PollQuestionIn(BaseModel):
    text: str = Field(..., min_length=1, max_length=500)
    choice_mode: Literal["single", "multi"] = "single"
    options: List[PollOptionIn] = Field(..., min_length=2, max_length=10)
    max_selections: Optional[int] = Field(default=None, ge=1, le=10)

class PollDataIn(BaseModel):
    questions: List[PollQuestionIn] = Field(..., min_length=1, max_length=10)
    closes_at: Optional[int] = Field(default=None, ge=0)
    anonymous: bool = True
    allow_vote_change: bool = True

class VoteIn(BaseModel):
    question_id: str = Field(..., min_length=1, max_length=64)
    option_id: str = Field(..., min_length=1, max_length=64)

class CreatePostRequest(ContentFieldsMixin):
    image_urls: List[str] = Field(default_factory=list)
    image_variants: Optional[List[Dict[str, Any]]] = Field(default=None)
    tags: List[str] = Field(default_factory=list)
    video_id: Optional[str] = Field(default=None, max_length=64, pattern=r"^v_[a-f0-9]{32}$")
    visibility: Literal["followers", "public"] = "followers"
    lock_type: Optional[Literal["fixed_price", "tip_lottery"]] = None
    unlock_price_cents: Optional[int] = Field(default=None, ge=0)
    unlock_limit: Optional[int] = Field(default=None, ge=1)
    lottery_tip_cents: Optional[int] = Field(default=None, ge=1)
    lottery_quiet_period_seconds: Optional[int] = Field(default=None, ge=1)
    lottery_state: Optional[Literal["open", "won", "closed"]] = None
    lottery_last_tip_at: Optional[str] = None
    lottery_last_tipper_user_id: Optional[str] = None
    lottery_winner_user_id: Optional[str] = None
    lottery_won_at: Optional[str] = None
    lottery_version: Optional[int] = Field(default=None, ge=0)
    file_paths: List[str] = Field(default_factory=list)
    # ADS-005: allow sponsored posts adjacent in feed
    allow_ads_near: bool = Field(default=True, description="Allow sponsored posts adjacent in feed")
    # ENGAGE-002: Poll/Survey post type
    post_type: Optional[Literal["standard", "poll", "survey"]] = None
    poll_data: Optional[PollDataIn] = None
    # FEED-005: Countdown post fields
    post_kind: Optional[Literal["text", "countdown"]] = Field(
        default=None,
        description="Post content kind. Default is text.",
    )
    countdown_title: Optional[str] = Field(default=None, min_length=1, max_length=200)
    target_datetime: Optional[int] = Field(
        default=None,
        description="UTC Unix timestamp (seconds) for countdown target.",
    )
    associated_event_type: Optional[Literal["broadcast", "call", "calendar", "custom"]] = None
    associated_event_id: Optional[str] = Field(default=None, max_length=128)
    publish_at: Optional[int] = Field(
        default=None,
        ge=0,
        description="Unix timestamp (seconds) for scheduled publish time.",
    )
    schedule_timezone: Optional[str] = Field(
        default=None,
        min_length=1,
        max_length=64,
        description="IANA timezone name used when scheduling (e.g. America/New_York).",
    )
    scheduled_at_local: Optional[str] = Field(
        default=None,
        min_length=1,
        max_length=32,
        description="User-entered local datetime string (for display/audit), e.g. 2026-12-31T19:00.",
    )

    model_config = {
        "json_schema_extra": {
            "examples": [
                {"body": "Legacy plain text post", "visibility": "followers"},
                {
                    "body_plain": "Hello world",
                    "body_markdown": "# Hello world",
                    "body_format": "markdown",
                    "body_version": 1,
                },
                {
                    "body_plain": "Hello rich world",
                    "body_rich": {"type": "doc", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Hello rich world"}]}]},
                    "body_format": "rich",
                    "body_version": 1,
                },
                {
                    "body_plain": "Scheduled post",
                    "publish_at": 1767225600,
                    "schedule_timezone": "America/New_York",
                    "scheduled_at_local": "2026-12-31T19:00",
                },
            ]
        }
    }


class PostVideoEmbed(BaseModel):
    video_id: str
    title: str
    thumbnail_url: Optional[str] = None
    duration_seconds: Optional[float] = None
    hls_manifest_url: Optional[str] = None
    playback_token: Optional[str] = None
    playback_expires_at: Optional[int] = None


class PostResponse(BaseModel):
    post_id: str
    author_id: str
    created_at: str
    published_at: Optional[str] = None
    status: Literal["scheduled", "published", "cancelled"] = "published"
    publish_at: Optional[int] = None
    schedule_timezone: Optional[str] = None
    scheduled_at_local: Optional[str] = None
    body: str
    body_plain: Optional[str] = None
    body_markdown: Optional[str] = None
    body_markdown_html: Optional[str] = None
    body_rich: Optional[Dict[str, Any]] = None
    body_format: BodyFormat = "plain"
    body_version: int = 1
    image_urls: List[str] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)
    visibility: str
    locked: bool
    lock_expired: bool = False
    lock_type: Optional[Literal["fixed_price", "tip_lottery"]] = None
    unlock_price_cents: Optional[int] = None
    unlock_limit: Optional[int] = None
    unlock_count: int = 0
    unlock_limit_reached: bool = False
    lottery_tip_cents: Optional[int] = None
    lottery_quiet_period_seconds: Optional[int] = None
    lottery_state: Optional[Literal["open", "won", "closed"]] = None
    lottery_last_tip_at: Optional[str] = None
    lottery_last_tipper_user_id: Optional[str] = None
    lottery_winner_user_id: Optional[str] = None
    lottery_won_at: Optional[str] = None
    lottery_version: Optional[int] = None
    like_count: int = 0
    comment_count: int = 0
    video: Optional[PostVideoEmbed] = None
    # ADS-005: creator ad adjacency control
    allow_ads_near: bool = True
    # ENGAGE-002: Poll fields
    post_type: str = "standard"
    poll_data: Optional[Dict[str, Any]] = None
    poll_vote_counts: Optional[Dict[str, Any]] = None
    poll_my_votes: Optional[Dict[str, Any]] = None
    # FEED-005: Countdown fields
    post_kind: str = "text"
    countdown_title: Optional[str] = None
    target_datetime: Optional[int] = None
    associated_event_type: Optional[str] = None
    associated_event_id: Optional[str] = None


class ScheduledPostsResponse(BaseModel):
    items: List[Dict[str, Any]] = Field(default_factory=list)
    next_cursor: Optional[str] = None

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "items": [
                        {
                            "post_id": "post_123",
                            "author_id": "user_abc",
                            "status": "scheduled",
                            "publish_at": 1767225600,
                            "schedule_timezone": "America/New_York",
                            "scheduled_at_local": "2026-12-31T19:00",
                            "created_at": "2026-01-01T00:00:00+00:00",
                            "published_at": None,
                            "body": "Scheduled post body",
                            "body_plain": "Scheduled post body",
                            "body_format": "plain",
                            "body_version": 1,
                            "image_urls": [],
                            "visibility": "followers",
                            "locked": False,
                            "like_count": 0,
                            "comment_count": 0,
                        }
                    ],
                    "next_cursor": "eyJwayI6ICJVU0VSI3UxIiwgInNrIjogIlNDSEVEVUxFRFBPU1QjMDAwMDAxNzY3MjI1NjAwI3Bvc3RfMTIzIn0",
                }
            ]
        }
    }


def _gif_allowed_domains() -> frozenset:
    """Resolve the GIF CDN domain allowlist from settings (GAP-0182)."""
    raw = getattr(S, "gif_cdn_allowed_domains", "") or ""
    return frozenset(d.strip().lower() for d in raw.split(",") if d.strip())


def _validate_gif_url(url: str) -> str:
    """GAP-0182: gif_url must be http(s) from an allowlisted GIF CDN domain.

    Rejects data:, javascript:, file:, scheme-relative (//), and arbitrary
    third-party domains. Applies identically in dev and prod (SECOPS-007).
    """
    url = (url or "").strip()
    parsed = urlparse(url)
    if parsed.scheme not in ("https", "http"):
        logger.warning("gif_url rejected (scheme)", extra={"scheme": parsed.scheme})
        raise ValueError(
            f"gif_url scheme '{parsed.scheme}' is not allowed; use https://"
        )
    host = (parsed.hostname or "").lower()
    if host not in _gif_allowed_domains():
        logger.warning("gif_url rejected (domain)", extra={"host": host})
        raise ValueError(
            f"gif_url domain '{host}' is not on the allowed GIF CDN list"
        )
    return url


def _sticker_allowed_prefixes() -> tuple:
    """Resolve allowed platform sticker URL prefixes (GAP-0183)."""
    base = ["/mock/s3/stickers/", "/stickers/", "/media/stickers/"]
    extra = getattr(S, "sticker_cdn_allowed_prefixes", "") or ""
    base.extend(p.strip() for p in extra.split(",") if p.strip())
    return tuple(base)


def _validate_sticker_url(url: str) -> str:
    """GAP-0183: sticker_url must reference platform-hosted content only.

    Accepts platform-relative paths (e.g. /mock/s3/stickers/...) or absolute
    URLs under the configured CDN base. Rejects arbitrary external URLs,
    data:, javascript:, and scheme-relative (//) forms. Same logic in dev and
    prod (SECOPS-007); prod must set FILEMGR_MEDIA_PREVIEW_CDN_BASE_URL.
    """
    url = (url or "").strip()
    # Platform-relative paths served from the same origin as the API.
    # A leading "//" is a scheme-relative URL (off-platform) — exclude it.
    if url.startswith("/") and not url.startswith("//"):
        if url.startswith(_sticker_allowed_prefixes()):
            return url
        logger.warning("sticker_url rejected (relative)", extra={"url_prefix": url[:64]})
        raise ValueError(
            "sticker_url relative path must start with a platform sticker prefix"
        )
    # Absolute CDN URLs when a CDN base is configured.
    cdn_base = (getattr(S, "filemgr_media_preview_cdn_base_url", "") or "").rstrip("/")
    if cdn_base and url.startswith(cdn_base + "/"):
        return url
    parsed = urlparse(url)
    logger.warning(
        "sticker_url rejected (origin)",
        extra={"scheme": parsed.scheme, "host": parsed.hostname},
    )
    raise ValueError(
        "sticker_url must be a platform-relative path or platform CDN URL; "
        f"got scheme='{parsed.scheme}', host='{parsed.hostname}'"
    )


class CreateCommentRequest(ContentFieldsMixin):
    parent_comment_id: Optional[str] = None
    # TIP-302: a comment can CARRY a tip. When tip_amount_cents is present the
    # create-comment handler charges it (recipient = the POST author) via
    # charge_tip BEFORE the comment row is written, then stamps tip_total_cents.
    tip_amount_cents: Optional[int] = Field(default=None, ge=1)
    tip_currency: str = "usd"
    tip_payment_method_id: Optional[str] = None
    # FEED-004: emoji/GIF/sticker comments. `kind` selects the content type.
    # For kind="text" the existing ContentFieldsMixin body_* fields are used.
    kind: Literal["text", "gif", "sticker"] = "text"
    # GIF fields (required when kind=gif) — mirrors MSG-008 message field names.
    gif_url: Optional[str] = Field(default=None, max_length=2048)
    gif_alt_text: Optional[str] = Field(default=None, max_length=256)
    gif_width: Optional[int] = Field(default=None, ge=0, le=4096)
    gif_height: Optional[int] = Field(default=None, ge=0, le=4096)
    # Sticker fields (required when kind=sticker)
    sticker_id: Optional[str] = Field(default=None, max_length=64)
    sticker_collection_id: Optional[str] = Field(default=None, max_length=64)
    sticker_url: Optional[str] = Field(default=None, max_length=2048)
    sticker_alt_text: Optional[str] = Field(default=None, max_length=256)

    model_config = {
        "json_schema_extra": {
            "examples": [
                {"body": "Legacy plain comment"},
                {"body_plain": "Item one", "body_markdown": "- Item one", "body_format": "markdown"},
                {
                    "body_plain": "Rich comment",
                    "body_rich": {"type": "doc", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Rich comment"}]}]},
                    "body_format": "rich",
                },
                {"kind": "gif", "gif_url": "https://media.giphy.com/x.gif", "gif_alt_text": "dance"},
                {
                    "kind": "sticker",
                    "sticker_id": "stk_love_heart_01",
                    "sticker_collection_id": "coll_love_pack",
                    "sticker_url": "/mock/s3/stickers/coll_love_pack/stk_love_heart_01.webp",
                    "sticker_alt_text": "Love heart sticker",
                },
            ]
        }
    }

    @model_validator(mode="after")
    def validate_comment_kind(self):
        # For text comments, defer to the inherited body-content validation
        # (ContentFieldsMixin.validate_content_fields already ran). For media
        # comments require the corresponding media fields and skip body checks.
        if self.kind == "gif":
            if not (self.gif_url or "").strip():
                raise ValueError("gif_url is required for gif comments")
            # GAP-0182: enforce https + GIF CDN domain allowlist
            self.gif_url = _validate_gif_url(self.gif_url)
        elif self.kind == "sticker":
            if not (self.sticker_id or "").strip():
                raise ValueError("sticker_id is required for sticker comments")
            if not (self.sticker_url or "").strip():
                raise ValueError("sticker_url is required for sticker comments")
            # GAP-0183: enforce platform-only sticker origin
            self.sticker_url = _validate_sticker_url(self.sticker_url)
        return self


class EditCommentRequest(ContentFieldsMixin):
    expected_version: int = Field(default=1, ge=1)


class CommentResponse(BaseModel):
    comment_id: str
    post_id: str
    author_id: str
    created_at: str
    updated_at: Optional[str] = None
    deleted: bool = False
    parent_comment_id: Optional[str] = None
    body: Optional[str] = None
    body_plain: Optional[str] = None
    body_markdown: Optional[str] = None
    body_markdown_html: Optional[str] = None
    body_rich: Optional[Dict[str, Any]] = None
    body_format: BodyFormat = "plain"
    body_version: int = 1
    version: int = 1
    tip_total_cents: int = 0
    # FEED-004: emoji/GIF/sticker comments
    kind: str = "text"
    gif_url: Optional[str] = None
    gif_alt_text: Optional[str] = None
    gif_width: Optional[int] = None
    gif_height: Optional[int] = None
    sticker_id: Optional[str] = None
    sticker_collection_id: Optional[str] = None
    sticker_url: Optional[str] = None
    sticker_alt_text: Optional[str] = None


class TipRequest(BaseModel):
    amount_cents: int = Field(..., ge=1)
    currency: str = "usd"
    # TIP-301: name an explicit / tip-default payment method for the comment
    # tip so charge_tip can resolve the tipper's saved PM (falls back to
    # tip-default -> default when None).
    payment_method_id: Optional[str] = None


class UnfollowRequest(BaseModel):
    target_user_id: str


class HidePostRequest(BaseModel):
    post_id: str


class FeedCapabilitiesResponse(BaseModel):
    unlock_limit_enabled: bool = False
    unlock_limit_rollout_mode: str = "off"


class EditPostRequest(ContentFieldsMixin):
    image_urls: Optional[List[str]] = None
    video_id: Optional[str] = Field(default=None, max_length=64, pattern=r"^v_[a-f0-9]{32}$")
    publish_at: Optional[int] = Field(default=None, ge=0)
    schedule_timezone: Optional[str] = Field(default=None, min_length=1, max_length=64)
    scheduled_at_local: Optional[str] = Field(default=None, min_length=1, max_length=32)
    unlock_limit: Optional[int] = Field(default=None, ge=1)


class DraftPostResponse(BaseModel):
    draft_id: str
    author_id: str
    created_at: str
    updated_at: str
    body: Optional[str] = None
    body_plain: Optional[str] = None
    body_markdown: Optional[str] = None
    body_rich: Optional[Dict[str, Any]] = None
    body_format: Optional[BodyFormat] = None
    body_version: int = 1
    image_urls: List[str] = Field(default_factory=list)
    file_paths: List[str] = Field(default_factory=list)
    unlock_price_cents: Optional[int] = Field(default=None, ge=0)
    video_id: Optional[str] = None


class CreateDraftPostRequest(ContentFieldsMixin):
    image_urls: List[str] = Field(default_factory=list)
    file_paths: List[str] = Field(default_factory=list)
    video_id: Optional[str] = Field(default=None, max_length=64, pattern=r"^v_[a-f0-9]{32}$")
    unlock_price_cents: Optional[int] = Field(default=None, ge=0)

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "body": "Legacy plain draft",
                    "image_urls": ["https://cdn.example.com/image-1.jpg"],
                    "file_paths": ["/docs/contracts.pdf"],
                },
                {
                    "body_plain": "Hello draft",
                    "body_markdown": "# Hello draft",
                    "body_format": "markdown",
                    "body_version": 1,
                    "unlock_price_cents": 299,
                },
                {
                    "body_plain": "Hello rich draft",
                    "body_rich": {
                        "type": "doc",
                        "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Hello rich draft"}]}],
                    },
                    "body_format": "rich",
                    "body_version": 1,
                },
            ]
        }
    }


class UpdateDraftPostRequest(BaseModel):
    body: Optional[str] = None
    body_plain: Optional[str] = None
    body_markdown: Optional[str] = None
    body_rich: Optional[Dict[str, Any]] = None
    body_format: Optional[BodyFormat] = None
    body_version: Optional[int] = Field(default=1, ge=1)
    image_urls: Optional[List[str]] = None
    file_paths: Optional[List[str]] = None
    unlock_price_cents: Optional[int] = Field(default=None, ge=0)
    video_id: Optional[str] = Field(default=None, max_length=64, pattern=r"^v_[a-f0-9]{32}$")
    expected_updated_at: Optional[str] = None

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "body_plain": "Updated plain draft body",
                    "image_urls": ["https://cdn.example.com/updated-image.jpg"],
                },
                {
                    "body_plain": "Updated markdown draft",
                    "body_markdown": "## Updated markdown draft",
                    "body_format": "markdown",
                    "unlock_price_cents": 499,
                },
                {
                    "body_plain": "Updated rich draft",
                    "body_rich": {
                        "type": "doc",
                        "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Updated rich draft"}]}],
                    },
                    "body_format": "rich",
                },
            ]
        }
    }


class ListDraftPostsResponse(BaseModel):
    items: List[DraftPostResponse] = Field(default_factory=list)
    next_cursor: Optional[str] = None

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "items": [
                        {
                            "draft_id": "dft_123",
                            "author_id": "user_123",
                            "created_at": "2026-04-04T00:00:00Z",
                            "updated_at": "2026-04-04T00:10:00Z",
                            "body_plain": "Saved draft body",
                            "body_format": "plain",
                            "image_urls": ["https://cdn.example.com/image-1.jpg"],
                            "file_paths": ["/docs/contract.pdf"],
                        }
                    ],
                    "next_cursor": "eyJwayI6ICJ..."
                }
            ]
        }
    }


class PublishDraftPostRequest(BaseModel):
    keep_copy: bool = False
    expected_updated_at: Optional[str] = None


class PresignUploadRequest(BaseModel):
    filename: str
    content_type: str
    size_bytes: Optional[int] = None


class PresignUploadResponse(BaseModel):
    attachment: Attachment
    put_url: str
    put_headers: Dict[str, str] = Field(default_factory=dict)


class UnlockPostRequest(BaseModel):
    post_id: str
    payment_method_id: Optional[str] = None
    # ADV-404: optional last-click CPA attribution handle carried from an ad CTA.
    ad_click_id: Optional[str] = None
    idempotency_key: Optional[str] = Field(
        default=None,
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9:_.-]+$",
    )


class UnlockPostResponse(BaseModel):
    post_id: str
    payment_intent: Dict[str, Any]


class PostTipRequest(BaseModel):
    amount_cents: int = Field(..., ge=1)
    currency: str = "usd"
    payment_method_id: Optional[str] = None


class ReactionRequest(BaseModel):
    emoji: str = Field(..., min_length=1, max_length=10)

class ContentRenderTelemetryRequest(BaseModel):
    reason: Literal["unsupported_format", "render_exception"]
    body_format: Optional[str] = None
    surface: Literal["post", "comment", "unknown"] = "unknown"


class DraftLifecycleTelemetryRequest(BaseModel):
    event: Literal["save_success", "save_fail", "load_success", "load_fail", "delete_success", "delete_fail", "publish_from_draft"]
    outcome: Literal["success", "fail"]
    reason_code: Optional[str] = Field(default=None, max_length=120)
    surface: Literal["composer", "unknown"] = "composer"


# -----------------------------
# Post serialization helper
# -----------------------------
def _rich_doc_to_plain_text(doc: Any) -> str:
    """Best-effort plain text extraction for legacy fallback rendering."""
    parts: List[str] = []

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            text = node.get("text")
            if isinstance(text, str) and text:
                parts.append(text)
            for child in node.get("content") or []:
                walk(child)
        elif isinstance(node, list):
            for child in node:
                walk(child)

    walk(doc)
    return " ".join(part.strip() for part in parts if part and part.strip()).strip()


def _coerce_body_text(value: Any) -> Optional[str]:
    if isinstance(value, str):
        text = value.strip()
        return text or None
    return None


def _coerce_optional_int(value: Any, *, minimum: Optional[int] = None) -> Optional[int]:
    if value is None:
        return None
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    if minimum is not None and parsed < minimum:
        return None
    return parsed


def _is_lock_expired(post: Dict[str, Any]) -> bool:
    raw = post.get("lock_expires_at")
    if raw is None:
        return False
    try:
        if isinstance(raw, (int, float)):
            expiry = datetime.fromtimestamp(float(raw), tz=timezone.utc)
        else:
            parsed = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
            expiry = parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except Exception:
        return False
    return expiry <= datetime.now(timezone.utc)


def _resolve_read_body_fields(item: Dict[str, Any]) -> Tuple[str, Optional[str], Optional[str], Optional[str], Optional[Dict[str, Any]], BodyFormat, int]:
    """Resolve legacy/new content fields for response serialization with rollout-safe fallbacks."""
    legacy_body = _coerce_body_text(item.get("body"))
    body_plain = _coerce_body_text(item.get("body_plain"))
    body_markdown = _coerce_body_text(item.get("body_markdown"))
    body_rich = item.get("body_rich") if isinstance(item.get("body_rich"), dict) else None
    rich_plain = _rich_doc_to_plain_text(body_rich) if body_rich else None

    resolved_plain = body_plain or legacy_body or body_markdown or rich_plain or ""
    resolved_body = resolved_plain

    body_markdown_html = item.get("body_markdown_html")
    if not isinstance(body_markdown_html, str) or not body_markdown_html.strip():
        body_markdown_html = render_markdown_sanitized_html(body_markdown or "") if body_markdown else None

    raw_body_format = item.get("body_format")
    if raw_body_format in {"plain", "markdown", "rich"}:
        body_format: BodyFormat = raw_body_format
    elif body_rich:
        body_format = "rich"
    elif body_markdown:
        body_format = "markdown"
    else:
        body_format = "plain"

    markdown_enabled = bool(getattr(S, "newsfeed_markdown_enabled", False))
    rich_enabled = bool(getattr(S, "newsfeed_richtext_enabled", False))

    if body_format == "rich" and not rich_enabled:
        body_format = "plain"
        body_rich = None
        body_markdown = None
        body_markdown_html = None
    elif body_format == "markdown" and not markdown_enabled:
        body_format = "plain"
        body_markdown = None
        body_markdown_html = None

    body_version = int(item.get("body_version") or 1)
    return resolved_body, resolved_plain or None, body_markdown, body_markdown_html, body_rich, body_format, body_version


def _reaction_summaries(reactions_map: Dict, viewer_id: Optional[str] = None):
    """Compute per-emoji counts and the viewer's own reactions from a DDB reactions map."""
    counts: Dict[str, int] = {}
    mine: List[str] = []
    for emoji, users in (reactions_map or {}).items():
        if isinstance(users, dict) and users:
            counts[emoji] = len(users)
            if viewer_id and users.get(viewer_id):
                mine.append(emoji)
    return counts, mine


def _resolve_post_lifecycle_fields(post: Dict[str, Any]) -> Tuple[Literal["scheduled", "published", "cancelled"], Optional[int], Optional[str], Optional[str], Optional[str]]:
    raw_status = str(post.get("status") or "").strip().lower()
    status: Literal["scheduled", "published", "cancelled"]
    if raw_status in {"scheduled", "published", "cancelled"}:
        status = raw_status
    else:
        status = "published"

    publish_at_raw = post.get("publish_at")
    try:
        publish_at = int(publish_at_raw) if publish_at_raw is not None else None
    except (TypeError, ValueError):
        publish_at = None

    published_at_raw = post.get("published_at")
    published_at = published_at_raw.strip() if isinstance(published_at_raw, str) and published_at_raw.strip() else None
    if not published_at and status == "published":
        created_at_raw = post.get("created_at")
        if isinstance(created_at_raw, str) and created_at_raw.strip():
            published_at = created_at_raw.strip()

    schedule_timezone_raw = post.get("schedule_timezone")
    schedule_timezone = schedule_timezone_raw.strip() if isinstance(schedule_timezone_raw, str) and schedule_timezone_raw.strip() else None

    scheduled_at_local_raw = post.get("scheduled_at_local")
    scheduled_at_local = scheduled_at_local_raw.strip() if isinstance(scheduled_at_local_raw, str) and scheduled_at_local_raw.strip() else None

    if status != "scheduled":
        publish_at = None
        schedule_timezone = None
        scheduled_at_local = None

    return status, publish_at, published_at, schedule_timezone, scheduled_at_local


def _write_feed_ref_for_published_post(*, user_id: str, post_id: str, created_at: str) -> None:
    feed_item = {
        "pk": pk_post(post_id),
        "sk": f"FEEDREF#{user_id}",
        "Entity": "FeedRef",
        "post_id": post_id,
        "owner_user_id": user_id,
        "created_at": created_at,
        "GSI1PK": f"FEED#{user_id}",
        "GSI1SK": f"{created_at}#POST#{post_id}",
    }
    ddb_put_item(feed_item)


def _write_scheduled_post_ref(
    *,
    user_id: str,
    post_id: str,
    created_at: str,
    publish_at: int,
    schedule_timezone: Optional[str] = None,
    scheduled_at_local: Optional[str] = None,
) -> None:
    scheduled_ref = {
        "pk": pk_user(user_id),
        "sk": sk_scheduled_post_ref(publish_at, post_id),
        "Entity": "ScheduledPostRef",
        "post_id": post_id,
        "owner_user_id": user_id,
        "status": "scheduled",
        "publish_at": publish_at,
        "schedule_timezone": schedule_timezone,
        "scheduled_at_local": scheduled_at_local,
        "created_at": created_at,
    }
    ddb_put_item(scheduled_ref)


def _normalized_post_lock_type(post: Dict[str, Any]) -> Optional[str]:
    raw_lock_type = post.get("lock_type")
    if raw_lock_type in {"fixed_price", "tip_lottery"}:
        return raw_lock_type
    if raw_lock_type is None:
        unlock_price = int(post["unlock_price_cents"]) if post.get("unlock_price_cents") is not None else 0
        if unlock_price > 0:
            logger.info(
                "newsfeed lock_type fallback",
                extra={
                    "event": "newsfeed_lock_type_fallback",
                    "post_id": post.get("post_id"),
                    "derived_lock_type": "fixed_price",
                },
            )
            return "fixed_price"
    return None


def _check_reposted_by_me(viewer_id: Optional[str], post_id: str) -> bool:
    """Check if the viewer has reposted a given post. O(1) point read."""
    if not viewer_id:
        return False
    try:
        item = tbl.get_item(Key={"pk": pk_repost(viewer_id), "sk": f"POST#{post_id}"}).get("Item")
        return bool(item)
    except Exception:
        return False


def pk_repost_lookup(user_id: str) -> str:
    """Key builder for repost entities."""
    return f"REPOST#{user_id}"


def _poll_fields_for_post(post: Dict[str, Any], locked_body: bool, viewer_id: Optional[str]) -> Dict[str, Any]:
    """Extract ENGAGE-002 poll fields for _post_to_dict output."""
    post_type = post.get("post_type", "standard")
    if post_type not in ("poll", "survey") or locked_body:
        return {"poll_data": None, "poll_vote_counts": None, "poll_my_votes": None}
    from app.services.newsfeed_polls import serialize_poll_for_post
    return serialize_poll_for_post(post, viewer_id)


def _post_to_dict(post: Dict[str, Any], locked_body: bool = False, liked_by_me: bool = False, unlocked: bool = False, viewer_id: Optional[str] = None, bookmarked_ids: Optional[set] = None) -> Dict[str, Any]:
    """Map a raw DDB post item to the FeedPost shape expected by the frontend.

    GAP-0357 sub-gap 1: callers that have pre-loaded the viewer's bookmarked
    post IDs may pass ``bookmarked_ids`` so each post carries an ``is_bookmarked``
    flag. Optional for backward compatibility (defaults to not-bookmarked).
    """
    body, body_plain, body_markdown, body_markdown_html, body_rich, body_format, body_version = _resolve_read_body_fields(post)
    status, publish_at, published_at, schedule_timezone, scheduled_at_local = _resolve_post_lifecycle_fields(post)

    # Support both old image_url (str) and new image_urls (list)
    image_urls = list(post.get("image_urls") or [])
    if not image_urls and post.get("image_url"):
        image_urls = [post["image_url"]]
    if locked_body:
        body = "[Locked content]"
        image_urls = []
        body_plain = body
        body_markdown = None
        body_markdown_html = None
        body_rich = None
        body_format = "plain"
        body_version = 1
    reactions_map = post.get("reactions") or {}
    reactions_counts, my_reactions = _reaction_summaries(reactions_map, viewer_id)
    post_id = post["post_id"]
    raw_attachments = [] if locked_body else (post.get("file_attachments") or [])
    file_attachments = [
        {
            "name": fa.get("name"),
            "content_type": fa.get("content_type"),
            "size": int(fa["size"]) if fa.get("size") is not None else None,
            "url": f"/api/posts/{post_id}/files/{i}",
        }
        for i, fa in enumerate(raw_attachments)
    ]
    unlock_limit_feature_on = _is_unlock_limit_enabled_for_user(viewer_id)
    unlock_limit = _coerce_optional_int(post.get("unlock_limit"), minimum=1) if unlock_limit_feature_on else None
    unlock_count = (_coerce_optional_int(post.get("unlock_count"), minimum=0) or 0) if unlock_limit_feature_on else 0
    lock_expired = _is_lock_expired(post)
    unlock_limit_reached = unlock_limit_feature_on and (not lock_expired) and unlock_limit is not None and unlock_count >= unlock_limit
    lock_type = _normalized_post_lock_type(post)
    unlock_price_cents = int(post["unlock_price_cents"]) if post.get("unlock_price_cents") is not None else None
    lottery_tip_cents = int(post["lottery_tip_cents"]) if post.get("lottery_tip_cents") is not None else None
    lottery_quiet_period_seconds = int(post["lottery_quiet_period_seconds"]) if post.get("lottery_quiet_period_seconds") is not None else None
    lottery_version = int(post["lottery_version"]) if post.get("lottery_version") is not None else None

    # Video embed metadata (FEED-001)
    video_embed = None
    raw_video_id = post.get("video_id")
    if raw_video_id and isinstance(raw_video_id, str):
        try:
            from app.services.video_metadata_store import get_video as _feed_vid
            _vr = _feed_vid(raw_video_id)
            video_embed = {
                "video_id": raw_video_id,
                "title": _vr.title,
                "thumbnail_url": _vr.thumbnail_url,
                "duration_seconds": _vr.duration_seconds,
                "hls_manifest_url": None if locked_body else _vr.hls_manifest_url,
                "playback_token": None,
                "playback_expires_at": None,
            }
        except Exception:
            video_embed = None

    return {
        "post_id": post_id,
        "author_id": post.get("user_id", ""),
        "created_at": post.get("created_at", ""),
        "published_at": published_at,
        "status": status,
        "publish_at": publish_at,
        "schedule_timezone": schedule_timezone,
        "scheduled_at_local": scheduled_at_local,
        "updated_at": post.get("updated_at"),
        "body": body,
        "body_plain": body_plain,
        "body_markdown": body_markdown,
        "body_markdown_html": body_markdown_html,
        "body_rich": body_rich,
        "body_format": body_format,
        "body_version": body_version,
        "image_urls": image_urls,
        "image_variants": list(post.get("image_variants") or []),
        "video": video_embed,
        "file_attachments": file_attachments,
        "visibility": post.get("visibility", "followers"),
        "locked": bool(post.get("locked")),
        "lock_expired": lock_expired,
        "lock_type": lock_type,
        "unlock_price_cents": unlock_price_cents,
        "unlock_limit": unlock_limit,
        "unlock_count": unlock_count,
        "unlock_limit_reached": unlock_limit_reached,
        "lottery_tip_cents": lottery_tip_cents,
        "lottery_quiet_period_seconds": lottery_quiet_period_seconds,
        "lottery_state": post.get("lottery_state"),
        "lottery_last_tip_at": post.get("lottery_last_tip_at"),
        "lottery_last_tipper_user_id": post.get("lottery_last_tipper_user_id"),
        "lottery_winner_user_id": post.get("lottery_winner_user_id"),
        "lottery_won_at": post.get("lottery_won_at"),
        "lottery_version": lottery_version,
        "unlocked": unlocked,
        "like_count": int(post.get("like_count", 0)),
        "comment_count": int(post.get("comment_count", 0)),
        "tip_total_cents": int(post.get("tip_total_cents", 0)),
        "tip_reactions": [
            {"tipper_id": _r.get("tipper_id"), "emoji": _r.get("emoji"),
             "amount_cents": int(_r.get("amount_cents") or 0),
             "tip_payment_id": _r.get("tip_payment_id"),
             "created_at": _r.get("created_at")}
            for _r in (post.get("tip_reactions") or [])
        ],
        "liked_by_me": liked_by_me,
        "reactions_counts": reactions_counts,
        "my_reactions": my_reactions,
        # BCAST-010: broadcast post type and metadata
        "post_type": post.get("post_type", "standard"),
        "broadcast_meta": post.get("broadcast_meta"),
        # SOCIAL-002: repost count
        "repost_count": int(post.get("repost_count", 0)),
        "reposted_by_me": _check_reposted_by_me(viewer_id, post_id) if viewer_id else False,
        # GAP-0357 sub-gap 1: per-viewer bookmark status
        "is_bookmarked": post_id in bookmarked_ids if bookmarked_ids else False,
        # FEED-007: per-viewer "interesting" signal + public aggregate
        "interesting_count": int(post.get("interesting_count", 0)),
        "is_interesting": _is_post_interesting(viewer_id, post_id) if viewer_id else False,
        # SOCIAL-006: hashtags/topics
        "tags": list(post.get("tags") or []),
        # ADS-005: creator ad adjacency control
        "allow_ads_near": bool(post.get("allow_ads_near", True)),
        # ADS-013: sponsored content / FTC disclosure
        "sponsored_by": post.get("sponsored_by"),
        "deal_id": post.get("deal_id"),
        "ftc_disclosure": post.get("ftc_disclosure"),
        # ENGAGE-002: Poll data
        **_poll_fields_for_post(post, locked_body, viewer_id),
        # FEED-005: Countdown fields (countdown_title hidden when post body is locked)
        "post_kind": post.get("post_kind", "text"),
        "countdown_title": None if locked_body else post.get("countdown_title"),
        "target_datetime": (
            int(post["target_datetime"]) if post.get("target_datetime") is not None else None
        ),
        "associated_event_type": post.get("associated_event_type"),
        "associated_event_id": None if locked_body else post.get("associated_event_id"),
        # FEED-003: Find-a-DateTime post fields (additive; only set for find_datetime posts)
        "find_datetime_id": post.get("find_datetime_id"),
        "find_datetime_title": post.get("find_datetime_title"),
        "find_datetime_from_date": post.get("find_datetime_from_date"),
        "find_datetime_to_date": post.get("find_datetime_to_date"),
        "find_datetime_start_hour": (
            int(post["find_datetime_start_hour"]) if post.get("find_datetime_start_hour") is not None else None
        ),
        "find_datetime_end_hour": (
            int(post["find_datetime_end_hour"]) if post.get("find_datetime_end_hour") is not None else None
        ),
        "find_datetime_slot_duration_minutes": (
            int(post["find_datetime_slot_duration_minutes"])
            if post.get("find_datetime_slot_duration_minutes") is not None else None
        ),
        "find_datetime_status": post.get("find_datetime_status"),
        # GROUP-002: Group context fields
        **({"group_id": post["group_id"], "audience": post.get("audience", "public"),
            "pinned": bool(post.get("pinned")),
            "pinned_at": int(post["pinned_at"]) if post.get("pinned_at") else None,
            "pinned_by": post.get("pinned_by")}
           if post.get("group_id") else {}),
    }


def _comment_to_dict(it: Dict[str, Any]) -> Dict[str, Any]:
    """Map a raw DDB comment item to the FeedComment shape expected by the frontend."""
    body, body_plain, body_markdown, body_markdown_html, body_rich, body_format, _body_version = _resolve_read_body_fields(it)
    if it.get("deleted"):
        body = None
        body_plain = None
        body_markdown = None
        body_markdown_html = None
        body_rich = None
        body_format = "plain"
    return {
        "comment_id": it["comment_id"],
        "post_id": it["post_id"],
        "author_id": it.get("user_id", ""),
        "created_at": it.get("created_at", ""),
        "updated_at": it.get("updated_at"),
        "deleted": bool(it.get("deleted")),
        "parent_comment_id": it.get("parent_comment_id"),
        "body": body,
        "body_plain": body_plain,
        "body_markdown": body_markdown,
        "body_markdown_html": body_markdown_html,
        "body_rich": body_rich,
        "body_format": body_format,
        "body_version": _body_version,
        "version": int(it.get("version", 1)),
        "tip_total_cents": int(it.get("tip_total_cents", 0)),
        "tip_reactions": [
            {"tipper_id": _r.get("tipper_id"), "emoji": _r.get("emoji"),
             "amount_cents": int(_r.get("amount_cents") or 0),
             "tip_payment_id": _r.get("tip_payment_id"),
             "created_at": _r.get("created_at")}
            for _r in (it.get("tip_reactions") or [])
        ],
        # FEED-004: emoji/GIF/sticker comments (additive — legacy items lack these)
        "kind": it.get("kind", "text"),
        "gif_url": it.get("gif_url"),
        "gif_alt_text": it.get("gif_alt_text"),
        "gif_width": int(it["gif_width"]) if it.get("gif_width") is not None else None,
        "gif_height": int(it["gif_height"]) if it.get("gif_height") is not None else None,
        "sticker_id": it.get("sticker_id"),
        "sticker_collection_id": it.get("sticker_collection_id"),
        "sticker_url": it.get("sticker_url"),
        "sticker_alt_text": it.get("sticker_alt_text"),
    }


# -----------------------------
# SSE Hub (in-memory per instance)
# -----------------------------
class SSEHub:
    """
    Per-instance connection registry. Distributed delivery is achieved via SNS->SQS,
    where each instance receives events from SQS and then dispatches locally.
    """

    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self._conns: Dict[str, Set[asyncio.Queue]] = {}

    async def add(self, user_id: str) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=200)
        async with self._lock:
            self._conns.setdefault(user_id, set()).add(q)
        return q

    async def remove(self, user_id: str, q: asyncio.Queue) -> None:
        async with self._lock:
            conns = self._conns.get(user_id)
            if not conns:
                return
            conns.discard(q)
            if not conns:
                self._conns.pop(user_id, None)

    async def publish(self, user_id: str, event: Dict[str, Any]) -> int:
        async with self._lock:
            qs = list(self._conns.get(user_id, set()))
        delivered = 0
        for q in qs:
            try:
                q.put_nowait(event)
                delivered += 1
            except asyncio.QueueFull:
                pass
        return delivered


sse_hub = SSEHub()


def sse_format(event: Dict[str, Any]) -> str:
    data = json.dumps(event, separators=(",", ":"))
    return f"data: {data}\n\n"


async def sse_event_stream(request: Request, user_id: str, q: asyncio.Queue):
    yield sse_format({"type": "hello", "user_id": user_id, "ts": now_iso()})

    keepalive_seconds = 15
    while True:
        if await request.is_disconnected():
            break
        try:
            event = await asyncio.wait_for(q.get(), timeout=keepalive_seconds)
            yield sse_format(event)
        except asyncio.TimeoutError:
            yield ":\n\n"


async def sqs_poller_task() -> None:
    if not EVENTS_SQS_URL or not sqs:
        return

    loop = asyncio.get_running_loop()

    while True:
        try:
            resp = await loop.run_in_executor(
                None,
                lambda: sqs.receive_message(
                    QueueUrl=EVENTS_SQS_URL,
                    MaxNumberOfMessages=10,
                    WaitTimeSeconds=20,
                    VisibilityTimeout=30,
                ),
            )
            msgs = resp.get("Messages", [])
            if not msgs:
                continue

            for msg in msgs:
                receipt = msg["ReceiptHandle"]
                body = msg.get("Body", "")

                try:
                    envelope = json.loads(body)
                    payload_str = envelope.get("Message", body)
                    payload = json.loads(payload_str) if isinstance(payload_str, str) else payload_str

                    user_id = payload.get("user_id") if isinstance(payload, dict) else None
                    if user_id:
                        await sse_hub.publish(user_id, payload)
                except Exception:
                    pass
                finally:
                    await loop.run_in_executor(
                        None,
                        lambda r=receipt: sqs.delete_message(QueueUrl=EVENTS_SQS_URL, ReceiptHandle=r),
                    )
        except Exception:
            await asyncio.sleep(1.0)


async def startup() -> None:
    if EVENTS_SQS_URL:
        asyncio.create_task(sqs_poller_task())


@router.get("/sse")
async def sse(request: Request, user_id: UserIdDep):
    q = await sse_hub.add(user_id)

    async def _gen():
        try:
            async for chunk in sse_event_stream(request, user_id, q):
                yield chunk
        finally:
            await sse_hub.remove(user_id, q)

    return StreamingResponse(_gen(), media_type="text/event-stream")


# -----------------------------
# Notification writer
# -----------------------------
def put_notification(*, recipient_user_id: str, notif_type: str, payload: Dict[str, Any]) -> str:
    notif_id = new_id("ntf")
    created_at = now_iso()
    item = {
        "pk": pk_notif(recipient_user_id),
        "sk": f"{created_at}#NOTIF#{notif_id}",
        "Entity": "Notification",
        "notif_id": notif_id,
        "recipient_user_id": recipient_user_id,
        "type": notif_type,
        "payload": payload,
        "created_at": created_at,
        "GSI3PK": pk_notif(recipient_user_id),
        "GSI3SK": f"{created_at}#{notif_id}",
        "read": False,
    }
    ddb_put_item(item)

    event = {
        "type": "notification",
        "user_id": recipient_user_id,
        "created_at": created_at,
        "data": {"notif_type": notif_type, "payload": payload, "notif_id": notif_id},
    }
    try:
        loop = asyncio.get_running_loop()
        loop.create_task(sse_hub.publish(recipient_user_id, event))
    except RuntimeError:
        # Called from a sync threadpool context — SSE push not possible; notification is in DDB
        pass

    return notif_id


# -----------------------------
# Following / hiding / unlock helpers
# -----------------------------
def _notify_author_unlock_limit_reached_once(*, post_id: str, triggered_by_user_id: Optional[str]) -> None:
    post = ddb_get_item({"pk": pk_post(post_id), "sk": sk_post()}) or {}
    author_id = post.get("user_id")
    if not author_id:
        return
    marker_key = {"pk": pk_post(post_id), "sk": "UNLOCK_LIMIT_REACHED_NOTIF"}
    try:
        tbl.put_item(
            Item={
                **marker_key,
                "Entity": "PostUnlockLimitReachedNotifMarker",
                "post_id": post_id,
                "recipient_user_id": author_id,
                "created_at": now_iso(),
            },
            ConditionExpression="attribute_not_exists(pk) AND attribute_not_exists(sk)",
        )
    except ClientError as exc:
        code = exc.response["Error"].get("Code", "")
        if code == "ConditionalCheckFailedException":
            return
        logger.warning("unlock_limit_reached notification marker write failed", extra={"post_id": post_id, "error_code": code})
        return
    put_notification(
        recipient_user_id=author_id,
        notif_type="post_unlock_limit_reached",
        payload={
            "post_id": post_id,
            "unlock_limit": _coerce_optional_int(post.get("unlock_limit"), minimum=1),
            "unlock_count": _coerce_optional_int(post.get("unlock_count"), minimum=0),
            "triggered_by_user_id": triggered_by_user_id or "",
            "created_at": now_iso(),
        },
    )


def is_following(viewer_id: str, target_id: str) -> bool:
    from app.services.social import get_follow_status
    status = get_follow_status(viewer_id, target_id)
    return status["is_following"]


def is_hidden(user_id: str, post_id: str) -> bool:
    it = ddb_get_item({"pk": pk_hide(user_id), "sk": f"POST#{post_id}"})
    return bool(it and it.get("hidden") is True)


@router.post("/feed/unhide")
def unhide_post(req: HidePostRequest, user_id: UserIdDep):
    """Unhide a post for the current viewer (FEED-006).

    Deletes the per-viewer hide record written by ``hide_post`` (pk=HIDE#{user},
    sk=POST#{post_id}). Idempotent: unhiding a post that is not hidden is a no-op
    success (DynamoDB delete_item does not error on a missing key).
    """
    ddb_delete_item({"pk": pk_hide(user_id), "sk": f"POST#{req.post_id}"})
    return {"ok": True, "post_id": req.post_id, "hidden": False}


@router.get("/feed/hidden")
def list_hidden_posts(
    limit: int = Query(20, ge=1, le=100),
    cursor: Optional[str] = None,
    user_id: UserIdDep = None,
):
    """List the posts the current viewer has hidden (FEED-006).

    Queries the viewer's hide partition (pk=HIDE#{user}, sk begins_with POST#)
    and hydrates each post via ``_post_to_dict``. Posts that were deleted after
    being hidden are returned as a minimal stub so the client can still offer an
    unhide affordance. Paginated with the same cursor scheme as the feed.
    """
    eks = decode_cursor_or_400(cursor)
    resp = ddb_query(
        KeyConditionExpression="pk = :pk AND begins_with(sk, :prefix)",
        ExpressionAttributeValues={":pk": pk_hide(user_id), ":prefix": "POST#"},
        Limit=limit,
        ExclusiveStartKey=eks if eks else None,
        ScanIndexForward=False,
    )
    items: List[Dict[str, Any]] = []
    for rec in resp.get("Items", []):
        sk = rec.get("sk", "")
        post_id = sk.split("#", 1)[-1] if "#" in sk else sk
        if not post_id:
            continue
        post = ddb_get_item({"pk": pk_post(post_id), "sk": sk_post()})
        if not post:
            items.append({"post_id": post_id, "hidden": True})
            continue
        d = _post_to_dict(post, viewer_id=user_id)
        d["hidden"] = True
        items.append(d)
    return {"items": items, "next_cursor": encode_cursor(resp.get("LastEvaluatedKey"))}


def has_unlocked(user_id: str, post_id: str) -> bool:
    it = ddb_get_item({"pk": pk_unlock(user_id), "sk": f"POST#{post_id}"})
    return bool(it and it.get("unlocked") is True)


def can_view_post(viewer_id: str, post: Dict[str, Any]) -> bool:
    author = str(post.get("user_id") or "").strip()
    if not author or author == viewer_id:
        return True
    if not can_access_creator(viewer_id, author):
        return False
    visibility = str(post.get("visibility") or "followers").strip().lower()
    if visibility == "public":
        return True
    return is_following(viewer_id, author)


def _dedupe_strs(values: List[str]) -> List[str]:
    seen: Set[str] = set()
    out: List[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        out.append(value)
    return out


def _validate_and_normalize_draft_image_urls(*, user_id: str, image_urls: List[str]) -> List[str]:
    normalized: List[str] = []
    for idx, raw in enumerate(image_urls):
        if not isinstance(raw, str):
            raise ValueError(f"invalid_draft_payload: image_urls[{idx}] must be a string")
        url = raw.strip()
        if not url:
            raise ValueError(f"invalid_draft_payload: image_urls[{idx}] cannot be empty")
        if len(url) > 2048:
            raise ValueError(f"invalid_draft_payload: image_urls[{idx}] exceeds max length (2048)")
        if url.startswith("/uploads/object"):
            parsed = urlparse(url)
            query = parse_qs(parsed.query or "")
            s3_key = ((query.get("s3_key") or [""])[0] or "").strip()
            if not s3_key:
                raise ValueError(f"invalid_draft_payload: image_urls[{idx}] missing s3_key")
            owner_prefix = f"uploads/{user_id}/"
            if not s3_key.startswith(owner_prefix):
                raise ValueError(
                    f"invalid_draft_payload: image_urls[{idx}] must reference an upload owned by the current user"
                )
            normalized.append(url)
            continue
        parsed = urlparse(url)
        if parsed.scheme != "https" or not parsed.netloc:
            raise ValueError(
                f"invalid_draft_payload: image_urls[{idx}] must be an https URL or an /uploads/object URL"
            )
        normalized.append(url)
    return _dedupe_strs(normalized)[:10]


def _validate_and_normalize_draft_file_paths(*, user_id: str, file_paths: List[str]) -> List[str]:
    normalized: List[str] = []
    for idx, raw in enumerate(file_paths):
        if not isinstance(raw, str):
            raise ValueError(f"invalid_draft_payload: file_paths[{idx}] must be a string")
        if not raw.strip():
            raise ValueError(f"invalid_draft_payload: file_paths[{idx}] cannot be empty")
        try:
            clean = norm_path(raw, is_folder=False)
            get_node(user_id, clean)
        except HTTPException as exc:
            if exc.status_code in {400, 403, 404}:
                raise ValueError(
                    f"invalid_draft_payload: file_paths[{idx}] must reference an existing file owned by the current user"
                ) from exc
            raise
        normalized.append(clean)
    return _dedupe_strs(normalized)[:5]


def _validate_and_normalize_unlock_price(unlock_price_cents: Optional[int]) -> Optional[int]:
    if unlock_price_cents is None:
        return None
    cents = int(unlock_price_cents)
    if cents <= 0:
        raise ValueError("invalid_draft_payload: unlock_price_cents must be greater than zero when provided")
    if cents > 10_000_000:
        raise ValueError("invalid_draft_payload: unlock_price_cents exceeds max allowed value")
    return cents


def _validate_and_normalize_draft_payload(*, user_id: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    normalized = dict(payload)
    normalized["image_urls"] = _validate_and_normalize_draft_image_urls(
        user_id=user_id,
        image_urls=list(normalized.get("image_urls") or []),
    )
    normalized["file_paths"] = _validate_and_normalize_draft_file_paths(
        user_id=user_id,
        file_paths=list(normalized.get("file_paths") or []),
    )
    normalized["unlock_price_cents"] = _validate_and_normalize_unlock_price(
        normalized.get("unlock_price_cents")
    )
    return normalized


def _build_file_attachments_for_post(*, user_id: str, file_paths: List[str]) -> List[Dict[str, Any]]:
    attachments: List[Dict[str, Any]] = []
    for idx, fp in enumerate(file_paths[:5]):
        try:
            node_path = norm_path(fp, is_folder=False)
            node = get_node(user_id, node_path)
        except HTTPException as exc:
            if exc.status_code in {400, 403, 404}:
                raise HTTPException(
                    status_code=422,
                    detail=f"Invalid attachment reference at file_paths[{idx}]: file is missing or not accessible",
                ) from exc
            raise
        attachments.append({
            "path": node_path,
            "name": node.get("name") or node_path.rsplit("/", 1)[-1],
            "content_type": node.get("content_type"),
            "size": int(node["size"]) if node.get("size") is not None else None,
            "owner": user_id,
        })
    return attachments


def _draft_payload_from_create(*, user_id: str, req: CreateDraftPostRequest) -> Dict[str, Any]:
    content = _content_from_payload(req)
    payload = {
        **content,
        "image_urls": list(req.image_urls or []),
        "file_paths": list(req.file_paths or []),
        "unlock_price_cents": req.unlock_price_cents,
    }
    return _validate_and_normalize_draft_payload(user_id=user_id, payload=payload)


def _draft_item_to_response(item: Dict[str, Any]) -> DraftPostResponse:
    payload = item.get("payload") if isinstance(item.get("payload"), dict) else {}
    return DraftPostResponse(
        draft_id=str(item.get("draft_id") or ""),
        author_id=str(item.get("author_id") or ""),
        created_at=str(item.get("created_at") or ""),
        updated_at=str(item.get("updated_at") or item.get("created_at") or ""),
        body=payload.get("body"),
        body_plain=payload.get("body_plain"),
        body_markdown=payload.get("body_markdown"),
        body_rich=payload.get("body_rich"),
        body_format=payload.get("body_format"),
        body_version=int(payload.get("body_version") or 1),
        image_urls=list(payload.get("image_urls") or []),
        file_paths=list(payload.get("file_paths") or []),
        unlock_price_cents=payload.get("unlock_price_cents"),
    )


def _get_draft_or_404(*, user_id: str, draft_id: str) -> Dict[str, Any]:
    item = ddb_get_item({"pk": pk_user(user_id), "sk": sk_draft(draft_id)})
    if not item or item.get("entity_type") != "draft_post":
        raise HTTPException(status_code=404, detail="Draft not found")
    if item.get("author_id") != user_id:
        # defensive: if key schema ever changes, keep ownership checks explicit
        raise HTTPException(status_code=404, detail="Draft not found")
    return item


def _unlock_request_fingerprint(
    *,
    post_id: str,
    payment_method_id: Optional[str],
    unlock_price_cents: Optional[int] = None,
    currency: str = "usd",
) -> str:
    payload = {
        "post_id": post_id,
        "payment_method_id": payment_method_id or "",
        "unlock_price_cents": int(unlock_price_cents or 0),
        "currency": currency.lower().strip(),
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _validate_unlock_attempt_idempotency(
    *,
    req_idempotency_key: Optional[str],
    req_request_fingerprint: Optional[str],
    unlock_attempt: Dict[str, Any],
) -> None:
    existing_idempotency_key = unlock_attempt.get("idempotency_key")
    if req_idempotency_key and existing_idempotency_key and existing_idempotency_key != req_idempotency_key:
        raise _unlock_idempotency_conflict_error()
    existing_request_fingerprint = unlock_attempt.get("request_fingerprint")
    if (
        req_idempotency_key
        and existing_idempotency_key == req_idempotency_key
        and req_request_fingerprint
        and existing_request_fingerprint
        and existing_request_fingerprint != req_request_fingerprint
    ):
        raise _unlock_idempotency_payload_mismatch_error()


def _begin_unlock_attempt(
    user_id: str,
    post_id: str,
    *,
    idempotency_key: Optional[str] = None,
    request_fingerprint: Optional[str] = None,
) -> Literal["new", "already_unlocked", "in_progress"]:
    key = {"pk": pk_unlock(user_id), "sk": f"POST#{post_id}"}
    try:
        tbl.put_item(
            Item={
                **key,
                "Entity": "Unlock",
                "user_id": user_id,
                "post_id": post_id,
                "unlocked": False,
                "in_progress": True,
                "updated_at": now_iso(),
                **({"idempotency_key": idempotency_key} if idempotency_key else {}),
                **({"request_fingerprint": request_fingerprint} if request_fingerprint else {}),
            },
            ConditionExpression="attribute_not_exists(pk) AND attribute_not_exists(sk)",
        )
        return "new"
    except ClientError as exc:
        code = exc.response["Error"].get("Code", "")
        if code != "ConditionalCheckFailedException":
            raise HTTPException(status_code=500, detail=f"DynamoDB error: {exc.response['Error'].get('Message','unknown')}") from exc
        existing = ddb_get_item(key) or {}
        _validate_unlock_attempt_idempotency(
            req_idempotency_key=idempotency_key,
            req_request_fingerprint=request_fingerprint,
            unlock_attempt=existing,
        )
        if bool(existing.get("unlocked")):
            return "already_unlocked"
        return "in_progress"


def _clear_unlock_attempt_if_not_unlocked(user_id: str, post_id: str) -> bool:
    try:
        tbl.delete_item(
            Key={"pk": pk_unlock(user_id), "sk": f"POST#{post_id}"},
            ConditionExpression="unlocked = :f",
            ExpressionAttributeValues={":f": False},
        )
        return True
    except ClientError:
        # Best-effort cleanup; a concurrent success should keep the record.
        return False


def _finalize_unlock_attempt_success(user_id: str, post_id: str, payment_intent_id: str) -> None:
    ddb_update_item(
        key={"pk": pk_unlock(user_id), "sk": f"POST#{post_id}"},
        update_expr="SET unlocked = :t, in_progress = :f, payment_intent_id = :pi, updated_at = :u",
        expr_vals={":t": True, ":f": False, ":pi": payment_intent_id, ":u": now_iso()},
    )


def _ddb_av_map(values: Dict[str, Any]) -> Dict[str, Any]:
    return {k: _ddb_type_serializer.serialize(v) for k, v in values.items()}


def _release_reserved_unlock_slot(post_id: str) -> None:
    try:
        tbl.update_item(
            Key={"pk": pk_post(post_id), "sk": sk_post()},
            UpdateExpression="SET unlock_count = unlock_count - :one",
            ConditionExpression="attribute_exists(unlock_count) AND unlock_count >= :one",
            ExpressionAttributeValues={":one": 1},
            ReturnValues="NONE",
        )
    except ClientError:
        # Best-effort compensation; reconciliation job handles residual drift.
        pass


def _unlock_attempt_is_stale(attempt: Dict[str, Any]) -> bool:
    if not attempt:
        return False
    if bool(attempt.get("unlocked")) or not bool(attempt.get("in_progress")):
        return False
    raw_updated_at = attempt.get("updated_at")
    if not raw_updated_at:
        return False
    try:
        updated = datetime.fromisoformat(str(raw_updated_at).replace("Z", "+00:00"))
        if updated.tzinfo is None:
            updated = updated.replace(tzinfo=timezone.utc)
    except Exception:
        return False
    stale_after_seconds = max(1, int(getattr(S, "newsfeed_unlock_attempt_stale_seconds", 300) or 300))
    return (datetime.now(timezone.utc) - updated).total_seconds() >= stale_after_seconds


def _recover_stale_unlock_attempt_if_needed(
    *,
    user_id: str,
    post_id: str,
    unlock_attempt: Dict[str, Any],
    unlock_limit_enabled: bool,
) -> bool:
    if not _unlock_attempt_is_stale(unlock_attempt):
        return False
    cleared = _clear_unlock_attempt_if_not_unlocked(user_id, post_id)
    if not cleared:
        return False
    if unlock_limit_enabled:
        _release_reserved_unlock_slot(post_id)
    _emit_unlock_lifecycle_event(
        "unlock_attempt_stale_recovered",
        user_id=user_id,
        post_id=post_id,
        reason_code="stale_in_progress_timeout",
    )
    return True


def _unlock_response_for_existing_attempt(
    *,
    post_id: str,
    req_idempotency_key: Optional[str],
    req_request_fingerprint: Optional[str],
    unlock_attempt: Dict[str, Any],
) -> UnlockPostResponse:
    _validate_unlock_attempt_idempotency(
        req_idempotency_key=req_idempotency_key,
        req_request_fingerprint=req_request_fingerprint,
        unlock_attempt=unlock_attempt,
    )
    existing_idempotency_key = unlock_attempt.get("idempotency_key")
    payment_intent: Dict[str, Any] = {"status": "already_unlocked"}
    if req_idempotency_key and existing_idempotency_key == req_idempotency_key:
        payment_intent = {
            "status": "succeeded",
            "payment_intent_id": unlock_attempt.get("payment_intent_id"),
            "replayed": True,
        }
    return UnlockPostResponse(post_id=post_id, payment_intent=payment_intent)


def _emit_unlock_idempotency_rejection(*, user_id: str, post_id: str, reason_code: str) -> None:
    _emit_unlock_lifecycle_event(
        "unlock_payment_failed",
        user_id=user_id,
        post_id=post_id,
        reason_code=reason_code,
        payment_status="idempotency_rejected",
    )


def _reserve_unlock_slot_or_raise(post_id: str, *, user_id: Optional[str] = None) -> None:
    try:
        tbl.update_item(
            Key={"pk": pk_post(post_id), "sk": sk_post()},
            UpdateExpression="SET unlock_count = if_not_exists(unlock_count, :z) + :one",
            ConditionExpression="attribute_not_exists(unlock_limit) OR attribute_not_exists(unlock_count) OR unlock_count < unlock_limit",
            ExpressionAttributeValues={":z": 0, ":one": 1},
            ReturnValues="NONE",
        )
    except ClientError as exc:
        code = exc.response["Error"].get("Code", "")
        if code == "ConditionalCheckFailedException":
            _emit_unlock_lifecycle_event(
                "unlock_limit_reached",
                user_id=user_id,
                post_id=post_id,
                reason_code="cap_reached_condition",
            )
            _notify_author_unlock_limit_reached_once(post_id=post_id, triggered_by_user_id=user_id)
            raise _unlock_limit_reached_error() from exc
        raise HTTPException(status_code=500, detail=f"DynamoDB error: {exc.response['Error'].get('Message','unknown')}") from exc


def _begin_unlock_attempt_with_reservation_fallback(
    user_id: str,
    post_id: str,
    *,
    idempotency_key: Optional[str] = None,
    request_fingerprint: Optional[str] = None,
) -> Literal["new", "already_unlocked", "in_progress"]:
    state = _begin_unlock_attempt(user_id, post_id, idempotency_key=idempotency_key, request_fingerprint=request_fingerprint)
    if state != "new":
        return state
    _reserve_unlock_slot_or_raise(post_id, user_id=user_id)
    return "new"


def _begin_unlock_attempt_with_reservation(
    user_id: str,
    post_id: str,
    *,
    idempotency_key: Optional[str] = None,
    request_fingerprint: Optional[str] = None,
) -> Literal["new", "already_unlocked", "in_progress"]:
    unlock_key = {"pk": pk_unlock(user_id), "sk": f"POST#{post_id}"}
    post_key = {"pk": pk_post(post_id), "sk": sk_post()}
    try:
        tbl.meta.client.transact_write_items(
            TransactItems=[
                {
                    "Update": {
                        "TableName": APP_TABLE,
                        "Key": _ddb_av_map(post_key),
                        "UpdateExpression": "SET unlock_count = if_not_exists(unlock_count, :z) + :one",
                        "ConditionExpression": "attribute_not_exists(unlock_limit) OR attribute_not_exists(unlock_count) OR unlock_count < unlock_limit",
                        "ExpressionAttributeValues": _ddb_av_map({":z": 0, ":one": 1}),
                    }
                },
                {
                    "Put": {
                        "TableName": APP_TABLE,
                        "Item": _ddb_av_map(
                            {
                                **unlock_key,
                                "Entity": "Unlock",
                                "user_id": user_id,
                                "post_id": post_id,
                                "unlocked": False,
                                "in_progress": True,
                                "updated_at": now_iso(),
                                **({"idempotency_key": idempotency_key} if idempotency_key else {}),
                                **({"request_fingerprint": request_fingerprint} if request_fingerprint else {}),
                            }
                        ),
                        "ConditionExpression": "attribute_not_exists(pk) AND attribute_not_exists(sk)",
                    }
                },
            ]
        )
        return "new"
    except ClientError as exc:
        code = exc.response["Error"].get("Code", "")
        if code == "TransactionCanceledException":
            existing = ddb_get_item(unlock_key) or {}
            if existing:
                _validate_unlock_attempt_idempotency(
                    req_idempotency_key=idempotency_key,
                    req_request_fingerprint=request_fingerprint,
                    unlock_attempt=existing,
                )
                if bool(existing.get("unlocked")):
                    return "already_unlocked"
                return "in_progress"
            _emit_unlock_lifecycle_event(
                "unlock_limit_reached",
                user_id=user_id,
                post_id=post_id,
                reason_code="cap_reached_transaction",
            )
            _notify_author_unlock_limit_reached_once(post_id=post_id, triggered_by_user_id=user_id)
            raise _unlock_limit_reached_error() from exc
        logger.warning("unlock transaction unavailable; using fallback path", extra={"post_id": post_id, "user_id": user_id, "error_code": code})
        return _begin_unlock_attempt_with_reservation_fallback(
            user_id,
            post_id,
            idempotency_key=idempotency_key,
            request_fingerprint=request_fingerprint,
        )


# -----------------------------
# Uploads (multipart POST + GET proxy)
# -----------------------------
_MAX_UPLOAD_BYTES = 10 * 1024 * 1024  # 10 MB


@router.post("/uploads/image")
async def upload_image(
    file: UploadFile = File(...),
    user_id: UserIdDep = None,
):
    ensure_uploads_enabled()
    if not (file.content_type or "").startswith("image/"):
        raise HTTPException(status_code=400, detail="Only image files are accepted")
    content = await file.read()
    if len(content) > _MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=400, detail="Image must be under 10 MB")
    attachment_id = new_id("att")
    safe_name = (file.filename or "upload.bin").replace("/", "_").replace("\\", "_")
    base_key = f"uploads/{user_id}/{attachment_id}"
    s3_key = f"{base_key}/{safe_name}"
    try:
        s3.put_object(Bucket=UPLOAD_BUCKET, Key=s3_key, Body=content, ContentType=file.content_type or "application/octet-stream")
    except ClientError as exc:
        raise HTTPException(status_code=500, detail=f"S3 error: {exc.response['Error'].get('Message','unknown')}") from exc
    encoded_key = quote(s3_key, safe="")
    url = f"/uploads/object?s3_key={encoded_key}"

    # PLATFORM-004: Generate and upload image variants
    variants: Dict[str, Any] = {}
    if S.image_optimization_enabled:
        try:
            from app.services.image_optimization import generate_variants
            variant_map = generate_variants(content, file.content_type or "image/jpeg")
            for vname, vdata in variant_map.items():
                vkey = f"{base_key}/{vname}.webp"
                s3.put_object(
                    Bucket=UPLOAD_BUCKET, Key=vkey,
                    Body=vdata["bytes"],
                    ContentType=vdata["content_type"],
                )
                variants[vname] = {
                    "url": f"/uploads/object?s3_key={quote(vkey, safe='')}",
                    "width": vdata["width"],
                    "height": vdata["height"],
                    "size_bytes": vdata["size_bytes"],
                }
        except Exception:
            logger.exception("Variant upload failed; serving original only")

    return {"url": url, "s3_key": s3_key, "variants": variants}


@router.get("/uploads/object")
def get_upload_object(s3_key: str = Query(...)):
    ensure_uploads_enabled()
    try:
        obj = s3.get_object(Bucket=UPLOAD_BUCKET, Key=s3_key)
    except ClientError as exc:
        raise HTTPException(status_code=404, detail="Not found") from exc
    content_type = obj.get("ContentType", "application/octet-stream")

    def _iter():
        for chunk in obj["Body"].iter_chunks(64 * 1024):
            if chunk:
                yield chunk

    # PLATFORM-004: Variants are immutable (keyed by attachment_id + size name)
    is_variant = any(s3_key.endswith(f"/{v}.webp") for v in ("sm", "md", "lg"))
    cache_control = (
        "public, max-age=31536000, immutable"
        if is_variant
        else "private, max-age=300"
    )
    return StreamingResponse(_iter(), media_type=content_type, headers={"Cache-Control": cache_control})


# -----------------------------
# Follow / Unfollow
# -----------------------------
@router.post("/social/unfollow")
def unfollow(req: UnfollowRequest, user_id: UserIdDep):
    from app.services.social import unfollow_user
    return unfollow_user(user_id, req.target_user_id)


@router.post("/social/refollow")
def refollow(req: UnfollowRequest, user_id: UserIdDep):
    from app.services.social import follow_user
    try:
        return follow_user(user_id, req.target_user_id)
    except ValueError:
        # Maintain backward compatibility — old endpoint didn't validate
        return {"ok": True}


# -----------------------------
# Posts
# -----------------------------
@router.post("/posts/drafts", response_model=DraftPostResponse)
def create_draft_post(req: CreateDraftPostRequest, user_id: UserIdDep):
    _ensure_drafts_feature_enabled(user_id)
    try:
        _enforce_draft_count_quota(user_id)
        draft_id = new_id("draft")
        payload = _draft_payload_from_create(user_id=user_id, req=req)
        _enforce_draft_payload_size(payload)
        item = build_draft_item(user_id=user_id, draft_id=draft_id, payload=payload)
        ddb_put_item(item)
        _emit_newsfeed_draft_metric("save_success", outcome="success", operation="create")
        return _draft_item_to_response(item)
    except ValueError as exc:
        _emit_newsfeed_draft_metric("save_fail", outcome="fail", operation="create", reason_code="validation_error")
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except HTTPException as exc:
        _emit_newsfeed_draft_metric("save_fail", outcome="fail", operation="create", reason_code=f"http_{exc.status_code}")
        raise


@router.get("/posts/drafts", response_model=ListDraftPostsResponse)
def list_draft_posts(
    user_id: UserIdDep,
    cursor: Optional[str] = Query(default=None),
    limit: int = Query(default=20, ge=1, le=100),
):
    _ensure_drafts_feature_enabled(user_id)
    query = build_draft_list_query(user_id=user_id, cursor=cursor, limit=limit)
    resp = ddb_query(**query)
    items = [_draft_item_to_response(it) for it in (resp.get("Items") or []) if it.get("entity_type") == "draft_post"]
    return ListDraftPostsResponse(items=items, next_cursor=encode_cursor(resp.get("LastEvaluatedKey")))


@router.get("/posts/drafts/{draft_id}", response_model=DraftPostResponse)
def get_draft_post(draft_id: str, user_id: UserIdDep):
    _ensure_drafts_feature_enabled(user_id)
    try:
        item = _get_draft_or_404(user_id=user_id, draft_id=draft_id)
        _emit_newsfeed_draft_metric("load_success", outcome="success")
        return _draft_item_to_response(item)
    except HTTPException as exc:
        _emit_newsfeed_draft_metric("load_fail", outcome="fail", reason_code=f"http_{exc.status_code}")
        raise


@router.patch("/posts/drafts/{draft_id}", response_model=DraftPostResponse)
def update_draft_post(draft_id: str, req: UpdateDraftPostRequest, user_id: UserIdDep):
    _ensure_drafts_feature_enabled(user_id)
    try:
        existing = _get_draft_or_404(user_id=user_id, draft_id=draft_id)
        _enforce_draft_expected_updated_at(
            expected_updated_at=req.expected_updated_at,
            existing_item=existing,
        )
        current_payload = existing.get("payload") if isinstance(existing.get("payload"), dict) else {}

        patch = req.model_dump(exclude_unset=True, exclude={"expected_updated_at"})
        merged: Dict[str, Any] = {**current_payload, **patch}

        # Validate merged content with create validator for parity with publish content rules.
        CreateDraftPostRequest(**merged)

        merged = _validate_and_normalize_draft_payload(user_id=user_id, payload=merged)
        _enforce_draft_payload_size(merged)

        updated_at = now_iso()
        item = build_draft_item(
            user_id=user_id,
            draft_id=draft_id,
            payload=merged,
            created_at=str(existing.get("created_at") or updated_at),
            updated_at=updated_at,
        )
        ddb_put_item(item)
        _emit_newsfeed_draft_metric("save_success", outcome="success", operation="update")
        return _draft_item_to_response(item)
    except ValueError as exc:
        _emit_newsfeed_draft_metric("save_fail", outcome="fail", operation="update", reason_code="validation_error")
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except HTTPException as exc:
        _emit_newsfeed_draft_metric("save_fail", outcome="fail", operation="update", reason_code=f"http_{exc.status_code}")
        raise


@router.delete("/posts/drafts/{draft_id}")
def delete_draft_post(
    draft_id: str,
    user_id: UserIdDep,
    expected_updated_at: Optional[str] = Query(default=None),
):
    _ensure_drafts_feature_enabled(user_id)
    try:
        existing = _get_draft_or_404(user_id=user_id, draft_id=draft_id)
        _enforce_draft_expected_updated_at(
            expected_updated_at=expected_updated_at,
            existing_item=existing,
        )
        ddb_delete_item({"pk": pk_user(user_id), "sk": sk_draft(draft_id)})
        _emit_newsfeed_draft_metric("delete_success", outcome="success")
        return {"ok": True}
    except HTTPException as exc:
        _emit_newsfeed_draft_metric("delete_fail", outcome="fail", reason_code=f"http_{exc.status_code}")
        raise


@router.post("/posts/drafts/{draft_id}/publish", response_model=PostResponse)
def publish_draft_post(
    draft_id: str,
    req: PublishDraftPostRequest,
    user_id: UserIdDep,
):
    _ensure_drafts_feature_enabled(user_id)
    try:
        draft_item = _get_draft_or_404(user_id=user_id, draft_id=draft_id)
        _enforce_draft_expected_updated_at(
            expected_updated_at=req.expected_updated_at,
            existing_item=draft_item,
        )
        payload = draft_item.get("payload") if isinstance(draft_item.get("payload"), dict) else {}
        if not payload:
            raise HTTPException(status_code=422, detail="Draft payload is empty")

        payload = _validate_and_normalize_draft_payload(user_id=user_id, payload=payload)
    except ValueError as exc:
        _emit_newsfeed_draft_metric("publish_from_draft", outcome="fail", reason_code="attachment_validation_error")
        raise HTTPException(status_code=422, detail=f"Invalid draft attachment reference: {exc}") from exc
    except HTTPException as exc:
        _emit_newsfeed_draft_metric("publish_from_draft", outcome="fail", reason_code=f"http_{exc.status_code}")
        raise

    try:
        post_req = CreatePostRequest(**payload)
    except ValidationError as exc:
        _emit_newsfeed_draft_metric("publish_from_draft", outcome="fail", reason_code="payload_validation_error")
        raise HTTPException(status_code=422, detail=f"Invalid draft payload: {exc.errors()}") from exc

    published = create_post(post_req, user_id)
    _emit_newsfeed_draft_metric("publish_from_draft", outcome="success")

    if not req.keep_copy:
        try:
            ddb_delete_item({"pk": pk_user(user_id), "sk": sk_draft(draft_id)})
        except Exception:
            logger.exception("draft cleanup failed after publish", extra={"user_id": user_id, "draft_id": draft_id})

    return published


@router.post(
    "/posts",
    response_model=PostResponse,
    responses={
        400: {
            "description": "Invalid schedule payload",
            "content": {
                "application/json": {
                    "examples": {
                        "invalid_timezone": {
                            "summary": "Invalid IANA timezone",
                            "value": {
                                "detail": {
                                    "code": "schedule_timezone_invalid",
                                    "message": "schedule_timezone must be a valid IANA timezone",
                                    "field": "schedule_timezone",
                                }
                            },
                        },
                        "publish_at_too_soon": {
                            "summary": "Publish time must be in the future",
                            "value": {
                                "detail": {
                                    "code": "schedule_publish_at_too_soon",
                                    "message": "publish_at must be at least 5 seconds in the future",
                                    "field": "publish_at",
                                    "minimum_publish_at": 1767000006,
                                }
                            },
                        },
                    }
                }
            },
        }
    },
)
def create_post(req: CreatePostRequest, user_id: UserIdDep):
    """
    Create a newsfeed post immediately or schedule it for later publication.

    Immediate create (no `publish_at`) publishes now and appears in the feed.
    Scheduled create (with `publish_at`) persists with `status=scheduled` and is excluded from feed until publish time.
    """
    unlock_limit_feature_on = _is_unlock_limit_enabled_for_user(user_id)
    unlock_price_cents = req.unlock_price_cents if req.unlock_price_cents and req.unlock_price_cents > 0 else None
    locked = unlock_price_cents is not None
    if req.unlock_limit is not None and not unlock_limit_feature_on:
        raise _unlock_limit_validation_error(
            "unlock_limit_feature_disabled",
            "unlock_limit is not enabled for this account",
        )
    if req.unlock_limit is not None and not locked:
        raise _unlock_limit_validation_error(
            "unlock_limit_requires_locked_post",
            "unlock_limit can only be set for locked posts",
        )
    unlock_limit = req.unlock_limit if locked else None
    _enforce_newsfeed_post_quota_precheck(user_id=user_id)
    post_id = new_id("post")
    created_at = now_iso()
    now_ts = int(time.time())

    has_schedule_metadata = bool(req.schedule_timezone or req.scheduled_at_local)
    if req.publish_at is not None or has_schedule_metadata:
        _require_newsfeed_scheduling_api_enabled()
    if req.publish_at is None and has_schedule_metadata:
        raise _schedule_payload_error(
            code="schedule_publish_at_required",
            field="publish_at",
            message="publish_at is required when schedule_timezone or scheduled_at_local is provided",
            operation="create",
        )

    is_scheduled = req.publish_at is not None
    if is_scheduled:
        min_lead = _schedule_min_lead_seconds()
        max_horizon = _schedule_max_horizon_seconds()
        max_publish_at = now_ts + max_horizon
        if req.publish_at is None or req.publish_at <= now_ts + min_lead:
            raise _schedule_payload_error(
                code="schedule_publish_at_too_soon",
                field="publish_at",
                message=f"publish_at must be at least {min_lead} seconds in the future",
                extra={"minimum_publish_at": now_ts + min_lead + 1},
                operation="create",
            )
        if int(req.publish_at) > max_publish_at:
            raise _schedule_payload_error(
                code="schedule_publish_at_too_far",
                field="publish_at",
                message=f"publish_at must be within {max_horizon} seconds from now",
                extra={"maximum_publish_at": max_publish_at},
                operation="create",
            )
        if not req.schedule_timezone:
            raise _schedule_payload_error(
                code="schedule_timezone_required",
                field="schedule_timezone",
                message="schedule_timezone is required when publish_at is set",
                operation="create",
            )
        try:
            ZoneInfo(req.schedule_timezone)
        except Exception as exc:
            raise _schedule_payload_error(
                code="schedule_timezone_invalid",
                field="schedule_timezone",
                message="schedule_timezone must be a valid IANA timezone",
                operation="create",
            ) from exc
        if req.scheduled_at_local and not _SCHEDULED_LOCAL_RE.fullmatch(req.scheduled_at_local):
            raise _schedule_payload_error(
                code="schedule_local_datetime_invalid",
                field="scheduled_at_local",
                message="scheduled_at_local must use format YYYY-MM-DDTHH:mm",
                operation="create",
            )

    requested_lock_type = req.lock_type
    unlock_price_cents = req.unlock_price_cents if req.unlock_price_cents and req.unlock_price_cents > 0 else None
    has_lottery_fields = any(
        value is not None
        for value in (
            req.lottery_tip_cents,
            req.lottery_quiet_period_seconds,
            req.lottery_state,
            req.lottery_last_tip_at,
            req.lottery_last_tipper_user_id,
            req.lottery_winner_user_id,
            req.lottery_won_at,
            req.lottery_version,
        )
    )
    lock_type: Optional[str] = None
    lottery_tip_cents: Optional[int] = None
    lottery_quiet_period_seconds: Optional[int] = None
    lottery_state: Optional[str] = None
    lottery_last_tip_at: Optional[str] = None
    lottery_last_tipper_user_id: Optional[str] = None
    lottery_winner_user_id: Optional[str] = None
    lottery_won_at: Optional[str] = None
    lottery_version: Optional[int] = None

    if requested_lock_type == "tip_lottery":
        if not bool(getattr(S, "newsfeed_tip_lottery_enabled", True)):
            _emit_newsfeed_lock_validation_reject(
                "tip_lottery_feature_disabled",
                lock_type=requested_lock_type,
                has_unlock_price=unlock_price_cents is not None,
                has_lottery_fields=has_lottery_fields,
            )
            raise HTTPException(status_code=403, detail="tip_lottery lock strategy is disabled")
        if unlock_price_cents is not None:
            _emit_newsfeed_lock_validation_reject(
                "tip_lottery_with_unlock_price",
                lock_type=requested_lock_type,
                has_unlock_price=True,
                has_lottery_fields=has_lottery_fields,
            )
            raise HTTPException(status_code=400, detail="unlock_price_cents is not allowed for tip_lottery lock type")
        if req.lottery_tip_cents is None or req.lottery_quiet_period_seconds is None:
            _emit_newsfeed_lock_validation_reject(
                "tip_lottery_missing_required_fields",
                lock_type=requested_lock_type,
                has_unlock_price=False,
                has_lottery_fields=has_lottery_fields,
            )
            raise HTTPException(status_code=400, detail="lottery_tip_cents and lottery_quiet_period_seconds are required for tip_lottery")
        lock_type = "tip_lottery"
        lottery_tip_cents = int(req.lottery_tip_cents)
        lottery_quiet_period_seconds = int(req.lottery_quiet_period_seconds)
        lottery_state = req.lottery_state or "open"
        lottery_last_tip_at = req.lottery_last_tip_at
        lottery_last_tipper_user_id = req.lottery_last_tipper_user_id
        lottery_winner_user_id = req.lottery_winner_user_id
        lottery_won_at = req.lottery_won_at
        lottery_version = int(req.lottery_version or 0)
    elif requested_lock_type == "fixed_price":
        if unlock_price_cents is None:
            _emit_newsfeed_lock_validation_reject(
                "fixed_price_missing_unlock_price",
                lock_type=requested_lock_type,
                has_unlock_price=False,
                has_lottery_fields=has_lottery_fields,
            )
            raise HTTPException(status_code=400, detail="unlock_price_cents must be positive when lock_type is fixed_price")
        if has_lottery_fields:
            _emit_newsfeed_lock_validation_reject(
                "fixed_price_with_lottery_fields",
                lock_type=requested_lock_type,
                has_unlock_price=True,
                has_lottery_fields=has_lottery_fields,
            )
            raise HTTPException(status_code=400, detail="lottery_* fields are not allowed when lock_type is fixed_price")
        lock_type = "fixed_price"
    elif requested_lock_type is None and has_lottery_fields:
        _emit_newsfeed_lock_validation_reject(
            "lottery_fields_without_lock_type",
            lock_type=requested_lock_type,
            has_unlock_price=unlock_price_cents is not None,
            has_lottery_fields=True,
        )
        raise HTTPException(status_code=400, detail="lock_type must be tip_lottery when lottery_* fields are provided")
    elif unlock_price_cents is not None:
        lock_type = "fixed_price"

    locked = lock_type is not None

    # --- Video validation (FEED-001) ---
    video_id = getattr(req, "video_id", None)
    if video_id:
        if req.image_urls:
            raise HTTPException(status_code=400, detail="video_id and image_urls are mutually exclusive; provide one or the other")
        from app.services.video_metadata_store import get_video as _feed_get_video
        try:
            _vid_record = _feed_get_video(video_id)
        except HTTPException:
            raise HTTPException(status_code=400, detail="video not found")
        if _vid_record.owner_user_id != user_id:
            raise HTTPException(status_code=403, detail="video is not owned by this user")
        if _vid_record.status != "published":
            raise HTTPException(status_code=400, detail="video must be in published status to attach to a post")

    # --- ENGAGE-002: Poll/Survey validation ---
    req_post_type = getattr(req, "post_type", None) or "standard"
    poll_data_built = None
    poll_vote_counts_init = None
    if req_post_type in ("poll", "survey"):
        if not getattr(S, "newsfeed_polls_enabled", True):
            raise HTTPException(status_code=403, detail="Polls are disabled")
        if not req.poll_data:
            raise HTTPException(status_code=400, detail="poll_data is required for poll/survey posts")
        from app.services.newsfeed_polls import create_poll_data, build_initial_vote_counts
        raw_questions = [q.model_dump() for q in req.poll_data.questions]
        poll_data_built = create_poll_data(
            questions=raw_questions,
            closes_at=req.poll_data.closes_at,
            anonymous=req.poll_data.anonymous,
            allow_vote_change=req.poll_data.allow_vote_change,
        )
        poll_vote_counts_init = build_initial_vote_counts(poll_data_built)

    # --- FEED-005: Countdown post validation ---
    post_kind = getattr(req, "post_kind", None) or "text"
    countdown_title: Optional[str] = None
    target_datetime: Optional[int] = None
    associated_event_type: Optional[str] = None
    associated_event_id: Optional[str] = None
    if post_kind == "countdown":
        if not bool(getattr(S, "countdown_posts_enabled", True)):
            raise HTTPException(status_code=403, detail="Countdown posts are disabled")
        if not req.countdown_title:
            raise HTTPException(status_code=400, detail="countdown_title required for countdown posts")
        if req.target_datetime is None or int(req.target_datetime) <= now_ts:
            raise HTTPException(status_code=400, detail="target_datetime must be in the future")
        if req.associated_event_type and req.associated_event_type != "custom" and not req.associated_event_id:
            raise HTTPException(status_code=400, detail="associated_event_id required for non-custom events")
        countdown_title = req.countdown_title
        target_datetime = int(req.target_datetime)
        associated_event_type = req.associated_event_type
        associated_event_id = req.associated_event_id

    content = _content_from_payload(req)
    _emit_newsfeed_content_metric(
        "create_post",
        surface="post",
        body_format=content.get("body_format", "plain"),
        lock_type=lock_type or "none",
    )

    # SOCIAL-006: Extract and merge hashtags
    explicit_tags = _normalize_tags(req.tags or [])
    body_plain_text = content.get("body_plain") or content.get("body") or ""
    body_tags = _extract_hashtags(body_plain_text)
    all_tags = list(dict.fromkeys(explicit_tags + body_tags))[:_MAX_TAGS_PER_POST]

    # Validate and collect file attachment metadata (max 5)
    file_attachments = _build_file_attachments_for_post(user_id=user_id, file_paths=req.file_paths)

    post_item = {
        "pk": pk_post(post_id),
        "sk": sk_post(),
        "Entity": "Post",
        "post_id": post_id,
        "user_id": user_id,
        "created_at": created_at,
        "published_at": None if is_scheduled else created_at,
        "status": "scheduled" if is_scheduled else "published",
        "publish_at": req.publish_at if is_scheduled else None,
        "schedule_timezone": req.schedule_timezone if is_scheduled else None,
        "scheduled_at_local": req.scheduled_at_local if is_scheduled else None,
        "GSI2PK": f"POST_AUTHOR#{user_id}",
        "GSI2SK": f"{created_at}#POST#{post_id}",
        **content,
        "image_urls": req.image_urls,
        "image_variants": list(getattr(req, "image_variants", None) or []),
        "video_id": video_id,
        "visibility": req.visibility,
        "locked": locked,
        "lock_type": lock_type,
        "unlock_price_cents": unlock_price_cents,
        "lottery_tip_cents": lottery_tip_cents,
        "lottery_quiet_period_seconds": lottery_quiet_period_seconds,
        "lottery_state": lottery_state,
        "lottery_last_tip_at": lottery_last_tip_at,
        "lottery_last_tipper_user_id": lottery_last_tipper_user_id,
        "lottery_winner_user_id": lottery_winner_user_id,
        "lottery_won_at": lottery_won_at,
        "lottery_version": lottery_version,
        "like_count": 0,
        "comment_count": 0,
        "file_attachments": file_attachments,
        "tags": all_tags,
        "allow_ads_near": req.allow_ads_near,
        "body_plain_lc": (content.get("body_plain") or content.get("body") or "").lower(),
    }
    # FEED-005: persist countdown fields (additive; only for countdown posts)
    if post_kind == "countdown":
        post_item["post_kind"] = "countdown"
        post_item["countdown_title"] = countdown_title
        post_item["target_datetime"] = target_datetime
        post_item["associated_event_type"] = associated_event_type
        post_item["associated_event_id"] = associated_event_id
    # ENGAGE-002: Attach poll data to post item
    if req_post_type in ("poll", "survey") and poll_data_built:
        post_item["post_type"] = req_post_type
        post_item["poll_data"] = poll_data_built
        post_item["poll_votes"] = {}
        post_item["poll_vote_counts"] = poll_vote_counts_init or {}
        post_item["poll_total_votes"] = 0
        # Initialize nested vote maps for each question/option
        for q in poll_data_built.get("questions", []):
            qid = q["question_id"]
            post_item["poll_votes"][qid] = {}
            for opt in q.get("options", []):
                post_item["poll_votes"][qid][opt["option_id"]] = {}
    if unlock_limit is not None:
        post_item["unlock_limit"] = unlock_limit
        post_item["unlock_count"] = 0
    if is_scheduled:
        post_item.update(schedule_due_index_values(req.publish_at or 0, post_id))
    ddb_put_item(post_item)

    # SOCIAL-006: Write tag index items
    if all_tags and not is_scheduled:
        try:
            _write_tag_index(post_id=post_id, user_id=user_id, created_at=created_at, tags=all_tags)
        except Exception:
            logger.warning("Failed to write tag index for post %s", post_id)

    # SOC-005: maintain post_count on profile
    if not is_scheduled:
        try:
            from app.core.tables import T as _T
            _T.profile.update_item(
                Key={"user_sub": user_id},
                UpdateExpression="ADD post_count :one",
                ExpressionAttributeValues={":one": 1},
            )
        except Exception:
            logger.warning("Failed to increment post_count for %s", user_id)

    if not is_scheduled:
        _write_feed_ref_for_published_post(user_id=user_id, post_id=post_id, created_at=created_at)
        try:
            from app.services.newsfeed_fanout import fan_out_post_to_followers
            fan_out_post_to_followers(author_id=user_id, post_id=post_id, created_at=created_at)
        except Exception:
            logger.exception("Fan-out failed for post %s by %s", post_id, user_id)
        _meter_newsfeed_post_publish(user_id=user_id, post_id=post_id)
        # GAP-0162: achievement progress hooks (no-op unless ACHIEVEMENTS_ENABLED)
        try:
            from app.services.achievement_progress import advance_progress, update_streak
            advance_progress(user_id, "post_count")
            update_streak(user_id, "posting_streak")
        except Exception:
            logger.debug("achievement hook: post_count/posting_streak", exc_info=True)
        # GAP-0337: analytics instrumentation (engagement). Best-effort; the
        # service swallows its own errors but we guard the call site too so an
        # analytics failure can never break post creation.
        try:
            record_engagement_event(
                creator_id=user_id,
                content_id=post_id,
                actor_id=user_id,
                action="share",
            )
        except Exception:
            logger.debug("analytics hook: create_post engagement", exc_info=True)
        # GAP-0356: emit mention alerts for @mentions in the post body.
        # Skipped for scheduled posts (handled above by the if not is_scheduled
        # guard) and for empty bodies. Best-effort: a mention-alert failure must
        # never break post creation.
        if body_plain_text:
            try:
                emit_mention_alerts(
                    text=body_plain_text,
                    author_user_id=user_id,
                    author_display_name=_post_fadt_display_name(user_id),
                    context_type="post",
                    context_id=post_id,
                    post_id=post_id,
                )
            except Exception:
                logger.warning("emit_mention_alerts failed for post %s", post_id, exc_info=True)
    else:
        record_newsfeed_schedule_operation(operation="create", outcome="success")
        _write_scheduled_post_ref(
            user_id=user_id,
            post_id=post_id,
            created_at=created_at,
            publish_at=req.publish_at or 0,
            schedule_timezone=req.schedule_timezone,
            scheduled_at_local=req.scheduled_at_local,
        )

    return PostResponse(
        post_id=post_id,
        author_id=user_id,
        created_at=created_at,
        published_at=None if is_scheduled else created_at,
        status="scheduled" if is_scheduled else "published",
        publish_at=req.publish_at if is_scheduled else None,
        schedule_timezone=req.schedule_timezone if is_scheduled else None,
        scheduled_at_local=req.scheduled_at_local if is_scheduled else None,
        body=content["body"],
        body_plain=content["body_plain"],
        body_markdown=content["body_markdown"],
        body_markdown_html=content["body_markdown_html"],
        body_rich=content["body_rich"],
        body_format=content["body_format"],
        body_version=content["body_version"],
        image_urls=req.image_urls,
        tags=all_tags,
        video=None,
        visibility=req.visibility,
        locked=locked,
        lock_type=lock_type,
        unlock_price_cents=unlock_price_cents,
        unlock_limit=unlock_limit,
        unlock_count=0,
        unlock_limit_reached=False,
        lottery_tip_cents=lottery_tip_cents,
        lottery_quiet_period_seconds=lottery_quiet_period_seconds,
        lottery_state=lottery_state,
        lottery_last_tip_at=lottery_last_tip_at,
        lottery_last_tipper_user_id=lottery_last_tipper_user_id,
        lottery_winner_user_id=lottery_winner_user_id,
        lottery_won_at=lottery_won_at,
        lottery_version=lottery_version,
        like_count=0,
        comment_count=0,
        allow_ads_near=req.allow_ads_near,
        post_type=req_post_type,
        poll_data=poll_data_built if poll_data_built else None,
        poll_vote_counts=poll_vote_counts_init if poll_vote_counts_init else None,
        poll_my_votes=None,
        post_kind=post_kind,
        countdown_title=countdown_title,
        target_datetime=target_datetime,
        associated_event_type=associated_event_type,
        associated_event_id=associated_event_id,
    )


@router.get(
    "/posts/scheduled",
    response_model=ScheduledPostsResponse,
)
def list_scheduled_posts(
    limit: int = Query(default=20, ge=1, le=50),
    cursor: Optional[str] = Query(default=None),
    user_id: UserIdDep = None,
):
    """List caller-owned scheduled posts in stable publish-time order (oldest scheduled publish first)."""
    _require_newsfeed_scheduling_api_enabled()
    eks = decode_cursor_or_400(cursor)
    resp = ddb_query(
        KeyConditionExpression="pk = :pk AND begins_with(sk, :prefix)",
        ExpressionAttributeValues={
            ":pk": pk_user(user_id),
            ":prefix": f"{SCHEDULED_POST_REF_PREFIX}#",
        },
        ScanIndexForward=True,
        Limit=limit,
        ExclusiveStartKey=eks if eks else None,
    )
    refs = resp.get("Items", [])
    parsed_refs: List[Tuple[int, str]] = []
    for ref in refs:
        post_id = str(ref.get("post_id") or "").strip()
        parsed = parse_scheduled_post_ref_sk(str(ref.get("sk") or ""))
        if not post_id or parsed is None:
            continue
        publish_at, parsed_post_id = parsed
        if parsed_post_id != post_id:
            continue
        parsed_refs.append((publish_at, post_id))

    parsed_refs.sort(key=lambda row: (row[0], row[1]))
    post_ids = [post_id for _publish_at, post_id in parsed_refs]
    posts: List[Dict[str, Any]] = []
    if post_ids:
        keys = [{"pk": pk_post(pid), "sk": sk_post()} for pid in post_ids]
        try:
            raw = ddb.batch_get_item(RequestItems={APP_TABLE: {"Keys": keys}})
            posts = raw.get("Responses", {}).get(APP_TABLE, [])
        except ClientError as exc:
            raise HTTPException(
                status_code=500,
                detail=f"DDB batch_get_item error: {exc.response['Error'].get('Message','unknown')}",
            ) from exc

    post_by_id = {post.get("post_id"): post for post in posts if post.get("post_id")}
    ordered: List[Dict[str, Any]] = []
    for _publish_at, post_id in parsed_refs:
        post = post_by_id.get(post_id)
        if not post:
            continue
        if post.get("user_id") != user_id:
            continue
        if str(post.get("status") or "").strip().lower() != "scheduled":
            continue
        ordered.append(_post_to_dict(post, viewer_id=user_id))

    return {"items": ordered, "next_cursor": encode_cursor(resp.get("LastEvaluatedKey"))}


@router.patch("/posts/{post_id}")
def edit_post(post_id: str, req: EditPostRequest, user_id: UserIdDep):
    post = ddb_get_item({"pk": pk_post(post_id), "sk": sk_post()})
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
    if post.get("user_id") != user_id:
        raise HTTPException(status_code=403, detail="Not your post")
    unlock_limit_in_payload = "unlock_limit" in req.model_fields_set
    if unlock_limit_in_payload:
        if not _is_unlock_limit_enabled_for_user(user_id):
            raise _unlock_limit_validation_error(
                "unlock_limit_feature_disabled",
                "unlock_limit is not enabled for this account",
            )
        if not bool(post.get("locked")):
            raise _unlock_limit_validation_error(
                "unlock_limit_requires_locked_post",
                "unlock_limit can only be set for locked posts",
            )
        current_unlock_count = max(0, int(post.get("unlock_count", 0)))
        if req.unlock_limit is not None and req.unlock_limit < current_unlock_count:
            raise _unlock_limit_validation_error(
                "unlock_limit_below_unlock_count",
                "unlock_limit cannot be lower than current unlock_count",
            )
    content = _content_from_payload(req)
    _emit_newsfeed_content_metric("edit_post", surface="post", body_format=content.get("body_format", "plain"))
    schedule_fields_in_payload = bool({"publish_at", "schedule_timezone", "scheduled_at_local"} & req.model_fields_set)
    if schedule_fields_in_payload:
        _require_newsfeed_scheduling_api_enabled()
    schedule_updates: Dict[str, Any] = {}
    if schedule_fields_in_payload:
        if str(post.get("status") or "").strip().lower() != "scheduled":
            record_newsfeed_schedule_operation(operation="edit", outcome="rejected")
            raise HTTPException(
                status_code=409,
                detail={
                    "code": "schedule_update_not_allowed",
                    "message": "schedule metadata can only be updated for scheduled posts",
                },
            )
        now_ts = int(time.time())
        min_lead = _schedule_min_lead_seconds()
        max_horizon = _schedule_max_horizon_seconds()
        max_publish_at = now_ts + max_horizon
        publish_at = req.publish_at if "publish_at" in req.model_fields_set else post.get("publish_at")
        schedule_timezone = req.schedule_timezone if "schedule_timezone" in req.model_fields_set else post.get("schedule_timezone")
        scheduled_at_local = req.scheduled_at_local if "scheduled_at_local" in req.model_fields_set else post.get("scheduled_at_local")

        if publish_at is None or int(publish_at) <= now_ts + min_lead:
            raise _schedule_payload_error(
                code="schedule_publish_at_too_soon",
                field="publish_at",
                message=f"publish_at must be at least {min_lead} seconds in the future",
                extra={"minimum_publish_at": now_ts + min_lead + 1},
                operation="edit",
            )
        if int(publish_at) > max_publish_at:
            raise _schedule_payload_error(
                code="schedule_publish_at_too_far",
                field="publish_at",
                message=f"publish_at must be within {max_horizon} seconds from now",
                extra={"maximum_publish_at": max_publish_at},
                operation="edit",
            )
        if not schedule_timezone:
            raise _schedule_payload_error(
                code="schedule_timezone_required",
                field="schedule_timezone",
                message="schedule_timezone is required when updating schedule metadata",
                operation="edit",
            )
        try:
            ZoneInfo(str(schedule_timezone))
        except Exception as exc:
            raise _schedule_payload_error(
                code="schedule_timezone_invalid",
                field="schedule_timezone",
                message="schedule_timezone must be a valid IANA timezone",
                operation="edit",
            ) from exc
        if scheduled_at_local is not None and (not isinstance(scheduled_at_local, str) or not _SCHEDULED_LOCAL_RE.fullmatch(scheduled_at_local)):
            raise _schedule_payload_error(
                code="schedule_local_datetime_invalid",
                field="scheduled_at_local",
                message="scheduled_at_local must use format YYYY-MM-DDTHH:mm",
                operation="edit",
            )
        schedule_updates = {
            "publish_at": int(publish_at),
            "schedule_timezone": str(schedule_timezone),
            "scheduled_at_local": scheduled_at_local,
        }

    image_urls_in_payload = "image_urls" in req.model_fields_set
    set_parts = [
        "#body = :b",
        "body_plain = :bp",
        "body_markdown = :bm",
        "body_markdown_html = :bmh",
        "body_rich = :br",
        "body_format = :bf",
        "body_version = :bv",
        "updated_at = :u",
    ]
    remove_parts: List[str] = []
    expr_vals: Dict[str, Any] = {
        ":b": content["body"],
        ":bp": content["body_plain"],
        ":bm": content["body_markdown"],
        ":bmh": content["body_markdown_html"],
        ":br": content["body_rich"],
        ":bf": content["body_format"],
        ":bv": content["body_version"],
        ":u": now_iso(),
    }
    if schedule_updates:
        set_parts.extend(
            [
                "publish_at = :pa",
                "schedule_timezone = :stz",
                "scheduled_at_local = :sal",
                f"{SCHEDULE_DUE_INDEX_PK_ATTR} = :sdpk",
                f"{SCHEDULE_DUE_INDEX_SK_ATTR} = :sdsk",
            ]
        )
        expr_vals[":pa"] = schedule_updates["publish_at"]
        expr_vals[":stz"] = schedule_updates["schedule_timezone"]
        expr_vals[":sal"] = schedule_updates["scheduled_at_local"]
        due_values = schedule_due_index_values(schedule_updates["publish_at"], post_id)
        expr_vals[":sdpk"] = due_values[SCHEDULE_DUE_INDEX_PK_ATTR]
        expr_vals[":sdsk"] = due_values[SCHEDULE_DUE_INDEX_SK_ATTR]

    if image_urls_in_payload:
        if req.image_urls:
            set_parts.append("image_urls = :imgs")
            expr_vals[":imgs"] = req.image_urls
        else:
            remove_parts.append("image_urls")
    if unlock_limit_in_payload:
        if req.unlock_limit is not None:
            set_parts.append("unlock_limit = :unlock_limit")
            expr_vals[":unlock_limit"] = req.unlock_limit
        else:
            remove_parts.append("unlock_limit")
    update_expr = f"SET {', '.join(set_parts)}"
    if remove_parts:
        update_expr = f"{update_expr} REMOVE {', '.join(remove_parts)}"
    if schedule_updates:
        condition_expr = "#user = :uid AND #status = :scheduled"
        expr_vals_tx = dict(expr_vals)
        expr_vals_tx[":uid"] = user_id
        expr_vals_tx[":scheduled"] = "scheduled"

        old_publish_at = int(post.get("publish_at") or 0)
        old_ref_sk = sk_scheduled_post_ref(old_publish_at, post_id)
        new_ref_sk = sk_scheduled_post_ref(int(schedule_updates["publish_at"]), post_id)
        transact_items: List[Dict[str, Any]] = [
            {
                "Update": {
                    "TableName": APP_TABLE,
                    "Key": _ddb_serialize_map({"pk": pk_post(post_id), "sk": sk_post()}),
                    "UpdateExpression": update_expr,
                    "ExpressionAttributeNames": {"#body": "body", "#status": "status", "#user": "user_id"},
                    "ExpressionAttributeValues": _ddb_serialize_map(expr_vals_tx),
                    "ConditionExpression": condition_expr,
                }
            }
        ]
        if old_ref_sk != new_ref_sk:
            transact_items.append(
                {
                    "Delete": {
                        "TableName": APP_TABLE,
                        "Key": _ddb_serialize_map({"pk": pk_user(user_id), "sk": old_ref_sk}),
                    }
                }
            )
            transact_items.append(
                {
                    "Put": {
                        "TableName": APP_TABLE,
                        "Item": _ddb_serialize_map(
                            {
                                "pk": pk_user(user_id),
                                "sk": new_ref_sk,
                                "Entity": "ScheduledPostRef",
                                "post_id": post_id,
                                "owner_user_id": user_id,
                                "status": "scheduled",
                                "publish_at": int(schedule_updates["publish_at"]),
                                "schedule_timezone": schedule_updates["schedule_timezone"],
                                "scheduled_at_local": schedule_updates.get("scheduled_at_local"),
                                "created_at": post.get("created_at") or now_iso(),
                            }
                        ),
                    }
                }
            )
        try:
            ddb.meta.client.transact_write_items(TransactItems=transact_items)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "TransactionCanceledException":
                record_newsfeed_schedule_operation(operation="edit", outcome="conflict")
                raise HTTPException(
                    status_code=409,
                    detail={
                        "code": "schedule_edit_conflict",
                        "message": "schedule update conflicted with concurrent modification",
                    },
                ) from exc
            record_newsfeed_schedule_operation(operation="edit", outcome="error")
            raise HTTPException(status_code=500, detail=f"DynamoDB error: {exc.response['Error'].get('Message','unknown')}") from exc
        updated = ddb_get_item({"pk": pk_post(post_id), "sk": sk_post()}) or {}
        record_newsfeed_schedule_operation(operation="edit", outcome="success")
    else:
        updated = ddb_update_item(
            key={"pk": pk_post(post_id), "sk": sk_post()},
            update_expr=update_expr,
            expr_names={"#body": "body"},
            expr_vals=expr_vals,
        )
    return _post_to_dict(updated, viewer_id=user_id)


@router.post("/posts/{post_id}/cancel")
def cancel_scheduled_post(post_id: str, user_id: UserIdDep):
    _require_newsfeed_scheduling_api_enabled()
    post = ddb_get_item({"pk": pk_post(post_id), "sk": sk_post()})
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
    if post.get("user_id") != user_id:
        raise HTTPException(status_code=403, detail="Not your post")

    status = str(post.get("status") or "").strip().lower()
    if status == "cancelled":
        record_newsfeed_schedule_operation(operation="cancel", outcome="noop")
        return _post_to_dict(post, viewer_id=user_id)
    if status != "scheduled":
        record_newsfeed_schedule_operation(operation="cancel", outcome="rejected")
        raise HTTPException(
            status_code=409,
            detail={
                "code": "schedule_cancel_not_allowed",
                "message": "only scheduled posts can be cancelled",
            },
        )

    publish_at = post.get("publish_at")
    try:
        publish_at_int = int(publish_at)
    except Exception as exc:
        record_newsfeed_schedule_operation(operation="cancel", outcome="invalid_state")
        raise HTTPException(
            status_code=409,
            detail={
                "code": "schedule_cancel_not_allowed",
                "message": "scheduled post has invalid publish_at",
            },
        ) from exc

    now = now_iso()
    ref_sk = sk_scheduled_post_ref(publish_at_int, post_id)
    try:
        tbl.update_item(
            Key={"pk": pk_post(post_id), "sk": sk_post()},
            UpdateExpression=f"SET #status = :cancelled, updated_at = :u REMOVE published_at, publish_at, schedule_timezone, scheduled_at_local, {SCHEDULE_DUE_INDEX_PK_ATTR}, {SCHEDULE_DUE_INDEX_SK_ATTR}",
            ConditionExpression="#user = :uid AND #status = :scheduled",
            ExpressionAttributeNames={"#status": "status", "#user": "user_id"},
            ExpressionAttributeValues={
                ":cancelled": "cancelled",
                ":u": now,
                ":uid": user_id,
                ":scheduled": "scheduled",
            },
        )
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code == "ConditionalCheckFailedException":
            latest = ddb_get_item({"pk": pk_post(post_id), "sk": sk_post()})
            latest_status = str((latest or {}).get("status") or "").strip().lower()
            if latest and latest.get("user_id") == user_id and latest_status == "cancelled":
                record_newsfeed_schedule_operation(operation="cancel", outcome="noop")
                return _post_to_dict(latest, viewer_id=user_id)
            record_newsfeed_schedule_operation(operation="cancel", outcome="conflict")
            raise HTTPException(
                status_code=409,
                detail={
                    "code": "schedule_cancel_conflict",
                    "message": "schedule cancel conflicted with concurrent modification",
                },
            ) from exc
        record_newsfeed_schedule_operation(operation="cancel", outcome="error")
        raise HTTPException(status_code=500, detail=f"DynamoDB error: {exc.response['Error'].get('Message','unknown')}") from exc
    try:
        tbl.delete_item(Key={"pk": pk_user(user_id), "sk": ref_sk})
    except ClientError:
        pass

    updated = ddb_get_item({"pk": pk_post(post_id), "sk": sk_post()}) or {
        **post,
        "status": "cancelled",
        "publish_at": None,
        "schedule_timezone": None,
        "scheduled_at_local": None,
        "published_at": None,
        "updated_at": now,
    }
    record_newsfeed_schedule_operation(operation="cancel", outcome="success")
    return _post_to_dict(updated, viewer_id=user_id)


@router.get("/posts/{post_id}")
def get_post(post_id: str, user_id: UserIdDep):
    post = ddb_get_item({"pk": pk_post(post_id), "sk": sk_post()})
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
    author = post.get("user_id")
    if author and author != user_id and not can_view_post(user_id, post):
        raise HTTPException(status_code=403, detail="Not authorized to view this post")
    locked = bool(post.get("locked"))
    is_locked_for_viewer = locked and author != user_id and not has_unlocked(user_id, post_id)
    viewer_unlocked = locked and not is_locked_for_viewer
    liked = bool(ddb_get_item({"pk": pk_like(user_id), "sk": f"POST#{post_id}"}))
    return _post_to_dict(post, locked_body=is_locked_for_viewer, liked_by_me=liked, unlocked=viewer_unlocked, viewer_id=user_id)


# ---------------------------------------------------------------------------
# FEED-003: Find-a-DateTime Newsfeed Post
#
# Reuses the MSG-009 overlap-computation service
# (app.services.messaging_find_datetime) and the shared AvailabilityGrid
# frontend component. Poll state is stored in the single-table `calendar` DDB
# table keyed by POSTFADT#{poll_id} (namespaced to avoid collision with the
# conversation-linked FADT#{poll_id} polls from MSG-009).
# ---------------------------------------------------------------------------


class CreateFindDateTimePostIn(BaseModel):
    """Request body for creating a Find-a-DateTime newsfeed post (FEED-003)."""
    title: str = Field(min_length=1, max_length=200)
    from_date: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}$")
    to_date: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}$")
    start_hour: int = Field(ge=0, le=23)
    end_hour: int = Field(ge=1, le=24)
    slot_duration_minutes: int = Field(default=30)
    deadline_hours: int = Field(default=48, ge=1, le=336)
    body: str = Field(default="", max_length=5000)

    @model_validator(mode="after")
    def _validate_fadt_post(self) -> "CreateFindDateTimePostIn":
        if self.slot_duration_minutes not in (15, 30, 60):
            raise ValueError("slot_duration_minutes must be 15, 30, or 60")
        if self.start_hour >= self.end_hour:
            raise ValueError("start_hour must be less than end_hour")
        return self


class SubmitPostAvailabilityIn(BaseModel):
    """Request body for submitting availability on a FADT post poll (FEED-003)."""
    slots: List[str] = Field(min_length=1, max_length=500)


def _post_fadt_pk(poll_id: str) -> str:
    """Single-table key for a post-linked Find-a-DateTime poll."""
    return f"POSTFADT#{poll_id}"


def _post_fadt_meta_or_404(poll_id: str) -> Dict[str, Any]:
    meta = T.calendar.get_item(
        Key={"calendar_id": _post_fadt_pk(poll_id), "sk": "META"}
    ).get("Item")
    if not meta:
        raise HTTPException(status_code=404, detail="Find-a-DateTime poll not found")
    return meta


def _post_fadt_display_name(user_sub: str) -> str:
    try:
        from app.core.tables import T as _T
        profile = _T.profile.get_item(Key={"user_sub": user_sub}).get("Item") or {}
        name = (profile.get("display_name") or profile.get("name") or "").strip()
        if name:
            return name
    except Exception:
        pass
    return user_sub


def _post_fadt_meta_out(meta: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "poll_id": meta.get("poll_id"),
        "post_id": meta.get("post_id"),
        "creator_sub": meta.get("creator_sub"),
        "title": meta.get("title"),
        "from_date": meta.get("from_date"),
        "to_date": meta.get("to_date"),
        "start_hour": int(meta.get("start_hour", 0)),
        "end_hour": int(meta.get("end_hour", 0)),
        "slot_duration_minutes": int(meta.get("slot_duration_minutes", 30)),
        "deadline_at": int(meta.get("deadline_at", 0)),
        "status": meta.get("status", "open"),
        "participant_count": int(meta.get("participant_count", 0)),
    }


@router.post("/posts/find-datetime", status_code=201)
def create_find_datetime_post(body: CreateFindDateTimePostIn, user_id: UserIdDep):
    """Create a Find-a-DateTime newsfeed post (FEED-003).

    Creates a regular newsfeed post item (so it flows through the normal feed +
    interaction endpoints) plus a linked FADT poll record in the calendar table.
    """
    from app.services.messaging_find_datetime import parse_date

    if not bool(getattr(S, "find_datetime_posts_enabled", True)):
        raise HTTPException(status_code=403, detail="Find-a-DateTime posts are not enabled")

    try:
        d0 = parse_date(body.from_date)
        d1 = parse_date(body.to_date)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid date format")
    if d0 >= d1:
        raise HTTPException(status_code=400, detail="from_date must be before to_date")
    span_days = (d1 - d0).days + 1
    max_days = int(getattr(S, "find_datetime_max_date_range_days", 14))
    if span_days > max_days:
        raise HTTPException(status_code=400, detail=f"Date range cannot exceed {max_days} days")

    _enforce_newsfeed_post_quota_precheck(user_id=user_id)

    post_id = new_id("post")
    poll_id = "fadt_" + uuid.uuid4().hex
    created_at = now_iso()
    ts = int(time.time())
    deadline_at = ts + body.deadline_hours * 3600

    # 1. Persist the FADT poll record (calendar single-table, post-namespaced).
    T.calendar.put_item(Item={
        "calendar_id": _post_fadt_pk(poll_id),
        "sk": "META",
        "type": "find_datetime_post",
        "poll_id": poll_id,
        "post_id": post_id,
        "creator_sub": user_id,
        "title": body.title,
        "from_date": body.from_date,
        "to_date": body.to_date,
        "start_hour": body.start_hour,
        "end_hour": body.end_hour,
        "slot_duration_minutes": body.slot_duration_minutes,
        "deadline_at": deadline_at,
        "status": "open",
        "created_at": ts,
        "participant_count": 0,
    })

    # 2. Persist the post item with find_datetime metadata (additive fields).
    post_item = {
        "pk": pk_post(post_id),
        "sk": sk_post(),
        "Entity": "Post",
        "post_id": post_id,
        "user_id": user_id,
        "created_at": created_at,
        "published_at": created_at,
        "status": "published",
        "GSI2PK": f"POST_AUTHOR#{user_id}",
        "GSI2SK": f"{created_at}#POST#{post_id}",
        "body": body.body,
        "body_plain": body.body,
        "body_format": "plain",
        "image_urls": [],
        "visibility": "public",
        "locked": False,
        "like_count": 0,
        "comment_count": 0,
        "body_plain_lc": body.body.lower(),
        "post_kind": "find_datetime",
        "find_datetime_id": poll_id,
        "find_datetime_title": body.title,
        "find_datetime_from_date": body.from_date,
        "find_datetime_to_date": body.to_date,
        "find_datetime_start_hour": body.start_hour,
        "find_datetime_end_hour": body.end_hour,
        "find_datetime_slot_duration_minutes": body.slot_duration_minutes,
        "find_datetime_status": "open",
    }
    ddb_put_item(post_item)

    _write_feed_ref_for_published_post(user_id=user_id, post_id=post_id, created_at=created_at)
    try:
        from app.services.newsfeed_fanout import fan_out_post_to_followers
        fan_out_post_to_followers(author_id=user_id, post_id=post_id, created_at=created_at)
    except Exception:
        logger.exception("Fan-out failed for find-datetime post %s by %s", post_id, user_id)

    return {
        "post_id": post_id,
        "user_id": user_id,
        "post_kind": "find_datetime",
        "find_datetime_id": poll_id,
        "title": body.title,
        "body": body.body,
        "from_date": body.from_date,
        "to_date": body.to_date,
        "start_hour": body.start_hour,
        "end_hour": body.end_hour,
        "slot_duration_minutes": body.slot_duration_minutes,
        "deadline_at": deadline_at,
        "status": "open",
        "created_at": created_at,
        "like_count": 0,
        "comment_count": 0,
    }


@router.get("/posts/find-datetime/{poll_id}")
def get_find_datetime_post(poll_id: str, user_id: UserIdDep):
    """Get Find-a-DateTime poll details (metadata + availabilities + result)."""
    from boto3.dynamodb.conditions import Key as _Key
    meta = _post_fadt_meta_or_404(poll_id)

    items = T.calendar.query(
        KeyConditionExpression=_Key("calendar_id").eq(_post_fadt_pk(poll_id)),
    ).get("Items", [])

    availabilities: List[Dict[str, Any]] = []
    best_windows: Optional[List[Dict[str, Any]]] = None
    for it in items:
        sk = str(it.get("sk", ""))
        if sk.startswith("AVAIL#"):
            availabilities.append({
                "user_sub": it.get("user_sub"),
                "user_name": it.get("user_name") or it.get("user_sub"),
                "slots": [str(s) for s in (it.get("slots") or [])],
                "submitted_at": int(it.get("submitted_at", 0)),
            })
        elif sk == "RESULT":
            best_windows = [
                {
                    "start": w.get("start"),
                    "end": w.get("end"),
                    "count": int(w.get("count", 0)),
                    "participants": [str(p) for p in (w.get("participants") or [])],
                }
                for w in (it.get("best_windows") or [])
            ]
    availabilities.sort(key=lambda a: a["submitted_at"])

    out = _post_fadt_meta_out(meta)
    out["availabilities"] = availabilities
    out["best_windows"] = best_windows
    return out


@router.post("/posts/find-datetime/{poll_id}/availability")
def submit_find_datetime_post_availability(
    poll_id: str, body: SubmitPostAvailabilityIn, user_id: UserIdDep
):
    """Submit or update availability for a post-linked FADT poll (any follower)."""
    from app.services.messaging_find_datetime import enumerate_slots

    meta = _post_fadt_meta_or_404(poll_id)
    if meta.get("status") != "open":
        raise HTTPException(status_code=400, detail="Poll is closed")
    ts = int(time.time())
    if ts > int(meta.get("deadline_at", 0)):
        raise HTTPException(status_code=400, detail="Submission deadline has passed")

    valid_slots = set(enumerate_slots(
        from_date=meta["from_date"],
        to_date=meta["to_date"],
        start_hour=int(meta["start_hour"]),
        end_hour=int(meta["end_hour"]),
        slot_duration_minutes=int(meta["slot_duration_minutes"]),
    ))
    submitted: List[str] = []
    seen: Set[str] = set()
    for s in body.slots:
        if s in seen:
            continue
        seen.add(s)
        if s not in valid_slots:
            raise HTTPException(status_code=400, detail="Slot is outside the allowed range")
        submitted.append(s)
    submitted.sort()

    existing = T.calendar.get_item(
        Key={"calendar_id": _post_fadt_pk(poll_id), "sk": f"AVAIL#{user_id}"}
    ).get("Item")
    is_update = existing is not None

    T.calendar.put_item(Item={
        "calendar_id": _post_fadt_pk(poll_id),
        "sk": f"AVAIL#{user_id}",
        "type": "fadt_post_availability",
        "user_sub": user_id,
        "user_name": _post_fadt_display_name(user_id),
        "slots": submitted,
        "submitted_at": ts,
    })

    participant_count = int(meta.get("participant_count", 0))
    if not is_update:
        try:
            upd = T.calendar.update_item(
                Key={"calendar_id": _post_fadt_pk(poll_id), "sk": "META"},
                UpdateExpression="ADD participant_count :one",
                ExpressionAttributeValues={":one": 1},
                ReturnValues="UPDATED_NEW",
            )
            participant_count = int(upd.get("Attributes", {}).get("participant_count", participant_count + 1))
        except Exception:
            participant_count += 1

    return {
        "ok": True,
        "poll_id": poll_id,
        "your_slot_count": len(submitted),
        "participant_count": participant_count,
        "submitted_at": ts,
    }


@router.post("/posts/find-datetime/{poll_id}/close")
def close_find_datetime_post(poll_id: str, user_id: UserIdDep):
    """Close a post-linked FADT poll and compute best windows (creator only)."""
    from boto3.dynamodb.conditions import Key as _Key
    from app.services.messaging_find_datetime import compute_best_windows

    meta = _post_fadt_meta_or_404(poll_id)
    if meta.get("creator_sub") != user_id:
        raise HTTPException(status_code=403, detail="Only the creator can close this poll")
    if meta.get("status") == "closed":
        raise HTTPException(status_code=400, detail="Poll is already closed")

    avail_items = T.calendar.query(
        KeyConditionExpression=_Key("calendar_id").eq(_post_fadt_pk(poll_id))
        & _Key("sk").begins_with("AVAIL#"),
    ).get("Items", [])
    availabilities = [
        {
            "user_sub": it.get("user_sub"),
            "user_name": it.get("user_name") or it.get("user_sub"),
            "slots": [str(s) for s in (it.get("slots") or [])],
        }
        for it in avail_items
    ]

    best_windows = compute_best_windows(
        availabilities, int(meta.get("slot_duration_minutes", 30))
    )

    ts = int(time.time())
    T.calendar.put_item(Item={
        "calendar_id": _post_fadt_pk(poll_id),
        "sk": "RESULT",
        "type": "fadt_post_result",
        "computed_at": ts,
        "best_windows": best_windows,
    })
    T.calendar.update_item(
        Key={"calendar_id": _post_fadt_pk(poll_id), "sk": "META"},
        UpdateExpression="SET #s = :s",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={":s": "closed"},
    )
    # Mirror status onto the post item so the card reflects closed state.
    post_id = meta.get("post_id")
    if post_id:
        try:
            tbl.update_item(
                Key={"pk": pk_post(post_id), "sk": sk_post()},
                UpdateExpression="SET find_datetime_status = :s",
                ExpressionAttributeValues={":s": "closed"},
            )
        except Exception:
            logger.warning("Failed to mirror find_datetime_status onto post %s", post_id)

    return {
        "ok": True,
        "poll_id": poll_id,
        "status": "closed",
        "participant_count": int(meta.get("participant_count", 0)),
        "best_windows": best_windows,
    }


@router.get("/posts/{post_id}/files/{file_index}")
def get_post_file(post_id: str, file_index: int, user_id: UserIdDep):
    """Proxy a file attachment from a post to an authorized viewer."""
    post = ddb_get_item({"pk": pk_post(post_id), "sk": sk_post()})
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
    author = post.get("user_id")
    if author and author != user_id and not can_view_post(user_id, post):
        raise HTTPException(status_code=403, detail="Not authorized to view this post")
    locked = bool(post.get("locked"))
    if locked and author != user_id and not has_unlocked(user_id, post_id):
        raise HTTPException(status_code=402, detail="Post is locked; unlock required")
    attachments = post.get("file_attachments") or []
    if file_index < 0 or file_index >= len(attachments):
        raise HTTPException(status_code=404, detail="File attachment not found")
    fa = attachments[file_index]
    owner = fa.get("owner")
    path = fa.get("path")
    if not owner or not path:
        raise HTTPException(status_code=404, detail="File attachment metadata missing")
    result = download_file(owner, path)
    node = result["node"]
    obj = result["object"]
    content_type = node.get("content_type") or "application/octet-stream"

    def _iter():
        body = obj["Body"]
        while True:
            chunk = body.read(1024 * 1024)
            if not chunk:
                break
            yield chunk

    headers: dict = {"Cache-Control": "private, max-age=300"}
    if node.get("size") is not None:
        headers["Content-Length"] = str(node["size"])
    return StreamingResponse(_iter(), media_type=content_type, headers=headers)


@router.delete("/posts/{post_id}")
def delete_post(post_id: str, user_id: UserIdDep):
    post = ddb_get_item({"pk": pk_post(post_id), "sk": sk_post()})
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
    if post.get("user_id") != user_id:
        raise HTTPException(status_code=403, detail="Not your post")
    try:
        tbl.delete_item(Key={"pk": pk_post(post_id), "sk": sk_post()})
        from app.services.newsfeed_fanout import fan_out_delete_post
        fan_out_delete_post(post_id=post_id)
    except ClientError as exc:
        raise HTTPException(
            status_code=500,
            detail=f"DynamoDB error: {exc.response['Error'].get('Message', 'unknown')}",
        ) from exc

    # SOC-005: decrement post_count on profile
    try:
        from app.core.tables import T as _T
        from boto3.dynamodb.conditions import Attr as _Attr
        _T.profile.update_item(
            Key={"user_sub": user_id},
            UpdateExpression="ADD post_count :neg_one",
            ConditionExpression=_Attr("post_count").gt(0),
            ExpressionAttributeValues={":neg_one": -1},
        )
    except ClientError as e:
        if e.response["Error"]["Code"] != "ConditionalCheckFailedException":
            logger.warning("Failed to decrement post_count for %s", user_id)
    except Exception:
        logger.warning("Failed to decrement post_count for %s", user_id)

    return {"ok": True}


@router.post("/posts/{post_id}/like")
def like_post(post_id: str, user_id: UserIdDep):
    post = ddb_get_item({"pk": pk_post(post_id), "sk": sk_post()})
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
    try:
        tbl.put_item(
            Item={
                "pk": pk_like(user_id),
                "sk": f"POST#{post_id}",
                "Entity": "Like",
                "user_id": user_id,
                "post_id": post_id,
                "created_at": now_iso(),
            },
            ConditionExpression="attribute_not_exists(pk)",
        )
        ddb_update_item(
            key={"pk": pk_post(post_id), "sk": sk_post()},
            update_expr="SET like_count = if_not_exists(like_count, :z) + :one",
            expr_vals={":one": 1, ":z": 0},
            return_values="NONE",
        )
        # GAP-0337: analytics instrumentation (engagement: reaction/like).
        # Only fires on a genuinely new like (the conditional put above succeeded);
        # best-effort so analytics can never break the like action.
        try:
            record_engagement_event(
                creator_id=post.get("user_id") or "",
                content_id=post_id,
                actor_id=user_id,
                action="reaction",
            )
        except Exception:
            logger.debug("analytics hook: like_post engagement", exc_info=True)
    except ClientError as exc:
        if exc.response["Error"].get("Code") != "ConditionalCheckFailedException":
            raise HTTPException(
                status_code=500,
                detail=f"DynamoDB error: {exc.response['Error'].get('Message', 'unknown')}",
            ) from exc
        # Already liked — idempotent
    return {"ok": True}


@router.post("/posts/{post_id}/unlike")
def unlike_post(post_id: str, user_id: UserIdDep):
    try:
        tbl.delete_item(
            Key={"pk": pk_like(user_id), "sk": f"POST#{post_id}"},
            ConditionExpression="attribute_exists(pk)",
        )
        try:
            ddb_update_item(
                key={"pk": pk_post(post_id), "sk": sk_post()},
                update_expr="SET like_count = like_count - :one",
                expr_vals={":one": 1, ":z": 0},
                condition_expr="like_count > :z",
                return_values="NONE",
            )
        except HTTPException as ex:
            if ex.status_code != 409:
                raise
            # ConditionalCheckFailed — like_count already at 0, that's fine
    except ClientError as exc:
        if exc.response["Error"].get("Code") != "ConditionalCheckFailedException":
            raise HTTPException(
                status_code=500,
                detail=f"DynamoDB error: {exc.response['Error'].get('Message', 'unknown')}",
            ) from exc
        # Already unliked — idempotent
    return {"ok": True}


@router.post("/posts/{post_id}/tip")
def tip_post(post_id: str, req: PostTipRequest, user_id: UserIdDep, _kyc: object = Depends(require_kyc_tier(2))):  # GAP-0268 (inert unless enforcement flag on)
    post = ddb_get_item({"pk": pk_post(post_id), "sk": sk_post()})
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
    if post.get("is_sponsored"):
        raise HTTPException(status_code=400, detail={"code": "tip_not_allowed_on_ad", "message": "Tipping is not available on sponsored posts."})
    if post.get("user_id") == user_id:
        raise HTTPException(status_code=400, detail="Cannot tip your own post")

    # Validate payment method belongs to this user (if provided and billing enabled)
    if req.payment_method_id and S.billing_table_name:
        billing_tbl = ddb.Table(S.billing_table_name)
        billing_items = billing_tbl.query(
            KeyConditionExpression="pk = :pk",
            ExpressionAttributeValues={":pk": f"USER#{user_id}"},
        ).get("Items", [])
        pm_ids = {
            it["payment_method_id"]
            for it in billing_items
            if it.get("sk", "").startswith("PM#") and "payment_method_id" in it
        }
        if req.payment_method_id not in pm_ids:
            raise HTTPException(status_code=400, detail="Payment method not found")

    # TIP-007: the mock PaymentProvider stub is replaced by the centralized
    # charge_tip seam (called below, after the tip_total bump). The stub always
    # "succeeded", so removing it changes no behavior.
    updated = ddb_update_item(
        key={"pk": pk_post(post_id), "sk": sk_post()},
        update_expr="SET tip_total_cents = if_not_exists(tip_total_cents, :z) + :amt",
        expr_vals={":z": 0, ":amt": req.amount_cents},
    )

    # Write billing ledger debit + credit entries via the centralized charge_tip seam.
    post_author = post.get("user_id")
    _tip_txn_id = ""
    if post_author and post_author != user_id:
        from app.services.tips import charge_tip
        _tp = charge_tip(
            tipper_id=user_id,
            recipient_id=post_author,
            amount_cents=req.amount_cents,
            currency=req.currency,
            payment_method_id=req.payment_method_id,
            content_type="post",
            content_id=post_id,
            meta={"post_id": post_id},
            idempotency_key=new_id("posttip"),
        )
        _tip_txn_id = _tp.tip_payment_id

    # GAP-0026: Best-effort license revenue split for tipped post.
    # Wrapped in try/except so a split failure never breaks the tip transaction.
    try:
        from app.services import license_revenue as _lr_svc
        _lr_svc.process_revenue_split(
            content_id=post_id,
            licensee_id=user_id,
            source_type="post_tip",
            source_amount_cents=req.amount_cents,
            source_txn_id=_tip_txn_id or post_id,
            currency=str(req.currency or "usd").lower(),
        )
    except Exception:
        logger.warning(
            "license revenue split failed for post tip on post %s", post_id
        )

    author = post.get("user_id")
    if author:
        put_notification(
            recipient_user_id=author,
            notif_type="tip_on_post",
            payload={
                "post_id": post_id,
                "from_user_id": user_id,
                "amount_cents": req.amount_cents,
                "currency": req.currency,
                "created_at": now_iso(),
            },
        )
        # GAP-0355: also emit a social alert (alerts table + bell badge).
        # Best-effort: never break the tip transaction.
        try:
            actor_name = _post_fadt_display_name(user_id)
            emit_social_alert(
                recipient_user_id=author,
                alert_type="post_tip",
                actor_user_id=user_id,
                actor_display_name=actor_name,
                batch_key=BATCH_KEY_PATTERNS["post_tip"].format(post_id=post_id),
                title=f"{actor_name} sent you a tip",
                details={
                    "post_id": post_id,
                    "amount_cents": req.amount_cents,
                    "currency": req.currency,
                },
                action_url=f"/feed/posts/{post_id}",
            )
        except Exception:
            logger.warning("post tip social alert failed post_id=%s", post_id, exc_info=True)

    # GAP-0162: achievement progress hook (no-op unless ACHIEVEMENTS_ENABLED)
    try:
        from app.services.achievement_progress import advance_progress
        advance_progress(user_id, "tip_count")
    except Exception:
        logger.debug("achievement hook: tip_count", exc_info=True)

    # GAP-0337: analytics instrumentation (revenue: tip). Creator = post author,
    # amount = tip amount, subscriber = tipper. Best-effort.
    try:
        record_revenue_event(
            creator_id=post.get("user_id") or "",
            revenue_type="tip",
            amount_cents=req.amount_cents,
            subscriber_id=user_id,
            content_id=post_id,
        )
    except Exception:
        logger.debug("analytics hook: tip_post revenue", exc_info=True)

    return {"ok": True, "tip_total_cents": int(updated.get("tip_total_cents", 0))}


@router.post("/posts/{post_id}/video/entitlement")
def issue_video_post_entitlement(post_id: str, user_id: UserIdDep = None):
    post = ddb_get_item({"pk": pk_post(post_id), "sk": sk_post()})
    if not post:
        raise HTTPException(status_code=404, detail="post not found")
    vid = post.get("video_id")
    if not vid:
        raise HTTPException(status_code=400, detail="post has no video")
    is_locked = bool(post.get("locked"))
    if is_locked:
        is_owner = post.get("user_id") == user_id
        if not is_owner and not has_unlocked(user_id, post_id):
            raise HTTPException(status_code=403, detail="post is locked")
    from app.services.playback_entitlements import issue_playback_entitlement
    from app.services.video_metadata_store import get_video as _ent_vid
    video = _ent_vid(vid)
    if video.status != "published" or not video.hls_manifest_url:
        raise HTTPException(status_code=400, detail="video is not available for playback")
    ttl = getattr(S, "video_playback_token_ttl_seconds", 300) or 300
    result = issue_playback_entitlement(
        tenant_id=video.owner_user_id,
        asset_id=video.id,
        session_id=f"feed_{user_id}_{post_id}",
        device_id="browser",
        profile="auto",
        audience="playback",
        ttl_seconds=ttl,
    )
    return {
        "video_id": vid,
        "hls_manifest_url": video.hls_manifest_url,
        "playback_token": result.get("token"),
        "playback_expires_at": result.get("expires_at_epoch"),
    }


@router.post("/posts/{post_id}/reactions")
def add_reaction(post_id: str, req: ReactionRequest, user_id: UserIdDep):
    post = ddb_get_item({"pk": pk_post(post_id), "sk": sk_post()})
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")

    reactions = dict(post.get("reactions") or {})
    emoji_map = dict(reactions.get(req.emoji, {}))
    emoji_map[user_id] = True
    reactions[req.emoji] = emoji_map

    ddb_update_item(
        key={"pk": pk_post(post_id), "sk": sk_post()},
        update_expr="SET reactions = :r",
        expr_vals={":r": reactions},
        return_values="NONE",
    )
    # GAP-0162: achievement progress hook (no-op unless ACHIEVEMENTS_ENABLED)
    try:
        from app.services.achievement_progress import advance_progress
        advance_progress(user_id, "reaction_count")
    except Exception:
        logger.debug("achievement hook: reaction_count", exc_info=True)
    # GAP-0355: notify the post owner of the new reaction via the social alert
    # system (alerts table + bell badge). Best-effort: never break the reaction.
    post_author = post.get("user_id")
    if post_author and post_author != user_id:
        try:
            actor_name = _post_fadt_display_name(user_id)
            emit_social_alert(
                recipient_user_id=post_author,
                alert_type="post_reaction",
                actor_user_id=user_id,
                actor_display_name=actor_name,
                batch_key=BATCH_KEY_PATTERNS["post_reaction"].format(post_id=post_id),
                title=f"{actor_name} reacted to your post",
                details={"post_id": post_id, "emoji": req.emoji},
                action_url=f"/feed/posts/{post_id}",
            )
        except Exception:
            logger.warning("reaction social alert failed post_id=%s", post_id, exc_info=True)
    return {"ok": True}


class PostTipReactRequest(BaseModel):
    amount_cents: int = Field(..., ge=1)
    currency: str = "usd"
    emoji: Optional[str] = None
    payment_method_id: Optional[str] = None


@router.post("/posts/{post_id}/reactions/tip")
def tip_react_to_post(post_id: str, req: PostTipReactRequest, user_id: UserIdDep, _kyc: object = Depends(require_kyc_tier(2))):  # GAP-0268 (inert unless enforcement flag on)
    """TIP-202: money-reaction (tip-react) on a POST -- DISTINCT from the free emoji
    add_reaction. Routes through the single charge_tip money-path
    (content_type="post_react"), crediting the POST AUTHOR, rejecting a self-tip,
    and -- only AFTER a successful charge -- recording a money-reaction badge +
    bumping tip_total_cents + emitting a social alert."""
    post = ddb_get_item({"pk": pk_post(post_id), "sk": sk_post()})
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
    if post.get("is_sponsored"):
        raise HTTPException(status_code=400, detail={"code": "tip_not_allowed_on_ad", "message": "Tipping is not available on sponsored posts."})
    author = post.get("user_id")
    if not author:
        raise HTTPException(status_code=400, detail="Post has no author to tip")
    if author == user_id:
        raise HTTPException(status_code=400, detail="Cannot tip your own post")

    emoji = (req.emoji or "\U0001F4B8").strip() or "\U0001F4B8"

    # Money-path via the single funnel. A self-tip (400) or a failed charge (402)
    # raises BEFORE any badge/ledger side effect -> no badge, no ledger on failure.
    from app.services.tips import charge_tip
    receipt = charge_tip(
        tipper_id=user_id,
        recipient_id=author,
        amount_cents=req.amount_cents,
        currency=req.currency,
        payment_method_id=req.payment_method_id,
        content_type="post_react",
        content_id=post_id,
        meta={"post_id": post_id, "emoji": emoji},
        idempotency_key=new_id("postreacttip"),
    )

    # Only reached on a successful charge. Record the money-reaction badge + running
    # tip total on the post (distinct from the free emoji `reactions` map).
    badge = {
        "tipper_id": user_id,
        "emoji": emoji,
        "amount_cents": int(req.amount_cents),
        "tip_payment_id": receipt.tip_payment_id,
        "created_at": now_iso(),
    }
    updated = ddb_update_item(
        key={"pk": pk_post(post_id), "sk": sk_post()},
        update_expr="SET tip_reactions = list_append(if_not_exists(tip_reactions, :empty), :new), tip_total_cents = if_not_exists(tip_total_cents, :z) + :amt",
        expr_vals={":empty": [], ":new": [badge], ":z": 0, ":amt": int(req.amount_cents)},
    )

    # GAP-0355: social alert to the post author (best-effort; never break the tip).
    try:
        actor_name = _post_fadt_display_name(user_id)
        emit_social_alert(
            recipient_user_id=author,
            alert_type="post_tip",
            actor_user_id=user_id,
            actor_display_name=actor_name,
            batch_key=BATCH_KEY_PATTERNS["post_tip"].format(post_id=post_id),
            title=f"{actor_name} sent you a tip reaction {emoji}",
            details={"post_id": post_id, "amount_cents": int(req.amount_cents), "emoji": emoji},
            action_url=f"/feed/posts/{post_id}",
        )
    except Exception:
        logger.warning("post tip-react social alert failed post_id=%s", post_id, exc_info=True)

    return {
        "ok": True,
        "tip_payment_id": receipt.tip_payment_id,
        "charged_cents": receipt.charged_cents,
        "net_cents": receipt.net_cents,
        "recipient_id": author,
        "emoji": emoji,
        "tip_total_cents": int(updated.get("tip_total_cents", 0)),
    }


@router.post("/posts/{post_id}/unreact")
def remove_reaction(post_id: str, req: ReactionRequest, user_id: UserIdDep):
    post = ddb_get_item({"pk": pk_post(post_id), "sk": sk_post()})
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")

    reactions = dict(post.get("reactions") or {})
    if req.emoji in reactions:
        emoji_map = dict(reactions[req.emoji])
        emoji_map.pop(user_id, None)
        if emoji_map:
            reactions[req.emoji] = emoji_map
        else:
            del reactions[req.emoji]
        ddb_update_item(
            key={"pk": pk_post(post_id), "sk": sk_post()},
            update_expr="SET reactions = :r",
            expr_vals={":r": reactions},
            return_values="NONE",
        )
    return {"ok": True}


@router.post("/feed/hide")
def hide_post(req: HidePostRequest, user_id: UserIdDep):
    item = {
        "pk": pk_hide(user_id),
        "sk": f"POST#{req.post_id}",
        "Entity": "Hide",
        "user_id": user_id,
        "post_id": req.post_id,
        "hidden": True,
        "created_at": now_iso(),
    }
    ddb_put_item(item)
    return {"ok": True, "post_id": req.post_id, "hidden": True}


def _is_post_interesting(viewer_id: Optional[str], post_id: str) -> bool:
    """FEED-007: whether ``viewer_id`` marked ``post_id`` interesting."""
    if not viewer_id:
        return False
    try:
        return _post_interesting_svc.is_interesting(viewer_id, post_id)
    except Exception:
        return False


@router.post("/feed/interesting")
def mark_post_interesting(req: HidePostRequest, user_id: UserIdDep):
    """FEED-007: Mark a post "interesting" for the current viewer (toggle ON).

    Per-viewer signal stored on the billing table (PK=USER#{sub},
    SK=POST_SIGNAL#{post_id}); distinct from likes/reactions. Idempotent: the
    service checks for an existing signal before writing, so a repeated mark is a
    no-op and the aggregate ``interesting_count`` is bumped exactly once.
    """
    post = ddb_get_item({"pk": pk_post(req.post_id), "sk": sk_post()})
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
    if post.get("user_id") == user_id:
        raise HTTPException(status_code=400, detail="Cannot signal your own post")
    return _post_interesting_svc.mark_interesting(user_id, req.post_id)


@router.post("/feed/uninteresting")
def unmark_post_interesting(req: HidePostRequest, user_id: UserIdDep):
    """FEED-007: Remove the viewer's "interesting" signal (toggle OFF).

    Idempotent — unmarking a post that is not marked is a no-op success and does
    not move the aggregate counter.
    """
    return _post_interesting_svc.unmark_interesting(user_id, req.post_id)


@router.get("/feed/interesting")
def list_interesting_posts(
    limit: int = Query(200, ge=1, le=1000),
    user_id: UserIdDep = None,
):
    """FEED-007: List post_ids the current viewer marked interesting.

    Powers the "more like this" feed-ranking boost: callers prioritise these
    posts (and same-author posts) in ranking.
    """
    post_ids = _post_interesting_svc.list_interesting_post_ids(user_id, limit=limit)
    return {"post_ids": post_ids, "count": len(post_ids)}


def _feed_request_mode(author_filter: Optional[str]) -> str:
    return "profile" if author_filter else "global"


# User subs are email addresses (e.g. e2e_alice@test.local), so the author_id
# filter must allow "@" and "+" in addition to the basic identifier characters.
_AUTHOR_ID_ALLOWED = re.compile(r"^[A-Za-z0-9._:@+-]{1,128}$")


def _normalize_author_filter_or_400(author_id: Optional[str]) -> Optional[str]:
    if author_id is None:
        return None
    candidate = str(author_id).strip()
    if not candidate:
        return None
    if not _AUTHOR_ID_ALLOWED.fullmatch(candidate):
        raise HTTPException(
            status_code=400,
            detail={
                "code": "invalid_author_id",
                "message": "author_id contains unsupported characters",
            },
        )
    return candidate


def _normalize_query_or_400(q: Optional[str]) -> Optional[str]:
    if q is None:
        return None
    candidate = str(q).strip()
    if not candidate:
        return None
    max_chars = max(1, int(getattr(S, "newsfeed_feed_max_query_chars", 200) or 200))
    if len(candidate) > max_chars:
        raise HTTPException(
            status_code=400,
            detail={
                "code": "invalid_query",
                "message": "q exceeds maximum length",
                "max_query_chars": max_chars,
            },
        )
    return candidate


def _emit_feed_filter_usage_metrics(*, mode: str, q: Optional[str], from_ts: Optional[str], to_ts: Optional[str], has_media: Optional[bool]) -> None:
    if q and str(q).strip():
        record_newsfeed_feed_filter_usage(mode=mode, filter_name="q")
    if from_ts:
        record_newsfeed_feed_filter_usage(mode=mode, filter_name="from")
    if to_ts:
        record_newsfeed_feed_filter_usage(mode=mode, filter_name="to")
    if has_media is not None:
        record_newsfeed_feed_filter_usage(mode=mode, filter_name="has_media")


def _build_feed_query_log_extra(
    *,
    mode: str,
    user_id: str,
    author_filter: Optional[str],
    limit: int,
    cursor: Optional[str],
    q: Optional[str],
    from_ts: Optional[str],
    to_ts: Optional[str],
    has_media: Optional[bool],
    page_depth: int,
    item_count: int,
    has_next_cursor: bool,
    outcome: str,
    error_type: Optional[str] = None,
) -> Dict[str, Any]:
    safe_query = {
        "has_q": bool(q and str(q).strip()),
        "q_length": len(str(q or "")),
        "has_from": bool(from_ts),
        "has_to": bool(to_ts),
        "has_media": has_media,
    }
    payload: Dict[str, Any] = {
        "event": "newsfeed_feed_query",
        "mode": mode,
        "viewer_id": user_id,
        "author_id": author_filter,
        "limit": int(limit),
        "cursor_present": bool(cursor),
        "page_depth": int(page_depth),
        "item_count": int(item_count),
        "has_next_cursor": bool(has_next_cursor),
        "query": safe_query,
        "outcome": outcome,
    }
    if error_type:
        payload["error_type"] = error_type
    return payload


def _feed_query_budget_limits() -> Tuple[int, int]:
    max_pages = max(1, int(getattr(S, "newsfeed_feed_max_scanned_pages", 20) or 20))
    max_elapsed_ms = max(1, int(getattr(S, "newsfeed_feed_max_elapsed_ms", 2000) or 2000))
    return max_pages, max_elapsed_ms


def _validate_filter_window_or_400(*, from_dt: Optional[datetime], to_dt: Optional[datetime]) -> None:
    if not from_dt or not to_dt:
        return
    max_window_days = max(1, int(getattr(S, "newsfeed_feed_max_window_days", 365) or 365))
    span_days = (to_dt - from_dt).total_seconds() / 86400.0
    if span_days > float(max_window_days):
        raise HTTPException(
            status_code=400,
            detail={
                "code": "invalid_time_window",
                "message": f"'from' and 'to' may span at most {max_window_days} days",
                "max_window_days": max_window_days,
            },
        )


def _http_error_type(exc: HTTPException) -> str:
    detail = exc.detail
    if isinstance(detail, dict):
        code = str(detail.get("code") or "").strip().lower()
        if code:
            return f"code_{code}"
    return f"http_{int(exc.status_code)}"


@router.get("/feed")
def view_feed(
    limit: int = Query(default=20, ge=1, le=50),
    cursor: Optional[str] = Query(default=None),
    author_id: Optional[str] = Query(default=None, min_length=1),
    q: Optional[str] = Query(default=None),
    from_ts: Optional[str] = Query(default=None, alias="from"),
    to_ts: Optional[str] = Query(default=None, alias="to"),
    has_media: Optional[bool] = Query(default=None),
    user_id: UserIdDep = None,
):
    author_filter: Optional[str] = None
    normalized_q: Optional[str] = None
    mode = _feed_request_mode(str(author_id).strip() if author_id else None)
    started = time.perf_counter()
    page_depth = 0
    max_scanned_pages, max_elapsed_ms = _feed_query_budget_limits()

    try:
        author_filter = _normalize_author_filter_or_400(author_id)
        normalized_q = _normalize_query_or_400(q)
        mode = _feed_request_mode(author_filter)
        from_dt, to_dt = parse_filter_window(from_ts, to_ts)
        _validate_filter_window_or_400(from_dt=from_dt, to_dt=to_dt)
        eks = decode_cursor_or_400(cursor)
        rate_limit_feed_query(user_id, mode)
        ordered: List[Dict[str, Any]] = []
        _fanout_source_by_post: Dict[str, str] = {}
        filter_params = FeedFilterParams(author_id=author_filter, q=normalized_q, from_dt=from_dt, to_dt=to_dt, has_media=has_media)
        next_eks = eks

        # Load blocked set once for feed filtering
        from app.services.blocking import get_blocked_set, get_blocked_by_set
        _feed_blocked_set = get_blocked_set(user_id) | get_blocked_by_set(user_id)

        # SOCIAL-007: Load snoozed-following set once; exclude their posts from the
        # main feed. Snooze auto-expires (snoozed_until <= now is not included).
        _feed_snoozed_set: Set[str] = set()
        if not author_filter:
            try:
                from app.services.social import get_snoozed_following_ids
                _feed_snoozed_set = get_snoozed_following_ids(user_id)
            except Exception:
                logger.exception("failed to load snoozed following set for feed filter")

        while len(ordered) < limit:
            elapsed_ms = (time.perf_counter() - started) * 1000.0
            if page_depth >= max_scanned_pages:
                record_newsfeed_feed_budget_hit(mode=mode, reason="max_scanned_pages")
                raise HTTPException(
                    status_code=422,
                    detail={
                        "code": "feed_query_budget_exceeded",
                        "reason": "max_scanned_pages",
                        "max_scanned_pages": max_scanned_pages,
                    },
                )
            if elapsed_ms > float(max_elapsed_ms):
                record_newsfeed_feed_budget_hit(mode=mode, reason="max_elapsed_ms")
                raise HTTPException(
                    status_code=422,
                    detail={
                        "code": "feed_query_budget_exceeded",
                        "reason": "max_elapsed_ms",
                        "max_elapsed_ms": max_elapsed_ms,
                    },
                )
            page_depth += 1
            _repost_meta_by_post: Dict[str, Dict[str, Any]] = {}
            if author_filter:
                resp = ddb_query(
                    IndexName="GSI2",
                    KeyConditionExpression="GSI2PK = :pk",
                    ExpressionAttributeValues={":pk": f"POST_AUTHOR#{author_filter}"},
                    ScanIndexForward=False,
                    Limit=limit,
                    ExclusiveStartKey=next_eks if next_eks else None,
                )
                posts = [it for it in (resp.get("Items") or []) if it.get("post_id")]
                post_ids = [str(it.get("post_id")) for it in posts if it.get("post_id")]
                unique_post_ids = list(dict.fromkeys(post_ids))
                post_by_id = {str(post.get("post_id")): post for post in posts if post.get("post_id")}
            else:
                resp = ddb_query(
                    IndexName="GSI1",
                    KeyConditionExpression="GSI1PK = :pk",
                    ExpressionAttributeValues={":pk": f"FEED#{user_id}"},
                    ScanIndexForward=False,
                    Limit=limit,
                    ExclusiveStartKey=next_eks if next_eks else None,
                )
                refs = resp.get("Items", [])
                # SOC-002: Build fan-out source map from feed refs
                for ref in refs:
                    _rpid = ref.get("post_id")
                    if _rpid and _rpid not in _fanout_source_by_post:
                        _fanout_source_by_post[_rpid] = "following" if ref.get("fanout") else "own"
                # SOCIAL-002: Build repost metadata map from feed refs
                for ref in refs:
                    if ref.get("ref_type") == "repost" and ref.get("post_id"):
                        pid = ref["post_id"]
                        if pid not in _repost_meta_by_post:
                            _repost_meta_by_post[pid] = {
                                "reposter_id": ref.get("reposter_id", ""),
                                "repost_quote": ref.get("quote"),
                                "repost_id": ref.get("repost_id"),
                            }
                post_ids = [ref.get("post_id") for ref in refs if ref.get("post_id")]
                # Deduplicate post_ids for batch_get_item (repost refs may duplicate the same post_id)
                unique_post_ids = list(dict.fromkeys(post_ids))
                posts = []
                if unique_post_ids:
                    try:
                        raw = ddb.batch_get_item(RequestItems={APP_TABLE: {"Keys": [{"pk": pk_post(pid), "sk": sk_post()} for pid in unique_post_ids]}})
                        posts = raw.get("Responses", {}).get(APP_TABLE, [])
                    except ClientError as exc:
                        raise HTTPException(
                            status_code=500,
                            detail=f"DDB batch_get_item error: {exc.response['Error'].get('Message','unknown')}",
                        ) from exc
                post_by_id = {post["post_id"]: post for post in posts if "post_id" in post}

            if not post_ids:
                next_eks = resp.get("LastEvaluatedKey")
                if not next_eks:
                    break
                continue

            liked_post_ids: set = set()
            try:
                like_raw = ddb.batch_get_item(
                    RequestItems={APP_TABLE: {"Keys": [{"pk": pk_like(user_id), "sk": f"POST#{pid}"} for pid in unique_post_ids]}}
                )
                liked_post_ids = {item.get("post_id", "") for item in like_raw.get("Responses", {}).get(APP_TABLE, [])}
            except ClientError:
                pass

            # GAP-0357 sub-gap 1: build the viewer's bookmarked-post-id set so each
            # feed post carries an accurate is_bookmarked flag (survives refresh).
            bookmarked_post_ids: set = set()
            try:
                bk_raw = ddb.batch_get_item(
                    RequestItems={APP_TABLE: {"Keys": [{"pk": pk_bookmark_lookup(user_id), "sk": f"post#{pid}"} for pid in unique_post_ids]}}
                )
                bookmarked_post_ids = {
                    item.get("content_id", "")
                    for item in bk_raw.get("Responses", {}).get(APP_TABLE, [])
                }
            except (ClientError, Exception):
                pass

            candidates: List[Dict[str, Any]] = []
            for post_id in unique_post_ids:
                post = post_by_id.get(post_id)
                if not post:
                    continue
                status, _publish_at, _published_at, _schedule_timezone, _scheduled_at_local = _resolve_post_lifecycle_fields(post)
                if status != "published":
                    continue
                if post.get("moderation_removed") or post.get("moderation_removed_at"):
                    continue
                if is_hidden(user_id, post_id):
                    continue
                if not post_matches_filters(post, filter_params):
                    continue
                candidates.append(post)

            for post in sort_posts_deterministically(candidates):
                author = post.get("user_id")
                post_id = str(post.get("post_id") or "")
                # Filter out posts from blocked users
                if author and author in _feed_blocked_set:
                    continue
                # SOCIAL-007: Filter out posts from snoozed followings
                if author and author in _feed_snoozed_set:
                    continue
                if author and author != user_id and not can_view_post(user_id, post):
                    continue

                locked = bool(post.get("locked"))
                is_locked_for_viewer = locked and author != user_id and not has_unlocked(user_id, post_id)
                viewer_unlocked = locked and not is_locked_for_viewer
                post_dict = _post_to_dict(
                    post,
                    locked_body=is_locked_for_viewer,
                    liked_by_me=post_id in liked_post_ids,
                    unlocked=viewer_unlocked,
                    viewer_id=user_id,
                    bookmarked_ids=bookmarked_post_ids,
                )
                # SOCIAL-002: Attach repost attribution if this feed item came from a repost
                repost_meta = _repost_meta_by_post.get(post_id) if not author_filter else None
                if repost_meta:
                    reposter_id = repost_meta["reposter_id"]
                    reposter_display = reposter_id
                    try:
                        rp_profile = T.profile.get_item(Key={"user_sub": reposter_id}).get("Item")
                        if rp_profile:
                            reposter_display = rp_profile.get("display_name") or rp_profile.get("name") or reposter_id
                    except Exception:
                        pass
                    post_dict["reposted_by"] = {"user_id": reposter_id, "display_name": reposter_display}
                    if repost_meta.get("repost_quote"):
                        post_dict["repost_quote"] = repost_meta["repost_quote"]
                # SOC-002: Add feed source attribution
                if not author_filter:
                    post_dict["source"] = _fanout_source_by_post.get(post_id, "own")
                ordered.append(post_dict)
                if len(ordered) >= limit:
                    break

            next_eks = resp.get("LastEvaluatedKey")
            if len(ordered) >= limit or not next_eks:
                break

        # ADS-005: Inject sponsored posts into the feed
        feed_items = ordered[:limit]
        if not author_filter:  # Only inject in the main feed, not author-filtered views
            feed_items = _inject_sponsored_posts(feed_items, user_id)
            # ADS-012 (GAP-0005): Elevate actively-boosted posts in the feed.
            # CRITICAL: newsfeed post dicts carry the id as "post_id", not the
            # default "content_id" — passing id_key explicitly is mandatory or
            # elevation silently no-ops.
            from app.services.content_boost import elevate_feed_items
            feed_items = elevate_feed_items(
                feed_items,
                content_type="post",
                id_key="post_id",
            )

        out = {"items": feed_items, "next_cursor": encode_cursor(next_eks)}
        _emit_feed_filter_usage_metrics(mode=mode, q=normalized_q, from_ts=from_ts, to_ts=to_ts, has_media=has_media)
        record_newsfeed_feed_page_depth(mode=mode, depth=page_depth)
        record_newsfeed_feed_request(mode=mode, outcome="success")
        record_newsfeed_feed_latency(mode=mode, outcome="success", elapsed_seconds=time.perf_counter() - started)
        logger.info(
            "newsfeed feed query",
            extra=_build_feed_query_log_extra(
                mode=mode,
                user_id=user_id,
                author_filter=author_filter,
                limit=limit,
                cursor=cursor,
                q=normalized_q,
                from_ts=from_ts,
                to_ts=to_ts,
                has_media=has_media,
                page_depth=page_depth,
                item_count=len(out["items"]),
                has_next_cursor=bool(out["next_cursor"]),
                outcome="success",
            ),
        )
        return out
    except ValueError as exc:
        record_newsfeed_feed_error(mode=mode, error_type="validation")
        record_newsfeed_feed_request(mode=mode, outcome="error")
        record_newsfeed_feed_latency(mode=mode, outcome="error", elapsed_seconds=time.perf_counter() - started)
        logger.warning(
            "newsfeed feed query validation error",
            extra=_build_feed_query_log_extra(
                mode=mode,
                user_id=user_id,
                author_filter=author_filter,
                limit=limit,
                cursor=cursor,
                q=normalized_q,
                from_ts=from_ts,
                to_ts=to_ts,
                has_media=has_media,
                page_depth=page_depth,
                item_count=0,
                has_next_cursor=False,
                outcome="error",
                error_type="validation",
            ),
        )
        raise HTTPException(status_code=400, detail=str(exc) or "Invalid 'from'/'to' datetime; expected ISO-8601") from exc
    except HTTPException as exc:
        error_type = _http_error_type(exc)
        record_newsfeed_feed_error(mode=mode, error_type=error_type)
        record_newsfeed_feed_request(mode=mode, outcome="error")
        record_newsfeed_feed_latency(mode=mode, outcome="error", elapsed_seconds=time.perf_counter() - started)
        logger.warning(
            "newsfeed feed query http error",
            extra=_build_feed_query_log_extra(
                mode=mode,
                user_id=user_id,
                author_filter=author_filter,
                limit=limit,
                cursor=cursor,
                q=normalized_q,
                from_ts=from_ts,
                to_ts=to_ts,
                has_media=has_media,
                page_depth=page_depth,
                item_count=0,
                has_next_cursor=False,
                outcome="error",
                error_type=error_type,
            ),
        )
        raise
    except Exception:
        record_newsfeed_feed_error(mode=mode, error_type="unhandled")
        record_newsfeed_feed_request(mode=mode, outcome="error")
        record_newsfeed_feed_latency(mode=mode, outcome="error", elapsed_seconds=time.perf_counter() - started)
        logger.exception(
            "newsfeed feed query unhandled error",
            extra=_build_feed_query_log_extra(
                mode=mode,
                user_id=user_id,
                author_filter=author_filter,
                limit=limit,
                cursor=cursor,
                q=normalized_q,
                from_ts=from_ts,
                to_ts=to_ts,
                has_media=has_media,
                page_depth=page_depth,
                item_count=0,
                has_next_cursor=False,
                outcome="error",
                error_type="unhandled",
            ),
        )
        raise


@router.get("/feed/capabilities", response_model=FeedCapabilitiesResponse)
def feed_capabilities(user_id: UserIdDep):
    enabled = _is_unlock_limit_enabled_for_user(user_id)
    mode = str(getattr(S, "newsfeed_unlock_limit_rollout_mode", "off") or "off")
    return FeedCapabilitiesResponse(
        unlock_limit_enabled=bool(enabled),
        unlock_limit_rollout_mode=mode,
    )


@router.get("/posts/{post_id}/attachments/{attachment_id}")
def download_post_attachment(
    post_id: str,
    attachment_id: str,
    user_id: UserIdDep = None,
    x_request_id: Optional[str] = Header(default=None, alias="X-Request-Id"),
):
    ensure_uploads_enabled()

    post = ddb_get_item({"PK": pk_post(post_id), "SK": sk_post()})
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")

    author = post.get("user_id")
    if author and author != user_id and not can_view_post(user_id, post):
        raise HTTPException(status_code=403, detail="Not authorized to view this post")

    if bool(post.get("locked")) and author != user_id and not has_unlocked(user_id, post_id):
        raise HTTPException(status_code=402, detail="Post is locked; unlock required")

    attachment = None
    for it in post.get("attachments") or []:
        if str((it or {}).get("attachment_id") or "") == attachment_id:
            attachment = it or {}
            break
    if not attachment:
        raise HTTPException(status_code=404, detail="Attachment not found")

    s3_key = str(attachment.get("s3_key") or "").strip()
    if not s3_key:
        raise HTTPException(status_code=404, detail="Attachment object not found")

    try:
        obj = s3.get_object(Bucket=UPLOAD_BUCKET, Key=s3_key)
    except ClientError as exc:
        raise HTTPException(status_code=404, detail="Attachment object not found") from exc

    body = obj.get("Body")
    if body is None:
        raise HTTPException(status_code=404, detail="Attachment stream missing")

    content_len = int(obj.get("ContentLength") or 0)
    content_type = str(attachment.get("content_type") or obj.get("ContentType") or "application/octet-stream")
    filename = str(attachment.get("filename") or os.path.basename(s3_key) or "attachment")
    attachment_key = f"{UPLOAD_BUCKET}/{s3_key}"

    def _iter_stream():
        sent = 0
        try:
            for chunk in body.iter_chunks(chunk_size=64 * 1024):
                if not chunk:
                    continue
                sent += len(chunk)
                yield chunk
        finally:
            _record_newsfeed_attachment_download(
                user_id=user_id,
                post_id=post_id,
                attachment_key=attachment_key,
                bytes_count=sent,
                idempotency_operation_id=x_request_id or attachment_id,
            )

    headers = {
        "Content-Disposition": f'inline; filename="{filename}"',
        "Cache-Control": "private, max-age=60",
    }
    if content_len > 0:
        headers["Content-Length"] = str(content_len)

    return StreamingResponse(_iter_stream(), media_type=content_type, headers=headers)


# -----------------------------
# Comments
# -----------------------------
@router.post("/posts/{post_id}/comments", response_model=CommentResponse)
def create_comment(post_id: str, req: CreateCommentRequest, user_id: UserIdDep):
    post = ddb_get_item({"pk": pk_post(post_id), "sk": sk_post()})
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")

    post_author = post.get("user_id")
    if post_author and post_author != user_id and not can_view_post(user_id, post):
        raise HTTPException(status_code=403, detail="Not authorized to comment on this post")

    if post.get("locked") and post.get("user_id") != user_id and not has_unlocked(user_id, post_id):
        raise HTTPException(status_code=402, detail="Post is locked; unlock required to comment")

    # FEED-004: gate media comments behind feature flag
    if req.kind in ("gif", "sticker") and not bool(getattr(S, "rich_comments_enabled", True)):
        raise HTTPException(status_code=400, detail="Media comments are not enabled")

    comment_id = new_id("cmt")
    created_at = now_iso()
    parent = req.parent_comment_id

    # TIP-302: comment-CARRYING tip. Charge FIRST (recipient = the POST author)
    # so a declined/failed charge raises BEFORE any comment row is written --
    # no orphan comment, no orphan stamp, no ledger. A tip on your OWN post
    # self-tips -> charge_tip raises 400 cannot_tip_self.
    comment_tip_total = 0
    if getattr(req, "tip_amount_cents", None):
        from app.services.tips import charge_tip
        charge_tip(
            tipper_id=user_id,
            recipient_id=post_author,
            amount_cents=int(req.tip_amount_cents),
            currency=(getattr(req, "tip_currency", "usd") or "usd"),
            payment_method_id=getattr(req, "tip_payment_method_id", None),
            content_type="comment",
            content_id=comment_id,
            meta={"post_id": post_id, "comment_id": comment_id, "carried": True},
            idempotency_key=new_id("cmtcarry"),
        )
        comment_tip_total = int(req.tip_amount_cents)

    # FEED-004: media comments (gif/sticker) carry no body content; text comments
    # use the existing ContentFieldsMixin envelope.
    if req.kind == "text":
        content = _content_from_payload(req)
    else:
        content = {
            "body": None,
            "body_plain": None,
            "body_markdown": None,
            "body_markdown_html": None,
            "body_rich": None,
            "body_format": "plain",
            "body_version": 1,
        }
    media_fields = {
        "kind": req.kind,
        "gif_url": req.gif_url,
        "gif_alt_text": req.gif_alt_text,
        "gif_width": req.gif_width,
        "gif_height": req.gif_height,
        "sticker_id": req.sticker_id,
        "sticker_collection_id": req.sticker_collection_id,
        "sticker_url": req.sticker_url,
        "sticker_alt_text": req.sticker_alt_text,
    }
    _emit_newsfeed_content_metric("create_comment", surface="comment", body_format=content.get("body_format", "plain"))

    item = {
        "pk": pk_post_comments(post_id),
        "sk": f"{created_at}#CMT#{comment_id}",
        "Entity": "Comment",
        "comment_id": comment_id,
        "post_id": post_id,
        "user_id": user_id,
        "created_at": created_at,
        "updated_at": None,
        "deleted": False,
        "parent_comment_id": parent,
        **content,
        **media_fields,
        "version": 1,
        "tip_total_cents": comment_tip_total,
        "GSI2PK": pk_post_comments(post_id),
        "GSI2SK": f"{created_at}#CMT#{comment_id}",
    }
    ddb_put_item(item)

    ddb_update_item(
        key={"pk": pk_post(post_id), "sk": sk_post()},
        update_expr="SET comment_count = if_not_exists(comment_count, :z) + :one",
        expr_vals={":z": 0, ":one": 1},
    )

    # GAP-0162: achievement progress hook (no-op unless ACHIEVEMENTS_ENABLED)
    try:
        from app.services.achievement_progress import advance_progress
        advance_progress(user_id, "comment_count")
    except Exception:
        logger.debug("achievement hook: comment_count", exc_info=True)

    # GAP-0337: analytics instrumentation (engagement: comment). Creator = post
    # author, actor = commenter. Best-effort.
    try:
        record_engagement_event(
            creator_id=post_author or "",
            content_id=post_id,
            actor_id=user_id,
            action="comment",
        )
    except Exception:
        logger.debug("analytics hook: create_comment engagement", exc_info=True)

    if post_author and post_author != user_id and parent is None:
        put_notification(
            recipient_user_id=post_author,
            notif_type="comment_on_post",
            payload={"post_id": post_id, "comment_id": comment_id, "from_user_id": user_id, "created_at": created_at},
        )
        # GAP-0355: also emit a social alert (alerts table + bell badge).
        # Best-effort: never break comment creation.
        try:
            actor_name = _post_fadt_display_name(user_id)
            emit_social_alert(
                recipient_user_id=post_author,
                alert_type="post_comment",
                actor_user_id=user_id,
                actor_display_name=actor_name,
                batch_key=BATCH_KEY_PATTERNS["post_comment"].format(post_id=post_id),
                title=f"{actor_name} commented on your post",
                details={"post_id": post_id, "comment_id": comment_id},
                action_url=f"/feed/posts/{post_id}",
            )
        except Exception:
            logger.warning("comment social alert failed post_id=%s", post_id, exc_info=True)

    if parent:
        q = ddb_query(
            KeyConditionExpression="pk = :pk",
            ExpressionAttributeValues={":pk": pk_post_comments(post_id)},
            ScanIndexForward=False,
            Limit=200,
        )
        parent_user = None
        for it in q.get("Items", []):
            if it.get("comment_id") == parent:
                parent_user = it.get("user_id")
                break
        if parent_user and parent_user != user_id:
            put_notification(
                recipient_user_id=parent_user,
                notif_type="reply_to_comment",
                payload={
                    "post_id": post_id,
                    "parent_comment_id": parent,
                    "comment_id": comment_id,
                    "from_user_id": user_id,
                    "created_at": created_at,
                },
            )
            # GAP-0355: also emit a social alert (alerts table + bell badge).
            # Best-effort: never break comment creation.
            try:
                actor_name = _post_fadt_display_name(user_id)
                emit_social_alert(
                    recipient_user_id=parent_user,
                    alert_type="comment_reply",
                    actor_user_id=user_id,
                    actor_display_name=actor_name,
                    title=f"{actor_name} replied to your comment",
                    details={
                        "post_id": post_id,
                        "parent_comment_id": parent,
                        "comment_id": comment_id,
                    },
                    action_url=f"/feed/posts/{post_id}",
                )
            except Exception:
                logger.warning("reply social alert failed post_id=%s", post_id, exc_info=True)

    # GAP-0356: emit mention alerts for @mentions in the comment body.
    # Media (gif/sticker) comments have body_plain=None; guard avoids the cost.
    if req.kind == "text" and content.get("body_plain"):
        try:
            emit_mention_alerts(
                text=content["body_plain"],
                author_user_id=user_id,
                author_display_name=_post_fadt_display_name(user_id),
                context_type="comment",
                context_id=comment_id,
                post_id=post_id,
            )
        except Exception:
            logger.warning("emit_mention_alerts failed for comment %s", comment_id, exc_info=True)

    return CommentResponse(
        comment_id=comment_id,
        post_id=post_id,
        author_id=user_id,
        created_at=created_at,
        updated_at=None,
        deleted=False,
        parent_comment_id=parent,
        body=content["body"],
        body_plain=content["body_plain"],
        body_markdown=content["body_markdown"],
        body_markdown_html=content["body_markdown_html"],
        body_rich=content["body_rich"],
        body_format=content["body_format"],
        body_version=content["body_version"],
        version=1,
        tip_total_cents=comment_tip_total,
        kind=req.kind,
        gif_url=req.gif_url,
        gif_alt_text=req.gif_alt_text,
        gif_width=req.gif_width,
        gif_height=req.gif_height,
        sticker_id=req.sticker_id,
        sticker_collection_id=req.sticker_collection_id,
        sticker_url=req.sticker_url,
        sticker_alt_text=req.sticker_alt_text,
    )


@router.get("/posts/{post_id}/comments")
def list_comments(
    post_id: str,
    limit: int = Query(default=20, ge=1, le=50),
    cursor: Optional[str] = Query(default=None),
    user_id: UserIdDep = None,
):
    post = ddb_get_item({"pk": pk_post(post_id), "sk": sk_post()})
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")

    if post.get("locked") and post.get("user_id") != user_id and not has_unlocked(user_id, post_id):
        raise HTTPException(status_code=402, detail="Post is locked; unlock required to view comments")

    eks = decode_cursor_or_400(cursor)
    resp = ddb_query(
        IndexName="GSI2",
        KeyConditionExpression="GSI2PK = :pk",
        ExpressionAttributeValues={":pk": pk_post_comments(post_id)},
        ScanIndexForward=True,
        Limit=limit,
        ExclusiveStartKey=eks if eks else None,
    )
    items = [
        _comment_to_dict(it)
        for it in resp.get("Items", [])
        if not it.get("moderation_removed")
    ]
    return {"items": items, "next_cursor": encode_cursor(resp.get("LastEvaluatedKey"))}


@router.patch("/posts/{post_id}/comments/{comment_id}", response_model=CommentResponse)
def edit_comment(post_id: str, comment_id: str, req: EditCommentRequest, user_id: UserIdDep):
    q = ddb_query(
        KeyConditionExpression="pk = :pk",
        ExpressionAttributeValues={":pk": pk_post_comments(post_id)},
        ScanIndexForward=False,
        Limit=500,
    )
    target = None
    for it in q.get("Items", []):
        if it.get("comment_id") == comment_id:
            target = it
            break
    if not target:
        raise HTTPException(status_code=404, detail="Comment not found")
    if target.get("user_id") != user_id:
        raise HTTPException(status_code=403, detail="Not your comment")
    if target.get("deleted"):
        raise HTTPException(status_code=409, detail="Comment deleted")

    key = {"pk": target["pk"], "sk": target["sk"]}
    new_version = int(req.expected_version) + 1

    content = _content_from_payload(req)
    _emit_newsfeed_content_metric("edit_comment", surface="comment", body_format=content.get("body_format", "plain"))
    updated = ddb_update_item(
        key=key,
        update_expr="SET #body = :b, body_plain = :bp, body_markdown = :bm, body_markdown_html = :bmh, body_rich = :br, body_format = :bf, body_version = :bv, updated_at = :u, version = :nv",
        expr_names={"#body": "body"},
        expr_vals={":b": content["body"], ":bp": content["body_plain"], ":bm": content["body_markdown"], ":bmh": content["body_markdown_html"], ":br": content["body_rich"], ":bf": content["body_format"], ":bv": content["body_version"], ":u": now_iso(), ":nv": new_version, ":ev": int(req.expected_version)},
        condition_expr="version = :ev",
    )

    return CommentResponse(
        comment_id=updated["comment_id"],
        post_id=updated["post_id"],
        author_id=updated.get("user_id", ""),
        created_at=updated["created_at"],
        updated_at=updated.get("updated_at"),
        deleted=bool(updated.get("deleted")),
        parent_comment_id=updated.get("parent_comment_id"),
        body=(updated.get("body_plain") or updated.get("body")) if not updated.get("deleted") else None,
        body_plain=updated.get("body_plain") if not updated.get("deleted") else None,
        body_markdown=updated.get("body_markdown") if not updated.get("deleted") else None,
        body_markdown_html=updated.get("body_markdown_html") if not updated.get("deleted") else None,
        body_rich=updated.get("body_rich") if not updated.get("deleted") else None,
        body_format=updated.get("body_format") if updated.get("body_format") in {"plain", "markdown", "rich"} else "plain",
        body_version=int(updated.get("body_version") or 1),
        version=int(updated.get("version", 1)),
        tip_total_cents=int(updated.get("tip_total_cents", 0)),
        kind=updated.get("kind", "text"),
        gif_url=updated.get("gif_url"),
        gif_alt_text=updated.get("gif_alt_text"),
        gif_width=int(updated["gif_width"]) if updated.get("gif_width") is not None else None,
        gif_height=int(updated["gif_height"]) if updated.get("gif_height") is not None else None,
        sticker_id=updated.get("sticker_id"),
        sticker_collection_id=updated.get("sticker_collection_id"),
        sticker_url=updated.get("sticker_url"),
        sticker_alt_text=updated.get("sticker_alt_text"),
    )


@router.delete("/posts/{post_id}/comments/{comment_id}")
def delete_comment(post_id: str, comment_id: str, user_id: UserIdDep):
    q = ddb_query(
        KeyConditionExpression="pk = :pk",
        ExpressionAttributeValues={":pk": pk_post_comments(post_id)},
        ScanIndexForward=False,
        Limit=500,
    )
    target = None
    for it in q.get("Items", []):
        if it.get("comment_id") == comment_id:
            target = it
            break
    if not target:
        raise HTTPException(status_code=404, detail="Comment not found")
    if target.get("user_id") != user_id:
        raise HTTPException(status_code=403, detail="Not your comment")

    key = {"pk": target["pk"], "sk": target["sk"]}
    ddb_update_item(
        key=key,
        update_expr="SET deleted = :t, #body = :null, body_plain = :null, body_markdown = :null, body_rich = :null, updated_at = :u",
        expr_names={"#body": "body"},
        expr_vals={":t": True, ":null": None, ":u": now_iso()},
    )
    return {"ok": True}


# -----------------------------
# Tips on comments
# -----------------------------
@router.post("/posts/{post_id}/comments/{comment_id}/tip")
def tip_comment(post_id: str, comment_id: str, req: TipRequest, user_id: UserIdDep):
    tipper_id = user_id

    q = ddb_query(
        KeyConditionExpression="pk = :pk",
        ExpressionAttributeValues={":pk": pk_post_comments(post_id)},
        ScanIndexForward=False,
        Limit=500,
    )
    target = None
    for it in q.get("Items", []):
        if it.get("comment_id") == comment_id:
            target = it
            break
    if not target:
        raise HTTPException(status_code=404, detail="Comment not found")
    if target.get("deleted"):
        raise HTTPException(status_code=409, detail="Comment deleted")

    # TIP-008: the mock PaymentProvider stub is replaced by the centralized
    # charge_tip seam (called below). Keep a stub-shaped receipt for the response.
    pi = {"provider": "stub", "payment_intent_id": None, "status": "succeeded"}

    comment_author = target.get("user_id")

    # TIP-301: charge via the centralized charge_tip seam BEFORE stamping the
    # comment, so a declined/failed charge (402) leaves NO tip_total bump and
    # NO ledger. payment_method_id now flows from TipRequest (explicit ->
    # tip-default -> default fallback inside charge_tip).
    if comment_author and comment_author != tipper_id:
        from app.services.tips import charge_tip
        _ct = charge_tip(
            tipper_id=tipper_id,
            recipient_id=comment_author,
            amount_cents=req.amount_cents,
            currency=req.currency,
            payment_method_id=getattr(req, "payment_method_id", None),
            content_type="comment",
            content_id=comment_id,
            meta={"post_id": post_id, "comment_id": comment_id},
            idempotency_key=new_id("cmttip"),
        )
        pi["payment_intent_id"] = _ct.tip_payment_id

    key = {"pk": target["pk"], "sk": target["sk"]}
    updated = ddb_update_item(
        key=key,
        update_expr="SET tip_total_cents = if_not_exists(tip_total_cents, :z) + :amt",
        expr_vals={":z": 0, ":amt": req.amount_cents},
    )

    if comment_author and comment_author != tipper_id:
        put_notification(
            recipient_user_id=comment_author,
            notif_type="tip_on_comment",
            payload={
                "post_id": post_id,
                "comment_id": comment_id,
                "from_user_id": tipper_id,
                "amount_cents": req.amount_cents,
                "currency": req.currency,
                "created_at": now_iso(),
            },
        )

    return {"ok": True, "tip_total_cents": int(updated.get("tip_total_cents", 0)), "payment_intent": pi}


# -----------------------------
# Unlock post via payment
# -----------------------------
@router.post("/posts/unlock", response_model=UnlockPostResponse)
def unlock_post(req: UnlockPostRequest, user_id: UserIdDep, _kyc: object = Depends(require_kyc_tier(2))):  # GAP-0268 (inert unless enforcement flag on)
    post = ddb_get_item({"pk": pk_post(req.post_id), "sk": sk_post()})
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
    _emit_unlock_lifecycle_event(
        "unlock_attempt",
        user_id=user_id,
        post_id=req.post_id,
        reason_code="request_received",
        unlock_limit=_coerce_optional_int(post.get("unlock_limit"), minimum=1),
        unlock_count=_coerce_optional_int(post.get("unlock_count"), minimum=0),
    )
    if not post.get("locked"):
        return UnlockPostResponse(post_id=req.post_id, payment_intent={"status": "not_required"})
    if post.get("user_id") == user_id:
        return UnlockPostResponse(post_id=req.post_id, payment_intent={"status": "not_required"})
    unlock_key = {"pk": pk_unlock(user_id), "sk": f"POST#{req.post_id}"}
    request_fingerprint = _unlock_request_fingerprint(
        post_id=req.post_id,
        payment_method_id=req.payment_method_id,
        unlock_price_cents=int(post.get("unlock_price_cents") or 0),
        currency="usd",
    )
    unlock_limit_enabled = _is_unlock_limit_enabled_for_user(user_id)
    existing_unlock = ddb_get_item(unlock_key) or {}
    if bool(existing_unlock.get("unlocked")):
        if req.idempotency_key:
            try:
                _validate_unlock_attempt_idempotency(
                    req_idempotency_key=req.idempotency_key,
                    req_request_fingerprint=request_fingerprint,
                    unlock_attempt=existing_unlock,
                )
            except HTTPException as exc:
                detail = exc.detail if isinstance(exc.detail, dict) else {}
                code = str(detail.get("code") or "")
                if code in {"unlock_idempotency_conflict", "unlock_idempotency_payload_mismatch"}:
                    _emit_unlock_idempotency_rejection(user_id=user_id, post_id=req.post_id, reason_code=code)
                raise
            _emit_unlock_replay_event(
                user_id=user_id,
                post_id=req.post_id,
                replay_state="already_unlocked",
                reason_code="existing_unlocked_precheck",
                replayed=True,
            )
            return _unlock_response_for_existing_attempt(
                post_id=req.post_id,
                req_idempotency_key=req.idempotency_key,
                req_request_fingerprint=request_fingerprint,
                unlock_attempt=existing_unlock,
            )
            
        _emit_unlock_replay_event(
            user_id=user_id,
            post_id=req.post_id,
            replay_state="already_unlocked",
            reason_code="existing_unlocked_precheck",
            replayed=False,
        )
        return UnlockPostResponse(post_id=req.post_id, payment_intent={"status": "already_unlocked"})
    if req.idempotency_key:
        if existing_unlock:
            try:
                _validate_unlock_attempt_idempotency(
                    req_idempotency_key=req.idempotency_key,
                    req_request_fingerprint=request_fingerprint,
                    unlock_attempt=existing_unlock,
                )
            except HTTPException as exc:
                detail = exc.detail if isinstance(exc.detail, dict) else {}
                code = str(detail.get("code") or "")
                if code in {"unlock_idempotency_conflict", "unlock_idempotency_payload_mismatch"}:
                    _emit_unlock_idempotency_rejection(user_id=user_id, post_id=req.post_id, reason_code=code)
                raise
            if bool(existing_unlock.get("unlocked")):
                return _unlock_response_for_existing_attempt(
                    post_id=req.post_id,
                    req_idempotency_key=req.idempotency_key,
                    req_request_fingerprint=request_fingerprint,
                    unlock_attempt=existing_unlock,
                )
            if bool(existing_unlock.get("in_progress")):
                recovered = _recover_stale_unlock_attempt_if_needed(
                    user_id=user_id,
                    post_id=req.post_id,
                    unlock_attempt=existing_unlock,
                    unlock_limit_enabled=unlock_limit_enabled,
                )
                if not recovered:
                    _emit_unlock_replay_event(
                        user_id=user_id,
                        post_id=req.post_id,
                        replay_state="in_progress",
                        reason_code="existing_in_progress_precheck",
                        replayed=True,
                    )
                    return UnlockPostResponse(post_id=req.post_id, payment_intent={"status": "in_progress", "replayed": True})
    try:
        _enforce_unlock_attempt_throttle(user_id, req.post_id)
    except HTTPException as exc:
        _emit_unlock_lifecycle_event(
            "unlock_payment_failed",
            user_id=user_id,
            post_id=req.post_id,
            reason_code="unlock_attempt_throttled",
            payment_status="throttled",
        )
        raise exc
    if _is_lock_expired(post):
        raise _post_lock_expired_error()
    try:
        if unlock_limit_enabled:
            attempt_state = _begin_unlock_attempt_with_reservation(
                user_id,
                req.post_id,
                idempotency_key=req.idempotency_key,
                request_fingerprint=request_fingerprint,
            )
        else:
            attempt_state = _begin_unlock_attempt(
                user_id,
                req.post_id,
                idempotency_key=req.idempotency_key,
                request_fingerprint=request_fingerprint,
            )
        if attempt_state == "already_unlocked":
            existing_unlock = ddb_get_item(unlock_key) or {}
            _emit_unlock_replay_event(
                user_id=user_id,
                post_id=req.post_id,
                replay_state="already_unlocked",
                reason_code="attempt_state_already_unlocked",
                replayed=bool(req.idempotency_key),
            )
            return _unlock_response_for_existing_attempt(
                post_id=req.post_id,
                req_idempotency_key=req.idempotency_key,
                req_request_fingerprint=request_fingerprint,
                unlock_attempt=existing_unlock,
            )
        if attempt_state == "in_progress":
            existing_unlock = ddb_get_item(unlock_key) or {}
            _validate_unlock_attempt_idempotency(
                req_idempotency_key=req.idempotency_key,
                req_request_fingerprint=request_fingerprint,
                unlock_attempt=existing_unlock,
            )
            existing_idempotency_key = existing_unlock.get("idempotency_key")
            if req.idempotency_key and existing_idempotency_key == req.idempotency_key:
                _emit_unlock_replay_event(
                    user_id=user_id,
                    post_id=req.post_id,
                    replay_state="in_progress",
                    reason_code="attempt_state_in_progress",
                    replayed=True,
                )
                return UnlockPostResponse(post_id=req.post_id, payment_intent={"status": "in_progress", "replayed": True})
            recovered = _recover_stale_unlock_attempt_if_needed(
                user_id=user_id,
                post_id=req.post_id,
                unlock_attempt=existing_unlock,
                unlock_limit_enabled=unlock_limit_enabled,
            )
            if recovered:
                if unlock_limit_enabled:
                    attempt_state = _begin_unlock_attempt_with_reservation(
                        user_id,
                        req.post_id,
                        idempotency_key=req.idempotency_key,
                        request_fingerprint=request_fingerprint,
                    )
                else:
                    attempt_state = _begin_unlock_attempt(
                        user_id,
                        req.post_id,
                        idempotency_key=req.idempotency_key,
                        request_fingerprint=request_fingerprint,
                    )
                if attempt_state == "already_unlocked":
                    latest_unlock = ddb_get_item(unlock_key) or {}
                    _emit_unlock_replay_event(
                        user_id=user_id,
                        post_id=req.post_id,
                        replay_state="already_unlocked",
                        reason_code="attempt_state_already_unlocked_after_recover",
                        replayed=bool(req.idempotency_key),
                    )
                    return _unlock_response_for_existing_attempt(
                        post_id=req.post_id,
                        req_idempotency_key=req.idempotency_key,
                        req_request_fingerprint=request_fingerprint,
                        unlock_attempt=latest_unlock,
                    )
                if attempt_state == "in_progress":
                    latest_unlock = ddb_get_item(unlock_key) or {}
                    _validate_unlock_attempt_idempotency(
                        req_idempotency_key=req.idempotency_key,
                        req_request_fingerprint=request_fingerprint,
                        unlock_attempt=latest_unlock,
                    )
                    latest_idempotency_key = latest_unlock.get("idempotency_key")
                    replayed = bool(req.idempotency_key and latest_idempotency_key == req.idempotency_key)
                    _emit_unlock_replay_event(
                        user_id=user_id,
                        post_id=req.post_id,
                        replay_state="in_progress",
                        reason_code="attempt_state_in_progress_after_recover",
                        replayed=replayed,
                    )
                    return UnlockPostResponse(post_id=req.post_id, payment_intent={"status": "in_progress", "replayed": replayed})
            else:
                return UnlockPostResponse(post_id=req.post_id, payment_intent={"status": "in_progress"})
    except HTTPException as exc:
        detail = exc.detail if isinstance(exc.detail, dict) else {}
        code = str(detail.get("code") or "")
        if code in {"unlock_idempotency_conflict", "unlock_idempotency_payload_mismatch"}:
            _emit_unlock_idempotency_rejection(user_id=user_id, post_id=req.post_id, reason_code=code)
        raise

    price = int(post.get("unlock_price_cents") or 0)
    if price <= 0:
        _release_reserved_unlock_slot(req.post_id)
        _clear_unlock_attempt_if_not_unlocked(user_id, req.post_id)
        raise HTTPException(status_code=500, detail="Locked post has invalid price")

    # Validate payment method belongs to this user
    if req.payment_method_id and S.billing_table_name:
        billing_tbl_pm = ddb.Table(S.billing_table_name)
        billing_items = billing_tbl_pm.query(
            KeyConditionExpression="pk = :pk",
            ExpressionAttributeValues={":pk": f"USER#{user_id}"},
        ).get("Items", [])
        pm_ids = {
            it["payment_method_id"]
            for it in billing_items
            if it.get("sk", "").startswith("PM#") and "payment_method_id" in it
        }
        if req.payment_method_id not in pm_ids:
            _release_reserved_unlock_slot(req.post_id)
            _clear_unlock_attempt_if_not_unlocked(user_id, req.post_id)
            _emit_unlock_lifecycle_event(
                "unlock_payment_failed",
                user_id=user_id,
                post_id=req.post_id,
                reason_code="payment_method_not_found",
                payment_status="validation_failed",
            )
            raise HTTPException(status_code=400, detail="Payment method not found")
    try:
        pi = payments.create_payment_intent(
            user_id=user_id,
            amount_cents=price,
            currency="usd",
            metadata={
                "type": "unlock_post",
                "post_id": req.post_id,
                "idempotency_key": req.idempotency_key or "",
                "request_fingerprint": request_fingerprint,
            },
        )
        conf = payments.confirm_payment_intent(payment_intent_id=pi["payment_intent_id"])
    except Exception:
        _release_reserved_unlock_slot(req.post_id)
        _clear_unlock_attempt_if_not_unlocked(user_id, req.post_id)
        _emit_unlock_lifecycle_event(
            "unlock_payment_failed",
            user_id=user_id,
            post_id=req.post_id,
            reason_code="payment_exception",
            payment_status="exception",
        )
        raise
    if conf.get("status") != "succeeded":
        _release_reserved_unlock_slot(req.post_id)
        _clear_unlock_attempt_if_not_unlocked(user_id, req.post_id)
        _emit_unlock_lifecycle_event(
            "unlock_payment_failed",
            user_id=user_id,
            post_id=req.post_id,
            reason_code=f"payment_status_{conf.get('status') or 'unknown'}",
            payment_status=str(conf.get("status") or ""),
        )
        raise HTTPException(status_code=402, detail="Payment failed")

    _finalize_unlock_attempt_success(user_id, req.post_id, pi["payment_intent_id"])
    _emit_unlock_lifecycle_event(
        "unlock_success",
        user_id=user_id,
        post_id=req.post_id,
        reason_code="payment_confirmed",
        payment_status=str(conf.get("status") or ""),
    )

    # GAP-0337: analytics instrumentation (revenue: unlock). Creator = post
    # author, amount = unlock price, subscriber = unlocking user. Best-effort.
    try:
        record_revenue_event(
            creator_id=post.get("user_id") or "",
            revenue_type="unlock",
            amount_cents=price,
            subscriber_id=user_id,
            content_id=req.post_id,
        )
    except Exception:
        logger.debug("analytics hook: unlock_post revenue", exc_info=True)

    # Write billing ledger debit entry (best-effort)
    if S.billing_table_name:
        try:
            billing_tbl_led = ddb.Table(S.billing_table_name)
            led_entry_id = uuid.uuid4().hex
            ts_now = int(time.time())
            billing_tbl_led.put_item(Item={
                "pk": f"USER#{user_id}",
                "sk": f"LEDGER#{ts_now}#{led_entry_id}",
                "entry_id": led_entry_id,
                "ts": ts_now,
                "type": "debit",
                "amount_cents": price,
                "currency": "USD",
                "state": "settled",
                "reason": "Post unlock",
                "meta": {
                    "post_id": req.post_id,
                    "payment_method_id": req.payment_method_id,
                    "idempotency_key": req.idempotency_key or "",
                    "request_fingerprint": request_fingerprint,
                    "payment_intent_id": pi.get("payment_intent_id"),
                },
            })
        except Exception:
            pass  # Best-effort; do not fail the unlock if billing write fails

    # GAP-0026: Best-effort license revenue split for unlocked post.
    # Wrapped in try/except so a split failure never breaks the unlock transaction.
    try:
        from app.services import license_revenue as _lr_svc
        _lr_svc.process_revenue_split(
            content_id=req.post_id,
            licensee_id=user_id,
            source_type="post_unlock",
            source_amount_cents=price,
            source_txn_id=pi.get("payment_intent_id") or "",
            currency="usd",
        )
    except Exception:
        logger.warning(
            "license revenue split failed for post unlock on post %s", req.post_id
        )

    author = post.get("user_id")
    if author and author != user_id:
        put_notification(
            recipient_user_id=author,
            notif_type="post_unlocked",
            payload={
                "post_id": req.post_id,
                "from_user_id": user_id,
                "amount_cents": price,
                "currency": "usd",
                "created_at": now_iso(),
            },
        )

    # GAP-0162: achievement progress hook (no-op unless ACHIEVEMENTS_ENABLED)
    try:
        from app.services.achievement_progress import advance_progress
        advance_progress(user_id, "unlock_count")
    except Exception:
        logger.debug("achievement hook: unlock_count", exc_info=True)

    # ADV-404: attribute this paid unlock to the unlocker's last ad click
    # (explicit ad_click_id or last-click 7d) and charge the CPA bid. Best-effort.
    try:
        from app.services.ad_attribution import attribute_conversion
        attribute_conversion(
            viewer_sub=user_id,
            conversion_type="unlock",
            conversion_value_cents=int(price or 0),
            ad_click_id=getattr(req, "ad_click_id", "") or "",
        )
    except Exception:
        logger.warning("ad_conversion_attribution_failed unlock post=%s", req.post_id, exc_info=True)

    return UnlockPostResponse(post_id=req.post_id, payment_intent=pi)


# -----------------------------
# Notifications inbox (view)
# -----------------------------
@router.get("/notifications")
def list_notifications(
    limit: int = Query(default=20, ge=1, le=50),
    cursor: Optional[str] = Query(default=None),
    user_id: UserIdDep = None,
):
    eks = decode_cursor_or_400(cursor)

    resp = ddb_query(
        IndexName="GSI3",
        KeyConditionExpression="GSI3PK = :pk",
        ExpressionAttributeValues={":pk": pk_notif(user_id)},
        ScanIndexForward=False,
        Limit=limit,
        ExclusiveStartKey=eks if eks else None,
    )
    return {"items": resp.get("Items", []), "next_cursor": encode_cursor(resp.get("LastEvaluatedKey"))}



@router.post("/telemetry/content-render")
def content_render_telemetry(req: ContentRenderTelemetryRequest, user_id: UserIdDep):
    _emit_newsfeed_content_reject(req.reason, source="renderer", body_format=req.body_format)
    return {"ok": True}


@router.post("/telemetry/draft-lifecycle")
def draft_lifecycle_telemetry(req: DraftLifecycleTelemetryRequest, user_id: UserIdDep):
    _ensure_drafts_feature_enabled(user_id)
    _emit_newsfeed_draft_metric(
        req.event,
        outcome=req.outcome,
        source="frontend",
        reason_code=req.reason_code,
        surface=req.surface,
    )
    return {"ok": True}


# ──────────────────────────────────────────────────────────────────────────────
# Reposts (SOCIAL-002)
# ──────────────────────────────────────────────────────────────────────────────


def pk_repost(user_id: str) -> str:
    return f"REPOST#{user_id}"


class RepostRequest(BaseModel):
    quote: Optional[str] = Field(default=None, max_length=500)


@router.post("/posts/{post_id}/repost", status_code=201)
def create_repost(post_id: str, req: RepostRequest, user_id: UserIdDep):
    """Create a repost (share post to own feed and fans out to followers)."""
    # 1. Verify post exists and is published
    post = ddb_get_item({"pk": pk_post(post_id), "sk": sk_post()})
    if not post:
        raise HTTPException(status_code=404, detail={"code": "post_not_found", "message": "Post not found"})
    status_val, _, _, _, _ = _resolve_post_lifecycle_fields(post)
    if status_val != "published":
        raise HTTPException(status_code=404, detail={"code": "post_not_found", "message": "Post not found"})

    # 2. Cannot repost own post
    author_id = post.get("user_id", "")
    if author_id == user_id:
        raise HTTPException(status_code=400, detail={"code": "self_repost", "message": "Cannot repost your own post"})

    # 3. Cannot repost locked posts
    if post.get("locked") and int(post.get("unlock_price_cents", 0) or 0) > 0:
        raise HTTPException(status_code=403, detail={"code": "post_locked", "message": "Cannot repost locked content"})

    # 4. Check block relationship
    try:
        from app.services.blocking import is_any_block
        if is_any_block(user_id, author_id):
            raise HTTPException(status_code=403, detail={"code": "blocked", "message": "Blocked"})
    except ImportError:
        pass

    # 5. Check not already reposted
    existing = ddb_get_item({"pk": pk_repost(user_id), "sk": f"POST#{post_id}"})
    if existing:
        raise HTTPException(status_code=409, detail={"code": "already_reposted", "message": "Already reposted"})

    # 6. Validate quote length
    quote_text = (req.quote or "").strip() if req.quote else None
    if quote_text and len(quote_text) > 500:
        raise HTTPException(status_code=400, detail={"code": "quote_too_long", "message": "Quote exceeds 500 characters"})
    # Strip HTML from quote
    if quote_text:
        quote_text = re.sub(r"<[^>]+>", "", quote_text).strip()

    created_at = now_iso()
    repost_id = new_id("rp")

    # 7. Write repost entity
    repost_item = {
        "pk": pk_repost(user_id),
        "sk": f"POST#{post_id}",
        "Entity": "Repost",
        "repost_id": repost_id,
        "user_id": user_id,
        "post_id": post_id,
        "original_author_id": author_id,
        "created_at": created_at,
        "GSI1PK": f"REPOSTS#{post_id}",
        "GSI1SK": f"{created_at}#{user_id}",
    }
    if quote_text:
        repost_item["quote"] = quote_text
    ddb_put_item(repost_item)

    # 7b. Notify the original author that their post was reposted.
    # Skip self-reposts (already guarded above) and empty author_id.
    # Best-effort: a notification failure must never fail the repost.
    if author_id and author_id != user_id:
        try:
            put_notification(
                recipient_user_id=author_id,
                notif_type="post_shared",
                payload={
                    "post_id": post_id,
                    "repost_id": repost_id,
                    "from_user_id": user_id,
                },
            )
        except Exception:
            logger.warning("repost put_notification failed post_id=%s repost_id=%s", post_id, repost_id, exc_info=True)
        try:
            actor_name = _post_fadt_display_name(user_id)
            emit_social_alert(
                recipient_user_id=author_id,
                alert_type="post_shared",
                actor_user_id=user_id,
                actor_display_name=actor_name,
                title=f"{actor_name} shared your post",
                details={"post_id": post_id, "repost_id": repost_id},
                action_url=f"/feed?post={post_id}",
            )
        except Exception:
            logger.warning("repost social alert failed post_id=%s repost_id=%s", post_id, repost_id, exc_info=True)

    # 8. Atomically increment repost_count on the post
    updated = ddb_update_item(
        key={"pk": pk_post(post_id), "sk": sk_post()},
        update_expr="SET repost_count = if_not_exists(repost_count, :z) + :one",
        expr_vals={":one": 1, ":z": 0},
        return_values="ALL_NEW",
    )
    new_count = int(updated.get("repost_count", 1))

    # 9. Write FEEDREF for the reposter's own feed
    reposter_feed_ref = {
        "pk": f"POST#{post_id}",
        "sk": f"FEEDREF#{user_id}#REPOST#{repost_id}",
        "Entity": "FeedRef",
        "ref_type": "repost",
        "repost_id": repost_id,
        "post_id": post_id,
        "reposter_id": user_id,
        "owner_user_id": user_id,
        "created_at": created_at,
        "fanout": False,
        "GSI1PK": f"FEED#{user_id}",
        "GSI1SK": f"{created_at}#REPOST#{repost_id}",
    }
    if quote_text:
        reposter_feed_ref["quote"] = quote_text
    ddb_put_item(reposter_feed_ref)

    # 10. Fan-out to followers
    try:
        from app.services.newsfeed_fanout import _get_all_follower_ids
        follower_ids = _get_all_follower_ids(user_id)
        for fid in follower_ids:
            try:
                tbl.put_item(Item={
                    "pk": f"POST#{post_id}",
                    "sk": f"FEEDREF#{fid}#REPOST#{repost_id}",
                    "Entity": "FeedRef",
                    "ref_type": "repost",
                    "repost_id": repost_id,
                    "post_id": post_id,
                    "reposter_id": user_id,
                    "owner_user_id": user_id,
                    "created_at": created_at,
                    "fanout": True,
                    "GSI1PK": f"FEED#{fid}",
                    "GSI1SK": f"{created_at}#REPOST#{repost_id}",
                    **({"quote": quote_text} if quote_text else {}),
                })
            except Exception:
                logger.exception("Failed to fan-out repost %s to follower %s", repost_id, fid)
    except Exception:
        logger.exception("Repost fan-out failed for %s", repost_id)

    return {"ok": True, "repost_id": repost_id, "repost_count": new_count}


@router.delete("/posts/{post_id}/repost")
def undo_repost(post_id: str, user_id: UserIdDep):
    """Undo a repost — removes the repost entity, decrements count, cleans up fan-out."""
    existing = ddb_get_item({"pk": pk_repost(user_id), "sk": f"POST#{post_id}"})
    if not existing:
        raise HTTPException(status_code=404, detail={"code": "repost_not_found", "message": "Repost not found"})

    repost_id = existing.get("repost_id", "")

    # 1. Delete the repost entity
    ddb_delete_item({"pk": pk_repost(user_id), "sk": f"POST#{post_id}"})

    # 2. Decrement repost_count (clamped at 0)
    new_count = 0
    try:
        updated = ddb_update_item(
            key={"pk": pk_post(post_id), "sk": sk_post()},
            update_expr="SET repost_count = repost_count - :one",
            expr_vals={":one": 1, ":z": 0},
            condition_expr="repost_count > :z",
            return_values="ALL_NEW",
        )
        new_count = int(updated.get("repost_count", 0))
    except HTTPException as ex:
        if ex.status_code != 409:
            raise
        # Count already at 0

    # 3. Clean up fan-out feed references for this repost
    try:
        # Query all FEEDREF items for this post that match this repost
        kwargs = {
            "KeyConditionExpression": "pk = :pk",
            "FilterExpression": "repost_id = :rid",
            "ExpressionAttributeValues": {
                ":pk": f"POST#{post_id}",
                ":rid": repost_id,
            },
            "Limit": 1000,
        }
        while True:
            resp = tbl.query(**kwargs)
            items = resp.get("Items", [])
            for item in items:
                try:
                    tbl.delete_item(Key={"pk": item["pk"], "sk": item["sk"]})
                except Exception:
                    logger.exception("Failed to delete repost feed ref pk=%s sk=%s", item["pk"], item["sk"])
            lek = resp.get("LastEvaluatedKey")
            if not lek:
                break
            kwargs["ExclusiveStartKey"] = lek
    except Exception:
        logger.exception("Repost fan-out cleanup failed for repost %s", repost_id)

    return {"ok": True, "repost_count": new_count}


@router.get("/posts/{post_id}/reposts")
def list_reposts(
    post_id: str,
    user_id: UserIdDep,
    limit: int = Query(default=20, ge=1, le=50),
    cursor: Optional[str] = Query(default=None),
):
    """List users who reposted a given post."""
    eks = decode_cursor_or_400(cursor)
    query_kwargs: Dict[str, Any] = {
        "IndexName": "GSI1",
        "KeyConditionExpression": "GSI1PK = :pk",
        "ExpressionAttributeValues": {":pk": f"REPOSTS#{post_id}"},
        "ScanIndexForward": False,
        "Limit": limit,
    }
    if eks:
        query_kwargs["ExclusiveStartKey"] = eks
    resp = ddb_query(**query_kwargs)
    items = resp.get("Items", [])
    next_cursor = encode_cursor(resp.get("LastEvaluatedKey"))

    reposts = []
    for item in items:
        uid = item.get("user_id", "")
        # Try to get display name from profile
        display_name = uid
        try:
            profile = T.profile.get_item(Key={"user_sub": uid}).get("Item")
            if profile:
                display_name = profile.get("display_name") or profile.get("name") or uid
        except Exception:
            pass
        reposts.append({
            "repost_id": item.get("repost_id"),
            "user_id": uid,
            "display_name": display_name,
            "quote": item.get("quote"),
            "created_at": item.get("created_at", ""),
        })

    return {
        "reposts": reposts,
        "next_cursor": next_cursor,
        "total_count": len(reposts),
    }


# ──────────────────────────────────────────────────────────────────────────────
# Bookmarks (SOCIAL-001)
# ──────────────────────────────────────────────────────────────────────────────

def pk_bookmark(user_id: str) -> str:
    return f"BOOKMARK#{user_id}"


def pk_bookmark_lookup(user_id: str) -> str:
    return f"BOOKMARK_LOOKUP#{user_id}"


class CreateBookmarkRequest(BaseModel):
    content_type: Literal["post", "video"] = "post"
    content_id: str = Field(..., min_length=1, max_length=64, pattern=r"^[a-zA-Z0-9_]+$")
    collection_id: Optional[str] = Field(default="default", max_length=64, pattern=r"^[a-zA-Z0-9_]+$")


class CreateCollectionRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)


class RenameCollectionRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)


class MoveBookmarkRequest(BaseModel):
    collection_id: str = Field(..., min_length=1, max_length=64, pattern=r"^[a-zA-Z0-9_]+$")


@router.post("/ui/bookmarks", status_code=201)
def create_bookmark(req: CreateBookmarkRequest, user_id: UserIdDep):
    content_type = req.content_type
    content_id = req.content_id
    collection_id = req.collection_id or "default"

    # Verify content exists
    if content_type == "post":
        post = ddb_get_item({"pk": pk_post(content_id), "sk": sk_post()})
        if not post:
            raise HTTPException(status_code=404, detail={"code": "content_not_found", "message": "Post not found"})

    # Check for duplicate
    existing = ddb_get_item({"pk": pk_bookmark_lookup(user_id), "sk": f"{content_type}#{content_id}"})
    if existing:
        raise HTTPException(status_code=409, detail={"code": "already_bookmarked", "message": "Already bookmarked"})

    created_at = now_iso()
    # Write main bookmark item (chronological listing via GSI1)
    bookmark_item = {
        "pk": pk_bookmark(user_id),
        "sk": f"{content_type}#{content_id}",
        "Entity": "Bookmark",
        "user_id": user_id,
        "content_type": content_type,
        "content_id": content_id,
        "collection_id": collection_id,
        "created_at": created_at,
        "GSI1PK": pk_bookmark(user_id),
        "GSI1SK": f"{created_at}#{content_type}#{content_id}",
    }
    ddb_put_item(bookmark_item)

    # Write lookup item (fast "is bookmarked?" check)
    lookup_item = {
        "pk": pk_bookmark_lookup(user_id),
        "sk": f"{content_type}#{content_id}",
        "Entity": "BookmarkLookup",
        "user_id": user_id,
        "content_type": content_type,
        "content_id": content_id,
        "collection_id": collection_id,
        "created_at": created_at,
    }
    ddb_put_item(lookup_item)

    return {
        "ok": True,
        "content_type": content_type,
        "content_id": content_id,
        "collection_id": collection_id,
        "created_at": created_at,
    }


@router.delete("/ui/bookmarks/{content_type}/{content_id}")
def delete_bookmark(content_type: str, content_id: str, user_id: UserIdDep):
    # Check existence via lookup
    existing = ddb_get_item({"pk": pk_bookmark_lookup(user_id), "sk": f"{content_type}#{content_id}"})
    if not existing:
        raise HTTPException(status_code=404, detail={"code": "bookmark_not_found", "message": "Bookmark not found"})

    # Delete main bookmark item
    ddb_delete_item({"pk": pk_bookmark(user_id), "sk": f"{content_type}#{content_id}"})
    # Delete lookup item
    ddb_delete_item({"pk": pk_bookmark_lookup(user_id), "sk": f"{content_type}#{content_id}"})

    return {"ok": True}


@router.patch("/ui/bookmarks/{content_type}/{content_id}")
def move_bookmark(content_type: str, content_id: str, req: MoveBookmarkRequest, user_id: UserIdDep):
    """GAP-0357 sub-gap 2: move an existing bookmark to a different collection.

    Owner-scoped: the bookmark is keyed by the caller's ``user_id`` partition,
    so a user can only ever move their own bookmarks (a foreign / missing
    bookmark yields 404).
    """
    sk = f"{content_type}#{content_id}"
    # Owner-scoped existence check (also confirms the caller owns it).
    existing = ddb_get_item({"pk": pk_bookmark(user_id), "sk": sk})
    if not existing:
        raise HTTPException(status_code=404, detail={"code": "bookmark_not_found", "message": "Bookmark not found"})

    new_collection_id = req.collection_id

    # Update the main bookmark item.
    ddb_update_item(
        key={"pk": pk_bookmark(user_id), "sk": sk},
        update_expr="SET collection_id = :c",
        expr_vals={":c": new_collection_id},
        return_values="NONE",
    )
    # Keep the lookup item in sync (best-effort; it may not exist for legacy rows).
    try:
        ddb_update_item(
            key={"pk": pk_bookmark_lookup(user_id), "sk": sk},
            update_expr="SET collection_id = :c",
            expr_vals={":c": new_collection_id},
            return_values="NONE",
        )
    except Exception:
        logger.warning("bookmark lookup collection sync failed for %s/%s", content_type, content_id, exc_info=True)

    return {
        "ok": True,
        "content_type": content_type,
        "content_id": content_id,
        "collection_id": new_collection_id,
    }


@router.get("/ui/bookmarks")
def list_bookmarks(
    user_id: UserIdDep,
    limit: int = Query(default=24, ge=1, le=100),
    cursor: Optional[str] = Query(default=None),
    content_type: Optional[str] = Query(default=None),
    collection_id: Optional[str] = Query(default=None),
):
    eks = decode_cursor_or_400(cursor)

    query_kwargs: Dict[str, Any] = {
        "IndexName": "GSI1",
        "KeyConditionExpression": "GSI1PK = :pk",
        "ExpressionAttributeValues": {":pk": pk_bookmark(user_id)},
        "ScanIndexForward": False,
        "Limit": limit,
    }

    filter_parts: List[str] = []
    if content_type:
        query_kwargs["ExpressionAttributeValues"][":ct"] = content_type
        filter_parts.append("content_type = :ct")
    if collection_id:
        query_kwargs["ExpressionAttributeValues"][":col"] = collection_id
        filter_parts.append("collection_id = :col")
    if filter_parts:
        query_kwargs["FilterExpression"] = " AND ".join(filter_parts)

    if eks:
        query_kwargs["ExclusiveStartKey"] = eks

    resp = ddb_query(**query_kwargs)
    items = resp.get("Items", [])

    # Enrich bookmarks with content previews
    bookmarks = []
    for item in items:
        ct = item.get("content_type", "post")
        cid = item.get("content_id", "")
        preview: Dict[str, Any] = {}

        if ct == "post":
            post = ddb_get_item({"pk": pk_post(cid), "sk": sk_post()})
            if post:
                post_dict = _post_to_dict(post, viewer_id=user_id)
                author_id = post_dict.get("author_id", "")
                preview = {
                    "author_id": author_id,
                    # GAP-0357 sub-gap 3: resolve the human-readable display name
                    # instead of copying the author UUID.
                    "author_display_name": _post_fadt_display_name(author_id),
                    "body_snippet": (post_dict.get("body", "") or "")[:200],
                    "image_url": (post_dict.get("image_urls") or [None])[0],
                    "like_count": post_dict.get("like_count", 0),
                }
            else:
                preview = {"author_id": "", "body_snippet": "[Post removed]"}
        elif ct == "video":
            # GAP-0357 sub-gap 3: enrich video bookmarks with video metadata
            # (mirrors the post branch). Previously these returned an empty
            # content_preview and rendered as "[No content]" in the UI.
            try:
                from app.services.video_metadata_store import get_video as _bk_get_video
                _vid = _bk_get_video(cid)
                preview = {
                    "video_id": cid,
                    "title": _vid.title,
                    "thumbnail_url": _vid.thumbnail_url,
                    "creator_id": _vid.owner_user_id,
                    "creator_display_name": _post_fadt_display_name(_vid.owner_user_id),
                    "duration_seconds": _vid.duration_seconds,
                    "view_count": _vid.view_count,
                }
            except Exception:
                preview = {"video_id": cid, "title": "[Video removed]"}

        bookmarks.append({
            "content_type": ct,
            "content_id": cid,
            "collection_id": item.get("collection_id", "default"),
            "created_at": item.get("created_at", ""),
            "content_preview": preview,
        })

    next_cursor = encode_cursor(resp.get("LastEvaluatedKey"))
    return {
        "bookmarks": bookmarks,
        "next_cursor": next_cursor,
        "total_count": len(bookmarks),
    }


@router.get("/ui/bookmarks/status")
def bookmark_status(
    user_id: UserIdDep,
    ids: str = Query(default=""),
):
    if not ids.strip():
        return {"statuses": {}}

    parsed = []
    for raw in ids.split(","):
        raw = raw.strip()
        if ":" not in raw:
            continue
        ctype, cid = raw.split(":", 1)
        parsed.append((ctype, cid))

    if len(parsed) > 25:
        raise HTTPException(status_code=400, detail="Max 25 items per request")

    statuses: Dict[str, bool] = {}
    for ctype, cid in parsed:
        key = f"{ctype}:{cid}"
        existing = ddb_get_item({"pk": pk_bookmark_lookup(user_id), "sk": f"{ctype}#{cid}"})
        statuses[key] = existing is not None

    return {"statuses": statuses}


# ── Bookmark Collections ─────────────────────────────────────────

def pk_bmcol(user_id: str) -> str:
    return f"BMCOL#{user_id}"


@router.post("/ui/bookmark-collections", status_code=201)
def create_collection(req: CreateCollectionRequest, user_id: UserIdDep):
    # Check collection limit
    resp = ddb_query(
        KeyConditionExpression="pk = :pk AND begins_with(sk, :prefix)",
        ExpressionAttributeValues={":pk": pk_bmcol(user_id), ":prefix": "COL#"},
        Select="COUNT",
    )
    count = resp.get("Count", 0)
    max_collections = int(getattr(S, "bookmarks_max_collections", 50) or 50)
    if count >= max_collections:
        raise HTTPException(status_code=400, detail={"code": "max_collections_reached", "message": f"Max {max_collections} collections"})

    collection_id = f"col_{uuid.uuid4().hex[:12]}"
    created_at = now_iso()
    item = {
        "pk": pk_bmcol(user_id),
        "sk": f"COL#{collection_id}",
        "Entity": "BookmarkCollection",
        "user_id": user_id,
        "collection_id": collection_id,
        "name": req.name.strip()[:100],
        "item_count": 0,
        "created_at": created_at,
        "updated_at": created_at,
    }
    ddb_put_item(item)

    return {
        "ok": True,
        "collection_id": collection_id,
        "name": req.name.strip()[:100],
        "item_count": 0,
        "created_at": created_at,
    }


@router.get("/ui/bookmark-collections")
def list_collections(user_id: UserIdDep):
    resp = ddb_query(
        KeyConditionExpression="pk = :pk AND begins_with(sk, :prefix)",
        ExpressionAttributeValues={":pk": pk_bmcol(user_id), ":prefix": "COL#"},
    )
    collections = []
    for item in resp.get("Items", []):
        collections.append({
            "collection_id": item.get("collection_id", ""),
            "name": item.get("name", ""),
            "item_count": int(item.get("item_count", 0)),
            "created_at": item.get("created_at", ""),
        })
    return {"collections": collections}


@router.patch("/ui/bookmark-collections/{collection_id}")
def rename_collection(collection_id: str, req: RenameCollectionRequest, user_id: UserIdDep):
    key = {"pk": pk_bmcol(user_id), "sk": f"COL#{collection_id}"}
    existing = ddb_get_item(key)
    if not existing:
        raise HTTPException(status_code=404, detail="Collection not found")

    updated_at = now_iso()
    ddb_update_item(
        key=key,
        update_expr="SET #n = :name, updated_at = :ua",
        expr_vals={":name": req.name.strip()[:100], ":ua": updated_at},
        expr_names={"#n": "name"},
    )
    return {"ok": True, "collection_id": collection_id, "name": req.name.strip()[:100]}


@router.delete("/ui/bookmark-collections/{collection_id}")
def delete_collection(collection_id: str, user_id: UserIdDep):
    key = {"pk": pk_bmcol(user_id), "sk": f"COL#{collection_id}"}
    existing = ddb_get_item(key)
    if not existing:
        raise HTTPException(status_code=404, detail="Collection not found")

    # Move bookmarks in this collection to "default"
    moved_count = 0
    resp = ddb_query(
        IndexName="GSI1",
        KeyConditionExpression="GSI1PK = :pk",
        ExpressionAttributeValues={":pk": pk_bookmark(user_id)},
        ScanIndexForward=False,
    )
    for item in resp.get("Items", []):
        if item.get("collection_id") == collection_id:
            bm_key = {"pk": pk_bookmark(user_id), "sk": item["sk"]}
            ddb_update_item(
                key=bm_key,
                update_expr="SET collection_id = :col",
                expr_vals={":col": "default"},
            )
            # Also update lookup item
            lookup_key = {"pk": pk_bookmark_lookup(user_id), "sk": item["sk"]}
            try:
                ddb_update_item(
                    key=lookup_key,
                    update_expr="SET collection_id = :col",
                    expr_vals={":col": "default"},
                )
            except Exception:
                pass
            moved_count += 1

    # Delete the collection
    ddb_delete_item(key)

    return {"ok": True, "moved_count": moved_count}


# ─── Bulk Operations (UX-004) ────────────────────────────────────────────────


class PostBulkDeleteReq(BaseModel):
    post_ids: List[str] = Field(..., min_length=1, max_length=50)


class PostBulkArchiveReq(BaseModel):
    post_ids: List[str] = Field(..., min_length=1, max_length=50)


@router.post("/posts/bulk-delete")
def bulk_delete_posts(body: PostBulkDeleteReq, user_id: UserIdDep):
    """Bulk-delete posts. Deletes posts permanently. Only posts owned by the authenticated user."""
    results = []
    for post_id in body.post_ids:
        try:
            post = ddb_get_item({"pk": pk_post(post_id), "sk": sk_post()})
            if not post:
                results.append({"post_id": post_id, "ok": False, "error": "not_found"})
                continue
            if post.get("user_id") != user_id:
                results.append({"post_id": post_id, "ok": False, "error": "not_owner"})
                continue
            tbl.delete_item(Key={"pk": pk_post(post_id), "sk": sk_post()})
            try:
                from app.services.newsfeed_fanout import fan_out_delete_post
                fan_out_delete_post(post_id=post_id)
            except Exception:
                pass
            results.append({"post_id": post_id, "ok": True})
        except Exception as e:
            results.append({"post_id": post_id, "ok": False, "error": str(e)})

    succeeded = sum(1 for r in results if r["ok"])
    failed = sum(1 for r in results if not r["ok"])
    return {"results": results, "succeeded": succeeded, "failed": failed}


@router.post("/posts/bulk-archive")
def bulk_archive_posts(body: PostBulkArchiveReq, user_id: UserIdDep):
    """Bulk-archive posts. Sets status='archived' on each post. Only posts owned by the authenticated user."""
    results = []
    for post_id in body.post_ids:
        try:
            post = ddb_get_item({"pk": pk_post(post_id), "sk": sk_post()})
            if not post:
                results.append({"post_id": post_id, "ok": False, "error": "not_found"})
                continue
            if post.get("user_id") != user_id:
                results.append({"post_id": post_id, "ok": False, "error": "not_owner"})
                continue
            ddb_update_item(
                key={"pk": pk_post(post_id), "sk": sk_post()},
                update_expr="SET #status = :archived, archived_at = :ts",
                expr_names={"#status": "status"},
                expr_vals={":archived": "archived", ":ts": now_iso()},
            )
            results.append({"post_id": post_id, "ok": True})
        except Exception as e:
            results.append({"post_id": post_id, "ok": False, "error": str(e)})

    succeeded = sum(1 for r in results if r["ok"])
    failed = sum(1 for r in results if not r["ok"])
    return {"results": results, "succeeded": succeeded, "failed": failed}


# -----------------------------
# Health
# -----------------------------
# ─── ENGAGE-002: Poll Endpoints ──────────────────────────────────────────────


@router.post("/posts/{post_id}/vote")
def vote_on_poll(post_id: str, body: VoteIn, user_id: UserIdDep):
    """Cast or change a vote on a poll/survey post."""
    post = ddb_get_item({"pk": pk_post(post_id), "sk": sk_post()})
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")

    # ── GAP-0164 fix: enforce visibility/subscription gate ──────────────────
    # Check access BEFORE revealing post type so a gated post does not become an
    # enumeration oracle (400 "not a poll" vs 403 leaks classification).
    post_author = str(post.get("user_id") or "").strip()
    if post_author and post_author != user_id and not can_view_post(user_id, post):
        raise HTTPException(status_code=403, detail="Not authorized to view this post")
    # ────────────────────────────────────────────────────────────────────────

    if post.get("post_type") not in ("poll", "survey"):
        raise HTTPException(status_code=400, detail="Post is not a poll")

    from app.services.newsfeed_polls import cast_vote, get_user_vote_for_question, get_user_multi_votes
    updated_counts = cast_vote(
        post=post,
        post_id=post_id,
        question_id=body.question_id,
        option_id=body.option_id,
        user_sub=user_id,
    )

    # Re-fetch post to get updated state
    refreshed = ddb_get_item({"pk": pk_post(post_id), "sk": sk_post()})
    total_votes = int(refreshed.get("poll_total_votes", 0)) if refreshed else 0
    poll_data = (refreshed or post).get("poll_data", {})
    question = None
    for q in poll_data.get("questions", []):
        if q.get("question_id") == body.question_id:
            question = q
            break
    choice_mode = question.get("choice_mode", "single") if question else "single"

    my_vote = None
    my_votes = None
    if choice_mode == "single":
        my_vote = get_user_vote_for_question(refreshed or post, body.question_id, user_id)
    else:
        my_votes = list(get_user_multi_votes(refreshed or post, body.question_id, user_id))

    # ── GAP-0163 fix: publish real-time poll:vote SSE event to post author ───
    # Mirrors the established put_notification pattern (sync handler runs in a
    # threadpool with no running loop, so RuntimeError is caught and dropped;
    # cross-worker delivery requires the SNS/SQS fan-out noted on SSEHub).
    if post_author:
        sse_payload = {
            "type": "poll:vote",
            "post_id": post_id,
            "question_id": body.question_id,
            "option_id": body.option_id,
            "vote_counts": updated_counts,
            "total_votes": total_votes,
            "voter_sub": user_id,
        }
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(sse_hub.publish(post_author, sse_payload))
        except RuntimeError:
            # Sync threadpool context — no running loop; SSE push not possible.
            pass
    # ────────────────────────────────────────────────────────────────────────

    return {
        "ok": True,
        "question_id": body.question_id,
        "option_id": body.option_id,
        "vote_counts": updated_counts,
        "total_votes": total_votes,
        "my_vote": my_vote,
        "my_votes": my_votes,
    }


@router.delete("/posts/{post_id}/vote")
def remove_poll_vote(post_id: str, question_id: str = Query(...), user_id: UserIdDep = None):
    """Remove user's vote on a poll question."""
    post = ddb_get_item({"pk": pk_post(post_id), "sk": sk_post()})
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
    if post.get("post_type") not in ("poll", "survey"):
        raise HTTPException(status_code=400, detail="Post is not a poll")

    from app.services.newsfeed_polls import remove_vote
    updated_counts = remove_vote(
        post=post,
        post_id=post_id,
        question_id=question_id,
        user_sub=user_id,
    )

    refreshed = ddb_get_item({"pk": pk_post(post_id), "sk": sk_post()})
    total_votes = int(refreshed.get("poll_total_votes", 0)) if refreshed else 0

    return {
        "ok": True,
        "question_id": question_id,
        "vote_counts": updated_counts,
        "total_votes": total_votes,
        "my_vote": None,
    }


@router.post("/posts/{post_id}/close-poll")
def close_poll_endpoint(post_id: str, user_id: UserIdDep):
    """Close a poll early. Only the post author can do this."""
    post = ddb_get_item({"pk": pk_post(post_id), "sk": sk_post()})
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
    if post.get("post_type") not in ("poll", "survey"):
        raise HTTPException(status_code=400, detail="Post is not a poll")

    from app.services.newsfeed_polls import close_poll
    return close_poll(post=post, post_id=post_id, user_sub=user_id)


@router.get("/posts/{post_id}/poll-results")
def get_poll_results_endpoint(post_id: str, question_id: str = Query(...), user_id: UserIdDep = None):
    """Get detailed poll results for a specific question."""
    post = ddb_get_item({"pk": pk_post(post_id), "sk": sk_post()})
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
    if post.get("post_type") not in ("poll", "survey"):
        raise HTTPException(status_code=400, detail="Post is not a poll")

    from app.services.newsfeed_polls import get_poll_results
    return get_poll_results(post=post, question_id=question_id, viewer_id=user_id)


@router.get("/health")
def health():
    return {
        "ok": True,
        "ts": int(time.time()),
        "uploads_enabled": bool(UPLOAD_BUCKET),
        "sse_fanout_enabled": bool(EVENTS_SQS_URL),
        "table": APP_TABLE,
        "region": AWS_REGION,
    }
