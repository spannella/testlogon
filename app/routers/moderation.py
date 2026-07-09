from __future__ import annotations

import hashlib
import logging
import os
import time
from typing import Any, Dict, List, Literal, Optional

from boto3.dynamodb.conditions import Attr, Key
from botocore.exceptions import ClientError
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, field_validator

from app.core.aws import ddb
from app.core.tables import T
from app.core.normalize import client_ip_from_request
from app.services.alerts import audit_event, write_alert
from app.services.content_reports_store import create_content_report
from app.services.moderation_audit_log import write_moderation_audit_event
from app.services.moderation_tickets_store import upsert_open_ticket_for_report
from app.services.moderation_flags import ensure_reporting_surface_enabled
from app.services.sessions import require_ui_session

APP_TABLE = os.environ.get("APP_TABLE", "app_single_table")
MESSAGES_TABLE = os.environ.get("DDB_MESSAGES", "Messages")
IDEMPOTENCY_WINDOW_SECONDS = 45
RATE_LIMIT_USER_WINDOW_SECONDS = int(os.environ.get("MODERATION_REPORT_RATE_LIMIT_USER_WINDOW_SECONDS", "60"))
RATE_LIMIT_USER_MAX = int(os.environ.get("MODERATION_REPORT_RATE_LIMIT_USER_MAX", "8"))
RATE_LIMIT_IP_WINDOW_SECONDS = int(os.environ.get("MODERATION_REPORT_RATE_LIMIT_IP_WINDOW_SECONDS", "60"))
RATE_LIMIT_IP_MAX = int(os.environ.get("MODERATION_REPORT_RATE_LIMIT_IP_MAX", "20"))
ALLOWED_TOPICS = {"sexual", "extortion", "criminal", "spam", "racist", "harassment", "hate", "violence_threats", "other"}

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1/moderation", tags=["moderation"])


class CreateModerationReportIn(BaseModel):
    content_type: Literal["feed_post", "feed_comment", "feed_media", "message", "message_media", "profile_photo"]
    content_id: str = Field(min_length=1, max_length=256)
    topics: List[str] = Field(min_length=1, max_length=5)
    reason_text: str = Field(min_length=5, max_length=2000)
    post_id: Optional[str] = Field(default=None, max_length=256)
    conversation_id: Optional[str] = Field(default=None, max_length=256)
    media_index: Optional[int] = Field(default=None, ge=0)

    @field_validator("topics")
    @classmethod
    def _validate_topics(cls, value: List[str]) -> List[str]:
        normalized = [v.strip().lower() for v in value if v and v.strip()]
        if not normalized:
            raise ValueError("at least one topic is required")
        for topic in normalized:
            if topic not in ALLOWED_TOPICS:
                raise ValueError(f"invalid topic: {topic}")
        return list(dict.fromkeys(normalized))


class CreateModerationReportOut(BaseModel):
    ok: bool
    report_id: str
    ticket_id: str
    status: Literal["submitted", "deduplicated"]
    created_at: int


# Backward-compatible alias for existing frontend calls.
compat_router = APIRouter(prefix="/moderation", tags=["moderation"])


def _linked_ticket_id(content_type: str, content_id: str) -> str:
    digest = hashlib.sha256(f"{content_type}:{content_id}".encode("utf-8")).hexdigest()[:20]
    return f"modtk_{digest}"


def _feed_post_exists(post_id: str) -> bool:
    table = ddb.Table(APP_TABLE)
    item = table.get_item(Key={"pk": f"POST#{post_id}", "sk": "META"}).get("Item")
    return bool(item)


def _feed_comment_exists(post_id: str, comment_id: str) -> bool:
    table = ddb.Table(APP_TABLE)
    resp = table.query(
        KeyConditionExpression=Key("pk").eq(f"POST#{post_id}#COMMENTS"),
        FilterExpression=Attr("comment_id").eq(comment_id),
        Limit=1,
    )
    return bool(resp.get("Items"))


def _feed_media_exists(post_id: str, media_index: Optional[int]) -> bool:
    table = ddb.Table(APP_TABLE)
    post = table.get_item(Key={"pk": f"POST#{post_id}", "sk": "META"}).get("Item")
    if not post:
        return False
    images = post.get("image_urls") or []
    if not isinstance(images, list) or not images:
        return False
    if media_index is None:
        return True
    return 0 <= int(media_index) < len(images)


def _message_exists(conversation_id: str, message_id: str) -> bool:
    table = ddb.Table(MESSAGES_TABLE)
    item = table.get_item(Key={"conversation_id": conversation_id, "message_id": message_id}).get("Item")
    return bool(item)


def _profile_photo_exists(user_id: str) -> bool:
    item = T.profile.get_item(Key={"user_id": user_id}).get("Item") or {}
    return bool(item.get("profile_photo_url"))


def _validate_content_exists(inp: CreateModerationReportIn) -> None:
    if inp.content_type == "feed_post":
        if not _feed_post_exists(inp.content_id):
            raise HTTPException(status_code=404, detail="content not found")
        return

    if inp.content_type == "feed_comment":
        if not inp.post_id:
            raise HTTPException(status_code=400, detail="post_id is required for feed_comment")
        if not _feed_comment_exists(inp.post_id, inp.content_id):
            raise HTTPException(status_code=404, detail="content not found")
        return

    if inp.content_type == "feed_media":
        if not inp.post_id:
            raise HTTPException(status_code=400, detail="post_id is required for feed_media")
        if not _feed_media_exists(inp.post_id, inp.media_index):
            raise HTTPException(status_code=404, detail="content not found")
        return

    if inp.content_type in {"message", "message_media"}:
        if not inp.conversation_id:
            raise HTTPException(status_code=400, detail="conversation_id is required for message content")
        if not _message_exists(inp.conversation_id, inp.content_id):
            raise HTTPException(status_code=404, detail="content not found")
        return

    if inp.content_type == "profile_photo":
        if not _profile_photo_exists(inp.content_id):
            raise HTTPException(status_code=404, detail="content not found")


def _hash_ip(ip: str) -> str:
    return hashlib.sha256(ip.encode("utf-8")).hexdigest()[:24]


def _query_report_count(*, index_name: str, partition_key_name: str, partition_key_value: str, since_ts: int, limit: int) -> int:
    resp = T.content_reports.query(
        IndexName=index_name,
        KeyConditionExpression=Key(partition_key_name).eq(partition_key_value) & Key("created_at").gte(str(since_ts)),
        ScanIndexForward=False,
        Limit=max(1, limit),
        Select="COUNT",
    )
    return int(resp.get("Count", 0) or 0)


def _query_ip_report_count(*, ip_hash: str, since_ts: int, limit: int) -> int:
    resp = T.content_reports.query(
        IndexName="ByCreatedAt",
        KeyConditionExpression=Key("created_scope").eq("ALL") & Key("created_at").gte(str(since_ts)),
        FilterExpression=Attr("ip_hash").eq(ip_hash),
        ScanIndexForward=False,
        Limit=max(1, limit),
    )
    return int(resp.get("Count", 0) or 0)


def _enforce_rate_limits(*, reporter_user_id: str, ip_hash: str, now_ts: int, request: Request | None, content_type: str, content_id: str) -> None:
    user_count = _query_report_count(
        index_name="ByReporterCreatedAt",
        partition_key_name="reporter_user_id",
        partition_key_value=reporter_user_id,
        since_ts=now_ts - RATE_LIMIT_USER_WINDOW_SECONDS,
        limit=RATE_LIMIT_USER_MAX,
    )
    if user_count >= RATE_LIMIT_USER_MAX:
        audit_event(
            "moderation_report_rate_limited",
            reporter_user_id,
            request,
            outcome="rate_limited",
            scope="user",
            count=user_count,
            window_seconds=RATE_LIMIT_USER_WINDOW_SECONDS,
            content_type=content_type,
            content_id=content_id,
        )
        raise HTTPException(
            status_code=429,
            detail="Rate limit exceeded for moderation reports",
            headers={"Retry-After": str(RATE_LIMIT_USER_WINDOW_SECONDS)},
        )

    ip_count = _query_ip_report_count(
        ip_hash=ip_hash,
        since_ts=now_ts - RATE_LIMIT_IP_WINDOW_SECONDS,
        limit=RATE_LIMIT_IP_MAX,
    )
    if ip_count >= RATE_LIMIT_IP_MAX:
        audit_event(
            "moderation_report_rate_limited",
            reporter_user_id,
            request,
            outcome="rate_limited",
            scope="ip",
            count=ip_count,
            window_seconds=RATE_LIMIT_IP_WINDOW_SECONDS,
            content_type=content_type,
            content_id=content_id,
        )
        raise HTTPException(
            status_code=429,
            detail="Rate limit exceeded for moderation reports",
            headers={"Retry-After": str(RATE_LIMIT_IP_WINDOW_SECONDS)},
        )


def _run_anti_spam_heuristics(*, reporter_user_id: str, inp: CreateModerationReportIn, request: Request | None) -> None:
    reason = inp.reason_text.strip().lower()
    suspicious = []
    if "http://" in reason or "https://" in reason:
        suspicious.append("contains_url")
    if len(set(reason)) <= 3 and len(reason) > 20:
        suspicious.append("low_entropy_text")
    if reason.count("!") >= 8:
        suspicious.append("excessive_punctuation")

    if suspicious:
        logger.warning(
            "moderation report anti-spam signal",
            extra={"reporter_user_id": reporter_user_id, "signals": suspicious, "content_type": inp.content_type, "content_id": inp.content_id},
        )
        audit_event(
            "moderation_report_anti_spam_signal",
            reporter_user_id,
            request,
            outcome="warning",
            signals=suspicious,
            content_type=inp.content_type,
            content_id=inp.content_id,
        )


def _find_recent_duplicate(*, reporter_user_id: str, content_type: str, content_id: str, now_ts: int) -> Dict[str, Any] | None:
    earliest = str(now_ts - IDEMPOTENCY_WINDOW_SECONDS)
    resp = T.content_reports.query(
        IndexName="ByReporterCreatedAt",
        KeyConditionExpression=Key("reporter_user_id").eq(reporter_user_id) & Key("created_at").gte(earliest),
        ScanIndexForward=False,
        Limit=20,
    )
    for item in resp.get("Items", []):
        if item.get("entity_type") != "content_report":
            continue
        if item.get("content_type") == content_type and item.get("content_id") == content_id:
            return item
    return None


def _create_report(inp: CreateModerationReportIn, ctx: Dict[str, str], request: Request | None = None) -> CreateModerationReportOut:
    reporter_user_id = str(ctx.get("user_sub") or "").strip()
    if not reporter_user_id:
        raise HTTPException(status_code=401, detail="Unauthorized")

    ensure_reporting_surface_enabled(inp.content_type)
    _validate_content_exists(inp)
    now_ts = int(time.time())
    ip = client_ip_from_request(request) if request is not None else str(ctx.get("ip") or "")
    ip_hash = _hash_ip(ip or "unknown")

    _enforce_rate_limits(
        reporter_user_id=reporter_user_id,
        ip_hash=ip_hash,
        now_ts=now_ts,
        request=request,
        content_type=inp.content_type,
        content_id=inp.content_id,
    )
    _run_anti_spam_heuristics(reporter_user_id=reporter_user_id, inp=inp, request=request)

    duplicate = _find_recent_duplicate(
        reporter_user_id=reporter_user_id,
        content_type=inp.content_type,
        content_id=inp.content_id,
        now_ts=now_ts,
    )
    if duplicate:
        ticket_id = str(duplicate.get("ticket_id") or _linked_ticket_id(inp.content_type, inp.content_id))
        report_id = str(duplicate.get("report_id") or "")
        write_moderation_audit_event(
            action="report_deduplicated",
            actor_user_id=reporter_user_id,
            ticket_id=ticket_id,
            report_id=report_id,
            content_type=inp.content_type,
            content_id=inp.content_id,
            metadata={"idempotency_window_seconds": IDEMPOTENCY_WINDOW_SECONDS},
        )
        write_alert(
            reporter_user_id,
            event="moderation_report_received",
            outcome="success",
            title="Report received",
            details={"report_id": report_id, "ticket_id": ticket_id, "status": "deduplicated"},
        )
        return CreateModerationReportOut(
            ok=True,
            report_id=report_id,
            ticket_id=ticket_id,
            status="deduplicated",
            created_at=int(str(duplicate.get("created_at") or now_ts)),
        )

    ticket_result = upsert_open_ticket_for_report(
        content_type=inp.content_type,
        content_id=inp.content_id,
        topics=inp.topics,
        now_ts=now_ts,
    )
    ticket_id = str(ticket_result.get("ticket_id") or _linked_ticket_id(inp.content_type, inp.content_id))
    try:
        report_id = create_content_report(
            reporter_user_id=reporter_user_id,
            content_type=inp.content_type,
            content_id=inp.content_id,
            topics=inp.topics,
            reason_text=inp.reason_text,
            linked_ticket_id=ticket_id,
            metadata={
                "post_id": inp.post_id,
                "conversation_id": inp.conversation_id,
                "media_index": inp.media_index,
                "ip_hash": ip_hash,
            },
        )
    except ClientError as exc:
        raise HTTPException(status_code=422, detail="invalid report payload") from exc

    write_moderation_audit_event(
        action="report_created",
        actor_user_id=reporter_user_id,
        ticket_id=ticket_id,
        report_id=report_id,
        content_type=inp.content_type,
        content_id=inp.content_id,
        metadata={"topics": inp.topics},
    )
    # MOD-A3: aggregate the report onto the moderation_case, apply the guarded
    # auto-hide (severe=1 report; lower>=3 or trusted reporter), and notify the
    # poster when hidden. Best-effort: never breaks the report write.
    try:
        from app.services import moderation_case as _mod_case
        _mod_case.on_report_filed(
            content_type=inp.content_type,
            content_id=inp.content_id,
            topics=inp.topics,
            reporter_user_id=reporter_user_id,
            ticket_id=ticket_id,
            metadata={
                "post_id": inp.post_id,
                "conversation_id": inp.conversation_id,
                "media_index": inp.media_index,
                "video_id": getattr(inp, "video_id", None),
            },
            now_ts=now_ts,
        )
    except Exception:
        logger.exception("moderation_case.on_report_filed failed (report still recorded)")
    write_alert(
        reporter_user_id,
        event="moderation_report_received",
        outcome="success",
        title="Report received",
        details={"report_id": report_id, "ticket_id": ticket_id, "status": "submitted"},
    )

    return CreateModerationReportOut(
        ok=True,
        report_id=report_id,
        ticket_id=ticket_id,
        status="submitted",
        created_at=now_ts,
    )


@router.post("/reports", response_model=CreateModerationReportOut)
def create_moderation_report(inp: CreateModerationReportIn, request: Request, ctx=Depends(require_ui_session)):
    return _create_report(inp, ctx, request=request)


@compat_router.post("/reports", response_model=CreateModerationReportOut)
def create_moderation_report_compat(inp: CreateModerationReportIn, request: Request, ctx=Depends(require_ui_session)):
    return _create_report(inp, ctx, request=request)
