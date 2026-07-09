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
ALLOWED_TOPICS = {"sexual", "extortion", "criminal", "spam", "racist", "harassment", "hate", "violence_threats", "other", "licensing_ip"}

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1/moderation", tags=["moderation"])


class CreateModerationReportIn(BaseModel):
    content_type: Literal["feed_post", "feed_comment", "feed_media", "message", "message_media", "video", "video_comment", "profile_photo"]
    content_id: str = Field(min_length=1, max_length=256)
    topics: List[str] = Field(min_length=1, max_length=5)
    reason_text: str = Field(min_length=5, max_length=2000)
    post_id: Optional[str] = Field(default=None, max_length=256)
    conversation_id: Optional[str] = Field(default=None, max_length=256)
    video_id: Optional[str] = Field(default=None, max_length=256)
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

    if inp.content_type == "video":
        # MODVIDEO: whole-video report; content_id is the video_id.
        try:
            _v = T.video_metadata.get_item(Key={"video_id": inp.content_id}).get("Item")
        except Exception:
            _v = True
        if not _v:
            raise HTTPException(status_code=404, detail="content not found")
        return

    if inp.content_type == "video_comment":
        # MODVIDEO: comment on a video; video_id carries the parent.
        if not inp.video_id:
            raise HTTPException(status_code=400, detail="video_id is required for video_comment")
        try:
            from app.services.video_comments import get_comment
            try:
                _vc = get_comment(video_id=inp.video_id, comment_id=inp.content_id)
            except TypeError:
                _vc = get_comment(inp.video_id, inp.content_id)
        except Exception:
            _vc = None
        if not _vc:
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

    # MODAB (MOD-B1): licensing/IP reports go to the DMCA auto-hide pipeline, not a general ticket.
    if "licensing_ip" in inp.topics:
        return _route_licensing_report_to_dmca(inp, reporter_user_id, now_ts)

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


# ── MODAB (MOD-B1): route a licensing/IP report to the DMCA auto-hide pipeline ──
def _route_licensing_report_to_dmca(inp: "CreateModerationReportIn", reporter_user_id: str, now_ts: int) -> "CreateModerationReportOut":
    from app.services.dmca_claims import file_dmca_claim

    ct = inp.content_type
    dmca_ct = ct
    content_id = inp.content_id
    if ct in ("feed_media", "feed_post"):
        dmca_ct = "feed_post"
        content_id = (getattr(inp, "post_id", None) or inp.content_id) if ct == "feed_media" else inp.content_id
    elif ct in ("message", "message_media"):
        dmca_ct = "message_media"

    claim_input = {
        "claimant_name": reporter_user_id,
        "claimant_email": f"{reporter_user_id}@reporter.testlogon",
        "content_type": dmca_ct,
        "content_id": content_id,
        "original_work_description": inp.reason_text,
        "sworn_statement": True,
        "good_faith_belief": True,
        "signature": reporter_user_id,
    }
    result = file_dmca_claim(claim_input, reporter_user_id)
    claim_id = str(result.get("claim_id") or "")
    write_moderation_audit_event(
        action="report_routed_to_dmca",
        actor_user_id=reporter_user_id,
        ticket_id=claim_id,
        content_type=inp.content_type,
        content_id=inp.content_id,
        metadata={"claim_id": claim_id, "strike_number": result.get("strike_number")},
    )
    write_alert(
        reporter_user_id,
        event="moderation_report_received",
        outcome="success",
        title="Report received",
        details={"report_id": claim_id, "ticket_id": claim_id, "status": "submitted", "routed": "dmca_licensing"},
    )
    return CreateModerationReportOut(ok=True, report_id=claim_id, ticket_id=claim_id, status="submitted", created_at=now_ts)


# ── MODAB (MOD-A5): poster response to a 30-day content hold ──
class HoldRespondIn(BaseModel):
    statement: str = Field(min_length=1, max_length=2000)


class HoldActionOut(BaseModel):
    ok: bool
    case_id: str
    state: str


def _hold_respond(case_id: str, ctx: Dict[str, str], inp: HoldRespondIn) -> HoldActionOut:
    uid = str(ctx.get("user_sub") or "").strip()
    if not uid:
        raise HTTPException(status_code=401, detail="Unauthorized")
    from app.services import moderation_lifecycle as _life
    try:
        res = _life.poster_respond(case_id=case_id, owner_user_id=uid, statement=inp.statement)
    except PermissionError:
        raise HTTPException(status_code=403, detail="not the content owner")
    except ValueError as exc:
        msg = str(exc)
        if msg == "case_not_found":
            raise HTTPException(status_code=404, detail="case not found") from exc
        raise HTTPException(status_code=409, detail=msg) from exc
    return HoldActionOut(ok=True, case_id=case_id, state=str(res.get("state") or ""))


def _hold_close(case_id: str, ctx: Dict[str, str]) -> HoldActionOut:
    uid = str(ctx.get("user_sub") or "").strip()
    if not uid:
        raise HTTPException(status_code=401, detail="Unauthorized")
    from app.services import moderation_lifecycle as _life
    try:
        res = _life.poster_close(case_id=case_id, owner_user_id=uid)
    except PermissionError:
        raise HTTPException(status_code=403, detail="not the content owner")
    except ValueError as exc:
        msg = str(exc)
        if msg == "case_not_found":
            raise HTTPException(status_code=404, detail="case not found") from exc
        raise HTTPException(status_code=409, detail=msg) from exc
    return HoldActionOut(ok=True, case_id=case_id, state=str(res.get("state") or ""))


@router.post("/holds/{case_id}/respond", response_model=HoldActionOut)
def hold_respond(case_id: str, inp: HoldRespondIn, ctx=Depends(require_ui_session)):
    return _hold_respond(case_id, ctx, inp)


@compat_router.post("/holds/{case_id}/respond", response_model=HoldActionOut)
def hold_respond_compat(case_id: str, inp: HoldRespondIn, ctx=Depends(require_ui_session)):
    return _hold_respond(case_id, ctx, inp)


@router.post("/holds/{case_id}/close", response_model=HoldActionOut)
def hold_close(case_id: str, ctx=Depends(require_ui_session)):
    return _hold_close(case_id, ctx)


@compat_router.post("/holds/{case_id}/close", response_model=HoldActionOut)
def hold_close_compat(case_id: str, ctx=Depends(require_ui_session)):
    return _hold_close(case_id, ctx)


# ── MOD-D2: poster lists their OWN moderation cases (My content under review) ──
class MyModerationCaseOut(BaseModel):
    case_id: str
    content_type: str = ""
    content_id: str = ""
    state: str = ""
    categories: List[str] = []
    report_count: int = 0
    hold_until: Optional[int] = None
    days_remaining: Optional[int] = None
    poster_response: Optional[str] = None
    responded_at: Optional[int] = None
    created_at: int = 0
    updated_at: int = 0


class MyModerationCasesOut(BaseModel):
    cases: List[MyModerationCaseOut]


# States surfaced on the poster's "My content under review" screen.
_MY_REVIEW_STATES = {"under_review", "hold", "awaiting_final"}


def _mod_coerce_int(v: Any) -> Optional[int]:
    try:
        return None if v is None else int(v)
    except (TypeError, ValueError):
        return None


def _case_to_my_out(item: Dict[str, Any], *, now_ts: int) -> "MyModerationCaseOut":
    cats_raw = item.get("categories") or []
    if isinstance(cats_raw, (set, frozenset)):
        cats = sorted(str(c) for c in cats_raw)
    elif isinstance(cats_raw, (list, tuple)):
        cats = [str(c) for c in cats_raw]
    else:
        cats = [str(cats_raw)]
    state = str(item.get("state") or "")
    hold_until = _mod_coerce_int(item.get("hold_until"))
    days_remaining = None
    if state == "hold" and hold_until:
        days_remaining = max(0, (int(hold_until) - int(now_ts) + 86399) // 86400)
    resp_txt = item.get("poster_response")
    return MyModerationCaseOut(
        case_id=str(item.get("case_id") or ""),
        content_type=str(item.get("content_type") or ""),
        content_id=str(item.get("content_id") or ""),
        state=state,
        categories=cats,
        report_count=_mod_coerce_int(item.get("report_count")) or 0,
        hold_until=hold_until,
        days_remaining=days_remaining,
        poster_response=(str(resp_txt) if resp_txt else None),
        responded_at=_mod_coerce_int(item.get("responded_at")),
        created_at=_mod_coerce_int(item.get("created_at")) or 0,
        updated_at=_mod_coerce_int(item.get("updated_at")) or 0,
    )


def _list_my_cases(ctx: Dict[str, str]) -> "MyModerationCasesOut":
    uid = str(ctx.get("user_sub") or "").strip()
    if not uid:
        raise HTTPException(status_code=401, detail="Unauthorized")
    now = int(time.time())
    out: List[MyModerationCaseOut] = []
    try:
        scan_kwargs: Dict[str, Any] = {"FilterExpression": Attr("owner_user_id").eq(uid)}
        pages = 0
        while True:
            resp = T.moderation_cases.scan(**scan_kwargs)
            for it in resp.get("Items", []) or []:
                if str(it.get("state") or "") in _MY_REVIEW_STATES:
                    out.append(_case_to_my_out(it, now_ts=now))
            lek = resp.get("LastEvaluatedKey")
            pages += 1
            if not lek or pages >= 20:
                break
            scan_kwargs["ExclusiveStartKey"] = lek
    except ClientError:
        logger.exception("moderation._list_my_cases scan failed for %s", uid)
        raise HTTPException(status_code=503, detail="unavailable")
    out.sort(key=lambda c: c.updated_at, reverse=True)
    return MyModerationCasesOut(cases=out)


@router.get("/cases/mine", response_model=MyModerationCasesOut)
def list_my_cases(ctx=Depends(require_ui_session)):
    return _list_my_cases(ctx)


@compat_router.get("/cases/mine", response_model=MyModerationCasesOut)
def list_my_cases_compat(ctx=Depends(require_ui_session)):
    return _list_my_cases(ctx)
