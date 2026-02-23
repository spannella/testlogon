from __future__ import annotations

import asyncio
import json
import logging
import os
import time
import uuid
from datetime import datetime, timezone
from typing import Annotated, Any, Dict, List, Literal, Optional, Set

from urllib.parse import quote

from botocore.exceptions import ClientError
from fastapi import APIRouter, Depends, File, Header, HTTPException, Query, Request, UploadFile
from pydantic import BaseModel, Field
from starlette.responses import StreamingResponse

from app.core.aws import ddb
from app.core.aws_clients import s3_client, sqs_client
from app.core.cursor import decode_cursor, encode_cursor
from app.core.settings import S
from app.services.filemanager import get_usage_summary
from app.services.sessions import require_ui_session
from app.services.subscription_access import can_access_creator
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

s3 = s3_client() if UPLOAD_BUCKET else None
sqs = sqs_client() if EVENTS_SQS_URL else None

router = APIRouter(tags=["newsfeed"])
logger = logging.getLogger(__name__)


# -----------------------------
# Helpers
# -----------------------------
def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex}"


def decode_cursor_or_400(cursor: Optional[str]) -> Optional[Dict[str, Any]]:
    if not cursor:
        return None
    decoded = decode_cursor(cursor)
    if decoded is None:
        raise HTTPException(status_code=400, detail="Invalid cursor")
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


class CreatePostRequest(BaseModel):
    body: str
    image_urls: List[str] = Field(default_factory=list)
    visibility: Literal["followers", "public"] = "followers"
    unlock_price_cents: Optional[int] = Field(default=None, ge=0)


class PostResponse(BaseModel):
    post_id: str
    author_id: str
    created_at: str
    body: str
    image_urls: List[str] = Field(default_factory=list)
    visibility: str
    locked: bool
    unlock_price_cents: Optional[int] = None
    like_count: int = 0
    comment_count: int = 0


class CreateCommentRequest(BaseModel):
    body: str
    parent_comment_id: Optional[str] = None


class EditCommentRequest(BaseModel):
    body: str
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
    version: int = 1
    tip_total_cents: int = 0


class TipRequest(BaseModel):
    amount_cents: int = Field(..., ge=1)
    currency: str = "usd"


class UnfollowRequest(BaseModel):
    target_user_id: str


class HidePostRequest(BaseModel):
    post_id: str


class EditPostRequest(BaseModel):
    body: str
    image_urls: Optional[List[str]] = None


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


class UnlockPostResponse(BaseModel):
    post_id: str
    payment_intent: Dict[str, Any]


# -----------------------------
# Post serialization helper
# -----------------------------
def _post_to_dict(post: Dict[str, Any], locked_body: bool = False, liked_by_me: bool = False) -> Dict[str, Any]:
    """Map a raw DDB post item to the FeedPost shape expected by the frontend."""
    body = post.get("body", "")
    # Handle legacy dict-format bodies gracefully
    if isinstance(body, dict):
        body = "[Content unavailable]"
    # Support both old image_url (str) and new image_urls (list)
    image_urls = list(post.get("image_urls") or [])
    if not image_urls and post.get("image_url"):
        image_urls = [post["image_url"]]
    if locked_body:
        body = "[Locked content]"
        image_urls = []
    return {
        "post_id": post["post_id"],
        "author_id": post.get("user_id", ""),
        "created_at": post.get("created_at", ""),
        "updated_at": post.get("updated_at"),
        "body": body,
        "image_urls": image_urls,
        "visibility": post.get("visibility", "followers"),
        "locked": bool(post.get("locked")),
        "unlock_price_cents": post.get("unlock_price_cents"),
        "like_count": int(post.get("like_count", 0)),
        "comment_count": int(post.get("comment_count", 0)),
        "liked_by_me": liked_by_me,
    }


def _comment_to_dict(it: Dict[str, Any]) -> Dict[str, Any]:
    """Map a raw DDB comment item to the FeedComment shape expected by the frontend."""
    body = it.get("body")
    if isinstance(body, dict):
        body = None  # deleted or legacy rich-text; treat as no body
    if it.get("deleted"):
        body = None
    return {
        "comment_id": it["comment_id"],
        "post_id": it["post_id"],
        "author_id": it.get("user_id", ""),
        "created_at": it.get("created_at", ""),
        "updated_at": it.get("updated_at"),
        "deleted": bool(it.get("deleted")),
        "parent_comment_id": it.get("parent_comment_id"),
        "body": body,
        "version": int(it.get("version", 1)),
        "tip_total_cents": int(it.get("tip_total_cents", 0)),
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
def is_following(viewer_id: str, target_id: str) -> bool:
    it = ddb_get_item({"pk": pk_user(viewer_id), "sk": f"FOLLOWING#{target_id}"})
    return bool(it and it.get("state") == "following")


def is_hidden(user_id: str, post_id: str) -> bool:
    it = ddb_get_item({"pk": pk_hide(user_id), "sk": f"POST#{post_id}"})
    return bool(it and it.get("hidden") is True)


def has_unlocked(user_id: str, post_id: str) -> bool:
    it = ddb_get_item({"pk": pk_unlock(user_id), "sk": f"POST#{post_id}"})
    return bool(it and it.get("unlocked") is True)


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
    s3_key = f"uploads/{user_id}/{attachment_id}/{safe_name}"
    try:
        s3.put_object(Bucket=UPLOAD_BUCKET, Key=s3_key, Body=content, ContentType=file.content_type or "application/octet-stream")
    except ClientError as exc:
        raise HTTPException(status_code=500, detail=f"S3 error: {exc.response['Error'].get('Message','unknown')}") from exc
    encoded_key = quote(s3_key, safe="")
    url = f"/uploads/object?s3_key={encoded_key}"
    return {"url": url, "s3_key": s3_key}


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

    return StreamingResponse(_iter(), media_type=content_type, headers={"Cache-Control": "private, max-age=300"})


# -----------------------------
# Follow / Unfollow
# -----------------------------
@router.post("/social/unfollow")
def unfollow(req: UnfollowRequest, user_id: UserIdDep):
    target = req.target_user_id
    item = {
        "pk": pk_user(user_id),
        "sk": f"FOLLOWING#{target}",
        "Entity": "Following",
        "user_id": user_id,
        "target_user_id": target,
        "state": "unfollowed",
        "updated_at": now_iso(),
    }
    ddb_put_item(item)
    return {"ok": True}


@router.post("/social/refollow")
def refollow(req: UnfollowRequest, user_id: UserIdDep):
    target = req.target_user_id
    item = {
        "pk": pk_user(user_id),
        "sk": f"FOLLOWING#{target}",
        "Entity": "Following",
        "user_id": user_id,
        "target_user_id": target,
        "state": "following",
        "updated_at": now_iso(),
    }
    ddb_put_item(item)
    return {"ok": True}


# -----------------------------
# Posts
# -----------------------------
@router.post("/posts", response_model=PostResponse)
def create_post(req: CreatePostRequest, user_id: UserIdDep):
    _enforce_newsfeed_post_quota_precheck(user_id=user_id)
    post_id = new_id("post")
    created_at = now_iso()

    unlock_price_cents = req.unlock_price_cents if req.unlock_price_cents and req.unlock_price_cents > 0 else None
    locked = unlock_price_cents is not None

    post_item = {
        "pk": pk_post(post_id),
        "sk": sk_post(),
        "Entity": "Post",
        "post_id": post_id,
        "user_id": user_id,
        "created_at": created_at,
        "body": req.body,
        "image_urls": req.image_urls,
        "visibility": req.visibility,
        "locked": locked,
        "unlock_price_cents": unlock_price_cents,
        "like_count": 0,
        "comment_count": 0,
    }
    ddb_put_item(post_item)

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
    _meter_newsfeed_post_publish(user_id=user_id, post_id=post_id)

    return PostResponse(
        post_id=post_id,
        author_id=user_id,
        created_at=created_at,
        body=req.body,
        image_urls=req.image_urls,
        visibility=req.visibility,
        locked=locked,
        unlock_price_cents=unlock_price_cents,
        like_count=0,
        comment_count=0,
    )


@router.patch("/posts/{post_id}")
def edit_post(post_id: str, req: EditPostRequest, user_id: UserIdDep):
    post = ddb_get_item({"pk": pk_post(post_id), "sk": sk_post()})
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
    if post.get("user_id") != user_id:
        raise HTTPException(status_code=403, detail="Not your post")
    image_urls_in_payload = "image_urls" in req.model_fields_set
    if image_urls_in_payload and req.image_urls:
        update_expr = "SET #body = :b, image_urls = :imgs, updated_at = :u"
        expr_vals = {":b": req.body, ":imgs": req.image_urls, ":u": now_iso()}
    elif image_urls_in_payload:
        update_expr = "SET #body = :b, updated_at = :u REMOVE image_urls"
        expr_vals = {":b": req.body, ":u": now_iso()}
    else:
        update_expr = "SET #body = :b, updated_at = :u"
        expr_vals = {":b": req.body, ":u": now_iso()}
    updated = ddb_update_item(
        key={"pk": pk_post(post_id), "sk": sk_post()},
        update_expr=update_expr,
        expr_names={"#body": "body"},
        expr_vals=expr_vals,
    )
    return _post_to_dict(updated)


@router.delete("/posts/{post_id}")
def delete_post(post_id: str, user_id: UserIdDep):
    post = ddb_get_item({"pk": pk_post(post_id), "sk": sk_post()})
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
    if post.get("user_id") != user_id:
        raise HTTPException(status_code=403, detail="Not your post")
    try:
        tbl.delete_item(Key={"pk": pk_post(post_id), "sk": sk_post()})
        tbl.delete_item(Key={"pk": pk_post(post_id), "sk": f"FEEDREF#{user_id}"})
    except ClientError as exc:
        raise HTTPException(
            status_code=500,
            detail=f"DynamoDB error: {exc.response['Error'].get('Message', 'unknown')}",
        ) from exc
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
    return {"ok": True}


@router.get("/feed")
def view_feed(
    limit: int = Query(default=20, ge=1, le=50),
    cursor: Optional[str] = Query(default=None),
    user_id: UserIdDep = None,
):
    eks = decode_cursor_or_400(cursor)

    resp = ddb_query(
        IndexName="GSI1",
        KeyConditionExpression="GSI1PK = :pk",
        ExpressionAttributeValues={":pk": f"FEED#{user_id}"},
        ScanIndexForward=False,
        Limit=limit,
        ExclusiveStartKey=eks if eks else None,
    )

    refs = resp.get("Items", [])
    post_ids = [ref.get("post_id") for ref in refs if ref.get("post_id")]

    posts: List[Dict[str, Any]] = []
    if post_ids:
        keys = [{"pk": pk_post(pid), "sk": sk_post()} for pid in post_ids]
        try:
            raw = ddb.batch_get_item(
                RequestItems={APP_TABLE: {"Keys": keys}}
            )
            posts = raw.get("Responses", {}).get(APP_TABLE, [])
        except ClientError as exc:
            raise HTTPException(
                status_code=500,
                detail=f"DDB batch_get_item error: {exc.response['Error'].get('Message','unknown')}",
            ) from exc

    post_by_id = {post["post_id"]: post for post in posts if "post_id" in post}

    # Batch-fetch like records so we can set liked_by_me per post
    liked_post_ids: set = set()
    if post_ids:
        like_keys = [{"pk": pk_like(user_id), "sk": f"POST#{pid}"} for pid in post_ids]
        try:
            like_raw = ddb.batch_get_item(RequestItems={APP_TABLE: {"Keys": like_keys}})
            liked_post_ids = {item.get("post_id", "") for item in like_raw.get("Responses", {}).get(APP_TABLE, [])}
        except ClientError:
            pass  # Best effort — liked_by_me will default to False

    ordered: List[Dict[str, Any]] = []

    for post_id in post_ids:
        post = post_by_id.get(post_id)
        if not post:
            continue

        if is_hidden(user_id, post_id):
            continue

        author = post.get("user_id")
        if author and author != user_id:
            if not can_access_creator(user_id, author):
                continue
            if not is_following(user_id, author):
                continue

        locked = bool(post.get("locked"))
        is_locked_for_viewer = locked and author != user_id and not has_unlocked(user_id, post_id)
        ordered.append(_post_to_dict(post, locked_body=is_locked_for_viewer, liked_by_me=post_id in liked_post_ids))

    return {"items": ordered, "next_cursor": encode_cursor(resp.get("LastEvaluatedKey"))}


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
    if author and author != user_id:
        if not can_access_creator(user_id, author):
            raise HTTPException(status_code=403, detail="Subscription required")
        if not is_following(user_id, author):
            raise HTTPException(status_code=403, detail="Following required")

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
    if post_author and post_author != user_id and not can_access_creator(user_id, post_author):
        raise HTTPException(status_code=403, detail="Subscription required to comment")

    if post.get("locked") and post.get("user_id") != user_id and not has_unlocked(user_id, post_id):
        raise HTTPException(status_code=402, detail="Post is locked; unlock required to comment")

    comment_id = new_id("cmt")
    created_at = now_iso()
    parent = req.parent_comment_id

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
        "body": req.body,
        "version": 1,
        "tip_total_cents": 0,
        "GSI2PK": pk_post_comments(post_id),
        "GSI2SK": f"{created_at}#CMT#{comment_id}",
    }
    ddb_put_item(item)

    ddb_update_item(
        key={"pk": pk_post(post_id), "sk": sk_post()},
        update_expr="SET comment_count = if_not_exists(comment_count, :z) + :one",
        expr_vals={":z": 0, ":one": 1},
    )

    if post_author and post_author != user_id and parent is None:
        put_notification(
            recipient_user_id=post_author,
            notif_type="comment_on_post",
            payload={"post_id": post_id, "comment_id": comment_id, "from_user_id": user_id, "created_at": created_at},
        )

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

    return CommentResponse(
        comment_id=comment_id,
        post_id=post_id,
        author_id=user_id,
        created_at=created_at,
        updated_at=None,
        deleted=False,
        parent_comment_id=parent,
        body=req.body,
        version=1,
        tip_total_cents=0,
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
    items = [_comment_to_dict(it) for it in resp.get("Items", [])]
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

    updated = ddb_update_item(
        key=key,
        update_expr="SET #body = :b, updated_at = :u, version = :nv",
        expr_names={"#body": "body"},
        expr_vals={":b": req.body, ":u": now_iso(), ":nv": new_version, ":ev": int(req.expected_version)},
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
        body=updated.get("body") if not updated.get("deleted") else None,
        version=int(updated.get("version", 1)),
        tip_total_cents=int(updated.get("tip_total_cents", 0)),
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
        update_expr="SET deleted = :t, #body = :null, updated_at = :u",
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

    pi = payments.create_payment_intent(
        user_id=tipper_id,
        amount_cents=req.amount_cents,
        currency=req.currency,
        metadata={"type": "tip", "post_id": post_id, "comment_id": comment_id},
    )
    conf = payments.confirm_payment_intent(payment_intent_id=pi["payment_intent_id"])
    if conf.get("status") != "succeeded":
        raise HTTPException(status_code=402, detail="Payment failed")

    key = {"pk": target["pk"], "sk": target["sk"]}
    updated = ddb_update_item(
        key=key,
        update_expr="SET tip_total_cents = if_not_exists(tip_total_cents, :z) + :amt",
        expr_vals={":z": 0, ":amt": req.amount_cents},
    )

    comment_author = updated.get("user_id")
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
def unlock_post(req: UnlockPostRequest, user_id: UserIdDep):
    post = ddb_get_item({"pk": pk_post(req.post_id), "sk": sk_post()})
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
    if not post.get("locked"):
        return UnlockPostResponse(post_id=req.post_id, payment_intent={"status": "not_required"})
    if post.get("user_id") == user_id:
        return UnlockPostResponse(post_id=req.post_id, payment_intent={"status": "not_required"})
    if has_unlocked(user_id, req.post_id):
        return UnlockPostResponse(post_id=req.post_id, payment_intent={"status": "already_unlocked"})

    price = int(post.get("unlock_price_cents") or 0)
    if price <= 0:
        raise HTTPException(status_code=500, detail="Locked post has invalid price")

    pi = payments.create_payment_intent(
        user_id=user_id,
        amount_cents=price,
        currency="usd",
        metadata={"type": "unlock_post", "post_id": req.post_id},
    )
    conf = payments.confirm_payment_intent(payment_intent_id=pi["payment_intent_id"])
    if conf.get("status") != "succeeded":
        raise HTTPException(status_code=402, detail="Payment failed")

    item = {
        "pk": pk_unlock(user_id),
        "sk": f"POST#{req.post_id}",
        "Entity": "Unlock",
        "user_id": user_id,
        "post_id": req.post_id,
        "unlocked": True,
        "created_at": now_iso(),
        "payment_intent_id": pi["payment_intent_id"],
    }
    ddb_put_item(item)

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


# -----------------------------
# Health
# -----------------------------
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
