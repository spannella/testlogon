from __future__ import annotations

import asyncio
import base64
import json
import os
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional, Set

import boto3
from botocore.exceptions import ClientError
from fastapi import APIRouter, Header, HTTPException, Query, Request
from pydantic import BaseModel, Field
from starlette.responses import StreamingResponse

from app.core.aws import ddb
from app.core.settings import S

# -----------------------------
# Config
# -----------------------------
APP_TABLE = os.environ.get("APP_TABLE", "app_single_table")
AWS_REGION = S.aws_region or os.environ.get("AWS_REGION", "us-east-1")
UPLOAD_BUCKET = os.environ.get("UPLOAD_BUCKET")
EVENTS_SQS_URL = os.environ.get("EVENTS_SQS_URL")

tbl = ddb.Table(APP_TABLE)

s3 = boto3.client("s3", region_name=AWS_REGION) if UPLOAD_BUCKET else None
sqs = boto3.client("sqs", region_name=AWS_REGION) if EVENTS_SQS_URL else None

router = APIRouter(tags=["newsfeed"])


# -----------------------------
# Helpers
# -----------------------------
def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex}"


def encode_cursor(last_evaluated_key: Optional[Dict[str, Any]]) -> Optional[str]:
    if not last_evaluated_key:
        return None
    raw = json.dumps(last_evaluated_key).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("utf-8")


def decode_cursor(cursor: Optional[str]) -> Optional[Dict[str, Any]]:
    if not cursor:
        return None
    try:
        raw = base64.urlsafe_b64decode(cursor.encode("utf-8"))
        return json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Invalid cursor") from exc


def require_user(x_user_id: Optional[str], user_id_qs: Optional[str] = None) -> str:
    uid = x_user_id or user_id_qs
    if not uid:
        raise HTTPException(status_code=401, detail="Missing user identity (X-User-Id header or user_id query param)")
    return uid


def ensure_uploads_enabled() -> None:
    if not UPLOAD_BUCKET or not s3:
        raise HTTPException(status_code=500, detail="UPLOAD_BUCKET not configured")


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
    try:
        return tbl.query(**kwargs)
    except ClientError as exc:
        raise HTTPException(status_code=500, detail=f"DynamoDB error: {exc.response['Error'].get('Message','unknown')}") from exc


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


class RichTextDoc(BaseModel):
    format: str = Field(..., description="e.g. 'tiptap-json', 'slate', 'quill-delta'")
    doc: Dict[str, Any]


class CreatePostRequest(BaseModel):
    body: RichTextDoc
    attachments: List[Attachment] = Field(default_factory=list)
    visibility: Literal["followers", "public"] = "followers"
    unlock_price_cents: Optional[int] = Field(default=None, ge=0)


class PostResponse(BaseModel):
    post_id: str
    user_id: str
    created_at: str
    body: RichTextDoc
    attachments: List[Attachment]
    visibility: str
    locked: bool
    unlock_price_cents: Optional[int] = None


class CreateCommentRequest(BaseModel):
    body: RichTextDoc
    parent_comment_id: Optional[str] = None


class EditCommentRequest(BaseModel):
    body: RichTextDoc
    expected_version: int = Field(..., ge=1)


class CommentResponse(BaseModel):
    comment_id: str
    post_id: str
    user_id: str
    created_at: str
    updated_at: Optional[str] = None
    deleted: bool = False
    parent_comment_id: Optional[str] = None
    body: Optional[RichTextDoc] = None
    version: int = 1
    tip_total_cents: int = 0


class TipRequest(BaseModel):
    amount_cents: int = Field(..., ge=1)
    currency: str = "usd"


class UnfollowRequest(BaseModel):
    target_user_id: str


class HidePostRequest(BaseModel):
    post_id: str


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
async def sse(
    request: Request,
    user_id: Optional[str] = Query(default=None, description="Dev/testing; prefer real auth"),
    x_user_id: Optional[str] = Header(default=None),
):
    uid = require_user(x_user_id, user_id_qs=user_id)
    q = await sse_hub.add(uid)

    async def _gen():
        try:
            async for chunk in sse_event_stream(request, uid, q):
                yield chunk
        finally:
            await sse_hub.remove(uid, q)

    return StreamingResponse(_gen(), media_type="text/event-stream")


# -----------------------------
# Notification writer
# -----------------------------
def put_notification(*, recipient_user_id: str, notif_type: str, payload: Dict[str, Any]) -> str:
    notif_id = new_id("ntf")
    created_at = now_iso()
    item = {
        "PK": pk_notif(recipient_user_id),
        "SK": f"{created_at}#NOTIF#{notif_id}",
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

    asyncio.create_task(
        sse_hub.publish(
            recipient_user_id,
            {
                "type": "notification",
                "user_id": recipient_user_id,
                "created_at": created_at,
                "data": {"notif_type": notif_type, "payload": payload, "notif_id": notif_id},
            },
        )
    )

    return notif_id


# -----------------------------
# Following / hiding / unlock helpers
# -----------------------------
def is_following(viewer_id: str, target_id: str) -> bool:
    it = ddb_get_item({"PK": pk_user(viewer_id), "SK": f"FOLLOWING#{target_id}"})
    return bool(it and it.get("state") == "following")


def is_hidden(user_id: str, post_id: str) -> bool:
    it = ddb_get_item({"PK": pk_hide(user_id), "SK": f"POST#{post_id}"})
    return bool(it and it.get("hidden") is True)


def has_unlocked(user_id: str, post_id: str) -> bool:
    it = ddb_get_item({"PK": pk_unlock(user_id), "SK": f"POST#{post_id}"})
    return bool(it and it.get("unlocked") is True)


# -----------------------------
# Uploads (S3 presigned PUT)
# -----------------------------
@router.post("/uploads/presign", response_model=PresignUploadResponse)
def presign_upload(req: PresignUploadRequest, x_user_id: Optional[str] = Header(default=None)):
    user_id = require_user(x_user_id)
    ensure_uploads_enabled()

    attachment_id = new_id("att")
    safe_name = req.filename.replace("/", "_").replace("\\", "_")
    s3_key = f"uploads/{user_id}/{attachment_id}/{safe_name}"

    try:
        put_url = s3.generate_presigned_url(
            ClientMethod="put_object",
            Params={"Bucket": UPLOAD_BUCKET, "Key": s3_key, "ContentType": req.content_type},
            ExpiresIn=60 * 10,
        )
    except ClientError as exc:
        raise HTTPException(status_code=500, detail=f"S3 error: {exc.response['Error'].get('Message','unknown')}") from exc

    attachment = Attachment(
        attachment_id=attachment_id,
        filename=req.filename,
        content_type=req.content_type,
        size_bytes=req.size_bytes,
        s3_key=s3_key,
        url=None,
    )
    return PresignUploadResponse(attachment=attachment, put_url=put_url, put_headers={"Content-Type": req.content_type})


# -----------------------------
# Follow / Unfollow
# -----------------------------
@router.post("/social/unfollow")
def unfollow(req: UnfollowRequest, x_user_id: Optional[str] = Header(default=None)):
    user_id = require_user(x_user_id)
    target = req.target_user_id
    item = {
        "PK": pk_user(user_id),
        "SK": f"FOLLOWING#{target}",
        "Entity": "Following",
        "user_id": user_id,
        "target_user_id": target,
        "state": "unfollowed",
        "updated_at": now_iso(),
    }
    ddb_put_item(item)
    return {"ok": True}


@router.post("/social/refollow")
def refollow(req: UnfollowRequest, x_user_id: Optional[str] = Header(default=None)):
    user_id = require_user(x_user_id)
    target = req.target_user_id
    item = {
        "PK": pk_user(user_id),
        "SK": f"FOLLOWING#{target}",
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
def create_post(req: CreatePostRequest, x_user_id: Optional[str] = Header(default=None)):
    user_id = require_user(x_user_id)
    post_id = new_id("post")
    created_at = now_iso()

    unlock_price_cents = req.unlock_price_cents if req.unlock_price_cents and req.unlock_price_cents > 0 else None
    locked = unlock_price_cents is not None

    post_item = {
        "PK": pk_post(post_id),
        "SK": sk_post(),
        "Entity": "Post",
        "post_id": post_id,
        "user_id": user_id,
        "created_at": created_at,
        "body": req.body.model_dump(),
        "attachments": [a.model_dump() for a in req.attachments],
        "visibility": req.visibility,
        "locked": locked,
        "unlock_price_cents": unlock_price_cents,
        "comment_count": 0,
    }
    ddb_put_item(post_item)

    feed_item = {
        "PK": pk_post(post_id),
        "SK": f"FEEDREF#{user_id}",
        "Entity": "FeedRef",
        "post_id": post_id,
        "owner_user_id": user_id,
        "created_at": created_at,
        "GSI1PK": f"FEED#{user_id}",
        "GSI1SK": f"{created_at}#POST#{post_id}",
    }
    ddb_put_item(feed_item)

    return PostResponse(
        post_id=post_id,
        user_id=user_id,
        created_at=created_at,
        body=req.body,
        attachments=req.attachments,
        visibility=req.visibility,
        locked=locked,
        unlock_price_cents=unlock_price_cents,
    )


@router.post("/feed/hide")
def hide_post(req: HidePostRequest, x_user_id: Optional[str] = Header(default=None)):
    user_id = require_user(x_user_id)
    item = {
        "PK": pk_hide(user_id),
        "SK": f"POST#{req.post_id}",
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
    x_user_id: Optional[str] = Header(default=None),
):
    user_id = require_user(x_user_id)
    eks = decode_cursor(cursor)

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
        keys = [{"PK": pk_post(pid), "SK": sk_post()} for pid in post_ids]
        try:
            client = boto3.client("dynamodb", region_name=AWS_REGION)
            raw = client.batch_get_item(
                RequestItems={
                    APP_TABLE: {
                        "Keys": [{"PK": {"S": key["PK"]}, "SK": {"S": key["SK"]}} for key in keys]
                    }
                }
            )
            got = raw.get("Responses", {}).get(APP_TABLE, [])

            def unmarshal(av: Dict[str, Any]):
                if "S" in av:
                    return av["S"]
                if "N" in av:
                    num = av["N"]
                    return int(num) if num.isdigit() else float(num)
                if "BOOL" in av:
                    return av["BOOL"]
                if "M" in av:
                    return {k: unmarshal(v) for k, v in av["M"].items()}
                if "L" in av:
                    return [unmarshal(x) for x in av["L"]]
                if "NULL" in av:
                    return None
                return None

            for item in got:
                posts.append({k: unmarshal(v) for k, v in item.items()})
        except ClientError as exc:
            raise HTTPException(
                status_code=500,
                detail=f"DDB batch_get_item error: {exc.response['Error'].get('Message','unknown')}",
            ) from exc

    post_by_id = {post["post_id"]: post for post in posts if "post_id" in post}
    ordered: List[Dict[str, Any]] = []

    for post_id in post_ids:
        post = post_by_id.get(post_id)
        if not post:
            continue

        if is_hidden(user_id, post_id):
            continue

        author = post.get("user_id")
        if author and author != user_id:
            if not is_following(user_id, author):
                continue

        locked = bool(post.get("locked"))
        if locked and author != user_id and not has_unlocked(user_id, post_id):
            post = dict(post)
            post["body"] = {"format": post.get("body", {}).get("format", "unknown"), "doc": {"locked": True}}
            post["attachments"] = []

        ordered.append(post)

    return {"items": ordered, "next_cursor": encode_cursor(resp.get("LastEvaluatedKey"))}


# -----------------------------
# Comments
# -----------------------------
@router.post("/posts/{post_id}/comments", response_model=CommentResponse)
def create_comment(post_id: str, req: CreateCommentRequest, x_user_id: Optional[str] = Header(default=None)):
    user_id = require_user(x_user_id)

    post = ddb_get_item({"PK": pk_post(post_id), "SK": sk_post()})
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")

    if post.get("locked") and post.get("user_id") != user_id and not has_unlocked(user_id, post_id):
        raise HTTPException(status_code=402, detail="Post is locked; unlock required to comment")

    comment_id = new_id("cmt")
    created_at = now_iso()
    parent = req.parent_comment_id

    item = {
        "PK": pk_post_comments(post_id),
        "SK": f"{created_at}#CMT#{comment_id}",
        "Entity": "Comment",
        "comment_id": comment_id,
        "post_id": post_id,
        "user_id": user_id,
        "created_at": created_at,
        "updated_at": None,
        "deleted": False,
        "parent_comment_id": parent,
        "body": req.body.model_dump(),
        "version": 1,
        "tip_total_cents": 0,
        "GSI2PK": pk_post_comments(post_id),
        "GSI2SK": f"{created_at}#CMT#{comment_id}",
    }
    ddb_put_item(item)

    ddb_update_item(
        key={"PK": pk_post(post_id), "SK": sk_post()},
        update_expr="SET comment_count = if_not_exists(comment_count, :z) + :one",
        expr_vals={":z": 0, ":one": 1},
    )

    post_author = post.get("user_id")
    if post_author and post_author != user_id and parent is None:
        put_notification(
            recipient_user_id=post_author,
            notif_type="comment_on_post",
            payload={"post_id": post_id, "comment_id": comment_id, "from_user_id": user_id, "created_at": created_at},
        )

    if parent:
        q = ddb_query(
            KeyConditionExpression="PK = :pk",
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
        user_id=user_id,
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
    x_user_id: Optional[str] = Header(default=None),
):
    user_id = require_user(x_user_id)

    post = ddb_get_item({"PK": pk_post(post_id), "SK": sk_post()})
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")

    if post.get("locked") and post.get("user_id") != user_id and not has_unlocked(user_id, post_id):
        raise HTTPException(status_code=402, detail="Post is locked; unlock required to view comments")

    eks = decode_cursor(cursor)
    resp = ddb_query(
        IndexName="GSI2",
        KeyConditionExpression="GSI2PK = :pk",
        ExpressionAttributeValues={":pk": pk_post_comments(post_id)},
        ScanIndexForward=True,
        Limit=limit,
        ExclusiveStartKey=eks if eks else None,
    )
    items = resp.get("Items", [])
    for it in items:
        if it.get("deleted"):
            it["body"] = None
    return {"items": items, "next_cursor": encode_cursor(resp.get("LastEvaluatedKey"))}


@router.patch("/posts/{post_id}/comments/{comment_id}", response_model=CommentResponse)
def edit_comment(post_id: str, comment_id: str, req: EditCommentRequest, x_user_id: Optional[str] = Header(default=None)):
    user_id = require_user(x_user_id)

    q = ddb_query(
        KeyConditionExpression="PK = :pk",
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

    key = {"PK": target["PK"], "SK": target["SK"]}
    new_version = int(req.expected_version) + 1

    updated = ddb_update_item(
        key=key,
        update_expr="SET #body = :b, updated_at = :u, version = :nv",
        expr_names={"#body": "body"},
        expr_vals={":b": req.body.model_dump(), ":u": now_iso(), ":nv": new_version, ":ev": int(req.expected_version)},
        condition_expr="version = :ev",
    )

    return CommentResponse(
        comment_id=updated["comment_id"],
        post_id=updated["post_id"],
        user_id=updated["user_id"],
        created_at=updated["created_at"],
        updated_at=updated.get("updated_at"),
        deleted=bool(updated.get("deleted")),
        parent_comment_id=updated.get("parent_comment_id"),
        body=RichTextDoc(**updated["body"]) if (updated.get("body") and not updated.get("deleted")) else None,
        version=int(updated.get("version", 1)),
        tip_total_cents=int(updated.get("tip_total_cents", 0)),
    )


@router.delete("/posts/{post_id}/comments/{comment_id}")
def delete_comment(post_id: str, comment_id: str, x_user_id: Optional[str] = Header(default=None)):
    user_id = require_user(x_user_id)

    q = ddb_query(
        KeyConditionExpression="PK = :pk",
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

    key = {"PK": target["PK"], "SK": target["SK"]}
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
def tip_comment(post_id: str, comment_id: str, req: TipRequest, x_user_id: Optional[str] = Header(default=None)):
    tipper_id = require_user(x_user_id)

    q = ddb_query(
        KeyConditionExpression="PK = :pk",
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

    key = {"PK": target["PK"], "SK": target["SK"]}
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
def unlock_post(req: UnlockPostRequest, x_user_id: Optional[str] = Header(default=None)):
    user_id = require_user(x_user_id)

    post = ddb_get_item({"PK": pk_post(req.post_id), "SK": sk_post()})
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
        "PK": pk_unlock(user_id),
        "SK": f"POST#{req.post_id}",
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
    x_user_id: Optional[str] = Header(default=None),
):
    user_id = require_user(x_user_id)
    eks = decode_cursor(cursor)

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
