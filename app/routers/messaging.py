from __future__ import annotations

import asyncio
import json
import os
import time
import uuid
from typing import Any, Dict, List, Literal, Optional

import anyio
import boto3
from boto3.dynamodb.conditions import Key
from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from app.auth.deps import extract_bearer_token, get_authenticated_user_sub
from app.core.aws import ddb
from app.core.settings import S
from app.services.alerts import audit_event
from app.services.sessions import require_ui_session
from app.services.subscription_access import require_subscription_access

# -------------------------
# Config / AWS clients
# -------------------------
AWS_REGION = S.aws_region or os.getenv("AWS_REGION", "us-east-1")

DDB_CONVERSATIONS = os.getenv("DDB_CONVERSATIONS", "Conversations")
DDB_PARTICIPANTS = os.getenv("DDB_PARTICIPANTS", "Participants")
DDB_MESSAGES = os.getenv("DDB_MESSAGES", "Messages")
DDB_USER_EVENTS = os.getenv("DDB_USER_EVENTS", "UserEvents")

DDB_USERS = os.getenv("DDB_USERS", "Users")
DDB_USER_SEARCH = os.getenv("DDB_USER_SEARCH", "UserSearch")

DDB_PRESENCE = os.getenv("DDB_PRESENCE", "UserPresence")
DDB_TYPING = os.getenv("DDB_TYPING", "Typing")

DDB_MESSAGE_EDITS = os.getenv("DDB_MESSAGE_EDITS", "MessageEdits")
DDB_MESSAGE_VIEWS = os.getenv("DDB_MESSAGE_VIEWS", "MessageViews")

S3_BUCKET_IMAGES = os.getenv("S3_BUCKET_IMAGES", "my-chat-images")

ONLINE_WINDOW_SEC = int(os.getenv("ONLINE_WINDOW_SEC", "30"))
PRESENCE_TTL_SEC = int(os.getenv("PRESENCE_TTL_SEC", "120"))
TYPING_TTL_SEC = int(os.getenv("TYPING_TTL_SEC", "10"))

VIEWS_TTL_SEC = int(os.getenv("VIEWS_TTL_SEC", "2592000"))  # 30d
EDITS_TTL_SEC = int(os.getenv("EDITS_TTL_SEC", "7776000"))  # 90d

s3 = boto3.client("s3", region_name=AWS_REGION)


tbl_convos = ddb.Table(DDB_CONVERSATIONS)
tbl_parts = ddb.Table(DDB_PARTICIPANTS)
tbl_msgs = ddb.Table(DDB_MESSAGES)
tbl_events = ddb.Table(DDB_USER_EVENTS)
tbl_users = ddb.Table(DDB_USERS)
tbl_search = ddb.Table(DDB_USER_SEARCH)
tbl_presence = ddb.Table(DDB_PRESENCE)
tbl_typing = ddb.Table(DDB_TYPING)

tbl_edits = ddb.Table(DDB_MESSAGE_EDITS)
tbl_views = ddb.Table(DDB_MESSAGE_VIEWS)

router = APIRouter(prefix="/messaging", tags=["messaging"])


# -------------------------
# Auth (Bearer token)
# -------------------------
def get_current_user_id(authorization: Optional[str] = Header(default=None)) -> str:
    """
    Replace with real JWT verification.
    Dev behavior: Authorization: Bearer <user_id>
    """
    return extract_bearer_token(authorization)


async def get_messaging_user_id(
    request: Request,
    authorization: Optional[str] = Header(default=None),
    x_session_id: Optional[str] = Header(default=None, alias="X-SESSION-ID"),
) -> str:
    if x_session_id:
        user_sub = await get_authenticated_user_sub(request)
        ctx = await require_ui_session(request, user_sub=user_sub, x_session_id=x_session_id)
        return ctx["user_sub"]
    return get_current_user_id(authorization)


# -------------------------
# Models
# -------------------------
class Contact(BaseModel):
    user_id: str
    display_name: str


class StartConversationIn(BaseModel):
    participant_ids: List[str] = Field(min_length=1)
    type: Literal["dm", "group"] = "dm"
    title: Optional[str] = None


class StartGroupConversationIn(BaseModel):
    participant_ids: List[str] = Field(min_length=2)
    title: Optional[str] = None


class ConversationOut(BaseModel):
    conversation_id: str
    type: str
    title: Optional[str] = None
    created_at: int
    created_by: str
    participant_count: int
    last_message_at: Optional[int] = None
    last_message_preview: Optional[str] = None
    status: str
    muted_until: int = 0
    last_read_at: int = 0


class SendTextMessageIn(BaseModel):
    text: str = Field(min_length=1, max_length=4000)
    reply_to_message_id: Optional[str] = None


class SendImagePresignIn(BaseModel):
    content_type: str = "image/jpeg"
    filename: str = "image.jpg"


class PresignOut(BaseModel):
    upload_url: str
    bucket: str
    key: str
    content_type: str


class CreateImageMessageIn(BaseModel):
    bucket: str
    key: str
    content_type: str = "image/jpeg"
    width: Optional[int] = None
    height: Optional[int] = None
    reply_to_message_id: Optional[str] = None


class MarkReadIn(BaseModel):
    last_read_at: int


class MuteIn(BaseModel):
    muted_until: int


class UpsertUserIn(BaseModel):
    user_id: str
    display_name: str
    email: Optional[str] = None


class TypingIn(BaseModel):
    is_typing: bool = True


class TypingUser(BaseModel):
    user_id: str
    updated_at: int


class PresenceHeartbeatIn(BaseModel):
    device: Optional[str] = None
    status: Optional[str] = None


class PresenceOut(BaseModel):
    user_id: str
    online: bool
    last_seen_at: int


class ParticipantOut(BaseModel):
    user_id: str
    status: str
    role: str
    muted_until: int = 0
    last_read_at: int = 0
    joined_at: int = 0
    left_at: int = 0


class ReactIn(BaseModel):
    emoji: str = Field(min_length=1, max_length=32)
    action: Literal["add", "remove"] = "add"


class EditMessageIn(BaseModel):
    text: str = Field(min_length=1, max_length=4000)


class ForwardMessageIn(BaseModel):
    source_conversation_id: str
    source_message_id: str
    note: Optional[str] = Field(default=None, max_length=1000)
    reply_to_message_id: Optional[str] = None


class ViewMessageIn(BaseModel):
    viewed_at: Optional[int] = None  # if omitted server uses now


class ViewAckOut(BaseModel):
    ok: bool
    conversation_id: str
    message_id: str
    viewer_id: str
    viewed_at: int


class MessageViewOut(BaseModel):
    user_id: str
    last_viewed_at: int
    view_count: int


class EditHistoryOut(BaseModel):
    edited_at: int
    edited_by: str
    old_text: str
    new_text: str


class MessageOut(BaseModel):
    conversation_id: str
    message_id: str
    sender_id: str
    created_at: int
    kind: Literal["text", "image"]
    text: Optional[str] = None
    image: Optional[Dict[str, Any]] = None

    reply_to_message_id: Optional[str] = None
    forwarded_from: Optional[Dict[str, Any]] = None
    forward_note: Optional[str] = None
    edited_at: Optional[int] = None
    edited_by: Optional[str] = None
    reactions_counts: Optional[Dict[str, int]] = None
    my_reactions: Optional[List[str]] = None


# -------------------------
# Helpers
# -------------------------

def now_ts() -> int:
    return int(time.time())


def new_id() -> str:
    return uuid.uuid4().hex


def _norm(s: str) -> str:
    s = (s or "").strip().lower()
    return "".join(ch for ch in s if ch.isalnum() or ch in "@._-")


def build_prefix_tokens(text: str, max_len: int = 12) -> list[str]:
    t = _norm(text)
    if not t:
        return []
    parts = [p for p in t.replace("@", " @").split() if p]
    out: list[str] = []
    for p in parts:
        for i in range(1, min(len(p), max_len) + 1):
            out.append(p[:i])
    return list(dict.fromkeys(out))


def get_participant_any(user_id: str, conversation_id: str) -> Optional[dict]:
    resp = tbl_parts.get_item(Key={"user_id": user_id, "conversation_id": conversation_id})
    return resp.get("Item")


def require_participant_active(user_id: str, conversation_id: str) -> dict:
    item = get_participant_any(user_id, conversation_id)
    if not item or item.get("status") != "active":
        raise HTTPException(status_code=403, detail="Not an active participant")
    return item


def _sse_pack(data: dict, event: str = "message") -> str:
    return f"event: {event}\ndata: {json.dumps(data, separators=(',', ':'))}\n\n"


def _ddb_fetch_events(user_id: str, after: Optional[str], limit: int) -> list[dict]:
    if after:
        resp = tbl_events.query(
            KeyConditionExpression=Key("user_id").eq(user_id) & Key("event_id").gt(after),
            Limit=limit,
            ScanIndexForward=True,
        )
    else:
        resp = tbl_events.query(
            KeyConditionExpression=Key("user_id").eq(user_id),
            Limit=limit,
            ScanIndexForward=True,
        )
    return resp.get("Items", [])


def _event_id() -> str:
    return f"e_{now_ts()}_{uuid.uuid4().hex}"


def fanout_event_to_conversation(
    conversation_id: str,
    sender_id: str,
    event_type: str,
    payload: dict,
    respect_mute: bool = True,
) -> None:
    resp = tbl_parts.query(IndexName="GSI1", KeyConditionExpression=Key("GSI1PK").eq(conversation_id))
    participants = resp.get("Items", [])
    ts = now_ts()
    ttl = ts + 7 * 24 * 3600

    with tbl_events.batch_writer() as bw:
        for p in participants:
            uid = p["user_id"]
            if uid == sender_id:
                continue
            if p.get("status") != "active":
                continue
            if respect_mute:
                mu = int(p.get("muted_until", 0) or 0)
                if mu and mu > ts:
                    continue
            bw.put_item(
                Item={
                    "user_id": uid,
                    "event_id": _event_id(),
                    "type": event_type,
                    "created_at": ts,
                    "conversation_id": conversation_id,
                    "payload": payload,
                    "ttl": ttl,
                }
            )


def _reaction_summaries(message_item: dict, viewer_user_id: str) -> tuple[Dict[str, int], List[str]]:
    reactions = message_item.get("reactions") or {}
    counts: Dict[str, int] = {}
    mine: List[str] = []
    for emoji, userset in reactions.items():
        if isinstance(userset, set):
            counts[emoji] = len(userset)
            if viewer_user_id in userset:
                mine.append(emoji)
        else:
            try:
                userset2 = set(userset)
                counts[emoji] = len(userset2)
                if viewer_user_id in userset2:
                    mine.append(emoji)
            except Exception:
                continue
    return counts, mine


def _get_message_or_404(conversation_id: str, message_id: str) -> dict:
    resp = tbl_msgs.get_item(Key={"conversation_id": conversation_id, "message_id": message_id})
    item = resp.get("Item")
    if not item:
        raise HTTPException(404, "Message not found")
    return item


def _validate_reply_target(conversation_id: str, reply_to_message_id: Optional[str]) -> None:
    if not reply_to_message_id:
        return
    _ = _get_message_or_404(conversation_id, reply_to_message_id)


def _message_key(conversation_id: str, message_id: str) -> str:
    return f"{conversation_id}#{message_id}"


# -------------------------
# Contacts
# -------------------------
@router.post("/admin/users/upsert")
def admin_upsert_user(inp: UpsertUserIn):
    ts = now_ts()
    tbl_users.put_item(
        Item={
            "user_id": inp.user_id,
            "display_name": inp.display_name,
            "email": inp.email or "",
            "updated_at": ts,
        }
    )

    tokens = set(build_prefix_tokens(inp.display_name))
    if inp.email:
        tokens |= set(build_prefix_tokens(inp.email))

    with tbl_search.batch_writer() as bw:
        for t in tokens:
            bw.put_item(
                Item={
                    "token": t,
                    "user_id": inp.user_id,
                    "display_name": inp.display_name,
                }
            )
    return {"ok": True, "tokens_written": len(tokens)}


@router.get("/contacts/search", response_model=List[Contact])
def search_contact(
    q: str = Query(..., min_length=1, max_length=64),
    limit: int = Query(10, ge=1, le=50),
    user_id: str = Depends(get_messaging_user_id),
):
    token = _norm(q)
    if not token:
        return []

    resp = tbl_search.query(KeyConditionExpression=Key("token").eq(token), Limit=limit)
    items = resp.get("Items", [])

    out: List[Contact] = []
    for it in items:
        uid = it["user_id"]
        if uid == user_id:
            continue
        out.append(Contact(user_id=uid, display_name=it.get("display_name", uid)))
    return out


# -------------------------
# Conversations
# -------------------------
@router.post("/conversations", response_model=ConversationOut)
def start_conversation(
    inp: StartConversationIn,
    req: Request = None,
    user_id: str = Depends(get_messaging_user_id),
):
    cid = "c_" + new_id()
    created_at = now_ts()

    participant_ids = list(dict.fromkeys([user_id] + inp.participant_ids))
    if inp.type == "dm" and len(participant_ids) != 2:
        raise HTTPException(400, "dm conversation must have exactly 2 unique participants")
    if inp.type == "group" and len(participant_ids) < 3:
        raise HTTPException(400, "group conversation must have at least 3 unique participants")
    for pid in participant_ids:
        if pid == user_id:
            continue
        require_subscription_access(user_id, pid)

    convo_item = {
        "conversation_id": cid,
        "created_at": created_at,
        "created_by": user_id,
        "type": inp.type,
        "title": inp.title,
        "participant_count": len(participant_ids),
        "last_message_at": 0,
        "last_message_preview": "",
    }
    tbl_convos.put_item(Item=convo_item, ConditionExpression="attribute_not_exists(conversation_id)")

    for pid in participant_ids:
        status = "active" if pid == user_id else "pending"
        tbl_parts.put_item(
            Item={
                "user_id": pid,
                "conversation_id": cid,
                "status": status,
                "role": "admin" if pid == user_id else "member",
                "muted_until": 0,
                "last_read_at": 0,
                "joined_at": created_at if status == "active" else 0,
                "left_at": 0,
                "GSI1PK": cid,
                "GSI1SK": pid,
            }
        )

    convo = ConversationOut(
        conversation_id=cid,
        type=inp.type,
        title=inp.title,
        created_at=created_at,
        created_by=user_id,
        participant_count=len(participant_ids),
        last_message_at=None,
        last_message_preview=None,
        status="active",
        muted_until=0,
        last_read_at=0,
    )
    audit_event(
        "messaging_conversation_started",
        user_id,
        req,
        outcome="success",
        conversation_id=cid,
        conversation_type=inp.type,
        participant_count=len(participant_ids),
    )
    return convo


@router.post("/conversations/group", response_model=ConversationOut)
def start_group_conversation(
    inp: StartGroupConversationIn,
    req: Request = None,
    user_id: str = Depends(get_messaging_user_id),
):
    return start_conversation(
        StartConversationIn(
            participant_ids=inp.participant_ids,
            type="group",
            title=inp.title,
        ),
        req,
        user_id=user_id,
    )


@router.post("/conversations/{conversation_id}/accept")
def accept_conversation(conversation_id: str, req: Request = None, user_id: str = Depends(get_messaging_user_id)):
    part = get_participant_any(user_id, conversation_id)
    if not part:
        raise HTTPException(404, "Not invited")
    if part.get("status") == "active":
        return {"ok": True}
    if part.get("status") != "pending":
        raise HTTPException(400, "Conversation not pending")

    ts = now_ts()
    tbl_parts.update_item(
        Key={"user_id": user_id, "conversation_id": conversation_id},
        UpdateExpression="SET #s = :active, joined_at = :ts",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={":active": "active", ":ts": ts, ":pending": "pending"},
        ConditionExpression="#s = :pending",
    )
    audit_event(
        "messaging_conversation_accepted",
        user_id,
        req,
        outcome="success",
        conversation_id=conversation_id,
    )
    return {"ok": True}


@router.get("/conversations", response_model=List[ConversationOut])
def list_conversations(user_id: str = Depends(get_messaging_user_id)):
    resp = tbl_parts.query(KeyConditionExpression=Key("user_id").eq(user_id), Limit=200)
    parts = resp.get("Items", [])
    out: List[ConversationOut] = []

    for p in parts:
        cid = p["conversation_id"]
        convo = tbl_convos.get_item(Key={"conversation_id": cid}).get("Item")
        if not convo:
            continue
        out.append(
            ConversationOut(
                conversation_id=cid,
                type=convo.get("type", "dm"),
                title=convo.get("title"),
                created_at=int(convo.get("created_at", 0)),
                created_by=convo.get("created_by", ""),
                participant_count=int(convo.get("participant_count", 0)),
                last_message_at=int(convo.get("last_message_at", 0)) or None,
                last_message_preview=convo.get("last_message_preview") or None,
                status=p.get("status", "pending"),
                muted_until=int(p.get("muted_until", 0) or 0),
                last_read_at=int(p.get("last_read_at", 0) or 0),
            )
        )

    out.sort(key=lambda x: (x.last_message_at or 0, x.created_at), reverse=True)
    return out


@router.post("/conversations/{conversation_id}/mute")
def mute_conversation(conversation_id: str, inp: MuteIn, req: Request = None, user_id: str = Depends(get_messaging_user_id)):
    part = get_participant_any(user_id, conversation_id)
    if not part:
        raise HTTPException(404, "Conversation not found for user")
    tbl_parts.update_item(
        Key={"user_id": user_id, "conversation_id": conversation_id},
        UpdateExpression="SET muted_until = :mu",
        ExpressionAttributeValues={":mu": int(inp.muted_until)},
    )
    audit_event(
        "messaging_conversation_muted",
        user_id,
        req,
        outcome="success",
        conversation_id=conversation_id,
        muted_until=int(inp.muted_until),
    )
    return {"ok": True, "muted_until": int(inp.muted_until)}


@router.post("/conversations/{conversation_id}/leave")
def leave_conversation(conversation_id: str, req: Request = None, user_id: str = Depends(get_messaging_user_id)):
    require_participant_active(user_id, conversation_id)
    ts = now_ts()

    tbl_parts.update_item(
        Key={"user_id": user_id, "conversation_id": conversation_id},
        UpdateExpression="SET #s = :left, left_at = :ts",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={":left": "left", ":ts": ts, ":active": "active"},
        ConditionExpression="#s = :active",
    )

    tbl_convos.update_item(
        Key={"conversation_id": conversation_id},
        UpdateExpression="ADD participant_count :neg",
        ExpressionAttributeValues={":neg": -1},
    )
    audit_event(
        "messaging_conversation_left",
        user_id,
        req,
        outcome="success",
        conversation_id=conversation_id,
    )
    return {"ok": True}


@router.delete("/conversations/{conversation_id}")
def delete_conversation_if_last(conversation_id: str, req: Request = None, user_id: str = Depends(get_messaging_user_id)):
    resp = tbl_parts.query(IndexName="GSI1", KeyConditionExpression=Key("GSI1PK").eq(conversation_id))
    items = resp.get("Items", [])
    active = [x for x in items if x.get("status") == "active"]

    if len(active) > 1:
        raise HTTPException(400, "Cannot delete conversation: other active participants exist")
    if len(active) == 1 and active[0]["user_id"] != user_id:
        raise HTTPException(403, "Only remaining active participant can delete conversation")

    tbl_convos.delete_item(Key={"conversation_id": conversation_id})
    for p in items:
        tbl_parts.delete_item(Key={"user_id": p["user_id"], "conversation_id": conversation_id})

    audit_event(
        "messaging_conversation_deleted",
        user_id,
        req,
        outcome="success",
        conversation_id=conversation_id,
    )
    return {"ok": True, "deleted": True}


@router.get("/conversations/{conversation_id}/participants", response_model=List[ParticipantOut])
def list_participants(conversation_id: str, user_id: str = Depends(get_messaging_user_id)):
    part = get_participant_any(user_id, conversation_id)
    if not part:
        raise HTTPException(403, "Not a participant")

    resp = tbl_parts.query(IndexName="GSI1", KeyConditionExpression=Key("GSI1PK").eq(conversation_id), Limit=500)
    items = resp.get("Items", [])

    out: List[ParticipantOut] = []
    for p in items:
        out.append(
            ParticipantOut(
                user_id=p["user_id"],
                status=p.get("status", "pending"),
                role=p.get("role", "member"),
                muted_until=int(p.get("muted_until", 0) or 0),
                last_read_at=int(p.get("last_read_at", 0) or 0),
                joined_at=int(p.get("joined_at", 0) or 0),
                left_at=int(p.get("left_at", 0) or 0),
            )
        )

    order = {"active": 0, "pending": 1, "left": 2}
    out.sort(key=lambda x: (order.get(x.status, 9), x.user_id))
    return out


# -------------------------
# Messages (list/send)
# -------------------------
@router.get("/conversations/{conversation_id}/messages", response_model=List[MessageOut])
def list_messages(
    conversation_id: str,
    limit: int = Query(50, ge=1, le=200),
    before: Optional[str] = None,
    user_id: str = Depends(get_messaging_user_id),
):
    require_participant_active(user_id, conversation_id)

    kwargs: Dict[str, Any] = {
        "KeyConditionExpression": Key("conversation_id").eq(conversation_id),
        "ScanIndexForward": False,
        "Limit": limit,
    }
    if before:
        kwargs["ExclusiveStartKey"] = {"conversation_id": conversation_id, "message_id": before}

    resp = tbl_msgs.query(**kwargs)
    items = resp.get("Items", [])

    out: List[MessageOut] = []
    for m in items:
        deleted_for = set(m.get("deleted_for", []))
        if user_id in deleted_for:
            continue

        counts, mine = _reaction_summaries(m, user_id)

        out.append(
            MessageOut(
                conversation_id=m["conversation_id"],
                message_id=m["message_id"],
                sender_id=m["sender_id"],
                created_at=int(m["created_at"]),
                kind=m["kind"],
                text=m.get("text"),
                image=m.get("image"),
                reply_to_message_id=m.get("reply_to_message_id"),
                forwarded_from=m.get("forwarded_from"),
                forward_note=m.get("forward_note"),
                edited_at=int(m.get("edited_at", 0)) or None,
                edited_by=m.get("edited_by"),
                reactions_counts=counts if counts else None,
                my_reactions=mine if mine else None,
            )
        )
    return out


@router.post("/conversations/{conversation_id}/messages", response_model=MessageOut)
def send_text_message(
    conversation_id: str,
    inp: SendTextMessageIn,
    req: Request = None,
    user_id: str = Depends(get_messaging_user_id),
):
    require_participant_active(user_id, conversation_id)
    resp = tbl_parts.query(IndexName="GSI1", KeyConditionExpression=Key("GSI1PK").eq(conversation_id))
    for participant in resp.get("Items", []):
        pid = participant.get("user_id")
        if pid and pid != user_id:
            require_subscription_access(user_id, pid)
    _validate_reply_target(conversation_id, inp.reply_to_message_id)

    mid = "m_" + new_id()
    ts = now_ts()

    item = {
        "conversation_id": conversation_id,
        "message_id": mid,
        "sender_id": user_id,
        "created_at": ts,
        "kind": "text",
        "text": inp.text,
        "deleted_for": set(),
        "reactions": {},
    }
    if inp.reply_to_message_id:
        item["reply_to_message_id"] = inp.reply_to_message_id

    tbl_msgs.put_item(Item=item)

    preview = inp.text[:140]
    tbl_convos.update_item(
        Key={"conversation_id": conversation_id},
        UpdateExpression="SET last_message_at = :ts, last_message_preview = :p",
        ExpressionAttributeValues={":ts": ts, ":p": preview},
    )

    message = MessageOut(
        conversation_id=conversation_id,
        message_id=mid,
        sender_id=user_id,
        created_at=ts,
        kind="text",
        text=inp.text,
        reply_to_message_id=inp.reply_to_message_id,
    )
    audit_event(
        "messaging_message_sent",
        user_id,
        req,
        outcome="success",
        conversation_id=conversation_id,
        message_id=mid,
        kind="text",
        reply_to_message_id=inp.reply_to_message_id,
    )
    return message


@router.post("/conversations/{conversation_id}/images/presign", response_model=PresignOut)
def presign_image_upload(conversation_id: str, inp: SendImagePresignIn, user_id: str = Depends(get_messaging_user_id)):
    require_participant_active(user_id, conversation_id)
    key = f"{conversation_id}/{user_id}/{now_ts()}_{uuid.uuid4().hex}_{inp.filename}"
    upload_url = s3.generate_presigned_url(
        ClientMethod="put_object",
        Params={"Bucket": S3_BUCKET_IMAGES, "Key": key, "ContentType": inp.content_type},
        ExpiresIn=900,
    )
    return PresignOut(upload_url=upload_url, bucket=S3_BUCKET_IMAGES, key=key, content_type=inp.content_type)


@router.post("/conversations/{conversation_id}/messages/image", response_model=MessageOut)
def create_image_message(
    conversation_id: str,
    inp: CreateImageMessageIn,
    req: Request = None,
    user_id: str = Depends(get_messaging_user_id),
):
    require_participant_active(user_id, conversation_id)
    resp = tbl_parts.query(IndexName="GSI1", KeyConditionExpression=Key("GSI1PK").eq(conversation_id))
    for participant in resp.get("Items", []):
        pid = participant.get("user_id")
        if pid and pid != user_id:
            require_subscription_access(user_id, pid)
    _validate_reply_target(conversation_id, inp.reply_to_message_id)

    mid = "m_" + new_id()
    ts = now_ts()

    item = {
        "conversation_id": conversation_id,
        "message_id": mid,
        "sender_id": user_id,
        "created_at": ts,
        "kind": "image",
        "image": {
            "bucket": inp.bucket,
            "key": inp.key,
            "content_type": inp.content_type,
            "width": inp.width,
            "height": inp.height,
        },
        "deleted_for": set(),
        "reactions": {},
    }
    if inp.reply_to_message_id:
        item["reply_to_message_id"] = inp.reply_to_message_id

    tbl_msgs.put_item(Item=item)

    tbl_convos.update_item(
        Key={"conversation_id": conversation_id},
        UpdateExpression="SET last_message_at = :ts, last_message_preview = :p",
        ExpressionAttributeValues={":ts": ts, ":p": "[image]"},
    )

    message = MessageOut(
        conversation_id=conversation_id,
        message_id=mid,
        sender_id=user_id,
        created_at=ts,
        kind="image",
        image=item["image"],
        reply_to_message_id=inp.reply_to_message_id,
    )
    audit_event(
        "messaging_message_sent",
        user_id,
        req,
        outcome="success",
        conversation_id=conversation_id,
        message_id=mid,
        kind="image",
        reply_to_message_id=inp.reply_to_message_id,
    )
    return message


@router.post("/conversations/{conversation_id}/read")
def mark_read(conversation_id: str, inp: MarkReadIn, req: Request = None, user_id: str = Depends(get_messaging_user_id)):
    require_participant_active(user_id, conversation_id)

    part = get_participant_any(user_id, conversation_id) or {}
    current = int(part.get("last_read_at", 0) or 0)
    newv = max(current, int(inp.last_read_at))

    tbl_parts.update_item(
        Key={"user_id": user_id, "conversation_id": conversation_id},
        UpdateExpression="SET last_read_at = :v",
        ExpressionAttributeValues={":v": newv},
    )
    audit_event(
        "messaging_conversation_read",
        user_id,
        req,
        outcome="success",
        conversation_id=conversation_id,
        last_read_at=newv,
    )
    return {"ok": True, "last_read_at": newv}


@router.delete("/conversations/{conversation_id}/messages/{message_id}")
def delete_message_for_me(
    conversation_id: str,
    message_id: str,
    req: Request = None,
    user_id: str = Depends(get_messaging_user_id),
):
    require_participant_active(user_id, conversation_id)
    tbl_msgs.update_item(
        Key={"conversation_id": conversation_id, "message_id": message_id},
        UpdateExpression="ADD deleted_for :u",
        ExpressionAttributeValues={":u": {user_id}},
    )
    audit_event(
        "messaging_message_deleted",
        user_id,
        req,
        outcome="success",
        conversation_id=conversation_id,
        message_id=message_id,
    )
    return {"ok": True}


# -------------------------
# React to message
# -------------------------
@router.post("/conversations/{conversation_id}/messages/{message_id}/reactions")
def react_to_message(
    conversation_id: str,
    message_id: str,
    inp: ReactIn,
    req: Request = None,
    user_id: str = Depends(get_messaging_user_id),
):
    require_participant_active(user_id, conversation_id)

    expr_names = {"#e": inp.emoji}
    expr_vals = {":empty": set(), ":u": {user_id}}

    if inp.action == "add":
        update_expr = "SET reactions.#e = if_not_exists(reactions.#e, :empty) ADD reactions.#e :u"
    else:
        update_expr = "SET reactions.#e = if_not_exists(reactions.#e, :empty) DELETE reactions.#e :u"

    try:
        tbl_msgs.update_item(
            Key={"conversation_id": conversation_id, "message_id": message_id},
            UpdateExpression=update_expr,
            ExpressionAttributeNames=expr_names,
            ExpressionAttributeValues=expr_vals,
            ConditionExpression="attribute_exists(message_id)",
        )
    except Exception as e:
        raise HTTPException(400, f"Reaction update failed: {str(e)}")

    ts = now_ts()
    fanout_event_to_conversation(
        conversation_id=conversation_id,
        sender_id=user_id,
        event_type="reaction:update",
        payload={
            "message_id": message_id,
            "emoji": inp.emoji,
            "action": inp.action,
            "user_id": user_id,
            "updated_at": ts,
        },
        respect_mute=False,
    )
    audit_event(
        "messaging_message_reaction",
        user_id,
        req,
        outcome="success",
        conversation_id=conversation_id,
        message_id=message_id,
        emoji=inp.emoji,
        action=inp.action,
    )
    return {"ok": True}


# -------------------------
# Edit message (+ edit history)
# -------------------------
@router.patch("/conversations/{conversation_id}/messages/{message_id}", response_model=MessageOut)
def edit_message(
    conversation_id: str,
    message_id: str,
    inp: EditMessageIn,
    req: Request = None,
    user_id: str = Depends(get_messaging_user_id),
):
    require_participant_active(user_id, conversation_id)

    msg = _get_message_or_404(conversation_id, message_id)
    if msg.get("kind") != "text":
        raise HTTPException(400, "Only text messages can be edited")
    if msg.get("sender_id") != user_id:
        raise HTTPException(403, "Only the sender can edit this message")

    old_text = msg.get("text") or ""
    new_text = inp.text
    if new_text == old_text:
        return MessageOut(
            conversation_id=msg["conversation_id"],
            message_id=msg["message_id"],
            sender_id=msg["sender_id"],
            created_at=int(msg["created_at"]),
            kind=msg["kind"],
            text=old_text,
            reply_to_message_id=msg.get("reply_to_message_id"),
            forwarded_from=msg.get("forwarded_from"),
            forward_note=msg.get("forward_note"),
            edited_at=int(msg.get("edited_at", 0)) or None,
            edited_by=msg.get("edited_by"),
        )

    ts = now_ts()

    tbl_edits.put_item(
        Item={
            "message_key": _message_key(conversation_id, message_id),
            "edited_at": ts,
            "edited_by": user_id,
            "old_text": old_text,
            "new_text": new_text,
            "ttl": ts + EDITS_TTL_SEC,
        }
    )

    try:
        tbl_msgs.update_item(
            Key={"conversation_id": conversation_id, "message_id": message_id},
            UpdateExpression="SET #t = :text, edited_at = :ts, edited_by = :uid",
            ExpressionAttributeNames={"#t": "text"},
            ExpressionAttributeValues={
                ":text": new_text,
                ":ts": ts,
                ":uid": user_id,
                ":kind_text": "text",
            },
            ConditionExpression="sender_id = :uid AND kind = :kind_text",
        )
    except Exception as e:
        raise HTTPException(400, f"Edit failed: {str(e)}")

    item = _get_message_or_404(conversation_id, message_id)
    counts, mine = _reaction_summaries(item, user_id)

    fanout_event_to_conversation(
        conversation_id=conversation_id,
        sender_id=user_id,
        event_type="message:edited",
        payload={"message_id": message_id, "edited_at": ts},
        respect_mute=False,
    )

    message = MessageOut(
        conversation_id=item["conversation_id"],
        message_id=item["message_id"],
        sender_id=item["sender_id"],
        created_at=int(item["created_at"]),
        kind=item["kind"],
        text=item.get("text"),
        image=item.get("image"),
        reply_to_message_id=item.get("reply_to_message_id"),
        forwarded_from=item.get("forwarded_from"),
        forward_note=item.get("forward_note"),
        edited_at=int(item.get("edited_at", 0)) or None,
        edited_by=item.get("edited_by"),
        reactions_counts=counts if counts else None,
        my_reactions=mine if mine else None,
    )
    audit_event(
        "messaging_message_edited",
        user_id,
        req,
        outcome="success",
        conversation_id=conversation_id,
        message_id=message_id,
    )
    return message


# -------------------------
# Check message edit history
# -------------------------
@router.get("/conversations/{conversation_id}/messages/{message_id}/edits", response_model=List[EditHistoryOut])
def get_edit_history(
    conversation_id: str,
    message_id: str,
    limit: int = Query(50, ge=1, le=200),
    user_id: str = Depends(get_messaging_user_id),
):
    require_participant_active(user_id, conversation_id)

    _ = _get_message_or_404(conversation_id, message_id)

    resp = tbl_edits.query(
        KeyConditionExpression=Key("message_key").eq(_message_key(conversation_id, message_id)),
        ScanIndexForward=False,
        Limit=limit,
    )
    items = resp.get("Items", [])

    out: List[EditHistoryOut] = []
    for it in items:
        out.append(
            EditHistoryOut(
                edited_at=int(it.get("edited_at", 0) or 0),
                edited_by=it.get("edited_by", ""),
                old_text=it.get("old_text", ""),
                new_text=it.get("new_text", ""),
            )
        )
    return out


# -------------------------
# Forward message
# -------------------------
@router.post("/conversations/{target_conversation_id}/messages/forward", response_model=MessageOut)
def forward_message(
    target_conversation_id: str,
    inp: ForwardMessageIn,
    req: Request = None,
    user_id: str = Depends(get_messaging_user_id),
):
    require_participant_active(user_id, target_conversation_id)
    require_participant_active(user_id, inp.source_conversation_id)

    _validate_reply_target(target_conversation_id, inp.reply_to_message_id)

    src = _get_message_or_404(inp.source_conversation_id, inp.source_message_id)
    if user_id in set(src.get("deleted_for", [])):
        raise HTTPException(403, "Cannot forward a message you deleted")

    mid = "m_" + new_id()
    ts = now_ts()

    forwarded_from = {
        "conversation_id": inp.source_conversation_id,
        "message_id": inp.source_message_id,
        "sender_id": src.get("sender_id"),
        "created_at": int(src.get("created_at", 0) or 0),
    }

    kind = src.get("kind")
    if kind not in ("text", "image"):
        raise HTTPException(400, "Unsupported source message kind")

    item: Dict[str, Any] = {
        "conversation_id": target_conversation_id,
        "message_id": mid,
        "sender_id": user_id,
        "created_at": ts,
        "kind": kind,
        "deleted_for": set(),
        "reactions": {},
        "forwarded_from": forwarded_from,
    }

    if inp.note:
        item["forward_note"] = inp.note
    if inp.reply_to_message_id:
        item["reply_to_message_id"] = inp.reply_to_message_id

    if kind == "text":
        item["text"] = src.get("text", "")
        preview = "[fwd] " + (item["text"] or "")[:140]
    else:
        item["image"] = src.get("image")
        preview = "[fwd image]"

    tbl_msgs.put_item(Item=item)

    tbl_convos.update_item(
        Key={"conversation_id": target_conversation_id},
        UpdateExpression="SET last_message_at = :ts, last_message_preview = :p",
        ExpressionAttributeValues={":ts": ts, ":p": preview},
    )

    fanout_event_to_conversation(
        conversation_id=target_conversation_id,
        sender_id=user_id,
        event_type="message:forwarded",
        payload={"message_id": mid, "forwarded_from": forwarded_from, "created_at": ts},
        respect_mute=False,
    )

    message = MessageOut(
        conversation_id=target_conversation_id,
        message_id=mid,
        sender_id=user_id,
        created_at=ts,
        kind=kind,
        text=item.get("text"),
        image=item.get("image"),
        reply_to_message_id=item.get("reply_to_message_id"),
        forwarded_from=item.get("forwarded_from"),
        forward_note=item.get("forward_note"),
    )
    audit_event(
        "messaging_message_forwarded",
        user_id,
        req,
        outcome="success",
        conversation_id=target_conversation_id,
        message_id=mid,
        source_conversation_id=inp.source_conversation_id,
        source_message_id=inp.source_message_id,
    )
    return message


# -------------------------
# Message view history (+ send timestamp)
# -------------------------
@router.post("/conversations/{conversation_id}/messages/{message_id}/view", response_model=ViewAckOut)
def mark_message_viewed(
    conversation_id: str,
    message_id: str,
    inp: ViewMessageIn,
    req: Request = None,
    user_id: str = Depends(get_messaging_user_id),
):
    """
    Call when a message becomes visible in the UI.
    Stores a per-(message,user) receipt with last_viewed_at + view_count.
    Returns the stored timestamp (server-controlled).
    """
    require_participant_active(user_id, conversation_id)
    _ = _get_message_or_404(conversation_id, message_id)

    ts = int(inp.viewed_at) if inp.viewed_at else now_ts()
    if ts > now_ts() + 300:
        ts = now_ts()

    key = {"conversation_id": conversation_id, "message_user": f"{message_id}#{user_id}"}

    tbl_views.update_item(
        Key=key,
        UpdateExpression=(
            "SET message_id = :mid, user_id = :uid, last_viewed_at = :ts, ttl = :ttl "
            "ADD view_count :one"
        ),
        ExpressionAttributeValues={
            ":mid": message_id,
            ":uid": user_id,
            ":ts": ts,
            ":ttl": ts + VIEWS_TTL_SEC,
            ":one": 1,
        },
    )

    fanout_event_to_conversation(
        conversation_id=conversation_id,
        sender_id=user_id,
        event_type="message:viewed",
        payload={"message_id": message_id, "viewer_id": user_id, "viewed_at": ts},
        respect_mute=False,
    )

    ack = ViewAckOut(
        ok=True,
        conversation_id=conversation_id,
        message_id=message_id,
        viewer_id=user_id,
        viewed_at=ts,
    )
    audit_event(
        "messaging_message_viewed",
        user_id,
        req,
        outcome="success",
        conversation_id=conversation_id,
        message_id=message_id,
        viewed_at=ts,
    )
    return ack


@router.get("/conversations/{conversation_id}/messages/{message_id}/views", response_model=List[MessageViewOut])
def get_message_views(
    conversation_id: str,
    message_id: str,
    limit: int = Query(200, ge=1, le=500),
    user_id: str = Depends(get_messaging_user_id),
):
    """
    Returns who has viewed a message and their last_viewed_at (timestamp) + count.
    """
    require_participant_active(user_id, conversation_id)
    _ = _get_message_or_404(conversation_id, message_id)

    resp = tbl_views.query(
        KeyConditionExpression=Key("conversation_id").eq(conversation_id)
        & Key("message_user").begins_with(f"{message_id}#"),
        Limit=limit,
        ScanIndexForward=True,
    )
    items = resp.get("Items", [])

    out: List[MessageViewOut] = []
    for it in items:
        out.append(
            MessageViewOut(
                user_id=it.get("user_id", ""),
                last_viewed_at=int(it.get("last_viewed_at", 0) or 0),
                view_count=int(it.get("view_count", 0) or 0),
            )
        )

    out.sort(key=lambda x: x.last_viewed_at, reverse=True)
    return out


# -------------------------
# Typing indicator
# -------------------------
@router.post("/conversations/{conversation_id}/typing")
def set_typing(conversation_id: str, inp: TypingIn, user_id: str = Depends(get_messaging_user_id)):
    require_participant_active(user_id, conversation_id)
    ts = now_ts()

    tbl_typing.put_item(
        Item={
            "conversation_id": conversation_id,
            "user_id": user_id,
            "is_typing": bool(inp.is_typing),
            "updated_at": ts,
            "ttl": ts + TYPING_TTL_SEC,
        }
    )

    fanout_event_to_conversation(
        conversation_id=conversation_id,
        sender_id=user_id,
        event_type="typing:update",
        payload={"user_id": user_id, "is_typing": bool(inp.is_typing), "updated_at": ts},
        respect_mute=False,
    )
    return {"ok": True, "is_typing": bool(inp.is_typing), "ttl": ts + TYPING_TTL_SEC}


@router.get("/conversations/{conversation_id}/typing", response_model=List[TypingUser])
def get_typing(conversation_id: str, user_id: str = Depends(get_messaging_user_id)):
    require_participant_active(user_id, conversation_id)

    resp = tbl_typing.query(KeyConditionExpression=Key("conversation_id").eq(conversation_id), Limit=200)
    items = resp.get("Items", [])
    ts = now_ts()

    out: List[TypingUser] = []
    for it in items:
        ttl = int(it.get("ttl", 0) or 0)
        if ttl and ttl <= ts:
            continue
        if not it.get("is_typing", False):
            continue
        out.append(TypingUser(user_id=it["user_id"], updated_at=int(it.get("updated_at", 0) or 0)))
    return out


# -------------------------
# Presence (online)
# -------------------------
@router.post("/presence/heartbeat")
def presence_heartbeat(inp: PresenceHeartbeatIn, user_id: str = Depends(get_messaging_user_id)):
    ts = now_ts()
    tbl_presence.put_item(
        Item={
            "user_id": user_id,
            "last_seen_at": ts,
            "device": inp.device or "",
            "status": inp.status or "online",
            "ttl": ts + PRESENCE_TTL_SEC,
        }
    )
    return {"ok": True, "user_id": user_id, "online": True, "last_seen_at": ts}


@router.get("/presence", response_model=List[PresenceOut])
def presence_get(
    user_ids: str = Query(..., description="Comma-separated user_ids"),
    user_id: str = Depends(get_messaging_user_id),
):
    ids = [x.strip() for x in user_ids.split(",") if x.strip()]
    if len(ids) > 200:
        raise HTTPException(400, "Too many user_ids (max 200)")

    keys = [{"user_id": uid} for uid in ids]
    resp = ddb.meta.client.batch_get_item(RequestItems={DDB_PRESENCE: {"Keys": keys}})
    items = resp.get("Responses", {}).get(DDB_PRESENCE, [])
    mp = {it["user_id"]: it for it in items}

    ts = now_ts()
    out: List[PresenceOut] = []
    for uid in ids:
        it = mp.get(uid)
        last_seen = int(it.get("last_seen_at", 0) or 0) if it else 0
        online = (ts - last_seen) <= ONLINE_WINDOW_SEC if last_seen else False
        out.append(PresenceOut(user_id=uid, online=online, last_seen_at=last_seen))
    return out


# -------------------------
# Events (poll + SSE)
# -------------------------
@router.get("/events")
def fetch_events(
    after: Optional[str] = None,
    limit: int = Query(50, ge=1, le=200),
    user_id: str = Depends(get_messaging_user_id),
):
    items = _ddb_fetch_events(user_id, after, limit)
    return {"events": items, "next_after": items[-1]["event_id"] if items else after}


@router.get("/events/stream")
async def events_stream(
    after: Optional[str] = None,
    limit: int = Query(50, ge=1, le=200),
    poll_ms: int = Query(1000, ge=200, le=5000),
    user_id: str = Depends(get_messaging_user_id),
):
    async def gen():
        cursor = after
        last_ping = time.time()
        yield ": stream-open\n\n"

        while True:
            now = time.time()
            if now - last_ping > 15:
                yield ": ping\n\n"
                last_ping = now

            events = await anyio.to_thread.run_sync(_ddb_fetch_events, user_id, cursor, limit)
            if events:
                for ev in events:
                    cursor = ev["event_id"]
                    yield _sse_pack(ev, event=ev.get("type", "message"))
                continue

            await asyncio.sleep(poll_ms / 1000.0)

    return StreamingResponse(gen(), media_type="text/event-stream")


@router.get("/healthz")
def healthz():
    return {"ok": True, "ts": now_ts()}
