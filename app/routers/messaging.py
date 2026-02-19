from __future__ import annotations

import asyncio
import base64
import binascii
import json
import logging
import os
import re
import time
import uuid
from html.parser import HTMLParser
from typing import Annotated, Any, Dict, Iterable, List, Literal, Optional, Sequence
from urllib.parse import urljoin, urlparse

import anyio
import boto3
from boto3.dynamodb.conditions import Attr, Key
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.exceptions import ClientError, NoCredentialsError
import requests
import snowballstemmer
from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field, model_validator
from pydantic_core import PydanticCustomError

from app.auth.deps import extract_bearer_token, get_authenticated_user_sub
from app.metrics import record_helpdesk_alert_sent, record_helpdesk_claim
from app.core.settings import S
from app.core.aws import ddb
from app.core.aws_clients import s3_client
from app.services.alerts import audit_event
from app.services.messaging_routing import (
    RoutingTransitionError,
    RoutingTransitionInput,
    build_routing_event_item,
    transition_helpdesk_routing,
)
from app.services.filemanager import get_node, get_usage_summary, norm_path
from app.services.sessions import require_ui_session
from app.services.subscription_access import require_subscription_access
from app.services.usage_metering import (
    build_usage_event,
    build_usage_source_idempotency_key,
    record_usage_event_and_aggregates,
)

# -------------------------
# Config / AWS clients
# -------------------------
AWS_REGION = S.aws_region or os.getenv("AWS_REGION", "us-east-1")

DDB_CONVERSATIONS = os.getenv("DDB_CONVERSATIONS", "Conversations")
DDB_PARTICIPANTS = os.getenv("DDB_PARTICIPANTS", "Participants")
DDB_MESSAGES = os.getenv("DDB_MESSAGES", "Messages")
DDB_USER_EVENTS = os.getenv("DDB_USER_EVENTS", "UserEvents")
DDB_CONVERSATION_ROUTING_EVENTS = os.getenv("DDB_CONVERSATION_ROUTING_EVENTS", "ConversationRoutingEvents")

DDB_USERS = os.getenv("DDB_USERS", "Users")
DDB_USER_SEARCH = os.getenv("DDB_USER_SEARCH", "UserSearch")
DDB_MESSAGE_SEARCH = os.getenv("DDB_MESSAGE_SEARCH", "MessageSearch")
OPENSEARCH_ENDPOINT = os.getenv("OPENSEARCH_ENDPOINT", "").strip()
OPENSEARCH_INDEX = os.getenv("OPENSEARCH_INDEX", "messages")
OPENSEARCH_REGION = os.getenv("OPENSEARCH_REGION", AWS_REGION)

DDB_PRESENCE = os.getenv("DDB_PRESENCE", "UserPresence")
DDB_TYPING = os.getenv("DDB_TYPING", "Typing")

DDB_MESSAGE_EDITS = os.getenv("DDB_MESSAGE_EDITS", "MessageEdits")
DDB_MESSAGE_VIEWS = os.getenv("DDB_MESSAGE_VIEWS", "MessageViews")
DDB_MESSAGE_RECEIPTS = os.getenv("DDB_MESSAGE_RECEIPTS", "MessageReceipts")

S3_BUCKET_IMAGES = os.getenv("S3_BUCKET_IMAGES", "my-chat-images")

ONLINE_WINDOW_SEC = int(os.getenv("ONLINE_WINDOW_SEC", "30"))
PRESENCE_TTL_SEC = int(os.getenv("PRESENCE_TTL_SEC", "120"))
TYPING_TTL_SEC = int(os.getenv("TYPING_TTL_SEC", "10"))

VIEWS_TTL_SEC = int(os.getenv("VIEWS_TTL_SEC", "2592000"))  # 30d
EDITS_TTL_SEC = int(os.getenv("EDITS_TTL_SEC", "7776000"))  # 90d
MESSAGE_REVOKE_WINDOW_SEC = int(os.getenv("MESSAGE_REVOKE_WINDOW_SEC", "300"))
HELPDESK_GROUP_MEMBERS_JSON = os.getenv("HELPDESK_GROUP_MEMBERS_JSON", "").strip()

s3 = s3_client()


tbl_convos = ddb.Table(DDB_CONVERSATIONS)
tbl_parts = ddb.Table(DDB_PARTICIPANTS)
tbl_msgs = ddb.Table(DDB_MESSAGES)
tbl_events = ddb.Table(DDB_USER_EVENTS)
tbl_routing_events = ddb.Table(DDB_CONVERSATION_ROUTING_EVENTS)
tbl_users = ddb.Table(DDB_USERS)
tbl_search = ddb.Table(DDB_USER_SEARCH)
tbl_msg_search = ddb.Table(DDB_MESSAGE_SEARCH)
tbl_presence = ddb.Table(DDB_PRESENCE)
tbl_typing = ddb.Table(DDB_TYPING)

tbl_edits = ddb.Table(DDB_MESSAGE_EDITS)
tbl_views = ddb.Table(DDB_MESSAGE_VIEWS)
tbl_receipts = ddb.Table(DDB_MESSAGE_RECEIPTS)

router = APIRouter(prefix="/messaging", tags=["messaging"])
logger = logging.getLogger(__name__)

MESSAGE_TEXT_MAX_CHARS = 4000
ENCRYPTED_CIPHERTEXT_MAX_BYTES = 8192
ENCRYPTED_EDIT_ERROR_CODE = "encrypted_message_edit_unsupported"
NO_AGENTS_ONLINE_NOTICE_TEXT = "No helpdesk agents are online right now. Please try again later."
NO_AGENTS_NOTICE_THROTTLE_SEC = int(os.getenv("NO_AGENTS_NOTICE_THROTTLE_SEC", "600"))
HELPDESK_AUTO_CLAIM_ON_REPLY_ENABLED = os.getenv("HELPDESK_AUTO_CLAIM_ON_REPLY_ENABLED", "0").strip().lower() in {"1", "true", "yes", "on"}


# -------------------------
# Auth (Bearer token)
# -------------------------
def get_current_user_id(authorization: Optional[str] = Header(default=None)) -> str:
    """
    Replace with real JWT verification.
    Dev behavior: Authorization: Bearer <user_id>
    """
    return extract_bearer_token(authorization)


def _meter_message_send(*, user_id: str, conversation_id: str, message_id: str) -> None:
    """Record one message-send unit usage event for a persisted message."""
    table_name = getattr(S, "filemgr_table_name", None)
    if not table_name:
        return
    try:
        key = build_usage_source_idempotency_key(
            "messaging_send",
            user_id=user_id,
            conversation_id=conversation_id,
            message_id=message_id,
        )
        event = build_usage_event(
            user_id=user_id,
            event_type="upload",
            bytes_count=0,
            source="messaging_send",
            resource_path=f"/messaging/{conversation_id}/{message_id}",
            idempotency_key=key,
        )
        record_usage_event_and_aggregates(ddb.Table(table_name), event)
    except Exception:
        logger.exception(
            "messaging send usage metering failed",
            extra={"conversation_id": conversation_id, "message_id": message_id, "user_id": user_id},
        )


def _meter_messaging_attachment_upload(
    *,
    user_id: str,
    bucket: str,
    key: str,
    conversation_id: str,
    message_id: str,
) -> None:
    """Record authoritative attachment upload bytes using object metadata."""
    table_name = getattr(S, "filemgr_table_name", None)
    if not table_name:
        return
    try:
        head = s3.head_object(Bucket=bucket, Key=key)
        size_bytes = int(head.get("ContentLength") or 0)
        if size_bytes <= 0:
            return
        idempotency_key = build_usage_source_idempotency_key(
            "messaging_attachment_upload",
            user_id=user_id,
            attachment_key=f"{bucket}/{key}",
            operation_id=message_id,
        )
        event = build_usage_event(
            user_id=user_id,
            event_type="upload",
            bytes_count=size_bytes,
            source="messaging_attachment_upload",
            resource_path=f"/messaging/{conversation_id}/{message_id}/attachments/{key}",
            idempotency_key=idempotency_key,
        )
        record_usage_event_and_aggregates(ddb.Table(table_name), event)
    except Exception:
        logger.exception(
            "messaging attachment upload metering failed",
            extra={
                "conversation_id": conversation_id,
                "message_id": message_id,
                "user_id": user_id,
                "bucket": bucket,
                "key": key,
            },
        )


def _record_messaging_attachment_download(
    *,
    user_id: str,
    conversation_id: str,
    message_id: str,
    attachment_key: str,
    bytes_count: int,
    idempotency_operation_id: Optional[str] = None,
) -> None:
    table_name = getattr(S, "filemgr_table_name", None)
    if not table_name or bytes_count <= 0:
        return
    try:
        idempotency_key = build_usage_source_idempotency_key(
            "messaging_attachment_download",
            user_id=user_id,
            attachment_key=attachment_key,
            operation_id=idempotency_operation_id or message_id,
        )
        event = build_usage_event(
            user_id=user_id,
            event_type="download",
            bytes_count=bytes_count,
            source="messaging_attachment_download",
            resource_path=f"/messaging/{conversation_id}/{message_id}/attachments/{attachment_key}",
            idempotency_key=idempotency_key,
        )
        record_usage_event_and_aggregates(ddb.Table(table_name), event)
    except Exception:
        logger.exception(
            "messaging attachment download metering failed",
            extra={
                "conversation_id": conversation_id,
                "message_id": message_id,
                "user_id": user_id,
                "attachment_key": attachment_key,
                "bytes_count": bytes_count,
            },
        )


def _messaging_quota_error(*, period_id: str, limit_count: int, used_count: int) -> HTTPException:
    remaining_count = max(0, int(limit_count) - int(used_count))
    return HTTPException(
        status_code=403,
        detail={
            "code": "messaging_send_quota_exceeded",
            "message": "messaging send quota exceeded",
            "quota_type": "messaging_send",
            "period_id": period_id,
            "limit_count": int(limit_count),
            "used_count": int(used_count),
            "remaining_count": remaining_count,
        },
    )


def _emit_messaging_quota_warning(
    *,
    threshold_percent: int,
    user_id: str,
    conversation_id: str,
    period_id: str,
    limit_count: int,
    projected_count: int,
    req: Optional[Request],
) -> None:
    logger.warning(
        "messaging send quota warning threshold crossed",
        extra={
            "user_id": user_id,
            "conversation_id": conversation_id,
            "period_id": period_id,
            "threshold_percent": threshold_percent,
            "limit_count": int(limit_count),
            "projected_count": int(projected_count),
        },
    )
    try:
        audit_event(
            "messaging_send_quota_warning",
            user_id,
            req,
            outcome="warning",
            conversation_id=conversation_id,
            period_id=period_id,
            threshold_percent=threshold_percent,
            limit_count=int(limit_count),
            projected_count=int(projected_count),
        )
    except Exception:
        logger.exception(
            "failed to emit messaging send quota warning audit event",
            extra={"user_id": user_id, "conversation_id": conversation_id, "threshold_percent": threshold_percent},
        )


def _enforce_message_send_quota_precheck(*, user_id: str, conversation_id: str, req: Optional[Request]) -> None:
    table_name = getattr(S, "filemgr_table_name", None)
    if not table_name:
        return
    try:
        usage = get_usage_summary(user_id)
    except Exception:
        logger.exception("failed to load usage summary for messaging quota pre-check", extra={"user_id": user_id})
        return

    message_usage = usage.get("message_send") or {}
    used_count = int(message_usage.get("used_count") or 0)
    limit_count = int(message_usage.get("limit_count") or 0)
    period_id = str(usage.get("period_id") or "")

    if limit_count > 0 and used_count >= limit_count:
        raise _messaging_quota_error(period_id=period_id, limit_count=limit_count, used_count=used_count)

    if not bool(getattr(S, "messaging_send_quota_soft_warnings_enabled", False)):
        return

    if limit_count <= 0:
        return

    projected_count = used_count + 1
    for threshold in (80, 95):
        trigger_at = max(1, int((limit_count * threshold + 99) // 100))
        if used_count < trigger_at <= projected_count:
            _emit_messaging_quota_warning(
                threshold_percent=threshold,
                user_id=user_id,
                conversation_id=conversation_id,
                period_id=period_id,
                limit_count=limit_count,
                projected_count=projected_count,
                req=req,
            )


async def get_messaging_user_id(
    request: Request,
    authorization: Optional[str] = Header(default=None),
    x_session_id: Optional[str] = Header(default=None, alias="X-SESSION-ID"),
) -> str:
    cookies = getattr(request, "cookies", {}) or {}
    if x_session_id or cookies.get(S.ui_session_cookie_name):
        user_sub = await get_authenticated_user_sub(request)
        ctx = await require_ui_session(request, user_sub=user_sub, x_session_id=x_session_id)
        return ctx["user_sub"]
    return get_current_user_id(authorization)


def _helpdesk_virtual_participant_id(group_id: str) -> str:
    return f"helpdesk_group:{group_id}"




# -------------------------
# Models
# -------------------------
class Contact(BaseModel):
    user_id: str
    display_name: str


class StartConversationIn(BaseModel):
    participant_ids: List[str] = Field(default_factory=list)
    participant_id: Optional[str] = None
    type: Literal["dm", "group"] = "dm"
    title: Optional[str] = None
    description: Optional[str] = Field(default=None, max_length=500)
    icon: Optional[str] = Field(default=None, max_length=500)
    topic: Optional[str] = Field(default=None, max_length=200)
    retention_days: Optional[int] = Field(default=None, ge=1, le=3650)
    routing_mode: Literal["standard", "helpdesk_bridge"] = "standard"
    helpdesk_group_id: Optional[str] = Field(default=None, max_length=128)

    @model_validator(mode="before")
    @classmethod
    def _normalize_legacy_fields(cls, data: Any):
        if not isinstance(data, dict):
            return data
        payload = dict(data)
        if not payload.get("participant_ids") and payload.get("participant_id"):
            payload["participant_ids"] = [payload["participant_id"]]
            logger.warning("messaging.start_conversation legacy payload used: participant_id")
        return payload

    @model_validator(mode="after")
    def _validate_helpdesk_routing(self):
        if self.routing_mode == "helpdesk_bridge":
            if not self.helpdesk_group_id:
                raise PydanticCustomError(
                    "helpdesk_group_required",
                    "helpdesk_group_id is required when routing_mode=helpdesk_bridge",
                )
            if self.type != "dm":
                raise PydanticCustomError(
                    "helpdesk_type_invalid",
                    "helpdesk_bridge conversations must use type=dm",
                )
        elif not self.participant_ids:
            raise PydanticCustomError(
                "participant_ids_required",
                "participant_ids must include at least one participant for standard conversations",
            )
        return self


class StartGroupConversationIn(BaseModel):
    participant_ids: List[str] = Field(min_length=2)
    title: Optional[str] = None
    description: Optional[str] = Field(default=None, max_length=500)
    icon: Optional[str] = Field(default=None, max_length=500)
    topic: Optional[str] = Field(default=None, max_length=200)
    retention_days: Optional[int] = Field(default=None, ge=1, le=3650)


class ConversationOut(BaseModel):
    conversation_id: str
    type: str
    title: Optional[str] = None
    description: Optional[str] = None
    icon: Optional[str] = None
    topic: Optional[str] = None
    retention_days: Optional[int] = None
    created_at: int
    created_by: str
    participant_count: int
    last_message_at: Optional[int] = None
    last_message_preview: Optional[str] = None
    status: str
    muted_until: int = 0
    last_read_at: int = 0
    unread_count: int = 0


class RoutingEventOut(BaseModel):
    conversation_id: str
    event_id: str
    event_type: str
    actor_user_id: str
    from_state: str
    to_state: str
    created_at: int
    assignment_version: int = 0
    routing_group_id: str = ""
    active_agent_user_id: str = ""
    metadata: Dict[str, Any] = Field(default_factory=dict)


class HelpdeskClaimOut(BaseModel):
    ok: bool
    conversation_id: str
    state: str
    assigned_agent_user_id: str
    assignment_version: int
    idempotent: bool = False


class LinkPreviewIn(BaseModel):
    url: str = Field(min_length=1, max_length=2000)
    title: Optional[str] = Field(default=None, max_length=200)
    description: Optional[str] = Field(default=None, max_length=1000)
    image_url: Optional[str] = Field(default=None, max_length=2000)
    site_name: Optional[str] = Field(default=None, max_length=200)


class MessageEncryptionEnvelope(BaseModel):
    version: Literal[1] = 1
    alg: Literal["AES-256-GCM"] = "AES-256-GCM"
    kdf: Literal["PBKDF2-SHA256"] = "PBKDF2-SHA256"
    iterations: int = Field(ge=100000, le=2000000)
    salt_b64: str = Field(min_length=4, max_length=256)
    iv_b64: str = Field(min_length=4, max_length=128)
    ciphertext_b64: str = Field(min_length=4, max_length=12000)

    @model_validator(mode="after")
    def _validate_binary_fields(self):
        try:
            salt = base64.b64decode(self.salt_b64, validate=True)
        except binascii.Error as exc:
            raise PydanticCustomError("enc_salt_invalid", "salt_b64 must be valid base64") from exc
        if len(salt) != 16:
            raise PydanticCustomError("enc_salt_length", "salt_b64 must decode to exactly 16 bytes")

        try:
            iv = base64.b64decode(self.iv_b64, validate=True)
        except binascii.Error as exc:
            raise PydanticCustomError("enc_iv_invalid", "iv_b64 must be valid base64") from exc
        if len(iv) != 12:
            raise PydanticCustomError("enc_iv_length", "iv_b64 must decode to exactly 12 bytes")

        try:
            ciphertext = base64.b64decode(self.ciphertext_b64, validate=True)
        except binascii.Error as exc:
            raise PydanticCustomError("enc_ciphertext_invalid", "ciphertext_b64 must be valid base64") from exc
        if len(ciphertext) <= 16:
            raise PydanticCustomError(
                "enc_ciphertext_length",
                "ciphertext_b64 must include ciphertext bytes plus authentication tag",
            )
        if len(ciphertext) > ENCRYPTED_CIPHERTEXT_MAX_BYTES:
            raise PydanticCustomError(
                "enc_ciphertext_too_large",
                f"ciphertext payload exceeds {ENCRYPTED_CIPHERTEXT_MAX_BYTES} byte limit",
            )
        return self


class SendTextMessageIn(BaseModel):
    text: Optional[str] = Field(default=None, min_length=1, max_length=MESSAGE_TEXT_MAX_CHARS)
    body: Optional[str] = None
    reply_to_message_id: Optional[str] = None
    preview: Optional[LinkPreviewIn] = None
    encryption: Optional[MessageEncryptionEnvelope] = None

    @model_validator(mode="before")
    @classmethod
    def _normalize_legacy_fields(cls, data: Any):
        if not isinstance(data, dict):
            return data
        payload = dict(data)
        if not payload.get("text") and payload.get("body"):
            payload["text"] = payload["body"]
            logger.warning("messaging.send_text legacy payload used: body")
        return payload

    @model_validator(mode="after")
    def _validate_shape(self):
        if self.encryption and self.text:
            raise PydanticCustomError(
                "message_text_encryption_conflict",
                "Provide either plaintext text or encryption envelope, not both",
            )
        if self.encryption and self.preview:
            raise PydanticCustomError(
                "message_encryption_preview_conflict",
                "Link previews are not supported for encrypted messages",
            )
        if not self.encryption and not self.text:
            raise PydanticCustomError(
                "message_text_required",
                "text is required when encryption envelope is not provided",
            )
        return self


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
    last_read_at: Optional[int] = None
    last_read_message_id: Optional[str] = None

    @model_validator(mode="after")
    def _validate_shape(self):
        if self.last_read_at is None and not self.last_read_message_id:
            raise ValueError("Either last_read_at or last_read_message_id is required")
        if self.last_read_message_id:
            logger.warning("messaging.mark_read legacy payload used: last_read_message_id")
        return self


class MuteIn(BaseModel):
    muted_until: Optional[int] = None
    muted: Optional[bool] = None

    @model_validator(mode="after")
    def _validate_shape(self):
        if self.muted_until is None and self.muted is None:
            raise ValueError("Either muted_until or muted is required")
        if self.muted is not None:
            logger.warning("messaging.mute legacy payload used: muted")
        return self


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


class MessagingConfigOut(BaseModel):
    messaging_encrypted_messages_enabled: bool


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


class UpdateConversationIn(BaseModel):
    title: Optional[str] = Field(default=None, max_length=200)
    description: Optional[str] = Field(default=None, max_length=500)
    icon: Optional[str] = Field(default=None, max_length=500)
    topic: Optional[str] = Field(default=None, max_length=200)
    retention_days: Optional[int] = Field(default=None, ge=1, le=3650)


class AddParticipantsIn(BaseModel):
    participant_ids: List[str] = Field(default_factory=list)


class UpdateParticipantRoleIn(BaseModel):
    role: Literal["admin", "member"]


class CreateFileMessageIn(BaseModel):
    path: str
    kind: Literal["file", "audio", "video"] = "file"
    duration_seconds: Optional[int] = Field(default=None, ge=1)
    reply_to_message_id: Optional[str] = None
    preview: Optional[LinkPreviewIn] = None


class EditMessageIn(BaseModel):
    text: str = Field(min_length=1, max_length=4000)
    body: Optional[str] = None

    @model_validator(mode="before")
    @classmethod
    def _normalize_legacy_fields(cls, data: Any):
        if not isinstance(data, dict):
            return data
        payload = dict(data)
        if not payload.get("text") and payload.get("body"):
            payload["text"] = payload["body"]
            logger.warning("messaging.edit legacy payload used: body")
        return payload


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
    kind: Literal["text", "image", "file", "audio", "video"]
    text: Optional[str] = None
    image: Optional[Dict[str, Any]] = None
    file: Optional[Dict[str, Any]] = None
    preview: Optional[Dict[str, Any]] = None

    reply_to_message_id: Optional[str] = None
    forwarded_from: Optional[Dict[str, Any]] = None
    forward_note: Optional[str] = None
    edited_at: Optional[int] = None
    edited_by: Optional[str] = None
    revoked_at: Optional[int] = None
    revoked_by: Optional[str] = None
    delivered_to_count: Optional[int] = None
    delivered_to_user_ids: Optional[List[str]] = None
    read_by_count: Optional[int] = None
    read_by_user_ids: Optional[List[str]] = None
    reactions_counts: Optional[Dict[str, int]] = None
    my_reactions: Optional[List[str]] = None
    is_encrypted: bool = False
    encryption: Optional[MessageEncryptionEnvelope] = None


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
    tokens = re.findall(r"[a-z0-9@._-]+", (text or "").lower())
    if not tokens:
        return []
    parts = [p for p in tokens if p]
    out: list[str] = []
    for p in parts:
        for i in range(1, min(len(p), max_len) + 1):
            out.append(p[:i])
    return list(dict.fromkeys(out))


def _tokenize_message(text: str, max_len: int = 32) -> list[str]:
    tokens = re.findall(r"[a-z0-9@._-]+", (text or "").lower())
    return [t[:max_len] for t in tokens if t]


def _stem_tokens(tokens: Sequence[str]) -> list[str]:
    stemmer = snowballstemmer.stemmer("english")
    return [stem for stem in stemmer.stemWords(list(tokens)) if stem]


def _token_ngrams(token: str, *, min_len: int = 3, max_len: int = 5) -> list[str]:
    if len(token) < min_len:
        return []
    ngrams: list[str] = []
    for size in range(min_len, min(max_len, len(token)) + 1):
        for idx in range(0, len(token) - size + 1):
            ngrams.append(token[idx : idx + size])
    return ngrams


def build_message_search_tokens(text: str, *, max_len: int = 32, max_prefix_len: int = 8) -> list[str]:
    tokens = _stem_tokens(_tokenize_message(text, max_len=max_len))
    out: list[str] = []
    for token in tokens:
        out.append(token)
        for i in range(1, min(len(token), max_prefix_len) + 1):
            out.append(token[:i])
        out.extend(_token_ngrams(token))
    return list(dict.fromkeys(out))


def build_message_query_tokens(query: str, *, max_len: int = 32) -> list[str]:
    tokens = _stem_tokens(_tokenize_message(query, max_len=max_len))
    out: list[str] = []
    for token in tokens:
        out.append(token)
        out.extend(build_prefix_tokens(token))
        out.extend(_token_ngrams(token))
    return list(dict.fromkeys(out))


def _message_search_key(conversation_id: str, message_id: str) -> str:
    return f"{conversation_id}#{message_id}"


def _message_search_enabled() -> bool:
    return bool(DDB_MESSAGE_SEARCH) and _aws_credentials_available()


def _message_receipts_enabled() -> bool:
    return bool(DDB_MESSAGE_RECEIPTS) and _aws_credentials_available()


def _encrypted_messages_enabled() -> bool:
    enabled = os.getenv(
        "MESSAGING_ENCRYPTED_MESSAGES_ENABLED",
        "true" if S.messaging_encrypted_messages_enabled else "false",
    ) not in ("0", "false", "False")
    kill_switch = os.getenv(
        "MESSAGING_ENCRYPTED_MESSAGES_KILL_SWITCH",
        "true" if S.messaging_encrypted_messages_kill_switch else "false",
    ) not in ("0", "false", "False")
    return enabled and not kill_switch


def _aws_credentials_available() -> bool:
    session = boto3.session.Session()
    return session.get_credentials() is not None


def _opensearch_enabled() -> bool:
    return bool(OPENSEARCH_ENDPOINT)


def _opensearch_request(method: str, path: str, *, body: Optional[dict] = None) -> Optional[dict]:
    if not _opensearch_enabled():
        return None
    url = f"{OPENSEARCH_ENDPOINT.rstrip('/')}{path}"
    data = json.dumps(body) if body is not None else None
    session = boto3.session.Session()
    credentials = session.get_credentials()
    if not credentials:
        return None
    frozen = credentials.get_frozen_credentials()
    headers = {"Content-Type": "application/json"}
    request = AWSRequest(method=method, url=url, data=data, headers=headers)
    SigV4Auth(frozen, "es", OPENSEARCH_REGION).add_auth(request)
    prepared = request.prepare()
    try:
        resp = requests.request(
            method,
            url,
            data=data,
            headers=dict(prepared.headers),
            timeout=2,
        )
    except requests.RequestException:
        return None
    if resp.status_code >= 400:
        return None
    if not resp.text:
        return None
    try:
        return resp.json()
    except ValueError:
        return None


def _opensearch_index_message(
    conversation_id: str,
    message_id: str,
    sender_id: str,
    created_at: int,
    text: str,
    kind: str,
) -> None:
    if not _opensearch_enabled():
        return
    doc_id = _message_search_key(conversation_id, message_id)
    body = {
        "conversation_id": conversation_id,
        "message_id": message_id,
        "sender_id": sender_id,
        "created_at": int(created_at),
        "text": text,
        "search_text": text,
        "kind": kind,
    }
    _opensearch_request("PUT", f"/{OPENSEARCH_INDEX}/_doc/{doc_id}", body=body)


def _opensearch_search_messages(
    query: str,
    *,
    limit: int,
    conversation_id: Optional[str] = None,
    allowed_conversation_ids: Optional[set[str]] = None,
    sender_id: Optional[str] = None,
    after_ts: Optional[int] = None,
    kinds: Optional[Sequence[str]] = None,
) -> Optional[list[str]]:
    if not _opensearch_enabled():
        return None
    filters: list[dict[str, Any]] = []
    if conversation_id:
        filters.append({"term": {"conversation_id": conversation_id}})
    if allowed_conversation_ids is not None:
        filters.append({"terms": {"conversation_id": list(allowed_conversation_ids)}})
    if sender_id:
        filters.append({"term": {"sender_id": sender_id}})
    if after_ts is not None:
        filters.append({"range": {"created_at": {"gte": int(after_ts)}}})
    if kinds:
        filters.append({"terms": {"kind": list(kinds)}})
    body: Dict[str, Any] = {
        "size": limit,
        "query": {
            "bool": {
                "must": {
                    "simple_query_string": {
                        "query": query,
                        "fields": ["text^2", "search_text^3"],
                    }
                },
                "filter": filters,
            }
        },
        "sort": [{"_score": "desc"}, {"created_at": "desc"}],
    }
    resp = _opensearch_request("POST", f"/{OPENSEARCH_INDEX}/_search", body=body)
    if not resp:
        return None
    hits = resp.get("hits", {}).get("hits", [])
    return [hit.get("_id") for hit in hits if hit.get("_id")]


def index_message_search(
    conversation_id: str,
    message_id: str,
    sender_id: str,
    created_at: int,
    text: str,
    *,
    kind: str = "text",
) -> None:
    if _message_search_enabled():
        tokens = build_message_search_tokens(text)
        if not tokens:
            return
        try:
            with tbl_msg_search.batch_writer() as bw:
                for token in tokens:
                    bw.put_item(
                        Item={
                            "token": token,
                            "message_key": _message_search_key(conversation_id, message_id),
                            "conversation_id": conversation_id,
                            "message_id": message_id,
                            "sender_id": sender_id,
                            "created_at": int(created_at),
                        }
                    )
        except ClientError:
            return
    _opensearch_index_message(conversation_id, message_id, sender_id, created_at, text, kind)


def remove_message_search(
    conversation_id: str,
    message_id: str,
    text: str,
) -> None:
    if not _message_search_enabled():
        return
    tokens = build_message_search_tokens(text)
    if not tokens:
        return
    try:
        with tbl_msg_search.batch_writer() as bw:
            for token in tokens:
                bw.delete_item(Key={"token": token, "message_key": _message_search_key(conversation_id, message_id)})
    except ClientError:
        return


def _filter_message_visible(message_item: dict, user_id: str) -> bool:
    deleted_for = set(message_item.get("deleted_for", []))
    if message_item.get("revoked_at"):
        return False
    return user_id not in deleted_for


def _message_search_text(message_item: dict) -> str:
    if bool(message_item.get("is_encrypted")):
        return ""
    return str(message_item.get("search_text") or message_item.get("text") or "")


def _is_searchable_kind(kind: Optional[str]) -> bool:
    return kind in {"text", "file", "audio", "video"}




def _is_searchable_message(message_item: dict) -> bool:
    return _is_searchable_kind(message_item.get("kind")) and not bool(message_item.get("is_encrypted"))


def _filter_search_kinds(kinds: Optional[Sequence[str]]) -> Optional[set[str]]:
    if not kinds:
        return None
    normalized = {str(k).strip().lower() for k in kinds if str(k).strip()}
    allowed = {"text", "image", "file", "audio", "video"}
    filtered = {k for k in normalized if k in allowed}
    return filtered or None


def _message_relevance_score(message_item: dict, query: str) -> float:
    query = (query or "").lower().strip()
    if not query:
        return 0.0
    text = _message_search_text(message_item).lower()
    if not text:
        return 0.0
    tokens = _stem_tokens(_tokenize_message(query))
    score = 0.0
    for token in tokens:
        if not token:
            continue
        if token in text:
            score += 3.0
        else:
            ngrams = _token_ngrams(token, min_len=3, max_len=4)
            if any(ngram in text for ngram in ngrams):
                score += 1.0
    created_at = int(message_item.get("created_at", 0) or 0)
    if created_at:
        age_days = max(0.0, (now_ts() - created_at) / 86400)
        score += max(0.0, 1.5 - (age_days / 14.0))
    return score


def _rank_messages_by_relevance(items: list[dict], query: str) -> list[dict]:
    scored = [(item, _message_relevance_score(item, query)) for item in items]
    scored.sort(key=lambda x: (x[1], int(x[0].get("created_at", 0) or 0)), reverse=True)
    return [item for item, _ in scored]


def _message_out_from_item(message_item: dict, viewer_user_id: str) -> MessageOut:
    counts, mine = _reaction_summaries(message_item, viewer_user_id)
    return MessageOut(
        conversation_id=message_item["conversation_id"],
        message_id=message_item["message_id"],
        sender_id=message_item["sender_id"],
        created_at=int(message_item["created_at"]),
        kind=message_item["kind"],
        text=message_item.get("text"),
        image=message_item.get("image"),
        file=message_item.get("file"),
        preview=message_item.get("preview"),
        reply_to_message_id=message_item.get("reply_to_message_id"),
        forwarded_from=message_item.get("forwarded_from"),
        forward_note=message_item.get("forward_note"),
        edited_at=int(message_item.get("edited_at", 0)) or None,
        edited_by=message_item.get("edited_by"),
        revoked_at=int(message_item.get("revoked_at", 0)) or None,
        revoked_by=message_item.get("revoked_by"),
        reactions_counts=counts if counts else None,
        my_reactions=mine if mine else None,
        is_encrypted=bool(message_item.get("is_encrypted")),
        encryption=message_item.get("encryption"),
    )


def _serialize_message_event_payload(message_item: dict, viewer_user_id: str) -> dict:
    """Serialize a message item to a JSON-safe event payload."""
    return _message_out_from_item(message_item, viewer_user_id).model_dump(exclude_none=True)


def _fetch_message_items(message_keys: Iterable[str]) -> list[dict]:
    items: list[dict] = []
    for key in message_keys:
        if "#" not in key:
            continue
        conversation_id, message_id = key.split("#", 1)
        resp = tbl_msgs.get_item(Key={"conversation_id": conversation_id, "message_id": message_id})
        item = resp.get("Item")
        if item:
            items.append(item)
    return items


def _search_messages_index(
    query_tokens: Sequence[str],
    *,
    conversation_id: Optional[str] = None,
    allowed_conversation_ids: Optional[set[str]] = None,
    sender_id: Optional[str] = None,
    after_ts: Optional[int] = None,
    limit: int = 50,
) -> Optional[list[dict]]:
    if not query_tokens:
        return []
    if not _message_search_enabled():
        return None
    message_map: Dict[str, dict] = {}
    try:
        for idx, token in enumerate(query_tokens):
            kwargs: Dict[str, Any] = {"KeyConditionExpression": Key("token").eq(token), "Limit": 200}
            filters = []
            if conversation_id:
                filters.append(Attr("conversation_id").eq(conversation_id))
            if sender_id:
                filters.append(Attr("sender_id").eq(sender_id))
            if after_ts is not None:
                filters.append(Attr("created_at").gte(int(after_ts)))
            if filters:
                expr = filters[0]
                for extra in filters[1:]:
                    expr = expr & extra
                kwargs["FilterExpression"] = expr
            resp = tbl_msg_search.query(**kwargs)
            items = resp.get("Items", [])
            if allowed_conversation_ids is not None:
                items = [item for item in items if item.get("conversation_id") in allowed_conversation_ids]
            if idx == 0:
                message_map = {item["message_key"]: item for item in items}
            else:
                allowed = {item["message_key"] for item in items}
                message_map = {k: v for k, v in message_map.items() if k in allowed}
            if not message_map:
                return []
        results = sorted(message_map.values(), key=lambda x: int(x.get("created_at", 0)), reverse=True)
        return results[:limit]
    except ClientError:
        return None


def _fallback_search_messages(
    conversation_id: str,
    query: str,
    *,
    limit: int,
    user_id: str,
    sender_id: Optional[str] = None,
    after_ts: Optional[int] = None,
    kinds: Optional[set[str]] = None,
) -> list[dict]:
    query_lower = query.lower()
    matches: list[dict] = []
    last_key = None
    while len(matches) < limit:
        kwargs: Dict[str, Any] = {
            "KeyConditionExpression": Key("conversation_id").eq(conversation_id),
            "ScanIndexForward": False,
            "Limit": 200,
        }
        if last_key:
            kwargs["ExclusiveStartKey"] = last_key
        resp = tbl_msgs.query(**kwargs)
        items = resp.get("Items", [])
        for item in items:
            if not _filter_message_visible(item, user_id):
                continue
            if sender_id and item.get("sender_id") != sender_id:
                continue
            if after_ts is not None and int(item.get("created_at", 0)) < int(after_ts):
                continue
            if kinds and item.get("kind") not in kinds:
                continue
            if not _is_searchable_message(item):
                continue
            text = _message_search_text(item).lower()
            if text and query_lower in text:
                matches.append(item)
                if len(matches) >= limit:
                    break
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break
    return matches


def get_participant_any(user_id: str, conversation_id: str) -> Optional[dict]:
    resp = tbl_parts.get_item(Key={"user_id": user_id, "conversation_id": conversation_id})
    return resp.get("Item")


def require_participant_active(user_id: str, conversation_id: str) -> dict:
    item = get_participant_any(user_id, conversation_id)
    if not item or item.get("status") != "active":
        raise HTTPException(status_code=403, detail="Not an active participant")
    return item


def require_participant_role(user_id: str, conversation_id: str, allowed: set[str]) -> dict:
    item = require_participant_active(user_id, conversation_id)
    role = item.get("role")
    if role not in allowed:
        raise HTTPException(status_code=403, detail="Insufficient role for this action")
    return item


def _get_conversation_or_404(conversation_id: str) -> dict:
    convo = tbl_convos.get_item(Key={"conversation_id": conversation_id}).get("Item")
    if not convo:
        raise HTTPException(404, "Conversation not found")
    return convo


def _routing_event_id(ts: int) -> str:
    return f"{int(ts):010d}#{new_id()}"


def _apply_helpdesk_routing_transition(
    *,
    conversation_id: str,
    cmd: RoutingTransitionInput,
    actor_user_id: str,
    metadata: Optional[Dict[str, Any]] = None,
) -> dict:
    convo = _get_conversation_or_404(conversation_id)
    result = transition_helpdesk_routing(convo, cmd)

    if result.changed:
        current_version = int(convo.get("assignment_version") or 0)
        update_expr_parts = []
        expr_values: Dict[str, Any] = {":expected_version": current_version, ":zero": 0}
        for idx, (key, value) in enumerate(result.patch.items()):
            token = f":v{idx}"
            update_expr_parts.append(f"{key} = {token}")
            expr_values[token] = value
        tbl_convos.update_item(
            Key={"conversation_id": conversation_id},
            UpdateExpression="SET " + ", ".join(update_expr_parts),
            ConditionExpression=(
                "(attribute_not_exists(assignment_version) AND :expected_version = :zero) "
                "OR assignment_version = :expected_version"
            ),
            ExpressionAttributeValues=expr_values,
        )
        convo = {**convo, **result.patch}

    event_created_at = int(cmd.now_ts)
    event_item = build_routing_event_item(
        conversation=convo,
        transition=result,
        actor_user_id=actor_user_id,
        created_at=event_created_at,
        event_id=_routing_event_id(event_created_at),
        metadata=metadata or {},
    )
    tbl_routing_events.put_item(Item=event_item, ConditionExpression="attribute_not_exists(event_id)")
    return {"transition": result, "event": event_item, "conversation": convo}


def _message_retention_ttl(conversation: dict, created_at: int) -> Optional[int]:
    retention_days = conversation.get("retention_days")
    if retention_days is None:
        return None
    try:
        days = int(retention_days)
    except (TypeError, ValueError):
        return None
    if days <= 0:
        return None
    return int(created_at) + days * 86400


def _serialize_preview(preview: Optional[LinkPreviewIn]) -> Optional[dict]:
    if not preview:
        return None
    return preview.dict(exclude_none=True)


class _LinkPreviewParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.title: Optional[str] = None
        self.meta: Dict[str, str] = {}
        self._in_title = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, Optional[str]]]) -> None:
        attrs_map = {k.lower(): v for k, v in attrs}
        if tag.lower() == "title":
            self._in_title = True
            return
        if tag.lower() == "meta":
            key = attrs_map.get("property") or attrs_map.get("name")
            content = attrs_map.get("content")
            if key and content:
                self.meta[key.lower()] = content.strip()

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        if self._in_title and not self.title:
            text = data.strip()
            if text:
                self.title = text


def _extract_first_url(text: str) -> Optional[str]:
    if not text:
        return None
    match = re.search(r"(https?://[^\s<>()]+)", text)
    if not match:
        return None
    url = match.group(1).rstrip(".,!?)]}\"'")
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        return None
    return url


def _fetch_link_preview(url: str) -> Optional[dict]:
    try:
        resp = requests.get(
            url,
            timeout=3,
            headers={"User-Agent": "MessagingPreviewBot/1.0"},
            stream=True,
        )
    except requests.RequestException:
        return None
    try:
        if resp.status_code >= 400:
            return None
        content_type = resp.headers.get("Content-Type", "")
        if "text/html" not in content_type:
            return None
        content = b""
        try:
            for chunk in resp.iter_content(chunk_size=65536):
                if not chunk:
                    break
                content += chunk
                if len(content) > 512000:
                    break
        except requests.RequestException:
            return None
    finally:
        resp.close()
    parser = _LinkPreviewParser()
    try:
        parser.feed(content.decode(errors="ignore"))
    except Exception:
        return None
    title = parser.meta.get("og:title") or parser.title
    description = parser.meta.get("og:description") or parser.meta.get("description")
    image_url = parser.meta.get("og:image")
    site_name = parser.meta.get("og:site_name")
    if image_url:
        image_url = urljoin(url, image_url)
    preview = {
        "url": url,
        "title": title,
        "description": description,
        "image_url": image_url,
        "site_name": site_name,
    }
    if not any(preview.values()):
        return None
    return {k: v for k, v in preview.items() if v}


def _message_receipt_summary(message_item: dict, participants: Sequence[dict]) -> tuple[List[str], List[str]]:
    if _message_receipts_enabled():
        convo_id = message_item.get("conversation_id")
        message_id = message_item.get("message_id")
        if convo_id and message_id:
            try:
                resp = tbl_receipts.query(
                    KeyConditionExpression=Key("conversation_id").eq(convo_id)
                    & Key("message_user").begins_with(f"{message_id}#"),
                    Limit=500,
                    ScanIndexForward=True,
                )
                items = resp.get("Items", [])
            except Exception:
                items = []
            delivered_users = [it["user_id"] for it in items if int(it.get("delivered_at", 0) or 0) > 0]
            read_by = [it["user_id"] for it in items if int(it.get("read_at", 0) or 0) > 0]
            delivered_users.sort()
            read_by.sort()
            return delivered_users, read_by
    active = [p for p in participants if p.get("status") == "active"]
    sender_id = message_item.get("sender_id")
    delivered = [p for p in active if p.get("user_id") != sender_id]
    delivered_users = [p["user_id"] for p in delivered if p.get("user_id")]
    created_at = int(message_item.get("created_at", 0) or 0)
    read_by = [
        p["user_id"]
        for p in active
        if int(p.get("last_read_at", 0) or 0) >= created_at
    ]
    delivered_users.sort()
    read_by.sort()
    return delivered_users, read_by


def _apply_message_receipts(message_out: MessageOut, message_item: dict, participants: Sequence[dict]) -> MessageOut:
    delivered_users, read_by = _message_receipt_summary(message_item, participants)
    message_out.delivered_to_user_ids = delivered_users
    message_out.delivered_to_count = len(delivered_users)
    message_out.read_by_user_ids = read_by
    message_out.read_by_count = len(read_by)
    return message_out


def _bump_unread_counts(conversation_id: str, sender_id: str, participants: Sequence[dict]) -> None:
    for p in participants:
        pid = p.get("user_id")
        if not pid or pid == sender_id:
            continue
        if p.get("status") != "active":
            continue
        tbl_parts.update_item(
            Key={"user_id": pid, "conversation_id": conversation_id},
            UpdateExpression="ADD unread_count :one",
            ExpressionAttributeValues={":one": 1},
        )


def _record_delivery_receipts(conversation_id: str, message_id: str, sender_id: str, participants: Sequence[dict]) -> None:
    if not _message_receipts_enabled():
        return
    ts = now_ts()
    with tbl_receipts.batch_writer() as bw:
        for p in participants:
            pid = p.get("user_id")
            if not pid or pid == sender_id:
                continue
            if p.get("status") != "active":
                continue
            bw.put_item(
                Item={
                    "conversation_id": conversation_id,
                    "message_user": f"{message_id}#{pid}",
                    "message_id": message_id,
                    "user_id": pid,
                    "delivered_at": ts,
                    "read_at": 0,
                }
            )


def _ensure_can_revoke_message(user_id: str, conversation_id: str, message_item: dict) -> None:
    if message_item.get("revoked_at"):
        raise HTTPException(400, "Message already revoked")
    created_at = int(message_item.get("created_at", 0) or 0)
    if now_ts() - created_at > MESSAGE_REVOKE_WINDOW_SEC:
        raise HTTPException(400, "Revocation window has expired")
    if message_item.get("sender_id") == user_id:
        return
    require_participant_role(user_id, conversation_id, {"admin"})


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


def _helpdesk_alert_event_id(conversation_id: str, target_user_id: str) -> str:
    return f"helpdesk_alert#{conversation_id}#{target_user_id}"


def _resolve_helpdesk_group_members(group_id: str) -> list[str]:
    gid = (group_id or "").strip()
    if not gid:
        return []

    members: list[str] = []
    if HELPDESK_GROUP_MEMBERS_JSON:
        try:
            raw = json.loads(HELPDESK_GROUP_MEMBERS_JSON)
            if isinstance(raw, dict):
                values = raw.get(gid, [])
                if isinstance(values, list):
                    members.extend(str(v).strip() for v in values if str(v).strip())
        except Exception:
            logger.exception("failed to parse HELPDESK_GROUP_MEMBERS_JSON")

    if members:
        return list(dict.fromkeys(members))

    # Fallback: allow user records to self-declare helpdesk groups.
    items = []
    try:
        resp = tbl_users.scan(FilterExpression=Attr("helpdesk_groups").contains(gid), ProjectionExpression="user_id")
        items.extend(resp.get("Items", []))
        while resp.get("LastEvaluatedKey"):
            resp = tbl_users.scan(
                FilterExpression=Attr("helpdesk_groups").contains(gid),
                ProjectionExpression="user_id",
                ExclusiveStartKey=resp["LastEvaluatedKey"],
            )
            items.extend(resp.get("Items", []))
    except Exception:
        return []

    return list(dict.fromkeys(str(it.get("user_id") or "").strip() for it in items if str(it.get("user_id") or "").strip()))


def _is_helpdesk_group_member(group_id: str, user_id: str) -> bool:
    uid = (user_id or "").strip()
    if not uid:
        return False
    return uid in set(_resolve_helpdesk_group_members(group_id))


def _is_user_online_available(user_id: str, ts: int) -> bool:
    try:
        item = tbl_presence.get_item(Key={"user_id": user_id}).get("Item") or {}
    except Exception:
        return False
    last_seen = int(item.get("last_seen_at", 0) or 0)
    status = str(item.get("status") or "online").lower()
    return bool(last_seen and (ts - last_seen) <= ONLINE_WINDOW_SEC and status in {"online", "available"})


def _resolve_online_helpdesk_members(group_id: str, ts: int) -> list[str]:
    members = _resolve_helpdesk_group_members(group_id)
    if not members:
        return []
    keys = [{"user_id": uid} for uid in members]
    try:
        resp = ddb.meta.client.batch_get_item(RequestItems={DDB_PRESENCE: {"Keys": keys}})
    except Exception:
        return []
    presence_items = {it.get("user_id"): it for it in resp.get("Responses", {}).get(DDB_PRESENCE, [])}
    out: list[str] = []
    for uid in members:
        it = presence_items.get(uid) or {}
        last_seen = int(it.get("last_seen_at", 0) or 0)
        status = str(it.get("status") or "online").lower()
        if last_seen and (ts - last_seen) <= ONLINE_WINDOW_SEC and status in {"online", "available"}:
            out.append(uid)
    return out


def fanout_helpdesk_alert(conversation_id: str, group_id: str, created_by: str) -> int:
    ts = now_ts()
    online_members = _resolve_online_helpdesk_members(group_id, ts)
    if not online_members:
        return 0

    ttl = ts + 7 * 24 * 3600
    delivered = 0
    for uid in online_members:
        event_item = {
            "user_id": uid,
            "event_id": _helpdesk_alert_event_id(conversation_id, uid),
            "type": "helpdesk.conversation.alerted",
            "created_at": ts,
            "conversation_id": conversation_id,
            "payload": {
                "conversation_id": conversation_id,
                "group_id": group_id,
                "created_by": created_by,
                "routing_state": "awaiting_agent",
            },
            "ttl": ttl,
        }
        try:
            tbl_events.put_item(Item=event_item, ConditionExpression="attribute_not_exists(event_id)")
            delivered += 1
            record_helpdesk_alert_sent("delivered")
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
                record_helpdesk_alert_sent("duplicate")
                continue
            record_helpdesk_alert_sent("error")
            logger.exception("failed to write helpdesk alert event", extra={"conversation_id": conversation_id, "target_user_id": uid})
        except Exception:
            record_helpdesk_alert_sent("error")
            logger.exception("failed to write helpdesk alert event", extra={"conversation_id": conversation_id, "target_user_id": uid})
    return delivered


def _emit_no_agents_online_notice(*, conversation_id: str, user_id: str, now: int) -> bool:
    convo = _get_conversation_or_404(conversation_id)
    last_notice_at = int(convo.get("no_agents_notice_sent_at", 0) or 0)
    if last_notice_at and (now - last_notice_at) < NO_AGENTS_NOTICE_THROTTLE_SEC:
        return False

    try:
        _apply_helpdesk_routing_transition(
            conversation_id=conversation_id,
            cmd=RoutingTransitionInput(action="pause_no_agents", now_ts=now),
            actor_user_id=user_id,
            metadata={"reason": "no_agents_online_creation"},
        )
    except RoutingTransitionError as exc:
        if exc.code != "routing_pause_invalid_state":
            raise

    message_id = "sys_no_agents_online"
    try:
        tbl_msgs.put_item(
            Item={
                "conversation_id": conversation_id,
                "message_id": message_id,
                "sender_id": "system",
                "created_at": now,
                "kind": "text",
                "text": NO_AGENTS_ONLINE_NOTICE_TEXT,
            },
            ConditionExpression="attribute_not_exists(message_id)",
        )
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ConditionalCheckFailedException":
            raise

    tbl_convos.update_item(
        Key={"conversation_id": conversation_id},
        UpdateExpression=(
            "SET last_message_at=:ts, last_message_preview=:preview, "
            "no_agents_notice_sent_at=:ts"
        ),
        ExpressionAttributeValues={
            ":ts": now,
            ":preview": NO_AGENTS_ONLINE_NOTICE_TEXT,
        },
    )
    return True




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
    if item is None:
        raise HTTPException(404, "Message not found")
    if not isinstance(item, dict):
        return {}
    return item


def _raise_encrypted_edit_unsupported() -> None:
    raise HTTPException(
        status_code=409,
        detail={
            "code": ENCRYPTED_EDIT_ERROR_CODE,
            "message": "Encrypted messages cannot be edited. Delete and resend a new encrypted message.",
        },
    )


def _validate_reply_target(conversation_id: str, reply_to_message_id: Optional[str]) -> None:
    if not reply_to_message_id:
        return
    msg = _get_message_or_404(conversation_id, reply_to_message_id)
    if isinstance(msg, dict) and msg.get("revoked_at"):
        raise HTTPException(400, "Cannot reply to a revoked message")


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
    q: Annotated[str, Query(..., min_length=1, max_length=64)],
    limit: Annotated[int, Query(ge=1, le=50)] = 10,
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

    routing_mode = inp.routing_mode
    routing_state = "awaiting_agent" if routing_mode == "helpdesk_bridge" else "none"
    group_id = inp.helpdesk_group_id if routing_mode == "helpdesk_bridge" else ""

    if routing_mode == "helpdesk_bridge":
        participant_ids = [user_id, _helpdesk_virtual_participant_id(group_id)]
    else:
        participant_ids = list(dict.fromkeys([user_id] + inp.participant_ids))

    if inp.type == "dm" and len(participant_ids) != 2:
        raise HTTPException(400, "dm conversation must have exactly 2 unique participants")
    if inp.type == "group" and len(participant_ids) < 3:
        raise HTTPException(400, "group conversation must have at least 3 unique participants")
    for pid in participant_ids:
        if pid == user_id or pid.startswith("helpdesk_group:"):
            continue
        require_subscription_access(user_id, pid)
    convo_item = {
        "conversation_id": cid,
        "created_at": created_at,
        "created_by": user_id,
        "type": inp.type,
        "title": inp.title,
        "description": inp.description,
        "icon": inp.icon,
        "topic": inp.topic,
        "retention_days": inp.retention_days,
        "participant_count": len(participant_ids),
        "last_message_at": 0,
        "last_message_preview": "",
        "routing_mode": routing_mode,
        "routing_group_id": group_id,
        "routing_state": routing_state,
        "active_agent_user_id": "",
        "active_agent_claimed_at": 0,
        "last_failover_at": 0,
        "assignment_version": 0,
        "no_agents_notice_sent_at": 0,
        "routing_state_group_pk": f"{routing_state}#{group_id}",
        "routing_state_group_sk": cid,
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
                "unread_count": 0,
                "joined_at": created_at if status == "active" else 0,
                "left_at": 0,
                "GSI1PK": cid,
                "GSI1SK": pid,
            }
        )

    if routing_mode == "helpdesk_bridge":
        delivered = fanout_helpdesk_alert(conversation_id=cid, group_id=group_id, created_by=user_id)
        if delivered == 0:
            _emit_no_agents_online_notice(conversation_id=cid, user_id=user_id, now=created_at)

    convo = ConversationOut(
        conversation_id=cid,
        type=inp.type,
        title=inp.title,
        description=inp.description,
        icon=inp.icon,
        topic=inp.topic,
        retention_days=inp.retention_days,
        created_at=created_at,
        created_by=user_id,
        participant_count=len(participant_ids),
        last_message_at=None,
        last_message_preview=None,
        status="active",
        muted_until=0,
        last_read_at=0,
        unread_count=0,
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
            description=inp.description,
            icon=inp.icon,
            topic=inp.topic,
            retention_days=inp.retention_days,
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
                description=convo.get("description"),
                icon=convo.get("icon"),
                topic=convo.get("topic"),
                retention_days=convo.get("retention_days"),
                created_at=int(convo.get("created_at", 0)),
                created_by=convo.get("created_by", ""),
                participant_count=int(convo.get("participant_count", 0)),
                last_message_at=int(convo.get("last_message_at", 0)) or None,
                last_message_preview=convo.get("last_message_preview") or None,
                status=p.get("status", "pending"),
                muted_until=int(p.get("muted_until", 0) or 0),
                last_read_at=int(p.get("last_read_at", 0) or 0),
                unread_count=int(p.get("unread_count", 0) or 0),
            )
        )

    out.sort(key=lambda x: (x.last_message_at or 0, x.created_at), reverse=True)
    return out


@router.post("/conversations/{conversation_id}/mute")
def mute_conversation(conversation_id: str, inp: MuteIn, req: Request = None, user_id: str = Depends(get_messaging_user_id)):
    part = get_participant_any(user_id, conversation_id)
    if not part:
        raise HTTPException(404, "Conversation not found for user")

    mute_until = inp.muted_until
    if mute_until is None:
        if inp.muted is True:
            default_window = int(os.getenv("LEGACY_MUTE_DEFAULT_WINDOW_SEC", "3600"))
            mute_until = now_ts() + default_window
            logger.warning(
                "messaging.mute converting legacy muted=true to muted_until",
                extra={"conversation_id": conversation_id, "user_id": user_id, "muted_until": mute_until},
            )
        else:
            mute_until = 0
            logger.warning(
                "messaging.mute converting legacy muted=false to muted_until=0",
                extra={"conversation_id": conversation_id, "user_id": user_id},
            )

    tbl_parts.update_item(
        Key={"user_id": user_id, "conversation_id": conversation_id},
        UpdateExpression="SET muted_until = :mu",
        ExpressionAttributeValues={":mu": int(mute_until)},
    )
    audit_event(
        "messaging_conversation_muted",
        user_id,
        req,
        outcome="success",
        conversation_id=conversation_id,
        muted_until=int(mute_until),
    )
    return {"ok": True, "muted_until": int(mute_until)}


@router.patch("/conversations/{conversation_id}", response_model=ConversationOut)
def update_conversation(
    conversation_id: str,
    inp: UpdateConversationIn,
    req: Request = None,
    user_id: str = Depends(get_messaging_user_id),
):
    require_participant_role(user_id, conversation_id, {"admin"})

    updates: Dict[str, Any] = {}
    for key in ("title", "description", "icon", "topic", "retention_days"):
        val = getattr(inp, key)
        if val is not None:
            updates[key] = val
    if not updates:
        raise HTTPException(400, "No updates provided")

    expr_names = {f"#{k}": k for k in updates}
    expr_vals = {f":{k}": v for k, v in updates.items()}
    update_expr = "SET " + ", ".join([f"#{k} = :{k}" for k in updates])

    tbl_convos.update_item(
        Key={"conversation_id": conversation_id},
        UpdateExpression=update_expr,
        ExpressionAttributeNames=expr_names,
        ExpressionAttributeValues=expr_vals,
    )

    convo = tbl_convos.get_item(Key={"conversation_id": conversation_id}).get("Item")
    if not convo:
        raise HTTPException(404, "Conversation not found")

    part = get_participant_any(user_id, conversation_id)
    out = ConversationOut(
        conversation_id=conversation_id,
        type=convo.get("type", "dm"),
        title=convo.get("title"),
        description=convo.get("description"),
        icon=convo.get("icon"),
        topic=convo.get("topic"),
        retention_days=convo.get("retention_days"),
        created_at=int(convo.get("created_at", 0)),
        created_by=convo.get("created_by", ""),
        participant_count=int(convo.get("participant_count", 0)),
        last_message_at=int(convo.get("last_message_at", 0)) or None,
        last_message_preview=convo.get("last_message_preview") or None,
        status="active",
        muted_until=int((part or {}).get("muted_until", 0) or 0),
        last_read_at=int((part or {}).get("last_read_at", 0) or 0),
        unread_count=int((part or {}).get("unread_count", 0) or 0),
    )
    audit_event(
        "messaging_conversation_updated",
        user_id,
        req,
        outcome="success",
        conversation_id=conversation_id,
        updates=list(updates.keys()),
    )
    return out


@router.post("/conversations/{conversation_id}/participants")
def add_participants(
    conversation_id: str,
    inp: AddParticipantsIn,
    req: Request = None,
    user_id: str = Depends(get_messaging_user_id),
):
    require_participant_role(user_id, conversation_id, {"admin"})

    added = 0
    ts = now_ts()
    for pid in dict.fromkeys(inp.participant_ids):
        if pid == user_id:
            continue
        require_subscription_access(user_id, pid)
        existing = get_participant_any(pid, conversation_id)
        if existing:
            if existing.get("status") in ("active", "pending"):
                continue
            tbl_parts.update_item(
                Key={"user_id": pid, "conversation_id": conversation_id},
                UpdateExpression="SET #s = :pending, role = :role, joined_at = :zero, left_at = :zero, unread_count = :zero",
                ExpressionAttributeNames={"#s": "status"},
                ExpressionAttributeValues={
                    ":pending": "pending",
                    ":role": existing.get("role") or "member",
                    ":zero": 0,
                },
            )
            added += 1
            continue

        tbl_parts.put_item(
            Item={
                "user_id": pid,
                "conversation_id": conversation_id,
                "status": "pending",
                "role": "member",
                "muted_until": 0,
                "last_read_at": 0,
                "unread_count": 0,
                "joined_at": 0,
                "left_at": 0,
                "GSI1PK": conversation_id,
                "GSI1SK": pid,
            }
        )
        added += 1

    if added:
        tbl_convos.update_item(
            Key={"conversation_id": conversation_id},
            UpdateExpression="ADD participant_count :inc",
            ExpressionAttributeValues={":inc": added},
        )
    audit_event(
        "messaging_conversation_participants_added",
        user_id,
        req,
        outcome="success",
        conversation_id=conversation_id,
        added_count=added,
    )
    return {"ok": True, "added_count": added}


@router.delete("/conversations/{conversation_id}/participants/{participant_id}")
def remove_participant(
    conversation_id: str,
    participant_id: str,
    req: Request = None,
    user_id: str = Depends(get_messaging_user_id),
):
    require_participant_role(user_id, conversation_id, {"admin"})
    if participant_id == user_id:
        raise HTTPException(400, "Use /leave to remove yourself from a conversation")
    part = get_participant_any(participant_id, conversation_id)
    if not part:
        raise HTTPException(404, "Participant not found")
    if part.get("status") != "left":
        ts = now_ts()
        tbl_parts.update_item(
            Key={"user_id": participant_id, "conversation_id": conversation_id},
            UpdateExpression="SET #s = :left, left_at = :ts",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={":left": "left", ":ts": ts},
        )
        tbl_convos.update_item(
            Key={"conversation_id": conversation_id},
            UpdateExpression="ADD participant_count :neg",
            ExpressionAttributeValues={":neg": -1},
        )
    audit_event(
        "messaging_conversation_participant_removed",
        user_id,
        req,
        outcome="success",
        conversation_id=conversation_id,
        participant_id=participant_id,
    )
    return {"ok": True}


@router.patch("/conversations/{conversation_id}/participants/{participant_id}")
def update_participant_role(
    conversation_id: str,
    participant_id: str,
    inp: UpdateParticipantRoleIn,
    req: Request = None,
    user_id: str = Depends(get_messaging_user_id),
):
    require_participant_role(user_id, conversation_id, {"admin"})
    part = get_participant_any(participant_id, conversation_id)
    if not part:
        raise HTTPException(404, "Participant not found")
    tbl_parts.update_item(
        Key={"user_id": participant_id, "conversation_id": conversation_id},
        UpdateExpression="SET role = :role",
        ExpressionAttributeValues={":role": inp.role},
    )
    audit_event(
        "messaging_conversation_participant_role_updated",
        user_id,
        req,
        outcome="success",
        conversation_id=conversation_id,
        participant_id=participant_id,
        role=inp.role,
    )
    return {"ok": True, "role": inp.role}


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


def _claim_helpdesk_conversation_internal(
    *,
    conversation_id: str,
    user_id: str,
    req: Optional[Request] = None,
) -> HelpdeskClaimOut:
    def _idempotent_success(latest: dict) -> HelpdeskClaimOut:
        record_helpdesk_claim("idempotent")
        return HelpdeskClaimOut(
            ok=True,
            conversation_id=conversation_id,
            state="assigned",
            assigned_agent_user_id=user_id,
            assignment_version=int(latest.get("assignment_version") or 0),
            idempotent=True,
        )

    convo = _get_conversation_or_404(conversation_id)
    if str(convo.get("routing_mode") or "") != "helpdesk_bridge":
        raise HTTPException(400, detail={"code": "helpdesk_claim_invalid_mode", "message": "conversation is not helpdesk-routed"})

    group_id = str(convo.get("routing_group_id") or "")
    if not _is_helpdesk_group_member(group_id, user_id):
        raise HTTPException(403, detail={"code": "helpdesk_claim_not_group_member", "message": "user is not a helpdesk group member"})

    ts = now_ts()
    if not _is_user_online_available(user_id, ts):
        raise HTTPException(403, detail={"code": "helpdesk_claim_not_available", "message": "user is not currently online/available"})

    current_state = str(convo.get("routing_state") or "none")
    current_agent = str(convo.get("active_agent_user_id") or "")
    current_version = int(convo.get("assignment_version") or 0)

    if current_state == "assigned":
        if current_agent == user_id:
            return _idempotent_success(convo)
        record_helpdesk_claim("conflict")
        raise HTTPException(409, detail={"code": "helpdesk_claim_already_assigned", "message": "conversation already assigned"})

    if current_state != "awaiting_agent":
        record_helpdesk_claim("conflict")
        raise HTTPException(409, detail={"code": "helpdesk_claim_invalid_state", "message": f"cannot claim from state: {current_state}"})

    try:
        result = _apply_helpdesk_routing_transition(
            conversation_id=conversation_id,
            cmd=RoutingTransitionInput(
                action="assign_agent",
                now_ts=ts,
                agent_user_id=user_id,
                expected_assignment_version=current_version,
            ),
            actor_user_id=user_id,
            metadata={"reason": "claim"},
        )
    except RoutingTransitionError as exc:
        if exc.code in {"routing_assign_invalid_state", "routing_assignment_version_conflict"}:
            latest = _get_conversation_or_404(conversation_id)
            if str(latest.get("routing_state") or "") == "assigned" and str(latest.get("active_agent_user_id") or "") == user_id:
                return _idempotent_success(latest)
            record_helpdesk_claim("conflict")
            raise HTTPException(409, detail={"code": "helpdesk_claim_conflict", "message": "conversation claim conflict"})
        raise HTTPException(400, detail={"code": exc.code, "message": exc.message})
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            latest = _get_conversation_or_404(conversation_id)
            if str(latest.get("routing_state") or "") == "assigned" and str(latest.get("active_agent_user_id") or "") == user_id:
                return _idempotent_success(latest)
            record_helpdesk_claim("conflict")
            raise HTTPException(409, detail={"code": "helpdesk_claim_conflict", "message": "conversation claim conflict"})
        raise

    updated = result.get("conversation", {}) if isinstance(result, dict) else {}
    audit_event(
        "messaging_helpdesk_conversation_claimed",
        user_id,
        req,
        outcome="success",
        conversation_id=conversation_id,
        routing_group_id=group_id,
    )
    record_helpdesk_claim("success")
    return HelpdeskClaimOut(
        ok=True,
        conversation_id=conversation_id,
        state=str(updated.get("routing_state") or "assigned"),
        assigned_agent_user_id=str(updated.get("active_agent_user_id") or user_id),
        assignment_version=int(updated.get("assignment_version") or (current_version + 1)),
        idempotent=False,
    )


@router.post("/helpdesk/conversations/{conversation_id}/claim", response_model=HelpdeskClaimOut)
def claim_helpdesk_conversation(
    conversation_id: str,
    req: Request = None,
    user_id: str = Depends(get_messaging_user_id),
):
    return _claim_helpdesk_conversation_internal(conversation_id=conversation_id, user_id=user_id, req=req)


def _auto_claim_helpdesk_on_first_reply(*, conversation_id: str, convo: dict, user_id: str, req: Optional[Request] = None) -> None:
    if str(convo.get("routing_mode") or "") != "helpdesk_bridge":
        return
    group_id = str(convo.get("routing_group_id") or "")
    if not group_id or not _is_helpdesk_group_member(group_id, user_id):
        return

    state = str(convo.get("routing_state") or "none")
    assigned_agent = str(convo.get("active_agent_user_id") or "")
    if state == "assigned" and assigned_agent and assigned_agent != user_id:
        raise HTTPException(409, detail={"code": "helpdesk_claim_already_assigned", "message": "conversation already assigned"})
    if state != "awaiting_agent":
        return
    if not HELPDESK_AUTO_CLAIM_ON_REPLY_ENABLED:
        raise HTTPException(409, detail={"code": "helpdesk_claim_required", "message": "explicit claim required before replying"})

    _claim_helpdesk_conversation_internal(conversation_id=conversation_id, user_id=user_id, req=req)


@router.get("/conversations/{conversation_id}/routing-events", response_model=List[RoutingEventOut])
def list_conversation_routing_events(
    conversation_id: str,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    user_id: str = Depends(get_messaging_user_id),
):
    require_participant_role(user_id, conversation_id, {"admin"})
    resp = tbl_routing_events.query(
        KeyConditionExpression=Key("conversation_id").eq(conversation_id),
        ScanIndexForward=False,
        Limit=limit,
    )
    items = resp.get("Items", [])
    return [
        RoutingEventOut(
            conversation_id=item.get("conversation_id", conversation_id),
            event_id=item.get("event_id", ""),
            event_type=item.get("event_type", ""),
            actor_user_id=item.get("actor_user_id", ""),
            from_state=item.get("from_state", ""),
            to_state=item.get("to_state", ""),
            created_at=int(item.get("created_at", 0) or 0),
            assignment_version=int(item.get("assignment_version", 0) or 0),
            routing_group_id=item.get("routing_group_id", ""),
            active_agent_user_id=item.get("active_agent_user_id", ""),
            metadata=item.get("metadata", {}) if isinstance(item.get("metadata"), dict) else {},
        )
        for item in items
    ]


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
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
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
    try:
        parts = tbl_parts.query(IndexName="GSI1", KeyConditionExpression=Key("GSI1PK").eq(conversation_id)).get("Items", [])
    except Exception:
        parts = []
    if not isinstance(parts, list):
        parts = []

    out: List[MessageOut] = []
    for m in items:
        if not _filter_message_visible(m, user_id):
            continue
        msg = _message_out_from_item(m, user_id)
        out.append(_apply_message_receipts(msg, m, parts))
    return out


@router.get("/conversations/{conversation_id}/messages/search", response_model=List[MessageOut])
def search_messages_in_conversation(
    conversation_id: str,
    q: Annotated[str, Query(..., min_length=1, max_length=200)],
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    sender_id: Annotated[Optional[str], Query(max_length=64)] = None,
    after_ts: Annotated[Optional[int], Query(ge=0)] = None,
    kind: Annotated[Optional[List[str]], Query()] = None,
    user_id: str = Depends(get_messaging_user_id),
):
    require_participant_active(user_id, conversation_id)
    if not isinstance(sender_id, str):
        sender_id = None
    if not isinstance(after_ts, int):
        after_ts = None
    kind_filter = _filter_search_kinds(kind)
    opensearch_kwargs = {
        "limit": limit,
        "conversation_id": conversation_id,
        "sender_id": sender_id,
        "after_ts": after_ts,
    }
    if kind_filter is not None:
        opensearch_kwargs["kinds"] = kind_filter
    opensearch_keys = _opensearch_search_messages(q, **opensearch_kwargs)
    if opensearch_keys is not None:
        message_items = _fetch_message_items(opensearch_keys)
        matches = [
            item
            for item in message_items
            if _is_searchable_message(item) and _filter_message_visible(item, user_id)
            and (not sender_id or item.get("sender_id") == sender_id)
            and (after_ts is None or int(item.get("created_at", 0)) >= int(after_ts))
            and (not kind_filter or item.get("kind") in kind_filter)
        ]
    else:
        query_tokens = build_message_query_tokens(q)
        indexed = _search_messages_index(
            query_tokens,
            conversation_id=conversation_id,
            sender_id=sender_id,
            after_ts=after_ts,
            limit=limit,
        )
        if indexed is None:
            matches = _fallback_search_messages(
                conversation_id,
                q,
                limit=limit,
                user_id=user_id,
                sender_id=sender_id,
                after_ts=after_ts,
                kinds=kind_filter,
            )
        else:
            message_items = _fetch_message_items([item["message_key"] for item in indexed])
            matches = [
                item
                for item in message_items
                if _is_searchable_message(item) and _filter_message_visible(item, user_id)
                and (not sender_id or item.get("sender_id") == sender_id)
                and (after_ts is None or int(item.get("created_at", 0)) >= int(after_ts))
                and (not kind_filter or item.get("kind") in kind_filter)
            ]

    matches = _rank_messages_by_relevance(matches, q)
    try:
        parts = tbl_parts.query(IndexName="GSI1", KeyConditionExpression=Key("GSI1PK").eq(conversation_id)).get("Items", [])
    except Exception:
        parts = []
    if not isinstance(parts, list):
        parts = []
    out = []
    for item in matches[:limit]:
        msg = _message_out_from_item(item, user_id)
        out.append(_apply_message_receipts(msg, item, parts))
    return out


@router.get("/messages/search", response_model=List[MessageOut])
def search_messages_all_conversations(
    q: Annotated[str, Query(..., min_length=1, max_length=200)],
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    sender_id: Annotated[Optional[str], Query(max_length=64)] = None,
    after_ts: Annotated[Optional[int], Query(ge=0)] = None,
    kind: Annotated[Optional[List[str]], Query()] = None,
    user_id: str = Depends(get_messaging_user_id),
):
    if not isinstance(sender_id, str):
        sender_id = None
    if not isinstance(after_ts, int):
        after_ts = None
    kind_filter = _filter_search_kinds(kind)
    try:
        parts = tbl_parts.query(KeyConditionExpression=Key("user_id").eq(user_id), Limit=200).get("Items", [])
    except Exception:
        parts = []
    allowed_conversation_ids = {p["conversation_id"] for p in parts if p.get("status") == "active"}
    if not allowed_conversation_ids:
        return []

    opensearch_kwargs = {
        "limit": limit,
        "allowed_conversation_ids": allowed_conversation_ids,
        "sender_id": sender_id,
        "after_ts": after_ts,
    }
    if kind_filter is not None:
        opensearch_kwargs["kinds"] = kind_filter
    opensearch_keys = _opensearch_search_messages(q, **opensearch_kwargs)

    matches: list[dict]
    if opensearch_keys is not None:
        message_items = _fetch_message_items(opensearch_keys)
        matches = [
            item
            for item in message_items
            if item.get("conversation_id") in allowed_conversation_ids
            and _is_searchable_message(item)
            and _filter_message_visible(item, user_id)
            and (not sender_id or item.get("sender_id") == sender_id)
            and (after_ts is None or int(item.get("created_at", 0)) >= int(after_ts))
            and (not kind_filter or item.get("kind") in kind_filter)
        ]
    else:
        query_tokens = build_message_query_tokens(q)
        indexed = _search_messages_index(
            query_tokens,
            allowed_conversation_ids=allowed_conversation_ids,
            sender_id=sender_id,
            after_ts=after_ts,
            limit=limit,
        )
        if indexed is None:
            matches = []
            for cid in allowed_conversation_ids:
                if len(matches) >= limit:
                    break
                matches.extend(
                    _fallback_search_messages(
                        cid,
                        q,
                        limit=limit - len(matches),
                        user_id=user_id,
                        sender_id=sender_id,
                        after_ts=after_ts,
                        kinds=kind_filter,
                    )
                )
        else:
            message_items = _fetch_message_items([item["message_key"] for item in indexed])
            matches = [
                item
                for item in message_items
                if item.get("conversation_id") in allowed_conversation_ids
                and _is_searchable_kind(item.get("kind"))
                and _filter_message_visible(item, user_id)
                and (not sender_id or item.get("sender_id") == sender_id)
                and (after_ts is None or int(item.get("created_at", 0)) >= int(after_ts))
                and (not kind_filter or item.get("kind") in kind_filter)
            ]

    matches = _rank_messages_by_relevance(matches, q)
    convo_participants: Dict[str, List[dict]] = {}
    for item in matches[:limit]:
        cid = item.get("conversation_id")
        if not cid or cid in convo_participants:
            continue
        convo_participants[cid] = tbl_parts.query(
            IndexName="GSI1",
            KeyConditionExpression=Key("GSI1PK").eq(cid),
        ).get("Items", [])
    out: List[MessageOut] = []
    for item in matches[:limit]:
        msg = _message_out_from_item(item, user_id)
        out.append(_apply_message_receipts(msg, item, convo_participants.get(item.get("conversation_id"), [])))
    return out


@router.post("/conversations/{conversation_id}/messages", response_model=MessageOut)
def send_text_message(
    conversation_id: str,
    inp: SendTextMessageIn,
    req: Request = None,
    user_id: str = Depends(get_messaging_user_id),
):
    require_participant_active(user_id, conversation_id)
    if inp.encryption and not _encrypted_messages_enabled():
        raise HTTPException(status_code=403, detail="Encrypted messaging is disabled")
    convo = _get_conversation_or_404(conversation_id)
    _auto_claim_helpdesk_on_first_reply(conversation_id=conversation_id, convo=convo, user_id=user_id, req=req)
    try:
        resp = tbl_parts.query(IndexName="GSI1", KeyConditionExpression=Key("GSI1PK").eq(conversation_id))
        participants = resp.get("Items", [])
    except Exception:
        participants = []
    for participant in participants:
        pid = participant.get("user_id")
        if pid and pid != user_id:
            require_subscription_access(user_id, pid)
    _enforce_message_send_quota_precheck(user_id=user_id, conversation_id=conversation_id, req=req)
    _validate_reply_target(conversation_id, inp.reply_to_message_id)

    mid = "m_" + new_id()
    ts = now_ts()

    is_encrypted = inp.encryption is not None
    message_text = inp.text or ""
    item: Dict[str, Any] = {
        "conversation_id": conversation_id,
        "message_id": mid,
        "sender_id": user_id,
        "created_at": ts,
        "kind": "text",
        "text": message_text if not is_encrypted else None,
        "is_encrypted": is_encrypted,
        "deleted_for": set(),
        "reactions": {},
    }
    if is_encrypted and inp.encryption:
        item["encryption"] = inp.encryption.model_dump()

    link_preview = _serialize_preview(inp.preview) if not is_encrypted else None
    if not link_preview and not is_encrypted:
        url = _extract_first_url(message_text)
        if url:
            link_preview = _fetch_link_preview(url)
    if link_preview:
        item["preview"] = link_preview
    ttl = _message_retention_ttl(convo, ts)
    if ttl:
        item["ttl"] = ttl
    if inp.reply_to_message_id:
        item["reply_to_message_id"] = inp.reply_to_message_id

    tbl_msgs.put_item(Item=item)
    _bump_unread_counts(conversation_id, user_id, participants)
    _record_delivery_receipts(conversation_id, mid, user_id, participants)
    if not is_encrypted:
        index_message_search(conversation_id, mid, user_id, ts, message_text, kind="text")

    preview_text = "[Encrypted message]" if is_encrypted else message_text[:140]
    tbl_convos.update_item(
        Key={"conversation_id": conversation_id},
        UpdateExpression="SET last_message_at = :ts, last_message_preview = :p",
        ExpressionAttributeValues={":ts": ts, ":p": preview_text},
    )

    message = MessageOut(
        conversation_id=conversation_id,
        message_id=mid,
        sender_id=user_id,
        created_at=ts,
        kind="text",
        text=message_text if not is_encrypted else None,
        preview=link_preview,
        reply_to_message_id=inp.reply_to_message_id,
        is_encrypted=is_encrypted,
        encryption=inp.encryption,
    )
    message = _apply_message_receipts(message, item, participants)

    fanout_event_to_conversation(
        conversation_id=conversation_id,
        sender_id=user_id,
        event_type="message:new",
        payload={
            "message_id": mid,
            "created_at": ts,
            "message": _serialize_message_event_payload(item, user_id),
        },
        respect_mute=False,
    )

    audit_event(
        "messaging_message_sent",
        user_id,
        req,
        outcome="success",
        conversation_id=conversation_id,
        message_id=mid,
        kind="text",
        is_encrypted=is_encrypted,
        reply_to_message_id=inp.reply_to_message_id,
    )
    _meter_message_send(user_id=user_id, conversation_id=conversation_id, message_id=mid)
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
    convo = _get_conversation_or_404(conversation_id)
    try:
        resp = tbl_parts.query(IndexName="GSI1", KeyConditionExpression=Key("GSI1PK").eq(conversation_id))
        participants = resp.get("Items", [])
    except Exception:
        participants = []
    for participant in participants:
        pid = participant.get("user_id")
        if pid and pid != user_id:
            require_subscription_access(user_id, pid)
    _enforce_message_send_quota_precheck(user_id=user_id, conversation_id=conversation_id, req=req)
    _validate_reply_target(conversation_id, inp.reply_to_message_id)


    mid = "m_" + new_id()
    ts = now_ts()

    item: Dict[str, Any] = {
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
    ttl = _message_retention_ttl(convo, ts)
    if ttl:
        item["ttl"] = ttl
    if inp.reply_to_message_id:
        item["reply_to_message_id"] = inp.reply_to_message_id

    tbl_msgs.put_item(Item=item)
    _bump_unread_counts(conversation_id, user_id, participants)
    _record_delivery_receipts(conversation_id, mid, user_id, participants)

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
    message = _apply_message_receipts(message, item, participants)
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
    _meter_message_send(user_id=user_id, conversation_id=conversation_id, message_id=mid)
    _meter_messaging_attachment_upload(
        user_id=user_id,
        bucket=inp.bucket,
        key=inp.key,
        conversation_id=conversation_id,
        message_id=mid,
    )
    return message


@router.post("/conversations/{conversation_id}/messages/file", response_model=MessageOut)
def create_file_message(
    conversation_id: str,
    inp: CreateFileMessageIn,
    req: Request = None,
    user_id: str = Depends(get_messaging_user_id),
):
    require_participant_active(user_id, conversation_id)
    convo = _get_conversation_or_404(conversation_id)
    resp = tbl_parts.query(IndexName="GSI1", KeyConditionExpression=Key("GSI1PK").eq(conversation_id))
    for participant in resp.get("Items", []):
        pid = participant.get("user_id")
        if pid and pid != user_id:
            require_subscription_access(user_id, pid)
    _enforce_message_send_quota_precheck(user_id=user_id, conversation_id=conversation_id, req=req)
    _validate_reply_target(conversation_id, inp.reply_to_message_id)

    path = norm_path(inp.path, is_folder=False)
    node = get_node(user_id, path)
    if node.get("type") != "file":
        raise HTTPException(400, "Path must reference a file")

    content_type = node.get("content_type") or "application/octet-stream"
    if inp.kind == "audio" and not content_type.startswith("audio/"):
        raise HTTPException(400, "Audio messages require an audio/* content type")
    if inp.kind == "video" and not content_type.startswith("video/"):
        raise HTTPException(400, "Video messages require a video/* content type")

    mid = "m_" + new_id()
    ts = now_ts()
    preview = _serialize_preview(inp.preview)

    duration_seconds = inp.duration_seconds or node.get("duration_seconds")
    item: Dict[str, Any] = {
        "conversation_id": conversation_id,
        "message_id": mid,
        "sender_id": user_id,
        "created_at": ts,
        "kind": inp.kind,
        "search_text": f"{node.get('name', '')} {node.get('path', '')}".strip(),
        "file": {
            "path": node.get("path"),
            "name": node.get("name"),
            "size": node.get("size"),
            "content_type": content_type,
            "duration_seconds": duration_seconds,
            "thumbnail": node.get("thumbnail"),
        },
        "deleted_for": set(),
        "reactions": {},
    }
    if preview:
        item["preview"] = preview
    ttl = _message_retention_ttl(convo, ts)
    if ttl:
        item["ttl"] = ttl
    if inp.reply_to_message_id:
        item["reply_to_message_id"] = inp.reply_to_message_id

    tbl_msgs.put_item(Item=item)
    _bump_unread_counts(conversation_id, user_id, resp.get("Items", []))
    _record_delivery_receipts(conversation_id, mid, user_id, resp.get("Items", []))
    if item.get("search_text"):
        index_message_search(conversation_id, mid, user_id, ts, item["search_text"], kind=inp.kind)

    preview_label = {
        "file": "[file]",
        "audio": "[voice note]",
        "video": "[video]",
    }.get(inp.kind, "[file]")
    tbl_convos.update_item(
        Key={"conversation_id": conversation_id},
        UpdateExpression="SET last_message_at = :ts, last_message_preview = :p",
        ExpressionAttributeValues={":ts": ts, ":p": preview_label},
    )

    message = MessageOut(
        conversation_id=conversation_id,
        message_id=mid,
        sender_id=user_id,
        created_at=ts,
        kind=inp.kind,
        file=item["file"],
        preview=preview,
        reply_to_message_id=inp.reply_to_message_id,
    )
    message = _apply_message_receipts(message, item, resp.get("Items", []))
    audit_event(
        "messaging_message_sent",
        user_id,
        req,
        outcome="success",
        conversation_id=conversation_id,
        message_id=mid,
        kind=inp.kind,
        reply_to_message_id=inp.reply_to_message_id,
    )
    _meter_message_send(user_id=user_id, conversation_id=conversation_id, message_id=mid)
    return message


@router.get("/conversations/{conversation_id}/messages/{message_id}/attachment")
def download_message_attachment(
    conversation_id: str,
    message_id: str,
    request: Request,
    x_request_id: Optional[str] = Header(default=None, alias="X-Request-Id"),
    user_id: str = Depends(get_messaging_user_id),
):
    require_participant_active(user_id, conversation_id)
    msg = _get_message_or_404(conversation_id, message_id)
    kind = str(msg.get("kind") or "")

    if kind == "image":
        image = msg.get("image") or {}
        bucket = str(image.get("bucket") or S3_BUCKET_IMAGES)
        key = str(image.get("key") or "")
        content_type = str(image.get("content_type") or "application/octet-stream")
        filename = os.path.basename(key) or "image"
    elif kind in {"file", "audio", "video"}:
        file_ref = msg.get("file") or {}
        path = file_ref.get("path")
        owner = str(msg.get("sender_id") or "") or user_id
        if not path:
            raise HTTPException(400, "Attachment path missing")
        node = get_node(owner, str(path))
        bucket = str(node.get("s3_bucket") or "")
        key = str(node.get("s3_key") or "")
        content_type = str(node.get("content_type") or file_ref.get("content_type") or "application/octet-stream")
        filename = str(node.get("name") or file_ref.get("name") or os.path.basename(key) or "attachment")
    else:
        raise HTTPException(400, "Message does not contain downloadable attachment")

    if not bucket or not key:
        raise HTTPException(404, "Attachment object not found")

    try:
        obj = s3.get_object(Bucket=bucket, Key=key)
    except Exception as exc:
        raise HTTPException(404, "Attachment object not found") from exc

    body = obj.get("Body")
    if body is None:
        raise HTTPException(404, "Attachment stream missing")

    content_len = int(obj.get("ContentLength") or 0)
    attachment_key = f"{bucket}/{key}"

    def _iter_stream() -> Iterable[bytes]:
        sent = 0
        try:
            for chunk in body.iter_chunks(chunk_size=64 * 1024):
                if not chunk:
                    continue
                sent += len(chunk)
                yield chunk
        finally:
            _record_messaging_attachment_download(
                user_id=user_id,
                conversation_id=conversation_id,
                message_id=message_id,
                attachment_key=attachment_key,
                bytes_count=sent,
                idempotency_operation_id=x_request_id,
            )

    headers = {
        "Content-Disposition": f'inline; filename="{filename}"',
        "Cache-Control": "private, max-age=60",
    }
    if content_len > 0:
        headers["Content-Length"] = str(content_len)

    audit_event(
        "messaging_attachment_downloaded",
        user_id,
        request,
        outcome="success",
        conversation_id=conversation_id,
        message_id=message_id,
        kind=kind,
        attachment_key=attachment_key,
    )
    return StreamingResponse(_iter_stream(), media_type=content_type, headers=headers)


@router.post("/conversations/{conversation_id}/read")
def mark_read(conversation_id: str, inp: MarkReadIn, req: Request = None, user_id: str = Depends(get_messaging_user_id)):
    require_participant_active(user_id, conversation_id)

    resolved_last_read_at = inp.last_read_at
    if resolved_last_read_at is None and inp.last_read_message_id:
        msg = tbl_msgs.get_item(Key={"conversation_id": conversation_id, "message_id": inp.last_read_message_id}).get("Item")
        if not msg:
            raise HTTPException(
                status_code=422,
                detail="last_read_message_id could not be resolved for this conversation",
            )
        resolved_last_read_at = int(msg.get("created_at", 0) or 0)
        if not resolved_last_read_at:
            raise HTTPException(
                status_code=422,
                detail="Resolved message is missing created_at timestamp",
            )
        logger.warning(
            "messaging.mark_read converted legacy last_read_message_id to last_read_at",
            extra={
                "conversation_id": conversation_id,
                "user_id": user_id,
                "message_id": inp.last_read_message_id,
                "last_read_at": resolved_last_read_at,
            },
        )

    part = get_participant_any(user_id, conversation_id) or {}
    current = int(part.get("last_read_at", 0) or 0)
    newv = max(current, int(resolved_last_read_at or 0))

    tbl_parts.update_item(
        Key={"user_id": user_id, "conversation_id": conversation_id},
        UpdateExpression="SET last_read_at = :v, unread_count = :zero",
        ExpressionAttributeValues={":v": newv, ":zero": 0},
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
    msg = _get_message_or_404(conversation_id, message_id)
    if isinstance(msg, dict) and msg.get("revoked_at"):
        raise HTTPException(400, "Message already revoked")
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


@router.delete("/conversations/{conversation_id}/messages/{message_id}/revoke", response_model=MessageOut)
def revoke_message_for_all(
    conversation_id: str,
    message_id: str,
    req: Request = None,
    user_id: str = Depends(get_messaging_user_id),
):
    require_participant_active(user_id, conversation_id)
    msg = _get_message_or_404(conversation_id, message_id)
    _ensure_can_revoke_message(user_id, conversation_id, msg)

    ts = now_ts()
    tbl_msgs.update_item(
        Key={"conversation_id": conversation_id, "message_id": message_id},
        UpdateExpression="SET revoked_at = :ts, revoked_by = :uid",
        ExpressionAttributeValues={":ts": ts, ":uid": user_id},
    )
    if _is_searchable_kind(msg.get("kind")):
        remove_message_search(conversation_id, message_id, _message_search_text(msg))

    fanout_event_to_conversation(
        conversation_id=conversation_id,
        sender_id=user_id,
        event_type="message:revoked",
        payload={"message_id": message_id, "revoked_at": ts, "revoked_by": user_id},
        respect_mute=False,
    )
    audit_event(
        "messaging_message_revoked",
        user_id,
        req,
        outcome="success",
        conversation_id=conversation_id,
        message_id=message_id,
        revoked_at=ts,
    )
    item = _get_message_or_404(conversation_id, message_id)
    return _message_out_from_item(item, user_id)


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
    msg = _get_message_or_404(conversation_id, message_id)
    if isinstance(msg, dict) and msg.get("revoked_at"):
        raise HTTPException(400, "Cannot react to a revoked message")

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
    if isinstance(msg, dict) and msg.get("revoked_at"):
        raise HTTPException(400, "Cannot edit a revoked message")
    if msg.get("sender_id") != user_id:
        raise HTTPException(403, "Only the sender can edit this message")
    if bool(msg.get("is_encrypted")):
        _raise_encrypted_edit_unsupported()

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

    remove_message_search(conversation_id, message_id, old_text)
    index_message_search(conversation_id, message_id, user_id, int(msg.get("created_at", ts)), new_text)

    item = _get_message_or_404(conversation_id, message_id)

    fanout_event_to_conversation(
        conversation_id=conversation_id,
        sender_id=user_id,
        event_type="message:edited",
        payload={"message_id": message_id, "edited_at": ts},
        respect_mute=False,
    )

    message = _message_out_from_item(item, user_id)
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
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    user_id: str = Depends(get_messaging_user_id),
):
    require_participant_active(user_id, conversation_id)

    msg = _get_message_or_404(conversation_id, message_id)
    if isinstance(msg, dict) and msg.get("revoked_at"):
        raise HTTPException(400, "Cannot view a revoked message")

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
    convo = _get_conversation_or_404(target_conversation_id)

    _validate_reply_target(target_conversation_id, inp.reply_to_message_id)

    src = _get_message_or_404(inp.source_conversation_id, inp.source_message_id)
    if src.get("revoked_at"):
        raise HTTPException(400, "Cannot forward a revoked message")
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
    if kind not in ("text", "image", "file", "audio", "video"):
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
    ttl = _message_retention_ttl(convo, ts)
    if ttl:
        item["ttl"] = ttl

    if inp.note:
        item["forward_note"] = inp.note
    if inp.reply_to_message_id:
        item["reply_to_message_id"] = inp.reply_to_message_id

    if kind == "text":
        is_encrypted = bool(src.get("is_encrypted"))
        if is_encrypted:
            item["is_encrypted"] = True
            item["encryption"] = src.get("encryption")
            item["text"] = None
            preview = "[fwd encrypted]"
        else:
            item["text"] = src.get("text", "")
            item["search_text"] = item["text"]
            preview = "[fwd] " + (item["text"] or "")[:140]
        if src.get("preview") and not is_encrypted:
            item["preview"] = src.get("preview")
    elif kind == "image":
        item["image"] = src.get("image")
        preview = "[fwd image]"
    else:
        item["file"] = src.get("file")
        if src.get("search_text"):
            item["search_text"] = src.get("search_text")
        elif item.get("file"):
            name = item["file"].get("name") or ""
            path = item["file"].get("path") or ""
            item["search_text"] = f"{name} {path}".strip()
        if src.get("preview"):
            item["preview"] = src.get("preview")
        preview = f"[fwd {kind}]"

    tbl_msgs.put_item(Item=item)
    if _is_searchable_kind(kind) and not bool(item.get("is_encrypted")):
        index_message_search(
            target_conversation_id,
            mid,
            user_id,
            ts,
            _message_search_text(item),
            kind=kind,
        )
    try:
        participants = tbl_parts.query(
            IndexName="GSI1",
            KeyConditionExpression=Key("GSI1PK").eq(target_conversation_id),
        ).get("Items", [])
    except Exception:
        participants = []
    _record_delivery_receipts(target_conversation_id, mid, user_id, participants)

    tbl_convos.update_item(
        Key={"conversation_id": target_conversation_id},
        UpdateExpression="SET last_message_at = :ts, last_message_preview = :p",
        ExpressionAttributeValues={":ts": ts, ":p": preview},
    )

    message = _apply_message_receipts(_message_out_from_item(item, user_id), item, participants)

    fanout_event_to_conversation(
        conversation_id=target_conversation_id,
        sender_id=user_id,
        event_type="message:forwarded",
        payload={
            "message_id": mid,
            "forwarded_from": forwarded_from,
            "created_at": ts,
            "message": _serialize_message_event_payload(item, user_id),
        },
        respect_mute=False,
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
    msg = _get_message_or_404(conversation_id, message_id)
    if isinstance(msg, dict) and msg.get("revoked_at"):
        raise HTTPException(400, "Message was revoked")

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
    if _message_receipts_enabled():
        tbl_receipts.update_item(
            Key={"conversation_id": conversation_id, "message_user": f"{message_id}#{user_id}"},
            UpdateExpression="SET message_id = :mid, user_id = :uid, delivered_at = if_not_exists(delivered_at, :ts), "
            "read_at = :ts",
            ExpressionAttributeValues={":mid": message_id, ":uid": user_id, ":ts": ts},
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
    limit: Annotated[int, Query(ge=1, le=500)] = 200,
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
    user_ids: Annotated[str, Query(..., description="Comma-separated user_ids")],
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
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    user_id: str = Depends(get_messaging_user_id),
):
    items = _ddb_fetch_events(user_id, after, limit)
    return {"events": items, "next_after": items[-1]["event_id"] if items else after}


@router.get("/events/stream")
async def events_stream(
    after: Optional[str] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    poll_ms: Annotated[int, Query(ge=200, le=5000)] = 1000,
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


@router.get("/config", response_model=MessagingConfigOut)
def messaging_config(user_id: str = Depends(get_messaging_user_id)):
    _ = user_id
    return MessagingConfigOut(messaging_encrypted_messages_enabled=_encrypted_messages_enabled())


@router.get("/healthz")
def healthz():
    return {"ok": True, "ts": now_ts()}
