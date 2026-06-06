from __future__ import annotations

import asyncio
import base64
import binascii
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import logging
import os
import hashlib
import hmac
import re
import threading
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
from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, Response
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field, model_validator
from pydantic_core import PydanticCustomError

from app.auth.deps import AuthenticatedUser, extract_bearer_token, get_authenticated_user, get_authenticated_user_sub, require_kyc_tier
from app.auth.policy import require_admin_scope
from app.metrics import (
    record_helpdesk_alert_sent,
    record_helpdesk_claim,
    record_helpdesk_claim_conflict,
    record_helpdesk_claim_success,
    record_helpdesk_failover,
    record_helpdesk_no_agents_notice,
    record_helpdesk_time_to_first_claim_ms,
    record_messaging_archive_export_outcome,
    record_mass_message_campaign_event,
    record_mass_message_destination_outcome,
    record_mass_message_destination_retry,
    record_mass_message_limit_event,
    record_mass_message_worker_latency,
    record_messaging_gallery_cursor_page_depth,
    record_messaging_gallery_latency,
    record_messaging_gallery_request,
    record_messaging_draft_latency,
    record_messaging_draft_operation,
    record_messaging_lottery_reveal_latency,
    record_messaging_lottery_send,
    record_messaging_lottery_unlock_attempt,
    record_messaging_lottery_unlock_latency,
    record_messaging_lottery_unlock_result,
    record_messaging_message_control_action,
    record_messaging_report_validation_error,
    record_messaging_thread_promotion_event,
    record_messaging_thread_promotion_retry,
    record_messaging_thread_invalid_cursor,
    record_messaging_thread_query_latency,
)
from app.core.settings import S
from app.core.cursor import decode_cursor, encode_cursor
from app.core.aws import ddb
from app.core.tables import T
from app.core.aws_clients import s3_client
from app.metrics import (
    record_once_media_conflict,
    record_once_media_consume,
    record_once_media_grant,
    record_once_media_grant_latency,
    record_once_media_send,
)
from app.services.alerts import audit_event
from app.services.messaging_routing import (
    RoutingTransitionError,
    RoutingTransitionInput,
    build_routing_event_item,
    transition_helpdesk_routing,
)
from app.services.filemanager import get_node, get_usage_summary, norm_path, share_node
from app.services.messaging_gallery import fetch_gallery_page
from app.services.messaging_gallery_index import fetch_gallery_index_page, sync_gallery_index_entries
from app.services.profile import get_profile_identity
from app.services.api_key_policy_enforcement import maybe_enforce_api_key_route_policy
from app.services.sessions import require_ui_session
from app.services.messaging_archive_writer import MessagingArchiveWriteError, _archive_root_dir, emit_messaging_archive_event
from app.services.messaging_archive_query import query_archive_records
from app.services.messaging_archive_export import build_case_export_bundle
from app.services.signature_packet_store import get_signature_packet_progress_for_user
from app.services.subscription_access import require_subscription_access
from app.services.internal_api_entitlements import enforce_internal_api_entitlement
from app.services.messaging_thread_contract import (
    MESSAGE_FIELD_PARENT_ID,
    MESSAGE_FIELD_REPLY_TO_ID,
    MESSAGE_FIELD_THREAD_ID,
    MESSAGE_FIELD_THREAD_ROOT_ID,
)
from app.services.messaging_threads_store import (
    create_message_thread_record,
    find_thread_for_root_message,
    get_message_thread_record,
)
from app.services.messaging_drafts import (
    DraftNotFoundError,
    DraftValidationError,
    create_draft,
    delete_draft,
    get_draft,
    list_drafts,
    update_draft,
)
from app.models_mass_message import (
    MassMessageCancelCampaignResponse,
    MassMessageCampaignListResponse,
    MassMessageCampaignSummary,
    MassMessageCampaignDetailResponse,
    MassMessageCreateCampaignRequest,
    MassMessageCreateCampaignResponse,
    MassMessageRejectedDestination,
)
from app.services.mass_message_campaigns import (
    apply_destination_counter_delta,
    create_or_get_campaign as create_or_get_mass_campaign_record,
    get_campaign as get_mass_campaign_record,
    list_campaigns_for_sender,
    list_due_scheduled_campaigns as list_due_scheduled_mass_campaigns,
    set_campaign_submission_result,
    update_campaign_status as update_mass_campaign_status,
)
from app.services.mass_message_campaign_destinations import upsert_destination as upsert_mass_destination
from app.services.mass_message_campaign_destinations import list_destinations_page as list_mass_destinations_page
from app.services.mass_message_destination_contract import (
    DESTINATION_ERROR_AUTHORIZATION,
    DESTINATION_ERROR_CONVERSATION_MISSING,
    DESTINATION_ERROR_POLICY_BLOCKED,
    DESTINATION_ERROR_TRANSIENT_INFRA,
    DESTINATION_ERROR_UNKNOWN,
)
from app.services.usage_metering import (
    build_usage_event,
    build_usage_source_idempotency_key,
    record_usage_event_and_aggregates,
)
from app.services import messaging_lottery_store
from app.services.messaging_lottery_rng import choose_weighted_outcome, LotterySelectionError

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
DDB_MESSAGE_GALLERY_INDEX = os.getenv("DDB_MESSAGE_GALLERY_INDEX", "")
OPENSEARCH_ENDPOINT = os.getenv("OPENSEARCH_ENDPOINT", "").strip()
OPENSEARCH_INDEX = os.getenv("OPENSEARCH_INDEX", "messages")
OPENSEARCH_REGION = os.getenv("OPENSEARCH_REGION", AWS_REGION)

DDB_PRESENCE = os.getenv("DDB_PRESENCE", "UserPresence")
DDB_TYPING = os.getenv("DDB_TYPING", "Typing")

DDB_MESSAGE_EDITS = os.getenv("DDB_MESSAGE_EDITS", "MessageEdits")


def _safe_int_env(name: str, default: int) -> int:
    raw = os.getenv(name, str(default))
    try:
        return int(raw)
    except (TypeError, ValueError):
        logger.warning("Invalid integer env override for %s=%r; using default=%d", name, raw, default)
        return default


MESSAGING_THREAD_CURSOR_SECRET = os.getenv("MESSAGING_THREAD_CURSOR_SECRET", "").strip()
MESSAGING_THREAD_CURSOR_PREVIOUS_SECRETS = [
    value.strip()
    for value in os.getenv("MESSAGING_THREAD_CURSOR_PREVIOUS_SECRETS", "").split(",")
    if value.strip()
]
MESSAGING_THREAD_CURSOR_TTL_SECONDS = max(60, _safe_int_env("MESSAGING_THREAD_CURSOR_TTL_SECONDS", 3600))
MESSAGING_THREAD_CURSOR_ALLOW_LEGACY = os.getenv("MESSAGING_THREAD_CURSOR_ALLOW_LEGACY", "1") not in ("0", "false", "False")
MESSAGING_THREAD_CURSOR_ALLOW_LEGACY_SIGNED_FIELDS = os.getenv("MESSAGING_THREAD_CURSOR_ALLOW_LEGACY_SIGNED_FIELDS", "0") not in (
    "0",
    "false",
    "False",
)
MESSAGING_THREAD_CURSOR_MAX_CHARS = max(256, _safe_int_env("MESSAGING_THREAD_CURSOR_MAX_CHARS", 4096))
MESSAGING_THREAD_CURSOR_VERSION = 1
MESSAGING_THREAD_CURSOR_ALG = "HS256"
DDB_MESSAGE_VIEWS = os.getenv("DDB_MESSAGE_VIEWS", "MessageViews")
DDB_MESSAGE_RECEIPTS = os.getenv("DDB_MESSAGE_RECEIPTS", "MessageReceipts")
DDB_MESSAGE_CONSUMPTION = os.getenv("DDB_MESSAGE_CONSUMPTION", "MessageConsumption")

S3_BUCKET_IMAGES = os.getenv("S3_BUCKET_IMAGES", "my-chat-images")

ONLINE_WINDOW_SEC = int(os.getenv("ONLINE_WINDOW_SEC", "30"))
PRESENCE_TTL_SEC = int(os.getenv("PRESENCE_TTL_SEC", "120"))
PRESENCE_SSE_COOLDOWN_SEC = int(os.getenv("PRESENCE_SSE_COOLDOWN_SEC", "60"))
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
tbl_gallery_index = ddb.Table(DDB_MESSAGE_GALLERY_INDEX) if DDB_MESSAGE_GALLERY_INDEX else None
tbl_presence = ddb.Table(DDB_PRESENCE)
tbl_typing = ddb.Table(DDB_TYPING)

tbl_edits = ddb.Table(DDB_MESSAGE_EDITS)
tbl_views = ddb.Table(DDB_MESSAGE_VIEWS)
tbl_receipts = ddb.Table(DDB_MESSAGE_RECEIPTS)
tbl_msg_consumption = ddb.Table(DDB_MESSAGE_CONSUMPTION)

router = APIRouter(prefix="/messaging", tags=["messaging"], dependencies=[Depends(maybe_enforce_api_key_route_policy)])
logger = logging.getLogger(__name__)

_MASS_MESSAGE_RATE_LOCK = threading.Lock()
_MASS_MESSAGE_USER_CREATE_TS: dict[str, deque[int]] = defaultdict(deque)
_MASS_MESSAGE_TENANT_CREATE_TS: dict[str, deque[int]] = defaultdict(deque)
_MASS_MESSAGE_ACTIVE_WORKERS = 0


require_legal_hold_admin = require_admin_scope("content_moderation")
require_compliance_query_admin = require_admin_scope("content_moderation")
require_compliance_export_admin = require_admin_scope("content_moderation")


def _mass_message_payload_hash(*, kind: str, text: str) -> str:
    payload = json.dumps({"kind": kind, "text": text}, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _messaging_mass_send_enabled() -> bool:
    enabled = os.getenv(
        "MESSAGING_MASS_SEND_ENABLED",
        "true" if getattr(S, "messaging_mass_send_enabled", True) else "false",
    ).strip().lower() in {"1", "true", "yes", "on"}
    kill_switch = os.getenv(
        "MESSAGING_MASS_SEND_KILL_SWITCH",
        "true" if getattr(S, "messaging_mass_send_kill_switch", False) else "false",
    ).strip().lower() in {"1", "true", "yes", "on"}
    return enabled and not kill_switch


def _mass_message_tenant_for_user(user_id: str) -> str:
    _ = user_id
    return "default"


def _mass_message_limits_config() -> dict[str, int]:
    return {
        "campaigns_per_user_per_hour": max(0, int(getattr(S, "messaging_mass_send_campaigns_per_user_per_hour", 20))),
        "campaigns_per_tenant_per_hour": max(0, int(getattr(S, "messaging_mass_send_campaigns_per_tenant_per_hour", 500))),
        "max_destinations_per_campaign": max(1, int(getattr(S, "messaging_mass_send_max_destinations_per_campaign", 100))),
        "max_concurrent_workers": max(1, int(getattr(S, "messaging_mass_send_max_concurrent_workers", 8))),
    }


def _trim_mass_message_rate_window(bucket: deque[int], *, now_ts: int, window_seconds: int) -> None:
    threshold = now_ts - window_seconds
    while bucket and bucket[0] <= threshold:
        bucket.popleft()


def _enforce_mass_message_create_limits(*, user_id: str, mode: str, destination_count: int) -> None:
    limits = _mass_message_limits_config()
    if destination_count > limits["max_destinations_per_campaign"]:
        record_mass_message_limit_event(scope="campaign", limit_name="destinations_per_campaign", outcome="blocked")
        raise HTTPException(
            status_code=429,
            detail={
                "code": "mass_send_destinations_limit_exceeded",
                "message": f"Campaign exceeds destination cap ({limits['max_destinations_per_campaign']}).",
                "limit": limits["max_destinations_per_campaign"],
                "provided": destination_count,
            },
        )
    record_mass_message_limit_event(scope="campaign", limit_name="destinations_per_campaign", outcome="allowed")

    tenant_id = _mass_message_tenant_for_user(user_id)
    now = now_ts()
    window_seconds = 3600
    with _MASS_MESSAGE_RATE_LOCK:
        user_bucket = _MASS_MESSAGE_USER_CREATE_TS[user_id]
        tenant_bucket = _MASS_MESSAGE_TENANT_CREATE_TS[tenant_id]
        _trim_mass_message_rate_window(user_bucket, now_ts=now, window_seconds=window_seconds)
        _trim_mass_message_rate_window(tenant_bucket, now_ts=now, window_seconds=window_seconds)

        user_limit = limits["campaigns_per_user_per_hour"]
        if user_limit > 0 and len(user_bucket) >= user_limit:
            record_mass_message_limit_event(scope="user", limit_name="campaigns_per_hour", outcome="blocked")
            raise HTTPException(
                status_code=429,
                detail={
                    "code": "mass_send_user_rate_limited",
                    "message": "Campaign creation rate limit exceeded for this user.",
                    "limit": user_limit,
                    "window_seconds": window_seconds,
                },
            )
        record_mass_message_limit_event(scope="user", limit_name="campaigns_per_hour", outcome="allowed")

        tenant_limit = limits["campaigns_per_tenant_per_hour"]
        if tenant_limit > 0 and len(tenant_bucket) >= tenant_limit:
            record_mass_message_limit_event(scope="tenant", limit_name="campaigns_per_hour", outcome="blocked")
            raise HTTPException(
                status_code=429,
                detail={
                    "code": "mass_send_tenant_rate_limited",
                    "message": "Campaign creation rate limit exceeded for this tenant.",
                    "limit": tenant_limit,
                    "window_seconds": window_seconds,
                },
            )
        record_mass_message_limit_event(scope="tenant", limit_name="campaigns_per_hour", outcome="allowed")

        if mode == "immediate":
            worker_limit = limits["max_concurrent_workers"]
            if _MASS_MESSAGE_ACTIVE_WORKERS >= worker_limit:
                record_mass_message_limit_event(scope="worker", limit_name="concurrent_workers", outcome="blocked")
                raise HTTPException(
                    status_code=429,
                    detail={
                        "code": "mass_send_worker_capacity_exceeded",
                        "message": "Too many concurrent mass messaging workers.",
                        "limit": worker_limit,
                    },
                )
            record_mass_message_limit_event(scope="worker", limit_name="concurrent_workers", outcome="allowed")


def _record_mass_message_campaign_created(*, user_id: str) -> None:
    tenant_id = _mass_message_tenant_for_user(user_id)
    now = now_ts()
    with _MASS_MESSAGE_RATE_LOCK:
        _MASS_MESSAGE_USER_CREATE_TS[user_id].append(now)
        _MASS_MESSAGE_TENANT_CREATE_TS[tenant_id].append(now)


def _reserve_mass_message_worker_slot() -> bool:
    limits = _mass_message_limits_config()
    with _MASS_MESSAGE_RATE_LOCK:
        global _MASS_MESSAGE_ACTIVE_WORKERS
        if _MASS_MESSAGE_ACTIVE_WORKERS >= limits["max_concurrent_workers"]:
            record_mass_message_limit_event(scope="worker", limit_name="concurrent_workers", outcome="blocked")
            return False
        _MASS_MESSAGE_ACTIVE_WORKERS += 1
        record_mass_message_limit_event(scope="worker", limit_name="concurrent_workers", outcome="allowed")
        return True


def _release_mass_message_worker_slot() -> None:
    with _MASS_MESSAGE_RATE_LOCK:
        global _MASS_MESSAGE_ACTIVE_WORKERS
        _MASS_MESSAGE_ACTIVE_WORKERS = max(0, _MASS_MESSAGE_ACTIVE_WORKERS - 1)


def _run_mass_message_worker_with_slot(*, campaign_id: str) -> None:
    try:
        run_mass_message_immediate_worker(campaign_id=campaign_id)
    finally:
        _release_mass_message_worker_slot()


def _kickoff_mass_message_dispatch(*, campaign_id: str, mode: str) -> None:
    if not _messaging_mass_send_enabled():
        logger.warning(
            "messaging.mass_message_dispatch_skipped_feature_flag_disabled",
            extra={"campaign_id": campaign_id, "mode": mode},
        )
        return
    if mode == "immediate":
        if not _reserve_mass_message_worker_slot():
            raise HTTPException(
                status_code=429,
                detail={
                    "code": "mass_send_worker_capacity_exceeded",
                    "message": "Too many concurrent mass messaging workers.",
                    "limit": _mass_message_limits_config()["max_concurrent_workers"],
                },
            )
        threading.Thread(
            target=_run_mass_message_worker_with_slot,
            kwargs={"campaign_id": campaign_id},
            daemon=True,
            name=f"mass-message-worker-{campaign_id}",
        ).start()
    logger.info(
        "messaging.mass_message_dispatch_requested",
        extra={"campaign_id": campaign_id, "mode": mode},
    )


def _cancel_pending_mass_destinations(*, campaign_id: str) -> int:
    cancelled = 0
    pagination_key: dict[str, Any] | None = None
    while True:
        rows, pagination_key = list_mass_destinations_page(
            campaign_id=campaign_id,
            limit=500,
            start_key=pagination_key,
        )
        for row in rows:
            if str(row.get("state") or "") != "pending":
                continue
            conversation_id = str(row.get("conversation_id") or "")
            if not conversation_id:
                continue
            try:
                upsert_mass_destination(
                    campaign_id=campaign_id,
                    conversation_id=conversation_id,
                    state="cancelled",
                    message_id=None,
                    error_code=None,
                )
                apply_destination_counter_delta(
                    campaign_id=campaign_id,
                    to_state="cancelled",
                    from_state="pending",
                )
                cancelled += 1
            except ValueError:
                continue
        if not pagination_key:
            break
    return cancelled


def _is_mass_message_destination_supported(conversation: dict) -> bool:
    return str(conversation.get("type") or "").lower() in {"dm", "group"}


def _classify_mass_destination_error(exc: Exception) -> str:
    if isinstance(exc, HTTPException):
        if exc.status_code in {401, 403}:
            return DESTINATION_ERROR_AUTHORIZATION
        if exc.status_code == 404:
            return DESTINATION_ERROR_CONVERSATION_MISSING
        if exc.status_code in {400, 409, 422}:
            return DESTINATION_ERROR_POLICY_BLOCKED
    if isinstance(exc, (TimeoutError, ConnectionError)):
        return DESTINATION_ERROR_TRANSIENT_INFRA
    if isinstance(exc, ValueError) and str(exc) == "campaign_payload_invalid":
        return DESTINATION_ERROR_UNKNOWN
    return DESTINATION_ERROR_TRANSIENT_INFRA


def _is_retryable_mass_destination_error(error_code: str) -> bool:
    return error_code in {DESTINATION_ERROR_TRANSIENT_INFRA}


def _mass_destination_retry_limits() -> tuple[int, float, float]:
    max_attempts = max(1, min(int(os.getenv("MASS_MESSAGE_MAX_RETRY_ATTEMPTS", "3")), 10))
    base_backoff = max(0.01, float(os.getenv("MASS_MESSAGE_RETRY_BASE_SECONDS", "0.25")))
    max_backoff = max(base_backoff, float(os.getenv("MASS_MESSAGE_RETRY_MAX_SECONDS", "4.0")))
    return max_attempts, base_backoff, max_backoff


def _retry_backoff_seconds(*, attempt_number: int, base_backoff: float, max_backoff: float) -> float:
    return min(max_backoff, base_backoff * (2 ** max(0, attempt_number - 1)))


def _process_mass_message_destination(*, campaign: dict[str, Any], destination: dict[str, Any]) -> dict[str, Any]:
    campaign_id = str(campaign.get("campaign_id") or "")
    conversation_id = str(destination.get("conversation_id") or "")
    sender_id = str(campaign.get("sender_id") or "")
    message_text = str(campaign.get("content_text") or "")
    message_kind = str(campaign.get("content_kind") or "text")
    if message_kind != "text" or not message_text:
        raise ValueError("campaign_payload_invalid")

    convo = _get_conversation_or_404(conversation_id)
    _enforce_helpdesk_send_constraints(conversation_id=conversation_id, convo=convo, user_id=sender_id, req=None)
    require_participant_active(sender_id, conversation_id)
    participants = tbl_parts.query(IndexName="GSI1", KeyConditionExpression=Key("GSI1PK").eq(conversation_id)).get("Items", [])

    ts = now_ts()
    mid = "m_" + new_id()
    item: Dict[str, Any] = {
        "conversation_id": conversation_id,
        "message_id": mid,
        "sender_id": sender_id,
        "created_at": ts,
        "kind": "text",
        "text": message_text,
        "is_encrypted": False,
        "reactions": {},
        "mass_campaign_id": campaign_id,
    }
    ttl = _message_retention_ttl(convo, ts)
    if ttl:
        item["ttl"] = ttl
    tbl_msgs.put_item(Item=item)
    _sync_gallery_index_message(item)

    _send_mass_message_destination(
        conversation_id=conversation_id,
        sender_id=sender_id,
        message_id=mid,
        created_at=ts,
        message_item=item,
        participants=participants,
        preview_text=message_text[:140],
    )
    _emit_message_lifecycle_archive_event_or_503(
        mutation="send",
        event_ts=ts,
        conversation_id=conversation_id,
        message_id=mid,
        actor_user_id=sender_id,
        event_type="message.sent",
        payload={
            "mutation": "send",
            "scheduled": False,
            "campaign_id": campaign_id,
            "message": _serialize_message_event_payload(item, sender_id),
        },
    )
    _meter_message_send(user_id=sender_id, conversation_id=conversation_id, message_id=mid)
    return {"state": "sent", "message_id": mid, "error_code": None}


def _process_mass_message_destination_with_retry(
    *,
    campaign: dict[str, Any],
    destination: dict[str, Any],
    max_attempts: int,
    base_backoff: float,
    max_backoff: float,
    mode: str = "immediate",
) -> dict[str, Any]:
    last_error_code = DESTINATION_ERROR_TRANSIENT_INFRA
    campaign_id = str(campaign.get("campaign_id") or "")
    for attempt in range(1, max_attempts + 1):
        if not _messaging_mass_send_enabled():
            return {
                "state": "failed",
                "message_id": None,
                "error_code": DESTINATION_ERROR_POLICY_BLOCKED,
                "attempts": attempt,
            }
        latest_campaign = get_mass_campaign_record(campaign_id) if campaign_id else None
        if latest_campaign and str(latest_campaign.get("status") or "") == "cancelled":
            return {
                "state": "cancelled",
                "message_id": None,
                "error_code": None,
                "attempts": attempt,
            }
        try:
            result = _process_mass_message_destination(campaign=campaign, destination=destination)
            result["attempts"] = attempt
            return result
        except Exception as exc:
            last_error_code = _classify_mass_destination_error(exc)
            if attempt >= max_attempts or not _is_retryable_mass_destination_error(last_error_code):
                return {"state": "failed", "message_id": None, "error_code": last_error_code, "attempts": attempt}
            record_mass_message_destination_retry(mode=mode, error_code=last_error_code)
            time.sleep(_retry_backoff_seconds(attempt_number=attempt, base_backoff=base_backoff, max_backoff=max_backoff))

    return {"state": "failed", "message_id": None, "error_code": last_error_code, "attempts": max_attempts}


def run_mass_message_immediate_worker(*, campaign_id: str, max_concurrency: int = 8) -> dict[str, int]:
    started = time.perf_counter()
    if not _messaging_mass_send_enabled():
        record_mass_message_worker_latency(mode="immediate", outcome="disabled", elapsed_seconds=time.perf_counter() - started)
        return {"processed": 0, "sent": 0, "failed": 0}
    campaign = get_mass_campaign_record(campaign_id)
    if not campaign:
        raise ValueError("campaign_not_found")
    mode = str(campaign.get("mode") or "immediate")
    sender_id = str(campaign.get("sender_id") or "")

    sent_count = 0
    failed_count = 0
    cancelled_count = 0
    max_attempts, base_backoff, max_backoff = _mass_destination_retry_limits()
    processed_count = 0
    pagination_key: dict[str, Any] | None = None
    worker_started = False
    with ThreadPoolExecutor(max_workers=max(1, min(int(max_concurrency), 32))) as executor:
        while True:
            latest_campaign = get_mass_campaign_record(campaign_id) or {}
            if str(latest_campaign.get("status") or "") == "cancelled":
                break
            page_rows, pagination_key = list_mass_destinations_page(
                campaign_id=campaign_id,
                limit=500,
                start_key=pagination_key,
            )
            pending = [row for row in page_rows if row.get("state") == "pending"]
            if pending and not worker_started:
                worker_started = True
                try:
                    update_mass_campaign_status(
                        campaign_id=campaign_id,
                        next_status="processing",
                        expected_status=str(campaign.get("status") or "pending"),
                    )
                except Exception:
                    pass
            if not pending:
                if not pagination_key:
                    break
                continue

            processed_count += len(pending)
            future_to_destination = {
                executor.submit(
                    _process_mass_message_destination_with_retry,
                    campaign=campaign,
                    destination=destination,
                    max_attempts=max_attempts,
                    base_backoff=base_backoff,
                    max_backoff=max_backoff,
                    mode=mode,
                ): destination
                for destination in pending
            }
            for future in as_completed(future_to_destination):
                destination = future_to_destination[future]
                conversation_id = str(destination.get("conversation_id") or "")
                from_state = str(destination.get("state") or "pending")
                try:
                    result = future.result()
                    if result.get("state") == "sent":
                        sent_count += 1
                        upsert_mass_destination(
                            campaign_id=campaign_id,
                            conversation_id=conversation_id,
                            state="sent",
                            message_id=result.get("message_id"),
                            error_code=None,
                        )
                        apply_destination_counter_delta(campaign_id=campaign_id, to_state="sent", from_state=from_state)
                        record_mass_message_destination_outcome(mode=mode, outcome="sent", error_code="none")
                    elif result.get("state") == "cancelled":
                        cancelled_count += 1
                        upsert_mass_destination(
                            campaign_id=campaign_id,
                            conversation_id=conversation_id,
                            state="cancelled",
                            message_id=None,
                            error_code=None,
                        )
                        apply_destination_counter_delta(campaign_id=campaign_id, to_state="cancelled", from_state=from_state)
                        record_mass_message_destination_outcome(mode=mode, outcome="cancelled", error_code="none")
                    else:
                        failed_count += 1
                        upsert_mass_destination(
                            campaign_id=campaign_id,
                            conversation_id=conversation_id,
                            state="failed",
                            message_id=None,
                            error_code=str(result.get("error_code") or DESTINATION_ERROR_UNKNOWN),
                        )
                        apply_destination_counter_delta(campaign_id=campaign_id, to_state="failed", from_state=from_state)
                        record_mass_message_destination_outcome(
                            mode=mode,
                            outcome="failed",
                            error_code=str(result.get("error_code") or DESTINATION_ERROR_UNKNOWN),
                        )
                except Exception as exc:
                    failed_count += 1
                    classified_error = _classify_mass_destination_error(exc)
                    upsert_mass_destination(
                        campaign_id=campaign_id,
                        conversation_id=conversation_id,
                        state="failed",
                        message_id=None,
                        error_code=classified_error,
                    )
                    apply_destination_counter_delta(campaign_id=campaign_id, to_state="failed", from_state=from_state)
                    record_mass_message_destination_outcome(mode=mode, outcome="failed", error_code=classified_error)
            if not pagination_key:
                break

    if processed_count == 0:
        record_mass_message_worker_latency(mode=mode, outcome="noop", elapsed_seconds=time.perf_counter() - started)
        return {"processed": 0, "sent": 0, "failed": 0}

    if cancelled_count > 0 and sent_count == 0 and failed_count == 0:
        worker_outcome = "cancelled"
    else:
        worker_outcome = "success" if failed_count == 0 else "partial_failure"
    try:
        latest = get_mass_campaign_record(campaign_id) or {}
        current_status = str(latest.get("status") or "processing")
        if current_status in {"pending", "processing"}:
            update_mass_campaign_status(campaign_id=campaign_id, next_status="completed", expected_status=current_status)
            record_mass_message_campaign_event(event="complete", mode=mode, outcome=worker_outcome)
    except Exception:
        worker_outcome = "completion_update_error"
    audit_event(
        "messaging_mass_campaign_completed",
        sender_id,
        None,
        outcome=worker_outcome,
        campaign_id=campaign_id,
        mode=mode,
        processed=processed_count,
        sent=sent_count,
        failed=failed_count,
        cancelled=cancelled_count,
    )
    record_mass_message_worker_latency(mode=mode, outcome=worker_outcome, elapsed_seconds=time.perf_counter() - started)
    return {"processed": processed_count, "sent": sent_count, "failed": failed_count}


def dispatch_due_scheduled_mass_campaigns(*, now_ts_value: int | None = None, limit: int = 100) -> dict[str, int]:
    """Scan due scheduled campaigns and enqueue immediate worker processing."""
    if not _messaging_mass_send_enabled():
        return {"scanned": 0, "claimed": 0, "skipped": 0}
    due = list_due_scheduled_mass_campaigns(now_ts=now_ts_value, limit=limit)
    scanned = len(due)
    claimed = 0
    skipped = 0

    for campaign in due:
        campaign_id = str(campaign.get("campaign_id") or "")
        if not campaign_id:
            skipped += 1
            continue
        try:
            update_mass_campaign_status(
                campaign_id=campaign_id,
                next_status="processing",
                expected_status="scheduled",
            )
        except Exception:
            skipped += 1
            continue

        if not _reserve_mass_message_worker_slot():
            record_mass_message_limit_event(scope="worker", limit_name="concurrent_workers", outcome="rollback")
            try:
                update_mass_campaign_status(
                    campaign_id=campaign_id,
                    next_status="scheduled",
                    expected_status="processing",
                )
            except Exception:
                # Best-effort rollback: if this fails, later reconciliation/ops checks
                # will flag the stuck processing campaign.
                pass
            skipped += 1
            continue
        worker_thread = threading.Thread(
            target=_run_mass_message_worker_with_slot,
            kwargs={"campaign_id": campaign_id},
            daemon=True,
            name=f"mass-message-scheduled-worker-{campaign_id}",
        )
        try:
            worker_thread.start()
            claimed += 1
        except Exception:
            _release_mass_message_worker_slot()
            record_mass_message_limit_event(scope="worker", limit_name="concurrent_workers", outcome="start_failure")
            try:
                update_mass_campaign_status(
                    campaign_id=campaign_id,
                    next_status="scheduled",
                    expected_status="processing",
                )
            except Exception:
                pass
            skipped += 1

    return {"scanned": scanned, "claimed": claimed, "skipped": skipped}


@router.post("/mass-messages", response_model=MassMessageCreateCampaignResponse, status_code=201)
def create_mass_message_campaign(
    req: MassMessageCreateCampaignRequest,
    user_id: str = Depends(get_authenticated_user_sub),
) -> MassMessageCreateCampaignResponse:
    if not _messaging_mass_send_enabled():
        raise HTTPException(
            status_code=403,
            detail={
                "code": "mass_send_disabled",
                "message": "Mass messaging create is disabled",
            },
        )
    _enforce_mass_message_create_limits(
        user_id=user_id,
        mode=req.mode,
        destination_count=len(req.conversation_ids),
    )
    accepted: list[str] = []
    rejected: list[MassMessageRejectedDestination] = []

    for conversation_id in req.conversation_ids:
        convo = tbl_convos.get_item(Key={"conversation_id": conversation_id}).get("Item")
        if not convo:
            rejected.append(
                MassMessageRejectedDestination(
                    conversation_id=conversation_id,
                    reason="conversation_not_found",
                )
            )
            continue
        if not _is_mass_message_destination_supported(convo):
            rejected.append(
                MassMessageRejectedDestination(
                    conversation_id=conversation_id,
                    reason="unsupported_conversation_type",
                )
            )
            continue
        participant = get_participant_any(user_id, conversation_id)
        if not participant or participant.get("status") != "active":
            rejected.append(
                MassMessageRejectedDestination(
                    conversation_id=conversation_id,
                    reason="not_active_participant",
                )
            )
            continue
        accepted.append(conversation_id)

    if not accepted:
        raise HTTPException(400, "No eligible destinations")

    payload_hash = _mass_message_payload_hash(kind=req.content.kind, text=req.content.text)
    campaign, created_new = create_or_get_mass_campaign_record(
        sender_id=user_id,
        mode=req.mode,
        payload_hash=payload_hash,
        send_at=req.send_at,
        idempotency_key=req.idempotency_key,
        content_kind=req.content.kind,
        content_text=req.content.text,
    )
    campaign_id = str(campaign["campaign_id"])

    if created_new:
        _record_mass_message_campaign_created(user_id=user_id)
        record_mass_message_campaign_event(event="create", mode=req.mode, outcome="success")
        for conversation_id in accepted:
            upsert_mass_destination(
                campaign_id=campaign_id,
                conversation_id=conversation_id,
                state="pending",
            )
            apply_destination_counter_delta(
                campaign_id=campaign_id,
                to_state="pending",
                from_state=None,
            )
        set_campaign_submission_result(
            campaign_id=campaign_id,
            accepted_conversation_ids=accepted,
            rejected=[item.model_dump() for item in rejected],
        )
    else:
        record_mass_message_campaign_event(event="create", mode=req.mode, outcome="idempotent_replay")
    audit_event(
        "messaging_mass_campaign_submitted",
        user_id,
        None,
        outcome="success",
        campaign_id=campaign_id,
        mode=req.mode,
        accepted_count=len(accepted),
        rejected_count=len(rejected),
        created_new=created_new,
    )

    latest_campaign = get_mass_campaign_record(campaign_id) or campaign
    _kickoff_mass_message_dispatch(campaign_id=campaign_id, mode=req.mode)
    accepted_for_response = list(latest_campaign.get("accepted_conversation_ids") or accepted)
    rejected_for_response = latest_campaign.get("rejected_destinations") or [item.model_dump() for item in rejected]
    rejected_models = [MassMessageRejectedDestination(**item) for item in rejected_for_response]

    return MassMessageCreateCampaignResponse(
        campaign_id=campaign_id,
        mode=str(latest_campaign.get("mode", req.mode)),
        status=str(latest_campaign.get("status", campaign.get("status", "pending"))),
        send_at=latest_campaign.get("send_at"),
        accepted_count=len(accepted_for_response),
        accepted_conversation_ids=accepted_for_response,
        rejected=rejected_models,
        counters={
            "total": int(latest_campaign.get("total", 0) or 0),
            "queued": int(latest_campaign.get("queued", 0) or 0),
            "sent": int(latest_campaign.get("sent", 0) or 0),
            "failed": int(latest_campaign.get("failed", 0) or 0),
            "cancelled": int(latest_campaign.get("cancelled", 0) or 0),
        },
        created_at=int(latest_campaign.get("created_at", campaign.get("created_at", now_ts()))),
        updated_at=int(latest_campaign.get("updated_at", campaign.get("updated_at", now_ts()))),
    )


@router.get("/mass-messages", response_model=MassMessageCampaignListResponse)
def list_mass_message_campaigns(
    limit: int = Query(25, ge=1, le=200),
    cursor: str | None = Query(default=None, max_length=2048),
    status: str | None = Query(default=None),
    mode: str | None = Query(default=None),
    user_id: str = Depends(get_authenticated_user_sub),
) -> MassMessageCampaignListResponse:
    if cursor is not None and not isinstance(cursor, str):
        cursor = None
    if status is not None and not isinstance(status, str):
        status = None
    if mode is not None and not isinstance(mode, str):
        mode = None

    decoded_cursor = decode_cursor(cursor)
    if cursor and decoded_cursor is None:
        raise HTTPException(status_code=400, detail="Invalid cursor")
    if decoded_cursor and str(decoded_cursor.get("sender_id") or "") != user_id:
        raise HTTPException(status_code=400, detail="Invalid cursor")
    if decoded_cursor:
        try:
            created_at_cursor = int(decoded_cursor.get("created_at", 0) or 0)
        except (TypeError, ValueError):
            raise HTTPException(status_code=400, detail="Invalid cursor")
        if not decoded_cursor.get("campaign_id") or created_at_cursor <= 0:
            raise HTTPException(status_code=400, detail="Invalid cursor")

    normalized_status = str(status or "").strip().lower() or None
    allowed_statuses = {"pending", "scheduled", "processing", "completed", "failed", "cancelled"}
    if normalized_status and normalized_status not in allowed_statuses:
        raise HTTPException(status_code=400, detail="Invalid status filter")

    normalized_mode = str(mode or "").strip().lower() or None
    if normalized_mode and normalized_mode not in {"immediate", "scheduled"}:
        raise HTTPException(status_code=400, detail="Invalid mode filter")

    def _sanitize_cursor_key(key: dict[str, Any] | None) -> dict[str, Any] | None:
        """Coerce Decimal values from DynamoDB LastEvaluatedKey to native Python types for JSON serialization."""
        if not key:
            return key
        from decimal import Decimal as _Dec
        out: dict[str, Any] = {}
        for k, v in key.items():
            if isinstance(v, _Dec):
                out[k] = int(v) if v == int(v) else float(v)
            else:
                out[k] = v
        return out

    filtered: list[MassMessageCampaignSummary] = []
    scan_key = decoded_cursor
    resume_key: dict[str, Any] | None = None
    has_more = False
    seen_cursor_tokens: set[str] = set()
    seen_campaign_ids: set[str] = set()
    while len(filtered) < limit:
        if scan_key is not None:
            token = encode_cursor(scan_key)
            if token in seen_cursor_tokens:
                break
            if token is not None:
                seen_cursor_tokens.add(token)
        campaigns, next_key = list_campaigns_for_sender(
            sender_id=user_id,
            limit=min(200, max(limit, 25)),
            start_key=scan_key,
        )
        for idx, campaign in enumerate(campaigns):
            campaign_status = str(campaign.get("status") or "pending")
            campaign_mode = str(campaign.get("mode") or "immediate")
            campaign_id = str(campaign.get("campaign_id") or "")
            if not campaign_id or campaign_id in seen_campaign_ids:
                continue
            if normalized_status and campaign_status != normalized_status:
                continue
            if normalized_mode and campaign_mode != normalized_mode:
                continue
            filtered.append(
                MassMessageCampaignSummary(
                    campaign_id=campaign_id,
                    mode=campaign_mode,  # type: ignore[arg-type]
                    status=campaign_status,  # type: ignore[arg-type]
                    send_at=campaign.get("send_at"),
                    counters={
                        "total": int(campaign.get("total", 0) or 0),
                        "queued": int(campaign.get("queued", 0) or 0),
                        "sent": int(campaign.get("sent", 0) or 0),
                        "failed": int(campaign.get("failed", 0) or 0),
                        "cancelled": int(campaign.get("cancelled", 0) or 0),
                    },
                    created_at=int(campaign.get("created_at", now_ts())),
                    updated_at=int(campaign.get("updated_at", now_ts())),
                )
            )
            if len(filtered) >= limit:
                has_more = idx < len(campaigns) - 1 or bool(next_key)
                resume_key = {
                    "campaign_id": campaign_id,
                    "sender_id": str(campaign.get("sender_id") or user_id),
                    "created_at": int(campaign.get("created_at", 0) or 0),
                }
                break
            seen_campaign_ids.add(campaign_id)
        if len(filtered) >= limit:
            break
        if not next_key:
            has_more = False
            resume_key = None
            break
        if next_key == scan_key:
            has_more = True
            resume_key = _sanitize_cursor_key(next_key)
            break
        scan_key = _sanitize_cursor_key(next_key)

    next_cursor = encode_cursor(resume_key if has_more else None)
    return MassMessageCampaignListResponse(items=filtered, next_cursor=next_cursor)


@router.get("/mass-messages/{campaign_id}", response_model=MassMessageCampaignDetailResponse)
def get_mass_message_campaign(
    campaign_id: str,
    limit: int = Query(100, ge=1, le=500),
    cursor: str | None = Query(default=None, max_length=2048),
    user_id: str = Depends(get_authenticated_user_sub),
) -> MassMessageCampaignDetailResponse:
    if cursor is not None and not isinstance(cursor, str):
        cursor = None

    campaign = get_mass_campaign_record(campaign_id)
    if not campaign:
        raise HTTPException(404, "Campaign not found")

    if str(campaign.get("sender_id") or "") != user_id:
        # Return 404 to avoid leaking campaign existence/details.
        raise HTTPException(404, "Campaign not found")

    decoded_cursor = decode_cursor(cursor)
    if cursor and decoded_cursor is None:
        raise HTTPException(status_code=400, detail="Invalid cursor")
    if decoded_cursor and (
        str(decoded_cursor.get("campaign_id") or "") != campaign_id
        or not decoded_cursor.get("conversation_id")
    ):
        raise HTTPException(status_code=400, detail="Invalid cursor")

    destinations, next_key = list_mass_destinations_page(
        campaign_id=campaign_id,
        limit=limit,
        start_key=decoded_cursor,
    )
    return MassMessageCampaignDetailResponse(
        campaign_id=campaign_id,
        sender_id=str(campaign.get("sender_id")),
        mode=str(campaign.get("mode", "immediate")),
        status=str(campaign.get("status", "pending")),
        send_at=campaign.get("send_at"),
        counters={
            "total": int(campaign.get("total", 0) or 0),
            "queued": int(campaign.get("queued", 0) or 0),
            "sent": int(campaign.get("sent", 0) or 0),
            "failed": int(campaign.get("failed", 0) or 0),
            "cancelled": int(campaign.get("cancelled", 0) or 0),
        },
        destinations=destinations,
        next_cursor=encode_cursor(next_key),
        created_at=int(campaign.get("created_at", now_ts())),
        updated_at=int(campaign.get("updated_at", now_ts())),
    )


@router.post("/mass-messages/{campaign_id}/cancel", response_model=MassMessageCancelCampaignResponse)
def cancel_mass_message_campaign(
    campaign_id: str,
    user_id: str = Depends(get_authenticated_user_sub),
) -> MassMessageCancelCampaignResponse:
    campaign = get_mass_campaign_record(campaign_id)
    if not campaign:
        raise HTTPException(404, "Campaign not found")
    if str(campaign.get("sender_id") or "") != user_id:
        raise HTTPException(404, "Campaign not found")

    current_status = str(campaign.get("status") or "pending")
    cancelled_destinations = 0
    if current_status in {"completed", "failed", "cancelled"}:
        record_mass_message_campaign_event(
            event="cancel",
            mode=str(campaign.get("mode") or "immediate"),
            outcome="noop_terminal",
        )
    else:
        try:
            updated = update_mass_campaign_status(
                campaign_id=campaign_id,
                next_status="cancelled",
                expected_status=current_status,
            )
            campaign = updated or campaign
            cancelled_destinations = _cancel_pending_mass_destinations(campaign_id=campaign_id)
            campaign = get_mass_campaign_record(campaign_id) or campaign
            record_mass_message_campaign_event(event="cancel", mode=str(campaign.get("mode") or "immediate"), outcome="success")
            audit_event(
                "messaging_mass_campaign_cancelled",
                user_id,
                None,
                outcome="success",
                campaign_id=campaign_id,
                cancelled_destinations=cancelled_destinations,
            )
        except ValueError:
            record_mass_message_campaign_event(
                event="cancel",
                mode=str(campaign.get("mode") or "immediate"),
                outcome="race",
            )
            campaign = get_mass_campaign_record(campaign_id) or campaign

    return MassMessageCancelCampaignResponse(
        campaign_id=campaign_id,
        status=str(campaign.get("status") or current_status),
        cancelled_destinations=cancelled_destinations,
        counters={
            "total": int(campaign.get("total", 0) or 0),
            "queued": int(campaign.get("queued", 0) or 0),
            "sent": int(campaign.get("sent", 0) or 0),
            "failed": int(campaign.get("failed", 0) or 0),
            "cancelled": int(campaign.get("cancelled", 0) or 0),
        },
        updated_at=int(campaign.get("updated_at", now_ts())),
    )


async def require_legal_hold_operator(user: AuthenticatedUser = Depends(get_authenticated_user), request: Request = None) -> AuthenticatedUser:
    return await require_legal_hold_admin(request=request, user=user)


async def require_compliance_query_operator(user: AuthenticatedUser = Depends(get_authenticated_user), request: Request = None) -> AuthenticatedUser:
    return await require_compliance_query_admin(request=request, user=user)


async def require_compliance_export_operator(user: AuthenticatedUser = Depends(get_authenticated_user), request: Request = None) -> AuthenticatedUser:
    return await require_compliance_export_admin(request=request, user=user)


def _log_message_control_action(*, actor_user_id: str, conversation_id: str, message_id: str, action: str, result: str, detail: str = "") -> None:
    logger.info(
        "messaging.message_control",
        extra={
            "actor_user_id": actor_user_id,
            "conversation_id": conversation_id,
            "message_id": message_id,
            "action": action,
            "result": result,
            "detail": detail,
        },
    )

def _emit_archive_event_or_503(*, event_id: str, event_ts: int, conversation_id: str, message_id: str, actor_user_id: str, event_type: str, payload: dict) -> None:
    try:
        emit_messaging_archive_event(
            event_id=event_id[:128],
            event_ts=event_ts,
            tenant_id="default",
            conversation_id=conversation_id,
            message_id=message_id,
            actor_user_id=actor_user_id,
            effective_user_id=actor_user_id,
            event_type=event_type,
            payload=payload,
        )
    except MessagingArchiveWriteError as exc:
        raise HTTPException(status_code=503, detail="Compliance archive write failed") from exc


def _emit_message_lifecycle_archive_event_or_503(
    *,
    mutation: str,
    event_ts: int,
    conversation_id: str,
    message_id: str,
    actor_user_id: str,
    event_type: str,
    payload: dict,
) -> None:
    _emit_archive_event_or_503(
        event_id=f"msg_{mutation}_{conversation_id}_{message_id}_{event_ts}_{actor_user_id}",
        event_ts=event_ts,
        conversation_id=conversation_id,
        message_id=message_id,
        actor_user_id=actor_user_id,
        event_type=event_type,
        payload=payload,
    )



def _emit_conversation_membership_archive_event_or_503(
    *,
    event_ts: int,
    conversation_id: str,
    subject_user_id: str,
    actor_user_id: str,
    event_type: str,
    payload: dict,
) -> None:
    _emit_archive_event_or_503(
        event_id=f"membership_{event_type}_{conversation_id}_{subject_user_id}_{event_ts}_{actor_user_id}",
        event_ts=event_ts,
        conversation_id=conversation_id,
        message_id=f"membership_{subject_user_id}",
        actor_user_id=actor_user_id,
        event_type=event_type,
        payload=payload,
    )



def _emit_report_archive_event_or_503(
    *,
    event_ts: int,
    conversation_id: str,
    message_id: str,
    actor_user_id: str,
    report_id: str,
    event_type: Literal["report.submitted", "report.status_changed"],
    payload: dict,
) -> None:
    _emit_archive_event_or_503(
        event_id=f"report_{event_type}_{conversation_id}_{message_id}_{report_id}_{event_ts}_{actor_user_id}",
        event_ts=event_ts,
        conversation_id=conversation_id,
        message_id=message_id,
        actor_user_id=actor_user_id,
        event_type=event_type,
        payload={"report_id": report_id, **payload},
    )

MESSAGE_TEXT_MAX_CHARS = 4000
ENCRYPTED_CIPHERTEXT_MAX_BYTES = 8192
ENCRYPTED_EDIT_ERROR_CODE = "encrypted_message_edit_unsupported"
NO_AGENTS_ONLINE_NOTICE_TEXT = "No helpdesk agents are online right now. Please try again later."
NO_AGENTS_NOTICE_THROTTLE_SEC = int(os.getenv("NO_AGENTS_NOTICE_THROTTLE_SEC", "600"))
HELPDESK_AUTO_CLAIM_ON_REPLY_ENABLED = os.getenv("HELPDESK_AUTO_CLAIM_ON_REPLY_ENABLED", "0").strip().lower() in {"1", "true", "yes", "on"}
MESSAGING_HIDDEN_TIMELINE_FILTER_ENABLED = bool(getattr(S, "messaging_hidden_timeline_filter_enabled", True))

HELPDESK_ROUTING_EVENT_SCHEMA_VERSION = 1
HELPDESK_ROUTING_LIFECYCLE_EVENT_TYPES = {
    "helpdesk.conversation.alerted",
    "helpdesk.conversation.assigned",
    "helpdesk.conversation.released",
    "helpdesk.conversation.no_agents_online",
}
CONSUMPTION_POLICY_NONE = "none"
CONSUMPTION_STATE_PENDING = "pending"
ONCE_MEDIA_GRANT_TTL_SEC = int(os.getenv("ONCE_MEDIA_GRANT_TTL_SEC", "120"))
ONCE_MEDIA_VIDEO_CONSUME_THRESHOLD_SEC = float(os.getenv("ONCE_MEDIA_VIDEO_CONSUME_THRESHOLD_SEC", "1.0"))
ONCE_MEDIA_AUDIO_CONSUME_THRESHOLD_SEC = float(os.getenv("ONCE_MEDIA_AUDIO_CONSUME_THRESHOLD_SEC", "1.0"))
ONCE_MEDIA_COHORT_HEADER = "x-once-media-cohort"


# -------------------------
# Auth (Bearer token)
# -------------------------
def get_current_user_id(authorization: Optional[str] = Header(default=None)) -> str:
    """
    Replace with real JWT verification.
    Dev behavior: Authorization: Bearer <user_id>
    """
    return extract_bearer_token(authorization)


def _enforce_messaging_internal_entitlement(*, user_id: str, action: str, request_id: Optional[str] = None) -> None:
    req_id = (request_id or "").strip() or f"messaging:{action}:{now_ts()}:{user_id}"
    enforce_internal_api_entitlement(
        user_id=user_id,
        namespace="messaging",
        action=action,
        request_id=req_id,
    )


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


def _ensure_user_indexed(user_id: str) -> None:
    """Lazily sync user into messaging search tables from the main profile store.

    Called on first messaging API access.  The tbl_users.get_item check is
    fast (single consistent read) so overhead on subsequent calls is minimal.
    """
    try:
        existing = tbl_users.get_item(Key={"user_id": user_id}).get("Item")
        if existing:
            return
        identity = get_profile_identity(user_id)
        display_name = (identity.get("display_name") or "").strip() or user_id
        email = (identity.get("email") or "").strip()
        ts = now_ts()
        tbl_users.put_item(Item={
            "user_id": user_id,
            "display_name": display_name,
            "email": email,
            "updated_at": ts,
        })
        tokens: set[str] = set(build_prefix_tokens(display_name))
        if email:
            tokens |= set(build_prefix_tokens(email))
        with tbl_search.batch_writer() as bw:
            for t in tokens:
                bw.put_item(Item={
                    "token": t,
                    "user_id": user_id,
                    "display_name": display_name,
                })
    except Exception:
        logger.exception("_ensure_user_indexed failed", extra={"user_id": user_id})


async def get_messaging_user_id(
    request: Request,
    authorization: Optional[str] = Header(default=None),
    x_session_id: Optional[str] = Header(default=None, alias="X-SESSION-ID"),
) -> str:
    principal = getattr(getattr(request, "state", None), "api_key_principal", None)
    if isinstance(principal, dict):
        uid = str(principal.get("user_sub") or "").strip()
        if uid:
            _ensure_user_indexed(uid)
            return uid

    cookies = getattr(request, "cookies", {}) or {}
    if x_session_id or cookies.get(S.ui_session_cookie_name):
        user_sub = await get_authenticated_user_sub(request)
        ctx = await require_ui_session(request, user_sub=user_sub, x_session_id=x_session_id)
        uid = ctx["user_sub"]
        _ensure_user_indexed(uid)
        return uid
    uid = get_current_user_id(authorization)
    _ensure_user_indexed(uid)
    return uid




def _csv_env_set(name: str, *, default: str = "") -> set[str]:
    raw = os.getenv(name, default)
    return {part.strip() for part in raw.split(",") if part.strip()}


def _resolve_user_tenant_id(user_id: str) -> str:
    uid = str(user_id or "").strip()
    if not uid:
        return ""
    try:
        user = tbl_users.get_item(Key={"user_id": uid}).get("Item") or {}
    except Exception:
        return ""
    return str(user.get("tenant_id") or user.get("tenant") or "").strip()


def _is_helpdesk_bridge_mode_enabled_for(*, user_id: str, group_id: str) -> bool:
    mode = os.getenv("HELPDESK_BRIDGE_MODE", "enabled").strip().lower()
    gid = str(group_id or "").strip()
    if mode in {"enabled", "on", "true", "1"}:
        return True
    if mode in {"disabled", "off", "false", "0", ""}:
        return False
    if mode in {"internal", "pilot_internal"}:
        internal_group_ids = _csv_env_set("HELPDESK_BRIDGE_INTERNAL_GROUP_IDS", default="helpdesk-internal")
        return gid in internal_group_ids
    if mode in {"selective", "tenant_group"}:
        enabled_group_ids = _csv_env_set("HELPDESK_BRIDGE_ENABLED_GROUP_IDS")
        if gid in enabled_group_ids:
            return True
        tenant_id = _resolve_user_tenant_id(user_id)
        enabled_tenant_ids = _csv_env_set("HELPDESK_BRIDGE_ENABLED_TENANT_IDS")
        return bool(tenant_id and tenant_id in enabled_tenant_ids)
    return False


def _is_thread_promotion_enabled_for(*, user_id: str) -> bool:
    mode = os.getenv("MESSAGING_THREAD_PROMOTION_MODE", "enabled").strip().lower()
    if mode in {"enabled", "on", "true", "1"}:
        return True
    if mode in {"disabled", "off", "false", "0", ""}:
        return False
    tenant_id = _resolve_user_tenant_id(user_id)
    if mode in {"internal", "pilot_internal"}:
        internal_tenant_ids = _csv_env_set("MESSAGING_THREAD_PROMOTION_INTERNAL_TENANT_IDS", default="internal")
        return bool(tenant_id and tenant_id in internal_tenant_ids)
    if mode in {"selective", "tenant"}:
        enabled_tenant_ids = _csv_env_set("MESSAGING_THREAD_PROMOTION_ENABLED_TENANT_IDS")
        return bool(tenant_id and tenant_id in enabled_tenant_ids)
    return False


def _is_messaging_drafts_enabled_for(*, user_id: str) -> bool:
    kill_switch = os.getenv("MESSAGING_DRAFTS_KILL_SWITCH", "0").strip().lower() in {"1", "true", "on", "yes"}
    if kill_switch:
        return False

    mode = os.getenv("MESSAGING_DRAFTS_MODE", "enabled").strip().lower()
    uid = str(user_id or "").strip()
    if mode in {"enabled", "on", "true", "1"}:
        return True
    if mode in {"disabled", "off", "false", "0", ""}:
        return False
    if mode in {"internal", "pilot_internal"}:
        tenant_id = _resolve_user_tenant_id(uid)
        internal_tenant_ids = _csv_env_set("MESSAGING_DRAFTS_INTERNAL_TENANT_IDS", default="internal")
        return bool(tenant_id and tenant_id in internal_tenant_ids)
    if mode in {"selective", "allowlist"}:
        enabled_user_ids = _csv_env_set("MESSAGING_DRAFTS_ENABLED_USER_IDS")
        if uid in enabled_user_ids:
            return True
        tenant_id = _resolve_user_tenant_id(uid)
        enabled_tenant_ids = _csv_env_set("MESSAGING_DRAFTS_ENABLED_TENANT_IDS")
        return bool(tenant_id and tenant_id in enabled_tenant_ids)
    return False


def _require_messaging_drafts_enabled(*, user_id: str) -> None:
    if not _is_messaging_drafts_enabled_for(user_id=user_id):
        raise HTTPException(status_code=403, detail="Messaging drafts are not enabled for this environment or tenant")



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


class FindOrCreateDmIn(BaseModel):
    user_id: str  # target user's sub


class ConversationOut(BaseModel):
    conversation_id: str
    type: str
    latest_pinned_message_id: Optional[str] = None
    latest_pinned_by_user_id: Optional[str] = None
    latest_pinned_at: Optional[int] = None
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
    routing_mode: Optional[str] = None
    routing_group_id: Optional[str] = None
    routing_state: Optional[str] = None
    active_agent_user_id: Optional[str] = None
    active_agent_claimed_at: Optional[int] = None
    assignment_version: Optional[int] = None
    participants: List["ParticipantOut"] = Field(default_factory=list)
    last_message: Optional["MessageOut"] = None


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
    # For text messages: ciphertext is stored here. For media messages: ciphertext lives in S3.
    ciphertext_b64: Optional[str] = Field(default=None, min_length=4, max_length=12000)

    @model_validator(mode="before")
    @classmethod
    def _coerce_decimals(cls, data: Any) -> Any:
        """DynamoDB returns numbers as Decimal; coerce to native int for Literal/int fields."""
        from decimal import Decimal as _Decimal
        if isinstance(data, dict):
            return {k: int(v) if isinstance(v, _Decimal) else v for k, v in data.items()}
        return data

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

        # ciphertext_b64 is optional for media messages (encrypted binary lives in S3)
        if self.ciphertext_b64 is not None:
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
    parent_message_id: Optional[str] = None
    thread_id: Optional[str] = None
    thread_root_message_id: Optional[str] = None
    preview: Optional[LinkPreviewIn] = None
    encryption: Optional[MessageEncryptionEnvelope] = None
    send_at: Optional[int] = None  # Unix timestamp; schedules delivery for the future
    tip_amount_cents: Optional[int] = Field(default=None, ge=1, le=100_000)  # e.g. 500 = $5.00
    tip_payment_method_id: Optional[str] = Field(default=None, max_length=200)
    expires_in_seconds: Optional[int] = Field(default=None, ge=10, le=604800)  # 10s–7d
    view_once: bool = False
    lock_price_cents: Optional[int] = Field(default=None, ge=1, le=100_000)
    lock_description: Optional[str] = Field(default=None, max_length=200)

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


class SendTipIn(BaseModel):
    amount_cents: int = Field(ge=1, le=100_000)
    currency: str = "USD"
    note: Optional[str] = Field(default=None, max_length=500)
    payment_method_id: Optional[str] = None


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
    filename: Optional[str] = Field(default=None, max_length=255)
    filesize: Optional[int] = None
    file_created_at: Optional[int] = None  # Unix seconds from file.lastModified
    caption: Optional[str] = Field(default=None, max_length=MESSAGE_TEXT_MAX_CHARS)
    kind: Literal["image", "file", "video"] = "image"
    reply_to_message_id: Optional[str] = None
    consumption_policy: Literal["none", "view_once"] = "none"
    expires_in_seconds: Optional[int] = Field(default=None, ge=10, le=604800)
    view_once: bool = False
    lock_price_cents: Optional[int] = Field(default=None, ge=1, le=100_000)
    lock_description: Optional[str] = Field(default=None, max_length=200)
    tip_amount_cents: Optional[int] = Field(default=None, ge=1, le=100_000)
    tip_payment_method_id: Optional[str] = Field(default=None, max_length=200)
    send_at: Optional[int] = None  # Unix timestamp; schedules delivery for the future
    encryption: Optional[MessageEncryptionEnvelope] = None
    # Blurred preview for locked images — small pixelated thumbnail shown before unlock
    preview_bucket: Optional[str] = Field(default=None, max_length=200)
    preview_key: Optional[str] = Field(default=None, max_length=500)


class PresignVoiceMessageRequest(BaseModel):
    content_type: str = Field(pattern=r"^audio/(webm|mp4|ogg|wav)")
    size_bytes: int = Field(ge=1, le=52_428_800)  # 50MB max
    duration_seconds: float = Field(ge=0.5, le=300)  # 0.5s to 5 minutes


class CreateVoiceMessageRequest(BaseModel):
    message_id: str = Field(pattern=r"^m_[a-f0-9]{32}$")
    s3_key: str
    content_type: str
    size_bytes: int = Field(ge=1)
    duration_seconds: float = Field(ge=0.5, le=300)
    waveform_data: List[float] = Field(min_length=10, max_length=200)
    consumption_policy: Literal["none", "listen_once"] = "none"
    reply_to_message_id: Optional[str] = None
    send_at: Optional[int] = None  # Unix timestamp; schedules delivery for the future


# ─── Voicemail models (CALL-014) ─────────────────────────────────────────────

class PresignVoicemailRequest(BaseModel):
    call_id: str = Field(min_length=1, max_length=128)
    content_type: str = Field(pattern=r"^(audio|video)/(webm|mp4|ogg|wav)")
    size_bytes: int = Field(ge=1, le=52_428_800)
    mode: Literal["audio", "video"] = "audio"


class CreateVoicemailRequest(BaseModel):
    message_id: str = Field(pattern=r"^m_[a-f0-9]{32}$")
    call_id: str = Field(min_length=1, max_length=128)
    s3_key: str = Field(min_length=1, max_length=500)
    content_type: str = Field(min_length=1, max_length=100)
    size_bytes: int = Field(ge=1, le=52_428_800)
    duration_seconds: float = Field(ge=0.5, le=60)
    waveform_data: List[float] = Field(min_length=10, max_length=200)
    mode: Literal["audio", "video"] = "audio"


class GalleryImageItemIn(BaseModel):
    bucket: str = Field(min_length=1, max_length=200)
    key: str = Field(min_length=1, max_length=500)
    content_type: str = Field(min_length=1, max_length=100)
    width: Optional[int] = None
    height: Optional[int] = None
    filename: Optional[str] = Field(default=None, max_length=255)
    filesize: Optional[int] = None
    preview_bucket: Optional[str] = Field(default=None, max_length=200)
    preview_key: Optional[str] = Field(default=None, max_length=500)


class CreateGalleryMessageIn(BaseModel):
    free_images: List[GalleryImageItemIn] = Field(default_factory=list)
    locked_images: List[GalleryImageItemIn] = Field(default_factory=list)
    text: Optional[str] = Field(default=None, max_length=2000)
    lock_price_cents: Optional[int] = Field(default=None, ge=1, le=100_000)
    lock_description: Optional[str] = Field(default=None, max_length=500)
    expires_in_seconds: Optional[int] = Field(default=None, ge=10, le=2592000)
    send_at: Optional[int] = None
    tip_amount_cents: Optional[int] = Field(default=None, ge=1, le=100_000)
    tip_payment_method_id: Optional[str] = Field(default=None, max_length=200)

    @model_validator(mode="after")
    def validate_gallery(self):
        if len(self.free_images) > 20:
            raise ValueError("free_images may not exceed 20 items")
        if len(self.locked_images) > 30:
            raise ValueError("locked_images may not exceed 30 items")
        if not self.free_images and not self.locked_images:
            raise ValueError("Gallery must have at least one item")
        if self.locked_images and not self.lock_price_cents:
            raise ValueError("lock_price_cents required when locked_images provided")
        for img in self.locked_images:
            if not img.preview_bucket or not img.preview_key:
                raise ValueError("Each locked image must have preview_bucket and preview_key")
        return self


class CreateFileShareMessageIn(BaseModel):
    file_path: str = Field(min_length=1, max_length=1000)
    permission: Literal["read", "write"] = "read"
    text: Optional[str] = Field(default=None, max_length=2000)
    send_at: Optional[int] = None

    @model_validator(mode="after")
    def validate_path(self):
        if not self.file_path.startswith("/"):
            raise ValueError("file_path must be absolute (start with /)")
        return self


class CreateVideoShareMessageIn(BaseModel):
    video_id: str = Field(min_length=1, max_length=128)
    text: Optional[str] = Field(default=None, max_length=2000)
    send_at: Optional[int] = None


class CreateCalendarShareMessageIn(BaseModel):
    calendar_id: str
    permission: Literal["read", "write"] = "read"
    include_booking_link: bool = False
    text: Optional[str] = Field(default=None, max_length=2000)
    send_at: Optional[int] = None


class CreateCalendarEventMessageIn(BaseModel):
    calendar_id: str
    event_id: str
    text: Optional[str] = Field(default=None, max_length=2000)
    send_at: Optional[int] = None


class MeetingPollSlotIn(BaseModel):
    start_utc: str
    end_utc: str


class CreateMeetingPollMessageIn(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    duration_minutes: int = Field(ge=15, le=1440, default=30)
    slots: List[MeetingPollSlotIn] = Field(min_length=2, max_length=5)
    text: Optional[str] = Field(default=None, max_length=2000)


class CreateFindDateTimeMessageIn(BaseModel):
    """Request body for creating a Find-a-DateTime poll message (MSG-009)."""
    title: str = Field(min_length=1, max_length=200)
    from_date: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}$")
    to_date: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}$")
    start_hour: int = Field(ge=0, le=23)
    end_hour: int = Field(ge=1, le=24)
    slot_duration_minutes: int = Field(default=30)
    deadline_hours: int = Field(default=48, ge=1, le=336)
    text: Optional[str] = Field(default=None, max_length=2000)

    @model_validator(mode="after")
    def _validate_fadt(self):
        if self.slot_duration_minutes not in (15, 30, 60):
            raise ValueError("slot_duration_minutes must be 15, 30, or 60")
        if self.start_hour >= self.end_hour:
            raise ValueError("start_hour must be less than end_hour")
        return self


class SubmitAvailabilityIn(BaseModel):
    """Request body for submitting Find-a-DateTime availability (MSG-009)."""
    slots: List[str] = Field(min_length=1, max_length=500)


class SendCountdownMessageIn(BaseModel):
    """Request model for sending a countdown message (MSG-010)."""
    title: str = Field(min_length=1, max_length=200)
    target_datetime: int = Field(description="UTC Unix timestamp of the target event")
    associated_event_type: str = Field(
        default="custom",
        pattern=r"^(broadcast|call|calendar|custom)$",
    )
    associated_event_id: Optional[str] = Field(default=None, max_length=128)
    reply_to_message_id: Optional[str] = None

    @model_validator(mode="after")
    def _validate_countdown(self):
        if self.target_datetime <= now_ts():
            raise ValueError("target_datetime must be in the future")
        if self.associated_event_type != "custom" and not self.associated_event_id:
            raise ValueError("associated_event_id required for non-custom events")
        return self


class SendGifMessageIn(BaseModel):
    """Request body for sending a GIF message (MSG-008)."""
    gif_url: str = Field(..., max_length=2048)
    gif_alt_text: str = Field(default="", max_length=256)
    gif_width: int = Field(default=0, ge=0, le=4096)
    gif_height: int = Field(default=0, ge=0, le=4096)
    reply_to_message_id: Optional[str] = None


class SendStickerMessageIn(BaseModel):
    """Request body for sending a sticker message (MSG-008)."""
    sticker_id: str = Field(..., min_length=1, max_length=64)
    sticker_collection_id: str = Field(..., min_length=1, max_length=64)
    reply_to_message_id: Optional[str] = None


class PollVoteIn(BaseModel):
    votes: Dict[str, Literal["yes", "no", "maybe"]]


class PollConfirmIn(BaseModel):
    slot_id: str
    calendar_id: Optional[str] = None


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
    messaging_gallery_enabled: bool
    messaging_dm_lottery_enabled: bool
    messaging_hide_controls_enabled: bool
    messaging_pins_enabled: bool
    messaging_reporting_enabled: bool
    messaging_mass_send_enabled: bool


class ParticipantOut(BaseModel):
    user_id: str
    status: str
    role: str
    muted_until: int = 0
    last_read_at: int = 0
    joined_at: int = 0
    left_at: int = 0
    assignment_state: Optional[str] = None
    assignment_owner_user_id: Optional[str] = None
    is_assignment_owner: Optional[bool] = None
    display_name: Optional[str] = None
    profile_photo_url: Optional[str] = None


# Partial rebuild now that ParticipantOut is defined; MessageOut not yet defined.
ConversationOut.model_rebuild(raise_errors=False)


class ReactIn(BaseModel):
    # max_length 64 to accommodate MSG-007 custom emoji reaction keys
    # of the form "custom:<shortcode>".
    emoji: str = Field(min_length=1, max_length=64)
    action: Literal["add", "remove"] = "add"


# MSG-011: max unique emoji reaction keys allowed per message.
MAX_UNIQUE_REACTIONS_PER_MESSAGE = 20


class ReactionUserOut(BaseModel):
    """A single user who reacted with a specific emoji."""
    user_sub: str
    display_name: str
    profile_photo_url: Optional[str] = None


class ReactionDetailsOut(BaseModel):
    """Detailed reaction breakdown for a message: emoji -> list of reactors."""
    reactions: Dict[str, List[ReactionUserOut]] = Field(default_factory=dict)


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
    consumption_policy: Literal["none", "view_once", "listen_once"] = "none"
    signature_packet_id: Optional[str] = Field(default=None, max_length=128)

    @model_validator(mode="after")
    def _validate_consumption_policy(self):
        if self.consumption_policy == "view_once" and self.kind != "video":
            raise PydanticCustomError(
                "invalid_media_kind_for_policy",
                "view_once is only supported for video file messages",
            )
        if self.consumption_policy == "listen_once" and self.kind != "audio":
            raise PydanticCustomError(
                "invalid_media_kind_for_policy",
                "listen_once is only supported for audio file messages",
            )
        return self


class LotteryOutcomeIn(BaseModel):
    display_label: Optional[str] = Field(default=None, max_length=80)
    weight_bps: int = Field(ge=1, le=10_000)
    payload_type: Literal["text", "image", "video"]
    text_content: Optional[str] = Field(default=None, max_length=4000)
    media_asset_id: Optional[str] = Field(default=None, min_length=1, max_length=256)


class LotteryConfigIn(BaseModel):
    version: str = Field(default="v1", min_length=1, max_length=32)
    outcomes: List[LotteryOutcomeIn] = Field(default_factory=list)


class CreateLotteryMessageIn(BaseModel):
    message_type: Literal["lottery_dm"] = "lottery_dm"
    conversation_id: str = Field(min_length=1, max_length=128)
    lottery_config: LotteryConfigIn


class LotteryOutcomeOut(BaseModel):
    outcome_id: str
    display_label: Optional[str] = None
    weight_bps: int
    payload_type: Literal["text", "image", "video"]
    text_content: Optional[str] = None
    media_asset_id: Optional[str] = None
    media_metadata: Optional[Dict[str, Any]] = None


class LotteryConfigOut(BaseModel):
    version: str
    outcomes: List[LotteryOutcomeOut]


class LotterySelectedOutcomeOut(BaseModel):
    outcome_id: str
    payload_type: Literal["text", "image", "video"]
    text_content: Optional[str] = None
    media_asset_id: Optional[str] = None


class LotteryMessageOut(BaseModel):
    message_id: str
    conversation_id: str
    sender_id: str
    message_type: Literal["lottery_dm"] = "lottery_dm"
    lock_state: Literal["locked", "unlocked"]
    lottery_config: LotteryConfigOut
    selected_outcome: Optional[LotterySelectedOutcomeOut] = None
    idempotent: bool = False
    created_at: int


class LotteryUnlockOut(BaseModel):
    message_id: str
    lock_state: Literal["unlocked"] = "unlocked"
    selected_outcome: LotterySelectedOutcomeOut
    unlocked_at: int


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


class AttachmentGrantOut(BaseModel):
    grant_token: str
    expires_at: int
    conversation_id: str
    message_id: str


class ConsumeAttachmentIn(BaseModel):
    consumption_attempt_id: str = Field(min_length=8, max_length=128)
    trigger: Literal["open", "play"]
    playback_seconds: Optional[float] = Field(default=None, ge=0)


class ConsumeAttachmentOut(BaseModel):
    ok: bool
    conversation_id: str
    message_id: str
    consumption_state: Literal["consumed"]
    consumed_at: int
    consumption_attempt_id: str


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
    kind: Literal["text", "image", "file", "audio", "video", "gallery", "file_share", "calendar_share", "calendar_event", "meeting_poll", "video_share", "voice_message", "voicemail", "countdown", "gif", "sticker", "find_datetime"]
    text: Optional[str] = None
    image: Optional[Dict[str, Any]] = None
    file: Optional[Dict[str, Any]] = None
    file_share: Optional[Dict[str, Any]] = None
    calendar_share: Optional[Dict[str, Any]] = None
    calendar_event: Optional[Dict[str, Any]] = None
    meeting_poll: Optional[Dict[str, Any]] = None
    # Find-a-DateTime message fields (MSG-009)
    find_datetime: Optional[Dict[str, Any]] = None
    video_share: Optional[Dict[str, Any]] = None
    lottery: Optional[Dict[str, Any]] = None
    voice_message: Optional[Dict[str, Any]] = None
    voicemail: Optional[Dict[str, Any]] = None
    # Countdown message fields (MSG-010)
    countdown_title: Optional[str] = None
    target_datetime: Optional[int] = None
    associated_event_type: Optional[str] = None
    associated_event_id: Optional[str] = None
    # GIF message fields (MSG-008)
    gif_url: Optional[str] = None
    gif_alt_text: Optional[str] = None
    gif_width: Optional[int] = None
    gif_height: Optional[int] = None
    gif_provider: Optional[str] = None
    # Sticker message fields (MSG-008)
    sticker_id: Optional[str] = None
    sticker_collection_id: Optional[str] = None
    sticker_url: Optional[str] = None
    sticker_alt_text: Optional[str] = None
    preview: Optional[Dict[str, Any]] = None
    # Gallery message fields
    free_images: Optional[List[Dict[str, Any]]] = None
    locked_images: Optional[List[Dict[str, Any]]] = None  # None = hidden (not unlocked)
    locked_image_count: Optional[int] = None

    reply_to_message_id: Optional[str] = Field(default=None, alias=MESSAGE_FIELD_REPLY_TO_ID)
    parent_message_id: Optional[str] = Field(default=None, alias=MESSAGE_FIELD_PARENT_ID)
    thread_id: Optional[str] = Field(default=None, alias=MESSAGE_FIELD_THREAD_ID)
    thread_root_message_id: Optional[str] = Field(default=None, alias=MESSAGE_FIELD_THREAD_ROOT_ID)
    has_thread: bool = False
    thread_reply_count: Optional[int] = None
    thread_last_reply_at: Optional[int] = None
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
    consumption_policy: Optional[Literal["none", "view_once", "listen_once"]] = None
    media_kind: Optional[Literal["image", "video", "audio"]] = None
    consumption_state: Optional[Literal["pending", "consumed", "expired", "failed"]] = None
    consumed_at: Optional[int] = None

    # Scheduled delivery
    scheduled: bool = False
    deliver_at: Optional[int] = None

    # Tips / money
    tip_amount_cents: Optional[int] = None
    tip_currency: Optional[str] = None
    tip_payment_id: Optional[str] = None

    # Expiry
    expires_at: Optional[int] = None      # absolute Unix timestamp when it expires
    view_once: bool = False
    expired: bool = False                  # true = content redacted, tombstone shown

    # Lock / PPV
    locked: bool = False                   # has a lock_price set
    lock_price_cents: Optional[int] = None
    lock_description: Optional[str] = None
    is_unlocked: bool = False              # viewer-specific: True once paid

    # Bot identity + quick replies (BOT-002)
    sender_type: Optional[Literal["user", "bot"]] = None
    bot_id: Optional[str] = None
    bot_name: Optional[str] = None
    bot_avatar_url: Optional[str] = None
    quick_replies: Optional[List[Dict[str, str]]] = None


# Rebuild ConversationOut now that MessageOut is also fully defined
ConversationOut.model_rebuild()

GalleryType = Literal["image", "video", "file", "link"]
GALLERY_TYPES: set[str] = {"image", "video", "file", "link"}


class GalleryItemOut(BaseModel):
    message_id: str
    conversation_id: str
    sender_id: str
    created_at: int
    type: GalleryType
    url: str
    thumbnail_url: Optional[str] = None
    title: Optional[str] = None
    file_name: Optional[str] = None
    content_type: Optional[str] = None
    size: Optional[int] = None


class GalleryPageOut(BaseModel):
    items: List[GalleryItemOut]
    next_cursor: Optional[str] = None


class ThreadMessagesPageOut(BaseModel):
    items: List[MessageOut]
    next_cursor: Optional[str] = None
    unread_count: int = 0


HELPDESK_MASKED_SENDER_ID = "Helpdesk"


class UnlockMessageIn(BaseModel):
    payment_method_id: Optional[str] = None


class UnlockOut(BaseModel):
    ok: bool
    conversation_id: str
    message_id: str
    unlock_payment_id: str
    amount_cents: int


class MessageControlsErrorOut(BaseModel):
    detail: str
    error_code: Optional[str] = None


class MessageControlActionOut(BaseModel):
    ok: bool
    conversation_id: str
    message_id: str
    action: Literal["hidden", "visible", "pinned", "unpinned"]
    updated_at: int


class HiddenMessagesPageOut(BaseModel):
    items: List[MessageOut]
    next_cursor: Optional[str] = None


class ConversationPinOut(BaseModel):
    conversation_id: str
    message_id: str
    pinned_by_user_id: str
    pinned_at: int
    is_active: bool


class ConversationPinsPageOut(BaseModel):
    items: List[ConversationPinOut]
    next_cursor: Optional[str] = None


class ReportMessageIn(BaseModel):
    reason_code: str = Field(min_length=2, max_length=64)
    statement: str = Field(min_length=5, max_length=2000)

    @model_validator(mode="after")
    def _validate_and_normalize(self):
        self.reason_code = (self.reason_code or "").strip().lower()
        self.statement = (self.statement or "").strip()
        if not self.reason_code:
            record_messaging_report_validation_error(reason="reason_code_required")
            raise ValueError("reason_code is required")
        if len(self.statement) < 5:
            record_messaging_report_validation_error(reason="statement_too_short")
            raise ValueError("statement must be at least 5 characters")
        if len(self.statement) > 2000:
            record_messaging_report_validation_error(reason="statement_too_long")
            raise ValueError("statement must be at most 2000 characters")
        return self


class ReportMessageOut(BaseModel):
    ok: bool
    report_id: str
    conversation_id: str
    message_id: str
    reason_code: str
    status: Literal["submitted"]
    created_at: int



class ReportStatusUpdateIn(BaseModel):
    status: Literal["submitted", "under_review", "actioned", "dismissed"]
    note: Optional[str] = Field(default=None, max_length=1000)


class ReportStatusUpdateOut(BaseModel):
    ok: bool
    report_id: str
    conversation_id: str
    message_id: str
    status: Literal["submitted", "under_review", "actioned", "dismissed"]
    updated_at: int


class LegalHoldCreateIn(BaseModel):
    case_id: str = Field(min_length=2, max_length=128)
    reason: str = Field(min_length=4, max_length=2000)
    message_id: Optional[str] = Field(default=None, max_length=128)
    report_id: Optional[str] = Field(default=None, max_length=128)


class LegalHoldOut(BaseModel):
    hold_id: str
    tenant_id: str
    conversation_id: str
    message_id: Optional[str] = None
    report_id: Optional[str] = None
    case_id: str
    reason: str
    status: Literal["active", "released"]
    created_at: int
    created_by_user_id: str
    released_at: Optional[int] = None
    released_by_user_id: Optional[str] = None


class LegalHoldReleaseIn(BaseModel):
    reason: str = Field(min_length=4, max_length=2000)


class ComplianceArchiveEventOut(BaseModel):
    event_id: str
    event_ts: int
    event_type: str
    conversation_id: str
    message_id: str
    actor_user_id: str
    effective_user_id: str
    object_key: str
    payload_hash: str
    prev_hash: str
    schema_version: int
    payload: Optional[Dict[str, Any]] = None


class ComplianceArchiveEventsPageOut(BaseModel):
    items: List[ComplianceArchiveEventOut]
    next_cursor: Optional[str] = None
    total_matches: int


class ComplianceArchiveExportCreateIn(BaseModel):
    case_id: str = Field(min_length=1, max_length=128)
    from_ts: int = Field(ge=0)
    to_ts: int = Field(ge=0)
    conversation_id: Optional[str] = None
    user_id: Optional[str] = None
    include_payload: bool = True


class ComplianceArchiveExportOut(BaseModel):
    export_id: str
    case_id: str
    tenant_id: str
    status: Literal["queued", "running", "completed", "failed"]
    created_at: int
    updated_at: int
    requested_by_user_id: str
    expires_at: int
    record_count: int = 0
    result_manifest_uri: Optional[str] = None
    error: Optional[str] = None


MESSAGE_CONTROLS_ERROR_RESPONSES = {
    401: {"model": MessageControlsErrorOut, "description": "Unauthorized"},
    403: {"model": MessageControlsErrorOut, "description": "Forbidden"},
    404: {"model": MessageControlsErrorOut, "description": "Not Found"},
    422: {"model": MessageControlsErrorOut, "description": "Validation Error"},
    429: {"model": MessageControlsErrorOut, "description": "Rate Limited"},
}


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


_MSG_SEARCH_MAX_PREFIX_LEN = 8  # must match build_message_search_tokens max_prefix_len


def build_message_query_tokens(query: str, *, max_len: int = 32) -> list[str]:
    tokens = _stem_tokens(_tokenize_message(query, max_len=max_len))
    out: list[str] = []
    for token in tokens:
        out.append(token)
        # Use the same prefix length cap as build_message_search_tokens so that
        # every query prefix token is guaranteed to exist in the index.
        for i in range(1, min(len(token), _MSG_SEARCH_MAX_PREFIX_LEN) + 1):
            out.append(token[:i])
        out.extend(_token_ngrams(token))
    return list(dict.fromkeys(out))


def _message_search_key(conversation_id: str, message_id: str) -> str:
    return f"{conversation_id}#{message_id}"


def _message_search_enabled() -> bool:
    return bool(DDB_MESSAGE_SEARCH) and _aws_credentials_available()


def _encode_gallery_cursor(message_id: str) -> str:
    payload = {"message_id": message_id}
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _gallery_attachment_fallback_url(conversation_id: str, message_id: str) -> str:
    return f"/messaging/conversations/{conversation_id}/messages/{message_id}/attachment"


def _decode_gallery_cursor(cursor: str) -> str:
    if not isinstance(cursor, str) or not cursor.strip():
        raise HTTPException(
            status_code=422,
            detail={"code": "gallery_cursor_invalid", "message": "Invalid gallery cursor"},
        )
    token = cursor.strip()
    padded = token + "=" * (-len(token) % 4)
    try:
        decoded = base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8")
        payload = json.loads(decoded)
        message_id = str(payload.get("message_id") or "").strip()
    except (UnicodeDecodeError, ValueError, TypeError, binascii.Error):
        raise HTTPException(
            status_code=422,
            detail={"code": "gallery_cursor_invalid", "message": "Invalid gallery cursor"},
        )
    if not message_id:
        raise HTTPException(
            status_code=422,
            detail={"code": "gallery_cursor_invalid", "message": "Invalid gallery cursor"},
        )
    return message_id


def _gallery_item_from_message(message: Dict[str, Any], gallery_type: str) -> Optional[GalleryItemOut]:
    if message.get("revoked") or message.get("revoked_at"):
        return None

    is_encrypted = bool(message.get("is_encrypted") or message.get("encryption"))
    kind = str(message.get("kind") or "").strip().lower()
    message_id = str(message.get("message_id") or "").strip()
    conversation_id = str(message.get("conversation_id") or "").strip()
    sender_id = str(message.get("sender_id") or "").strip()
    created_at = int(message.get("created_at") or 0)
    if not message_id or not conversation_id or not sender_id or created_at <= 0:
        return None

    # Encrypted-content gallery policy:
    # - Encrypted payloads are excluded from image/video/file tabs.
    # - For links, only explicit preview.url is exposed; other preview metadata is redacted.
    if is_encrypted:
        if gallery_type != "link":
            return None
        preview = message.get("preview") if isinstance(message.get("preview"), dict) else {}
        url = str(preview.get("url") or "").strip()
        if not url:
            return None
        return GalleryItemOut(
            message_id=message_id,
            conversation_id=conversation_id,
            sender_id=sender_id,
            created_at=created_at,
            type="link",
            url=url,
            title=None,
            thumbnail_url=None,
        )

    if gallery_type == "image" and kind == "image":
        image = message.get("image") if isinstance(message.get("image"), dict) else {}
        url = str(image.get("url") or "").strip()
        if not url:
            bucket = str(image.get("bucket") or "").strip()
            key = str(image.get("key") or "").strip()
            if bucket and key:
                url = _gallery_attachment_fallback_url(conversation_id, message_id)
            else:
                return None
        return GalleryItemOut(
            message_id=message_id,
            conversation_id=conversation_id,
            sender_id=sender_id,
            created_at=created_at,
            type="image",
            url=url,
            content_type=str(image.get("content_type") or "").strip() or None,
        )

    if gallery_type == "video" and kind == "video":
        file_payload = message.get("file") if isinstance(message.get("file"), dict) else {}
        url = str(file_payload.get("url") or "").strip()
        if not url:
            path = str(file_payload.get("path") or "").strip()
            if path:
                url = _gallery_attachment_fallback_url(conversation_id, message_id)
            else:
                return None
        size = file_payload.get("size")
        return GalleryItemOut(
            message_id=message_id,
            conversation_id=conversation_id,
            sender_id=sender_id,
            created_at=created_at,
            type="video",
            url=url,
            thumbnail_url=str(file_payload.get("thumbnail") or "").strip() or None,
            file_name=str(file_payload.get("name") or "").strip() or None,
            content_type=str(file_payload.get("content_type") or "").strip() or None,
            size=int(size) if isinstance(size, (int, float)) else None,
        )

    if gallery_type == "video" and kind == "video_share":
        vs = message.get("video_share") or {}
        url = vs.get("hls_manifest_url") or vs.get("thumbnail_url") or ""
        if url:
            return GalleryItemOut(
                message_id=message_id,
                conversation_id=conversation_id,
                sender_id=sender_id,
                created_at=created_at,
                type="video",
                url=url,
                thumbnail_url=vs.get("thumbnail_url"),
            )

    include_audio = os.getenv("MESSAGING_GALLERY_INCLUDE_AUDIO", "0") in ("1", "true", "True")
    if gallery_type == "file" and (kind == "file" or (include_audio and kind == "audio")):
        file_payload = message.get("file") if isinstance(message.get("file"), dict) else {}
        url = str(file_payload.get("url") or "").strip()
        if not url:
            path = str(file_payload.get("path") or "").strip()
            if path:
                url = _gallery_attachment_fallback_url(conversation_id, message_id)
            else:
                return None
        size = file_payload.get("size")
        return GalleryItemOut(
            message_id=message_id,
            conversation_id=conversation_id,
            sender_id=sender_id,
            created_at=created_at,
            type="file",
            url=url,
            file_name=str(file_payload.get("name") or "").strip() or None,
            content_type=str(file_payload.get("content_type") or "").strip() or None,
            size=int(size) if isinstance(size, (int, float)) else None,
        )

    if gallery_type == "link" and kind == "text":
        preview = message.get("preview") if isinstance(message.get("preview"), dict) else {}
        url = str(preview.get("url") or "").strip()
        if not url:
            return None
        return GalleryItemOut(
            message_id=message_id,
            conversation_id=conversation_id,
            sender_id=sender_id,
            created_at=created_at,
            type="link",
            url=url,
            thumbnail_url=str(preview.get("image_url") or "").strip() or None,
            title=str(preview.get("title") or "").strip() or None,
        )

    return None


def _message_receipts_enabled() -> bool:
    return bool(DDB_MESSAGE_RECEIPTS) and _aws_credentials_available()


def _messaging_gallery_enabled() -> bool:
    enabled = os.getenv(
        "MESSAGING_GALLERY_ENABLED",
        "true" if S.messaging_gallery_enabled else "false",
    ) not in ("0", "false", "False")
    kill_switch = os.getenv(
        "MESSAGING_GALLERY_KILL_SWITCH",
        "true" if S.messaging_gallery_kill_switch else "false",
    ) not in ("0", "false", "False")
    return enabled and not kill_switch


def _messaging_gallery_index_enabled() -> bool:
    enabled = os.getenv(
        "MESSAGING_GALLERY_INDEX_ENABLED",
        "true" if S.messaging_gallery_index_enabled else "false",
    ) not in ("0", "false", "False")
    return bool(enabled and tbl_gallery_index is not None and _aws_credentials_available())


def _messaging_dm_lottery_enabled() -> bool:
    enabled = os.getenv(
        "MESSAGING_DM_LOTTERY_ENABLED",
        "true" if S.messaging_dm_lottery_enabled else "false",
    ) not in ("0", "false", "False")
    kill_switch = os.getenv(
        "MESSAGING_DM_LOTTERY_KILL_SWITCH",
        "true" if S.messaging_dm_lottery_kill_switch else "false",
    ) not in ("0", "false", "False")
    return enabled and not kill_switch


def _messaging_client_version(req: Request | None) -> str:
    if not req:
        return "unknown"
    headers = req.headers
    preferred = headers.get("x-client-version") or headers.get("x-app-version")
    if preferred and preferred.strip():
        return preferred.strip()
    user_agent = headers.get("user-agent") or ""
    if user_agent.strip():
        return user_agent.strip()[:48]
    return "unknown"


def _messaging_hide_controls_enabled() -> bool:
    return os.getenv(
        "MESSAGING_HIDE_CONTROLS_ENABLED",
        "true" if S.messaging_hide_controls_enabled else "false",
    ) not in ("0", "false", "False")


def _messaging_pins_enabled() -> bool:
    return os.getenv(
        "MESSAGING_PINS_ENABLED",
        "true" if S.messaging_pins_enabled else "false",
    ) not in ("0", "false", "False")


def _messaging_reporting_enabled() -> bool:
    return os.getenv(
        "MESSAGING_REPORTING_ENABLED",
        "true" if S.messaging_reporting_enabled else "false",
    ) not in ("0", "false", "False")


def _messaging_compliance_export_enabled() -> bool:
    return os.getenv(
        "MESSAGING_COMPLIANCE_EXPORT_ENABLED",
        "true" if S.messaging_compliance_export_enabled else "false",
    ) not in ("0", "false", "False")


def _messaging_compliance_legal_hold_enabled() -> bool:
    return os.getenv(
        "MESSAGING_COMPLIANCE_LEGAL_HOLD_ENABLED",
        "true" if S.messaging_compliance_legal_hold_enabled else "false",
    ) not in ("0", "false", "False")


def _require_message_controls_capability(enabled: bool, detail: str) -> None:
    if not enabled:
        raise HTTPException(status_code=403, detail=detail)


def _require_dm_lottery_enabled() -> None:
    if not _messaging_dm_lottery_enabled():
        raise HTTPException(
            status_code=403,
            detail={"code": "feature-disabled", "message": "messaging.dm_lottery is disabled"},
        )


_LOTTERY_UNLOCK_RATE_LIMIT_LOCK = threading.Lock()
_LOTTERY_UNLOCK_RATE_LIMIT_EVENTS: dict[str, list[int]] = {}


def _enforce_lottery_unlock_rate_limit(*, user_id: str, conversation_id: str, message_id: str, now: int) -> None:
    enabled = os.environ.get(
        "MESSAGING_DM_LOTTERY_UNLOCK_RATE_LIMIT_ENABLED",
        "true" if S.messaging_dm_lottery_unlock_rate_limit_enabled else "false",
    ).lower() in ("1", "true", "yes", "on")
    if not enabled:
        return

    window_seconds = max(
        1,
        int(
            os.environ.get(
                "MESSAGING_DM_LOTTERY_UNLOCK_RATE_LIMIT_WINDOW_SECONDS",
                str(S.messaging_dm_lottery_unlock_rate_limit_window_seconds),
            )
        ),
    )
    max_events = max(
        1,
        int(
            os.environ.get(
                "MESSAGING_DM_LOTTERY_UNLOCK_RATE_LIMIT_MAX",
                str(S.messaging_dm_lottery_unlock_rate_limit_max),
            )
        ),
    )
    key = f"{user_id}|{conversation_id}|{message_id}"
    cutoff = now - window_seconds
    with _LOTTERY_UNLOCK_RATE_LIMIT_LOCK:
        events = [ts for ts in _LOTTERY_UNLOCK_RATE_LIMIT_EVENTS.get(key, []) if ts >= cutoff]
        if len(events) >= max_events:
            _LOTTERY_UNLOCK_RATE_LIMIT_EVENTS[key] = events
            record_messaging_message_control_action(action="lottery_unlock", result="rate_limited")
            audit_event(
                "messaging_lottery_unlock_rate_limited",
                user_id,
                None,
                outcome="rate_limited",
                conversation_id=conversation_id,
                message_id=message_id,
                count=len(events),
                window_seconds=window_seconds,
            )
            raise HTTPException(
                status_code=429,
                detail={
                    "code": "rate_limited",
                    "message": "Too many lottery unlock attempts. Please retry later.",
                    "scope": "user_conversation_message",
                },
                headers={"Retry-After": str(window_seconds)},
            )
        events.append(now)
        _LOTTERY_UNLOCK_RATE_LIMIT_EVENTS[key] = events


def _resolve_and_validate_lottery_media_asset(*, media_asset_id: str, conversation_id: str, owner_user_id: str) -> dict[str, Any]:
    raw = str(media_asset_id or "").strip()
    if not raw:
        raise HTTPException(
            status_code=422,
            detail={"code": "invalid-media-asset", "message": "media_asset_id is required for media outcomes"},
        )
    bucket = S3_BUCKET_IMAGES
    key = raw
    if raw.startswith("s3://"):
        tail = raw[len("s3://") :]
        if "/" not in tail:
            raise HTTPException(
                status_code=422,
                detail={"code": "invalid-media-asset", "message": "media_asset_id must include bucket and key"},
            )
        bucket, key = tail.split("/", 1)
    elif ":" in raw:
        b, k = raw.split(":", 1)
        if b and k:
            bucket, key = b, k

    expected_prefix = f"{conversation_id}/{owner_user_id}/"
    if not key.startswith(expected_prefix):
        raise HTTPException(
            status_code=403,
            detail={"code": "unauthorized", "message": "media asset does not belong to sender or conversation"},
        )
    try:
        head = s3.head_object(Bucket=bucket, Key=key)
    except Exception as exc:
        raise HTTPException(
            status_code=422,
            detail={"code": "invalid-media-asset", "message": "media asset not found"},
        ) from exc

    return {
        "bucket": bucket,
        "key": key,
        "content_type": str(head.get("ContentType") or ""),
        "content_length": int(head.get("ContentLength") or 0),
        "etag": str(head.get("ETag") or "").strip('"') or None,
        "last_modified": int(head.get("LastModified").timestamp()) if head.get("LastModified") else None,
    }


def _lottery_dedupe_message_id(*, sender_id: str, conversation_id: str, idempotency_key: str) -> str:
    digest = hashlib.sha256(f"{sender_id}|{conversation_id}|{idempotency_key}".encode("utf-8")).hexdigest()[:32]
    return f"m_lottery_{digest}"


def _lottery_config_signature(config: Mapping[str, Any]) -> str:
    payload = {
        "version": str(config.get("version") or "v1"),
        "outcomes": [
            {
                "outcome_id": str(out.get("outcome_id") or ""),
                "display_label": (str(out.get("display_label") or "") or None),
                "weight_bps": int(out.get("weight_bps") or 0),
                "payload_type": str(out.get("payload_type") or ""),
                "text_content": (str(out.get("text_content") or "") or None),
                "media_asset_id": (str(out.get("media_asset_id") or "") or None),
            }
            for out in (config.get("outcomes") or [])
        ],
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _lottery_message_item(
    *,
    conversation_id: str,
    message_id: str,
    sender_id: str,
    created_at: int,
    persisted_cfg: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "conversation_id": conversation_id,
        "message_id": message_id,
        "sender_id": sender_id,
        "created_at": created_at,
        "kind": "text",
        "text": "🎲 Lottery message",
        "lottery": {
            "message_type": "lottery_dm",
            "lock_state": "locked",
            "version": persisted_cfg.get("version", "v1"),
            "outcome_ids": [str(out.get("outcome_id") or "") for out in (persisted_cfg.get("outcomes") or [])],
        },
        "reactions": {},
    }


def _encode_gallery_index_cursor(sort_key: str) -> str:
    payload = {"gallery_sort": sort_key}
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _decode_gallery_index_cursor(cursor: str) -> str:
    if not isinstance(cursor, str) or not cursor.strip():
        raise HTTPException(
            status_code=422,
            detail={"code": "gallery_cursor_invalid", "message": "Invalid gallery cursor"},
        )
    token = cursor.strip()
    padded = token + "=" * (-len(token) % 4)
    try:
        decoded = base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8")
        payload = json.loads(decoded)
        sort_key = str(payload.get("gallery_sort") or "").strip()
    except (UnicodeDecodeError, ValueError, TypeError, binascii.Error):
        raise HTTPException(
            status_code=422,
            detail={"code": "gallery_cursor_invalid", "message": "Invalid gallery cursor"},
        )
    if not sort_key:
        raise HTTPException(
            status_code=422,
            detail={"code": "gallery_cursor_invalid", "message": "Invalid gallery cursor"},
        )
    return sort_key


def _gallery_index_entries_from_message(message: Dict[str, Any]) -> list[Dict[str, Any]]:
    out: list[Dict[str, Any]] = []
    for gallery_type in GALLERY_TYPES:
        item = _gallery_item_from_message(message, gallery_type)
        if item is None:
            continue
        row = {
            "type": item.type,
            "sender_id": item.sender_id,
            "created_at": int(item.created_at),
            "url": item.url,
            "thumbnail_url": item.thumbnail_url,
            "title": item.title,
            "file_name": item.file_name,
            "content_type": item.content_type,
            "size": item.size,
            "deleted_for": list(message.get("deleted_for") or []),
            "revoked_at": int(message.get("revoked_at") or 0),
        }
        out.append(row)
    return out


def _sync_gallery_index_message(message: Dict[str, Any]) -> None:
    if not _messaging_gallery_index_enabled():
        return
    conversation_id = str(message.get("conversation_id") or "").strip()
    message_id = str(message.get("message_id") or "").strip()
    created_at = int(message.get("created_at") or 0)
    if not conversation_id or not message_id or not created_at:
        return
    entries = _gallery_index_entries_from_message(message)
    try:
        sync_gallery_index_entries(
            table=tbl_gallery_index,
            conversation_id=conversation_id,
            message_id=message_id,
            created_at=created_at,
            entries=entries,
        )
    except Exception:
        logger.exception(
            "messaging gallery index sync failed",
            extra={"conversation_id": conversation_id, "message_id": message_id},
        )


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


def _safe_index_message(item: Dict[str, Any]) -> None:
    try:
        text = item.get("text") or ""
        if text:
            index_message_search(
                item.get("conversation_id", ""),
                item.get("message_id", ""),
                item.get("sender_id", ""),
                int(item.get("created_at", 0)),
                text,
            )
    except Exception:
        pass


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
    if message_item.get("moderation_hidden") or message_item.get("moderation_removed_at"):
        return False
    # Scheduled messages are only visible to the sender until delivered
    if message_item.get("status") == "scheduled" and message_item.get("sender_id") != user_id:
        return False
    return user_id not in deleted_for


def _message_search_text(message_item: dict) -> str:
    if bool(message_item.get("is_encrypted")):
        return ""
    return str(message_item.get("search_text") or message_item.get("text") or "")


def _is_searchable_kind(kind: Optional[str]) -> bool:
    return kind in {"text", "file", "audio", "video", "video_share"}




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


def _is_once_consumption_policy(policy: Optional[str]) -> bool:
    return policy in {"view_once", "listen_once"}


def _extract_once_media_cohort(req: Optional[Request]) -> str:
    if req is None:
        return "default"
    raw = req.headers.get(ONCE_MEDIA_COHORT_HEADER, "")
    cohort = re.sub(r"[^a-zA-Z0-9._-]", "", raw.strip().lower())
    if not cohort:
        return "default"
    return cohort[:32]


def _media_kind_for_message_item(message_item: dict) -> Optional[str]:
    kind = str(message_item.get("kind") or "").lower()
    if kind == "image":
        return "image"
    if kind == "video":
        return "video"
    if kind == "audio":
        return "audio"
    return None


def _consumption_partition_key(user_id: str, message_id: str) -> str:
    return f"{user_id}#{message_id}"


def _put_message_consumption_records(
    *,
    conversation_id: str,
    message_id: str,
    sender_id: str,
    participants: Sequence[dict],
    consumption_policy: Optional[str],
    media_kind: Optional[str],
    created_at: int,
) -> None:
    if not _is_once_consumption_policy(consumption_policy):
        return
    if media_kind not in {"image", "video", "audio"}:
        return
    state = CONSUMPTION_STATE_PENDING
    for participant in participants:
        recipient_id = participant.get("user_id")
        if not recipient_id or recipient_id == sender_id:
            continue
        item = {
            "conversation_id": conversation_id,
            "recipient_message": _consumption_partition_key(str(recipient_id), message_id),
            "recipient_id": str(recipient_id),
            "message_id": message_id,
            "sender_id": sender_id,
            "created_at": int(created_at),
            "consumption_policy": consumption_policy,
            "media_kind": media_kind,
            "consumption_state": state,
            "consumed_at": 0,
            "GSI1PK": f"{conversation_id}#{state}",
            "GSI1SK": f"{int(created_at):010d}#{message_id}#{recipient_id}",
            "GSI2SK": f"{int(created_at):010d}#{conversation_id}#{message_id}",
        }
        tbl_msg_consumption.put_item(Item=item)


def _get_message_consumption_for_user(conversation_id: str, message_id: str, viewer_user_id: str) -> Optional[dict]:
    try:
        resp = tbl_msg_consumption.get_item(
            Key={
                "conversation_id": conversation_id,
                "recipient_message": _consumption_partition_key(viewer_user_id, message_id),
            }
        )
    except Exception:
        return None
    return resp.get("Item")


def _merge_consumption_state(message_item: dict, viewer_user_id: str) -> dict:
    merged = dict(message_item)
    policy = merged.get("consumption_policy")
    if not _is_once_consumption_policy(policy):
        return merged
    state_item = _get_message_consumption_for_user(
        str(merged.get("conversation_id") or ""),
        str(merged.get("message_id") or ""),
        viewer_user_id,
    )
    if state_item:
        merged["consumption_state"] = state_item.get("consumption_state")
        merged["consumed_at"] = int(state_item.get("consumed_at", 0) or 0) or None
        merged["media_kind"] = state_item.get("media_kind") or merged.get("media_kind")
    return merged


def _once_media_error(status_code: int, code: str, message: str, *, retryable: bool = False) -> None:
    raise HTTPException(status_code=status_code, detail={"code": code, "message": message, "retryable": retryable})


def _once_media_grant_secret() -> str:
    return os.getenv("MESSAGING_ONCE_MEDIA_GRANT_SECRET", "dev-once-media-grant-secret")


def _encode_once_media_grant(*, conversation_id: str, message_id: str, recipient_id: str, expires_at: int) -> str:
    payload = {
        "cid": conversation_id,
        "mid": message_id,
        "rid": recipient_id,
        "exp": int(expires_at),
    }
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    body = base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=")
    sig = hmac.new(_once_media_grant_secret().encode("utf-8"), body.encode("utf-8"), hashlib.sha256).digest()
    sig_b64 = base64.urlsafe_b64encode(sig).decode("utf-8").rstrip("=")
    return f"{body}.{sig_b64}"


def _decode_once_media_grant(token: str) -> Optional[dict]:
    if not token or "." not in token:
        return None
    body, sig = token.split(".", 1)
    expected = hmac.new(_once_media_grant_secret().encode("utf-8"), body.encode("utf-8"), hashlib.sha256).digest()
    expected_b64 = base64.urlsafe_b64encode(expected).decode("utf-8").rstrip("=")
    if not hmac.compare_digest(sig, expected_b64):
        return None
    padded = body + "=" * ((4 - len(body) % 4) % 4)
    try:
        data = json.loads(base64.urlsafe_b64decode(padded.encode("utf-8")).decode("utf-8"))
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    return data


def _validate_once_media_grant(*, token: str, conversation_id: str, message_id: str, recipient_id: str) -> None:
    data = _decode_once_media_grant(token)
    if not data:
        _once_media_error(403, "invalid_grant", "Invalid once-media access grant", retryable=False)
    exp = int(data.get("exp") or 0)
    if exp <= now_ts():
        _once_media_error(410, "grant_expired", "Once-media access grant expired", retryable=True)
    if data.get("cid") != conversation_id or data.get("mid") != message_id or data.get("rid") != recipient_id:
        _once_media_error(403, "invalid_grant", "Invalid once-media access grant", retryable=False)


def _get_once_media_state_or_error(*, conversation_id: str, message_id: str, recipient_id: str, message_item: dict) -> dict:
    policy = message_item.get("consumption_policy")
    if not _is_once_consumption_policy(policy):
        _once_media_error(422, "invalid_consumption_policy", "Message is not configured for once-media access", retryable=False)
    if str(message_item.get("sender_id") or "") == recipient_id:
        _once_media_error(403, "recipient_required", "Sender cannot request once-media recipient grants", retryable=False)
    state = _get_message_consumption_for_user(conversation_id, message_id, recipient_id)
    if not state:
        _once_media_error(404, "consumption_state_missing", "Recipient consumption state not found", retryable=False)
    if state.get("consumption_state") != CONSUMPTION_STATE_PENDING:
        _once_media_error(409, "already_consumed", "Message has already been consumed", retryable=False)
    return state


def _validate_consume_trigger_or_error(*, message_item: dict, trigger: str, playback_seconds: Optional[float]) -> None:
    policy = str(message_item.get("consumption_policy") or "")
    media_kind = str(message_item.get("media_kind") or _media_kind_for_message_item(message_item) or "")

    if media_kind == "image":
        if trigger != "open":
            _once_media_error(422, "invalid_consume_trigger", "Image once-media requires trigger 'open'", retryable=False)
        return

    if media_kind == "video":
        if policy != "view_once":
            _once_media_error(422, "invalid_consumption_policy", "Video once-media must use view_once policy", retryable=False)
        if trigger != "play":
            _once_media_error(422, "invalid_consume_trigger", "Video once-media requires trigger 'play'", retryable=False)
        if playback_seconds is None or float(playback_seconds) < ONCE_MEDIA_VIDEO_CONSUME_THRESHOLD_SEC:
            _once_media_error(
                409,
                "consume_threshold_not_met",
                "Video consume threshold not met yet",
                retryable=True,
            )
        return

    if media_kind == "audio":
        if policy != "listen_once":
            _once_media_error(422, "invalid_consumption_policy", "Audio once-media must use listen_once policy", retryable=False)
        if trigger != "play":
            _once_media_error(422, "invalid_consume_trigger", "Audio once-media requires trigger 'play'", retryable=False)
        if playback_seconds is None or float(playback_seconds) < ONCE_MEDIA_AUDIO_CONSUME_THRESHOLD_SEC:
            _once_media_error(
                409,
                "consume_threshold_not_met",
                "Audio consume threshold not met yet",
                retryable=True,
            )
        return

    _once_media_error(422, "invalid_media_kind_for_policy", "Unsupported once-media kind for consume", retryable=False)


def _consume_once_media_state_atomic(
    *,
    conversation_id: str,
    message_id: str,
    recipient_id: str,
    consumption_attempt_id: str,
    consumed_at: int,
) -> dict:
    key = {
        "conversation_id": conversation_id,
        "recipient_message": _consumption_partition_key(recipient_id, message_id),
    }
    try:
        tbl_msg_consumption.update_item(
            Key=key,
            ConditionExpression=(
                Attr("consumption_state").eq(CONSUMPTION_STATE_PENDING)
                | Attr("last_consumption_attempt_id").eq(consumption_attempt_id)
            ),
            UpdateExpression=(
                "SET consumption_state = :consumed, "
                "consumed_at = if_not_exists(consumed_at, :ts), "
                "last_consumption_attempt_id = :attempt"
            ),
            ExpressionAttributeValues={
                ":consumed": "consumed",
                ":ts": int(consumed_at),
                ":attempt": consumption_attempt_id,
            },
        )
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ConditionalCheckFailedException":
            raise
        state = _get_message_consumption_for_user(conversation_id, message_id, recipient_id)
        if not state:
            _once_media_error(404, "consumption_state_missing", "Recipient consumption state not found", retryable=False)
        if state.get("last_consumption_attempt_id") == consumption_attempt_id and state.get("consumption_state") == "consumed":
            return {
                "consumption_state": "consumed",
                "consumed_at": int(state.get("consumed_at", 0) or consumed_at),
                "consumption_attempt_id": consumption_attempt_id,
                "idempotent_replay": True,
            }
        _once_media_error(409, "already_consumed", "Message has already been consumed", retryable=False)

    state = _get_message_consumption_for_user(conversation_id, message_id, recipient_id) or {}
    return {
        "consumption_state": "consumed",
        "consumed_at": int(state.get("consumed_at", 0) or consumed_at),
        "consumption_attempt_id": consumption_attempt_id,
        "idempotent_replay": bool(state.get("last_consumption_attempt_id") == consumption_attempt_id),
    }


def _is_expired(item: dict, now: int) -> bool:
    expires_at = item.get("expires_at")
    if not expires_at:
        return False
    return int(expires_at) < now


def _is_view_once_consumed(item: dict, viewer_user_id: str) -> bool:
    if not item.get("view_once"):
        return False
    if viewer_user_id == item.get("sender_id"):
        return False
    seen = item.get("view_once_seen") or set()
    return viewer_user_id in seen


def _project_gallery_image(img_dict: dict) -> dict:
    """Project a gallery image item dict to a response dict with URL added in dev mode."""
    out = dict(img_dict)
    if S.dev_mode:
        from urllib.parse import quote as _gi_quote
        bucket = out.get("bucket", "")
        key = out.get("key", "")
        if bucket and key and not out.get("url"):
            out["url"] = f"/mock/s3/{bucket}/{_gi_quote(key, safe='/')}"
        # Also generate preview_url from preview_bucket/preview_key if present
        pb = out.get("preview_bucket", "")
        pk = out.get("preview_key", "")
        if pb and pk and not out.get("preview_url"):
            out["preview_url"] = f"/mock/s3/{pb}/{_gi_quote(pk, safe='/')}"
    return out


def _lottery_projection_for_viewer(message_item: dict, viewer_user_id: str) -> Optional[Dict[str, Any]]:
    lottery_meta = message_item.get("lottery") if isinstance(message_item.get("lottery"), dict) else None
    if not lottery_meta or str(lottery_meta.get("message_type") or "") != "lottery_dm":
        return None

    message_id = str(message_item.get("message_id") or "")
    sender_id = str(message_item.get("sender_id") or "")
    if not message_id:
        return {"message_type": "lottery_dm", "lock_state": "locked"}

    cfg = messaging_lottery_store.get_lottery_config(message_id=message_id) or {}
    unlock = None if viewer_user_id == sender_id else messaging_lottery_store.get_lottery_unlock(
        message_id=message_id,
        recipient_id=viewer_user_id,
    )

    if not unlock:
        return {
            "message_type": "lottery_dm",
            "lock_state": "locked",
        }

    selected_outcome_id = str(unlock.get("selected_outcome_id") or "")
    selected = next(
        (o for o in (cfg.get("outcomes") or []) if str(o.get("outcome_id") or "") == selected_outcome_id),
        None,
    )
    if not selected:
        return {
            "message_type": "lottery_dm",
            "lock_state": "locked",
        }
    return {
        "message_type": "lottery_dm",
        "lock_state": "unlocked",
        "selected_outcome": {
            "outcome_id": selected_outcome_id,
            "payload_type": str(selected.get("payload_type") or "text"),
            "text_content": (str(selected.get("text_content") or "") or None),
            "media_asset_id": (str(selected.get("media_asset_id") or "") or None),
            "media_metadata": (dict(selected.get("media_metadata") or {}) or None),
        },
    }


def _message_out_from_item(message_item: dict, viewer_user_id: str) -> MessageOut:
    merged_item = _merge_consumption_state(message_item, viewer_user_id)
    lottery_out = _lottery_projection_for_viewer(merged_item, viewer_user_id)

    file_payload = merged_item.get("file")
    if isinstance(file_payload, dict):
        packet_id = str(file_payload.get("signature_packet_id") or "")
        if packet_id:
            try:
                progress = get_signature_packet_progress_for_user(packet_id, viewer_user_id)
            except Exception:
                progress = None
            if progress:
                merged_file = dict(file_payload)
                merged_file.update(progress)
                merged_item["file"] = merged_file

    counts, mine = _reaction_summaries(merged_item, viewer_user_id)

    # Consumption policy projection (main)
    raw_policy = merged_item.get("consumption_policy")
    policy = raw_policy if _is_once_consumption_policy(raw_policy) else None
    media_kind = merged_item.get("media_kind") if policy else None
    consumption_state = merged_item.get("consumption_state") if policy else None
    consumed_at = (int(merged_item.get("consumed_at", 0) or 0) or None) if policy else None

    # Sender projection (main)
    conversation_id = str(merged_item.get("conversation_id") or "")
    projected_sender_id = _project_message_sender_id(
        message_item=merged_item,
        viewer_user_id=viewer_user_id,
        conversation_id=conversation_id,
    )

    # Expiry / view-once / lock projection (branch)
    now = now_ts()
    expired = _is_expired(merged_item, now)
    view_once_consumed = _is_view_once_consumed(merged_item, viewer_user_id)
    has_lock = bool(merged_item.get("lock_price_cents"))
    is_unlocked = (
        viewer_user_id in (merged_item.get("unlocked_by") or {})
        or viewer_user_id == merged_item.get("sender_id")
    )
    content_hidden = expired or view_once_consumed or (has_lock and not is_unlocked)

    deliver_at = int(merged_item.get("deliver_at", 0)) or None

    text = None if content_hidden else merged_item.get("text")
    raw_image = None if content_hidden else merged_item.get("image")

    # For single locked images with a blurred preview: when content is hidden due to lock
    # (not expiry or view-once consumption), show the preview image instead of nothing.
    if (content_hidden and has_lock and not is_unlocked and not expired and not view_once_consumed
            and merged_item.get("kind") == "image"
            and merged_item.get("preview_key") and merged_item.get("preview_bucket")):
        from urllib.parse import quote as _pv_url_quote
        _pv_bucket = merged_item["preview_bucket"]
        _pv_key = merged_item["preview_key"]
        _pv_url = f"/mock/s3/{_pv_bucket}/{_pv_url_quote(_pv_key, safe='/')}" if S.dev_mode else ""
        raw_image = {
            "bucket": _pv_bucket,
            "key": _pv_key,
            "content_type": merged_item.get("image", {}).get("content_type", "image/jpeg"),
            "url": _pv_url,
            "preview_url": _pv_url,
        }

    # In DEV_MODE, add a directly-accessible URL to image messages so the browser
    # can display them without needing a real AWS S3 endpoint.
    if raw_image and S.dev_mode and not raw_image.get("url"):
        from urllib.parse import quote as _url_quote
        _bucket = raw_image.get("bucket", "")
        _key = raw_image.get("key", "")
        if _bucket and _key:
            raw_image = dict(raw_image)
            raw_image["url"] = f"/mock/s3/{_bucket}/{_url_quote(_key, safe='/')}"
    image = raw_image
    raw_file = None if content_hidden else merged_item.get("file")
    # In DEV_MODE, add a directly-accessible URL to file messages (PDF, audio, video)
    # so the browser can open them without needing a real AWS S3 endpoint.
    if raw_file and S.dev_mode and not raw_file.get("url"):
        _bucket_f = raw_file.get("bucket", "")
        _key_f = raw_file.get("key", "")
        if _bucket_f and _key_f:
            from urllib.parse import quote as _url_quote_f
            raw_file = dict(raw_file)
            raw_file["url"] = f"/mock/s3/{_bucket_f}/{_url_quote_f(_key_f, safe='/')}"
    file_ = raw_file
    preview = None if content_hidden else merged_item.get("preview")

    # Gallery message projection
    free_images_out: Optional[List[Dict[str, Any]]] = None
    locked_images_out: Optional[List[Dict[str, Any]]] = None
    locked_image_count: Optional[int] = None
    if merged_item.get("kind") == "gallery":
        raw_free = merged_item.get("free_images") or []
        raw_locked = merged_item.get("locked_images") or []
        locked_image_count = len(raw_locked)
        # Free images are always visible (lock only gates locked_images)
        if not expired:
            free_images_out = [_project_gallery_image(img) for img in raw_free]
        # Locked images: visible if unlocked or sender; show preview thumbnails otherwise
        if not expired and is_unlocked:
            locked_images_out = [_project_gallery_image(img) for img in raw_locked]
        elif not expired:
            # Show blurred preview thumbnails for locked images
            locked_images_out = None  # hidden; frontend uses locked_image_count to know count

    # File share message projection
    file_share_out: Optional[Dict[str, Any]] = None
    if merged_item.get("kind") == "file_share":
        raw_fs = merged_item.get("file_share") or {}
        file_share_out = {
            "path": raw_fs.get("path"),
            "name": raw_fs.get("name"),
            "size": int(raw_fs["size"]) if raw_fs.get("size") is not None else None,
            "content_type": raw_fs.get("content_type"),
            "permission": raw_fs.get("permission", "read"),
            "owner": raw_fs.get("owner"),
            "is_encrypted": bool(raw_fs.get("is_encrypted", False)),
        }

    calendar_share_out: Optional[Dict[str, Any]] = None
    if merged_item.get("kind") == "calendar_share":
        raw = merged_item.get("calendar_share") or {}
        calendar_share_out = {k: raw.get(k) for k in
            ["calendar_id", "name", "owner", "permission", "booking_link_id", "booking_public_url"]}

    calendar_event_out: Optional[Dict[str, Any]] = None
    if merged_item.get("kind") == "calendar_event":
        raw = merged_item.get("calendar_event") or {}
        calendar_event_out = {k: raw.get(k) for k in
            ["event_id", "calendar_id", "name", "start_utc", "end_utc", "all_day", "all_day_date", "timezone", "description", "owner"]}

    meeting_poll_out: Optional[Dict[str, Any]] = None
    if merged_item.get("kind") == "meeting_poll":
        raw = merged_item.get("meeting_poll") or {}
        meeting_poll_out = {k: raw.get(k) for k in
            ["poll_id", "creator_id", "title", "duration_minutes", "status", "confirmed_slot_id"]}

    # Find-a-DateTime message projection (MSG-009)
    find_datetime_out: Optional[Dict[str, Any]] = None
    if merged_item.get("kind") == "find_datetime":
        raw = merged_item.get("find_datetime") or {}
        find_datetime_out = {
            "poll_id": raw.get("poll_id"),
            "creator_id": raw.get("creator_id"),
            "title": raw.get("title"),
            "from_date": raw.get("from_date"),
            "to_date": raw.get("to_date"),
            "start_hour": int(raw["start_hour"]) if raw.get("start_hour") is not None else None,
            "end_hour": int(raw["end_hour"]) if raw.get("end_hour") is not None else None,
            "slot_duration_minutes": int(raw["slot_duration_minutes"]) if raw.get("slot_duration_minutes") is not None else None,
            "status": raw.get("status"),
        }

    # Video share message projection
    video_share_out: Optional[Dict[str, Any]] = None
    if merged_item.get("kind") == "video_share":
        raw_vs = merged_item.get("video_share") or {}
        vid = raw_vs.get("video_id")
        hls_url = None
        playback_token = None
        playback_expires_at = None
        if vid and viewer_user_id:
            try:
                from app.services.video_metadata_store import get_video as _vs_get
                vr = _vs_get(vid)
                hls_url = vr.hls_manifest_url
                from app.services.playback_entitlements import issue_playback_entitlement
                ttl = getattr(S, "video_share_playback_token_ttl_seconds", 300) or 300
                ent = issue_playback_entitlement(
                    tenant_id=vr.owner_user_id,
                    asset_id=vr.id,
                    session_id=f"msg_{viewer_user_id}",
                    device_id="browser",
                    profile="auto",
                    audience="playback",
                    ttl_seconds=ttl,
                )
                playback_token = ent.get("token")
                playback_expires_at = ent.get("expires_at_epoch")
            except Exception:
                pass
        video_share_out = {
            "video_id": raw_vs.get("video_id"),
            "owner_user_id": raw_vs.get("owner_user_id"),
            "title": raw_vs.get("title"),
            "thumbnail_url": raw_vs.get("thumbnail_url"),
            "duration_seconds": float(raw_vs["duration_seconds"]) if raw_vs.get("duration_seconds") else None,
            "width": int(raw_vs["width"]) if raw_vs.get("width") else None,
            "height": int(raw_vs["height"]) if raw_vs.get("height") else None,
            "visibility": raw_vs.get("visibility"),
            "drm_enabled": bool(raw_vs.get("drm_enabled", False)),
            "hls_manifest_url": hls_url,
            "playback_token": playback_token,
            "playback_expires_at": playback_expires_at,
        }

    # Voice message projection
    voice_message_out: Optional[Dict[str, Any]] = None
    if merged_item.get("kind") == "voice_message" and not content_hidden:
        from urllib.parse import quote as _vm_url_quote
        _vm_s3_key = str(merged_item.get("audio_url") or "")
        _vm_audio_url = ""
        if _vm_s3_key:
            if S.dev_mode:
                _vm_audio_url = f"/mock/s3/{S3_BUCKET_IMAGES}/{_vm_url_quote(_vm_s3_key, safe='/')}"
            else:
                _vm_audio_url = _vm_s3_key  # In prod, generate presigned URL as needed
        raw_waveform = merged_item.get("waveform_data") or []
        voice_message_out = {
            "audio_url": _vm_audio_url,
            "audio_content_type": merged_item.get("audio_content_type"),
            "audio_size_bytes": int(merged_item.get("audio_size_bytes", 0)),
            "duration_seconds": float(merged_item.get("duration_seconds", 0)),
            "waveform_data": [float(v) for v in raw_waveform],
        }

    # Voicemail projection (CALL-014)
    voicemail_out: Optional[Dict[str, Any]] = None
    if merged_item.get("kind") == "voicemail" and not content_hidden:
        from urllib.parse import quote as _vml_url_quote
        _vml_mode = str(merged_item.get("voicemail_mode") or "audio")
        _vml_media_url = ""
        if _vml_mode == "video":
            _vml_s3_key = str(merged_item.get("video_url") or "")
        else:
            _vml_s3_key = str(merged_item.get("audio_url") or "")
        if _vml_s3_key:
            if S.dev_mode:
                _vml_media_url = f"/mock/s3/{S3_BUCKET_IMAGES}/{_vml_url_quote(_vml_s3_key, safe='/')}"
            else:
                _vml_media_url = _vml_s3_key
        raw_waveform_vm = merged_item.get("waveform_data") or []
        voicemail_out = {
            "call_id": str(merged_item.get("call_id") or ""),
            "mode": _vml_mode,
            "audio_url": _vml_media_url if _vml_mode == "audio" else None,
            "video_url": _vml_media_url if _vml_mode == "video" else None,
            "content_type": merged_item.get("audio_content_type") or merged_item.get("video_content_type"),
            "size_bytes": int(merged_item.get("audio_size_bytes") or merged_item.get("video_size_bytes") or 0),
            "duration_seconds": float(merged_item.get("duration_seconds", 0)),
            "waveform_data": [float(v) for v in raw_waveform_vm],
            "call_state": str(merged_item.get("call_state") or ""),
            "caller_user_id": str(merged_item.get("caller_user_id") or ""),
            "callee_user_id": str(merged_item.get("callee_user_id") or ""),
        }

    # Countdown message projection (MSG-010)
    countdown_title_out: Optional[str] = None
    countdown_target_out: Optional[int] = None
    countdown_event_type_out: Optional[str] = None
    countdown_event_id_out: Optional[str] = None
    if merged_item.get("kind") == "countdown":
        countdown_title_out = merged_item.get("countdown_title")
        if merged_item.get("target_datetime") is not None:
            countdown_target_out = int(merged_item["target_datetime"])
        countdown_event_type_out = merged_item.get("associated_event_type")
        countdown_event_id_out = merged_item.get("associated_event_id")

    # GIF / Sticker message projection (MSG-008)
    gif_url_out: Optional[str] = None
    gif_alt_text_out: Optional[str] = None
    gif_width_out: Optional[int] = None
    gif_height_out: Optional[int] = None
    gif_provider_out: Optional[str] = None
    sticker_id_out: Optional[str] = None
    sticker_collection_id_out: Optional[str] = None
    sticker_url_out: Optional[str] = None
    sticker_alt_text_out: Optional[str] = None
    if merged_item.get("kind") == "gif":
        gif_url_out = merged_item.get("gif_url")
        gif_alt_text_out = merged_item.get("gif_alt_text") or ""
        gif_width_out = int(merged_item.get("gif_width") or 0)
        gif_height_out = int(merged_item.get("gif_height") or 0)
        gif_provider_out = merged_item.get("gif_provider") or "mock"
    elif merged_item.get("kind") == "sticker":
        sticker_id_out = merged_item.get("sticker_id")
        sticker_collection_id_out = merged_item.get("sticker_collection_id")
        sticker_url_out = merged_item.get("sticker_url")
        sticker_alt_text_out = merged_item.get("sticker_alt_text") or ""

    thread_id_value = str(merged_item.get(MESSAGE_FIELD_THREAD_ID) or "").strip()
    has_thread = False
    thread_reply_count: Optional[int] = None
    thread_last_reply_at: Optional[int] = None
    if thread_id_value:
        thread_count, thread_last_reply_at = _thread_summary(conversation_id, thread_id_value)
        thread_reply_count = max(thread_count - 1, 0)
        has_thread = thread_reply_count > 0

    return MessageOut(
        conversation_id=merged_item["conversation_id"],
        message_id=merged_item["message_id"],
        sender_id=projected_sender_id,
        created_at=int(merged_item["created_at"]),
        kind=merged_item["kind"],
        text=text,
        image=image,
        file=file_,
        file_share=file_share_out,
        calendar_share=calendar_share_out,
        calendar_event=calendar_event_out,
        meeting_poll=meeting_poll_out,
        find_datetime=find_datetime_out,
        video_share=video_share_out,
        voice_message=voice_message_out,
        voicemail=voicemail_out,
        countdown_title=countdown_title_out,
        target_datetime=countdown_target_out,
        associated_event_type=countdown_event_type_out,
        associated_event_id=countdown_event_id_out,
        gif_url=gif_url_out,
        gif_alt_text=gif_alt_text_out,
        gif_width=gif_width_out,
        gif_height=gif_height_out,
        gif_provider=gif_provider_out,
        sticker_id=sticker_id_out,
        sticker_collection_id=sticker_collection_id_out,
        sticker_url=sticker_url_out,
        sticker_alt_text=sticker_alt_text_out,
        lottery=lottery_out,
        preview=preview,
        free_images=free_images_out,
        locked_images=locked_images_out,
        locked_image_count=locked_image_count,
        reply_to_message_id=merged_item.get(MESSAGE_FIELD_REPLY_TO_ID),
        parent_message_id=merged_item.get(MESSAGE_FIELD_PARENT_ID),
        thread_id=merged_item.get(MESSAGE_FIELD_THREAD_ID),
        thread_root_message_id=merged_item.get(MESSAGE_FIELD_THREAD_ROOT_ID),
        has_thread=has_thread,
        thread_reply_count=thread_reply_count,
        thread_last_reply_at=thread_last_reply_at,
        forwarded_from=merged_item.get("forwarded_from"),
        forward_note=merged_item.get("forward_note"),
        edited_at=int(merged_item.get("edited_at", 0)) or None,
        edited_by=merged_item.get("edited_by"),
        revoked_at=int(merged_item.get("revoked_at", 0)) or None,
        revoked_by=merged_item.get("revoked_by"),
        reactions_counts=counts if counts else None,
        my_reactions=mine if mine else None,
        is_encrypted=bool(merged_item.get("is_encrypted")),
        encryption=merged_item.get("encryption"),
        consumption_policy=policy,
        media_kind=media_kind,
        consumption_state=consumption_state,
        consumed_at=consumed_at,
        scheduled=merged_item.get("status") == "scheduled",
        deliver_at=deliver_at,
        tip_amount_cents=int(merged_item["tip_amount_cents"]) if merged_item.get("tip_amount_cents") else None,
        tip_currency=merged_item.get("tip_currency"),
        tip_payment_id=merged_item.get("tip_payment_id"),
        expires_at=int(merged_item["expires_at"]) if merged_item.get("expires_at") else None,
        view_once=bool(merged_item.get("view_once")),
        expired=expired,
        locked=has_lock,
        lock_price_cents=int(merged_item["lock_price_cents"]) if merged_item.get("lock_price_cents") else None,
        lock_description=merged_item.get("lock_description"),
        is_unlocked=is_unlocked,
        sender_type=merged_item.get("sender_type"),
        bot_id=merged_item.get("bot_id"),
        bot_name=merged_item.get("bot_name"),
        bot_avatar_url=merged_item.get("bot_avatar_url"),
        quick_replies=merged_item.get("quick_replies") or None,
    )


def _serialize_message_event_payload(message_item: dict, viewer_user_id: str) -> dict:
    """Serialize a message item to a JSON-safe event payload."""
    return _message_out_from_item(message_item, viewer_user_id).model_dump(exclude_none=True)


def _thread_summary(conversation_id: str, thread_id: str) -> tuple[int, Optional[int]]:
    count = 0
    last_created_at: Optional[int] = None
    query_kwargs: Dict[str, Any] = {
        "IndexName": "ByThreadCreatedAt",
        "KeyConditionExpression": Key(MESSAGE_FIELD_THREAD_ID).eq(thread_id),
        "ScanIndexForward": True,
    }
    while True:
        resp = tbl_msgs.query(**query_kwargs)
        for item in resp.get("Items", []):
            if str(item.get("conversation_id") or "") != conversation_id:
                continue
            count += 1
            created_at = int(item.get("created_at") or 0)
            if created_at and (last_created_at is None or created_at > last_created_at):
                last_created_at = created_at
        lek = resp.get("LastEvaluatedKey")
        if not lek:
            break
        query_kwargs["ExclusiveStartKey"] = lek
    return count, last_created_at


def _project_message_sender_id(*, message_item: dict, viewer_user_id: str, conversation_id: str) -> str:
    sender_id = str(message_item.get("sender_id") or "")
    if not sender_id:
        return sender_id
    try:
        convo = _get_conversation_or_404(conversation_id)
    except Exception:
        return sender_id
    if str(convo.get("routing_mode") or "") != "helpdesk_bridge":
        return sender_id
    group_id = str(convo.get("routing_group_id") or "")
    if not group_id:
        return sender_id
    viewer_is_helpdesk_agent = _is_helpdesk_group_member(group_id, viewer_user_id)
    if viewer_is_helpdesk_agent:
        return sender_id
    sender_is_helpdesk_agent = _is_helpdesk_group_member(group_id, sender_id)
    if sender_is_helpdesk_agent:
        return HELPDESK_MASKED_SENDER_ID
    return sender_id


def _project_event_for_user(event_item: dict, user_id: str) -> dict:
    out = dict(event_item or {})
    event_type = str(out.get("type") or "")
    if event_type in HELPDESK_ROUTING_LIFECYCLE_EVENT_TYPES:
        payload = out.get("payload")
        if isinstance(payload, dict):
            convo_id = str(payload.get("conversation_id") or out.get("conversation_id") or "")
            if convo_id:
                try:
                    convo = _get_conversation_or_404(convo_id)
                    out_payload = _project_helpdesk_lifecycle_payload_for_user(
                        payload=payload,
                        conversation=convo,
                        user_id=user_id,
                    )
                    out["payload"] = out_payload
                except Exception:
                    return out
        return out
    if event_type != "message:new":
        return out
    payload = out.get("payload")
    if not isinstance(payload, dict):
        return out
    message_payload = payload.get("message")
    if not isinstance(message_payload, dict):
        return out
    conversation_id = str(message_payload.get("conversation_id") or out.get("conversation_id") or "")
    message_id = str(message_payload.get("message_id") or "")
    if not conversation_id or not message_id:
        return out
    try:
        message_item = _get_message_or_404(conversation_id, message_id)
    except Exception:
        return out
    payload_out = dict(payload)
    payload_out["message"] = _serialize_message_event_payload(message_item, user_id)
    out["payload"] = payload_out
    return out


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


_INDEX_QUERY_LIMIT = 200
# Minimum token length to use for intersection.  Tokens shorter than this are
# prefix/ngram helpers that match too many messages to be useful as an AND filter.
_MIN_INTERSECTION_TOKEN_LEN = 4


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
            kwargs: Dict[str, Any] = {
                "KeyConditionExpression": Key("token").eq(token),
                "Limit": _INDEX_QUERY_LIMIT,
            }
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
                # Skip intersection for tokens that are too short (too common) or
                # whose result set was truncated by the query limit (unreliable for AND).
                # DynamoDB sets LastEvaluatedKey when more items exist beyond the Limit.
                truncated = "LastEvaluatedKey" in resp
                if len(token) < _MIN_INTERSECTION_TOKEN_LEN or truncated:
                    continue
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


def _is_helpdesk_agent_viewer(convo: dict, user_id: str) -> bool:
    if str(convo.get("routing_mode") or "") != "helpdesk_bridge":
        return False
    group_id = str(convo.get("routing_group_id") or "")
    if not group_id:
        return False
    return _is_helpdesk_group_member(group_id, user_id)


def _find_existing_dm(user_sub: str, target_sub: str) -> Optional[str]:
    """Return conversation_id of an existing DM between user_sub and target_sub, or None."""
    dm_conv_ids: List[str] = []
    last_key = None
    while True:
        kwargs: Dict[str, Any] = {
            "KeyConditionExpression": Key("user_id").eq(user_sub),
            "Limit": 500,
        }
        if last_key:
            kwargs["ExclusiveStartKey"] = last_key
        resp = tbl_parts.query(**kwargs)
        for item in resp.get("Items", []):
            if item.get("conv_type") == "dm" or True:
                # We need to check the conversation type from tbl_convos; collect all
                dm_conv_ids.append(item["conversation_id"])
        last_key = resp.get("LastEvaluatedKey")
        if not last_key or len(dm_conv_ids) >= 2000:
            break

    if not dm_conv_ids:
        return None

    # Filter to only DM conversations (type == "dm")
    # We batch-check which of these cids the target is also a participant in
    batch_size = 100
    for i in range(0, len(dm_conv_ids), batch_size):
        chunk = dm_conv_ids[i:i + batch_size]
        keys = [{"user_id": target_sub, "conversation_id": cid} for cid in chunk]
        resp = ddb.batch_get_item(RequestItems={tbl_parts.name: {"Keys": keys}})
        hits = resp.get("Responses", {}).get(tbl_parts.name, [])
        for hit in hits:
            cid = hit["conversation_id"]
            # Verify it's a DM
            convo_item = tbl_convos.get_item(Key={"conversation_id": cid}).get("Item")
            if convo_item and convo_item.get("type") == "dm":
                return cid

    return None


def _get_latest_active_pin(conversation_id: str) -> Optional[dict]:
    try:
        resp = T.conversation_pins.query(
            IndexName="ByConversationActivePinnedAt",
            KeyConditionExpression=Key("conversation_active").eq(f"{conversation_id}#1"),
            ScanIndexForward=False,
            Limit=1,
        )
    except Exception:
        return None

    items = resp.get("Items", [])
    if not items:
        return None
    pin = items[0]
    return {
        "message_id": str(pin.get("message_id") or ""),
        "pinned_by_user_id": str(pin.get("pinned_by_user_id") or ""),
        "pinned_at": int(pin.get("pinned_at", 0) or 0),
    }


def _conversation_out_from_items(*, conversation_id: str, convo: dict, participant: dict, viewer_user_id: str) -> ConversationOut:
    latest_pin = _get_latest_active_pin(conversation_id)

    out = ConversationOut(
        conversation_id=conversation_id,
        type=convo.get("type", "dm"),
        latest_pinned_message_id=(latest_pin or {}).get("message_id") or None,
        latest_pinned_by_user_id=(latest_pin or {}).get("pinned_by_user_id") or None,
        latest_pinned_at=int((latest_pin or {}).get("pinned_at", 0) or 0) or None,
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
        status=participant.get("status", "pending"),
        muted_until=int(participant.get("muted_until", 0) or 0),
        last_read_at=int(participant.get("last_read_at", 0) or 0),
        unread_count=int(participant.get("unread_count", 0) or 0),
    )
    raw_routing_mode = str(convo.get("routing_mode") or "")
    if raw_routing_mode == "helpdesk_bridge":
        # Always expose routing_mode to all participants so the UI can identify
        # the conversation as a helpdesk chat (e.g. customer "Your Support Chats" view).
        out.routing_mode = raw_routing_mode
    if _is_helpdesk_agent_viewer(convo, viewer_user_id):
        out.routing_group_id = str(convo.get("routing_group_id") or "")
        out.routing_state = str(convo.get("routing_state") or "")
        out.active_agent_user_id = str(convo.get("active_agent_user_id") or "")
        out.active_agent_claimed_at = int(convo.get("active_agent_claimed_at", 0) or 0)
        out.assignment_version = int(convo.get("assignment_version", 0) or 0)
    return out


def _enrich_participant_out(p: dict, profile_cache: Dict[str, Any]) -> "ParticipantOut":
    pid = p["user_id"]
    if pid not in profile_cache:
        try:
            profile_cache[pid] = get_profile_identity(pid)
        except Exception:
            profile_cache[pid] = {}
    identity = profile_cache[pid]
    display_name = identity.get("display_name")
    if not display_name:
        display_name = tbl_users.get_item(Key={"user_id": pid}).get("Item", {}).get("display_name")
    return ParticipantOut(
        user_id=pid,
        status=p.get("status", "pending"),
        role=p.get("role", "member"),
        muted_until=int(p.get("muted_until", 0) or 0),
        last_read_at=int(p.get("last_read_at", 0) or 0),
        joined_at=int(p.get("joined_at", 0) or 0),
        left_at=int(p.get("left_at", 0) or 0),
        display_name=display_name or None,
        profile_photo_url=identity.get("profile_photo_url") or None,
    )


def _get_conversation_participants_enriched(conversation_id: str, profile_cache: Dict[str, Any]) -> List["ParticipantOut"]:
    items = tbl_parts.query(
        IndexName="GSI1",
        KeyConditionExpression=Key("GSI1PK").eq(conversation_id),
        Limit=50,
    ).get("Items", [])
    return [_enrich_participant_out(p, profile_cache) for p in items if p.get("status") != "left"]


def _helpdesk_lifecycle_event_payload(*, conversation: Mapping[str, Any], event_item: Mapping[str, Any]) -> dict:
    return {
        "schema_version": HELPDESK_ROUTING_EVENT_SCHEMA_VERSION,
        "conversation_id": str(event_item.get("conversation_id") or conversation.get("conversation_id") or ""),
        "event_id": str(event_item.get("event_id") or ""),
        "event_type": str(event_item.get("event_type") or ""),
        "occurred_at": int(event_item.get("created_at", 0) or 0),
        "routing_group_id": str(event_item.get("routing_group_id") or conversation.get("routing_group_id") or ""),
        "from_state": str(event_item.get("from_state") or ""),
        "to_state": str(event_item.get("to_state") or ""),
        "routing_state": str(conversation.get("routing_state") or ""),
        "assignment_version": int(event_item.get("assignment_version", 0) or conversation.get("assignment_version", 0) or 0),
        "active_agent_user_id": str(conversation.get("active_agent_user_id") or event_item.get("active_agent_user_id") or ""),
        "metadata": event_item.get("metadata", {}) if isinstance(event_item.get("metadata"), dict) else {},
    }




def _is_helpdesk_authorized_for_conversation(conversation: Mapping[str, Any], user_id: str) -> bool:
    if str(conversation.get("routing_mode") or "") != "helpdesk_bridge":
        return False
    group_id = str(conversation.get("routing_group_id") or "")
    if not group_id:
        return False
    return _is_helpdesk_group_member(group_id, user_id)


def _project_helpdesk_lifecycle_payload_for_user(*, payload: Mapping[str, Any], conversation: Mapping[str, Any], user_id: str) -> dict:
    out = dict(payload or {})
    if _is_helpdesk_authorized_for_conversation(conversation, user_id):
        return out
    out["active_agent_user_id"] = ""
    out["metadata"] = {}
    return out

def _helpdesk_lifecycle_recipients(conversation_id: str, actor_user_id: str) -> list[str]:
    recipients: list[str] = []
    try:
        participants = tbl_parts.query(IndexName="GSI1", KeyConditionExpression=Key("GSI1PK").eq(conversation_id), Limit=500).get("Items", [])
    except Exception:
        participants = []
    for part in participants:
        if part.get("status") == "active":
            uid = str(part.get("user_id") or "")
            if uid and not uid.startswith("helpdesk_group:"):
                recipients.append(uid)
    if actor_user_id:
        recipients.append(str(actor_user_id))
    return list(dict.fromkeys(recipients))


def _fanout_helpdesk_lifecycle_event(*, conversation: Mapping[str, Any], event_item: Mapping[str, Any], actor_user_id: str) -> None:
    event_type = str(event_item.get("event_type") or "")
    if event_type not in HELPDESK_ROUTING_LIFECYCLE_EVENT_TYPES:
        return
    conversation_id = str(conversation.get("conversation_id") or event_item.get("conversation_id") or "")
    if not conversation_id:
        return
    payload = _helpdesk_lifecycle_event_payload(conversation=conversation, event_item=event_item)
    ts = int(event_item.get("created_at", now_ts()) or now_ts())
    ttl = ts + 7 * 24 * 3600
    recipients = _helpdesk_lifecycle_recipients(conversation_id, actor_user_id)
    for uid in recipients:
        projected_payload = _project_helpdesk_lifecycle_payload_for_user(
            payload=payload,
            conversation=conversation,
            user_id=uid,
        )
        try:
            tbl_events.put_item(
                Item={
                    "user_id": uid,
                    "event_id": f"routing#{conversation_id}#{event_item.get('event_id','')}#{uid}",
                    "type": event_type,
                    "created_at": ts,
                    "conversation_id": conversation_id,
                    "payload": projected_payload,
                    "ttl": ttl,
                },
                ConditionExpression="attribute_not_exists(event_id)",
            )
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
                continue
            logger.exception("failed to fanout helpdesk lifecycle event", extra={"conversation_id": conversation_id, "event_type": event_type, "user_id": uid})
        except Exception:
            logger.exception("failed to fanout helpdesk lifecycle event", extra={"conversation_id": conversation_id, "event_type": event_type, "user_id": uid})

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

    routing_event_type = str(event_item.get("event_type") or "")
    if routing_event_type in {"helpdesk.conversation.assigned", "helpdesk.conversation.released"}:
        assignment_kind = "assigned" if routing_event_type.endswith("assigned") else "released"
        assignment_target_user = str(event_item.get("active_agent_user_id") or actor_user_id)
        if assignment_target_user:
            emit_messaging_archive_event(
                event_id=f"assignment_{conversation_id}_{event_item.get('event_id','')}",
                event_ts=event_created_at,
                tenant_id="default",
                conversation_id=conversation_id,
                message_id=f"membership_{assignment_target_user}",
                actor_user_id=actor_user_id,
                effective_user_id=assignment_target_user,
                event_type="conversation.role_changed",
                payload={
                    "transition": "assignment_changed",
                    "assignment": assignment_kind,
                    "subject_user_id": assignment_target_user,
                    "routing_event_id": str(event_item.get("event_id") or ""),
                    "routing_event_type": routing_event_type,
                    "from_state": str(event_item.get("from_state") or ""),
                    "to_state": str(event_item.get("to_state") or ""),
                    "assignment_version": int(event_item.get("assignment_version", 0) or 0),
                    "timeline_state": {
                        "routing_state": str(event_item.get("routing_state") or ""),
                        "occurred_at": int(event_item.get("created_at", event_created_at) or event_created_at),
                    },
                },
            )

    _fanout_helpdesk_lifecycle_event(conversation=convo, event_item=event_item, actor_user_id=actor_user_id)
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


def _send_single_destination_message(
    *,
    conversation_id: str,
    sender_id: str,
    message_id: str,
    created_at: int,
    message_item: dict[str, Any],
    participants: Sequence[dict],
    is_scheduled: bool,
    preview_text: str,
    search_text: str | None = None,
    search_kind: str | None = None,
    consumption_policy: str = CONSUMPTION_POLICY_NONE,
    media_kind: str | None = None,
) -> None:
    """Apply single-destination send side effects shared by API sends and mass fanout workers."""
    if is_scheduled:
        return

    _bump_unread_counts(conversation_id, sender_id, participants)
    _record_delivery_receipts(conversation_id, message_id, sender_id, participants)

    if search_text is not None and search_kind:
        index_message_search(conversation_id, message_id, sender_id, created_at, search_text, kind=search_kind)

    if consumption_policy != CONSUMPTION_POLICY_NONE and media_kind:
        _put_message_consumption_records(
            conversation_id=conversation_id,
            message_id=message_id,
            sender_id=sender_id,
            participants=participants,
            consumption_policy=consumption_policy,
            media_kind=media_kind,
            created_at=created_at,
        )

    tbl_convos.update_item(
        Key={"conversation_id": conversation_id},
        UpdateExpression="SET last_message_at = :ts, last_message_preview = :p, last_message_id = :mid",
        ExpressionAttributeValues={":ts": created_at, ":p": preview_text, ":mid": message_id},
    )

    fanout_event_to_conversation(
        conversation_id=conversation_id,
        sender_id=sender_id,
        event_type="message:new",
        payload={
            "message_id": message_id,
            "created_at": created_at,
            "message": _serialize_message_event_payload(message_item, sender_id),
        },
        respect_mute=False,
    )


def _send_mass_message_destination(
    *,
    conversation_id: str,
    sender_id: str,
    message_id: str,
    created_at: int,
    message_item: dict[str, Any],
    participants: Sequence[dict],
    preview_text: str,
) -> None:
    """Worker-facing shim for mass fanout destinations using shared single-send helper."""
    _send_single_destination_message(
        conversation_id=conversation_id,
        sender_id=sender_id,
        message_id=message_id,
        created_at=created_at,
        message_item=message_item,
        participants=participants,
        is_scheduled=False,
        preview_text=preview_text,
        search_text=str(message_item.get("text") or "") if message_item.get("kind") == "text" else None,
        search_kind="text" if message_item.get("kind") == "text" else None,
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


class _DecimalEncoder(json.JSONEncoder):
    def default(self, o):
        from decimal import Decimal as _Decimal
        if isinstance(o, _Decimal):
            return float(o) if o % 1 else int(o)
        return super().default(o)


def _sse_pack(data: dict, event: str = "message") -> str:
    return f"event: {event}\ndata: {json.dumps(data, separators=(',', ':'), cls=_DecimalEncoder)}\n\n"


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




def _normalize_presence_status(status: Optional[str]) -> str:
    value = str(status or "online").strip().lower()
    if value in {"online", "available", "offline", "unavailable"}:
        return value
    return "online"


def _assigned_helpdesk_conversations_for_agent(user_id: str) -> list[dict]:
    try:
        parts = tbl_parts.query(KeyConditionExpression=Key("user_id").eq(user_id), Limit=500).get("Items", [])
    except Exception:
        return []
    out: list[dict] = []
    for part in parts:
        cid = str(part.get("conversation_id") or "")
        if not cid:
            continue
        try:
            convo = _get_conversation_or_404(cid)
        except HTTPException:
            continue
        if str(convo.get("routing_mode") or "") != "helpdesk_bridge":
            continue
        if str(convo.get("routing_state") or "") != "assigned":
            continue
        if str(convo.get("active_agent_user_id") or "") != user_id:
            continue
        out.append(convo)
    return out




def _helpdesk_groups_for_agent(user_id: str) -> list[str]:
    uid = str(user_id or "").strip()
    if not uid:
        return []
    groups: list[str] = []
    if HELPDESK_GROUP_MEMBERS_JSON:
        try:
            raw = json.loads(HELPDESK_GROUP_MEMBERS_JSON)
            if isinstance(raw, dict):
                for gid, members in raw.items():
                    if not isinstance(members, list):
                        continue
                    if uid in {str(v).strip() for v in members}:
                        groups.append(str(gid).strip())
        except Exception:
            logger.exception("failed to parse HELPDESK_GROUP_MEMBERS_JSON")

    try:
        user = tbl_users.get_item(Key={"user_id": uid}).get("Item") or {}
    except Exception:
        user = {}
    declared_groups = user.get("helpdesk_groups")
    if isinstance(declared_groups, list):
        groups.extend(str(v).strip() for v in declared_groups if str(v).strip())

    return list(dict.fromkeys([g for g in groups if g]))


def _paused_helpdesk_conversations_for_groups(group_ids: Sequence[str]) -> list[dict]:
    groups = [str(g).strip() for g in group_ids if str(g).strip()]
    if not groups:
        return []
    items: list[dict] = []
    for gid in groups:
        pk = f"paused_no_agents_online#{gid}"
        try:
            resp = tbl_convos.scan(FilterExpression=Attr("routing_state_group_pk").eq(pk), Limit=200)
            items.extend(resp.get("Items", []))
            while resp.get("LastEvaluatedKey"):
                resp = tbl_convos.scan(
                    FilterExpression=Attr("routing_state_group_pk").eq(pk),
                    Limit=200,
                    ExclusiveStartKey=resp["LastEvaluatedKey"],
                )
                items.extend(resp.get("Items", []))
        except Exception:
            logger.exception("failed to scan paused helpdesk conversations", extra={"group_id": gid})
    dedup: dict[str, dict] = {}
    for item in items:
        cid = str(item.get("conversation_id") or "")
        if cid:
            dedup[cid] = item
    return list(dedup.values())

def _handle_helpdesk_presence_event(*, user_id: str, status: str, ts: int) -> dict:
    processed = 0
    transitioned = 0
    failed = 0
    action = "none"
    if status in {"offline", "unavailable"}:
        action = "release_assigned"
        conversations = _assigned_helpdesk_conversations_for_agent(user_id)
        processed = len(conversations)
        for convo in conversations:
            record_helpdesk_failover("assignee_disconnect")
            cid = str(convo.get("conversation_id") or "")
            version = int(convo.get("assignment_version") or 0)
            try:
                release_result = _apply_helpdesk_routing_transition(
                    conversation_id=cid,
                    cmd=RoutingTransitionInput(
                        action="release_agent",
                        now_ts=ts,
                        agent_user_id=user_id,
                        expected_assignment_version=version,
                    ),
                    actor_user_id=user_id,
                    metadata={"reason": "presence_status_change", "status": status},
                )
                transitioned += 1
                released_convo = release_result.get("conversation", {}) if isinstance(release_result, dict) else {}
                group_id = str(released_convo.get("routing_group_id") or convo.get("routing_group_id") or "")
                if group_id:
                    delivered = fanout_helpdesk_alert(conversation_id=cid, group_id=group_id, created_by=user_id)
                    if delivered > 0:
                        _apply_helpdesk_routing_transition(
                            conversation_id=cid,
                            cmd=RoutingTransitionInput(
                                action="alert_awaiting",
                                now_ts=ts,
                                expected_assignment_version=int(released_convo.get("assignment_version") or 0),
                            ),
                            actor_user_id=user_id,
                            metadata={"reason": "presence_realert", "status": status, "delivered": delivered},
                        )
                    else:
                        _emit_no_agents_online_notice(conversation_id=cid, user_id=user_id, now=ts)
            except RoutingTransitionError as exc:
                if exc.code in {"routing_release_invalid_state", "routing_assignment_version_conflict", "routing_release_agent_mismatch"}:
                    continue
                failed += 1
            except Exception:
                failed += 1
                logger.exception("helpdesk presence routing transition failed", extra={"conversation_id": cid, "user_id": user_id, "status": status})

    elif status in {"online", "available"}:
        action = "resume_paused"
        groups = _helpdesk_groups_for_agent(user_id)
        paused = _paused_helpdesk_conversations_for_groups(groups)
        processed = len(paused)
        for convo in paused:
            cid = str(convo.get("conversation_id") or "")
            version = int(convo.get("assignment_version") or 0)
            gid = str(convo.get("routing_group_id") or "")
            try:
                _apply_helpdesk_routing_transition(
                    conversation_id=cid,
                    cmd=RoutingTransitionInput(
                        action="resume_awaiting",
                        now_ts=ts,
                        expected_assignment_version=version,
                    ),
                    actor_user_id=user_id,
                    metadata={"reason": "presence_available", "status": status},
                )
                transitioned += 1
                if gid:
                    fanout_helpdesk_alert(conversation_id=cid, group_id=gid, created_by=user_id)
            except RoutingTransitionError as exc:
                if exc.code in {"routing_resume_invalid_state", "routing_assignment_version_conflict"}:
                    continue
                failed += 1
            except Exception:
                failed += 1
                logger.exception("helpdesk presence resume transition failed", extra={"conversation_id": cid, "user_id": user_id, "status": status})

    return {
        "action": action,
        "processed": processed,
        "transitioned": transitioned,
        "failed": failed,
    }


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
                "schema_version": HELPDESK_ROUTING_EVENT_SCHEMA_VERSION,
                "conversation_id": conversation_id,
                "event_id": _helpdesk_alert_event_id(conversation_id, uid),
                "event_type": "helpdesk.conversation.alerted",
                "occurred_at": ts,
                "routing_group_id": group_id,
                "from_state": "awaiting_agent",
                "to_state": "awaiting_agent",
                "routing_state": "awaiting_agent",
                "assignment_version": 0,
                "active_agent_user_id": "",
                "metadata": {"created_by": created_by},
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
        record_helpdesk_no_agents_notice("throttled")
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
    record_helpdesk_no_agents_notice("sent")
    return True




def _ddb_safe(value: Any) -> Any:
    """Recursively convert Python float to Decimal for DynamoDB compatibility."""
    from decimal import Decimal as _DdbDec
    if isinstance(value, float):
        return _DdbDec(str(value))
    if isinstance(value, dict):
        return {k: _ddb_safe(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_ddb_safe(v) for v in value]
    return value


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
    safe_payload = _ddb_safe(payload)

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
                    "payload": safe_payload,
                    "ttl": ttl,
                }
            )


def _fanout_new_message_event(
    *,
    conversation_id: str,
    sender_id: str,
    message_item: dict,
    payload: dict,
    respect_mute: bool = False,
) -> None:
    thread_id = str(message_item.get(MESSAGE_FIELD_THREAD_ID) or "").strip()
    thread_root_message_id = str(message_item.get(MESSAGE_FIELD_THREAD_ROOT_ID) or "").strip()
    event_type = "message:thread_new" if thread_id else "message:new"
    enriched_payload = dict(payload)
    if thread_id:
        enriched_payload.setdefault("thread_id", thread_id)
        if thread_root_message_id:
            enriched_payload.setdefault("thread_root_message_id", thread_root_message_id)
        enriched_payload.setdefault("notification_scope", "thread")
    else:
        enriched_payload.setdefault("notification_scope", "conversation")

    fanout_event_to_conversation(
        conversation_id=conversation_id,
        sender_id=sender_id,
        event_type=event_type,
        payload=enriched_payload,
        respect_mute=respect_mute,
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


def _resolve_tip_recipient(conversation_id: str, sender_id: str) -> Optional[str]:
    """For DMs, return the other participant. For groups, return None.

    DM conversations have exactly 2 participants. Group conversations have 3+.
    For DMs, the tip recipient is unambiguous -- it is the other participant.
    For groups, attached tips are ambiguous (who receives them?) so this
    function returns None, and the caller should skip the ledger write.
    Post-send tips on group messages use the message author directly.
    """
    try:
        resp = tbl_parts.query(
            IndexName="GSI1",
            KeyConditionExpression=Key("GSI1PK").eq(conversation_id),
            Limit=10,
        )
        participants = resp.get("Items", [])
    except Exception:
        return None
    other_ids = [p.get("user_id") for p in participants if p.get("user_id") != sender_id]
    if len(other_ids) == 1:
        return other_ids[0]
    return None  # Group chat or error


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


def _load_message_item(conversation_id: str, message_id: str) -> Optional[dict]:
    resp = tbl_msgs.get_item(Key={"conversation_id": conversation_id, "message_id": message_id})
    return resp.get("Item")


def _resolve_thread_root_message_id(conversation_id: str, parent_message: dict) -> str:
    threaded_root = str(parent_message.get(MESSAGE_FIELD_THREAD_ROOT_ID) or "").strip()
    if threaded_root:
        return threaded_root

    cursor = str(parent_message.get("message_id") or "")
    visited: set[str] = set()
    while cursor and cursor not in visited:
        visited.add(cursor)
        current = _load_message_item(conversation_id, cursor)
        if not current:
            raise HTTPException(status_code=400, detail="Reply target ancestry is invalid")
        if str(current.get("conversation_id") or "") != conversation_id:
            raise HTTPException(status_code=400, detail="Reply target ancestry crosses conversations")
        parent_id = str(current.get(MESSAGE_FIELD_PARENT_ID) or "").strip()
        if not parent_id:
            return str(current.get("message_id") or cursor)
        cursor = parent_id
    if cursor in visited:
        raise HTTPException(status_code=400, detail="Reply target ancestry contains a cycle")
    return str(parent_message.get("message_id") or "")


def _validate_reply_parent_and_thread_context(conversation_id: str, parent_message: dict) -> None:
    parent_conversation_id = str(parent_message.get("conversation_id") or conversation_id)
    if parent_conversation_id and parent_conversation_id != conversation_id:
        raise HTTPException(status_code=400, detail="Reply target is not in this conversation")

    thread_id = str(parent_message.get(MESSAGE_FIELD_THREAD_ID) or "").strip()
    if not thread_id:
        return
    thread = get_message_thread_record(thread_id)
    if not thread:
        raise HTTPException(status_code=400, detail="Reply target thread does not exist")
    if thread.conversation_id != conversation_id:
        raise HTTPException(status_code=400, detail="Reply target thread is not in this conversation")

    declared_root = str(parent_message.get(MESSAGE_FIELD_THREAD_ROOT_ID) or "").strip()
    if declared_root and thread.root_message_id != declared_root:
        raise HTTPException(status_code=409, detail="Reply target thread root mismatch")


def _count_direct_replies(conversation_id: str, root_message_id: str) -> int:
    count = 0
    query_kwargs: Dict[str, Any] = {
        "KeyConditionExpression": Key("conversation_id").eq(conversation_id),
    }
    while True:
        resp = tbl_msgs.query(**query_kwargs)
        for item in resp.get("Items", []):
            if str(item.get(MESSAGE_FIELD_PARENT_ID) or "") == root_message_id:
                count += 1
        lek = resp.get("LastEvaluatedKey")
        if not lek:
            break
        query_kwargs["ExclusiveStartKey"] = lek
    return count


def _promote_existing_subtree(conversation_id: str, root_message_id: str, thread_id: str) -> None:
    items: List[dict] = []
    query_kwargs: Dict[str, Any] = {
        "KeyConditionExpression": Key("conversation_id").eq(conversation_id),
    }
    while True:
        resp = tbl_msgs.query(**query_kwargs)
        items.extend(resp.get("Items", []))
        lek = resp.get("LastEvaluatedKey")
        if not lek:
            break
        query_kwargs["ExclusiveStartKey"] = lek

    by_parent: Dict[str, List[str]] = {}
    by_message_id: Dict[str, dict] = {}
    for item in items:
        message_id = str(item.get("message_id") or "")
        if not message_id:
            continue
        by_message_id[message_id] = item
        parent_id = str(item.get(MESSAGE_FIELD_PARENT_ID) or "")
        if parent_id:
            by_parent.setdefault(parent_id, []).append(message_id)

    stack = [root_message_id]
    seen: set[str] = set()
    while stack:
        current = stack.pop()
        if current in seen:
            continue
        seen.add(current)
        if current in by_message_id:
            tbl_msgs.update_item(
                Key={"conversation_id": conversation_id, "message_id": current},
                UpdateExpression=f"SET {MESSAGE_FIELD_THREAD_ID} = :tid, {MESSAGE_FIELD_THREAD_ROOT_ID} = :rid",
                ExpressionAttributeValues={":tid": thread_id, ":rid": root_message_id},
            )
        stack.extend(by_parent.get(current, []))


def _deterministic_thread_id(root_message_id: str) -> str:
    return f"thr_{root_message_id}"


def _is_retryable_thread_creation_error(exc: ClientError) -> bool:
    code = str(exc.response.get("Error", {}).get("Code") or "")
    return code in {
        "TransactionCanceledException",
        "ProvisionedThroughputExceededException",
        "ThrottlingException",
        "InternalServerError",
    }


def _ensure_thread_record_for_root(
    *,
    conversation_id: str,
    root_message_id: str,
    actor_user_id: str,
    created_at: int,
    max_attempts: int = 3,
):
    thread_id = _deterministic_thread_id(root_message_id)
    for _attempt in range(max_attempts):
        existing = find_thread_for_root_message(root_message_id)
        if existing:
            record_messaging_thread_promotion_event(stage="thread_record", outcome="reused_existing")
            return existing
        try:
            created = create_message_thread_record(
                thread_id=thread_id,
                conversation_id=conversation_id,
                root_message_id=root_message_id,
                created_at=created_at,
                created_by=actor_user_id,
            )
            record_messaging_thread_promotion_event(stage="thread_record", outcome="created")
            return created
        except ClientError as exc:
            if not _is_retryable_thread_creation_error(exc):
                record_messaging_thread_promotion_event(stage="thread_record", outcome="failed_non_retryable")
                raise
            record_messaging_thread_promotion_retry(reason=str(exc.response.get("Error", {}).get("Code") or "retryable"))
            continue
    existing = find_thread_for_root_message(root_message_id)
    if existing:
        record_messaging_thread_promotion_event(stage="thread_record", outcome="reused_after_retry")
        return existing
    record_messaging_thread_promotion_event(stage="thread_record", outcome="failed_exhausted")
    raise RuntimeError(f"Failed to resolve thread record for root={root_message_id}")


def _build_reply_linkage_fields(
    *,
    conversation_id: str,
    reply_to_message_id: Optional[str],
    actor_user_id: str,
    created_at: int,
) -> Dict[str, str]:
    if not reply_to_message_id:
        return {}
    parent_message = _get_message_or_404(conversation_id, reply_to_message_id)
    _validate_reply_parent_and_thread_context(conversation_id, parent_message)
    parent_message_id = str(parent_message.get("message_id") or reply_to_message_id)
    linkage = {
        MESSAGE_FIELD_REPLY_TO_ID: parent_message_id,
        MESSAGE_FIELD_PARENT_ID: parent_message_id,
    }

    existing_thread_id = str(parent_message.get(MESSAGE_FIELD_THREAD_ID) or "")
    if existing_thread_id:
        linkage[MESSAGE_FIELD_THREAD_ID] = existing_thread_id
        linkage[MESSAGE_FIELD_THREAD_ROOT_ID] = str(parent_message.get(MESSAGE_FIELD_THREAD_ROOT_ID) or parent_message_id)
        record_messaging_thread_promotion_event(stage="linkage", outcome="reused_parent_thread")
        return linkage

    root_message_id = _resolve_thread_root_message_id(conversation_id, parent_message)
    direct_reply_count = _count_direct_replies(conversation_id, root_message_id)
    parent_is_reply = bool(parent_message.get(MESSAGE_FIELD_PARENT_ID))
    should_promote = parent_is_reply or direct_reply_count >= 1
    if not should_promote:
        record_messaging_thread_promotion_event(stage="linkage", outcome="no_promotion")
        return linkage
    if not _is_thread_promotion_enabled_for(user_id=actor_user_id):
        record_messaging_thread_promotion_event(stage="linkage", outcome="rollout_disabled")
        return linkage

    thread_record = _ensure_thread_record_for_root(
        conversation_id=conversation_id,
        root_message_id=root_message_id,
        actor_user_id=actor_user_id,
        created_at=created_at,
    )
    _promote_existing_subtree(conversation_id, root_message_id, thread_record.id)
    linkage[MESSAGE_FIELD_THREAD_ID] = thread_record.id
    linkage[MESSAGE_FIELD_THREAD_ROOT_ID] = root_message_id
    record_messaging_thread_promotion_event(stage="linkage", outcome="promoted")
    return linkage


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
    _kyc: object = Depends(require_kyc_tier(1)),  # GAP-0268 (inert unless enforcement flag on)
):
    cid = "c_" + new_id()
    created_at = now_ts()

    routing_mode = inp.routing_mode
    routing_state = "awaiting_agent" if routing_mode == "helpdesk_bridge" else "none"
    group_id = inp.helpdesk_group_id if routing_mode == "helpdesk_bridge" else ""

    if routing_mode == "helpdesk_bridge":
        if not _is_helpdesk_bridge_mode_enabled_for(user_id=user_id, group_id=group_id):
            raise HTTPException(
                403,
                detail={
                    "code": "helpdesk_bridge_mode_disabled",
                    "message": "helpdesk bridge mode is not enabled for this group/tenant",
                },
            )
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
        status = "active" if (pid == user_id or inp.type == "dm") else "pending"
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

    profile_cache: Dict[str, Any] = {}
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
    convo.participants = _get_conversation_participants_enriched(cid, profile_cache)
    for pid in participant_ids:
        participant_status = "active" if (pid == user_id or inp.type == "dm") else "pending"
        _emit_conversation_membership_archive_event_or_503(
            event_ts=created_at,
            conversation_id=cid,
            subject_user_id=pid,
            actor_user_id=user_id,
            event_type="conversation.member_joined",
            payload={
                "transition": "conversation_created",
                "subject_user_id": pid,
                "status": participant_status,
                "role": "admin" if pid == user_id else "member",
                "timeline_state": {"conversation_created_at": created_at, "participant_count": len(participant_ids)},
            },
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
    _kyc: object = Depends(require_kyc_tier(1)),  # GAP-0268 (inert unless enforcement flag on)
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


@router.post("/conversations/dm/find-or-create", response_model=ConversationOut)
def find_or_create_dm(inp: FindOrCreateDmIn, req: Request = None, user_id: str = Depends(get_messaging_user_id)):
    """Find an existing DM with the target user or create a new one."""
    target_sub = inp.user_id
    if user_id == target_sub:
        raise HTTPException(400, "Cannot DM yourself")

    # Block enforcement: prevent DM creation between blocked users
    from app.services.blocking import is_any_block
    if is_any_block(user_id, target_sub):
        raise HTTPException(403, "Cannot message this user")

    existing_id = _find_existing_dm(user_id, target_sub)
    if existing_id:
        convo_item = tbl_convos.get_item(Key={"conversation_id": existing_id}).get("Item")
        part_item = tbl_parts.get_item(Key={"user_id": user_id, "conversation_id": existing_id}).get("Item", {})
        if convo_item:
            profile_cache: Dict[str, Any] = {}
            out = _conversation_out_from_items(
                conversation_id=existing_id,
                convo=convo_item,
                participant=part_item,
                viewer_user_id=user_id,
            )
            out.participants = _get_conversation_participants_enriched(existing_id, profile_cache)
            return out

    # No existing DM — create one using the same logic as start_conversation
    return start_conversation(
        StartConversationIn(participant_ids=[target_sub], type="dm"),
        req=req,
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
    # Step 1: Paginate to get all participant records for this user.
    parts: List[dict] = []
    last_key = None
    while True:
        kwargs: dict = {"KeyConditionExpression": Key("user_id").eq(user_id), "Limit": 500}
        if last_key:
            kwargs["ExclusiveStartKey"] = last_key
        resp = tbl_parts.query(**kwargs)
        parts.extend(resp.get("Items", []))
        last_key = resp.get("LastEvaluatedKey")
        if not last_key or len(parts) >= 2000:
            break
    if not parts:
        return []

    parts_by_cid = {p["conversation_id"]: p for p in parts}
    cids = list(parts_by_cid.keys())

    # Step 2: Batch-fetch all conversation records to get last_message_at for
    # sorting. batch_get_item accepts up to 100 keys per call, so chunk it.
    convo_map: Dict[str, dict] = {}
    for i in range(0, len(cids), 100):
        batch_keys = [{"conversation_id": cid} for cid in cids[i : i + 100]]
        try:
            batch_resp = ddb.batch_get_item(
                RequestItems={DDB_CONVERSATIONS: {"Keys": batch_keys}}
            )
            for item in batch_resp.get("Responses", {}).get(DDB_CONVERSATIONS, []):
                convo_map[item["conversation_id"]] = item
        except Exception:
            pass  # Fall back to per-item fetches below if batch fails

    # Step 3: Sort all conversations by recency and cap enrichment at the top
    # 200 to avoid thousands of DDB calls on accounts with many conversations.
    def _sort_key(cid: str) -> tuple:
        convo = convo_map.get(cid, {})
        return (int(convo.get("last_message_at", 0) or 0), int(convo.get("created_at", 0) or 0))

    sorted_cids = sorted(cids, key=_sort_key, reverse=True)
    top_cids = sorted_cids[:200]

    # Step 4: Enrich the top 200 conversations with participants + last message.
    out: List[ConversationOut] = []
    profile_cache: Dict[str, Any] = {}

    for cid in top_cids:
        p = parts_by_cid[cid]
        convo = convo_map.get(cid)
        if not convo:
            # Fall back to individual get_item if batch missed this item.
            convo = tbl_convos.get_item(Key={"conversation_id": cid}).get("Item")
        if not convo:
            continue
        convo_out = _conversation_out_from_items(conversation_id=cid, convo=convo, participant=p, viewer_user_id=user_id)
        convo_out.participants = _get_conversation_participants_enriched(cid, profile_cache)

        # Include the last message object so the conversation list can render
        # accurate preview text for expired/view-once/locked messages.
        last_msg_id = convo.get("last_message_id")
        if last_msg_id:
            try:
                last_msg_item = tbl_msgs.get_item(
                    Key={"conversation_id": cid, "message_id": last_msg_id}
                ).get("Item")
                if last_msg_item:
                    convo_out.last_message = _message_out_from_item(last_msg_item, user_id)
            except Exception:
                pass  # Best-effort; don't fail if last message can't be fetched

        out.append(convo_out)

    out.sort(key=lambda x: (x.last_message_at or 0, x.created_at), reverse=True)
    return out


@router.get("/conversations/{conversation_id}", response_model=ConversationOut)
def get_conversation(conversation_id: str, user_id: str = Depends(get_messaging_user_id)):
    part = get_participant_any(user_id, conversation_id)
    if not part:
        raise HTTPException(404, "Conversation not found")
    convo = _get_conversation_or_404(conversation_id)
    profile_cache: Dict[str, Any] = {}
    convo_out = _conversation_out_from_items(conversation_id=conversation_id, convo=convo, participant=part, viewer_user_id=user_id)
    convo_out.participants = _get_conversation_participants_enriched(conversation_id, profile_cache)
    return convo_out


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
    out = _conversation_out_from_items(
        conversation_id=conversation_id,
        convo=convo,
        participant=part or {"status": "active"},
        viewer_user_id=user_id,
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
    added_participants: list[tuple[str, str, str]] = []
    for pid in dict.fromkeys(inp.participant_ids):
        if pid == user_id:
            continue
        require_subscription_access(user_id, pid)
        existing = get_participant_any(pid, conversation_id)
        if existing:
            if existing.get("status") in ("active", "pending"):
                continue
            restored_role = str(existing.get("role") or "member")
            tbl_parts.update_item(
                Key={"user_id": pid, "conversation_id": conversation_id},
                UpdateExpression="SET #s = :pending, #r = :role, joined_at = :zero, left_at = :zero, unread_count = :zero",
                ExpressionAttributeNames={"#s": "status", "#r": "role"},
                ExpressionAttributeValues={
                    ":pending": "pending",
                    ":role": restored_role,
                    ":zero": 0,
                },
            )
            added += 1
            added_participants.append((pid, "pending", restored_role))
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
        added_participants.append((pid, "pending", "member"))

    if added:
        tbl_convos.update_item(
            Key={"conversation_id": conversation_id},
            UpdateExpression="ADD participant_count :inc",
            ExpressionAttributeValues={":inc": added},
        )
    for participant_id, participant_status, participant_role in added_participants:
        _emit_conversation_membership_archive_event_or_503(
            event_ts=ts,
            conversation_id=conversation_id,
            subject_user_id=participant_id,
            actor_user_id=user_id,
            event_type="conversation.member_joined",
            payload={
                "transition": "participant_added",
                "subject_user_id": participant_id,
                "status": participant_status,
                "role": participant_role,
                "timeline_state": {"participant_count_delta": added},
            },
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
    ts = now_ts()
    if part.get("status") != "left":
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
    _emit_conversation_membership_archive_event_or_503(
        event_ts=ts,
        conversation_id=conversation_id,
        subject_user_id=participant_id,
        actor_user_id=user_id,
        event_type="conversation.member_left",
        payload={
            "transition": "participant_removed",
            "subject_user_id": participant_id,
            "prior_status": str(part.get("status") or ""),
            "timeline_state": {"left_at": ts},
        },
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
    prior_role = str(part.get("role") or "member")
    tbl_parts.update_item(
        Key={"user_id": participant_id, "conversation_id": conversation_id},
        UpdateExpression="SET #r = :role",
        ExpressionAttributeNames={"#r": "role"},
        ExpressionAttributeValues={":role": inp.role},
    )
    _emit_conversation_membership_archive_event_or_503(
        event_ts=now_ts(),
        conversation_id=conversation_id,
        subject_user_id=participant_id,
        actor_user_id=user_id,
        event_type="conversation.role_changed",
        payload={
            "transition": "role_changed",
            "subject_user_id": participant_id,
            "from_role": prior_role,
            "to_role": inp.role,
        },
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
    _emit_conversation_membership_archive_event_or_503(
        event_ts=ts,
        conversation_id=conversation_id,
        subject_user_id=user_id,
        actor_user_id=user_id,
        event_type="conversation.member_left",
        payload={
            "transition": "self_left",
            "subject_user_id": user_id,
            "timeline_state": {"left_at": ts},
        },
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
        record_helpdesk_claim_conflict()
        raise HTTPException(409, detail={"code": "helpdesk_claim_already_assigned", "message": "conversation already assigned"})

    if current_state != "awaiting_agent":
        record_helpdesk_claim("conflict")
        record_helpdesk_claim_conflict()
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
            record_helpdesk_claim_conflict()
            raise HTTPException(409, detail={"code": "helpdesk_claim_conflict", "message": "conversation claim conflict"})
        raise HTTPException(400, detail={"code": exc.code, "message": exc.message})
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            latest = _get_conversation_or_404(conversation_id)
            if str(latest.get("routing_state") or "") == "assigned" and str(latest.get("active_agent_user_id") or "") == user_id:
                return _idempotent_success(latest)
            record_helpdesk_claim("conflict")
            record_helpdesk_claim_conflict()
            raise HTTPException(409, detail={"code": "helpdesk_claim_conflict", "message": "conversation claim conflict"})
        raise

    updated = result.get("conversation", {}) if isinstance(result, dict) else {}

    # Add the claiming agent as an active participant (admin role) so they can send messages.
    # Use a conditional put to avoid overwriting an existing participant record.
    existing_part = tbl_parts.get_item(Key={"user_id": user_id, "conversation_id": conversation_id}).get("Item")
    membership_transition = "none"
    if not existing_part:
        tbl_parts.put_item(Item={
            "user_id": user_id,
            "conversation_id": conversation_id,
            "status": "active",
            "role": "admin",
            "muted_until": 0,
            "last_read_at": 0,
            "unread_count": 0,
            "joined_at": ts,
            "left_at": 0,
            "GSI1PK": conversation_id,
            "GSI1SK": user_id,
        })
        tbl_convos.update_item(
            Key={"conversation_id": conversation_id},
            UpdateExpression="ADD participant_count :inc",
            ExpressionAttributeValues={":inc": 1},
        )
        membership_transition = "helpdesk_agent_joined"
    elif existing_part.get("status") != "active":
        tbl_parts.update_item(
            Key={"user_id": user_id, "conversation_id": conversation_id},
            UpdateExpression="SET #s = :active, role = :role, joined_at = :ts",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={":active": "active", ":role": "admin", ":ts": ts},
        )
        membership_transition = "helpdesk_agent_reactivated"

    if membership_transition != "none":
        _emit_conversation_membership_archive_event_or_503(
            event_ts=ts,
            conversation_id=conversation_id,
            subject_user_id=user_id,
            actor_user_id=user_id,
            event_type="conversation.member_joined",
            payload={
                "transition": membership_transition,
                "subject_user_id": user_id,
                "status": "active",
                "role": "admin",
                "timeline_state": {
                    "routing_event_id": str(result.get("event", {}).get("event_id") or ""),
                    "routing_state": str(updated.get("routing_state") or "assigned"),
                    "assignment_version": int(updated.get("assignment_version") or (current_version + 1)),
                },
            },
        )

    audit_event(
        "messaging_helpdesk_conversation_claimed",
        user_id,
        req,
        outcome="success",
        conversation_id=conversation_id,
        routing_group_id=group_id,
    )
    record_helpdesk_claim("success")
    record_helpdesk_claim_success()
    created_at = int(convo.get("created_at", 0) or 0)
    if created_at > 0:
        record_helpdesk_time_to_first_claim_ms(max(0, ts - created_at) * 1000.0)
    return HelpdeskClaimOut(
        ok=True,
        conversation_id=conversation_id,
        state=str(updated.get("routing_state") or "assigned"),
        assigned_agent_user_id=str(updated.get("active_agent_user_id") or user_id),
        assignment_version=int(updated.get("assignment_version") or (current_version + 1)),
        idempotent=False,
    )


@router.get("/helpdesk/queue", response_model=List[ConversationOut])
def get_helpdesk_queue(
    group_id: str = Query(..., max_length=128),
    state: Optional[str] = Query(None),
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    user_id: str = Depends(get_messaging_user_id),
):
    if not _is_helpdesk_group_member(group_id, user_id):
        raise HTTPException(403, detail={"code": "not_helpdesk_member"})
    states = [state] if state else ["awaiting_agent", "assigned", "paused_no_agents_online"]
    items: list[dict] = []
    for s in states:
        pk = f"{s}#{group_id}"
        # Paginate through all items in this state (DynamoDB Limit is per page,
        # not a total cap). Cap at 1000 per state as a safety limit.
        last_key = None
        per_state: list[dict] = []
        while len(per_state) < 1000:
            kwargs: dict = {
                "IndexName": "RoutingStateGroupIndex",
                "KeyConditionExpression": Key("routing_state_group_pk").eq(pk),
                "Limit": 200,
            }
            if last_key:
                kwargs["ExclusiveStartKey"] = last_key
            resp = tbl_convos.query(**kwargs)
            per_state.extend(resp.get("Items", []))
            last_key = resp.get("LastEvaluatedKey")
            if not last_key:
                break
        items.extend(per_state)
    results: List[ConversationOut] = []
    for convo in items:
        cid = convo.get("conversation_id", "")
        part = tbl_parts.get_item(Key={"user_id": user_id, "conversation_id": cid}).get("Item") or {}
        results.append(_conversation_out_from_items(conversation_id=cid, convo=convo, participant=part, viewer_user_id=user_id))
    return results


@router.post("/helpdesk/conversations/{conversation_id}/claim", response_model=HelpdeskClaimOut)
def claim_helpdesk_conversation(
    conversation_id: str,
    req: Request = None,
    user_id: str = Depends(get_messaging_user_id),
):
    return _claim_helpdesk_conversation_internal(conversation_id=conversation_id, user_id=user_id, req=req)


def _enforce_helpdesk_send_constraints(*, conversation_id: str, convo: dict, user_id: str, req: Optional[Request] = None) -> None:
    if str(convo.get("routing_mode") or "") != "helpdesk_bridge":
        return
    group_id = str(convo.get("routing_group_id") or "")
    if not group_id or not _is_helpdesk_group_member(group_id, user_id):
        return

    state = str(convo.get("routing_state") or "none")
    assigned_agent = str(convo.get("active_agent_user_id") or "")
    if state == "assigned":
        if assigned_agent and assigned_agent != user_id:
            raise HTTPException(
                409,
                detail={
                    "code": "helpdesk_assignee_required",
                    "message": "only the assigned helpdesk agent can reply",
                },
            )
        return

    if state == "awaiting_agent":
        if not HELPDESK_AUTO_CLAIM_ON_REPLY_ENABLED:
            raise HTTPException(409, detail={"code": "helpdesk_claim_required", "message": "explicit claim required before replying"})
        claim = _claim_helpdesk_conversation_internal(conversation_id=conversation_id, user_id=user_id, req=req)
        claimed_agent = str(getattr(claim, "assigned_agent_user_id", "") or "")
        if claimed_agent and claimed_agent != user_id:
            raise HTTPException(
                409,
                detail={
                    "code": "helpdesk_assignee_required",
                    "message": "only the assigned helpdesk agent can reply",
                },
            )
        return

    raise HTTPException(
        409,
        detail={
            "code": "helpdesk_claim_invalid_state",
            "message": f"cannot send while routing_state={state}",
        },
    )


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

    convo = _get_conversation_or_404(conversation_id)
    helpdesk_agent_view = _is_helpdesk_agent_viewer(convo, user_id)

    resp = tbl_parts.query(IndexName="GSI1", KeyConditionExpression=Key("GSI1PK").eq(conversation_id), Limit=500)
    items = resp.get("Items", [])

    out: List[ParticipantOut] = []
    if str(convo.get("routing_mode") or "") == "helpdesk_bridge" and not helpdesk_agent_view:
        requester = next((p for p in items if p.get("user_id") == user_id), part)
        out.append(
            ParticipantOut(
                user_id=user_id,
                status=requester.get("status", "active"),
                role=requester.get("role", "member"),
                muted_until=int(requester.get("muted_until", 0) or 0),
                last_read_at=int(requester.get("last_read_at", 0) or 0),
                joined_at=int(requester.get("joined_at", 0) or 0),
                left_at=int(requester.get("left_at", 0) or 0),
            )
        )
        helpdesk_status = "active" if str(convo.get("routing_state") or "") == "assigned" else "pending"
        out.append(
            ParticipantOut(
                user_id=HELPDESK_MASKED_SENDER_ID,
                status=helpdesk_status,
                role="member",
            )
        )
        return out

    assignment_state = str(convo.get("routing_state") or "") if str(convo.get("routing_mode") or "") == "helpdesk_bridge" else ""
    assignment_owner = str(convo.get("active_agent_user_id") or "") if assignment_state else ""
    profile_cache: Dict[str, Any] = {}
    for p in items:
        participant_out = _enrich_participant_out(p, profile_cache)
        if helpdesk_agent_view and assignment_state:
            participant_out.assignment_state = assignment_state
            participant_out.assignment_owner_user_id = assignment_owner
            participant_out.is_assignment_owner = bool(assignment_owner and p.get("user_id") == assignment_owner)
        out.append(participant_out)

    order = {"active": 0, "pending": 1, "left": 2}
    out.sort(key=lambda x: (order.get(x.status, 9), x.user_id))
    return out



REPORT_CONTEXT_RADIUS = 5
REPORT_CONTEXT_SCAN_LIMIT = 500


def _message_allowed_in_report_context(item: dict, user_id: str) -> bool:
    # Only include messages visible to reporter and not hard-revoked/deleted artifacts.
    if not _filter_message_visible(item, user_id):
        return False
    if item.get("revoked_at"):
        return False
    return True




def _query_report_count(*, index_name: str, partition_key_name: str, partition_key_value: str, since_ts: int, limit: int) -> int:
    resp = T.message_reports.query(
        IndexName=index_name,
        KeyConditionExpression=Key(partition_key_name).eq(partition_key_value) & Key("created_at").gte(since_ts),
        Select="COUNT",
        Limit=max(1, limit),
        ScanIndexForward=False,
    )
    return int(resp.get("Count", 0) or 0)


def _enforce_report_rate_limits(conversation_id: str, user_id: str, now: int) -> None:
    enabled = os.environ.get(
        "MESSAGING_REPORT_RATE_LIMIT_ENABLED",
        "true" if S.messaging_report_rate_limit_enabled else "false",
    ).lower() in ("1", "true", "yes", "on")
    if not enabled:
        return

    user_window = max(1, int(os.environ.get("MESSAGING_REPORT_RATE_LIMIT_USER_WINDOW_SECONDS", str(S.messaging_report_rate_limit_user_window_seconds))))
    user_max = max(1, int(os.environ.get("MESSAGING_REPORT_RATE_LIMIT_USER_MAX", str(S.messaging_report_rate_limit_user_max))))
    convo_window = max(1, int(os.environ.get("MESSAGING_REPORT_RATE_LIMIT_CONVERSATION_WINDOW_SECONDS", str(S.messaging_report_rate_limit_conversation_window_seconds))))
    convo_max = max(1, int(os.environ.get("MESSAGING_REPORT_RATE_LIMIT_CONVERSATION_MAX", str(S.messaging_report_rate_limit_conversation_max))))

    user_count = _query_report_count(
        index_name="ByReporterCreatedAt",
        partition_key_name="reported_by_user_id",
        partition_key_value=user_id,
        since_ts=now - user_window,
        limit=user_max,
    )
    if user_count >= user_max:
        record_messaging_message_control_action(action="report", result="rate_limited")
        _log_message_control_action(actor_user_id=user_id, conversation_id=conversation_id, message_id="", action="report", result="rate_limited", detail="scope=user")
        audit_event("messaging_report_rate_limited", user_id, None, outcome="rate_limited", scope="user", conversation_id=conversation_id, count=user_count, window_seconds=user_window)
        raise HTTPException(status_code=429, detail="Rate limit exceeded for message reports", headers={"Retry-After": str(user_window)})

    convo_count = _query_report_count(
        index_name="ByConversationCreatedAt",
        partition_key_name="conversation_id",
        partition_key_value=conversation_id,
        since_ts=now - convo_window,
        limit=convo_max,
    )
    if convo_count >= convo_max:
        record_messaging_message_control_action(action="report", result="rate_limited")
        _log_message_control_action(actor_user_id=user_id, conversation_id=conversation_id, message_id="", action="report", result="rate_limited", detail="scope=conversation")
        audit_event("messaging_report_rate_limited", user_id, None, outcome="rate_limited", scope="conversation", conversation_id=conversation_id, count=convo_count, window_seconds=convo_window)
        raise HTTPException(status_code=429, detail="Rate limit exceeded for message reports", headers={"Retry-After": str(convo_window)})

def _load_report_context_message_ids(conversation_id: str, target_message_id: str, user_id: str) -> List[str]:
    """Build immutable, server-side report context around a target message (±REPORT_CONTEXT_RADIUS)."""
    items: List[dict] = []
    last_key: Optional[dict] = None

    while len(items) < REPORT_CONTEXT_SCAN_LIMIT:
        kwargs: Dict[str, Any] = {
            "KeyConditionExpression": Key("conversation_id").eq(conversation_id),
            "ScanIndexForward": False,
            "Limit": 100,
        }
        if last_key:
            kwargs["ExclusiveStartKey"] = last_key

        resp = tbl_msgs.query(**kwargs)
        page_items = resp.get("Items", []) or []
        if not page_items:
            break
        items.extend(page_items)

        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break

    items.sort(key=lambda i: (int(i.get("created_at", 0) or 0), str(i.get("message_id") or "")))
    allowed = [i for i in items if _message_allowed_in_report_context(i, user_id)]

    target_index = next((idx for idx, itm in enumerate(allowed) if str(itm.get("message_id") or "") == target_message_id), -1)
    if target_index < 0:
        return [target_message_id]

    start = max(0, target_index - REPORT_CONTEXT_RADIUS)
    end = min(len(allowed), target_index + REPORT_CONTEXT_RADIUS + 1)
    context_ids = [str(itm.get("message_id") or "") for itm in allowed[start:end] if itm.get("message_id")]
    if target_message_id not in context_ids:
        context_ids.append(target_message_id)
    return context_ids

def _load_hidden_message_ids_for_user(conversation_id: str, user_id: str, message_ids: Sequence[str]) -> set[str]:
    if not message_ids:
        return set()

    keys = [
        {"conversation_id": conversation_id, "message_user": f"{mid}#{user_id}"}
        for mid in message_ids
        if mid
    ]
    if not keys:
        return set()

    hidden: set[str] = set()
    table_name = T.message_visibility_overrides.name

    for i in range(0, len(keys), 100):
        chunk = keys[i : i + 100]
        resp = ddb.meta.client.batch_get_item(RequestItems={table_name: {"Keys": chunk}})
        items = resp.get("Responses", {}).get(table_name, [])
        for item in items:
            if str(item.get("state") or "") != "hidden":
                continue
            message_id = str(item.get("message_id") or "").strip()
            if message_id:
                hidden.add(message_id)

    return hidden


class DraftCreateIn(BaseModel):
    text: str = Field(min_length=1, max_length=MESSAGE_TEXT_MAX_CHARS)
    client_updated_at: int | None = Field(default=None, ge=0)


class DraftPatchIn(BaseModel):
    text: str = Field(min_length=1, max_length=MESSAGE_TEXT_MAX_CHARS)
    client_updated_at: int | None = Field(default=None, ge=0)


class DraftOut(BaseModel):
    draft_id: str
    conversation_id: str
    owner_user_id: str
    text: str
    version: int
    created_at: int
    updated_at: int
    client_updated_at: int | None = None
    tenant_id: str | None = None


class DraftEnvelope(BaseModel):
    draft: DraftOut


class DraftListOut(BaseModel):
    items: List[DraftOut]
    next_cursor: str | None = None


def _decode_drafts_cursor(cursor: str | None) -> dict[str, Any] | None:
    if not cursor:
        return None
    try:
        return decode_cursor(cursor)
    except Exception as exc:
        raise HTTPException(status_code=422, detail="Invalid cursor") from exc


def _encode_drafts_cursor(cursor: dict[str, Any] | None) -> str | None:
    if not cursor:
        return None
    return encode_cursor(cursor)


def _translate_draft_error(exc: Exception) -> HTTPException:
    if isinstance(exc, DraftValidationError):
        return HTTPException(status_code=422, detail=str(exc))
    if isinstance(exc, DraftNotFoundError):
        return HTTPException(status_code=404, detail="Draft not found")
    return HTTPException(status_code=500, detail="Draft operation failed")


def _record_draft_endpoint_metrics(*, operation: str, source: str, result: str, started_at: float) -> None:
    record_messaging_draft_operation(operation=operation, source=source, result=result)
    record_messaging_draft_latency(
        operation=operation,
        source=source,
        elapsed_seconds=max(0.0, time.perf_counter() - started_at),
    )


@router.get("/conversations/{conversation_id}/drafts", response_model=DraftListOut)
def list_conversation_drafts(
    conversation_id: str,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    cursor: str | None = None,
    user_id: str = Depends(get_messaging_user_id),
):
    started_at = time.perf_counter()
    _require_messaging_drafts_enabled(user_id=user_id)
    require_participant_active(user_id, conversation_id)
    try:
        result = list_drafts(
            owner_user_id=user_id,
            conversation_id=conversation_id,
            limit=limit,
            cursor=_decode_drafts_cursor(cursor),
        )
    except Exception as exc:
        _record_draft_endpoint_metrics(operation="list", source="server", result="error", started_at=started_at)
        raise _translate_draft_error(exc) from exc

    _record_draft_endpoint_metrics(operation="list", source="server", result="success", started_at=started_at)
    return DraftListOut(items=result.get("items", []), next_cursor=_encode_drafts_cursor(result.get("next_cursor")))


@router.post("/conversations/{conversation_id}/drafts", response_model=DraftEnvelope, status_code=201)
def create_conversation_draft(
    conversation_id: str,
    inp: DraftCreateIn,
    idempotency_key: Annotated[str, Header(alias="Idempotency-Key", min_length=1, max_length=128)],
    user_id: str = Depends(get_messaging_user_id),
):
    started_at = time.perf_counter()
    del idempotency_key  # reserved for service-level idempotency store
    _require_messaging_drafts_enabled(user_id=user_id)
    require_participant_active(user_id, conversation_id)
    try:
        draft = create_draft(
            owner_user_id=user_id,
            conversation_id=conversation_id,
            text=inp.text,
            client_updated_at=inp.client_updated_at,
        )
    except Exception as exc:
        _record_draft_endpoint_metrics(operation="create", source="server", result="error", started_at=started_at)
        raise _translate_draft_error(exc) from exc
    _record_draft_endpoint_metrics(operation="create", source="server", result="success", started_at=started_at)
    return DraftEnvelope(draft=draft)


@router.get("/conversations/{conversation_id}/drafts/{draft_id}", response_model=DraftEnvelope)
def get_conversation_draft(
    conversation_id: str,
    draft_id: str,
    user_id: str = Depends(get_messaging_user_id),
):
    started_at = time.perf_counter()
    _require_messaging_drafts_enabled(user_id=user_id)
    require_participant_active(user_id, conversation_id)
    try:
        draft = get_draft(owner_user_id=user_id, conversation_id=conversation_id, draft_id=draft_id)
    except Exception as exc:
        _record_draft_endpoint_metrics(operation="get", source="server", result="error", started_at=started_at)
        raise _translate_draft_error(exc) from exc
    _record_draft_endpoint_metrics(operation="get", source="server", result="success", started_at=started_at)
    return DraftEnvelope(draft=draft)


@router.patch("/conversations/{conversation_id}/drafts/{draft_id}", response_model=DraftEnvelope)
def patch_conversation_draft(
    conversation_id: str,
    draft_id: str,
    inp: DraftPatchIn,
    user_id: str = Depends(get_messaging_user_id),
):
    started_at = time.perf_counter()
    _require_messaging_drafts_enabled(user_id=user_id)
    require_participant_active(user_id, conversation_id)
    try:
        draft = update_draft(
            owner_user_id=user_id,
            conversation_id=conversation_id,
            draft_id=draft_id,
            text=inp.text,
            client_updated_at=inp.client_updated_at,
        )
    except Exception as exc:
        _record_draft_endpoint_metrics(operation="update", source="server", result="error", started_at=started_at)
        raise _translate_draft_error(exc) from exc
    _record_draft_endpoint_metrics(operation="update", source="server", result="success", started_at=started_at)
    return DraftEnvelope(draft=draft)


@router.delete("/conversations/{conversation_id}/drafts/{draft_id}", status_code=204, response_class=Response)
def delete_conversation_draft(
    conversation_id: str,
    draft_id: str,
    user_id: str = Depends(get_messaging_user_id),
):
    started_at = time.perf_counter()
    _require_messaging_drafts_enabled(user_id=user_id)
    require_participant_active(user_id, conversation_id)
    try:
        delete_draft(owner_user_id=user_id, conversation_id=conversation_id, draft_id=draft_id)
    except Exception as exc:
        _record_draft_endpoint_metrics(operation="delete", source="server", result="error", started_at=started_at)
        raise _translate_draft_error(exc) from exc
    _record_draft_endpoint_metrics(operation="delete", source="server", result="success", started_at=started_at)
    return None


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

    try:
        parts = tbl_parts.query(IndexName="GSI1", KeyConditionExpression=Key("GSI1PK").eq(conversation_id)).get("Items", [])
    except Exception:
        parts = []
    if not isinstance(parts, list):
        parts = []

    out: List[MessageOut] = []
    last_key = {"conversation_id": conversation_id, "message_id": before} if before else None

    while len(out) < limit:
        kwargs: Dict[str, Any] = {
            "KeyConditionExpression": Key("conversation_id").eq(conversation_id),
            "ScanIndexForward": False,
            "Limit": limit,
        }
        if last_key:
            kwargs["ExclusiveStartKey"] = last_key

        resp = tbl_msgs.query(**kwargs)
        items = resp.get("Items", [])
        if not items:
            break

        hidden_ids: set[str] = set()
        if MESSAGING_HIDDEN_TIMELINE_FILTER_ENABLED:
            message_ids = [str(item.get("message_id") or "") for item in items]
            hidden_ids = _load_hidden_message_ids_for_user(conversation_id, user_id, message_ids)

        for m in items:
            if m.get("message_id") in hidden_ids:
                continue
            if not _filter_message_visible(m, user_id):
                continue
            msg = _message_out_from_item(m, user_id)
            out.append(_apply_message_receipts(msg, m, parts))
            if len(out) >= limit:
                break

        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break

    # Sort by created_at descending (newest first) so the response is in
    # chronological order regardless of DynamoDB sort-key (message_id) ordering.
    out.sort(key=lambda m: m.created_at, reverse=True)
    return out


def _thread_cursor_signing_secrets() -> List[str]:
    # Prefer dedicated thread cursor secret; fall back to existing app secret for safer defaults.
    primary = MESSAGING_THREAD_CURSOR_SECRET or S.ui_access_token_secret or "dev-insecure-thread-cursor-secret"
    secrets = [primary]
    for old_secret in MESSAGING_THREAD_CURSOR_PREVIOUS_SECRETS:
        if old_secret and old_secret not in secrets:
            secrets.append(old_secret)
    return secrets


def _sign_thread_cursor_payload(payload_b64: str, *, secret: Optional[str] = None) -> str:
    secret = secret or _thread_cursor_signing_secrets()[0]
    digest = hmac.new(secret.encode("utf-8"), payload_b64.encode("utf-8"), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).decode("utf-8").rstrip("=")


def _encode_thread_messages_cursor(
    *,
    last_evaluated_key: Optional[Dict[str, Any]],
    thread_id: str,
    conversation_id: str,
    user_id: str,
) -> Optional[str]:
    if not isinstance(last_evaluated_key, dict) or not last_evaluated_key:
        return None
    payload = {
        "version": MESSAGING_THREAD_CURSOR_VERSION,
        "alg": MESSAGING_THREAD_CURSOR_ALG,
        "v": MESSAGING_THREAD_CURSOR_VERSION,
        "tid": thread_id,
        "cid": conversation_id,
        "uid": user_id,
        "exp": int(time.time()) + MESSAGING_THREAD_CURSOR_TTL_SECONDS,
        "lek": last_evaluated_key,
    }
    payload_raw = json.dumps(payload, separators=(",", ":"), sort_keys=True, cls=_DecimalEncoder).encode("utf-8")
    payload_b64 = base64.urlsafe_b64encode(payload_raw).decode("utf-8").rstrip("=")
    signature = _sign_thread_cursor_payload(payload_b64)
    return f"{payload_b64}.{signature}"


def _decode_thread_messages_cursor_or_400(
    *,
    thread_id: str,
    conversation_id: str,
    user_id: str,
    cursor: str,
) -> Dict[str, Any]:
    def _validate_thread_lek_or_400(lek: Any) -> Dict[str, Any]:
        if not isinstance(lek, dict) or not lek:
            raise HTTPException(
                status_code=400,
                detail={"code": "invalid_cursor", "message": "cursor payload is malformed"},
            )
        lek_thread_id = str(lek.get(MESSAGE_FIELD_THREAD_ID) or "")
        if lek_thread_id != thread_id:
            raise HTTPException(
                status_code=400,
                detail={"code": "invalid_cursor", "message": "cursor does not match requested thread_id"},
            )
        lek_conversation_id = str(lek.get("conversation_id") or "")
        if lek_conversation_id != conversation_id:
            raise HTTPException(
                status_code=400,
                detail={"code": "invalid_cursor", "message": "cursor does not match requested conversation"},
            )
        if not str(lek.get("message_id") or "").strip():
            raise HTTPException(
                status_code=400,
                detail={"code": "invalid_cursor", "message": "cursor payload is malformed"},
            )
        return lek

    raw = (cursor or "").strip()
    if not raw:
        raise HTTPException(
            status_code=400,
            detail={"code": "invalid_cursor", "message": "cursor is required"},
        )
    if len(raw) > MESSAGING_THREAD_CURSOR_MAX_CHARS:
        raise HTTPException(
            status_code=400,
            detail={"code": "invalid_cursor", "message": "cursor is too long"},
        )

    payload_b64: Optional[str] = None
    signature: Optional[str] = None
    if "." in raw:
        payload_b64, signature = raw.rsplit(".", 1)
    elif MESSAGING_THREAD_CURSOR_ALLOW_LEGACY:
        decoded_legacy = decode_cursor(raw)
        if not isinstance(decoded_legacy, dict):
            raise HTTPException(
                status_code=400,
                detail={
                    "code": "invalid_cursor",
                    "message": "cursor must be urlsafe base64 encoded JSON for thread pagination",
                },
            )
        return _validate_thread_lek_or_400(decoded_legacy)
    else:
        raise HTTPException(
            status_code=400,
            detail={"code": "invalid_cursor", "message": "cursor signature is required"},
        )

    valid_signature = any(
        hmac.compare_digest(_sign_thread_cursor_payload(payload_b64, secret=secret), signature or "")
        for secret in _thread_cursor_signing_secrets()
    )
    if not valid_signature:
        raise HTTPException(
            status_code=400,
            detail={"code": "invalid_cursor", "message": "cursor signature is invalid"},
        )
    try:
        pad = "=" * ((4 - (len(payload_b64 or "") % 4)) % 4)
        payload_raw = base64.urlsafe_b64decode(((payload_b64 or "") + pad).encode("utf-8"))
        payload = json.loads(payload_raw.decode("utf-8"))
    except Exception:
        raise HTTPException(
            status_code=400,
            detail={"code": "invalid_cursor", "message": "cursor payload is malformed"},
        )
    if not isinstance(payload, dict):
        raise HTTPException(
            status_code=400,
            detail={"code": "invalid_cursor", "message": "cursor payload is malformed"},
        )
    if "version" not in payload:
        if MESSAGING_THREAD_CURSOR_ALLOW_LEGACY_SIGNED_FIELDS and "v" in payload:
            version = payload.get("v")
        else:
            raise HTTPException(
                status_code=400,
                detail={"code": "invalid_cursor", "message": "cursor version is missing"},
            )
    else:
        version = payload.get("version")
    try:
        version_num = int(version or 0)
    except (TypeError, ValueError):
        raise HTTPException(
            status_code=400,
            detail={"code": "invalid_cursor", "message": "cursor version is malformed"},
        )
    if version_num != MESSAGING_THREAD_CURSOR_VERSION:
        raise HTTPException(
            status_code=400,
            detail={"code": "invalid_cursor", "message": "cursor version is unsupported"},
        )
    if "alg" not in payload:
        if MESSAGING_THREAD_CURSOR_ALLOW_LEGACY_SIGNED_FIELDS:
            alg = MESSAGING_THREAD_CURSOR_ALG
        else:
            raise HTTPException(
                status_code=400,
                detail={"code": "invalid_cursor", "message": "cursor algorithm is missing"},
            )
    else:
        alg = str(payload.get("alg") or "").upper()
    if alg != MESSAGING_THREAD_CURSOR_ALG:
        raise HTTPException(
            status_code=400,
            detail={"code": "invalid_cursor", "message": "cursor algorithm is unsupported"},
        )
    try:
        exp = int(payload.get("exp", 0) or 0)
    except (TypeError, ValueError):
        raise HTTPException(
            status_code=400,
            detail={"code": "invalid_cursor", "message": "cursor expiry is malformed"},
        )
    if exp <= int(time.time()):
        raise HTTPException(
            status_code=400,
            detail={"code": "invalid_cursor", "message": "cursor has expired"},
        )
    if str(payload.get("tid") or "") != thread_id:
        raise HTTPException(
            status_code=400,
            detail={"code": "invalid_cursor", "message": "cursor does not match requested thread_id"},
        )
    if str(payload.get("cid") or "") != conversation_id:
        raise HTTPException(
            status_code=400,
            detail={"code": "invalid_cursor", "message": "cursor does not match requested conversation"},
        )
    if str(payload.get("uid") or "") != user_id:
        raise HTTPException(
            status_code=400,
            detail={"code": "invalid_cursor", "message": "cursor does not match current user"},
        )
    return _validate_thread_lek_or_400(payload.get("lek"))


def _normalize_cursor_error_reason(detail: Any) -> str:
    reason = "unknown"
    if isinstance(detail, dict):
        reason = str(detail.get("message") or detail.get("code") or "unknown")
    elif isinstance(detail, str):
        reason = detail
    reason = reason.strip() or "unknown"
    reason = re.sub(r"[^a-zA-Z0-9 .:_-]", "?", reason)
    return reason[:200]


def _cursor_error_category(detail: Any) -> str:
    reason = _normalize_cursor_error_reason(detail).lower()
    if "too long" in reason:
        return "too_long"
    if "signature" in reason:
        return "signature"
    if "expired" in reason:
        return "expired"
    if "algorithm" in reason:
        return "algorithm"
    if "version" in reason:
        return "version"
    if "payload" in reason:
        return "payload"
    if "urlsafe base64" in reason:
        return "payload"
    if "match requested thread_id" in reason:
        return "scope_thread"
    if "match requested conversation" in reason:
        return "scope_conversation"
    if "match current user" in reason:
        return "scope_user"
    return "other"


@router.get("/threads/{thread_id}/messages", response_model=ThreadMessagesPageOut)
def list_thread_messages(
    thread_id: str,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    cursor: Optional[str] = None,
    req: Request = None,
    user_id: str = Depends(get_messaging_user_id),
):
    started = time.perf_counter()
    outcome = "success"
    thread = get_message_thread_record(thread_id)
    if not thread:
        outcome = "not_found"
        record_messaging_thread_query_latency(
            endpoint="list_thread_messages",
            outcome=outcome,
            elapsed_seconds=time.perf_counter() - started,
        )
        audit_event(
            "messaging_thread_query_not_found",
            user_id,
            req,
            outcome=outcome,
            thread_id=thread_id,
        )
        raise HTTPException(status_code=404, detail="Thread not found")
    try:
        participant = require_participant_active(user_id, thread.conversation_id)
    except HTTPException:
        outcome = "forbidden"
        record_messaging_thread_query_latency(
            endpoint="list_thread_messages",
            outcome=outcome,
            elapsed_seconds=time.perf_counter() - started,
        )
        audit_event(
            "messaging_thread_query_forbidden",
            user_id,
            req,
            outcome=outcome,
            thread_id=thread_id,
            conversation_id=thread.conversation_id,
        )
        raise

    try:
        parts = tbl_parts.query(
            IndexName="GSI1",
            KeyConditionExpression=Key("GSI1PK").eq(thread.conversation_id),
        ).get("Items", [])
    except Exception:
        parts = []
    if not isinstance(parts, list):
        parts = []

    kwargs: Dict[str, Any] = {
        "IndexName": "ByThreadCreatedAt",
        "KeyConditionExpression": Key(MESSAGE_FIELD_THREAD_ID).eq(thread_id),
        "ScanIndexForward": True,
        "Limit": limit,
    }
    if cursor:
        try:
            kwargs["ExclusiveStartKey"] = _decode_thread_messages_cursor_or_400(
                thread_id=thread_id,
                conversation_id=thread.conversation_id,
                user_id=user_id,
                cursor=cursor,
            )
        except HTTPException as exc:
            outcome = "invalid_cursor"
            reason_category = _cursor_error_category(exc.detail)
            record_messaging_thread_query_latency(
                endpoint="list_thread_messages",
                outcome=outcome,
                elapsed_seconds=time.perf_counter() - started,
            )
            record_messaging_thread_invalid_cursor(
                endpoint="list_thread_messages",
                reason_category=reason_category,
            )
            audit_event(
                "messaging_thread_query_invalid_cursor",
                user_id,
                req,
                outcome=outcome,
                reason=_normalize_cursor_error_reason(exc.detail),
                reason_category=reason_category,
                thread_id=thread_id,
                conversation_id=thread.conversation_id,
            )
            raise
    try:
        resp = tbl_msgs.query(**kwargs)
    except Exception:
        outcome = "error"
        record_messaging_thread_query_latency(
            endpoint="list_thread_messages",
            outcome=outcome,
            elapsed_seconds=time.perf_counter() - started,
        )
        audit_event(
            "messaging_thread_query_failed",
            user_id,
            req,
            outcome=outcome,
            thread_id=thread_id,
            conversation_id=thread.conversation_id,
        )
        logger.exception(
            "messaging.thread_read query failed",
            extra={"thread_id": thread_id, "user_id": user_id},
        )
        raise HTTPException(
            status_code=503,
            detail={
                "code": "thread_query_failed",
                "message": "thread message query temporarily unavailable",
            },
        )
    raw_items = resp.get("Items", [])

    hidden_ids: set[str] = set()
    if MESSAGING_HIDDEN_TIMELINE_FILTER_ENABLED:
        message_ids = [str(item.get("message_id") or "") for item in raw_items]
        hidden_ids = _load_hidden_message_ids_for_user(thread.conversation_id, user_id, message_ids)

    items: List[MessageOut] = []
    for raw in raw_items:
        if raw.get("message_id") in hidden_ids:
            continue
        if not _filter_message_visible(raw, user_id):
            continue
        msg = _message_out_from_item(raw, user_id)
        items.append(_apply_message_receipts(msg, raw, parts))

    next_cursor = _encode_thread_messages_cursor(
        last_evaluated_key=resp.get("LastEvaluatedKey"),
        thread_id=thread_id,
        conversation_id=thread.conversation_id,
        user_id=user_id,
    )
    last_read_at = int(participant.get("last_read_at", 0) or 0)
    unread_count = sum(1 for msg in items if int(msg.created_at) > last_read_at and msg.sender_id != user_id)
    record_messaging_thread_query_latency(
        endpoint="list_thread_messages",
        outcome=outcome,
        elapsed_seconds=time.perf_counter() - started,
    )
    return ThreadMessagesPageOut(items=items, next_cursor=next_cursor, unread_count=unread_count)


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


@router.get("/conversations/{conversation_id}/gallery", response_model=GalleryPageOut)
def list_conversation_gallery(
    conversation_id: str,
    type: Annotated[str, Query(description="Gallery type: image, video, file, link")],
    cursor: Annotated[Optional[str], Query(description="Pagination cursor")] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    user_id: str = Depends(get_messaging_user_id),
):
    started = time.perf_counter()
    gallery_type = (type or "").strip().lower() or "unknown"
    outcome = "error"
    try:
        if not _messaging_gallery_enabled():
            outcome = "disabled"
            raise HTTPException(status_code=404, detail="Gallery disabled")

        require_participant_active(user_id, conversation_id)
        if gallery_type not in GALLERY_TYPES:
            outcome = "invalid_type"
            raise HTTPException(
                status_code=422,
                detail={
                    "code": "gallery_type_invalid",
                    "message": "Invalid gallery type",
                    "allowed": sorted(GALLERY_TYPES),
                },
            )

        if _messaging_gallery_index_enabled():
            cursor_sort_key = _decode_gallery_index_cursor(cursor) if cursor else None
            raw_items, next_sort_key = fetch_gallery_index_page(
                table=tbl_gallery_index,
                conversation_id=conversation_id,
                gallery_type=gallery_type,
                limit=limit,
                cursor_sort_key=cursor_sort_key,
            )
            items = [
                GalleryItemOut(
                    conversation_id=str(row.get("conversation_id") or conversation_id),
                    type=str(row.get("type") or gallery_type),
                    message_id=str(row.get("message_id") or ""),
                    sender_id=str(row.get("sender_id") or ""),
                    created_at=int(row.get("created_at") or 0),
                    url=str(row.get("url") or ""),
                    thumbnail_url=row.get("thumbnail_url"),
                    title=row.get("title"),
                    file_name=row.get("file_name"),
                    content_type=row.get("content_type"),
                    size=(int(row.get("size")) if row.get("size") is not None else None),
                )
                for row in raw_items
                if _filter_message_visible(row, user_id)
            ]
            next_cursor = _encode_gallery_index_cursor(next_sort_key) if next_sort_key else None
        else:
            cursor_message_id = _decode_gallery_cursor(cursor) if cursor else None

            items, next_message_id = fetch_gallery_page(
                table=tbl_msgs,
                conversation_id=conversation_id,
                gallery_type=gallery_type,
                limit=limit,
                cursor_message_id=cursor_message_id,
                is_visible=lambda m: _filter_message_visible(m, user_id),
                map_item=_gallery_item_from_message,
            )
            next_cursor = _encode_gallery_cursor(next_message_id) if next_message_id else None

        record_messaging_gallery_cursor_page_depth(
            gallery_type=gallery_type,
            depth=0 if cursor is None else 1,
        )

        outcome = "success"
        return GalleryPageOut(items=items, next_cursor=next_cursor)
    except HTTPException as exc:
        if outcome == "error":
            outcome = "http_%s" % exc.status_code
        raise
    finally:
        record_messaging_gallery_request(gallery_type=gallery_type, outcome=outcome)
        record_messaging_gallery_latency(
            gallery_type=gallery_type,
            elapsed_seconds=time.perf_counter() - started,
        )


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


def _run_bot_trigger_evaluation(*, conversation_id: str, message_item: dict) -> None:
    """Evaluate chat-bot triggers for a freshly delivered message and dispatch
    any matching bot replies (GAP-0133).

    Called best-effort after a non-scheduled, non-encrypted text message has been
    persisted and fanned out. Any failure here must never break the user's send,
    so the whole body is wrapped in a broad try/except. Bots cannot read
    ciphertext, so encrypted messages are excluded by the caller.

    Reuses the existing bot subsystem unchanged:
      - chat_bot.get_bots_for_conversation: active bots assigned to the convo
      - chat_bot.evaluate_triggers: returns the matching response_template_id
      - bot_template.get_template / render_template: resolve the reply text
      - chat_bot.send_bot_message: persists the bot reply (GAP-0015) + fan-out meta
    """
    try:
        from app.services.chat_bot import (
            evaluate_triggers,
            get_bots_for_conversation,
            send_bot_message,
        )
        from app.services.bot_template import get_template, render_template

        bots = get_bots_for_conversation(conversation_id=conversation_id)
        for bot in bots:
            try:
                template_id = evaluate_triggers(
                    bot=bot,
                    conversation_id=conversation_id,
                    incoming_message=message_item,
                    event_type="message",
                )
                if not template_id:
                    continue
                template = get_template(bot_id=bot["bot_id"], template_id=template_id)
                if not template:
                    continue
                rendered = render_template(
                    template=template,
                    creator_id=bot.get("creator_id"),
                    bot=bot,
                    conversation_id=conversation_id,
                )
                send_bot_message(
                    bot_id=bot["bot_id"],
                    conversation_id=conversation_id,
                    text=rendered["rendered_text"],
                )
            except Exception:  # noqa: BLE001 - one bot failing must not block others
                logger.exception(
                    "bot_trigger_evaluation_bot_failed conversation_id=%s bot_id=%s",
                    conversation_id,
                    bot.get("bot_id"),
                )
    except Exception:  # noqa: BLE001 - bot evaluation must never break the send path
        logger.exception(
            "bot_trigger_evaluation_failed conversation_id=%s", conversation_id
        )


@router.post("/conversations/{conversation_id}/messages", response_model=MessageOut)
def send_text_message(
    conversation_id: str,
    inp: SendTextMessageIn,
    req: Request = None,
    user_id: str = Depends(get_messaging_user_id),
    _kyc: object = Depends(require_kyc_tier(1)),  # GAP-0268 (inert unless enforcement flag on)
):
    _enforce_messaging_internal_entitlement(
        user_id=user_id,
        action="send_message",
        request_id=(req.headers.get("x-request-id") if req else None),
    )
    require_participant_active(user_id, conversation_id)
    if inp.encryption and not _encrypted_messages_enabled():
        raise HTTPException(status_code=403, detail="Encrypted messaging is disabled")
    convo = _get_conversation_or_404(conversation_id)
    _enforce_helpdesk_send_constraints(conversation_id=conversation_id, convo=convo, user_id=user_id, req=req)
    try:
        resp = tbl_parts.query(IndexName="GSI1", KeyConditionExpression=Key("GSI1PK").eq(conversation_id))
        participants = resp.get("Items", [])
    except Exception:
        participants = []
    # Block enforcement: prevent sending messages to blocked users in DMs
    if convo.get("type") == "dm":
        from app.services.blocking import is_any_block as _is_any_block_check
        for participant in participants:
            pid = participant.get("user_id")
            if pid and pid != user_id and _is_any_block_check(user_id, pid):
                raise HTTPException(403, "Cannot send message to this user")
    for participant in participants:
        pid = participant.get("user_id")
        if pid and pid != user_id:
            require_subscription_access(user_id, pid)
    _enforce_message_send_quota_precheck(user_id=user_id, conversation_id=conversation_id, req=req)
    _validate_reply_target(conversation_id, inp.reply_to_message_id)

    # Validate send_at: must be in the future (at least 5 seconds from now)
    ts = now_ts()
    deliver_at: Optional[int] = None
    is_scheduled = False
    if inp.send_at is not None:
        if inp.send_at <= ts + 5:
            raise HTTPException(400, "send_at must be at least 5 seconds in the future")
        deliver_at = inp.send_at
        is_scheduled = True

    # Process tip
    tip_amount_cents: Optional[int] = None
    tip_currency: Optional[str] = None
    tip_payment_id: Optional[str] = None
    if inp.tip_amount_cents:
        tip_amount_cents = inp.tip_amount_cents
        tip_currency = "USD"
        # In dev mode, mock the payment; in production this would call a payment processor
        tip_payment_id = "tip_" + new_id()

    mid = "m_" + new_id()

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
        "reactions": {},
    }
    if is_encrypted and inp.encryption:
        item["encryption"] = inp.encryption.model_dump()
    if is_scheduled:
        item["status"] = "scheduled"
        item["deliver_at"] = deliver_at
    if tip_amount_cents:
        item["tip_amount_cents"] = tip_amount_cents
        item["tip_currency"] = tip_currency
        item["tip_payment_id"] = tip_payment_id
        # Store the payment method on the item so the delivery loop can include it
        # in the billing entry meta when the message is eventually promoted.
        if inp.tip_payment_method_id:
            item["tip_payment_method_id"] = inp.tip_payment_method_id
        if not is_scheduled:
            # Write billing immediately only for messages delivered right now.
            # Scheduled messages defer billing to _deliver_scheduled_message so
            # that cancelling a scheduled tipped message does not charge the sender.
            recipient_id = _resolve_tip_recipient(conversation_id, user_id)
            if recipient_id:
                from app.services.tip_ledger import TipLedgerEntry, write_tip_ledger
                write_tip_ledger(TipLedgerEntry(
                    tipper_user_id=user_id,
                    recipient_user_id=recipient_id,
                    amount_cents=tip_amount_cents,
                    currency="USD",
                    content_type="message",
                    content_id=mid,
                    payment_method_id=inp.tip_payment_method_id,
                    tip_payment_id=tip_payment_id,
                    extra_meta={"conversation_id": conversation_id},
                ))

    # Validate: lock_price_cents and tip_amount_cents cannot both be set
    if inp.lock_price_cents and inp.tip_amount_cents:
        raise HTTPException(400, "Cannot combine lock_price_cents with tip_amount_cents")

    # Expiry
    # When the message is scheduled, start the timer from the scheduled delivery time
    # (deliver_at) rather than the current request time, so the recipient gets the full
    # expiry window after the message actually arrives.
    expires_at = None
    if inp.expires_in_seconds:
        expiry_base = deliver_at if is_scheduled else ts
        expires_at = expiry_base + inp.expires_in_seconds
        item["expires_at"] = expires_at
    if inp.view_once:
        item["view_once"] = True
        # Do NOT store view_once_seen as an empty set — DynamoDB rejects empty sets.
        # The ADD update in mark_message_viewed inserts the first element on first view.
    # Lock / PPV
    if inp.lock_price_cents:
        item["lock_price_cents"] = inp.lock_price_cents
        item["unlocked_by"] = {}  # pre-initialize so nested SET path works
        if inp.lock_description:
            item["lock_description"] = inp.lock_description

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
    item.update(
        _build_reply_linkage_fields(
            conversation_id=conversation_id,
            reply_to_message_id=inp.reply_to_message_id,
            actor_user_id=user_id,
            created_at=ts,
        )
    )

    tbl_msgs.put_item(Item=item)
    _sync_gallery_index_message(item)

    preview_text = "[Encrypted message]" if is_encrypted else message_text[:140]
    _send_single_destination_message(
        conversation_id=conversation_id,
        sender_id=user_id,
        message_id=mid,
        created_at=ts,
        message_item=item,
        participants=participants,
        is_scheduled=is_scheduled,
        preview_text=preview_text,
        search_text=message_text if not is_encrypted else None,
        search_kind="text" if not is_encrypted else None,
    )

    message = MessageOut(
        conversation_id=conversation_id,
        message_id=mid,
        sender_id=user_id,
        created_at=ts,
        kind="text",
        text=message_text if not is_encrypted else None,
        preview=link_preview,
        reply_to_message_id=item.get(MESSAGE_FIELD_REPLY_TO_ID),
        parent_message_id=item.get(MESSAGE_FIELD_PARENT_ID),
        thread_id=item.get(MESSAGE_FIELD_THREAD_ID),
        thread_root_message_id=item.get(MESSAGE_FIELD_THREAD_ROOT_ID),
        is_encrypted=is_encrypted,
        encryption=inp.encryption,
        scheduled=is_scheduled,
        deliver_at=deliver_at,
        tip_amount_cents=tip_amount_cents,
        tip_currency=tip_currency,
        tip_payment_id=tip_payment_id,
        expires_at=expires_at,
        view_once=inp.view_once,
        locked=bool(inp.lock_price_cents),
        lock_price_cents=inp.lock_price_cents,
        lock_description=inp.lock_description,
        is_unlocked=True,  # sender always sees their own content
    )
    if not is_scheduled:
        message = _apply_message_receipts(message, item, participants)

    if not is_scheduled:
        _fanout_new_message_event(
            conversation_id=conversation_id,
            sender_id=user_id,
            message_item=item,
            payload={
                "message_id": mid,
                "created_at": ts,
                "message": _serialize_message_event_payload(item, user_id),
            },
            respect_mute=False,
        )

    # GAP-0133: evaluate chat-bot triggers for live (non-scheduled) plaintext
    # messages and dispatch matching bot replies. Best-effort; never breaks the
    # send. Scheduled messages fire triggers at delivery time, not queue time;
    # encrypted messages are skipped because bots cannot read ciphertext.
    if not is_scheduled and not is_encrypted:
        _run_bot_trigger_evaluation(conversation_id=conversation_id, message_item=item)

    audit_event(
        "messaging_message_sent",
        user_id,
        req,
        outcome="success",
        conversation_id=conversation_id,
        message_id=mid,
        kind="text",
        is_encrypted=is_encrypted,
        reply_to_message_id=item.get(MESSAGE_FIELD_REPLY_TO_ID),
        parent_message_id=item.get(MESSAGE_FIELD_PARENT_ID),
        scheduled=is_scheduled,
        tip_amount_cents=tip_amount_cents,
    )
    _emit_message_lifecycle_archive_event_or_503(
        mutation="send",
        event_ts=ts,
        conversation_id=conversation_id,
        message_id=mid,
        actor_user_id=user_id,
        event_type="message.sent",
        payload={"mutation": "send", "scheduled": is_scheduled, "message": _serialize_message_event_payload(item, user_id)},
    )
    _meter_message_send(user_id=user_id, conversation_id=conversation_id, message_id=mid)
    return message


@router.post("/conversations/{conversation_id}/images/presign", response_model=PresignOut)
def presign_image_upload(conversation_id: str, inp: SendImagePresignIn, user_id: str = Depends(get_messaging_user_id)):
    require_participant_active(user_id, conversation_id)
    from urllib.parse import quote as _url_quote
    key = f"{conversation_id}/{user_id}/{now_ts()}_{uuid.uuid4().hex}_{inp.filename}"
    if S.dev_mode:
        # In DEV_MODE, moto presigned URLs point to inaccessible AWS endpoints.
        # Return a path-relative URL so the browser routes through the Vite proxy
        # to the in-app mock S3 PUT handler (see s3_mock.py, mounted at /mock/s3).
        upload_url = f"/mock/s3/{S3_BUCKET_IMAGES}/{_url_quote(key, safe='/')}"
    else:
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
    _kyc: object = Depends(require_kyc_tier(1)),  # GAP-0268 (inert unless enforcement flag on)
):
    require_participant_active(user_id, conversation_id)
    convo = _get_conversation_or_404(conversation_id)
    _enforce_helpdesk_send_constraints(conversation_id=conversation_id, convo=convo, user_id=user_id, req=req)
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

    # Validate send_at: must be in the future (at least 5 seconds from now)
    ts = now_ts()
    deliver_at_img: Optional[int] = None
    is_scheduled_img = False
    if inp.send_at is not None:
        if inp.send_at <= ts + 5:
            raise HTTPException(400, "send_at must be at least 5 seconds in the future")
        deliver_at_img = inp.send_at
        is_scheduled_img = True

    mid = "m_" + new_id()

    item: Dict[str, Any] = {
        "conversation_id": conversation_id,
        "message_id": mid,
        "sender_id": user_id,
        "created_at": ts,
        "kind": inp.kind,
        "reactions": {},
    }
    if inp.kind in ("file", "video"):
        item["file"] = {
            "bucket": inp.bucket,
            "key": inp.key,
            "content_type": inp.content_type,
            "name": inp.filename,
            "size": inp.filesize,
        }
    else:
        item["image"] = {
            "bucket": inp.bucket,
            "key": inp.key,
            "content_type": inp.content_type,
            "width": inp.width,
            "height": inp.height,
            "filename": inp.filename,
            "filesize": inp.filesize,
            "file_created_at": inp.file_created_at,
        }
    if inp.caption:
        item["text"] = inp.caption
    # Expiry
    # When the message is scheduled, start the timer from the scheduled delivery time
    # (deliver_at_img) rather than the current request time.
    expires_at = None
    if inp.expires_in_seconds:
        expiry_base = deliver_at_img if is_scheduled_img else ts
        expires_at = expiry_base + inp.expires_in_seconds
        item["expires_at"] = expires_at
    if inp.view_once:
        item["view_once"] = True
        # Do NOT store view_once_seen as an empty set — DynamoDB rejects empty sets.
    # Lock / PPV
    if inp.lock_price_cents:
        item["lock_price_cents"] = inp.lock_price_cents
        item["unlocked_by"] = {}  # pre-initialize so nested SET path works
        if inp.lock_description:
            item["lock_description"] = inp.lock_description
        # Store blurred preview location for locked single images
        if inp.preview_bucket and inp.preview_key:
            item["preview_bucket"] = inp.preview_bucket
            item["preview_key"] = inp.preview_key

    # Scheduling
    if is_scheduled_img:
        item["status"] = "scheduled"
        item["deliver_at"] = deliver_at_img

    # Tip attached to message
    tip_amount_cents: Optional[int] = None
    if inp.tip_amount_cents:
        if inp.lock_price_cents:
            raise HTTPException(400, "Cannot combine lock_price_cents with tip_amount_cents")
        tip_amount_cents = inp.tip_amount_cents
        _img_tip_payment_id = "tip_" + new_id()
        item["tip_amount_cents"] = tip_amount_cents
        item["tip_currency"] = "USD"
        item["tip_payment_id"] = _img_tip_payment_id
        if inp.tip_payment_method_id:
            item["tip_payment_method_id"] = inp.tip_payment_method_id
        if not is_scheduled_img:
            # Write billing immediately only for messages delivered right now.
            # Scheduled messages defer billing to _deliver_scheduled_message.
            recipient_id = _resolve_tip_recipient(conversation_id, user_id)
            if recipient_id:
                from app.services.tip_ledger import TipLedgerEntry, write_tip_ledger
                write_tip_ledger(TipLedgerEntry(
                    tipper_user_id=user_id,
                    recipient_user_id=recipient_id,
                    amount_cents=tip_amount_cents,
                    currency="USD",
                    content_type="message",
                    content_id=mid,
                    payment_method_id=inp.tip_payment_method_id,
                    tip_payment_id=_img_tip_payment_id,
                    extra_meta={"conversation_id": conversation_id},
                ))

    ttl = _message_retention_ttl(convo, ts)
    if ttl:
        item["ttl"] = ttl
    item.update(
        _build_reply_linkage_fields(
            conversation_id=conversation_id,
            reply_to_message_id=inp.reply_to_message_id,
            actor_user_id=user_id,
            created_at=ts,
        )
    )
    if inp.consumption_policy != CONSUMPTION_POLICY_NONE:
        item["consumption_policy"] = inp.consumption_policy
        item["media_kind"] = "image"

    # Encryption: store envelope without ciphertext_b64 (encrypted binary lives in S3)
    is_encrypted_img = inp.encryption is not None
    if is_encrypted_img:
        item["is_encrypted"] = True
        item["encryption"] = inp.encryption.model_dump(exclude_none=True)

    tbl_msgs.put_item(Item=item)
    _sync_gallery_index_message(item)

    _preview = inp.caption or ("[file]" if inp.kind == "file" else "[video]" if inp.kind == "video" else "[image]")
    _send_single_destination_message(
        conversation_id=conversation_id,
        sender_id=user_id,
        message_id=mid,
        created_at=ts,
        message_item=item,
        participants=participants,
        is_scheduled=is_scheduled_img,
        preview_text=_preview,
        consumption_policy=inp.consumption_policy,
        media_kind="image",
    )

    message = MessageOut(
        conversation_id=conversation_id,
        message_id=mid,
        sender_id=user_id,
        created_at=ts,
        kind=inp.kind,
        image=item.get("image"),
        file=item.get("file"),
        text=inp.caption,
        reply_to_message_id=item.get(MESSAGE_FIELD_REPLY_TO_ID),
        parent_message_id=item.get(MESSAGE_FIELD_PARENT_ID),
        thread_id=item.get(MESSAGE_FIELD_THREAD_ID),
        thread_root_message_id=item.get(MESSAGE_FIELD_THREAD_ROOT_ID),
        consumption_policy=inp.consumption_policy if inp.consumption_policy != CONSUMPTION_POLICY_NONE else None,
        media_kind="image" if inp.consumption_policy != CONSUMPTION_POLICY_NONE else None,
        consumption_state=CONSUMPTION_STATE_PENDING if inp.consumption_policy != CONSUMPTION_POLICY_NONE else None,
        expires_at=expires_at,
        view_once=inp.view_once,
        locked=bool(inp.lock_price_cents),
        lock_price_cents=inp.lock_price_cents,
        lock_description=inp.lock_description,
        is_unlocked=True,  # sender always sees their own content
        tip_amount_cents=tip_amount_cents,
        tip_currency="USD" if tip_amount_cents else None,
        scheduled=is_scheduled_img,
        deliver_at=deliver_at_img,
        is_encrypted=is_encrypted_img,
        encryption=inp.encryption,
    )
    if not is_scheduled_img:
        message = _apply_message_receipts(message, item, participants)
    audit_event(
        "messaging_message_sent",
        user_id,
        req,
        outcome="success",
        conversation_id=conversation_id,
        message_id=mid,
        kind="image",
        reply_to_message_id=item.get(MESSAGE_FIELD_REPLY_TO_ID),
        parent_message_id=item.get(MESSAGE_FIELD_PARENT_ID),
        tip_amount_cents=tip_amount_cents,
    )
    _emit_message_lifecycle_archive_event_or_503(
        mutation="send",
        event_ts=ts,
        conversation_id=conversation_id,
        message_id=mid,
        actor_user_id=user_id,
        event_type="message.sent",
        payload={"mutation": "send", "scheduled": is_scheduled_img, "message": _serialize_message_event_payload(item, user_id)},
    )
    _meter_message_send(user_id=user_id, conversation_id=conversation_id, message_id=mid)
    _meter_messaging_attachment_upload(
        user_id=user_id,
        bucket=inp.bucket,
        key=inp.key,
        conversation_id=conversation_id,
        message_id=mid,
    )
    if inp.consumption_policy != CONSUMPTION_POLICY_NONE:
        record_once_media_send(
            media_kind="image",
            consumption_policy=inp.consumption_policy,
            cohort=_extract_once_media_cohort(req),
        )
    return message


# ─── Voice Message Endpoints (MSG-002) ──────────────────────────────────────


@router.post("/conversations/{conversation_id}/voice-message/presign")
def presign_voice_message(
    conversation_id: str,
    body: PresignVoiceMessageRequest,
    user_id: str = Depends(get_messaging_user_id),
):
    """Get a presigned S3 upload URL for a voice recording."""
    if not S.voice_message_enabled:
        raise HTTPException(404, "Voice messages are not enabled")
    require_participant_active(user_id, conversation_id)
    from urllib.parse import quote as _vm_pq
    msg_id = "m_" + uuid.uuid4().hex
    ext = "webm"
    if "mp4" in body.content_type:
        ext = "mp4"
    elif "ogg" in body.content_type:
        ext = "ogg"
    elif "wav" in body.content_type:
        ext = "wav"
    s3_key = f"voice-messages/{conversation_id}/{msg_id}.{ext}"
    if S.dev_mode:
        upload_url = f"/mock/s3/{S3_BUCKET_IMAGES}/{_vm_pq(s3_key, safe='/')}"
    else:
        upload_url = s3.generate_presigned_url(
            ClientMethod="put_object",
            Params={"Bucket": S3_BUCKET_IMAGES, "Key": s3_key, "ContentType": body.content_type},
            ExpiresIn=300,
        )
    return {"message_id": msg_id, "upload_url": upload_url, "s3_key": s3_key}


@router.post("/conversations/{conversation_id}/voice-message", response_model=MessageOut)
def create_voice_message(
    conversation_id: str,
    body: CreateVoiceMessageRequest,
    req: Request = None,
    user_id: str = Depends(get_messaging_user_id),
):
    """Create a voice message after uploading the audio to S3."""
    if not S.voice_message_enabled:
        raise HTTPException(404, "Voice messages are not enabled")
    require_participant_active(user_id, conversation_id)
    convo = _get_conversation_or_404(conversation_id)
    _enforce_helpdesk_send_constraints(conversation_id=conversation_id, convo=convo, user_id=user_id, req=req)
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
    _validate_reply_target(conversation_id, body.reply_to_message_id)

    ts = now_ts()

    # Validate scheduled send
    deliver_at: Optional[int] = None
    is_scheduled = False
    if body.send_at is not None:
        if body.send_at <= ts + 5:
            raise HTTPException(400, "send_at must be at least 5 seconds in the future")
        deliver_at = body.send_at
        is_scheduled = True

    mid = body.message_id
    max_samples = S.voice_message_waveform_samples
    waveform = [max(0.0, min(1.0, float(v))) for v in body.waveform_data[:max_samples]]

    from decimal import Decimal as _DecVM
    waveform_dec = [_DecVM(str(v)) for v in waveform]
    item: Dict[str, Any] = {
        "conversation_id": conversation_id,
        "message_id": mid,
        "sender_id": user_id,
        "created_at": ts,
        "kind": "voice_message",
        "text": None,
        "audio_url": body.s3_key,
        "audio_content_type": body.content_type,
        "audio_size_bytes": body.size_bytes,
        "duration_seconds": _DecVM(str(body.duration_seconds)),
        "waveform_data": waveform_dec,
        "reactions": {},
    }

    if body.consumption_policy != CONSUMPTION_POLICY_NONE:
        item["consumption_policy"] = body.consumption_policy
        item["media_kind"] = "audio"

    # Scheduling
    if is_scheduled:
        item["status"] = "scheduled"
        item["deliver_at"] = deliver_at

    ttl = _message_retention_ttl(convo, ts)
    if ttl:
        item["ttl"] = ttl
    item.update(
        _build_reply_linkage_fields(
            conversation_id=conversation_id,
            reply_to_message_id=body.reply_to_message_id,
            actor_user_id=user_id,
            created_at=ts,
        )
    )

    tbl_msgs.put_item(Item=item)

    _send_single_destination_message(
        conversation_id=conversation_id,
        sender_id=user_id,
        message_id=mid,
        created_at=ts,
        message_item=item,
        participants=participants,
        is_scheduled=is_scheduled,
        preview_text="[Voice message]",
        consumption_policy=body.consumption_policy,
        media_kind="audio" if body.consumption_policy != CONSUMPTION_POLICY_NONE else None,
    )

    from urllib.parse import quote as _vm_url_quote2
    _vm_audio_url_out = ""
    if body.s3_key:
        if S.dev_mode:
            _vm_audio_url_out = f"/mock/s3/{S3_BUCKET_IMAGES}/{_vm_url_quote2(body.s3_key, safe='/')}"
        else:
            _vm_audio_url_out = body.s3_key

    message = MessageOut(
        conversation_id=conversation_id,
        message_id=mid,
        sender_id=user_id,
        created_at=ts,
        kind="voice_message",
        voice_message={
            "audio_url": _vm_audio_url_out,
            "audio_content_type": body.content_type,
            "audio_size_bytes": body.size_bytes,
            "duration_seconds": float(body.duration_seconds),
            "waveform_data": waveform,
        },
        reply_to_message_id=item.get(MESSAGE_FIELD_REPLY_TO_ID),
        parent_message_id=item.get(MESSAGE_FIELD_PARENT_ID),
        thread_id=item.get(MESSAGE_FIELD_THREAD_ID),
        thread_root_message_id=item.get(MESSAGE_FIELD_THREAD_ROOT_ID),
        consumption_policy=body.consumption_policy if body.consumption_policy != CONSUMPTION_POLICY_NONE else None,
        media_kind="audio" if body.consumption_policy != CONSUMPTION_POLICY_NONE else None,
        consumption_state=CONSUMPTION_STATE_PENDING if body.consumption_policy != CONSUMPTION_POLICY_NONE else None,
        scheduled=is_scheduled,
        deliver_at=deliver_at,
    )
    if not is_scheduled:
        message = _apply_message_receipts(message, item, participants)
    audit_event(
        "messaging_message_sent",
        user_id,
        req,
        outcome="success",
        conversation_id=conversation_id,
        message_id=mid,
        kind="voice_message",
        reply_to_message_id=item.get(MESSAGE_FIELD_REPLY_TO_ID),
        parent_message_id=item.get(MESSAGE_FIELD_PARENT_ID),
    )
    _emit_message_lifecycle_archive_event_or_503(
        mutation="send",
        event_ts=ts,
        conversation_id=conversation_id,
        message_id=mid,
        actor_user_id=user_id,
        event_type="message.sent",
        payload={"mutation": "send", "scheduled": is_scheduled, "message": _serialize_message_event_payload(item, user_id)},
    )
    _meter_message_send(user_id=user_id, conversation_id=conversation_id, message_id=mid)
    return message


# ─── Voicemail Endpoints (CALL-014) ──────────────────────────────────────────

VOICEMAIL_ELIGIBLE_STATES = {"declined", "missed", "busy"}


@router.post("/conversations/{conversation_id}/voicemail/presign")
def presign_voicemail(
    conversation_id: str,
    body: PresignVoicemailRequest,
    user_id: str = Depends(get_messaging_user_id),
):
    """Get a presigned S3 upload URL for a voicemail recording."""
    if not S.voicemail_enabled:
        raise HTTPException(404, "Voicemail is not enabled")
    require_participant_active(user_id, conversation_id)

    from app.services.messaging_call_sessions import get_call_session
    call = get_call_session(body.call_id)
    if not call:
        raise HTTPException(404, "Call not found")
    if call.conversation_id != conversation_id:
        raise HTTPException(400, "Call does not belong to this conversation")
    if call.caller_user_id != user_id:
        raise HTTPException(403, "Only the caller can leave a voicemail")
    if call.state not in VOICEMAIL_ELIGIBLE_STATES:
        raise HTTPException(400, f"Call state '{call.state}' is not voicemail-eligible")
    if call.paid:
        raise HTTPException(400, "Voicemail is not available for paid calls")
    if call.voicemail_message_id:
        raise HTTPException(409, "A voicemail has already been left for this call")

    msg_id = "m_" + uuid.uuid4().hex
    ext = "webm"
    if "mp4" in body.content_type:
        ext = "mp4"
    elif "ogg" in body.content_type:
        ext = "ogg"
    elif "wav" in body.content_type:
        ext = "wav"
    s3_key = f"voicemails/{conversation_id}/{msg_id}.{ext}"

    from urllib.parse import quote as _vml_pq
    if S.dev_mode:
        upload_url = f"/mock/s3/{S3_BUCKET_IMAGES}/{_vml_pq(s3_key, safe='/')}"
    else:
        upload_url = s3.generate_presigned_url(
            ClientMethod="put_object",
            Params={"Bucket": S3_BUCKET_IMAGES, "Key": s3_key, "ContentType": body.content_type},
            ExpiresIn=300,
        )
    return {"message_id": msg_id, "upload_url": upload_url, "s3_key": s3_key}


@router.post("/conversations/{conversation_id}/voicemail", response_model=MessageOut)
def create_voicemail(
    conversation_id: str,
    body: CreateVoicemailRequest,
    req: Request = None,
    user_id: str = Depends(get_messaging_user_id),
):
    """Create a voicemail message after uploading the recording to S3."""
    if not S.voicemail_enabled:
        raise HTTPException(404, "Voicemail is not enabled")
    require_participant_active(user_id, conversation_id)

    from app.services.messaging_call_sessions import get_call_session, set_voicemail_message_id
    call = get_call_session(body.call_id)
    if not call:
        raise HTTPException(404, "Call not found")
    if call.conversation_id != conversation_id:
        raise HTTPException(400, "Call does not belong to this conversation")
    if call.caller_user_id != user_id:
        raise HTTPException(403, "Only the caller can leave a voicemail")
    if call.state not in VOICEMAIL_ELIGIBLE_STATES:
        raise HTTPException(400, f"Call state '{call.state}' is not voicemail-eligible")
    if call.paid:
        raise HTTPException(400, "Voicemail is not available for paid calls")
    if call.voicemail_message_id:
        raise HTTPException(409, "A voicemail has already been left for this call")

    convo = _get_conversation_or_404(conversation_id)
    ts = now_ts()
    mid = body.message_id

    max_samples = S.voice_message_waveform_samples
    waveform = [max(0.0, min(1.0, float(v))) for v in body.waveform_data[:max_samples]]
    from decimal import Decimal as _DecVML
    waveform_dec = [_DecVML(str(v)) for v in waveform]

    item: Dict[str, Any] = {
        "conversation_id": conversation_id,
        "message_id": mid,
        "sender_id": user_id,
        "created_at": ts,
        "kind": "voicemail",
        "text": None,
        "call_id": body.call_id,
        "voicemail_mode": body.mode,
        "duration_seconds": _DecVML(str(body.duration_seconds)),
        "waveform_data": waveform_dec,
        "call_state": call.state,
        "caller_user_id": call.caller_user_id,
        "callee_user_id": call.callee_user_id,
        "reactions": {},
    }

    if body.mode == "video":
        item["video_url"] = body.s3_key
        item["video_content_type"] = body.content_type
        item["video_size_bytes"] = body.size_bytes
    else:
        item["audio_url"] = body.s3_key
        item["audio_content_type"] = body.content_type
        item["audio_size_bytes"] = body.size_bytes

    ttl = _message_retention_ttl(convo, ts)
    if ttl:
        item["ttl"] = ttl

    tbl_msgs.put_item(Item=item)

    # Link voicemail to call session
    set_voicemail_message_id(call_id=body.call_id, voicemail_message_id=mid)

    # Lookup participants for SSE and notification
    try:
        resp = tbl_parts.query(IndexName="GSI1", KeyConditionExpression=Key("GSI1PK").eq(conversation_id))
        participants = resp.get("Items", [])
    except Exception:
        participants = []

    _send_single_destination_message(
        conversation_id=conversation_id,
        sender_id=user_id,
        message_id=mid,
        created_at=ts,
        message_item=item,
        participants=participants,
        is_scheduled=False,
        preview_text="[Voicemail]",
    )

    # Dispatch alert to callee (or all group members)
    try:
        from app.services.alerts import write_alert
        for participant in participants:
            participant_user_id = str(participant.get("user_id") or "")
            if participant_user_id and participant_user_id != user_id:
                try:
                    write_alert(
                        user_sub=participant_user_id,
                        event="voicemail_received",
                        outcome="info",
                        title="Missed call — voicemail left",
                        details={
                            "conversation_id": conversation_id,
                            "message_id": mid,
                            "call_id": body.call_id,
                            "caller_user_id": user_id,
                            "voicemail_mode": body.mode,
                            "duration_seconds": body.duration_seconds,
                        },
                    )
                except Exception:
                    pass  # best-effort delivery
    except Exception:
        pass

    # Build response
    from urllib.parse import quote as _vml_url_quote2
    _vml_media_url_out = ""
    if body.s3_key:
        if S.dev_mode:
            _vml_media_url_out = f"/mock/s3/{S3_BUCKET_IMAGES}/{_vml_url_quote2(body.s3_key, safe='/')}"
        else:
            _vml_media_url_out = body.s3_key

    message = MessageOut(
        conversation_id=conversation_id,
        message_id=mid,
        sender_id=user_id,
        created_at=ts,
        kind="voicemail",
        voicemail={
            "call_id": body.call_id,
            "mode": body.mode,
            "audio_url": _vml_media_url_out if body.mode == "audio" else None,
            "video_url": _vml_media_url_out if body.mode == "video" else None,
            "content_type": body.content_type,
            "size_bytes": body.size_bytes,
            "duration_seconds": float(body.duration_seconds),
            "waveform_data": waveform,
            "call_state": call.state,
            "caller_user_id": call.caller_user_id,
            "callee_user_id": call.callee_user_id,
        },
    )
    return message


@router.post("/conversations/{conversation_id}/messages/gallery", response_model=MessageOut)
def create_gallery_message(
    conversation_id: str,
    inp: CreateGalleryMessageIn,
    req: Request = None,
    user_id: str = Depends(get_messaging_user_id),
):
    require_participant_active(user_id, conversation_id)
    convo = _get_conversation_or_404(conversation_id)
    _enforce_helpdesk_send_constraints(conversation_id=conversation_id, convo=convo, user_id=user_id, req=req)
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

    ts = now_ts()
    deliver_at_gal: Optional[int] = None
    is_scheduled_gal = False
    if inp.send_at is not None:
        if inp.send_at <= ts + 5:
            raise HTTPException(400, "send_at must be at least 5 seconds in the future")
        deliver_at_gal = inp.send_at
        is_scheduled_gal = True

    mid = "m_" + new_id()

    # Serialize image lists for DDB storage
    def _serialize_img(img: GalleryImageItemIn) -> dict:
        d: Dict[str, Any] = {
            "bucket": img.bucket,
            "key": img.key,
            "content_type": img.content_type,
        }
        if img.width is not None:
            d["width"] = img.width
        if img.height is not None:
            d["height"] = img.height
        if img.filename:
            d["filename"] = img.filename
        if img.filesize is not None:
            d["filesize"] = img.filesize
        if img.preview_bucket:
            d["preview_bucket"] = img.preview_bucket
        if img.preview_key:
            d["preview_key"] = img.preview_key
        return d

    item: Dict[str, Any] = {
        "conversation_id": conversation_id,
        "message_id": mid,
        "sender_id": user_id,
        "created_at": ts,
        "kind": "gallery",
        "reactions": {},
        "free_images": [_serialize_img(img) for img in inp.free_images],
        "locked_images": [_serialize_img(img) for img in inp.locked_images],
    }

    if inp.text:
        item["text"] = inp.text

    # Expiry
    expires_at_gal = None
    if inp.expires_in_seconds:
        expiry_base = deliver_at_gal if is_scheduled_gal else ts
        expires_at_gal = expiry_base + inp.expires_in_seconds
        item["expires_at"] = expires_at_gal

    # Lock / PPV for locked images
    if inp.lock_price_cents:
        item["lock_price_cents"] = inp.lock_price_cents
        item["unlocked_by"] = {}
        if inp.lock_description:
            item["lock_description"] = inp.lock_description

    # Scheduling
    if is_scheduled_gal:
        item["status"] = "scheduled"
        item["deliver_at"] = deliver_at_gal

    # Tip attached to message
    gal_tip_amount_cents: Optional[int] = None
    if inp.tip_amount_cents:
        if inp.lock_price_cents:
            raise HTTPException(400, "Cannot combine lock_price_cents with tip_amount_cents")
        gal_tip_amount_cents = inp.tip_amount_cents
        _gal_tip_payment_id = "tip_" + new_id()
        item["tip_amount_cents"] = gal_tip_amount_cents
        item["tip_currency"] = "USD"
        item["tip_payment_id"] = _gal_tip_payment_id
        if inp.tip_payment_method_id:
            item["tip_payment_method_id"] = inp.tip_payment_method_id
        if not is_scheduled_gal:
            recipient_id = _resolve_tip_recipient(conversation_id, user_id)
            if recipient_id:
                from app.services.tip_ledger import TipLedgerEntry, write_tip_ledger
                write_tip_ledger(TipLedgerEntry(
                    tipper_user_id=user_id,
                    recipient_user_id=recipient_id,
                    amount_cents=gal_tip_amount_cents,
                    currency="USD",
                    content_type="message",
                    content_id=mid,
                    payment_method_id=inp.tip_payment_method_id,
                    tip_payment_id=_gal_tip_payment_id,
                    extra_meta={"conversation_id": conversation_id},
                ))

    ttl = _message_retention_ttl(convo, ts)
    if ttl:
        item["ttl"] = ttl

    tbl_msgs.put_item(Item=item)

    _preview = inp.text or f"[Gallery: {len(inp.free_images)} free + {len(inp.locked_images)} locked]"
    _send_single_destination_message(
        conversation_id=conversation_id,
        sender_id=user_id,
        message_id=mid,
        created_at=ts,
        message_item=item,
        participants=participants,
        is_scheduled=is_scheduled_gal,
        preview_text=_preview,
    )

    # Build response: sender always sees all images
    free_imgs_out = [_project_gallery_image(img.model_dump()) for img in inp.free_images]
    locked_imgs_out = [_project_gallery_image(img.model_dump()) for img in inp.locked_images]

    message = MessageOut(
        conversation_id=conversation_id,
        message_id=mid,
        sender_id=user_id,
        created_at=ts,
        kind="gallery",
        text=inp.text,
        free_images=free_imgs_out if not expires_at_gal or ts < expires_at_gal else None,
        locked_images=locked_imgs_out if not expires_at_gal or ts < expires_at_gal else None,
        locked_image_count=len(inp.locked_images),
        expires_at=expires_at_gal,
        locked=bool(inp.lock_price_cents),
        lock_price_cents=inp.lock_price_cents,
        lock_description=inp.lock_description,
        is_unlocked=True,  # sender always sees their own content
        tip_amount_cents=gal_tip_amount_cents,
        tip_currency="USD" if gal_tip_amount_cents else None,
        scheduled=is_scheduled_gal,
        deliver_at=deliver_at_gal,
    )
    if not is_scheduled_gal:
        message = _apply_message_receipts(message, item, participants)

    audit_event(
        "messaging_message_sent",
        user_id,
        req,
        outcome="success",
        conversation_id=conversation_id,
        message_id=mid,
        kind="gallery",
    )
    _emit_message_lifecycle_archive_event_or_503(
        mutation="send",
        event_ts=ts,
        conversation_id=conversation_id,
        message_id=mid,
        actor_user_id=user_id,
        event_type="message.sent",
        payload={"mutation": "send", "scheduled": is_scheduled_gal, "message": _serialize_message_event_payload(item, user_id)},
    )
    _meter_message_send(user_id=user_id, conversation_id=conversation_id, message_id=mid)
    return message


@router.post("/conversations/{conversation_id}/messages/file-share", response_model=MessageOut)
def create_file_share_message(
    conversation_id: str,
    inp: CreateFileShareMessageIn,
    req: Request = None,
    user_id: str = Depends(get_messaging_user_id),
    _kyc: object = Depends(require_kyc_tier(1)),  # GAP-0268 (inert unless enforcement flag on)
):
    require_participant_active(user_id, conversation_id)
    convo = _get_conversation_or_404(conversation_id)
    try:
        resp = tbl_parts.query(IndexName="GSI1", KeyConditionExpression=Key("GSI1PK").eq(conversation_id))
        participants = resp.get("Items", [])
    except Exception:
        participants = []

    # Validate file exists and is owned by the sender
    file_path_norm = norm_path(inp.file_path, is_folder=None)
    node = get_node(user_id, file_path_norm)  # raises 404 if not found or owned by another user

    # Share the file with every non-sender participant (best-effort)
    for participant in participants:
        pid = participant.get("user_id")
        if pid and pid != user_id:
            try:
                share_node(user_id, file_path_norm, pid, inp.permission)
            except Exception:
                pass  # do not fail the send if the share operation fails

    ts = now_ts()
    deliver_at_fs: Optional[int] = None
    is_scheduled_fs = False
    if inp.send_at is not None:
        if inp.send_at <= ts + 5:
            raise HTTPException(400, "send_at must be at least 5 seconds in the future")
        deliver_at_fs = inp.send_at
        is_scheduled_fs = True

    mid = "m_" + new_id()

    file_share_data: Dict[str, Any] = {
        "path": node.get("path", file_path_norm),
        "name": node.get("name") or file_path_norm.rstrip("/").rsplit("/", 1)[-1],
        "size": int(node["size"]) if node.get("size") is not None else None,
        "content_type": node.get("content_type"),
        "permission": inp.permission,
        "owner": user_id,
        "is_encrypted": bool(node.get("is_encrypted")),
    }

    item: Dict[str, Any] = {
        "conversation_id": conversation_id,
        "message_id": mid,
        "sender_id": user_id,
        "created_at": ts,
        "kind": "file_share",
        "reactions": {},
        "file_share": file_share_data,
    }

    if inp.text:
        item["text"] = inp.text
    if is_scheduled_fs:
        item["status"] = "scheduled"
        item["deliver_at"] = deliver_at_fs

    ttl = _message_retention_ttl(convo, ts)
    if ttl:
        item["ttl"] = ttl

    tbl_msgs.put_item(Item=item)

    if not is_scheduled_fs:
        _bump_unread_counts(conversation_id, user_id, participants)
        _record_delivery_receipts(conversation_id, mid, user_id, participants)

        preview_text = inp.text or f"[Shared file: {file_share_data['name']}]"
        tbl_convos.update_item(
            Key={"conversation_id": conversation_id},
            UpdateExpression="SET last_message_at = :ts, last_message_preview = :p, last_message_id = :mid",
            ExpressionAttributeValues={":ts": ts, ":p": preview_text, ":mid": mid},
        )

        _fanout_new_message_event(
            conversation_id=conversation_id,
            sender_id=user_id,
            message_item=item,
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
        kind="file_share",
        scheduled=is_scheduled_fs,
    )
    _emit_message_lifecycle_archive_event_or_503(
        mutation="send",
        event_ts=ts,
        conversation_id=conversation_id,
        message_id=mid,
        actor_user_id=user_id,
        event_type="message.sent",
        payload={"mutation": "send", "scheduled": is_scheduled_fs, "message": _serialize_message_event_payload(item, user_id)},
    )
    _meter_message_send(user_id=user_id, conversation_id=conversation_id, message_id=mid)
    return _message_out_from_item(item, user_id)


@router.post("/conversations/{conversation_id}/messages/video-share", response_model=MessageOut)
def create_video_share_message(
    conversation_id: str,
    inp: CreateVideoShareMessageIn,
    req: Request = None,
    user_id: str = Depends(get_messaging_user_id),
):
    if not getattr(S, "video_sharing_enabled", True):
        raise HTTPException(403, "video sharing is disabled")
    require_participant_active(user_id, conversation_id)
    convo = _get_conversation_or_404(conversation_id)
    try:
        resp = tbl_parts.query(IndexName="GSI1", KeyConditionExpression=Key("GSI1PK").eq(conversation_id))
        participants = resp.get("Items", [])
    except Exception:
        participants = []

    from app.services.video_metadata_store import get_video as _get_vod_video
    try:
        video = _get_vod_video(inp.video_id)
    except HTTPException:
        raise HTTPException(404, "video not found")

    is_owner = video.owner_user_id == user_id
    if not is_owner:
        if video.status != "published":
            raise HTTPException(403, "video is not published")
        if video.visibility == "private":
            raise HTTPException(403, "cannot share a private video you do not own")
    if is_owner and video.status not in ("approved", "published"):
        raise HTTPException(400, "video must be approved or published to share")

    from decimal import Decimal as _DecVS
    video_share_data: Dict[str, Any] = {
        "video_id": video.id,
        "owner_user_id": video.owner_user_id,
        "title": video.title,
        "thumbnail_url": video.thumbnail_url,
        "duration_seconds": _DecVS(str(video.duration_seconds)) if video.duration_seconds is not None else None,
        "width": video.width,
        "height": video.height,
        "visibility": video.visibility,
        "drm_enabled": getattr(video, "drm_enabled", False),
    }

    ts = now_ts()
    deliver_at_vs: Optional[int] = None
    is_scheduled_vs = False
    if inp.send_at is not None:
        if inp.send_at <= ts + 5:
            raise HTTPException(400, "send_at must be at least 5 seconds in the future")
        deliver_at_vs = inp.send_at
        is_scheduled_vs = True

    mid = "m_" + new_id()

    item: Dict[str, Any] = {
        "conversation_id": conversation_id,
        "message_id": mid,
        "sender_id": user_id,
        "created_at": ts,
        "kind": "video_share",
        "video_share": video_share_data,
        "reactions": {},
    }
    if inp.text:
        item["text"] = inp.text
    if is_scheduled_vs:
        item["status"] = "scheduled"
        item["deliver_at"] = deliver_at_vs

    ttl = _message_retention_ttl(convo, ts)
    if ttl:
        item["ttl"] = ttl

    tbl_msgs.put_item(Item=item)

    if not is_scheduled_vs:
        _bump_unread_counts(conversation_id, user_id, participants)
        _record_delivery_receipts(conversation_id, mid, user_id, participants)

        preview_text = inp.text or f"[Shared video: {video_share_data['title']}]"
        tbl_convos.update_item(
            Key={"conversation_id": conversation_id},
            UpdateExpression="SET last_message_at = :ts, last_message_preview = :p, last_message_id = :mid",
            ExpressionAttributeValues={":ts": ts, ":p": preview_text[:200], ":mid": mid},
        )

        _fanout_new_message_event(
            conversation_id=conversation_id,
            sender_id=user_id,
            message_item=item,
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
        kind="video_share",
        scheduled=is_scheduled_vs,
    )
    _emit_message_lifecycle_archive_event_or_503(
        mutation="send",
        event_ts=ts,
        conversation_id=conversation_id,
        message_id=mid,
        actor_user_id=user_id,
        event_type="message.sent",
        payload={"mutation": "send", "scheduled": is_scheduled_vs, "message": _serialize_message_event_payload(item, user_id)},
    )
    _meter_message_send(user_id=user_id, conversation_id=conversation_id, message_id=mid)
    return _message_out_from_item(item, user_id)


# -------------------------
# Calendar messaging helpers
# -------------------------

def _share_calendar_to_user(calendar_id: str, recipient_sub: str, permission: str, granter_sub: str) -> None:
    """Grant a calendar share to a recipient user — mirrors calendar.py share_calendar logic."""
    from datetime import datetime, timezone as _tz
    now = datetime.now(_tz.utc).isoformat().replace("+00:00", "Z")
    # Write the share record on the calendar partition
    T.calendar.put_item(Item={
        "calendar_id": calendar_id,
        "sk": f"share#{recipient_sub}",
        "type": "calendar_share",
        "user_sub": recipient_sub,
        "permission": permission,
        "created_at_utc": now,
        "granted_by": granter_sub,
    })
    # Write the access index record so the calendar appears in the recipient's calendar list
    T.calendar.put_item(Item={
        "calendar_id": f"user#{recipient_sub}",
        "sk": f"calendar#{calendar_id}",
        "type": "calendar_access",
        "target_calendar_id": calendar_id,
        "permission": permission,
        "created_at_utc": now,
    })


@router.post("/conversations/{conversation_id}/messages/calendar-share", response_model=MessageOut)
def create_calendar_share_message(
    conversation_id: str,
    inp: CreateCalendarShareMessageIn,
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

    # Validate calendar exists and is owned by sender
    cal_item = T.calendar.get_item(Key={"calendar_id": inp.calendar_id, "sk": "meta"}).get("Item")
    if not cal_item:
        raise HTTPException(404, "Calendar not found")
    if cal_item.get("owner_user_sub") != user_id:
        raise HTTPException(403, "You do not own this calendar")

    # Share the calendar with all non-sender participants (best-effort)
    for participant in participants:
        pid = participant.get("user_id")
        if pid and pid != user_id:
            try:
                _share_calendar_to_user(inp.calendar_id, pid, inp.permission, user_id)
            except Exception:
                pass

    # Optionally create/retrieve a booking link
    booking_link_id: Optional[str] = None
    booking_public_url: Optional[str] = None
    if inp.include_booking_link:
        try:
            existing_links = T.calendar.query(
                KeyConditionExpression=Key("calendar_id").eq(inp.calendar_id) & Key("sk").begins_with("booking#"),
            ).get("Items", [])
            if existing_links:
                link_item = existing_links[0]
                booking_link_id = link_item.get("link_id")
            else:
                booking_link_id = new_id()
                from datetime import datetime, timezone as _tz
                now_iso = datetime.now(_tz.utc).isoformat().replace("+00:00", "Z")
                T.calendar.put_item(Item={
                    "calendar_id": inp.calendar_id,
                    "sk": f"booking#{booking_link_id}",
                    "type": "booking_link",
                    "link_id": booking_link_id,
                    "name": f"{cal_item.get('name', 'Meeting')} — 30 min",
                    "duration_minutes": 30,
                    "timezone": cal_item.get("timezone", "UTC"),
                    "created_at_utc": now_iso,
                    "owner_user_sub": user_id,
                })
            if booking_link_id:
                booking_public_url = f"/booking/{booking_link_id}"
        except Exception:
            pass

    ts = now_ts()
    deliver_at_cs: Optional[int] = None
    is_scheduled_cs = False
    if inp.send_at is not None:
        if inp.send_at <= ts + 5:
            raise HTTPException(400, "send_at must be at least 5 seconds in the future")
        deliver_at_cs = inp.send_at
        is_scheduled_cs = True

    mid = "m_" + new_id()

    calendar_share_data: Dict[str, Any] = {
        "calendar_id": inp.calendar_id,
        "name": cal_item.get("name", ""),
        "owner": user_id,
        "permission": inp.permission,
    }
    if booking_link_id:
        calendar_share_data["booking_link_id"] = booking_link_id
    if booking_public_url:
        calendar_share_data["booking_public_url"] = booking_public_url

    item: Dict[str, Any] = {
        "conversation_id": conversation_id,
        "message_id": mid,
        "sender_id": user_id,
        "created_at": ts,
        "kind": "calendar_share",
        "reactions": {},
        "calendar_share": calendar_share_data,
    }
    if inp.text:
        item["text"] = inp.text
    if is_scheduled_cs:
        item["status"] = "scheduled"
        item["deliver_at"] = deliver_at_cs

    ttl = _message_retention_ttl(convo, ts)
    if ttl:
        item["ttl"] = ttl

    tbl_msgs.put_item(Item=item)

    if not is_scheduled_cs:
        _bump_unread_counts(conversation_id, user_id, participants)
        _record_delivery_receipts(conversation_id, mid, user_id, participants)
        preview_text = inp.text or f"[Shared calendar: {calendar_share_data['name']}]"
        tbl_convos.update_item(
            Key={"conversation_id": conversation_id},
            UpdateExpression="SET last_message_at = :ts, last_message_preview = :p, last_message_id = :mid",
            ExpressionAttributeValues={":ts": ts, ":p": preview_text, ":mid": mid},
        )
        _fanout_new_message_event(
            conversation_id=conversation_id,
            sender_id=user_id,
            message_item=item,
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
        kind="calendar_share",
        scheduled=is_scheduled_cs,
    )
    _emit_message_lifecycle_archive_event_or_503(
        mutation="send",
        event_ts=ts,
        conversation_id=conversation_id,
        message_id=mid,
        actor_user_id=user_id,
        event_type="message.sent",
        payload={"mutation": "send", "scheduled": is_scheduled_cs, "message": _serialize_message_event_payload(item, user_id)},
    )
    _meter_message_send(user_id=user_id, conversation_id=conversation_id, message_id=mid)
    return _message_out_from_item(item, user_id)


@router.post("/conversations/{conversation_id}/messages/calendar-event", response_model=MessageOut)
def create_calendar_event_message(
    conversation_id: str,
    inp: CreateCalendarEventMessageIn,
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

    # Validate calendar access and load event
    cal_item = T.calendar.get_item(Key={"calendar_id": inp.calendar_id, "sk": "meta"}).get("Item")
    if not cal_item:
        raise HTTPException(404, "Calendar not found")
    if cal_item.get("owner_user_sub") != user_id:
        raise HTTPException(403, "You do not own this calendar")

    event_item = T.calendar.get_item(Key={"calendar_id": inp.calendar_id, "sk": f"event#{inp.event_id}"}).get("Item")
    if not event_item:
        raise HTTPException(404, "Event not found")

    ts = now_ts()
    deliver_at_ce: Optional[int] = None
    is_scheduled_ce = False
    if inp.send_at is not None:
        if inp.send_at <= ts + 5:
            raise HTTPException(400, "send_at must be at least 5 seconds in the future")
        deliver_at_ce = inp.send_at
        is_scheduled_ce = True

    mid = "m_" + new_id()

    calendar_event_data: Dict[str, Any] = {
        "event_id": inp.event_id,
        "calendar_id": inp.calendar_id,
        "name": event_item.get("name", ""),
        "start_utc": event_item.get("start_utc"),
        "end_utc": event_item.get("end_utc"),
        "all_day": bool(event_item.get("all_day", False)),
        "all_day_date": event_item.get("all_day_date"),
        "timezone": event_item.get("timezone", "UTC"),
        "description": event_item.get("description"),
        "owner": user_id,
    }

    item: Dict[str, Any] = {
        "conversation_id": conversation_id,
        "message_id": mid,
        "sender_id": user_id,
        "created_at": ts,
        "kind": "calendar_event",
        "reactions": {},
        "calendar_event": calendar_event_data,
    }
    if inp.text:
        item["text"] = inp.text
    if is_scheduled_ce:
        item["status"] = "scheduled"
        item["deliver_at"] = deliver_at_ce

    ttl = _message_retention_ttl(convo, ts)
    if ttl:
        item["ttl"] = ttl

    tbl_msgs.put_item(Item=item)

    if not is_scheduled_ce:
        _bump_unread_counts(conversation_id, user_id, participants)
        _record_delivery_receipts(conversation_id, mid, user_id, participants)
        preview_text = inp.text or f"[Event: {calendar_event_data['name']}]"
        tbl_convos.update_item(
            Key={"conversation_id": conversation_id},
            UpdateExpression="SET last_message_at = :ts, last_message_preview = :p, last_message_id = :mid",
            ExpressionAttributeValues={":ts": ts, ":p": preview_text, ":mid": mid},
        )
        _fanout_new_message_event(
            conversation_id=conversation_id,
            sender_id=user_id,
            message_item=item,
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
        kind="calendar_event",
        scheduled=is_scheduled_ce,
    )
    _emit_message_lifecycle_archive_event_or_503(
        mutation="send",
        event_ts=ts,
        conversation_id=conversation_id,
        message_id=mid,
        actor_user_id=user_id,
        event_type="message.sent",
        payload={"mutation": "send", "scheduled": is_scheduled_ce, "message": _serialize_message_event_payload(item, user_id)},
    )
    _meter_message_send(user_id=user_id, conversation_id=conversation_id, message_id=mid)
    return _message_out_from_item(item, user_id)


@router.post("/conversations/{conversation_id}/messages/meeting-poll", response_model=MessageOut)
def create_meeting_poll_message(
    conversation_id: str,
    inp: CreateMeetingPollMessageIn,
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

    poll_id = new_id()
    ts = now_ts()
    mid = "m_" + new_id()

    slots_data = []
    for slot in inp.slots:
        slots_data.append({
            "slot_id": new_id(),
            "start_utc": slot.start_utc,
            "end_utc": slot.end_utc,
        })

    # Store poll metadata in T.calendar table (reusing as single-table store)
    T.calendar.put_item(Item={
        "calendar_id": f"MPOLL#{poll_id}",
        "sk": "meta",
        "type": "meeting_poll",
        "poll_id": poll_id,
        "conversation_id": conversation_id,
        "title": inp.title,
        "duration_minutes": inp.duration_minutes,
        "slots": slots_data,
        "status": "open",
        "creator_id": user_id,
        "confirmed_slot_id": None,
        "created_at": ts,
    })

    meeting_poll_data: Dict[str, Any] = {
        "poll_id": poll_id,
        "creator_id": user_id,
        "title": inp.title,
        "duration_minutes": inp.duration_minutes,
        "status": "open",
        "confirmed_slot_id": None,
    }

    item: Dict[str, Any] = {
        "conversation_id": conversation_id,
        "message_id": mid,
        "sender_id": user_id,
        "created_at": ts,
        "kind": "meeting_poll",
        "reactions": {},
        "meeting_poll": meeting_poll_data,
    }
    if inp.text:
        item["text"] = inp.text

    ttl = _message_retention_ttl(convo, ts)
    if ttl:
        item["ttl"] = ttl

    tbl_msgs.put_item(Item=item)

    _bump_unread_counts(conversation_id, user_id, participants)
    _record_delivery_receipts(conversation_id, mid, user_id, participants)
    preview_text = inp.text or f"[Meeting poll: {inp.title}]"
    tbl_convos.update_item(
        Key={"conversation_id": conversation_id},
        UpdateExpression="SET last_message_at = :ts, last_message_preview = :p, last_message_id = :mid",
        ExpressionAttributeValues={":ts": ts, ":p": preview_text, ":mid": mid},
    )
    _fanout_new_message_event(
        conversation_id=conversation_id,
        sender_id=user_id,
        message_item=item,
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
        kind="meeting_poll",
    )
    _emit_message_lifecycle_archive_event_or_503(
        mutation="send",
        event_ts=ts,
        conversation_id=conversation_id,
        message_id=mid,
        actor_user_id=user_id,
        event_type="message.sent",
        payload={"mutation": "send", "scheduled": False, "message": _serialize_message_event_payload(item, user_id)},
    )
    _meter_message_send(user_id=user_id, conversation_id=conversation_id, message_id=mid)
    return _message_out_from_item(item, user_id)


@router.post("/conversations/{conversation_id}/messages/countdown", response_model=MessageOut, status_code=201)
def create_countdown_message(
    conversation_id: str,
    inp: SendCountdownMessageIn,
    req: Request = None,
    user_id: str = Depends(get_messaging_user_id),
):
    """Send a countdown message to a conversation (MSG-010)."""
    if not S.countdown_messages_enabled:
        raise HTTPException(403, "Countdown messages are not enabled")
    require_participant_active(user_id, conversation_id)
    convo = _get_conversation_or_404(conversation_id)
    _validate_reply_target(conversation_id, inp.reply_to_message_id)
    try:
        resp = tbl_parts.query(IndexName="GSI1", KeyConditionExpression=Key("GSI1PK").eq(conversation_id))
        participants = resp.get("Items", [])
    except Exception:
        participants = []

    ts = now_ts()
    mid = "m_" + new_id()

    item: Dict[str, Any] = {
        "conversation_id": conversation_id,
        "message_id": mid,
        "sender_id": user_id,
        "created_at": ts,
        "kind": "countdown",
        "reactions": {},
        "text": inp.title,
        "countdown_title": inp.title,
        "target_datetime": inp.target_datetime,
        "associated_event_type": inp.associated_event_type,
    }
    if inp.associated_event_id:
        item["associated_event_id"] = inp.associated_event_id
    if inp.reply_to_message_id:
        item[MESSAGE_FIELD_REPLY_TO_ID] = inp.reply_to_message_id

    ttl = _message_retention_ttl(convo, ts)
    if ttl:
        item["ttl"] = ttl

    tbl_msgs.put_item(Item=item)

    _bump_unread_counts(conversation_id, user_id, participants)
    _record_delivery_receipts(conversation_id, mid, user_id, participants)
    preview_text = f"[Countdown: {inp.title}]"
    tbl_convos.update_item(
        Key={"conversation_id": conversation_id},
        UpdateExpression="SET last_message_at = :ts, last_message_preview = :p, last_message_id = :mid",
        ExpressionAttributeValues={":ts": ts, ":p": preview_text, ":mid": mid},
    )
    _fanout_new_message_event(
        conversation_id=conversation_id,
        sender_id=user_id,
        message_item=item,
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
        kind="countdown",
    )
    _emit_message_lifecycle_archive_event_or_503(
        mutation="send",
        event_ts=ts,
        conversation_id=conversation_id,
        message_id=mid,
        actor_user_id=user_id,
        event_type="message.sent",
        payload={"mutation": "send", "scheduled": False, "message": _serialize_message_event_payload(item, user_id)},
    )
    _meter_message_send(user_id=user_id, conversation_id=conversation_id, message_id=mid)
    return _message_out_from_item(item, user_id)


@router.post("/conversations/{conversation_id}/messages/gif", response_model=MessageOut, status_code=201)
def send_gif_message(
    conversation_id: str,
    inp: SendGifMessageIn,
    req: Request = None,
    user_id: str = Depends(get_messaging_user_id),
):
    """Send a GIF message to a conversation (MSG-008)."""
    if not S.gif_messages_enabled:
        raise HTTPException(403, "GIF messages are not enabled")
    require_participant_active(user_id, conversation_id)
    convo = _get_conversation_or_404(conversation_id)
    _validate_reply_target(conversation_id, inp.reply_to_message_id)
    try:
        resp = tbl_parts.query(IndexName="GSI1", KeyConditionExpression=Key("GSI1PK").eq(conversation_id))
        participants = resp.get("Items", [])
    except Exception:
        participants = []

    ts = now_ts()
    mid = "m_" + new_id()
    item: Dict[str, Any] = {
        "conversation_id": conversation_id,
        "message_id": mid,
        "sender_id": user_id,
        "created_at": ts,
        "kind": "gif",
        "reactions": {},
        "text": None,
        "gif_url": inp.gif_url,
        "gif_alt_text": inp.gif_alt_text or "",
        "gif_width": int(inp.gif_width or 0),
        "gif_height": int(inp.gif_height or 0),
        "gif_provider": S.gif_provider or "mock",
    }
    if inp.reply_to_message_id:
        item[MESSAGE_FIELD_REPLY_TO_ID] = inp.reply_to_message_id

    ttl = _message_retention_ttl(convo, ts)
    if ttl:
        item["ttl"] = ttl

    tbl_msgs.put_item(Item=item)
    _bump_unread_counts(conversation_id, user_id, participants)
    _record_delivery_receipts(conversation_id, mid, user_id, participants)
    tbl_convos.update_item(
        Key={"conversation_id": conversation_id},
        UpdateExpression="SET last_message_at = :ts, last_message_preview = :p, last_message_id = :mid",
        ExpressionAttributeValues={":ts": ts, ":p": "[GIF]", ":mid": mid},
    )
    _fanout_new_message_event(
        conversation_id=conversation_id,
        sender_id=user_id,
        message_item=item,
        payload={
            "message_id": mid,
            "created_at": ts,
            "message": _serialize_message_event_payload(item, user_id),
        },
        respect_mute=False,
    )
    audit_event(
        "messaging_message_sent", user_id, req, outcome="success",
        conversation_id=conversation_id, message_id=mid, kind="gif",
    )
    _emit_message_lifecycle_archive_event_or_503(
        mutation="send", event_ts=ts, conversation_id=conversation_id, message_id=mid,
        actor_user_id=user_id, event_type="message.sent",
        payload={"mutation": "send", "scheduled": False, "message": _serialize_message_event_payload(item, user_id)},
    )
    _meter_message_send(user_id=user_id, conversation_id=conversation_id, message_id=mid)
    return _message_out_from_item(item, user_id)


@router.post("/conversations/{conversation_id}/messages/sticker", response_model=MessageOut, status_code=201)
def send_sticker_message(
    conversation_id: str,
    inp: SendStickerMessageIn,
    req: Request = None,
    user_id: str = Depends(get_messaging_user_id),
):
    """Send a sticker message to a conversation (MSG-008)."""
    if not S.sticker_messages_enabled:
        raise HTTPException(403, "Sticker messages are not enabled")
    require_participant_active(user_id, conversation_id)
    convo = _get_conversation_or_404(conversation_id)
    _validate_reply_target(conversation_id, inp.reply_to_message_id)

    # Resolve the sticker from the collection (must exist + be active).
    from app.services import sticker_collections as _sticker_svc
    collection_meta = _sticker_svc.get_collection_meta(inp.sticker_collection_id, active_only=True)
    if not collection_meta:
        raise HTTPException(404, "collection_not_found")
    sticker = _sticker_svc.get_sticker(inp.sticker_collection_id, inp.sticker_id)
    if not sticker:
        raise HTTPException(404, "sticker_not_found")

    try:
        resp = tbl_parts.query(IndexName="GSI1", KeyConditionExpression=Key("GSI1PK").eq(conversation_id))
        participants = resp.get("Items", [])
    except Exception:
        participants = []

    ts = now_ts()
    mid = "m_" + new_id()
    item: Dict[str, Any] = {
        "conversation_id": conversation_id,
        "message_id": mid,
        "sender_id": user_id,
        "created_at": ts,
        "kind": "sticker",
        "reactions": {},
        "text": None,
        "sticker_id": inp.sticker_id,
        "sticker_collection_id": inp.sticker_collection_id,
        "sticker_url": sticker["image_url"],
        "sticker_alt_text": sticker.get("alt_text") or "",
    }
    if inp.reply_to_message_id:
        item[MESSAGE_FIELD_REPLY_TO_ID] = inp.reply_to_message_id

    ttl = _message_retention_ttl(convo, ts)
    if ttl:
        item["ttl"] = ttl

    tbl_msgs.put_item(Item=item)
    _bump_unread_counts(conversation_id, user_id, participants)
    _record_delivery_receipts(conversation_id, mid, user_id, participants)
    tbl_convos.update_item(
        Key={"conversation_id": conversation_id},
        UpdateExpression="SET last_message_at = :ts, last_message_preview = :p, last_message_id = :mid",
        ExpressionAttributeValues={":ts": ts, ":p": "[Sticker]", ":mid": mid},
    )
    _fanout_new_message_event(
        conversation_id=conversation_id,
        sender_id=user_id,
        message_item=item,
        payload={
            "message_id": mid,
            "created_at": ts,
            "message": _serialize_message_event_payload(item, user_id),
        },
        respect_mute=False,
    )
    audit_event(
        "messaging_message_sent", user_id, req, outcome="success",
        conversation_id=conversation_id, message_id=mid, kind="sticker",
    )
    _emit_message_lifecycle_archive_event_or_503(
        mutation="send", event_ts=ts, conversation_id=conversation_id, message_id=mid,
        actor_user_id=user_id, event_type="message.sent",
        payload={"mutation": "send", "scheduled": False, "message": _serialize_message_event_payload(item, user_id)},
    )
    _meter_message_send(user_id=user_id, conversation_id=conversation_id, message_id=mid)
    return _message_out_from_item(item, user_id)


@router.get("/conversations/{conversation_id}/polls/{poll_id}")
def get_meeting_poll(
    conversation_id: str,
    poll_id: str,
    req: Request = None,
    user_id: str = Depends(get_messaging_user_id),
):
    _enforce_messaging_internal_entitlement(
        user_id=user_id,
        action="upload_attachment",
        request_id=(req.headers.get("x-request-id") if req else None),
    )
    require_participant_active(user_id, conversation_id)
    meta = T.calendar.get_item(Key={"calendar_id": f"MPOLL#{poll_id}", "sk": "meta"}).get("Item")
    if not meta:
        raise HTTPException(404, "Poll not found")
    if meta.get("conversation_id") != conversation_id:
        raise HTTPException(403, "Poll does not belong to this conversation")

    # Load all votes
    votes_resp = T.calendar.query(
        KeyConditionExpression=Key("calendar_id").eq(f"MPOLL#{poll_id}") & Key("sk").begins_with("vote#"),
    )
    vote_items = votes_resp.get("Items", [])

    # Build slot vote counts
    slots_raw = meta.get("slots") or []
    yes_counts: Dict[str, int] = {s["slot_id"]: 0 for s in slots_raw}
    maybe_counts: Dict[str, int] = {s["slot_id"]: 0 for s in slots_raw}
    no_counts: Dict[str, int] = {s["slot_id"]: 0 for s in slots_raw}
    my_votes: Dict[str, str] = {}

    for vote_item in vote_items:
        voter = vote_item["sk"].replace("vote#", "")
        votes_map = vote_item.get("votes") or {}
        for sid, choice in votes_map.items():
            if sid not in yes_counts:
                continue
            if choice == "yes":
                yes_counts[sid] += 1
            elif choice == "maybe":
                maybe_counts[sid] += 1
            elif choice == "no":
                no_counts[sid] += 1
            if voter == user_id:
                my_votes[sid] = choice

    slots_out = []
    for s in slots_raw:
        sid = s["slot_id"]
        slots_out.append({
            "slot_id": sid,
            "start_utc": s["start_utc"],
            "end_utc": s["end_utc"],
            "yes_count": yes_counts.get(sid, 0),
            "maybe_count": maybe_counts.get(sid, 0),
            "no_count": no_counts.get(sid, 0),
            "my_vote": my_votes.get(sid),
        })

    confirmed_slot_id = meta.get("confirmed_slot_id")

    return {
        "poll_id": poll_id,
        "title": meta.get("title"),
        "duration_minutes": int(meta.get("duration_minutes", 30)),
        "creator_id": meta.get("creator_id"),
        "status": meta.get("status", "open"),
        "confirmed_slot_id": confirmed_slot_id,
        "slots": slots_out,
    }


@router.post("/conversations/{conversation_id}/polls/{poll_id}/vote")
def vote_meeting_poll(
    conversation_id: str,
    poll_id: str,
    inp: PollVoteIn,
    user_id: str = Depends(get_messaging_user_id),
):
    require_participant_active(user_id, conversation_id)
    meta = T.calendar.get_item(Key={"calendar_id": f"MPOLL#{poll_id}", "sk": "meta"}).get("Item")
    if not meta:
        raise HTTPException(404, "Poll not found")
    if meta.get("conversation_id") != conversation_id:
        raise HTTPException(403, "Poll does not belong to this conversation")
    if meta.get("status") != "open":
        raise HTTPException(400, "Poll is not open for voting")

    valid_slot_ids = {s["slot_id"] for s in (meta.get("slots") or [])}
    for sid in inp.votes:
        if sid not in valid_slot_ids:
            raise HTTPException(400, f"Unknown slot_id: {sid}")

    T.calendar.put_item(Item={
        "calendar_id": f"MPOLL#{poll_id}",
        "sk": f"vote#{user_id}",
        "type": "poll_vote",
        "voter_id": user_id,
        "votes": inp.votes,
        "voted_at": now_ts(),
    })

    fanout_event_to_conversation(
        conversation_id=conversation_id,
        sender_id=user_id,
        event_type="poll:vote",
        payload={"poll_id": poll_id},
        respect_mute=False,
    )
    return {"ok": True}


@router.post("/conversations/{conversation_id}/polls/{poll_id}/confirm")
def confirm_meeting_poll(
    conversation_id: str,
    poll_id: str,
    inp: PollConfirmIn,
    user_id: str = Depends(get_messaging_user_id),
):
    require_participant_active(user_id, conversation_id)
    meta = T.calendar.get_item(Key={"calendar_id": f"MPOLL#{poll_id}", "sk": "meta"}).get("Item")
    if not meta:
        raise HTTPException(404, "Poll not found")
    if meta.get("conversation_id") != conversation_id:
        raise HTTPException(403, "Poll does not belong to this conversation")
    if meta.get("creator_id") != user_id:
        raise HTTPException(403, "Only the poll creator can confirm a slot")
    if meta.get("status") != "open":
        raise HTTPException(400, "Poll is not open")

    slots_raw = meta.get("slots") or []
    slot = next((s for s in slots_raw if s["slot_id"] == inp.slot_id), None)
    if not slot:
        raise HTTPException(400, "Unknown slot_id")

    event_id: Optional[str] = None
    if inp.calendar_id:
        try:
            cal_item = T.calendar.get_item(Key={"calendar_id": inp.calendar_id, "sk": "meta"}).get("Item")
            if cal_item and cal_item.get("owner_user_sub") == user_id:
                event_id = new_id()
                from datetime import datetime, timezone as _tz
                now_iso = datetime.now(_tz.utc).isoformat().replace("+00:00", "Z")
                T.calendar.put_item(Item={
                    "calendar_id": inp.calendar_id,
                    "sk": f"event#{event_id}",
                    "type": "event",
                    "event_id": event_id,
                    "name": meta.get("title", "Meeting"),
                    "start_utc": slot["start_utc"],
                    "end_utc": slot["end_utc"],
                    "all_day": False,
                    "timezone": cal_item.get("timezone", "UTC"),
                    "description": f"Meeting poll confirmed: {meta.get('title')}",
                    "status": "confirmed",
                    "created_at_utc": now_iso,
                    "owner_user_sub": user_id,
                })
        except Exception:
            event_id = None

    T.calendar.update_item(
        Key={"calendar_id": f"MPOLL#{poll_id}", "sk": "meta"},
        UpdateExpression="SET #s = :s, confirmed_slot_id = :cid",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={":s": "confirmed", ":cid": inp.slot_id},
    )

    fanout_event_to_conversation(
        conversation_id=conversation_id,
        sender_id=user_id,
        event_type="poll:confirmed",
        payload={"poll_id": poll_id, "slot_id": inp.slot_id},
        respect_mute=False,
    )
    return {"ok": True, "event_id": event_id, "calendar_id": inp.calendar_id}


# ---------------------------------------------------------------------------
# Find-a-DateTime (MSG-009)
# ---------------------------------------------------------------------------


def _fadt_pk(poll_id: str) -> str:
    return f"FADT#{poll_id}"


def _fadt_meta_or_404(poll_id: str) -> dict:
    meta = T.calendar.get_item(Key={"calendar_id": _fadt_pk(poll_id), "sk": "META"}).get("Item")
    if not meta:
        raise HTTPException(404, "Find-a-DateTime poll not found")
    return meta


def _fadt_display_name(user_sub: str) -> str:
    try:
        ident = get_profile_identity(user_sub)
        name = (ident.get("display_name") or "").strip()
        if name:
            return name
    except Exception:
        pass
    try:
        u = tbl_users.get_item(Key={"user_id": user_sub}).get("Item", {})
        if u.get("display_name"):
            return str(u["display_name"])
    except Exception:
        pass
    return user_sub


def _fadt_meta_out(meta: dict) -> dict:
    return {
        "poll_id": meta.get("poll_id"),
        "conversation_id": meta.get("conversation_id"),
        "message_id": meta.get("message_id"),
        "creator_sub": meta.get("creator_sub"),
        "title": meta.get("title"),
        "from_date": meta.get("from_date"),
        "to_date": meta.get("to_date"),
        "start_hour": int(meta.get("start_hour", 0)),
        "end_hour": int(meta.get("end_hour", 0)),
        "slot_duration_minutes": int(meta.get("slot_duration_minutes", 30)),
        "deadline_at": int(meta.get("deadline_at", 0)),
        "status": meta.get("status", "open"),
        "created_at": int(meta.get("created_at", 0)),
        "participant_count": int(meta.get("participant_count", 0)),
    }


@router.post("/conversations/{conversation_id}/messages/find-datetime", response_model=MessageOut, status_code=201)
def create_find_datetime_message(
    conversation_id: str,
    inp: CreateFindDateTimeMessageIn,
    req: Request = None,
    user_id: str = Depends(get_messaging_user_id),
):
    """Create a Find-a-DateTime poll message in a conversation (MSG-009)."""
    if not S.find_datetime_enabled:
        raise HTTPException(403, "Find-a-DateTime messages are not enabled")
    require_participant_active(user_id, conversation_id)
    convo = _get_conversation_or_404(conversation_id)

    from app.services.messaging_find_datetime import parse_date

    try:
        d0 = parse_date(inp.from_date)
        d1 = parse_date(inp.to_date)
    except ValueError:
        raise HTTPException(400, "Invalid date format")
    if d0 >= d1:
        raise HTTPException(400, "from_date must be before to_date")
    span_days = (d1 - d0).days + 1
    if span_days > S.find_datetime_max_date_range_days:
        raise HTTPException(400, f"Date range cannot exceed {S.find_datetime_max_date_range_days} days")

    try:
        resp = tbl_parts.query(IndexName="GSI1", KeyConditionExpression=Key("GSI1PK").eq(conversation_id))
        participants = resp.get("Items", [])
    except Exception:
        participants = []

    poll_id = "fadt_" + uuid.uuid4().hex
    ts = now_ts()
    mid = "m_" + new_id()
    deadline_at = ts + inp.deadline_hours * 3600

    T.calendar.put_item(Item={
        "calendar_id": _fadt_pk(poll_id),
        "sk": "META",
        "type": "find_datetime",
        "poll_id": poll_id,
        "conversation_id": conversation_id,
        "message_id": mid,
        "creator_sub": user_id,
        "title": inp.title,
        "from_date": inp.from_date,
        "to_date": inp.to_date,
        "start_hour": inp.start_hour,
        "end_hour": inp.end_hour,
        "slot_duration_minutes": inp.slot_duration_minutes,
        "deadline_at": deadline_at,
        "status": "open",
        "created_at": ts,
        "participant_count": 0,
    })

    find_datetime_data: Dict[str, Any] = {
        "poll_id": poll_id,
        "creator_id": user_id,
        "title": inp.title,
        "from_date": inp.from_date,
        "to_date": inp.to_date,
        "start_hour": inp.start_hour,
        "end_hour": inp.end_hour,
        "slot_duration_minutes": inp.slot_duration_minutes,
        "status": "open",
    }

    item: Dict[str, Any] = {
        "conversation_id": conversation_id,
        "message_id": mid,
        "sender_id": user_id,
        "created_at": ts,
        "kind": "find_datetime",
        "reactions": {},
        "find_datetime": find_datetime_data,
    }
    if inp.text:
        item["text"] = inp.text

    ttl = _message_retention_ttl(convo, ts)
    if ttl:
        item["ttl"] = ttl

    tbl_msgs.put_item(Item=item)

    _bump_unread_counts(conversation_id, user_id, participants)
    _record_delivery_receipts(conversation_id, mid, user_id, participants)
    preview_text = inp.text or f"[Find a Time: {inp.title}]"
    tbl_convos.update_item(
        Key={"conversation_id": conversation_id},
        UpdateExpression="SET last_message_at = :ts, last_message_preview = :p, last_message_id = :mid",
        ExpressionAttributeValues={":ts": ts, ":p": preview_text, ":mid": mid},
    )
    _fanout_new_message_event(
        conversation_id=conversation_id,
        sender_id=user_id,
        message_item=item,
        payload={
            "message_id": mid,
            "created_at": ts,
            "message": _serialize_message_event_payload(item, user_id),
        },
        respect_mute=False,
    )

    audit_event(
        "messaging_message_sent", user_id, req, outcome="success",
        conversation_id=conversation_id, message_id=mid, kind="find_datetime",
    )
    _emit_message_lifecycle_archive_event_or_503(
        mutation="send", event_ts=ts, conversation_id=conversation_id, message_id=mid,
        actor_user_id=user_id, event_type="message.sent",
        payload={"mutation": "send", "scheduled": False, "message": _serialize_message_event_payload(item, user_id)},
    )
    _meter_message_send(user_id=user_id, conversation_id=conversation_id, message_id=mid)
    return _message_out_from_item(item, user_id)


@router.get("/messages/find-datetime/{poll_id}")
def get_find_datetime(
    poll_id: str,
    user_id: str = Depends(get_messaging_user_id),
):
    """Get Find-a-DateTime poll metadata, all availabilities, and result (MSG-009)."""
    meta = _fadt_meta_or_404(poll_id)
    conversation_id = meta.get("conversation_id")
    require_participant_active(user_id, conversation_id)

    items = T.calendar.query(
        KeyConditionExpression=Key("calendar_id").eq(_fadt_pk(poll_id)),
    ).get("Items", [])

    availabilities: List[Dict[str, Any]] = []
    result: Optional[Dict[str, Any]] = None
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
            result = {
                "computed_at": int(it.get("computed_at", 0)),
                "best_windows": [
                    {
                        "start": w.get("start"),
                        "end": w.get("end"),
                        "count": int(w.get("count", 0)),
                        "participants": [str(p) for p in (w.get("participants") or [])],
                    }
                    for w in (it.get("best_windows") or [])
                ],
            }
    availabilities.sort(key=lambda a: a["submitted_at"])

    return {
        "meta": _fadt_meta_out(meta),
        "availabilities": availabilities,
        "result": result,
    }


@router.post("/messages/find-datetime/{poll_id}/availability")
def submit_find_datetime_availability(
    poll_id: str,
    inp: SubmitAvailabilityIn,
    user_id: str = Depends(get_messaging_user_id),
):
    """Submit or update availability for a Find-a-DateTime poll (MSG-009)."""
    meta = _fadt_meta_or_404(poll_id)
    conversation_id = meta.get("conversation_id")
    require_participant_active(user_id, conversation_id)

    if meta.get("status") != "open":
        raise HTTPException(400, "Poll is closed")
    ts = now_ts()
    if ts > int(meta.get("deadline_at", 0)):
        raise HTTPException(400, "Submission deadline has passed")

    from app.services.messaging_find_datetime import enumerate_slots

    valid_slots = set(enumerate_slots(
        from_date=meta["from_date"],
        to_date=meta["to_date"],
        start_hour=int(meta["start_hour"]),
        end_hour=int(meta["end_hour"]),
        slot_duration_minutes=int(meta["slot_duration_minutes"]),
    ))
    # Deduplicate while preserving determinism.
    submitted = []
    seen = set()
    for s in inp.slots:
        if s in seen:
            continue
        seen.add(s)
        if s not in valid_slots:
            raise HTTPException(400, "Slot is outside the allowed range")
        submitted.append(s)
    submitted.sort()

    existing = T.calendar.get_item(
        Key={"calendar_id": _fadt_pk(poll_id), "sk": f"AVAIL#{user_id}"}
    ).get("Item")
    is_update = existing is not None

    user_name = _fadt_display_name(user_id)
    T.calendar.put_item(Item={
        "calendar_id": _fadt_pk(poll_id),
        "sk": f"AVAIL#{user_id}",
        "type": "fadt_availability",
        "user_sub": user_id,
        "user_name": user_name,
        "slots": submitted,
        "submitted_at": ts,
    })

    participant_count = int(meta.get("participant_count", 0))
    if not is_update:
        try:
            upd = T.calendar.update_item(
                Key={"calendar_id": _fadt_pk(poll_id), "sk": "META"},
                UpdateExpression="ADD participant_count :one",
                ExpressionAttributeValues={":one": 1},
                ReturnValues="UPDATED_NEW",
            )
            participant_count = int(upd.get("Attributes", {}).get("participant_count", participant_count + 1))
        except Exception:
            participant_count += 1

    fanout_event_to_conversation(
        conversation_id=conversation_id,
        sender_id=user_id,
        event_type="fadt:availability",
        payload={"poll_id": poll_id, "user_sub": user_id, "participant_count": participant_count},
        respect_mute=False,
    )
    return {
        "ok": True,
        "poll_id": poll_id,
        "user_sub": user_id,
        "slots_count": len(submitted),
        "participant_count": participant_count,
        "submitted_at": ts,
    }


@router.post("/messages/find-datetime/{poll_id}/close")
def close_find_datetime(
    poll_id: str,
    user_id: str = Depends(get_messaging_user_id),
):
    """Close a Find-a-DateTime poll and compute best windows (creator only, MSG-009)."""
    meta = _fadt_meta_or_404(poll_id)
    conversation_id = meta.get("conversation_id")
    require_participant_active(user_id, conversation_id)

    if meta.get("creator_sub") != user_id:
        raise HTTPException(403, "Only the creator can close this poll")
    if meta.get("status") == "closed":
        raise HTTPException(400, "Poll is already closed")

    from app.services.messaging_find_datetime import compute_best_windows

    avail_items = T.calendar.query(
        KeyConditionExpression=Key("calendar_id").eq(_fadt_pk(poll_id)) & Key("sk").begins_with("AVAIL#"),
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
        availabilities,
        int(meta.get("slot_duration_minutes", 30)),
    )

    ts = now_ts()
    T.calendar.put_item(Item={
        "calendar_id": _fadt_pk(poll_id),
        "sk": "RESULT",
        "type": "fadt_result",
        "computed_at": ts,
        "best_windows": best_windows,
    })
    T.calendar.update_item(
        Key={"calendar_id": _fadt_pk(poll_id), "sk": "META"},
        UpdateExpression="SET #s = :s",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={":s": "closed"},
    )

    fanout_event_to_conversation(
        conversation_id=conversation_id,
        sender_id=user_id,
        event_type="fadt:result",
        payload={"poll_id": poll_id, "best_windows": best_windows},
        respect_mute=False,
    )
    return {
        "ok": True,
        "poll_id": poll_id,
        "status": "closed",
        "result": {"computed_at": ts, "best_windows": best_windows},
    }


@router.post("/conversations/{conversation_id}/messages/file", response_model=MessageOut)
def create_file_message(
    conversation_id: str,
    inp: CreateFileMessageIn,
    req: Request = None,
    user_id: str = Depends(get_messaging_user_id),
):
    require_participant_active(user_id, conversation_id)
    convo = _get_conversation_or_404(conversation_id)
    _enforce_helpdesk_send_constraints(conversation_id=conversation_id, convo=convo, user_id=user_id, req=req)
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
            "signature_packet_id": inp.signature_packet_id,
        },
        "reactions": {},
    }
    if preview:
        item["preview"] = preview
    ttl = _message_retention_ttl(convo, ts)
    if ttl:
        item["ttl"] = ttl
    item.update(
        _build_reply_linkage_fields(
            conversation_id=conversation_id,
            reply_to_message_id=inp.reply_to_message_id,
            actor_user_id=user_id,
            created_at=ts,
        )
    )
    if inp.consumption_policy != CONSUMPTION_POLICY_NONE:
        item["consumption_policy"] = inp.consumption_policy
        item["media_kind"] = inp.kind if inp.kind in {"audio", "video"} else None

    tbl_msgs.put_item(Item=item)
    _sync_gallery_index_message(item)
    _bump_unread_counts(conversation_id, user_id, resp.get("Items", []))
    _record_delivery_receipts(conversation_id, mid, user_id, resp.get("Items", []))
    _put_message_consumption_records(
        conversation_id=conversation_id,
        message_id=mid,
        sender_id=user_id,
        participants=resp.get("Items", []),
        consumption_policy=inp.consumption_policy,
        media_kind=item.get("media_kind"),
        created_at=ts,
    )
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
        reply_to_message_id=item.get(MESSAGE_FIELD_REPLY_TO_ID),
        parent_message_id=item.get(MESSAGE_FIELD_PARENT_ID),
        thread_id=item.get(MESSAGE_FIELD_THREAD_ID),
        thread_root_message_id=item.get(MESSAGE_FIELD_THREAD_ROOT_ID),
        consumption_policy=inp.consumption_policy if inp.consumption_policy != CONSUMPTION_POLICY_NONE else None,
        media_kind=item.get("media_kind") if inp.consumption_policy != CONSUMPTION_POLICY_NONE else None,
        consumption_state=CONSUMPTION_STATE_PENDING if inp.consumption_policy != CONSUMPTION_POLICY_NONE else None,
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
        reply_to_message_id=item.get(MESSAGE_FIELD_REPLY_TO_ID),
        parent_message_id=item.get(MESSAGE_FIELD_PARENT_ID),
    )
    _emit_message_lifecycle_archive_event_or_503(
        mutation="send",
        event_ts=ts,
        conversation_id=conversation_id,
        message_id=mid,
        actor_user_id=user_id,
        event_type="message.sent",
        payload={"mutation": "send", "scheduled": False, "message": _serialize_message_event_payload(item, user_id)},
    )
    _meter_message_send(user_id=user_id, conversation_id=conversation_id, message_id=mid)
    if inp.consumption_policy != CONSUMPTION_POLICY_NONE and item.get("media_kind"):
        record_once_media_send(
            media_kind=str(item.get("media_kind") or "unknown"),
            consumption_policy=inp.consumption_policy,
            cohort=_extract_once_media_cohort(req),
        )
    return message


@router.post("/conversations/{conversation_id}/messages/{message_id}/attachment/grant", response_model=AttachmentGrantOut)
def create_once_media_attachment_grant(
    conversation_id: str,
    message_id: str,
    request: Request,
    user_id: str = Depends(get_messaging_user_id),
):
    started = time.perf_counter()
    cohort = _extract_once_media_cohort(request)
    media_kind = "unknown"
    require_participant_active(user_id, conversation_id)
    try:
        msg = _get_message_or_404(conversation_id, message_id)
        media_kind = str(msg.get("media_kind") or "unknown")
        _ = _get_once_media_state_or_error(
            conversation_id=conversation_id,
            message_id=message_id,
            recipient_id=user_id,
            message_item=msg,
        )

        expires_at = now_ts() + max(1, ONCE_MEDIA_GRANT_TTL_SEC)
        grant_token = _encode_once_media_grant(
            conversation_id=conversation_id,
            message_id=message_id,
            recipient_id=user_id,
            expires_at=expires_at,
        )

        audit_event(
            "messaging_attachment_grant_issued",
            user_id,
            request,
            outcome="success",
            conversation_id=conversation_id,
            message_id=message_id,
            expires_at=expires_at,
        )
        record_once_media_grant(media_kind=media_kind, outcome="success", cohort=cohort)
        record_once_media_grant_latency(
            media_kind=media_kind,
            outcome="success",
            elapsed_seconds=time.perf_counter() - started,
            cohort=cohort,
        )
        return AttachmentGrantOut(
            grant_token=grant_token,
            expires_at=expires_at,
            conversation_id=conversation_id,
            message_id=message_id,
        )
    except HTTPException as exc:
        reason = str((exc.detail or {}).get("code") or "http_error") if isinstance(exc.detail, dict) else "http_error"
        record_once_media_grant(media_kind=media_kind, outcome="error", reason=reason, cohort=cohort)
        record_once_media_grant_latency(
            media_kind=media_kind,
            outcome="error",
            elapsed_seconds=time.perf_counter() - started,
            cohort=cohort,
        )
        raise


@router.post("/conversations/{conversation_id}/messages/{message_id}/attachment/consume", response_model=ConsumeAttachmentOut)
def consume_once_media_attachment(
    conversation_id: str,
    message_id: str,
    inp: ConsumeAttachmentIn,
    request: Request,
    grant_token: str = Query(..., min_length=16),
    user_id: str = Depends(get_messaging_user_id),
):
    cohort = _extract_once_media_cohort(request)
    media_kind = "unknown"
    require_participant_active(user_id, conversation_id)
    try:
        msg = _get_message_or_404(conversation_id, message_id)
        media_kind = str(msg.get("media_kind") or "unknown")
        _ = _get_once_media_state_or_error(
            conversation_id=conversation_id,
            message_id=message_id,
            recipient_id=user_id,
            message_item=msg,
        )
        _validate_once_media_grant(
            token=grant_token,
            conversation_id=conversation_id,
            message_id=message_id,
            recipient_id=user_id,
        )
        _validate_consume_trigger_or_error(
            message_item=msg,
            trigger=inp.trigger,
            playback_seconds=inp.playback_seconds,
        )

        result = _consume_once_media_state_atomic(
            conversation_id=conversation_id,
            message_id=message_id,
            recipient_id=user_id,
            consumption_attempt_id=inp.consumption_attempt_id,
            consumed_at=now_ts(),
        )

        audit_event(
            "messaging_attachment_consumed",
            user_id,
            request,
            outcome="success",
            conversation_id=conversation_id,
            message_id=message_id,
            consumption_attempt_id=inp.consumption_attempt_id,
            consumed_at=result["consumed_at"],
            idempotent_replay=result.get("idempotent_replay", False),
        )
        consume_reason = "idempotent_replay" if result.get("idempotent_replay") else "none"
        record_once_media_consume(media_kind=media_kind, outcome="success", reason=consume_reason, cohort=cohort)
        return ConsumeAttachmentOut(
            ok=True,
            conversation_id=conversation_id,
            message_id=message_id,
            consumption_state="consumed",
            consumed_at=int(result["consumed_at"]),
            consumption_attempt_id=inp.consumption_attempt_id,
        )
    except HTTPException as exc:
        reason = str((exc.detail or {}).get("code") or "http_error") if isinstance(exc.detail, dict) else "http_error"
        record_once_media_consume(media_kind=media_kind, outcome="error", reason=reason, cohort=cohort)
        if reason == "already_consumed":
            record_once_media_conflict(media_kind=media_kind, cohort=cohort)
        raise


@router.get("/conversations/{conversation_id}/messages/{message_id}/attachment")
def download_message_attachment(
    conversation_id: str,
    message_id: str,
    request: Request,
    grant_token: Optional[str] = Query(default=None),
    x_request_id: Optional[str] = Header(default=None, alias="X-Request-Id"),
    user_id: str = Depends(get_messaging_user_id),
):
    _enforce_messaging_internal_entitlement(
        user_id=user_id,
        action="download_attachment",
        request_id=x_request_id,
    )
    require_participant_active(user_id, conversation_id)
    msg = _get_message_or_404(conversation_id, message_id)
    kind = str(msg.get("kind") or "")

    if _is_once_consumption_policy(msg.get("consumption_policy")):
        _ = _get_once_media_state_or_error(
            conversation_id=conversation_id,
            message_id=message_id,
            recipient_id=user_id,
            message_item=msg,
        )
        _validate_once_media_grant(
            token=grant_token or "",
            conversation_id=conversation_id,
            message_id=message_id,
            recipient_id=user_id,
        )

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

    once_media = _is_once_consumption_policy(msg.get("consumption_policy"))
    headers = {
        "Content-Disposition": f'inline; filename="{filename}"',
        "Cache-Control": "no-store, no-cache, max-age=0, must-revalidate" if once_media else "private, max-age=60",
    }
    if once_media:
        headers["Pragma"] = "no-cache"
        headers["Expires"] = "0"
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
    msg = _get_message_or_404(conversation_id, message_id)
    _sync_gallery_index_message(msg)
    ts = now_ts()
    audit_event(
        "messaging_message_deleted",
        user_id,
        req,
        outcome="success",
        conversation_id=conversation_id,
        message_id=message_id,
    )
    _emit_message_lifecycle_archive_event_or_503(
        mutation="delete",
        event_ts=ts,
        conversation_id=conversation_id,
        message_id=message_id,
        actor_user_id=user_id,
        event_type="message.deleted",
        payload={"mutation": "delete", "scope": "for_me", "deleted_for_user_id": user_id},
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

    revoked_item = dict(msg)
    revoked_item["revoked_at"] = ts
    revoked_item["revoked_by"] = user_id
    _sync_gallery_index_message(revoked_item)

    # If this was the last message, update conversation preview to show it was deleted
    convo = tbl_convos.get_item(Key={"conversation_id": conversation_id}).get("Item") or {}
    if convo.get("last_message_at") == msg.get("created_at"):
        tbl_convos.update_item(
            Key={"conversation_id": conversation_id},
            UpdateExpression="SET last_message_preview = :p",
            ExpressionAttributeValues={":p": "[Message deleted]"},
        )

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
    _emit_message_lifecycle_archive_event_or_503(
        mutation="revoke",
        event_ts=ts,
        conversation_id=conversation_id,
        message_id=message_id,
        actor_user_id=user_id,
        event_type="message.revoked",
        payload={"mutation": "revoke", "message": _serialize_message_event_payload(item, user_id)},
    )
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

    # MSG-011: enforce a per-message unique-emoji reaction cap. Adding a brand
    # new emoji key once the cap is reached is rejected; reacting with an emoji
    # that already exists on the message (a new user joining an existing
    # reaction) is always allowed.
    if inp.action == "add":
        existing_reactions = msg.get("reactions") or {}
        if (
            inp.emoji not in existing_reactions
            and len(existing_reactions) >= MAX_UNIQUE_REACTIONS_PER_MESSAGE
        ):
            raise HTTPException(
                status_code=400,
                detail=f"Maximum {MAX_UNIQUE_REACTIONS_PER_MESSAGE} unique reactions per message",
            )

    expr_names = {"#e": inp.emoji}

    try:
        if inp.action == "add":
            tbl_msgs.update_item(
                Key={"conversation_id": conversation_id, "message_id": message_id},
                UpdateExpression="ADD reactions.#e :u",
                ExpressionAttributeNames=expr_names,
                ExpressionAttributeValues={":u": {user_id}},
                ConditionExpression="attribute_exists(message_id)",
            )
        else:
            try:
                tbl_msgs.update_item(
                    Key={"conversation_id": conversation_id, "message_id": message_id},
                    UpdateExpression="DELETE reactions.#e :u",
                    ExpressionAttributeNames=expr_names,
                    ExpressionAttributeValues={":u": {user_id}},
                    ConditionExpression="attribute_exists(message_id) AND attribute_exists(reactions.#e)",
                )
            except ClientError as ce:
                if ce.response["Error"]["Code"] != "ConditionalCheckFailedException":
                    raise
    except ClientError as e:
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


# MSG-011: Reaction detail — who reacted with what (avatars + display names).
@router.get(
    "/conversations/{conversation_id}/messages/{message_id}/reactions/details",
    response_model=ReactionDetailsOut,
)
def get_reaction_details(
    conversation_id: str,
    message_id: str,
    user_id: str = Depends(get_messaging_user_id),
):
    require_participant_active(user_id, conversation_id)
    msg = _get_message_or_404(conversation_id, message_id)
    reactions = msg.get("reactions") or {}

    # Collect the distinct reactor user-subs across all emoji keys, then resolve
    # each to a display name + avatar once (a user may react with many emojis).
    all_subs: set[str] = set()
    for userset in reactions.values():
        try:
            all_subs.update(set(userset))
        except TypeError:
            continue

    profile_cache: Dict[str, dict] = {}
    for sub in all_subs:
        try:
            profile_cache[sub] = get_profile_identity(sub) or {}
        except Exception:
            profile_cache[sub] = {}

    details: Dict[str, List[ReactionUserOut]] = {}
    for emoji, userset in reactions.items():
        try:
            subs = list(set(userset))
        except TypeError:
            continue
        users: List[ReactionUserOut] = []
        for sub in subs:
            ident = profile_cache.get(sub) or {}
            name = (ident.get("display_name") or "").strip() or sub[:8]
            users.append(
                ReactionUserOut(
                    user_sub=sub,
                    display_name=name,
                    profile_photo_url=ident.get("profile_photo_url"),
                )
            )
        details[emoji] = users

    return ReactionDetailsOut(reactions=details)


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
            "edited_at": str(ts),
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
    _sync_gallery_index_message(item)

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
    _emit_message_lifecycle_archive_event_or_503(
        mutation="edit",
        event_ts=ts,
        conversation_id=conversation_id,
        message_id=message_id,
        actor_user_id=user_id,
        event_type="message.edited",
        payload={"mutation": "edit", "previous_text": old_text, "message": _serialize_message_event_payload(item, user_id)},
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
    _enforce_helpdesk_send_constraints(conversation_id=target_conversation_id, convo=convo, user_id=user_id, req=req)

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
        "reactions": {},
        "forwarded_from": forwarded_from,
    }
    ttl = _message_retention_ttl(convo, ts)
    if ttl:
        item["ttl"] = ttl

    if inp.note:
        item["forward_note"] = inp.note
    item.update(
        _build_reply_linkage_fields(
            conversation_id=target_conversation_id,
            reply_to_message_id=inp.reply_to_message_id,
            actor_user_id=user_id,
            created_at=ts,
        )
    )

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
    _sync_gallery_index_message(item)
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
        reply_to_message_id=item.get(MESSAGE_FIELD_REPLY_TO_ID),
        parent_message_id=item.get(MESSAGE_FIELD_PARENT_ID),
    )
    _emit_message_lifecycle_archive_event_or_503(
        mutation="send",
        event_ts=ts,
        conversation_id=target_conversation_id,
        message_id=mid,
        actor_user_id=user_id,
        event_type="message.sent",
        payload={"mutation": "send", "scheduled": False, "message": _serialize_message_event_payload(item, user_id)},
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
            "SET message_id = :mid, user_id = :uid, last_viewed_at = :ts, #ttl = :ttl "
            "ADD view_count :one"
        ),
        ExpressionAttributeNames={"#ttl": "ttl"},
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

    # View-once: mark this user as having consumed their view
    if msg.get("view_once") and user_id != msg.get("sender_id"):
        tbl_msgs.update_item(
            Key={"conversation_id": conversation_id, "message_id": message_id},
            UpdateExpression="ADD view_once_seen :uid",
            ExpressionAttributeValues={":uid": {user_id}},
        )
        fanout_event_to_conversation(
            conversation_id=conversation_id,
            sender_id=user_id,
            event_type="message:view_once_consumed",
            payload={"message_id": message_id, "viewer_id": user_id},
            respect_mute=False,
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



@router.post(
    "/conversations/{conversation_id}/messages/{message_id}/hide",
    response_model=MessageControlActionOut,
    responses=MESSAGE_CONTROLS_ERROR_RESPONSES,
)
def hide_message_for_me(
    conversation_id: str,
    message_id: str,
    user_id: str = Depends(get_messaging_user_id),
):
    """Hide a message for the current participant (idempotent upsert)."""
    _require_message_controls_capability(_messaging_hide_controls_enabled(), "Message hide controls are disabled")
    require_participant_active(user_id, conversation_id)
    _ = _get_message_or_404(conversation_id, message_id)
    ts = now_ts()
    message_user = f"{message_id}#{user_id}"
    conversation_user = f"{conversation_id}#{user_id}"

    # Idempotent upsert keyed by (conversation_id, message_user).
    T.message_visibility_overrides.update_item(
        Key={"conversation_id": conversation_id, "message_user": message_user},
        UpdateExpression=(
            "SET message_id = :mid, user_id = :uid, #state = :state, "
            "updated_at = :updated_at, conversation_user = :conversation_user"
        ),
        ExpressionAttributeNames={"#state": "state"},
        ExpressionAttributeValues={
            ":mid": message_id,
            ":uid": user_id,
            ":state": "hidden",
            ":updated_at": ts,
            ":conversation_user": conversation_user,
        },
    )

    record_messaging_message_control_action(action="hide", result="success")
    _log_message_control_action(actor_user_id=user_id, conversation_id=conversation_id, message_id=message_id, action="hide", result="success")
    _emit_archive_event_or_503(
        event_id=f"mc_hide_{conversation_id}_{message_id}_{ts}_{user_id}",
        event_ts=ts,
        conversation_id=conversation_id,
        message_id=message_id,
        actor_user_id=user_id,
        event_type="message.deleted",
        payload={"action": "hide", "state": "hidden"},
    )
    return MessageControlActionOut(
        ok=True,
        conversation_id=conversation_id,
        message_id=message_id,
        action="hidden",
        updated_at=ts,
    )


@router.delete(
    "/conversations/{conversation_id}/messages/{message_id}/hide",
    response_model=MessageControlActionOut,
    responses=MESSAGE_CONTROLS_ERROR_RESPONSES,
)
def unhide_message_for_me(
    conversation_id: str,
    message_id: str,
    user_id: str = Depends(get_messaging_user_id),
):
    """Unhide a message for the current participant (idempotent upsert)."""
    _require_message_controls_capability(_messaging_hide_controls_enabled(), "Message hide controls are disabled")
    require_participant_active(user_id, conversation_id)
    _ = _get_message_or_404(conversation_id, message_id)
    ts = now_ts()
    message_user = f"{message_id}#{user_id}"
    conversation_user = f"{conversation_id}#{user_id}"

    # Idempotent upsert keyed by (conversation_id, message_user).
    T.message_visibility_overrides.update_item(
        Key={"conversation_id": conversation_id, "message_user": message_user},
        UpdateExpression=(
            "SET message_id = :mid, user_id = :uid, #state = :state, "
            "updated_at = :updated_at, conversation_user = :conversation_user"
        ),
        ExpressionAttributeNames={"#state": "state"},
        ExpressionAttributeValues={
            ":mid": message_id,
            ":uid": user_id,
            ":state": "visible",
            ":updated_at": ts,
            ":conversation_user": conversation_user,
        },
    )

    record_messaging_message_control_action(action="unhide", result="success")
    _log_message_control_action(actor_user_id=user_id, conversation_id=conversation_id, message_id=message_id, action="unhide", result="success")
    _emit_archive_event_or_503(
        event_id=f"mc_unhide_{conversation_id}_{message_id}_{ts}_{user_id}",
        event_ts=ts,
        conversation_id=conversation_id,
        message_id=message_id,
        actor_user_id=user_id,
        event_type="message.edited",
        payload={"action": "unhide", "state": "visible"},
    )
    return MessageControlActionOut(
        ok=True,
        conversation_id=conversation_id,
        message_id=message_id,
        action="visible",
        updated_at=ts,
    )


@router.get(
    "/conversations/{conversation_id}/hidden-messages",
    response_model=HiddenMessagesPageOut,
    responses=MESSAGE_CONTROLS_ERROR_RESPONSES,
)
def list_hidden_messages(
    conversation_id: str,
    cursor: Optional[str] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    user_id: str = Depends(get_messaging_user_id),
):
    """List hidden messages for the current participant with stable pagination."""
    _require_message_controls_capability(_messaging_hide_controls_enabled(), "Message hide controls are disabled")
    require_participant_active(user_id, conversation_id)

    eks = decode_cursor(cursor)
    if cursor and not eks:
        raise HTTPException(status_code=400, detail="invalid cursor")

    out: list[MessageOut] = []
    last_evaluated_key = eks

    while len(out) < limit:
        remaining = max(1, limit - len(out))
        resp = T.message_visibility_overrides.query(
            IndexName="ByConversationUserUpdatedAt",
            KeyConditionExpression=Key("conversation_user").eq(f"{conversation_id}#{user_id}"),
            FilterExpression=Attr("state").eq("hidden"),
            ScanIndexForward=True,
            Limit=remaining,
            **({"ExclusiveStartKey": last_evaluated_key} if last_evaluated_key else {}),
        )

        items = resp.get("Items", [])
        for override in items:
            if str(override.get("state") or "") != "hidden":
                continue
            mid = str(override.get("message_id") or "").strip()
            if not mid:
                continue
            msg = tbl_msgs.get_item(Key={"conversation_id": conversation_id, "message_id": mid}).get("Item")
            if not msg:
                continue
            out.append(_message_out_from_item(msg, user_id))
            if len(out) >= limit:
                break

        last_evaluated_key = resp.get("LastEvaluatedKey")
        if not last_evaluated_key:
            break

    return HiddenMessagesPageOut(
        items=out,
        next_cursor=encode_cursor(last_evaluated_key),
    )


@router.post(
    "/conversations/{conversation_id}/messages/{message_id}/pin",
    response_model=MessageControlActionOut,
    responses=MESSAGE_CONTROLS_ERROR_RESPONSES,
)
def pin_message(
    conversation_id: str,
    message_id: str,
    req: Request = None,
    user_id: str = Depends(get_messaging_user_id),
):
    """Pin a message in a conversation (participant-scoped authorization)."""
    _require_message_controls_capability(_messaging_pins_enabled(), "Message pin controls are disabled")
    require_participant_active(user_id, conversation_id)
    _ = _get_message_or_404(conversation_id, message_id)

    ts = now_ts()
    conversation_active = f"{conversation_id}#1"
    latest_pin_sort = f"{ts:013d}#{message_id}"

    T.conversation_pins.update_item(
        Key={"conversation_id": conversation_id, "message_id": message_id},
        UpdateExpression=(
            "SET pinned_by_user_id = :pinned_by_user_id, pinned_at = :pinned_at, "
            "is_active = :is_active, conversation_active = :conversation_active, "
            "latest_pin_sort = :latest_pin_sort REMOVE unpinned_by_user_id, unpinned_at"
        ),
        ExpressionAttributeValues={
            ":pinned_by_user_id": user_id,
            ":pinned_at": ts,
            ":is_active": True,
            ":conversation_active": conversation_active,
            ":latest_pin_sort": latest_pin_sort,
        },
    )

    fanout_event_to_conversation(
        conversation_id=conversation_id,
        sender_id=user_id,
        event_type="message:pinned",
        payload={
            "conversation_id": conversation_id,
            "message_id": message_id,
            "pinned_by_user_id": user_id,
            "pinned_at": ts,
        },
        respect_mute=False,
    )
    audit_event(
        "messaging_message_pinned",
        user_id,
        req,
        outcome="success",
        conversation_id=conversation_id,
        message_id=message_id,
        pinned_by_user_id=user_id,
        pinned_at=ts,
    )

    record_messaging_message_control_action(action="pin", result="success")
    _log_message_control_action(actor_user_id=user_id, conversation_id=conversation_id, message_id=message_id, action="pin", result="success")
    _emit_archive_event_or_503(
        event_id=f"mc_pin_{conversation_id}_{message_id}_{ts}_{user_id}",
        event_ts=ts,
        conversation_id=conversation_id,
        message_id=message_id,
        actor_user_id=user_id,
        event_type="message.edited",
        payload={"action": "pin", "is_active": True},
    )
    return MessageControlActionOut(
        ok=True,
        conversation_id=conversation_id,
        message_id=message_id,
        action="pinned",
        updated_at=ts,
    )


@router.delete(
    "/conversations/{conversation_id}/messages/{message_id}/pin",
    response_model=MessageControlActionOut,
    responses=MESSAGE_CONTROLS_ERROR_RESPONSES,
)
def unpin_message(
    conversation_id: str,
    message_id: str,
    req: Request = None,
    user_id: str = Depends(get_messaging_user_id),
):
    """Unpin a message in a conversation (participant-scoped authorization)."""
    _require_message_controls_capability(_messaging_pins_enabled(), "Message pin controls are disabled")
    require_participant_active(user_id, conversation_id)
    _ = _get_message_or_404(conversation_id, message_id)

    ts = now_ts()

    T.conversation_pins.update_item(
        Key={"conversation_id": conversation_id, "message_id": message_id},
        UpdateExpression=(
            "SET is_active = :is_active, unpinned_by_user_id = :unpinned_by_user_id, "
            "unpinned_at = :unpinned_at, conversation_active = :conversation_inactive, "
            "latest_pin_sort = :latest_pin_sort"
        ),
        ExpressionAttributeValues={
            ":is_active": False,
            ":unpinned_by_user_id": user_id,
            ":unpinned_at": ts,
            ":conversation_inactive": f"{conversation_id}#0",
            ":latest_pin_sort": f"{ts:013d}#{message_id}",
        },
    )

    fanout_event_to_conversation(
        conversation_id=conversation_id,
        sender_id=user_id,
        event_type="message:unpinned",
        payload={
            "conversation_id": conversation_id,
            "message_id": message_id,
            "unpinned_by_user_id": user_id,
            "unpinned_at": ts,
        },
        respect_mute=False,
    )
    audit_event(
        "messaging_message_unpinned",
        user_id,
        req,
        outcome="success",
        conversation_id=conversation_id,
        message_id=message_id,
        unpinned_by_user_id=user_id,
        unpinned_at=ts,
    )

    record_messaging_message_control_action(action="unpin", result="success")
    _log_message_control_action(actor_user_id=user_id, conversation_id=conversation_id, message_id=message_id, action="unpin", result="success")
    _emit_archive_event_or_503(
        event_id=f"mc_unpin_{conversation_id}_{message_id}_{ts}_{user_id}",
        event_ts=ts,
        conversation_id=conversation_id,
        message_id=message_id,
        actor_user_id=user_id,
        event_type="message.edited",
        payload={"action": "unpin", "is_active": False},
    )
    return MessageControlActionOut(
        ok=True,
        conversation_id=conversation_id,
        message_id=message_id,
        action="unpinned",
        updated_at=ts,
    )


@router.get(
    "/conversations/{conversation_id}/pins",
    response_model=ConversationPinsPageOut,
    responses=MESSAGE_CONTROLS_ERROR_RESPONSES,
)
def list_conversation_pins(
    conversation_id: str,
    cursor: Optional[str] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    user_id: str = Depends(get_messaging_user_id),
):
    """List active pins in a conversation ordered by newest pin first."""
    require_participant_active(user_id, conversation_id)

    eks = decode_cursor(cursor)
    if cursor and not eks:
        raise HTTPException(status_code=400, detail="invalid cursor")

    resp = T.conversation_pins.query(
        IndexName="ByConversationActivePinnedAt",
        KeyConditionExpression=Key("conversation_active").eq(f"{conversation_id}#1"),
        ScanIndexForward=False,
        Limit=limit,
        **({"ExclusiveStartKey": eks} if eks else {}),
    )

    items = []
    for pin in resp.get("Items", []):
        items.append(
            ConversationPinOut(
                conversation_id=conversation_id,
                message_id=str(pin.get("message_id") or ""),
                pinned_by_user_id=str(pin.get("pinned_by_user_id") or ""),
                pinned_at=int(pin.get("pinned_at", 0) or 0),
                is_active=bool(pin.get("is_active", False)),
            )
        )

    return ConversationPinsPageOut(items=items, next_cursor=encode_cursor(resp.get("LastEvaluatedKey")))




def _is_record_under_active_legal_hold(*, tenant_id: str, conversation_id: str, message_id: str) -> bool:
    conversation_status = f"{conversation_id}#active"
    last_key = None
    while True:
        kwargs: Dict[str, Any] = {
            "IndexName": "ByConversationStatusCreatedAt",
            "KeyConditionExpression": Key("conversation_status").eq(conversation_status),
            "ScanIndexForward": False,
            "Limit": 100,
        }
        if last_key:
            kwargs["ExclusiveStartKey"] = last_key
        resp = T.message_legal_holds.query(**kwargs)
        for item in resp.get("Items", []):
            if str(item.get("tenant_id") or "") != tenant_id:
                continue
            hold_message_id = str(item.get("message_id") or "")
            if hold_message_id and hold_message_id == message_id:
                return True
            # conversation-scoped legal hold (no message_id) blocks all records in conversation
            if not hold_message_id:
                return True
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break
    return False

@router.post(
    "/conversations/{conversation_id}/messages/{message_id}/report",
    response_model=ReportMessageOut,
    responses=MESSAGE_CONTROLS_ERROR_RESPONSES,
)
def report_message(
    conversation_id: str,
    message_id: str,
    inp: ReportMessageIn,
    user_id: str = Depends(get_messaging_user_id),
):
    """Submit a moderation report for a message in a conversation the user participates in."""
    _require_message_controls_capability(_messaging_reporting_enabled(), "Message reporting is disabled")
    require_participant_active(user_id, conversation_id)
    _ = _get_message_or_404(conversation_id, message_id)

    ts = now_ts()
    _enforce_report_rate_limits(conversation_id, user_id, ts)

    report_id = f"rpt_{new_id()}"
    context_message_ids = _load_report_context_message_ids(conversation_id, message_id, user_id)

    T.message_reports.put_item(
        Item={
            "report_id": report_id,
            "conversation_id": conversation_id,
            "message_id": message_id,
            "reported_by_user_id": user_id,
            "reason_code": inp.reason_code,
            "statement": inp.statement,
            "context_message_ids": context_message_ids,
            "created_at": ts,
            "status": "submitted",
        }
    )

    for context_message_id in context_message_ids:
        T.message_report_context.put_item(
            Item={
                "report_id": report_id,
                "message_id": context_message_id,
                "conversation_id": conversation_id,
                "created_at": ts,
            }
        )

    record_messaging_message_control_action(action="report", result="success")
    _log_message_control_action(actor_user_id=user_id, conversation_id=conversation_id, message_id=message_id, action="report", result="success", detail=f"reason={inp.reason_code}")
    _emit_report_archive_event_or_503(
        event_ts=ts,
        conversation_id=conversation_id,
        message_id=message_id,
        actor_user_id=user_id,
        report_id=report_id,
        event_type="report.submitted",
        payload={
            "action": "report",
            "reason_code": inp.reason_code,
            "status": "submitted",
            "timeline_state": {"created_at": ts, "reported_by_user_id": user_id},
        },
    )
    return ReportMessageOut(
        ok=True,
        report_id=report_id,
        conversation_id=conversation_id,
        message_id=message_id,
        reason_code=inp.reason_code,
        status="submitted",
        created_at=ts,
    )


@router.patch(
    "/conversations/{conversation_id}/reports/{report_id}/status",
    response_model=ReportStatusUpdateOut,
    responses=MESSAGE_CONTROLS_ERROR_RESPONSES,
)
def update_report_status(
    conversation_id: str,
    report_id: str,
    inp: ReportStatusUpdateIn,
    req: Request = None,
    user_id: str = Depends(get_messaging_user_id),
):
    """Update moderation status for a report and archive the status transition."""
    require_participant_role(user_id, conversation_id, {"admin"})
    report_item = T.message_reports.get_item(Key={"report_id": report_id}).get("Item") or {}
    if not report_item:
        raise HTTPException(status_code=404, detail="Report not found")
    if str(report_item.get("conversation_id") or "") != conversation_id:
        raise HTTPException(status_code=404, detail="Report not found")

    ts = now_ts()
    previous_status = str(report_item.get("status") or "submitted")
    note = (inp.note or "").strip()

    update_expr = "SET #status = :status, updated_at = :ts, updated_by_user_id = :uid"
    expr_names = {"#status": "status"}
    expr_values: Dict[str, Any] = {":status": inp.status, ":ts": ts, ":uid": user_id}
    if note:
        update_expr += ", moderation_note = :note"
        expr_values[":note"] = note

    T.message_reports.update_item(
        Key={"report_id": report_id},
        UpdateExpression=update_expr,
        ExpressionAttributeNames=expr_names,
        ExpressionAttributeValues=expr_values,
    )

    _emit_report_archive_event_or_503(
        event_ts=ts,
        conversation_id=conversation_id,
        message_id=str(report_item.get("message_id") or ""),
        actor_user_id=user_id,
        report_id=report_id,
        event_type="report.status_changed",
        payload={
            "action": "report_status_update",
            "from_status": previous_status,
            "to_status": inp.status,
            "note": note or None,
            "timeline_state": {"updated_at": ts, "updated_by_user_id": user_id},
        },
    )

    audit_event(
        "messaging_report_status_updated",
        user_id,
        req,
        outcome="success",
        conversation_id=conversation_id,
        report_id=report_id,
        from_status=previous_status,
        to_status=inp.status,
    )

    return ReportStatusUpdateOut(
        ok=True,
        report_id=report_id,
        conversation_id=conversation_id,
        message_id=str(report_item.get("message_id") or ""),
        status=inp.status,
        updated_at=ts,
    )


@router.post(
    "/conversations/{conversation_id}/legal-holds",
    response_model=LegalHoldOut,
    responses=MESSAGE_CONTROLS_ERROR_RESPONSES,
)
def create_message_legal_hold(
    conversation_id: str,
    inp: LegalHoldCreateIn,
    req: Request = None,
    actor: AuthenticatedUser = Depends(require_legal_hold_operator),
):
    _require_message_controls_capability(_messaging_compliance_legal_hold_enabled(), "Compliance legal hold is disabled")
    actor_user_id = str(actor.sub or "")
    require_participant_active(actor_user_id, conversation_id)

    target_message_id = (inp.message_id or "").strip()
    target_report_id = (inp.report_id or "").strip()
    if target_message_id:
        _ = _get_message_or_404(conversation_id, target_message_id)
    elif target_report_id:
        rpt = T.message_reports.get_item(Key={"report_id": target_report_id}).get("Item") or {}
        if not rpt or str(rpt.get("conversation_id") or "") != conversation_id:
            raise HTTPException(status_code=404, detail="Report not found")
        target_message_id = str(rpt.get("message_id") or "")
    else:
        raise HTTPException(status_code=422, detail="message_id or report_id is required")

    ts = now_ts()
    hold_id = f"lh_{new_id()}"
    item = {
        "hold_id": hold_id,
        "tenant_id": "default",
        "conversation_id": conversation_id,
        "conversation_status": f"{conversation_id}#active",
        "message_id": target_message_id or "",
        "report_id": target_report_id or "",
        "case_id": inp.case_id.strip(),
        "reason": inp.reason.strip(),
        "status": "active",
        "created_at": ts,
        "created_by_user_id": actor_user_id,
        "updated_at": ts,
    }
    T.message_legal_holds.put_item(Item=item)

    audit_event(
        "messaging_legal_hold_created",
        actor_user_id,
        req,
        outcome="success",
        conversation_id=conversation_id,
        hold_id=hold_id,
        case_id=item["case_id"],
        message_id=target_message_id or None,
        report_id=target_report_id or None,
    )

    return LegalHoldOut(
        hold_id=hold_id,
        tenant_id="default",
        conversation_id=conversation_id,
        message_id=target_message_id or None,
        report_id=target_report_id or None,
        case_id=item["case_id"],
        reason=item["reason"],
        status="active",
        created_at=ts,
        created_by_user_id=actor_user_id,
    )


@router.post(
    "/conversations/{conversation_id}/legal-holds/{hold_id}/release",
    response_model=LegalHoldOut,
    responses=MESSAGE_CONTROLS_ERROR_RESPONSES,
)
def release_message_legal_hold(
    conversation_id: str,
    hold_id: str,
    inp: LegalHoldReleaseIn,
    req: Request = None,
    actor: AuthenticatedUser = Depends(require_legal_hold_operator),
):
    _require_message_controls_capability(_messaging_compliance_legal_hold_enabled(), "Compliance legal hold is disabled")
    actor_user_id = str(actor.sub or "")
    require_participant_active(actor_user_id, conversation_id)

    hold = T.message_legal_holds.get_item(Key={"hold_id": hold_id}).get("Item") or {}
    if not hold or str(hold.get("conversation_id") or "") != conversation_id:
        raise HTTPException(status_code=404, detail="Legal hold not found")

    ts = now_ts()
    T.message_legal_holds.update_item(
        Key={"hold_id": hold_id},
        UpdateExpression=(
            "SET #status = :released, conversation_status = :conversation_status, "
            "released_at = :ts, released_by_user_id = :uid, release_reason = :reason, updated_at = :ts"
        ),
        ExpressionAttributeNames={"#status": "status"},
        ExpressionAttributeValues={
            ":released": "released",
            ":conversation_status": f"{conversation_id}#released",
            ":ts": ts,
            ":uid": actor_user_id,
            ":reason": inp.reason.strip(),
        },
    )

    audit_event(
        "messaging_legal_hold_released",
        actor_user_id,
        req,
        outcome="success",
        conversation_id=conversation_id,
        hold_id=hold_id,
    )

    return LegalHoldOut(
        hold_id=hold_id,
        tenant_id=str(hold.get("tenant_id") or "default"),
        conversation_id=conversation_id,
        message_id=str(hold.get("message_id") or "") or None,
        report_id=str(hold.get("report_id") or "") or None,
        case_id=str(hold.get("case_id") or ""),
        reason=str(hold.get("reason") or ""),
        status="released",
        created_at=int(hold.get("created_at", 0) or 0),
        created_by_user_id=str(hold.get("created_by_user_id") or ""),
        released_at=ts,
        released_by_user_id=actor_user_id,
    )


@router.get(
    "/conversations/{conversation_id}/legal-holds",
    response_model=List[LegalHoldOut],
    responses=MESSAGE_CONTROLS_ERROR_RESPONSES,
)
def list_message_legal_holds(
    conversation_id: str,
    status: Literal["active", "released", "all"] = Query("active"),
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    actor: AuthenticatedUser = Depends(require_legal_hold_operator),
):
    _require_message_controls_capability(_messaging_compliance_legal_hold_enabled(), "Compliance legal hold is disabled")
    actor_user_id = str(actor.sub or "")
    require_participant_active(actor_user_id, conversation_id)

    items: List[dict] = []
    if status in {"active", "released"}:
        resp = T.message_legal_holds.query(
            IndexName="ByConversationStatusCreatedAt",
            KeyConditionExpression=Key("conversation_status").eq(f"{conversation_id}#{status}"),
            ScanIndexForward=False,
            Limit=limit,
        )
        items = resp.get("Items", [])
    else:
        for st in ("active", "released"):
            resp = T.message_legal_holds.query(
                IndexName="ByConversationStatusCreatedAt",
                KeyConditionExpression=Key("conversation_status").eq(f"{conversation_id}#{st}"),
                ScanIndexForward=False,
                Limit=limit,
            )
            items.extend(resp.get("Items", []))
        items.sort(key=lambda x: int(x.get("created_at", 0) or 0), reverse=True)
        items = items[:limit]

    out: List[LegalHoldOut] = []
    for item in items:
        out.append(LegalHoldOut(
            hold_id=str(item.get("hold_id") or ""),
            tenant_id=str(item.get("tenant_id") or "default"),
            conversation_id=conversation_id,
            message_id=str(item.get("message_id") or "") or None,
            report_id=str(item.get("report_id") or "") or None,
            case_id=str(item.get("case_id") or ""),
            reason=str(item.get("reason") or ""),
            status=str(item.get("status") or "active"),
            created_at=int(item.get("created_at", 0) or 0),
            created_by_user_id=str(item.get("created_by_user_id") or ""),
            released_at=int(item.get("released_at", 0) or 0) or None,
            released_by_user_id=str(item.get("released_by_user_id") or "") or None,
        ))
    return out


@router.get(
    "/compliance/archive/events",
    response_model=ComplianceArchiveEventsPageOut,
    responses=MESSAGE_CONTROLS_ERROR_RESPONSES,
)
def query_compliance_archive_events(
    conversation_id: Optional[str] = None,
    user_id_filter: Annotated[Optional[str], Query(alias="user_id")] = None,
    from_ts: Annotated[Optional[int], Query(ge=0)] = None,
    to_ts: Annotated[Optional[int], Query(ge=0)] = None,
    cursor: Optional[str] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    sort: Literal["asc", "desc"] = "desc",
    include_payload: bool = False,
    actor: AuthenticatedUser = Depends(require_compliance_query_operator),
):
    _ = actor
    if from_ts is not None and to_ts is not None and from_ts > to_ts:
        raise HTTPException(status_code=422, detail="from_ts must be <= to_ts")

    offset = 0
    if cursor:
        parsed = decode_cursor(cursor)
        if not parsed or "offset" not in parsed:
            raise HTTPException(status_code=400, detail="invalid cursor")
        try:
            offset = max(0, int(parsed.get("offset", 0) or 0))
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(status_code=400, detail="invalid cursor") from exc

    result = query_archive_records(
        root_dir=_archive_root_dir(),
        tenant_id="default",
        conversation_id=(conversation_id or None),
        user_id=(user_id_filter or None),
        from_ts=from_ts,
        to_ts=to_ts,
        sort_order=sort,
        limit=limit,
        offset=offset,
        include_payload=include_payload,
    )

    items = [ComplianceArchiveEventOut(**item) for item in result.items]
    next_cursor = encode_cursor({"offset": result.next_offset}) if result.next_offset is not None else None
    return ComplianceArchiveEventsPageOut(items=items, next_cursor=next_cursor, total_matches=result.total_matches)


def _exports_root_dir() -> str:
    return (S.messaging_compliance_export_root_dir or ".compliance_exports").strip() or ".compliance_exports"


def _default_export_ttl_seconds() -> int:
    return max(60, int(S.messaging_compliance_export_default_ttl_seconds or 0))


def _load_export_or_404(export_id: str) -> dict[str, Any]:
    item = T.message_compliance_exports.get_item(Key={"export_id": export_id}).get("Item") or {}
    if not item:
        raise HTTPException(status_code=404, detail="Export not found")
    return item


def _ensure_export_not_expired(item: dict[str, Any]) -> None:
    expires_at = int(item.get("expires_at", 0) or 0)
    if expires_at and now_ts() > expires_at:
        raise HTTPException(status_code=410, detail="Export artifact expired")


def _run_export_job(export_id: str, request: ComplianceArchiveExportCreateIn, actor_user_id: str) -> ComplianceArchiveExportOut:
    ts = now_ts()
    query_snapshot = {
        "conversation_id": (request.conversation_id or None),
        "user_id": (request.user_id or None),
        "from_ts": int(request.from_ts),
        "to_ts": int(request.to_ts),
        "sort": "asc",
        "include_payload": bool(request.include_payload),
    }

    T.message_compliance_exports.update_item(
        Key={"export_id": export_id},
        UpdateExpression="SET #status=:running, updated_at=:ts",
        ExpressionAttributeNames={"#status": "status"},
        ExpressionAttributeValues={":running": "running", ":ts": ts},
    )
    try:
        artifact = build_case_export_bundle(
            export_id=export_id,
            case_id=request.case_id.strip(),
            tenant_id="default",
            requested_by_user_id=actor_user_id,
            generated_at=ts,
            expires_at=ts + _default_export_ttl_seconds(),
            archive_root_dir=_archive_root_dir(),
            export_root_dir=_exports_root_dir(),
            manifest_signing_key=S.messaging_compliance_export_manifest_signing_key,
            manifest_signing_key_id=S.messaging_compliance_export_manifest_signing_key_id,
            query_snapshot=query_snapshot,
        )
    except Exception as exc:  # noqa: BLE001
        T.message_compliance_exports.update_item(
            Key={"export_id": export_id},
            UpdateExpression="SET #status=:failed, error=:error, updated_at=:ts",
            ExpressionAttributeNames={"#status": "status"},
            ExpressionAttributeValues={":failed": "failed", ":error": str(exc), ":ts": now_ts()},
        )
        raise

    done_ts = now_ts()
    manifest_uri = f"file://{artifact.manifest_path}"
    T.message_compliance_exports.update_item(
        Key={"export_id": export_id},
        UpdateExpression=(
            "SET #status=:completed, updated_at=:ts, manifest_uri=:manifest_uri, "
            "artifact_dir=:artifact_dir, manifest_path=:manifest_path, records_path=:records_path, "
            "record_count=:record_count"
        ),
        ExpressionAttributeNames={"#status": "status"},
        ExpressionAttributeValues={
            ":completed": "completed",
            ":ts": done_ts,
            ":manifest_uri": manifest_uri,
            ":artifact_dir": artifact.artifact_dir,
            ":manifest_path": artifact.manifest_path,
            ":records_path": artifact.records_path,
            ":record_count": artifact.record_count,
        },
    )

    item = _load_export_or_404(export_id)
    return ComplianceArchiveExportOut(
        export_id=export_id,
        case_id=str(item.get("case_id") or ""),
        tenant_id=str(item.get("tenant_id") or "default"),
        status=str(item.get("status") or "completed"),
        created_at=int(item.get("created_at", 0) or 0),
        updated_at=int(item.get("updated_at", done_ts) or done_ts),
        requested_by_user_id=str(item.get("requested_by_user_id") or actor_user_id),
        expires_at=int(item.get("expires_at", 0) or 0),
        record_count=int(item.get("record_count", 0) or 0),
        result_manifest_uri=str(item.get("manifest_uri") or "") or None,
        error=str(item.get("error") or "") or None,
    )


@router.post(
    "/compliance/archive/exports",
    response_model=ComplianceArchiveExportOut,
    responses=MESSAGE_CONTROLS_ERROR_RESPONSES,
)
def create_compliance_archive_export(
    inp: ComplianceArchiveExportCreateIn,
    req: Request = None,
    actor: AuthenticatedUser = Depends(require_compliance_export_operator),
):
    _require_message_controls_capability(_messaging_compliance_export_enabled(), "Compliance export is disabled")
    actor_user_id = str(actor.sub or "")
    if inp.from_ts > inp.to_ts:
        raise HTTPException(status_code=422, detail="from_ts must be <= to_ts")

    ts = now_ts()
    export_id = f"exp_{new_id()}"
    item = {
        "export_id": export_id,
        "tenant_id": "default",
        "case_id": inp.case_id.strip(),
        "status": "queued",
        "created_at": ts,
        "updated_at": ts,
        "requested_by_user_id": actor_user_id,
        "expires_at": ts + _default_export_ttl_seconds(),
        "query_snapshot": {
            "conversation_id": inp.conversation_id,
            "user_id": inp.user_id,
            "from_ts": inp.from_ts,
            "to_ts": inp.to_ts,
            "include_payload": inp.include_payload,
        },
    }
    T.message_compliance_exports.put_item(Item=item)

    try:
        out = _run_export_job(export_id, inp, actor_user_id)
        record_messaging_archive_export_outcome(outcome="success")
    except Exception as exc:  # noqa: BLE001
        record_messaging_archive_export_outcome(outcome="failure")
        audit_event("messaging_compliance_export_failed", actor_user_id, req, outcome="failed", export_id=export_id, case_id=inp.case_id, error=str(exc))
        raise HTTPException(status_code=500, detail="export generation failed") from exc

    audit_event("messaging_compliance_export_created", actor_user_id, req, outcome="success", export_id=export_id, case_id=inp.case_id)
    return out


@router.get(
    "/compliance/archive/exports/{export_id}",
    response_model=ComplianceArchiveExportOut,
    responses=MESSAGE_CONTROLS_ERROR_RESPONSES,
)
def get_compliance_archive_export(
    export_id: str,
    actor: AuthenticatedUser = Depends(require_compliance_export_operator),
):
    _require_message_controls_capability(_messaging_compliance_export_enabled(), "Compliance export is disabled")
    _ = actor
    item = _load_export_or_404(export_id)
    return ComplianceArchiveExportOut(
        export_id=export_id,
        case_id=str(item.get("case_id") or ""),
        tenant_id=str(item.get("tenant_id") or "default"),
        status=str(item.get("status") or "queued"),
        created_at=int(item.get("created_at", 0) or 0),
        updated_at=int(item.get("updated_at", 0) or 0),
        requested_by_user_id=str(item.get("requested_by_user_id") or ""),
        expires_at=int(item.get("expires_at", 0) or 0),
        record_count=int(item.get("record_count", 0) or 0),
        result_manifest_uri=str(item.get("manifest_uri") or "") or None,
        error=str(item.get("error") or "") or None,
    )


@router.get(
    "/compliance/archive/exports",
    response_model=List[ComplianceArchiveExportOut],
    responses=MESSAGE_CONTROLS_ERROR_RESPONSES,
)
def list_compliance_archive_exports(
    case_id: str,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    actor: AuthenticatedUser = Depends(require_compliance_export_operator),
):
    _require_message_controls_capability(_messaging_compliance_export_enabled(), "Compliance export is disabled")
    _ = actor
    resp = T.message_compliance_exports.query(
        IndexName="ByCaseCreatedAt",
        KeyConditionExpression=Key("case_id").eq(case_id),
        ScanIndexForward=False,
        Limit=limit,
    )
    out: List[ComplianceArchiveExportOut] = []
    for item in resp.get("Items", []):
        out.append(ComplianceArchiveExportOut(
            export_id=str(item.get("export_id") or ""),
            case_id=str(item.get("case_id") or ""),
            tenant_id=str(item.get("tenant_id") or "default"),
            status=str(item.get("status") or "queued"),
            created_at=int(item.get("created_at", 0) or 0),
            updated_at=int(item.get("updated_at", 0) or 0),
            requested_by_user_id=str(item.get("requested_by_user_id") or ""),
            expires_at=int(item.get("expires_at", 0) or 0),
            record_count=int(item.get("record_count", 0) or 0),
            result_manifest_uri=str(item.get("manifest_uri") or "") or None,
            error=str(item.get("error") or "") or None,
        ))
    return out


@router.get(
    "/compliance/archive/exports/{export_id}/manifest",
    responses=MESSAGE_CONTROLS_ERROR_RESPONSES,
)
def get_compliance_archive_export_manifest(
    export_id: str,
    actor: AuthenticatedUser = Depends(require_compliance_export_operator),
):
    _require_message_controls_capability(_messaging_compliance_export_enabled(), "Compliance export is disabled")
    _ = actor
    item = _load_export_or_404(export_id)
    _ensure_export_not_expired(item)
    if str(item.get("status") or "") != "completed":
        raise HTTPException(status_code=409, detail="export not completed")
    p = str(item.get("manifest_path") or "")
    if not p or not os.path.exists(p):
        raise HTTPException(status_code=404, detail="manifest not found")
    with open(p, "r", encoding="utf-8") as f:
        return json.loads(f.read())


@router.get(
    "/compliance/archive/exports/{export_id}/records",
    responses=MESSAGE_CONTROLS_ERROR_RESPONSES,
)
def get_compliance_archive_export_records(
    export_id: str,
    actor: AuthenticatedUser = Depends(require_compliance_export_operator),
):
    _require_message_controls_capability(_messaging_compliance_export_enabled(), "Compliance export is disabled")
    _ = actor
    item = _load_export_or_404(export_id)
    _ensure_export_not_expired(item)
    if str(item.get("status") or "") != "completed":
        raise HTTPException(status_code=409, detail="export not completed")
    p = str(item.get("records_path") or "")
    if not p or not os.path.exists(p):
        raise HTTPException(status_code=404, detail="records not found")
    with open(p, "rb") as f:
        content = f.read()
    return StreamingResponse(iter([content]), media_type="application/x-ndjson")


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
def _fanout_presence_update(user_id: str, online: bool, last_seen_at: int) -> None:
    """Push presence:update SSE to all conversation partners."""
    try:
        parts = tbl_parts.query(KeyConditionExpression=Key("user_id").eq(user_id), Limit=500).get("Items", [])
        conversation_ids = {str(p.get("conversation_id") or "") for p in parts if p.get("conversation_id")}
        seen_users: set[str] = set()
        ts = now_ts()
        ttl = ts + 7 * 24 * 3600
        payload = _ddb_safe({"user_id": user_id, "online": online, "last_seen_at": last_seen_at})
        with tbl_events.batch_writer() as bw:
            for cid in conversation_ids:
                resp = tbl_parts.query(IndexName="GSI1", KeyConditionExpression=Key("GSI1PK").eq(cid))
                for p in resp.get("Items", []):
                    uid = str(p.get("user_id") or "")
                    if not uid or uid == user_id or uid in seen_users:
                        continue
                    if p.get("status") != "active":
                        continue
                    seen_users.add(uid)
                    bw.put_item(
                        Item={
                            "user_id": uid,
                            "event_id": _event_id(),
                            "type": "presence:update",
                            "created_at": ts,
                            "conversation_id": "",
                            "payload": payload,
                            "ttl": ttl,
                        }
                    )
    except Exception:
        pass


@router.post("/presence/heartbeat")
def presence_heartbeat(
    inp: PresenceHeartbeatIn,
    request: Request = None,
    x_request_id: Optional[str] = None,
    user_id: str = Depends(get_messaging_user_id),
):
    _enforce_messaging_internal_entitlement(
        user_id=user_id,
        action="presence_heartbeat",
        request_id=x_request_id or (request.headers.get("x-request-id") if request else None),
    )
    ts = now_ts()
    status = _normalize_presence_status(inp.status)

    # Check previous heartbeat for cooldown-based SSE fanout
    prev_item = None
    try:
        prev_resp = tbl_presence.get_item(Key={"user_id": user_id})
        prev_item = prev_resp.get("Item")
    except Exception:
        pass
    prev_last_seen = int(prev_item.get("last_seen_at", 0) or 0) if prev_item else 0

    tbl_presence.put_item(
        Item={
            "user_id": user_id,
            "last_seen_at": ts,
            "device": inp.device or "",
            "status": status,
            "ttl": ts + PRESENCE_TTL_SEC,
        }
    )

    online = status in {"online", "available"}
    if ts - prev_last_seen >= PRESENCE_SSE_COOLDOWN_SEC:
        _fanout_presence_update(user_id, online, ts)

    routing = _handle_helpdesk_presence_event(user_id=user_id, status=status, ts=ts)
    audit_event(
        "messaging_presence_heartbeat_processed",
        user_id,
        None,
        outcome="success",
        presence_status=status,
        routing_action=routing.get("action"),
        routing_processed=int(routing.get("processed", 0) or 0),
        routing_transitioned=int(routing.get("transitioned", 0) or 0),
        routing_failed=int(routing.get("failed", 0) or 0),
    )
    return {
        "ok": True,
        "user_id": user_id,
        "online": online,
        "last_seen_at": ts,
        "status": status,
        "routing": routing,
    }


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
    raw_items = _ddb_fetch_events(user_id, after, limit)
    items = [_project_event_for_user(item, user_id) for item in raw_items]
    return {"events": items, "next_after": items[-1]["event_id"] if items else after}


@router.get("/events/stream")
async def events_stream(
    after: Optional[str] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    poll_ms: Annotated[int, Query(ge=200, le=5000)] = 1000,
    request: Request = None,
    x_request_id: Optional[str] = None,
    user_id: str = Depends(get_messaging_user_id),
):
    _enforce_messaging_internal_entitlement(
        user_id=user_id,
        action="stream_events",
        request_id=x_request_id or (request.headers.get("x-request-id") if request else None),
    )
    async def gen():
        cursor = after
        last_ping = time.time()
        yield ": stream-open\n\n"

        while True:
            now = time.time()
            if now - last_ping > 15:
                yield ": ping\n\n"
                last_ping = now

            raw_events = await anyio.to_thread.run_sync(_ddb_fetch_events, user_id, cursor, limit)
            events = [_project_event_for_user(ev, user_id) for ev in raw_events]
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
    return MessagingConfigOut(
        messaging_encrypted_messages_enabled=_encrypted_messages_enabled(),
        messaging_gallery_enabled=_messaging_gallery_enabled(),
        messaging_dm_lottery_enabled=_messaging_dm_lottery_enabled(),
        messaging_hide_controls_enabled=_messaging_hide_controls_enabled(),
        messaging_pins_enabled=_messaging_pins_enabled(),
        messaging_reporting_enabled=_messaging_reporting_enabled(),
        messaging_mass_send_enabled=_messaging_mass_send_enabled(),
    )


@router.post("/messages/lottery", response_model=LotteryMessageOut)
def create_lottery_message(
    payload: CreateLotteryMessageIn,
    req: Request = None,
    idempotency_key: Optional[str] = Header(default=None, alias="Idempotency-Key"),
    user_id: str = Depends(get_messaging_user_id),
):
    client_version = _messaging_client_version(req)
    _require_dm_lottery_enabled()
    _enforce_messaging_internal_entitlement(
        user_id=user_id,
        action="send_message",
        request_id=(req.headers.get("x-request-id") if req else None),
    )
    require_participant_active(user_id, payload.conversation_id)
    convo = _get_conversation_or_404(payload.conversation_id)
    if str(convo.get("type") or "").strip().lower() != "dm":
        raise HTTPException(
            status_code=422,
            detail={"code": "not-dm", "message": "Lottery messages are only supported in DM conversations"},
        )

    ts = now_ts()
    normalized_idempotency_key = (idempotency_key or "").strip()
    if len(normalized_idempotency_key) > 128:
        record_messaging_lottery_send(outcome="invalid_idempotency_key", client_version=client_version)
        raise HTTPException(
            status_code=422,
            detail={"code": "invalid-idempotency-key", "message": "Idempotency-Key must be <= 128 characters"},
        )
    if normalized_idempotency_key and not re.fullmatch(r"[A-Za-z0-9._:-]+", normalized_idempotency_key):
        record_messaging_lottery_send(outcome="invalid_idempotency_key", client_version=client_version)
        raise HTTPException(
            status_code=422,
            detail={
                "code": "invalid-idempotency-key",
                "message": "Idempotency-Key may only contain letters, numbers, dot, underscore, colon, and hyphen",
            },
        )
    message_id = (
        _lottery_dedupe_message_id(
            sender_id=user_id,
            conversation_id=payload.conversation_id,
            idempotency_key=normalized_idempotency_key,
        )
        if normalized_idempotency_key
        else "m_" + new_id()
    )
    normalized_outcomes: list[dict[str, Any]] = []
    for idx, outcome in enumerate(payload.lottery_config.outcomes):
        out = outcome.model_dump(exclude_none=True)
        out.setdefault("outcome_id", f"o_{message_id}_{idx + 1}")
        payload_type = str(out.get("payload_type") or "")
        if payload_type in {"image", "video"}:
            metadata = _resolve_and_validate_lottery_media_asset(
                media_asset_id=str(out.get("media_asset_id") or ""),
                conversation_id=payload.conversation_id,
                owner_user_id=user_id,
            )
            out["media_asset_id"] = f"{metadata['bucket']}:{metadata['key']}"
            out["media_metadata"] = metadata
        normalized_outcomes.append(out)
    config_payload = {"version": payload.lottery_config.version, "outcomes": normalized_outcomes}

    if normalized_idempotency_key:
        existing_cfg = messaging_lottery_store.get_lottery_config(message_id=message_id)
        if existing_cfg:
            same_actor = (
                str(existing_cfg.get("sender_id") or "") == user_id
                and str(existing_cfg.get("conversation_id") or "") == payload.conversation_id
            )
            same_payload = _lottery_config_signature(existing_cfg) == _lottery_config_signature(config_payload)
            if not (same_actor and same_payload):
                record_messaging_lottery_send(outcome="idempotency_conflict", client_version=client_version)
                audit_event(
                    "messaging_lottery_created",
                    user_id,
                    req,
                    outcome="idempotency_conflict",
                    conversation_id=payload.conversation_id,
                    message_id=message_id,
                    event_ts=ts,
                )
                raise HTTPException(
                    status_code=409,
                    detail={
                        "code": "idempotency-conflict",
                        "message": "Idempotency-Key replayed with a different lottery payload",
                    },
                )
            existing_created_at = int(existing_cfg.get("created_at") or ts)
            existing_msg = tbl_msgs.get_item(
                Key={"conversation_id": payload.conversation_id, "message_id": message_id}
            ).get("Item")
            replay_outcome = "idempotent"
            replay_repair_failed = False
            if not existing_msg:
                repaired_message_item = _lottery_message_item(
                    conversation_id=payload.conversation_id,
                    message_id=message_id,
                    sender_id=user_id,
                    created_at=existing_created_at,
                    persisted_cfg=existing_cfg,
                )
                try:
                    tbl_msgs.put_item(
                        Item=repaired_message_item,
                        ConditionExpression="attribute_not_exists(message_id)",
                    )
                    _safe_index_message(repaired_message_item)
                    replay_outcome = "idempotent_repaired"
                except Exception:
                    # If orphan repair fails, surface explicit server error so callers can retry.
                    logger.exception(
                        "messaging.create_lottery_message idempotent orphan repair failed",
                        extra={
                            "conversation_id": payload.conversation_id,
                            "message_id": message_id,
                            "user_id": user_id,
                        },
                    )
                    replay_outcome = "idempotent_orphan_unrepaired"
                    replay_repair_failed = True
            record_messaging_lottery_send(outcome=replay_outcome, client_version=client_version)
            audit_event(
                "messaging_lottery_created",
                user_id,
                req,
                outcome=replay_outcome,
                conversation_id=payload.conversation_id,
                message_id=message_id,
                event_ts=existing_created_at,
                outcome_count=len(existing_cfg.get("outcomes") or []),
                outcome_ids=[str(out.get("outcome_id") or "") for out in (existing_cfg.get("outcomes") or [])],
                payload_types=[str(out.get("payload_type") or "") for out in (existing_cfg.get("outcomes") or [])],
                idempotent_replay=True,
            )
            if replay_repair_failed:
                raise HTTPException(
                    status_code=500,
                    detail={
                        "code": "idempotent-repair-failed",
                        "message": "Failed to repair lottery message during idempotent replay",
                    },
                )
            return LotteryMessageOut(
                message_id=message_id,
                conversation_id=payload.conversation_id,
                sender_id=user_id,
                message_type="lottery_dm",
                lock_state="locked",
                lottery_config=LotteryConfigOut(
                    version=str(existing_cfg.get("version") or "v1"),
                    outcomes=[
                        LotteryOutcomeOut(
                            outcome_id=str(out.get("outcome_id") or ""),
                            display_label=(str(out.get("display_label") or "") or None),
                            weight_bps=int(out.get("weight_bps") or 0),
                            payload_type=str(out.get("payload_type") or "text"),
                            text_content=(str(out.get("text_content") or "") or None),
                            media_asset_id=(str(out.get("media_asset_id") or "") or None),
                            media_metadata=(dict(out.get("media_metadata") or {}) or None),
                        )
                        for out in (existing_cfg.get("outcomes") or [])
                    ],
                ),
                selected_outcome=None,
                idempotent=True,
                created_at=existing_created_at,
            )

    try:
        persisted_cfg = messaging_lottery_store.put_lottery_config(
            message_id=message_id,
            conversation_id=payload.conversation_id,
            sender_id=user_id,
            lottery_config=config_payload,
            created_at=ts,
        )
    except messaging_lottery_store.LotteryConfigValidationError as exc:
        record_messaging_lottery_send(outcome="invalid_config", client_version=client_version)
        raise HTTPException(
            status_code=422,
            detail={
                "code": "invalid-config",
                "message": str(exc),
                "issues": exc.issues,
            },
        ) from exc
    except Exception as exc:
        record_messaging_lottery_send(outcome="config_persist_error", client_version=client_version)
        raise HTTPException(status_code=500, detail="Failed to persist lottery config") from exc

    message_item = _lottery_message_item(
        conversation_id=payload.conversation_id,
        message_id=message_id,
        sender_id=user_id,
        created_at=ts,
        persisted_cfg=persisted_cfg,
    )
    try:
        tbl_msgs.put_item(Item=message_item, ConditionExpression="attribute_not_exists(message_id)")
    except Exception as exc:
        try:
            ddb.Table(S.lottery_message_config_table_name).delete_item(Key={"message_id": message_id})
        except Exception:
            pass
        record_messaging_lottery_send(outcome="message_persist_error", client_version=client_version)
        raise HTTPException(status_code=500, detail="Failed to create lottery message") from exc

    _safe_index_message(message_item)
    _meter_message_send(user_id=user_id, conversation_id=payload.conversation_id, message_id=message_id)
    record_messaging_lottery_send(outcome="success", client_version=client_version)
    audit_event(
        "messaging_lottery_created",
        user_id,
        req,
        outcome="success",
        conversation_id=payload.conversation_id,
        message_id=message_id,
        event_ts=ts,
        outcome_count=len(persisted_cfg.get("outcomes") or []),
        outcome_ids=[str(out.get("outcome_id") or "") for out in (persisted_cfg.get("outcomes") or [])],
        payload_types=[str(out.get("payload_type") or "") for out in (persisted_cfg.get("outcomes") or [])],
    )

    return LotteryMessageOut(
        message_id=message_id,
        conversation_id=payload.conversation_id,
        sender_id=user_id,
        message_type="lottery_dm",
        lock_state="locked",
        lottery_config=LotteryConfigOut(
            version=str(persisted_cfg.get("version") or "v1"),
            outcomes=[
                LotteryOutcomeOut(
                    outcome_id=str(out.get("outcome_id") or ""),
                    display_label=(str(out.get("display_label") or "") or None),
                    weight_bps=int(out.get("weight_bps") or 0),
                    payload_type=str(out.get("payload_type") or "text"),
                    text_content=(str(out.get("text_content") or "") or None),
                    media_asset_id=(str(out.get("media_asset_id") or "") or None),
                    media_metadata=(dict(out.get("media_metadata") or {}) or None),
                )
                for out in (persisted_cfg.get("outcomes") or [])
            ],
        ),
        selected_outcome=None,
        idempotent=False,
        created_at=ts,
    )


@router.post("/messages/{message_id}/lottery/unlock", response_model=LotteryUnlockOut)
def unlock_lottery_message(
    message_id: str,
    req: Request = None,
    user_id: str = Depends(get_messaging_user_id),
):
    started = time.perf_counter()
    client_version = _messaging_client_version(req)
    reveal_latency_header = (req.headers.get("x-lottery-reveal-latency-ms") if req else None) or ""
    record_messaging_lottery_unlock_attempt(client_version=client_version)

    def _record_unlock_telemetry(outcome: str) -> None:
        elapsed = max(0.0, time.perf_counter() - started)
        reveal_elapsed = elapsed
        if reveal_latency_header:
            try:
                parsed_ms = float(reveal_latency_header)
                if parsed_ms >= 0:
                    reveal_elapsed = parsed_ms / 1000.0
            except Exception:
                reveal_elapsed = elapsed
        record_messaging_lottery_unlock_result(outcome=outcome, client_version=client_version)
        record_messaging_lottery_unlock_latency(
            outcome=outcome,
            elapsed_seconds=elapsed,
            client_version=client_version,
        )
        record_messaging_lottery_reveal_latency(
            outcome=outcome,
            elapsed_seconds=reveal_elapsed,
            client_version=client_version,
        )

    _require_dm_lottery_enabled()
    cfg = messaging_lottery_store.get_lottery_config(message_id=message_id)
    if not cfg:
        _record_unlock_telemetry("message_not_found")
        raise HTTPException(status_code=404, detail={"code": "message-not-found", "message": "Lottery message not found"})

    conversation_id = str(cfg.get("conversation_id") or "")
    sender_id = str(cfg.get("sender_id") or "")
    require_participant_active(user_id, conversation_id)
    if user_id == sender_id:
        _record_unlock_telemetry("unauthorized_sender")
        raise HTTPException(
            status_code=403,
            detail={"code": "unauthorized", "message": "Sender cannot unlock their own lottery message"},
        )
    try:
        _enforce_lottery_unlock_rate_limit(
            user_id=user_id,
            conversation_id=conversation_id,
            message_id=message_id,
            now=now_ts(),
        )
    except HTTPException:
        _record_unlock_telemetry("rate_limited")
        raise

    # Short-circuit existing unlock so repeated calls are deterministic with no reroll.
    existing_unlock = messaging_lottery_store.get_lottery_unlock(message_id=message_id, recipient_id=user_id)
    if existing_unlock:
        selected_outcome_id = str(existing_unlock.get("selected_outcome_id") or "")
        selected = next((o for o in (cfg.get("outcomes") or []) if str(o.get("outcome_id") or "") == selected_outcome_id), None)
        if not selected:
            _record_unlock_telemetry("config_mismatch")
            raise HTTPException(status_code=500, detail="Lottery outcome configuration mismatch")
        unlocked_at = int(existing_unlock.get("unlocked_at") or now_ts())
        audit_event(
            "messaging_lottery_unlocked",
            user_id,
            req,
            outcome="idempotent",
            conversation_id=conversation_id,
            message_id=message_id,
            event_ts=unlocked_at,
            selected_outcome_id=selected_outcome_id,
        )
        _record_unlock_telemetry("idempotent")
        return LotteryUnlockOut(
            message_id=message_id,
            lock_state="unlocked",
            selected_outcome=LotterySelectedOutcomeOut(
                outcome_id=selected_outcome_id,
                payload_type=str(selected.get("payload_type") or "text"),
                text_content=(str(selected.get("text_content") or "") or None),
                media_asset_id=(str(selected.get("media_asset_id") or "") or None),
            ),
            unlocked_at=unlocked_at,
        )

    try:
        selected, rng_roll = choose_weighted_outcome(cfg.get("outcomes") or [])
    except LotterySelectionError as exc:
        _record_unlock_telemetry("invalid_config")
        raise HTTPException(status_code=422, detail={"code": "invalid-config", "message": str(exc)}) from exc

    try:
        unlock = messaging_lottery_store.put_lottery_unlock(
            message_id=message_id,
            recipient_id=user_id,
            selected_outcome_id=str(selected.get("outcome_id") or ""),
            unlocked_at=now_ts(),
            rng_roll=rng_roll,
        ).item
    except Exception as exc:
        _record_unlock_telemetry("unlock_persist_error")
        raise HTTPException(
            status_code=500,
            detail={"code": "unlock-persist-error", "message": "Failed to persist lottery unlock"},
        ) from exc

    selected_outcome_id = str(unlock.get("selected_outcome_id") or "")
    selected_payload = next((o for o in (cfg.get("outcomes") or []) if str(o.get("outcome_id") or "") == selected_outcome_id), None)
    if not selected_payload:
        _record_unlock_telemetry("config_mismatch")
        raise HTTPException(status_code=500, detail="Lottery outcome configuration mismatch")
    unlocked_at = int(unlock.get("unlocked_at") or now_ts())
    audit_event(
        "messaging_lottery_unlocked",
        user_id,
        req,
        outcome="success",
        conversation_id=conversation_id,
        message_id=message_id,
        event_ts=unlocked_at,
        selected_outcome_id=selected_outcome_id,
    )
    _record_unlock_telemetry("success")

    return LotteryUnlockOut(
        message_id=message_id,
        lock_state="unlocked",
        selected_outcome=LotterySelectedOutcomeOut(
            outcome_id=selected_outcome_id,
            payload_type=str(selected_payload.get("payload_type") or "text"),
            text_content=(str(selected_payload.get("text_content") or "") or None),
            media_asset_id=(str(selected_payload.get("media_asset_id") or "") or None),
        ),
        unlocked_at=unlocked_at,
    )


@router.get("/messages/{message_id}/lottery", response_model=LotteryMessageOut)
def get_lottery_message(
    message_id: str,
    user_id: str = Depends(get_messaging_user_id),
):
    _require_dm_lottery_enabled()
    cfg = messaging_lottery_store.get_lottery_config(message_id=message_id)
    if not cfg:
        raise HTTPException(
            status_code=404,
            detail={"code": "message-not-found", "message": "Lottery message not found"},
        )

    conversation_id = str(cfg.get("conversation_id") or "")
    sender_id = str(cfg.get("sender_id") or "")
    require_participant_active(user_id, conversation_id)

    selected_outcome: Optional[LotterySelectedOutcomeOut] = None
    lock_state: Literal["locked", "unlocked"] = "locked"
    if user_id != sender_id:
        unlock = messaging_lottery_store.get_lottery_unlock(message_id=message_id, recipient_id=user_id)
        if unlock:
            selected_outcome_id = str(unlock.get("selected_outcome_id") or "")
            selected = next(
                (o for o in (cfg.get("outcomes") or []) if str(o.get("outcome_id") or "") == selected_outcome_id),
                None,
            )
            if not selected:
                raise HTTPException(status_code=500, detail="Lottery outcome configuration mismatch")
            selected_outcome = LotterySelectedOutcomeOut(
                outcome_id=selected_outcome_id,
                payload_type=str(selected.get("payload_type") or "text"),
                text_content=(str(selected.get("text_content") or "") or None),
                media_asset_id=(str(selected.get("media_asset_id") or "") or None),
            )
            lock_state = "unlocked"

    return LotteryMessageOut(
        message_id=str(cfg.get("message_id") or message_id),
        conversation_id=conversation_id,
        sender_id=sender_id,
        message_type="lottery_dm",
        lock_state=lock_state,
        lottery_config=LotteryConfigOut(
            version=str(cfg.get("version") or "v1"),
            outcomes=[
                LotteryOutcomeOut(
                    outcome_id=str(out.get("outcome_id") or ""),
                    display_label=(str(out.get("display_label") or "") or None),
                    weight_bps=int(out.get("weight_bps") or 0),
                    payload_type=str(out.get("payload_type") or "text"),
                    text_content=(str(out.get("text_content") or "") or None),
                    media_asset_id=(str(out.get("media_asset_id") or "") or None),
                    media_metadata=(dict(out.get("media_metadata") or {}) or None),
                )
                for out in (cfg.get("outcomes") or [])
            ],
        ),
        selected_outcome=selected_outcome,
        idempotent=False,
        created_at=int(cfg.get("created_at") or now_ts()),
    )


@router.get("/healthz")
def healthz():
    return {"ok": True, "ts": now_ts()}


# -------------------------
# Scheduled Messages
# -------------------------

@router.get("/conversations/{conversation_id}/messages/scheduled", response_model=List[MessageOut])
def list_scheduled_messages(
    conversation_id: str,
    user_id: str = Depends(get_messaging_user_id),
):
    """Return the caller's pending scheduled messages in a conversation."""
    require_participant_active(user_id, conversation_id)
    # Paginate through all DDB pages — FilterExpression is applied after the 1MB page
    # fetch, so a single query() call silently misses items on later pages (fixes #145).
    items = []
    kwargs: dict = dict(
        KeyConditionExpression=Key("conversation_id").eq(conversation_id),
        FilterExpression=Attr("status").eq("scheduled") & Attr("sender_id").eq(user_id),
    )
    while True:
        resp = tbl_msgs.query(**kwargs)
        items.extend(resp.get("Items", []))
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break
        kwargs["ExclusiveStartKey"] = last_key
    items.sort(key=lambda x: int(x.get("deliver_at", 0)))
    return [_message_out_from_item(item, user_id) for item in items]


@router.delete(
    "/conversations/{conversation_id}/messages/{message_id}/schedule",
    response_model=Dict[str, Any],
)
def cancel_scheduled_message(
    conversation_id: str,
    message_id: str,
    req: Request = None,
    user_id: str = Depends(get_messaging_user_id),
):
    """Cancel a scheduled message (only the sender can cancel)."""
    require_participant_active(user_id, conversation_id)
    msg = _get_message_or_404(conversation_id, message_id)
    if msg.get("sender_id") != user_id:
        raise HTTPException(403, "Only the sender can cancel a scheduled message")
    if msg.get("status") != "scheduled":
        raise HTTPException(400, "Message is not scheduled")
    ts = now_ts()
    tbl_msgs.delete_item(Key={"conversation_id": conversation_id, "message_id": message_id})
    audit_event(
        "messaging_scheduled_message_cancelled",
        user_id,
        req,
        outcome="success",
        conversation_id=conversation_id,
        message_id=message_id,
    )
    _emit_message_lifecycle_archive_event_or_503(
        mutation="delete",
        event_ts=ts,
        conversation_id=conversation_id,
        message_id=message_id,
        actor_user_id=user_id,
        event_type="message.deleted",
        payload={"mutation": "delete", "reason": "scheduled_cancelled", "message": _serialize_message_event_payload(msg, user_id)},
    )
    return {"ok": True, "message_id": message_id}


def _deliver_scheduled_message(item: dict) -> None:
    """Promote a scheduled message to delivered status."""
    conversation_id = item["conversation_id"]
    message_id = item["message_id"]
    user_id = item["sender_id"]
    ts = now_ts()

    # Remove scheduled status
    tbl_msgs.update_item(
        Key={"conversation_id": conversation_id, "message_id": message_id},
        UpdateExpression="REMOVE #s, deliver_at SET created_at = :ts",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={":ts": ts},
    )

    # Write deferred tip billing now that the message is actually delivered.
    # (Billing was intentionally skipped at schedule time so that cancelling
    # a scheduled tipped message does not charge the sender.)
    if item.get("tip_amount_cents"):
        recipient_id = _resolve_tip_recipient(conversation_id, user_id)
        if recipient_id:
            from app.services.tip_ledger import TipLedgerEntry, write_tip_ledger
            write_tip_ledger(TipLedgerEntry(
                tipper_user_id=user_id,
                recipient_user_id=recipient_id,
                amount_cents=int(item["tip_amount_cents"]),
                currency=item.get("tip_currency", "USD"),
                content_type="message",
                content_id=message_id,
                payment_method_id=item.get("tip_payment_method_id"),
                tip_payment_id=item.get("tip_payment_id"),
                extra_meta={"conversation_id": conversation_id},
            ))

    # Fetch participants and bump unread counts
    try:
        resp = tbl_parts.query(IndexName="GSI1", KeyConditionExpression=Key("GSI1PK").eq(conversation_id))
        participants = resp.get("Items", [])
    except Exception:
        participants = []

    _bump_unread_counts(conversation_id, user_id, participants)
    _record_delivery_receipts(conversation_id, message_id, user_id, participants)
    index_message_search(
        conversation_id, message_id, user_id, ts,
        item.get("text", ""), kind=item.get("kind", "text"),
    )

    preview_text = (item.get("text") or "")[:140]
    tbl_convos.update_item(
        Key={"conversation_id": conversation_id},
        UpdateExpression="SET last_message_at = :ts, last_message_preview = :p",
        ExpressionAttributeValues={":ts": ts, ":p": preview_text},
    )

    _fanout_new_message_event(
        conversation_id=conversation_id,
        sender_id=user_id,
        message_item=item,
        payload={"conversation_id": conversation_id, "message_id": message_id},
    )
    # Also notify the sender — fanout excludes them by default, but they need
    # to know their scheduled message was promoted so their chat view refreshes.
    ts_notify = now_ts()
    tbl_events.put_item(Item={
        "user_id": user_id,
        "event_id": _event_id(),
        "type": "message:thread_new" if item.get(MESSAGE_FIELD_THREAD_ID) else "message:new",
        "created_at": ts_notify,
        "conversation_id": conversation_id,
        "payload": {
            "conversation_id": conversation_id,
            "message_id": message_id,
            **({"thread_id": item.get(MESSAGE_FIELD_THREAD_ID)} if item.get(MESSAGE_FIELD_THREAD_ID) else {}),
            "notification_scope": "thread" if item.get(MESSAGE_FIELD_THREAD_ID) else "conversation",
        },
        "ttl": ts_notify + 7 * 24 * 3600,
    })

    delivered_item = dict(item)
    delivered_item.pop("status", None)
    delivered_item.pop("deliver_at", None)
    delivered_item["created_at"] = ts
    emit_messaging_archive_event(
        event_id=f"msg_scheduled_delivery_{conversation_id}_{message_id}_{ts}_{user_id}",
        event_ts=ts,
        tenant_id="default",
        conversation_id=conversation_id,
        message_id=message_id,
        actor_user_id=user_id,
        effective_user_id=user_id,
        event_type="message.edited",
        payload={
            "mutation": "scheduled_delivery_transition",
            "from_status": "scheduled",
            "to_status": "sent",
            "message": _serialize_message_event_payload(delivered_item, user_id),
        },
    )
    logger.info("Delivered scheduled message %s in conversation %s", message_id, conversation_id)


async def _expire_stale_invites() -> None:
    """Server-side backstop: transition invited calls to missed after timeout."""
    from app.services.messaging_call_lifecycle import CallLifecycleError, timeout_call
    from app.services.messaging_call_sessions import _table as _call_sessions_table

    timeout_seconds = S.messaging_webrtc_call_ringing_timeout_seconds
    cutoff_ts = int(now_ts()) - timeout_seconds
    try:
        tbl = _call_sessions_table()
        resp = tbl.scan(
            FilterExpression=Attr("state").eq("invited") & Attr("start_ts").lte(cutoff_ts),
        )
        for item in resp.get("Items", []):
            call_id = str(item.get("call_id") or "")
            if not call_id:
                continue
            try:
                updated, event = timeout_call(
                    call_id=call_id,
                    actor_user_id="system",
                    reason="server_timeout",
                )
                # GAP-0142: fan out call.missed from the backstop too, so the
                # callee dismisses the ringing overlay even when the caller's
                # client never sends the timeout request.
                fanout_event_to_conversation(
                    conversation_id=updated.conversation_id,
                    sender_id="system",
                    event_type="call.missed",
                    payload={
                        "call_id": updated.call_id,
                        "caller_user_id": updated.caller_user_id,
                        "callee_user_id": updated.callee_user_id,
                        "from_state": event.from_state,
                        "reason": event.reason,
                        "event_ts": event.event_ts,
                    },
                    respect_mute=False,
                )
                logger.info("Server timeout expired stale invite call_id=%s", call_id)
            except CallLifecycleError:
                # Already transitioned or other expected error — skip
                pass
            except Exception as exc:
                logger.error("Failed to timeout stale invite %s: %s", call_id, exc)
    except Exception as exc:
        logger.error("Expire stale invites loop error: %s", exc)


async def _messaging_background_loop() -> None:
    """Background task: deliver due scheduled messages and expire timed-out messages."""
    import time as _time
    from app.services.job_registry import register_task, report_error, report_poll

    register_task("scheduled_messages", 30, enabled=True,
                   description="Delivers scheduled messages and expires timed-out messages")

    while True:
        _start = _time.perf_counter()
        _processed = 0
        _failed = 0
        _loop_error = False
        # A) Deliver due scheduled messages
        try:
            resp = tbl_msgs.scan(
                FilterExpression=Attr("status").eq("scheduled") & Attr("deliver_at").lte(now_ts()),
            )
            for item in resp.get("Items", []):
                try:
                    _deliver_scheduled_message(item)
                    _processed += 1
                except Exception as exc:
                    _failed += 1
                    logger.error(
                        "Failed to deliver scheduled message %s: %s",
                        item.get("message_id"), exc,
                    )
        except Exception as exc:
            _loop_error = True
            logger.error("Scheduled messages loop error: %s", exc)

        # B) Expire messages past expires_at
        try:
            resp = tbl_msgs.scan(
                FilterExpression=(
                    Attr("expires_at").exists()
                    & Attr("expires_at").lte(now_ts())
                    & Attr("expired").ne(True)
                )
            )
            for item in resp.get("Items", []):
                try:
                    tbl_msgs.update_item(
                        Key={
                            "conversation_id": item["conversation_id"],
                            "message_id": item["message_id"],
                        },
                        UpdateExpression="SET expired = :t REMOVE #txt, image, #file, preview",
                        ExpressionAttributeNames={"#txt": "text", "#file": "file"},
                        ExpressionAttributeValues={":t": True},
                    )
                    fanout_event_to_conversation(
                        conversation_id=item["conversation_id"],
                        sender_id=item.get("sender_id", ""),
                        event_type="message:expired",
                        payload={
                            "message_id": item["message_id"],
                            "conversation_id": item["conversation_id"],
                        },
                        respect_mute=False,
                    )
                    logger.info(
                        "Expired message %s in conversation %s",
                        item.get("message_id"), item.get("conversation_id"),
                    )
                    _processed += 1
                except Exception as exc:
                    _failed += 1
                    logger.error(
                        "Failed to expire message %s: %s",
                        item.get("message_id"), exc,
                    )
        except Exception as exc:
            _loop_error = True
            logger.error("Expiry loop error: %s", exc)

        # C) Expire stale call invites (server-side ringing timeout backstop)
        await _expire_stale_invites()

        _dur = (_time.perf_counter() - _start) * 1000
        if _loop_error:
            report_error("scheduled_messages", "Loop iteration error")
        else:
            report_poll("scheduled_messages", items_processed=_processed,
                        items_failed=_failed, duration_ms=_dur)

        await asyncio.sleep(30)


def start_scheduled_messages_task() -> None:
    asyncio.create_task(_messaging_background_loop())


# -------------------------
# Message Tips
# -------------------------

class TipOut(BaseModel):
    ok: bool
    conversation_id: str
    message_id: str
    tip_payment_id: str
    amount_cents: int
    currency: str


@router.post(
    "/conversations/{conversation_id}/messages/{message_id}/tip",
    response_model=TipOut,
)
def send_message_tip(
    conversation_id: str,
    message_id: str,
    inp: SendTipIn,
    req: Request = None,
    user_id: str = Depends(get_messaging_user_id),
    _kyc: object = Depends(require_kyc_tier(2)),  # GAP-0268 (inert unless enforcement flag on)
):
    """Send a monetary tip attached to a message."""
    require_participant_active(user_id, conversation_id)
    msg = _get_message_or_404(conversation_id, message_id)
    if msg.get("revoked_at"):
        raise HTTPException(400, "Cannot tip a revoked message")
    if msg.get("sender_id") == user_id:
        raise HTTPException(400, "Cannot tip your own message")

    # Validate the chosen payment method belongs to this user
    if inp.payment_method_id:
        billing_tbl = ddb.Table(S.billing_table_name)
        billing_pk = f"USER#{user_id}"
        billing_items = billing_tbl.query(
            KeyConditionExpression="pk = :pk",
            ExpressionAttributeValues={":pk": billing_pk},
        ).get("Items", [])
        pm_ids = {
            it["payment_method_id"]
            for it in billing_items
            if it.get("sk", "").startswith("PM#") and "payment_method_id" in it
        }
        if inp.payment_method_id not in pm_ids:
            raise HTTPException(400, "Payment method not found")

    # Mock payment in dev mode; real payment processor in production
    tip_payment_id = "tip_" + new_id()
    ts = now_ts()

    update_expr = (
        "SET tip_amount_cents = if_not_exists(tip_amount_cents, :zero) + :amt, "
        "tip_currency = :cur, tip_payment_id = :pid, tip_updated_at = :ts"
    )
    expr_values: dict = {
        ":zero": 0,
        ":amt": inp.amount_cents,
        ":cur": inp.currency,
        ":pid": tip_payment_id,
        ":ts": ts,
    }
    if inp.payment_method_id:
        update_expr += ", tip_payment_method_id = :pmid"
        expr_values[":pmid"] = inp.payment_method_id

    tbl_msgs.update_item(
        Key={"conversation_id": conversation_id, "message_id": message_id},
        UpdateExpression=update_expr,
        ExpressionAttributeValues=expr_values,
    )

    # Write billing ledger debit + credit entries for the tip
    msg_author = msg.get("sender_id")
    if msg_author and msg_author != user_id:
        from app.services.tip_ledger import TipLedgerEntry, write_tip_ledger
        write_tip_ledger(TipLedgerEntry(
            tipper_user_id=user_id,
            recipient_user_id=msg_author,
            amount_cents=inp.amount_cents,
            currency=inp.currency,
            content_type="message",
            content_id=message_id,
            payment_method_id=inp.payment_method_id,
            tip_payment_id=tip_payment_id,
            extra_meta={"conversation_id": conversation_id},
        ))
        # FIN-001: generate an invoice for the tip (best-effort)
        from app.services.invoices import create_invoice_safe
        from app.services.profile import get_profile_identity
        _buyer = get_profile_identity(user_id)
        _seller = get_profile_identity(msg_author)
        create_invoice_safe(
            user_sub=user_id,
            invoice_type="tip",
            amount_cents=int(inp.amount_cents),
            line_items=[{"description": "Tip on message", "quantity": 1, "amount_cents": int(inp.amount_cents)}],
            ledger_entry_id=tip_payment_id,
            seller_id=msg_author,
            seller_name=_seller.get("display_name") or msg_author,
            buyer_name=_buyer.get("display_name") or user_id,
            buyer_email=_buyer.get("email") or "",
            payment_method_summary=str(inp.payment_method_id or ""),
            currency=str(inp.currency or "usd").lower(),
        )

    # GAP-0026: Best-effort license revenue split for tipped message.
    # Wrapped in try/except so a split failure never breaks the tip transaction.
    try:
        from app.services import license_revenue as _lr_svc
        _lr_svc.process_revenue_split(
            content_id=message_id,
            licensee_id=user_id,
            source_type="tip",
            source_amount_cents=inp.amount_cents,
            source_txn_id=tip_payment_id,
            currency=str(inp.currency or "usd").lower(),
        )
    except Exception:
        logger.warning(
            "license revenue split failed for tip on message %s", message_id
        )

    fanout_event_to_conversation(
        conversation_id=conversation_id,
        sender_id=user_id,
        event_type="message:tip",
        payload={
            "conversation_id": conversation_id,
            "message_id": message_id,
            "tipper_id": user_id,
            "amount_cents": inp.amount_cents,
            "currency": inp.currency,
            "tip_payment_id": tip_payment_id,
        },
    )
    audit_event(
        "messaging_tip_sent",
        user_id,
        req,
        outcome="success",
        conversation_id=conversation_id,
        message_id=message_id,
        amount_cents=inp.amount_cents,
        currency=inp.currency,
    )
    return TipOut(
        ok=True,
        conversation_id=conversation_id,
        message_id=message_id,
        tip_payment_id=tip_payment_id,
        amount_cents=inp.amount_cents,
        currency=inp.currency,
    )


# -------------------------
# Unlock (PPV) Message
# -------------------------

@router.post(
    "/conversations/{conversation_id}/messages/{message_id}/unlock",
    response_model=UnlockOut,
)
def unlock_message(
    conversation_id: str,
    message_id: str,
    inp: UnlockMessageIn,
    req: Request = None,
    user_id: str = Depends(get_messaging_user_id),
    _kyc: object = Depends(require_kyc_tier(2)),  # GAP-0268 (inert unless enforcement flag on)
):
    """Pay to unlock a locked (PPV) message."""
    require_participant_active(user_id, conversation_id)
    msg = _get_message_or_404(conversation_id, message_id)

    if not msg.get("lock_price_cents"):
        raise HTTPException(400, "Message is not locked")
    if msg.get("sender_id") == user_id:
        raise HTTPException(400, "Sender cannot unlock their own message")
    if user_id in (msg.get("unlocked_by") or {}):
        raise HTTPException(400, "Already unlocked")

    amount_cents = int(msg["lock_price_cents"])

    # Validate the chosen payment method belongs to this user
    if inp.payment_method_id:
        billing_tbl = ddb.Table(S.billing_table_name)
        billing_pk = f"USER#{user_id}"
        billing_items = billing_tbl.query(
            KeyConditionExpression="pk = :pk",
            ExpressionAttributeValues={":pk": billing_pk},
        ).get("Items", [])
        pm_ids = {
            it["payment_method_id"]
            for it in billing_items
            if it.get("sk", "").startswith("PM#") and "payment_method_id" in it
        }
        if inp.payment_method_id not in pm_ids:
            raise HTTPException(400, "Payment method not found")

    # Dev-mode: mock payment; production would call a real payment processor
    unlock_payment_id = "unlock_" + new_id()
    unlock_ts = now_ts()

    tbl_msgs.update_item(
        Key={"conversation_id": conversation_id, "message_id": message_id},
        UpdateExpression="SET unlocked_by.#uid = :pid",
        ExpressionAttributeNames={"#uid": user_id},
        ExpressionAttributeValues={":pid": unlock_payment_id},
    )

    # Write billing ledger entries for the unlock.
    # Debit the buyer and credit the seller. Both carry content_id (the
    # message_id) so FIN-006 per-content revenue can attribute unlock
    # earnings to the locked content item.
    _seller_id = msg.get("sender_id") or ""
    try:
        billing_tbl_led = ddb.Table(S.billing_table_name)
        led_entry_id = uuid.uuid4().hex
        led_sk = f"LEDGER#{unlock_ts}#{led_entry_id}"
        billing_tbl_led.put_item(Item={
            "pk": f"USER#{user_id}",
            "sk": led_sk,
            "entry_id": led_entry_id,
            "ts": unlock_ts,
            "type": "debit",
            "amount_cents": amount_cents,
            "currency": "USD",
            "state": "settled",
            "reason": "Message unlock",
            "meta": {
                "conversation_id": conversation_id,
                "message_id": message_id,
                "content_id": message_id,
                "content_type": "message",
                "unlock_payment_id": unlock_payment_id,
            },
        })
        # Credit the seller (creator) so unlock revenue is attributable.
        if _seller_id and _seller_id != user_id:
            credit_entry_id = uuid.uuid4().hex
            billing_tbl_led.put_item(Item={
                "pk": f"USER#{_seller_id}",
                "sk": f"LEDGER#{unlock_ts}#{credit_entry_id}",
                "entry_id": credit_entry_id,
                "ts": unlock_ts,
                "type": "credit",
                "amount_cents": amount_cents,
                "currency": "USD",
                "state": "settled",
                "reason": "Message unlock",
                "meta": {
                    "conversation_id": conversation_id,
                    "message_id": message_id,
                    "content_id": message_id,
                    "content_type": "message",
                    "unlock_payment_id": unlock_payment_id,
                    "unlocker_id": user_id,
                },
            })
    except Exception:
        pass  # Best-effort ledger write

    # GAP-0026: Best-effort license revenue split for unlocked message.
    # Wrapped in try/except so a split failure never breaks the unlock transaction.
    try:
        from app.services import license_revenue as _lr_svc
        _lr_svc.process_revenue_split(
            content_id=message_id,
            licensee_id=user_id,
            source_type="unlock",
            source_amount_cents=amount_cents,
            source_txn_id=unlock_payment_id,
            currency="usd",
        )
    except Exception:
        logger.warning(
            "license revenue split failed for unlock on message %s", message_id
        )

    # FIN-001: generate an invoice for the unlock (best-effort)
    try:
        from app.services.invoices import create_invoice_safe
        from app.services.profile import get_profile_identity
        _seller_id = msg.get("sender_id") or ""
        _buyer = get_profile_identity(user_id)
        _seller = get_profile_identity(_seller_id) if _seller_id else {}
        _lock_desc = msg.get("lock_description") or "content"
        create_invoice_safe(
            user_sub=user_id,
            invoice_type="unlock",
            amount_cents=int(amount_cents),
            line_items=[{"description": f"Unlock: {_lock_desc}", "quantity": 1, "amount_cents": int(amount_cents)}],
            ledger_entry_id=unlock_payment_id,
            seller_id=_seller_id,
            seller_name=(_seller.get("display_name") if _seller else None) or _seller_id or "Platform",
            buyer_name=_buyer.get("display_name") or user_id,
            buyer_email=_buyer.get("email") or "",
            payment_method_summary=str(inp.payment_method_id or ""),
            currency="usd",
        )
    except Exception:
        pass

    fanout_event_to_conversation(
        conversation_id=conversation_id,
        sender_id=user_id,
        event_type="message:unlocked",
        payload={
            "message_id": message_id,
            "unlocker_id": user_id,
            "unlock_payment_id": unlock_payment_id,
            "amount_cents": amount_cents,
        },
        respect_mute=False,
    )
    audit_event(
        "messaging_message_unlocked",
        user_id,
        req,
        outcome="success",
        conversation_id=conversation_id,
        message_id=message_id,
        amount_cents=amount_cents,
    )
    return UnlockOut(
        ok=True,
        conversation_id=conversation_id,
        message_id=message_id,
        unlock_payment_id=unlock_payment_id,
        amount_cents=amount_cents,
    )


class TurnIceServerOut(BaseModel):
    urls: list[str]
    username: str
    credential: str


class TurnCredentialsOut(BaseModel):
    ttl_seconds: int
    expires_at: int
    ice_servers: list[TurnIceServerOut]


class TurnCredentialErrorDetailOut(BaseModel):
    code: str
    message: str


class TurnCredentialErrorOut(BaseModel):
    detail: TurnCredentialErrorDetailOut


TURN_CREDENTIAL_ERROR_STATUS_MAP = {
    "feature_disabled": 403,
    "turn_not_configured": 503,
    "turn_invalid_url": 503,
    "turn_invalid_ttl": 503,
    "participant_lookup_failed": 503,
    "call_not_found": 404,
    "forbidden": 403,
    "call_participant_mismatch": 409,
    "invalid_state": 409,
    "validation_error": 400,
}
TURN_CREDENTIAL_ENDPOINT_RESPONSES = {
    400: {"model": TurnCredentialErrorOut, "description": "Invalid TURN credential request"},
    403: {"model": TurnCredentialErrorOut, "description": "Forbidden or feature disabled"},
    404: {"model": TurnCredentialErrorOut, "description": "Call session not found"},
    409: {"model": TurnCredentialErrorOut, "description": "Call state or participant mismatch"},
    503: {"model": TurnCredentialErrorOut, "description": "TURN service/configuration unavailable"},
}


@router.post(
    "/messages/calls/{call_id}/turn-credentials",
    response_model=TurnCredentialsOut,
    responses=TURN_CREDENTIAL_ENDPOINT_RESPONSES,
)
async def issue_turn_credentials_endpoint(
    call_id: str,
    user_id: str = Depends(get_messaging_user_id),
):
    from app.services.messaging_turn_credentials import TurnCredentialIssueError, issue_turn_credentials

    try:
        creds = issue_turn_credentials(call_id=call_id, actor_user_id=user_id)
        return TurnCredentialsOut(
            ttl_seconds=creds.ttl_seconds,
            expires_at=creds.expires_at,
            ice_servers=[TurnIceServerOut(**server) for server in creds.ice_servers],
        )
    except TurnCredentialIssueError as exc:
        raise HTTPException(
            status_code=TURN_CREDENTIAL_ERROR_STATUS_MAP.get(exc.code, 400),
            detail={"code": exc.code, "message": str(exc)},
        )


# ---------------------------------------------------------------------------
# WebRTC Call Lifecycle Routes
# ---------------------------------------------------------------------------

class CallInviteIn(BaseModel):
    call_id: str
    conversation_id: str
    callee_user_id: str
    initial_mode: str = "audio"
    idempotency_key: Optional[str] = None
    paid: bool = False
    rate_cents_per_min: Optional[int] = None


class CallInviteOut(BaseModel):
    call_id: str
    conversation_id: str
    caller_user_id: str
    callee_user_id: str
    state: str
    initial_mode: str
    start_ts: int
    paid: bool = False
    rate_cents_per_minute: Optional[int] = None


class CallAcceptIn(BaseModel):
    idempotency_key: Optional[str] = None


class CallDeclineIn(BaseModel):
    reason: str = "declined"


class CallEndIn(BaseModel):
    reason: str = "ended"
    idempotency_key: Optional[str] = None


class CallActionOut(BaseModel):
    call_id: str
    conversation_id: str
    state: str
    from_state: Optional[str] = None
    reason: Optional[str] = None
    event_ts: int
    voicemail_eligible: bool = False


_CALL_ERROR_STATUS_MAP = {
    "call_not_found": 404,
    "forbidden": 403,
    "invalid_state_transition": 409,
    "callee_busy": 409,
    "caller_busy": 409,
    "duplicate_call_id": 409,
    "idempotency_conflict": 409,
}


def _call_error_to_http(exc) -> HTTPException:
    return HTTPException(
        status_code=_CALL_ERROR_STATUS_MAP.get(exc.code, 400),
        detail={"code": exc.code, "message": str(exc)},
    )


@router.post("/messages/calls/invite", response_model=CallInviteOut)
async def create_call_invite(
    body: CallInviteIn,
    user_id: str = Depends(get_messaging_user_id),
):
    from app.services.messaging_call_lifecycle import CallLifecycleError, create_invite
    from app.core.settings import S as _settings

    paid = body.paid
    rate_cents = 0
    max_dur = 0

    if paid:
        if not _settings.call_billing_enabled:
            raise HTTPException(400, detail={"code": "feature_disabled", "message": "Paid calls are not enabled"})
        from app.services.call_billing_timer import get_call_rate, check_balance_for_paid_call
        rate_settings = get_call_rate(body.callee_user_id)
        if not rate_settings or not rate_settings.enabled:
            raise HTTPException(400, detail={"code": "paid_calls_disabled", "message": "Creator has not enabled paid calls"})
        rate_cents = rate_settings.rate_cents_per_minute
        max_dur = rate_settings.max_duration_minutes * 60
        try:
            check_balance_for_paid_call(
                caller_user_id=user_id,
                rate_cents_per_minute=rate_cents,
                min_balance_minutes=rate_settings.min_balance_minutes,
            )
        except ValueError as ve:
            detail = ve.args[0] if ve.args else {"code": "insufficient_balance"}
            raise HTTPException(402, detail=detail)

    try:
        record, _event = create_invite(
            call_id=body.call_id,
            conversation_id=body.conversation_id,
            actor_user_id=user_id,
            caller_user_id=user_id,
            callee_user_id=body.callee_user_id,
            initial_mode=body.initial_mode,
            idempotency_key=body.idempotency_key,
            paid=paid,
            rate_cents_per_min=rate_cents,
            max_duration_seconds=max_dur,
        )
        return CallInviteOut(
            call_id=record.call_id,
            conversation_id=record.conversation_id,
            caller_user_id=record.caller_user_id,
            callee_user_id=record.callee_user_id,
            state=record.state,
            initial_mode=record.initial_mode,
            start_ts=record.start_ts,
            paid=record.paid,
            rate_cents_per_minute=record.rate_cents_per_min if record.paid else None,
        )
    except CallLifecycleError as exc:
        raise _call_error_to_http(exc)


@router.post("/messages/calls/{call_id}/accept", response_model=CallActionOut)
async def accept_call_invite(
    call_id: str,
    body: CallAcceptIn = CallAcceptIn(),
    user_id: str = Depends(get_messaging_user_id),
):
    from app.services.messaging_call_lifecycle import CallLifecycleError, accept_invite

    try:
        record, event = accept_invite(
            call_id=call_id,
            actor_user_id=user_id,
            idempotency_key=body.idempotency_key,
        )
        return CallActionOut(
            call_id=record.call_id,
            conversation_id=record.conversation_id,
            state=record.state,
            from_state=event.from_state,
            event_ts=event.event_ts,
        )
    except CallLifecycleError as exc:
        raise _call_error_to_http(exc)


@router.post("/messages/calls/{call_id}/decline", response_model=CallActionOut)
async def decline_call_invite(
    call_id: str,
    body: CallDeclineIn = CallDeclineIn(),
    user_id: str = Depends(get_messaging_user_id),
):
    from app.services.messaging_call_lifecycle import CallLifecycleError, decline_invite

    try:
        record, event = decline_invite(
            call_id=call_id,
            actor_user_id=user_id,
            reason=body.reason,
        )
        _vm_eligible = (
            record.state in VOICEMAIL_ELIGIBLE_STATES
            and not record.paid
            and not record.voicemail_message_id
            and S.voicemail_enabled
        )
        return CallActionOut(
            call_id=record.call_id,
            conversation_id=record.conversation_id,
            state=record.state,
            from_state=event.from_state,
            reason=event.reason,
            event_ts=event.event_ts,
            voicemail_eligible=_vm_eligible,
        )
    except CallLifecycleError as exc:
        raise _call_error_to_http(exc)


@router.post("/messages/calls/{call_id}/end", response_model=CallActionOut)
async def end_call_endpoint(
    call_id: str,
    body: CallEndIn = CallEndIn(),
    user_id: str = Depends(get_messaging_user_id),
):
    from app.services.messaging_call_lifecycle import CallLifecycleError, end_call

    try:
        record, event = end_call(
            call_id=call_id,
            actor_user_id=user_id,
            reason=body.reason,
            idempotency_key=body.idempotency_key,
        )
        return CallActionOut(
            call_id=record.call_id,
            conversation_id=record.conversation_id,
            state=record.state,
            from_state=event.from_state,
            reason=event.reason,
            event_ts=event.event_ts,
        )
    except CallLifecycleError as exc:
        raise _call_error_to_http(exc)


class CallTimeoutIn(BaseModel):
    reason: str = "no_answer"
    idempotency_key: Optional[str] = None


@router.post("/messages/calls/{call_id}/timeout", response_model=CallActionOut)
async def timeout_call_endpoint(
    call_id: str,
    body: CallTimeoutIn = CallTimeoutIn(),
    user_id: str = Depends(get_messaging_user_id),
):
    from app.services.messaging_call_lifecycle import CallLifecycleError, timeout_call

    try:
        record, event = timeout_call(
            call_id=call_id,
            actor_user_id=user_id,
            reason=body.reason,
            idempotency_key=body.idempotency_key,
        )
        # GAP-0142: fan out call.missed so the callee dismisses the ringing
        # overlay in real time instead of waiting for the next SSE poll.
        fanout_event_to_conversation(
            conversation_id=record.conversation_id,
            sender_id=user_id,
            event_type="call.missed",
            payload={
                "call_id": record.call_id,
                "caller_user_id": record.caller_user_id,
                "callee_user_id": record.callee_user_id,
                "from_state": event.from_state,
                "reason": event.reason,
                "event_ts": event.event_ts,
            },
            respect_mute=False,
        )
        _vm_eligible = (
            record.state in VOICEMAIL_ELIGIBLE_STATES
            and not record.paid
            and not record.voicemail_message_id
            and S.voicemail_enabled
        )
        return CallActionOut(
            call_id=record.call_id,
            conversation_id=record.conversation_id,
            state=record.state,
            from_state=event.from_state,
            reason=event.reason,
            event_ts=event.event_ts,
            voicemail_eligible=_vm_eligible,
        )
    except CallLifecycleError as exc:
        raise _call_error_to_http(exc)


# ---------------------------------------------------------------------------
# WebRTC Signaling Relay
# ---------------------------------------------------------------------------


class CallSignalingIn(BaseModel):
    type: str = Field(..., pattern=r"^(webrtc\.offer|webrtc\.answer|webrtc\.ice_candidate|webrtc\.screen_share_start|webrtc\.screen_share_stop)$")
    event_id: str = Field(..., min_length=1, max_length=128)
    conversation_id: str = Field(..., min_length=1, max_length=128)
    recipient_user_id: str = Field(..., min_length=1, max_length=128)
    nonce: str = Field(..., min_length=8, max_length=128)
    sent_at: int
    payload: dict = Field(default_factory=dict)


class CallSignalingOut(BaseModel):
    event_id: str
    call_id: str
    conversation_id: str
    event_type: str
    delivered_to: str
    status: str


class CallSignalingErrorOut(BaseModel):
    code: str
    message: str


_SIGNALING_ERROR_STATUS_MAP = {
    "validation_error": 400,
    "unsupported_version": 400,
    "stale_timestamp": 400,
    "unauthorized": 403,
    "forbidden": 403,
    "call_not_found": 404,
    "call_lookup_failed": 503,
    "participant_lookup_failed": 503,
    "replay_detected": 409,
    "replay_guard_failed": 503,
    "invalid_state": 409,
    "delivery_failed": 503,
    "rate_limited": 429,
}

SIGNALING_RATE_LIMIT_WINDOW_SECONDS = int(
    os.environ.get("MESSAGING_WEBRTC_SIGNALING_RATE_LIMIT_WINDOW_SECONDS", "10")
)
SIGNALING_RATE_LIMIT_MAX = int(
    os.environ.get("MESSAGING_WEBRTC_SIGNALING_RATE_LIMIT_MAX", "60")
)


def _enforce_webrtc_signaling_enabled() -> None:
    if S.messaging_webrtc_direct_call_kill_switch:
        raise HTTPException(status_code=403, detail={"code": "feature_disabled", "message": "WebRTC signaling is disabled"})
    if not S.messaging_webrtc_direct_call_enabled:
        raise HTTPException(status_code=403, detail={"code": "feature_disabled", "message": "WebRTC direct calls are not enabled"})


def _enforce_signaling_rate_limit(user_id: str) -> None:
    now = int(time.time())
    bucket = now // SIGNALING_RATE_LIMIT_WINDOW_SECONDS
    counter_key = f"SIGNALING_RATE#{user_id}#{bucket}"
    try:
        resp = tbl_events.update_item(
            Key={"user_id": counter_key, "event_id": "counter"},
            UpdateExpression="SET #c = if_not_exists(#c, :zero) + :one, #ttl = :ttl",
            ExpressionAttributeNames={"#c": "counter", "#ttl": "ttl"},
            ExpressionAttributeValues={
                ":zero": 0,
                ":one": 1,
                ":ttl": now + SIGNALING_RATE_LIMIT_WINDOW_SECONDS * 2,
            },
            ReturnValues="UPDATED_NEW",
        )
        count = int(resp.get("Attributes", {}).get("counter", 0))
        if count > SIGNALING_RATE_LIMIT_MAX:
            raise HTTPException(
                status_code=429,
                detail={"code": "rate_limited", "message": "Signaling rate limit exceeded"},
            )
    except HTTPException:
        raise
    except Exception:
        pass  # Fail open -- do not block signaling if rate limit check fails


SIGNALING_ENDPOINT_RESPONSES = {
    400: {"model": CallSignalingErrorOut, "description": "Invalid signaling envelope"},
    403: {"model": CallSignalingErrorOut, "description": "Feature disabled or forbidden"},
    404: {"model": CallSignalingErrorOut, "description": "Call session not found"},
    409: {"model": CallSignalingErrorOut, "description": "Replay detected or invalid state"},
    429: {"model": CallSignalingErrorOut, "description": "Rate limit exceeded"},
    503: {"model": CallSignalingErrorOut, "description": "Service temporarily unavailable"},
}


@router.post(
    "/messages/calls/{call_id}/signal",
    response_model=CallSignalingOut,
    responses=SIGNALING_ENDPOINT_RESPONSES,
)
async def send_signaling_event(
    call_id: str,
    body: CallSignalingIn,
    user_id: str = Depends(get_messaging_user_id),
):
    from app.services.messaging_call_signaling import SignalingValidationError, route_signaling_event

    _enforce_webrtc_signaling_enabled()
    _enforce_signaling_rate_limit(user_id)

    envelope = {
        "type": body.type,
        "version": 1,
        "event_id": body.event_id,
        "call_id": call_id,
        "conversation_id": body.conversation_id,
        "sender_user_id": user_id,
        "recipient_user_id": body.recipient_user_id,
        "nonce": body.nonce,
        "sent_at": body.sent_at,
        "payload": body.payload,
    }

    try:
        ack = route_signaling_event(envelope=envelope, actor_user_id=user_id)
    except SignalingValidationError as exc:
        raise HTTPException(
            status_code=_SIGNALING_ERROR_STATUS_MAP.get(exc.code, 400),
            detail={"code": exc.code, "message": str(exc)},
        )

    return CallSignalingOut(
        event_id=ack.event_id,
        call_id=ack.call_id,
        conversation_id=ack.conversation_id,
        event_type=ack.event_type,
        delivered_to=ack.delivered_to,
        status=ack.status,
    )


# ---------------------------------------------------------------------------
# Chat Delegation endpoints (DELEGATE-002)
# ---------------------------------------------------------------------------

from app.models import (
    DelegatedConversationOut,
    DelegatedMessageOut,
    DelegatedSendMessageIn,
    ChatDelegateAuditEntry,
)
from app.services.delegate_chat import (
    list_creator_conversations as _dc_list_convos,
    get_creator_conversation_messages as _dc_list_msgs,
    send_message_as_creator as _dc_send_msg,
    get_delegated_messages_audit as _dc_audit,
)


@router.get(
    "/delegate/{creator_id}/conversations",
    response_model=List[DelegatedConversationOut],
)
def list_delegated_conversations(
    creator_id: str,
    user_id: str = Depends(get_messaging_user_id),
):
    """List creator's conversations as a delegate (requires chat_read)."""
    items = _dc_list_convos(creator_id=creator_id, delegate_id=user_id)
    return [DelegatedConversationOut(**item) for item in items]


@router.get(
    "/delegate/{creator_id}/conversations/{conversation_id}/messages",
    response_model=List[DelegatedMessageOut],
)
def list_delegated_messages(
    creator_id: str,
    conversation_id: str,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    before: Optional[str] = None,
    user_id: str = Depends(get_messaging_user_id),
):
    """List messages in creator's conversation as a delegate (requires chat_read)."""
    items = _dc_list_msgs(
        creator_id=creator_id,
        delegate_id=user_id,
        conversation_id=conversation_id,
        limit=limit,
        before=before,
    )
    return [DelegatedMessageOut(**item) for item in items]


@router.post(
    "/delegate/{creator_id}/conversations/{conversation_id}/messages",
    response_model=DelegatedMessageOut,
)
def send_delegated_message(
    creator_id: str,
    conversation_id: str,
    body: DelegatedSendMessageIn,
    user_id: str = Depends(get_messaging_user_id),
):
    """Send a message as the creator via delegation (requires chat_respond)."""
    result = _dc_send_msg(
        creator_id=creator_id,
        delegate_id=user_id,
        conversation_id=conversation_id,
        text=body.text,
        reply_to_message_id=body.reply_to_message_id,
    )
    return DelegatedMessageOut(**result)


@router.get(
    "/delegate/{creator_id}/audit",
    response_model=List[ChatDelegateAuditEntry],
)
def list_delegated_chat_audit(
    creator_id: str,
    conversation_id: Optional[str] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    user_id: str = Depends(get_messaging_user_id),
):
    """List messages sent by delegates in creator's conversations (creator only)."""
    items = _dc_audit(
        creator_id=creator_id,
        requester_id=user_id,
        conversation_id=conversation_id,
        limit=limit,
    )
    return [ChatDelegateAuditEntry(**item) for item in items]
