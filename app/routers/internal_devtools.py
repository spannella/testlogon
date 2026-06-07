from __future__ import annotations

import base64
import json
import logging
from typing import Literal, Optional

from fastapi import APIRouter, HTTPException, Query

from app.core.settings import S
from app.models import (
    DevtoolsBillingLedgerOut,
    DevtoolsBillingLedgerSummaryOut,
    DevtoolsEmailMessagesOut,
    DevtoolsFfmpegHealthOut,
    DevtoolsSmsConversationsOut,
)
from app.services.devtools.read_service import (
    get_billing_ledger,
    get_billing_summary,
    get_email_messages,
    get_sms_conversations,
)
from app.services.ffmpeg_manager import validate_ffmpeg

router = APIRouter(prefix="/internal/dev-tools", tags=["internal-dev-tools"])
logger = logging.getLogger(__name__)


def _require_devtools_enabled() -> None:
    if not S.dev_mode:
        raise HTTPException(
            status_code=404,
            detail={"code": "devtools_disabled", "message": "internal dev-tools routes are disabled"},
        )


def _audit_devtools_access(endpoint: str, **filters: object) -> None:
    # Dev-only access note for local debugging traceability.
    logger.info("internal_devtools_access", extra={"endpoint": endpoint, "filters": filters})


def _decode_cursor(cursor: Optional[str]) -> int:
    """Decode URL-safe base64 cursor that stores {"offset": <int>}.

    Contract behavior:
    - missing cursor -> offset=0
    - malformed cursor -> 400 with deterministic `invalid_cursor` error payload
    """

    if not cursor:
        return 0

    try:
        # Add safe padding for urlsafe base64 decode.
        padded = cursor + "=" * (-len(cursor) % 4)
        decoded = base64.urlsafe_b64decode(padded.encode("utf-8")).decode("utf-8")
        payload = json.loads(decoded)
    except Exception as exc:  # pragma: no cover - defensive parsing path
        raise HTTPException(
            status_code=400,
            detail={
                "code": "invalid_cursor",
                "message": "cursor must be urlsafe base64 JSON with an integer offset",
            },
        ) from exc

    offset = payload.get("offset")
    if not isinstance(offset, int) or offset < 0:
        raise HTTPException(
            status_code=400,
            detail={
                "code": "invalid_cursor",
                "message": "cursor offset must be a non-negative integer",
            },
        )
    return offset


@router.get("/email/messages", response_model=DevtoolsEmailMessagesOut)
def get_devtools_email_messages(
    mailbox: Optional[str] = Query(default=None, max_length=320),
    thread_id: Optional[str] = Query(default=None, max_length=128),
    q: Optional[str] = Query(default=None, max_length=256),
    state: Optional[Literal["all", "unread", "sent"]] = Query(default="all"),
    limit: int = Query(default=50, ge=1, le=200),
    cursor: Optional[str] = Query(default=None, max_length=512),
) -> DevtoolsEmailMessagesOut:
    _require_devtools_enabled()
    _audit_devtools_access("email/messages", mailbox=mailbox, thread_id=thread_id, q=q, state=state, limit=limit, cursor=bool(cursor))
    offset = _decode_cursor(cursor)
    return get_email_messages(
        S.devtools_email_log_path,
        mailbox=mailbox,
        thread_id=thread_id,
        q=q,
        state=state or "all",
        limit=limit,
        offset=offset,
    )


@router.get("/sms/conversations", response_model=DevtoolsSmsConversationsOut)
def get_devtools_sms_conversations(
    participant: Optional[str] = Query(default=None, max_length=64),
    q: Optional[str] = Query(default=None, max_length=256),
    limit: int = Query(default=50, ge=1, le=200),
    cursor: Optional[str] = Query(default=None, max_length=512),
) -> DevtoolsSmsConversationsOut:
    _require_devtools_enabled()
    _audit_devtools_access("sms/conversations", participant=participant, q=q, limit=limit, cursor=bool(cursor))
    offset = _decode_cursor(cursor)
    return get_sms_conversations(
        S.devtools_sms_log_path,
        participant=participant,
        q=q,
        limit=limit,
        offset=offset,
    )


@router.get("/billing/ledger", response_model=DevtoolsBillingLedgerOut)
def get_devtools_billing_ledger(
    provider: Optional[Literal["stripe", "ccbill", "paypal"]] = None,
    status: Optional[Literal["pending", "completed", "failed", "refunded", "canceled"]] = None,
    from_ts: Optional[str] = Query(default=None, alias="from", max_length=40),
    to_ts: Optional[str] = Query(default=None, alias="to", max_length=40),
    limit: int = Query(default=50, ge=1, le=200),
    cursor: Optional[str] = Query(default=None, max_length=512),
) -> DevtoolsBillingLedgerOut:
    _require_devtools_enabled()
    _audit_devtools_access("billing/ledger", provider=provider, status=status, from_ts=from_ts, to_ts=to_ts, limit=limit, cursor=bool(cursor))
    offset = _decode_cursor(cursor)
    return get_billing_ledger(
        S.devtools_billing_stripe_log_path,
        S.devtools_billing_backend_log_path,
        provider=provider,
        status=status,
        from_ts=from_ts,
        to_ts=to_ts,
        limit=limit,
        offset=offset,
    )


@router.get("/billing/summary", response_model=DevtoolsBillingLedgerSummaryOut)
def get_devtools_billing_summary(
    provider: Optional[Literal["stripe", "ccbill", "paypal"]] = None,
    status: Optional[Literal["pending", "completed", "failed", "refunded", "canceled"]] = None,
    from_ts: Optional[str] = Query(default=None, alias="from", max_length=40),
    to_ts: Optional[str] = Query(default=None, alias="to", max_length=40),
) -> DevtoolsBillingLedgerSummaryOut:
    _require_devtools_enabled()
    _audit_devtools_access("billing/summary", provider=provider, status=status, from_ts=from_ts, to_ts=to_ts)
    return get_billing_summary(
        S.devtools_billing_stripe_log_path,
        S.devtools_billing_backend_log_path,
        provider=provider,
        status=status,
        from_ts=from_ts,
        to_ts=to_ts,
    )


@router.get("/ffmpeg-health", response_model=DevtoolsFfmpegHealthOut)
def get_devtools_ffmpeg_health() -> DevtoolsFfmpegHealthOut:
    """Return FFmpeg binary status and codec availability (dev mode only)."""
    _require_devtools_enabled()
    _audit_devtools_access("ffmpeg-health")
    result = validate_ffmpeg()
    return DevtoolsFfmpegHealthOut(**result)
