from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Optional

from app.core.time import now_ts

logger = logging.getLogger(__name__)

ALLOWED_SIGNALING_TYPES = {
    "call.invite",
    "call.ring",
    "call.accept",
    "call.decline",
    "webrtc.offer",
    "webrtc.answer",
    "webrtc.ice_candidate",
    "call.end",
    "call.recording_request",
    "call.recording_accept",
    "call.recording_decline",
    "call.recording_started",
    "call.recording_stopped",
    "webrtc.screen_share_start",
    "webrtc.screen_share_stop",
    # CALL-014: voicemail signals
    "call.voicemail_start",
    "call.voicemail_complete",
}
MAX_SIGNALING_SKEW_SECONDS = int(os.getenv("MESSAGING_WEBRTC_SIGNALING_MAX_SKEW_SECONDS", "120"))
NONCE_TTL_SECONDS = int(os.getenv("MESSAGING_WEBRTC_SIGNALING_NONCE_TTL_SECONDS", "600"))
MAX_SIGNALING_PAYLOAD_BYTES = int(os.getenv("MESSAGING_WEBRTC_SIGNALING_MAX_PAYLOAD_BYTES", "8192"))
TERMINAL_CALL_STATES = {"ended", "missed", "declined", "busy", "failed", "canceled"}
# CALL-014: voicemail signals allowed in terminal states
VOICEMAIL_SIGNAL_TYPES = {"call.voicemail_start", "call.voicemail_complete"}
MAX_IDENTIFIER_LENGTH = 128
STATE_ALLOWED_SIGNALING_TYPES: dict[str, set[str]] = {
    "invited": {"call.invite", "call.ring", "call.accept", "call.decline", "call.end"},
    "accepted": {
        "webrtc.offer", "webrtc.answer", "webrtc.ice_candidate", "call.end",
        "webrtc.screen_share_start", "webrtc.screen_share_stop",
    },
    "connected": {
        "webrtc.offer", "webrtc.answer", "webrtc.ice_candidate", "call.end",
        "call.recording_request", "call.recording_accept", "call.recording_decline",
        "call.recording_started", "call.recording_stopped",
        "webrtc.screen_share_start", "webrtc.screen_share_stop",
    },
    # CALL-014: voicemail signals in terminal states
    "declined": {"call.voicemail_start", "call.voicemail_complete"},
    "missed": {"call.voicemail_start", "call.voicemail_complete"},
    "busy": {"call.voicemail_start", "call.voicemail_complete"},
}


class SignalingValidationError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class SignalingAck:
    event_id: str
    call_id: str
    conversation_id: str
    event_type: str
    delivered_to: str
    status: str


def _events_table():
    from app.core.aws import ddb

    return ddb.Table(os.getenv("DDB_USER_EVENTS", "UserEvents"))


def _load_conversation_participants(conversation_id: str) -> set[str]:
    from app.core.aws import ddb
    from boto3.dynamodb.conditions import Key

    table_name = os.getenv("DDB_PARTICIPANTS", "Participants")
    items = ddb.Table(table_name).query(
        IndexName="GSI1",
        KeyConditionExpression=Key("GSI1PK").eq(conversation_id),
    ).get("Items", [])
    return {str(item["user_id"]).strip() for item in items if item.get("user_id")}


def _load_call_session(call_id: str):
    from app.services.messaging_call_sessions import get_call_session

    return get_call_session(call_id)


def _require_str(envelope: Mapping[str, Any], key: str, *, max_len: int | None = None) -> str:
    value = str(envelope.get(key) or "").strip()
    if not value:
        raise SignalingValidationError("validation_error", f"missing {key}")
    if max_len is not None and len(value) > max_len:
        raise SignalingValidationError("validation_error", f"{key} exceeds maximum length {max_len}")
    return value


def _require_int(envelope: Mapping[str, Any], key: str) -> int:
    raw = envelope.get(key)
    try:
        return int(raw)
    except Exception as exc:
        raise SignalingValidationError("validation_error", f"missing or invalid {key}") from exc


def _validate_envelope(envelope: Mapping[str, Any]) -> tuple[str, str, str, str, str, str, int]:
    event_type = _require_str(envelope, "type")
    if event_type not in ALLOWED_SIGNALING_TYPES:
        raise SignalingValidationError("validation_error", "unsupported signaling type")

    version = int(envelope.get("version") or 0)
    if version != 1:
        raise SignalingValidationError("unsupported_version", "unsupported signaling version")

    event_id = _require_str(envelope, "event_id", max_len=MAX_IDENTIFIER_LENGTH)
    call_id = _require_str(envelope, "call_id", max_len=MAX_IDENTIFIER_LENGTH)
    conversation_id = _require_str(envelope, "conversation_id", max_len=MAX_IDENTIFIER_LENGTH)
    sender_user_id = _require_str(envelope, "sender_user_id", max_len=MAX_IDENTIFIER_LENGTH)
    recipient_user_id = _require_str(envelope, "recipient_user_id", max_len=MAX_IDENTIFIER_LENGTH)
    nonce = _require_str(envelope, "nonce", max_len=128)
    sent_at = _require_int(envelope, "sent_at")
    if len(nonce) < 8 or len(nonce) > 128:
        raise SignalingValidationError("validation_error", "nonce must be between 8 and 128 chars")

    now = int(now_ts())
    if abs(now - sent_at) > MAX_SIGNALING_SKEW_SECONDS:
        raise SignalingValidationError("stale_timestamp", "signaling timestamp is outside accepted skew window")

    return event_type, event_id, call_id, conversation_id, sender_user_id, recipient_user_id, nonce, sent_at


def _reserve_signaling_nonce(*, conversation_id: str, sender_user_id: str, nonce: str, sent_at: int) -> bool:
    table = _events_table()
    nonce_event_id = f"nonce#{conversation_id}#{sender_user_id}#{nonce}"
    item = {
        "user_id": f"SIGNALING_NONCE#{conversation_id}",
        "event_id": nonce_event_id,
        "type": "call.nonce_guard",
        "payload": {
            "conversation_id": conversation_id,
            "sender_user_id": sender_user_id,
            "nonce": nonce,
            "sent_at": sent_at,
        },
        "created_at": int(now_ts()),
        "conversation_id": conversation_id,
        "sender_id": sender_user_id,
        "read": True,
        "ttl": int(now_ts()) + NONCE_TTL_SECONDS,
    }
    try:
        table.put_item(Item=item, ConditionExpression="attribute_not_exists(event_id)")
        return True
    except Exception:
        return False


def _record_signaling_metric(*, outcome: str, reason: str, event_type: str, elapsed_seconds: float | None = None) -> None:
    try:
        from app.metrics import record_webrtc_signaling_event, record_webrtc_signaling_latency

        record_webrtc_signaling_event(outcome=outcome, reason=reason, event_type=event_type)
        if elapsed_seconds is not None:
            record_webrtc_signaling_latency(
                outcome=outcome,
                reason=reason,
                event_type=event_type,
                elapsed_seconds=elapsed_seconds,
            )
    except Exception:
        return


def _is_conditional_write_conflict(exc: Exception) -> bool:
    text = f"{exc.__class__.__name__}:{exc}".lower()
    return "conditionalcheckfailed" in text or "conditional check failed" in text


def route_signaling_event(
    *,
    envelope: Mapping[str, Any],
    actor_user_id: str,
    participant_resolver: Callable[[str], set[str]] = _load_conversation_participants,
    call_session_resolver: Callable[[str], Any] = _load_call_session,
    put_item: Optional[Callable[..., Any]] = None,
    replay_guard: Optional[Callable[..., bool]] = None,
    metrics_recorder: Callable[..., None] = _record_signaling_metric,
) -> SignalingAck:
    started_at = time.perf_counter()

    def emit_metric(*, outcome: str, reason: str, event_type: str) -> None:
        metrics_recorder(
            outcome=outcome,
            reason=reason,
            event_type=event_type,
            elapsed_seconds=(time.perf_counter() - started_at),
        )

    raw_event_type = str(envelope.get("type") or "unknown")
    try:
        event_type, event_id, call_id, conversation_id, sender_user_id, recipient_user_id, nonce, sent_at = _validate_envelope(envelope)
    except SignalingValidationError as exc:
        emit_metric(outcome="error", reason=exc.code, event_type=raw_event_type)
        raise

    if sender_user_id != actor_user_id:
        emit_metric(outcome="error", reason="unauthorized", event_type=event_type)
        raise SignalingValidationError("unauthorized", "sender_user_id does not match authenticated actor")

    try:
        participants = participant_resolver(conversation_id)
    except Exception as exc:
        emit_metric(outcome="error", reason="participant_lookup_failed", event_type=event_type)
        raise SignalingValidationError("participant_lookup_failed", "failed to load conversation participants") from exc
    if sender_user_id not in participants or recipient_user_id not in participants:
        emit_metric(outcome="error", reason="forbidden", event_type=event_type)
        raise SignalingValidationError("forbidden", "sender/recipient are not conversation participants")
    if sender_user_id == recipient_user_id:
        emit_metric(outcome="error", reason="validation_error", event_type=event_type)
        raise SignalingValidationError("validation_error", "sender and recipient must differ")

    try:
        call_session = call_session_resolver(call_id)
    except Exception as exc:
        emit_metric(outcome="error", reason="call_lookup_failed", event_type=event_type)
        raise SignalingValidationError("call_lookup_failed", "failed to load call session") from exc
    if not call_session:
        emit_metric(outcome="error", reason="call_not_found", event_type=event_type)
        raise SignalingValidationError("call_not_found", "call session not found")
    if str(getattr(call_session, "conversation_id", "") or "") != conversation_id:
        emit_metric(outcome="error", reason="forbidden", event_type=event_type)
        raise SignalingValidationError("forbidden", "call session does not belong to conversation")
    call_participants = {
        str(getattr(call_session, "caller_user_id", "") or ""),
        str(getattr(call_session, "callee_user_id", "") or ""),
    }
    if sender_user_id not in call_participants or recipient_user_id not in call_participants:
        emit_metric(outcome="error", reason="forbidden", event_type=event_type)
        raise SignalingValidationError("forbidden", "sender/recipient are not participants of this call")
    call_state = str(getattr(call_session, "state", "") or "").strip().lower()
    if call_state in TERMINAL_CALL_STATES and event_type != "call.end" and event_type not in VOICEMAIL_SIGNAL_TYPES:
        emit_metric(outcome="error", reason="invalid_state", event_type=event_type)
        raise SignalingValidationError("invalid_state", f"cannot route {event_type} when call is {call_state}")
    allowed_events = STATE_ALLOWED_SIGNALING_TYPES.get(call_state)
    if allowed_events is not None and event_type not in allowed_events:
        emit_metric(outcome="error", reason="invalid_state", event_type=event_type)
        raise SignalingValidationError("invalid_state", f"{event_type} not allowed when call is {call_state}")

    guard = replay_guard or _reserve_signaling_nonce
    try:
        replay_allowed = guard(conversation_id=conversation_id, sender_user_id=sender_user_id, nonce=nonce, sent_at=sent_at)
    except Exception as exc:
        emit_metric(outcome="error", reason="replay_guard_failed", event_type=event_type)
        raise SignalingValidationError("replay_guard_failed", "failed to evaluate signaling replay guard") from exc
    if not replay_allowed:
        emit_metric(outcome="error", reason="replay_detected", event_type=event_type)
        raise SignalingValidationError("replay_detected", "duplicate signaling nonce rejected")

    payload_raw = envelope.get("payload")
    if payload_raw is None:
        payload: dict[str, Any] = {}
    elif isinstance(payload_raw, Mapping):
        payload = dict(payload_raw)
    else:
        emit_metric(outcome="error", reason="validation_error", event_type=event_type)
        raise SignalingValidationError("validation_error", "payload must be an object")
    try:
        payload_size = len(json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
    except Exception as exc:
        emit_metric(outcome="error", reason="validation_error", event_type=event_type)
        raise SignalingValidationError("validation_error", "payload must be JSON-serializable") from exc
    if payload_size > MAX_SIGNALING_PAYLOAD_BYTES:
        emit_metric(outcome="error", reason="validation_error", event_type=event_type)
        raise SignalingValidationError("validation_error", "payload exceeds maximum allowed size")

    ts = int(now_ts())
    event_item = {
        "user_id": recipient_user_id,
        "event_id": event_id,
        "type": event_type,
        "payload": payload,
        "created_at": ts,
        "conversation_id": conversation_id,
        "sender_id": sender_user_id,
        "call_id": call_id,
        "read": False,
        "ttl": ts + 7 * 24 * 3600,
    }

    writer = put_item or _events_table().put_item
    try:
        writer(Item=event_item, ConditionExpression="attribute_not_exists(event_id)")
        status = "delivered"
    except Exception as exc:
        if _is_conditional_write_conflict(exc):
            logger.info(
                "messaging.call.signaling_delivery_duplicate",
                extra={
                    "event_id": event_id,
                    "call_id": call_id,
                    "conversation_id": conversation_id,
                    "recipient_user_id": recipient_user_id,
                    "event_type": event_type,
                },
            )
            emit_metric(outcome="success", reason="duplicate", event_type=event_type)
            return SignalingAck(
                event_id=event_id,
                call_id=call_id,
                conversation_id=conversation_id,
                event_type=event_type,
                delivered_to=recipient_user_id,
                status="duplicate",
            )
        emit_metric(outcome="error", reason="delivery_failed", event_type=event_type)
        logger.exception(
            "messaging.call.signaling_delivery_failed",
            extra={
                "event_id": event_id,
                "call_id": call_id,
                "conversation_id": conversation_id,
                "recipient_user_id": recipient_user_id,
                "event_type": event_type,
                "error": str(exc),
            },
        )
        raise SignalingValidationError("delivery_failed", "failed to deliver signaling event") from exc

    logger.info(
        "messaging.call.signaling_delivered",
        extra={
            "event_id": event_id,
            "call_id": call_id,
            "conversation_id": conversation_id,
            "recipient_user_id": recipient_user_id,
            "event_type": event_type,
            "status": status,
        },
    )
    emit_metric(outcome="success", reason="delivered", event_type=event_type)

    return SignalingAck(
        event_id=event_id,
        call_id=call_id,
        conversation_id=conversation_id,
        event_type=event_type,
        delivered_to=recipient_user_id,
        status=status,
    )


__all__ = ["route_signaling_event", "SignalingValidationError", "SignalingAck", "ALLOWED_SIGNALING_TYPES"]
