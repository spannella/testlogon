from __future__ import annotations

from enum import Enum
from typing import Any


class DestinationState(str, Enum):
    PENDING = "pending"
    SENT = "sent"
    FAILED = "failed"
    SKIPPED = "skipped"
    CANCELLED = "cancelled"


ALLOWED_DESTINATION_TRANSITIONS: dict[DestinationState, set[DestinationState]] = {
    DestinationState.PENDING: {
        DestinationState.SENT,
        DestinationState.FAILED,
        DestinationState.SKIPPED,
        DestinationState.CANCELLED,
    },
    DestinationState.FAILED: {DestinationState.PENDING, DestinationState.CANCELLED},
    DestinationState.SENT: set(),
    DestinationState.SKIPPED: set(),
    DestinationState.CANCELLED: set(),
}

DESTINATION_ERROR_AUTHORIZATION = "authorization"
DESTINATION_ERROR_CONVERSATION_MISSING = "conversation_missing"
DESTINATION_ERROR_POLICY_BLOCKED = "policy_blocked"
DESTINATION_ERROR_TRANSIENT_INFRA = "transient_infra"
DESTINATION_ERROR_UNKNOWN = "unknown"
CANONICAL_DESTINATION_ERROR_CODES = {
    DESTINATION_ERROR_AUTHORIZATION,
    DESTINATION_ERROR_CONVERSATION_MISSING,
    DESTINATION_ERROR_POLICY_BLOCKED,
    DESTINATION_ERROR_TRANSIENT_INFRA,
    DESTINATION_ERROR_UNKNOWN,
}
DESTINATION_ERROR_CODE_ALIASES = {
    "authorization_denied": DESTINATION_ERROR_AUTHORIZATION,
    "conversation_not_found": DESTINATION_ERROR_CONVERSATION_MISSING,
    "send_failed": DESTINATION_ERROR_TRANSIENT_INFRA,
    "campaign_payload_invalid": DESTINATION_ERROR_UNKNOWN,
}


def parse_destination_state(value: str | DestinationState) -> DestinationState:
    if isinstance(value, DestinationState):
        return value
    try:
        return DestinationState(str(value).strip().lower())
    except ValueError as exc:
        raise ValueError("invalid destination state") from exc


def can_transition_destination_state(current_state: str | DestinationState, next_state: str | DestinationState) -> bool:
    current = parse_destination_state(current_state)
    nxt = parse_destination_state(next_state)
    return nxt in ALLOWED_DESTINATION_TRANSITIONS[current]


def validate_destination_transition(current_state: str | DestinationState, next_state: str | DestinationState) -> None:
    if not can_transition_destination_state(current_state, next_state):
        raise ValueError("invalid destination state transition")


def campaign_state_key(*, campaign_id: str, state: str | DestinationState) -> str:
    normalized = parse_destination_state(state).value
    return f"{campaign_id}#{normalized}"


def destination_idempotency_key(*, campaign_id: str, conversation_id: str) -> str:
    return f"{campaign_id}:{conversation_id}"


def normalize_destination_error_code(*, state: str | DestinationState, error_code: str | None) -> str | None:
    normalized_state = parse_destination_state(state)
    if normalized_state is not DestinationState.FAILED:
        return None
    raw = str(error_code or "").strip().lower()
    if not raw:
        return DESTINATION_ERROR_UNKNOWN
    normalized = DESTINATION_ERROR_CODE_ALIASES.get(raw, raw)
    if normalized in CANONICAL_DESTINATION_ERROR_CODES:
        return normalized
    return DESTINATION_ERROR_UNKNOWN


def build_destination_metadata(
    *,
    campaign_id: str,
    conversation_id: str,
    state: str | DestinationState,
    message_id: str | None = None,
    error_code: str | None = None,
    attempt_count: int | None = None,
    updated_at: int | None = None,
    created_at: int | None = None,
    idempotency_key: str | None = None,
) -> dict[str, Any]:
    normalized = parse_destination_state(state)
    attempts = int(attempt_count or 0)
    normalized_error_code = normalize_destination_error_code(state=normalized, error_code=error_code)
    return {
        "campaign_id": campaign_id,
        "conversation_id": conversation_id,
        "state": normalized.value,
        "message_id": message_id,
        "error_code": normalized_error_code,
        "attempt_count": attempts,
        "updated_at": updated_at,
        "created_at": created_at,
        "campaign_state": campaign_state_key(campaign_id=campaign_id, state=normalized),
        "idempotency_key": idempotency_key or destination_idempotency_key(
            campaign_id=campaign_id,
            conversation_id=conversation_id,
        ),
    }
