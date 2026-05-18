from __future__ import annotations

import time
from typing import Any

from app.services.mass_message_destination_contract import (
    ALLOWED_DESTINATION_TRANSITIONS,
    DestinationState,
    build_destination_metadata,
    campaign_state_key,
    destination_idempotency_key,
    normalize_destination_error_code,
    parse_destination_state,
    validate_destination_transition,
)

VALID_DESTINATION_STATES = {state.value for state in DestinationState}
ALLOWED_DESTINATION_TRANSITIONS_EXPORT: dict[str, set[str]] = {
    state.value: {n.value for n in next_states}
    for state, next_states in ALLOWED_DESTINATION_TRANSITIONS.items()
}


def _destinations_table():
    from app.core.tables import T

    return T.mass_message_campaign_destinations


def _now_ts() -> int:
    return int(time.time())


def _normalize_record(record: dict[str, Any]) -> dict[str, Any]:
    if not record:
        return record
    return build_destination_metadata(
        campaign_id=str(record.get("campaign_id", "")),
        conversation_id=str(record.get("conversation_id", "")),
        state=str(record.get("state", DestinationState.PENDING.value)),
        message_id=record.get("message_id"),
        error_code=record.get("error_code"),
        attempt_count=int(record.get("attempt_count", 0) or 0),
        updated_at=record.get("updated_at"),
        created_at=record.get("created_at"),
        idempotency_key=record.get("idempotency_key"),
    )


def upsert_destination(
    *,
    campaign_id: str,
    conversation_id: str,
    state: str,
    message_id: str | None = None,
    error_code: str | None = None,
    updated_at: int | None = None,
) -> dict[str, Any]:
    """Create or update a destination row idempotently."""
    normalized_state = parse_destination_state(state).value
    normalized_error_code = normalize_destination_error_code(state=normalized_state, error_code=error_code)
    deterministic_idempotency_key = destination_idempotency_key(
        campaign_id=campaign_id,
        conversation_id=conversation_id,
    )

    ts = int(updated_at or _now_ts())
    existing = get_destination(campaign_id=campaign_id, conversation_id=conversation_id)
    if existing:
        current_state = str(existing.get("state") or "")
        if (
            current_state == normalized_state
            and existing.get("message_id") == message_id
            and existing.get("error_code") == normalized_error_code
            and existing.get("idempotency_key") == deterministic_idempotency_key
        ):
            # Idempotent no-op: repeated write with same key+payload should not
            # alter counters/timestamps or bump attempts.
            return existing
        validate_destination_transition(current_state, normalized_state)

    expr_names = {
        "#state": "state",
        "#message_id": "message_id",
        "#error_code": "error_code",
        "#updated_at": "updated_at",
        "#created_at": "created_at",
        "#campaign_state": "campaign_state",
        "#attempt_count": "attempt_count",
        "#idempotency_key": "idempotency_key",
    }
    expr_values: dict[str, Any] = {
        ":state": normalized_state,
        ":message_id": message_id,
        ":error_code": normalized_error_code,
        ":updated_at": ts,
        ":created_at": ts,
        ":campaign_state": campaign_state_key(campaign_id=campaign_id, state=normalized_state),
        ":attempt_count_inc": 1,
        ":idempotency_key": deterministic_idempotency_key,
    }

    resp = _destinations_table().update_item(
        Key={"campaign_id": campaign_id, "conversation_id": conversation_id},
        UpdateExpression=(
            "SET #state = :state, "
            "#message_id = :message_id, "
            "#error_code = :error_code, "
            "#campaign_state = :campaign_state, "
            "#idempotency_key = :idempotency_key, "
            "#updated_at = :updated_at, "
            "#created_at = if_not_exists(#created_at, :created_at) "
            "ADD #attempt_count :attempt_count_inc"
        ),
        ExpressionAttributeNames=expr_names,
        ExpressionAttributeValues=expr_values,
        ReturnValues="ALL_NEW",
    )
    return _normalize_record(resp.get("Attributes", {}))


def get_destination(*, campaign_id: str, conversation_id: str) -> dict[str, Any] | None:
    resp = _destinations_table().get_item(Key={"campaign_id": campaign_id, "conversation_id": conversation_id})
    item = resp.get("Item")
    if not item:
        return None
    return _normalize_record(item)


def list_destinations(*, campaign_id: str, limit: int = 100) -> list[dict[str, Any]]:
    destinations, _ = list_destinations_page(campaign_id=campaign_id, limit=limit)
    return destinations


def list_destinations_page(
    *,
    campaign_id: str,
    limit: int = 100,
    start_key: dict[str, Any] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    safe_limit = max(1, min(int(limit), 500))
    query_kwargs: dict[str, Any] = {
        "KeyConditionExpression": "campaign_id = :campaign_id",
        "ExpressionAttributeValues": {":campaign_id": campaign_id},
        "Limit": safe_limit,
        "ScanIndexForward": True,
    }
    if start_key:
        query_kwargs["ExclusiveStartKey"] = start_key
    resp = _destinations_table().query(
        **query_kwargs,
    )
    return [_normalize_record(item) for item in resp.get("Items", [])], resp.get("LastEvaluatedKey")
