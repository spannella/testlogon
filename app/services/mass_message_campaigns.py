from __future__ import annotations

import time
import uuid
from typing import Any
import hashlib

from app.services.mass_message_campaign_contract import (
    ALLOWED_STATUS_TRANSITIONS as _ALLOWED_STATUS_TRANSITIONS,
    CampaignMode,
    CampaignStatus,
    can_transition_status as _can_transition_status,
    parse_campaign_mode,
    parse_campaign_status,
    validate_status_transition,
)
from app.services.mass_message_destination_contract import DestinationState, parse_destination_state

VALID_MODES = {m.value for m in CampaignMode}
VALID_STATUSES = {s.value for s in CampaignStatus}
ALLOWED_STATUS_TRANSITIONS: dict[str, set[str]] = {
    status.value: {n.value for n in next_states}
    for status, next_states in _ALLOWED_STATUS_TRANSITIONS.items()
}
COUNTER_FIELDS = ("total", "queued", "sent", "failed", "cancelled")
DESTINATION_STATE_TO_COUNTER_FIELD = {
    DestinationState.PENDING.value: "queued",
    DestinationState.SENT.value: "sent",
    DestinationState.FAILED.value: "failed",
    DestinationState.CANCELLED.value: "cancelled",
}


def _is_conditional_check_failed(exc: Exception) -> bool:
    response = getattr(exc, "response", None)
    if not isinstance(response, dict):
        return False
    return response.get("Error", {}).get("Code") == "ConditionalCheckFailedException"


def _campaigns_table():
    from app.core.tables import T

    return T.mass_message_campaigns


def _require_non_empty(value: str, field_name: str) -> str:
    cleaned = str(value or "").strip()
    if not cleaned:
        raise ValueError(f"{field_name} required")
    return cleaned


def _now_ts() -> int:
    return int(time.time())


def _counter_field_for_destination_state(state: str | None) -> str | None:
    if state is None:
        return None
    normalized = parse_destination_state(state).value
    return DESTINATION_STATE_TO_COUNTER_FIELD.get(normalized)


def _initial_status_for_mode(mode: str) -> str:
    parsed_mode = parse_campaign_mode(mode)
    if parsed_mode is CampaignMode.IMMEDIATE:
        return CampaignStatus.PENDING.value
    if parsed_mode is CampaignMode.SCHEDULED:
        return CampaignStatus.SCHEDULED.value
    raise ValueError("invalid mode")


def can_transition_status(current_status: str, next_status: str) -> bool:
    try:
        return _can_transition_status(current_status, next_status)
    except ValueError:
        return False


def create_campaign(
    *,
    sender_id: str,
    mode: str,
    payload_hash: str,
    send_at: int | None = None,
    campaign_id: str | None = None,
    created_at: int | None = None,
    idempotency_key: str | None = None,
    content_kind: str | None = None,
    content_text: str | None = None,
) -> dict[str, Any]:
    sender_id = _require_non_empty(sender_id, "sender_id")
    payload_hash = _require_non_empty(payload_hash, "payload_hash")

    parsed_mode = parse_campaign_mode(mode)
    if parsed_mode is CampaignMode.IMMEDIATE and send_at is not None:
        raise ValueError("immediate mode does not support send_at")
    if parsed_mode is CampaignMode.SCHEDULED and (send_at is None or send_at <= 0):
        raise ValueError("scheduled mode requires positive send_at")

    ts = int(created_at or _now_ts())
    cid = campaign_id or f"mmc_{uuid.uuid4().hex}"
    normalized_mode = parsed_mode.value
    status = _initial_status_for_mode(normalized_mode)

    item: dict[str, Any] = {
        "campaign_id": cid,
        "sender_id": sender_id,
        "mode": normalized_mode,
        "status": status,
        "payload_hash": payload_hash,
        "created_at": ts,
        "updated_at": ts,
        "queued": 0,
        "sent": 0,
        "failed": 0,
        "cancelled": 0,
        "total": 0,
    }
    if idempotency_key:
        item["idempotency_key"] = str(idempotency_key)
    if send_at is not None:
        item["send_at"] = int(send_at)
    if content_kind is not None:
        item["content_kind"] = str(content_kind)
    if content_text is not None:
        item["content_text"] = str(content_text)

    _campaigns_table().put_item(
        Item=item,
        ConditionExpression="attribute_not_exists(campaign_id)",
    )
    return item


def campaign_id_from_idempotency(*, sender_id: str, idempotency_key: str) -> str:
    seed = f"{sender_id}:{idempotency_key}".encode("utf-8")
    digest = hashlib.sha256(seed).hexdigest()[:32]
    return f"mmc_idm_{digest}"


def create_or_get_campaign(
    *,
    sender_id: str,
    mode: str,
    payload_hash: str,
    send_at: int | None = None,
    idempotency_key: str | None = None,
    created_at: int | None = None,
    content_kind: str | None = None,
    content_text: str | None = None,
) -> tuple[dict[str, Any], bool]:
    if not idempotency_key:
        return (
            create_campaign(
                sender_id=sender_id,
                mode=mode,
                payload_hash=payload_hash,
                send_at=send_at,
                created_at=created_at,
                content_kind=content_kind,
                content_text=content_text,
            ),
            True,
        )

    campaign_id = campaign_id_from_idempotency(sender_id=sender_id, idempotency_key=idempotency_key)
    try:
        created = create_campaign(
            sender_id=sender_id,
            mode=mode,
            payload_hash=payload_hash,
            send_at=send_at,
            campaign_id=campaign_id,
            created_at=created_at,
            idempotency_key=idempotency_key,
            content_kind=content_kind,
            content_text=content_text,
        )
        return created, True
    except Exception as exc:
        if not _is_conditional_check_failed(exc):
            raise
        existing = get_campaign(campaign_id)
        if not existing:
            raise ValueError("idempotent campaign lookup failed") from exc
        return existing, False


def get_campaign(campaign_id: str) -> dict[str, Any] | None:
    campaign_id = _require_non_empty(campaign_id, "campaign_id")
    resp = _campaigns_table().get_item(Key={"campaign_id": campaign_id})
    return resp.get("Item")


def list_due_scheduled_campaigns(*, now_ts: int | None = None, limit: int = 100) -> list[dict[str, Any]]:
    ts = int(now_ts or _now_ts())
    safe_limit = max(1, min(int(limit), 500))
    resp = _campaigns_table().query(
        IndexName="ByStatusSendAt",
        KeyConditionExpression="status = :status AND send_at <= :send_at",
        ExpressionAttributeValues={
            ":status": CampaignStatus.SCHEDULED.value,
            ":send_at": ts,
        },
        Limit=safe_limit,
        ScanIndexForward=True,
    )
    return list(resp.get("Items", []))


def list_campaigns_for_sender(
    *,
    sender_id: str,
    limit: int = 50,
    start_key: dict[str, Any] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    sender_id = _require_non_empty(sender_id, "sender_id")
    safe_limit = max(1, min(int(limit), 200))
    query_kwargs: dict[str, Any] = {
        "IndexName": "BySenderCreatedAt",
        "KeyConditionExpression": "sender_id = :sender_id",
        "ExpressionAttributeValues": {
            ":sender_id": sender_id,
        },
        "Limit": safe_limit,
        "ScanIndexForward": False,
    }
    if start_key:
        query_kwargs["ExclusiveStartKey"] = start_key
    resp = _campaigns_table().query(**query_kwargs)
    return list(resp.get("Items", [])), resp.get("LastEvaluatedKey")


def update_campaign_status(
    *,
    campaign_id: str,
    next_status: str,
    expected_status: str | None = None,
    expected_updated_at: int | None = None,
    now_ts: int | None = None,
) -> dict[str, Any]:
    campaign_id = _require_non_empty(campaign_id, "campaign_id")
    try:
        normalized_next_status = parse_campaign_status(next_status).value
    except ValueError as exc:
        raise ValueError("invalid next status") from exc

    existing = get_campaign(campaign_id)
    if not existing:
        raise KeyError("campaign not found")

    current_status = str(existing.get("status") or "")
    parse_campaign_status(current_status)  # deterministic rejection if stored value is invalid
    if expected_status is not None and current_status != expected_status:
        raise ValueError("campaign status changed")
    validate_status_transition(current_status, normalized_next_status)

    ts = int(now_ts or _now_ts())
    try:
        condition_expr = "#status = :current_status"
        expr_values = {
            ":current_status": current_status,
            ":next_status": normalized_next_status,
            ":updated_at": ts,
        }
        if expected_updated_at is not None:
            condition_expr += " AND #updated_at = :expected_updated_at"
            expr_values[":expected_updated_at"] = int(expected_updated_at)

        resp = _campaigns_table().update_item(
            Key={"campaign_id": campaign_id},
            ConditionExpression=condition_expr,
            UpdateExpression="SET #status = :next_status, #updated_at = :updated_at",
            ExpressionAttributeNames={
                "#status": "status",
                "#updated_at": "updated_at",
            },
            ExpressionAttributeValues=expr_values,
            ReturnValues="ALL_NEW",
        )
    except Exception as exc:
        if _is_conditional_check_failed(exc):
            if expected_updated_at is not None:
                raise ValueError("campaign version changed") from exc
            raise ValueError("campaign status changed") from exc
        raise
    return resp.get("Attributes", {})


def apply_destination_counter_delta(
    *,
    campaign_id: str,
    to_state: str,
    from_state: str | None = None,
    now_ts: int | None = None,
) -> dict[str, Any]:
    """Atomically update campaign aggregate counters from a destination state change."""
    campaign_id = _require_non_empty(campaign_id, "campaign_id")
    to_field = _counter_field_for_destination_state(to_state)
    from_field = _counter_field_for_destination_state(from_state)

    if from_field is not None and from_field == to_field:
        return {}

    ts = int(now_ts or _now_ts())
    names = {"#updated_at": "updated_at"}
    values: dict[str, Any] = {":updated_at": ts}
    add_tokens: list[str] = []

    if from_state is None:
        names["#total"] = "total"
        values[":delta_total"] = 1
        add_tokens.append("#total :delta_total")

    if from_field is not None:
        names[f"#from_{from_field}"] = from_field
        values[f":delta_from_{from_field}"] = -1
        add_tokens.append(f"#from_{from_field} :delta_from_{from_field}")

    if to_field is not None:
        names[f"#to_{to_field}"] = to_field
        values[f":delta_to_{to_field}"] = 1
        add_tokens.append(f"#to_{to_field} :delta_to_{to_field}")

    if not add_tokens:
        return {}

    update_expression = "SET #updated_at = :updated_at ADD " + ", ".join(add_tokens)
    resp = _campaigns_table().update_item(
        Key={"campaign_id": campaign_id},
        UpdateExpression=update_expression,
        ExpressionAttributeNames=names,
        ExpressionAttributeValues=values,
        ReturnValues="ALL_NEW",
    )
    return resp.get("Attributes", {})


def build_counter_totals_from_destinations(destinations: list[dict[str, Any]]) -> dict[str, int]:
    totals = {field: 0 for field in COUNTER_FIELDS}
    for row in destinations:
        totals["total"] += 1
        state = parse_destination_state(str(row.get("state", DestinationState.PENDING.value))).value
        counter_field = DESTINATION_STATE_TO_COUNTER_FIELD.get(state)
        if counter_field:
            totals[counter_field] += 1
    return totals


def set_campaign_submission_result(
    *,
    campaign_id: str,
    accepted_conversation_ids: list[str],
    rejected: list[dict[str, Any]],
) -> dict[str, Any]:
    campaign_id = _require_non_empty(campaign_id, "campaign_id")
    resp = _campaigns_table().update_item(
        Key={"campaign_id": campaign_id},
        UpdateExpression="SET #accepted = :accepted, #rejected = :rejected, #updated_at = :updated_at",
        ExpressionAttributeNames={
            "#accepted": "accepted_conversation_ids",
            "#rejected": "rejected_destinations",
            "#updated_at": "updated_at",
        },
        ExpressionAttributeValues={
            ":accepted": accepted_conversation_ids,
            ":rejected": rejected,
            ":updated_at": _now_ts(),
        },
        ReturnValues="ALL_NEW",
    )
    return resp.get("Attributes", {})
