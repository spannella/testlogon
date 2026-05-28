from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Optional

from app.core.time import now_ts

CallMode = Literal["audio", "video"]
CallState = Literal["invited", "accepted", "connected", "ended", "missed", "declined", "busy", "failed", "canceled"]
NetworkPath = Literal["p2p", "turn"]


def _table():
    from app.core.tables import T
    return T.message_call_sessions


@dataclass(frozen=True)
class CallSessionRecord:
    call_id: str
    conversation_id: str
    caller_user_id: str
    callee_user_id: str
    initial_mode: CallMode
    state: CallState
    start_ts: int
    connect_ts: Optional[int] = None
    end_ts: Optional[int] = None
    end_reason: Optional[str] = None
    network_path: Optional[NetworkPath] = None
    updated_at: Optional[int] = None
    lifecycle_events: Optional[list[dict[str, object]]] = None
    idempotency_records: Optional[dict[str, dict[str, object]]] = None
    # BCAST-011: broadcast linkage
    broadcast_session_id: str = ""
    # CALL-011 pay-per-minute billing fields
    paid: bool = False
    rate_cents_per_min: int = 0
    billing_status: str = ""
    billing_start_ts: Optional[int] = None
    last_billed_ts: Optional[int] = None
    total_billed_cents: int = 0
    total_billed_seconds: int = 0
    billing_cycle_count: int = 0
    platform_fee_bps: int = 0
    max_duration_seconds: int = 0
    caller_last_heartbeat_ts: Optional[int] = None
    callee_last_heartbeat_ts: Optional[int] = None
    # CALL-014: voicemail linkage
    voicemail_message_id: Optional[str] = None


def _item_from_record(record: CallSessionRecord) -> dict[str, object]:
    ts = int(record.updated_at if record.updated_at is not None else now_ts())
    item: dict[str, object] = {
        "call_id": record.call_id,
        "conversation_id": record.conversation_id,
        "caller_user_id": record.caller_user_id,
        "callee_user_id": record.callee_user_id,
        "initial_mode": record.initial_mode,
        "state": record.state,
        "start_ts": int(record.start_ts),
        "start_ts_sort": int(record.start_ts),
        "connect_ts": int(record.connect_ts) if record.connect_ts is not None else None,
        "end_ts": int(record.end_ts) if record.end_ts is not None else None,
        "end_reason": record.end_reason,
        "network_path": record.network_path,
        "updated_at": ts,
        "lifecycle_events": list(record.lifecycle_events or []),
        "idempotency_records": dict(record.idempotency_records or {}),
        # BCAST-011: broadcast linkage
        "broadcast_session_id": record.broadcast_session_id or "",
        # CALL-011 billing fields
        "paid": record.paid,
        "rate_cents_per_min": int(record.rate_cents_per_min),
        "billing_status": record.billing_status or "",
        "total_billed_cents": int(record.total_billed_cents),
        "total_billed_seconds": int(record.total_billed_seconds),
        "billing_cycle_count": int(record.billing_cycle_count),
        "platform_fee_bps": int(record.platform_fee_bps),
        "max_duration_seconds": int(record.max_duration_seconds),
    }
    if record.billing_start_ts is not None:
        item["billing_start_ts"] = int(record.billing_start_ts)
    if record.last_billed_ts is not None:
        item["last_billed_ts"] = int(record.last_billed_ts)
    if record.caller_last_heartbeat_ts is not None:
        item["caller_last_heartbeat_ts"] = int(record.caller_last_heartbeat_ts)
    if record.callee_last_heartbeat_ts is not None:
        item["callee_last_heartbeat_ts"] = int(record.callee_last_heartbeat_ts)
    # CALL-014: voicemail linkage
    if record.voicemail_message_id:
        item["voicemail_message_id"] = record.voicemail_message_id
    return item


def _record_from_item(item: dict[str, object]) -> CallSessionRecord:
    return CallSessionRecord(
        call_id=str(item.get("call_id") or ""),
        conversation_id=str(item.get("conversation_id") or ""),
        caller_user_id=str(item.get("caller_user_id") or ""),
        callee_user_id=str(item.get("callee_user_id") or ""),
        initial_mode=str(item.get("initial_mode") or "audio"),
        state=str(item.get("state") or "invited"),
        start_ts=int(item.get("start_ts") or 0),
        connect_ts=int(item["connect_ts"]) if item.get("connect_ts") is not None else None,
        end_ts=int(item["end_ts"]) if item.get("end_ts") is not None else None,
        end_reason=str(item.get("end_reason")) if item.get("end_reason") is not None else None,
        network_path=str(item.get("network_path")) if item.get("network_path") is not None else None,
        updated_at=int(item.get("updated_at") or 0),
        lifecycle_events=list(item.get("lifecycle_events") or []),
        idempotency_records=dict(item.get("idempotency_records") or {}),
        # BCAST-011: broadcast linkage
        broadcast_session_id=str(item.get("broadcast_session_id") or ""),
        # CALL-011 billing fields
        paid=bool(item.get("paid", False)),
        rate_cents_per_min=int(item.get("rate_cents_per_min") or 0),
        billing_status=str(item.get("billing_status") or ""),
        billing_start_ts=int(item["billing_start_ts"]) if item.get("billing_start_ts") is not None else None,
        last_billed_ts=int(item["last_billed_ts"]) if item.get("last_billed_ts") is not None else None,
        total_billed_cents=int(item.get("total_billed_cents") or 0),
        total_billed_seconds=int(item.get("total_billed_seconds") or 0),
        billing_cycle_count=int(item.get("billing_cycle_count") or 0),
        platform_fee_bps=int(item.get("platform_fee_bps") or 0),
        max_duration_seconds=int(item.get("max_duration_seconds") or 0),
        caller_last_heartbeat_ts=int(item["caller_last_heartbeat_ts"]) if item.get("caller_last_heartbeat_ts") is not None else None,
        callee_last_heartbeat_ts=int(item["callee_last_heartbeat_ts"]) if item.get("callee_last_heartbeat_ts") is not None else None,
        # CALL-014: voicemail linkage
        voicemail_message_id=str(item["voicemail_message_id"]) if item.get("voicemail_message_id") else None,
    )


def create_call_session(
    *,
    call_id: str,
    conversation_id: str,
    caller_user_id: str,
    callee_user_id: str,
    initial_mode: CallMode,
    state: CallState = "invited",
    start_ts: Optional[int] = None,
    paid: bool = False,
    rate_cents_per_min: int = 0,
    max_duration_seconds: int = 0,
    broadcast_session_id: str = "",
) -> CallSessionRecord:
    record = CallSessionRecord(
        call_id=call_id,
        conversation_id=conversation_id,
        caller_user_id=caller_user_id,
        callee_user_id=callee_user_id,
        initial_mode=initial_mode,
        state=state,
        start_ts=int(start_ts if start_ts is not None else now_ts()),
        paid=paid,
        rate_cents_per_min=rate_cents_per_min,
        max_duration_seconds=max_duration_seconds,
        broadcast_session_id=broadcast_session_id,
    )
    item = _item_from_record(record)
    _table().put_item(Item=item)
    return _record_from_item(item)


def get_call_session(call_id: str) -> Optional[CallSessionRecord]:
    item = _table().get_item(Key={"call_id": call_id}).get("Item")
    if not item:
        return None
    return _record_from_item(item)


def update_call_session_state(
    *,
    call_id: str,
    state: CallState,
    connect_ts: Optional[int] = None,
    end_ts: Optional[int] = None,
    end_reason: Optional[str] = None,
    network_path: Optional[NetworkPath] = None,
    lifecycle_event: Optional[dict[str, object]] = None,
    idempotency_entry: Optional[tuple[str, dict[str, object]]] = None,
) -> Optional[CallSessionRecord]:
    existing = get_call_session(call_id)
    if not existing:
        return None

    event_log = list(existing.lifecycle_events or [])
    if lifecycle_event:
        event_log.append(dict(lifecycle_event))
    idempotency_records = dict(existing.idempotency_records or {})
    if idempotency_entry:
        idempotency_records[str(idempotency_entry[0])] = dict(idempotency_entry[1])

    item = _item_from_record(
        CallSessionRecord(
            call_id=existing.call_id,
            conversation_id=existing.conversation_id,
            caller_user_id=existing.caller_user_id,
            callee_user_id=existing.callee_user_id,
            initial_mode=existing.initial_mode,
            state=state,
            start_ts=existing.start_ts,
            connect_ts=connect_ts if connect_ts is not None else existing.connect_ts,
            end_ts=end_ts if end_ts is not None else existing.end_ts,
            end_reason=end_reason if end_reason is not None else existing.end_reason,
            network_path=network_path if network_path is not None else existing.network_path,
            lifecycle_events=event_log,
            idempotency_records=idempotency_records,
            # BCAST-011: preserve broadcast linkage
            broadcast_session_id=existing.broadcast_session_id,
            # CALL-011: preserve billing fields
            paid=existing.paid,
            rate_cents_per_min=existing.rate_cents_per_min,
            billing_status=existing.billing_status,
            billing_start_ts=existing.billing_start_ts,
            last_billed_ts=existing.last_billed_ts,
            total_billed_cents=existing.total_billed_cents,
            total_billed_seconds=existing.total_billed_seconds,
            billing_cycle_count=existing.billing_cycle_count,
            platform_fee_bps=existing.platform_fee_bps,
            max_duration_seconds=existing.max_duration_seconds,
            caller_last_heartbeat_ts=existing.caller_last_heartbeat_ts,
            callee_last_heartbeat_ts=existing.callee_last_heartbeat_ts,
            # CALL-014: preserve voicemail linkage
            voicemail_message_id=existing.voicemail_message_id,
        )
    )
    _table().put_item(Item=item)
    return _record_from_item(item)


def set_voicemail_message_id(*, call_id: str, voicemail_message_id: str) -> Optional[CallSessionRecord]:
    """Set the voicemail_message_id on a call session record (CALL-014).

    Uses a full read-modify-write to link a voicemail message to a call.
    Idempotent: if already linked, returns existing record.
    """
    existing = get_call_session(call_id)
    if not existing:
        return None
    if existing.voicemail_message_id:
        return existing  # already linked, idempotent

    item = _item_from_record(
        CallSessionRecord(
            call_id=existing.call_id,
            conversation_id=existing.conversation_id,
            caller_user_id=existing.caller_user_id,
            callee_user_id=existing.callee_user_id,
            initial_mode=existing.initial_mode,
            state=existing.state,
            start_ts=existing.start_ts,
            connect_ts=existing.connect_ts,
            end_ts=existing.end_ts,
            end_reason=existing.end_reason,
            network_path=existing.network_path,
            lifecycle_events=existing.lifecycle_events,
            idempotency_records=existing.idempotency_records,
            broadcast_session_id=existing.broadcast_session_id,
            paid=existing.paid,
            rate_cents_per_min=existing.rate_cents_per_min,
            billing_status=existing.billing_status,
            billing_start_ts=existing.billing_start_ts,
            last_billed_ts=existing.last_billed_ts,
            total_billed_cents=existing.total_billed_cents,
            total_billed_seconds=existing.total_billed_seconds,
            billing_cycle_count=existing.billing_cycle_count,
            platform_fee_bps=existing.platform_fee_bps,
            max_duration_seconds=existing.max_duration_seconds,
            caller_last_heartbeat_ts=existing.caller_last_heartbeat_ts,
            callee_last_heartbeat_ts=existing.callee_last_heartbeat_ts,
            voicemail_message_id=voicemail_message_id,
        )
    )
    _table().put_item(Item=item)
    return _record_from_item(item)


def list_call_sessions_for_conversation(conversation_id: str, *, limit: int = 50) -> list[CallSessionRecord]:
    resp = _table().query(
        IndexName="ByConversationStartedAt",
        KeyConditionExpression="conversation_id = :conversation_id",
        ExpressionAttributeValues={":conversation_id": conversation_id},
        ScanIndexForward=False,
        Limit=int(limit),
    )
    return [_record_from_item(item) for item in (resp.get("Items") or [])]
