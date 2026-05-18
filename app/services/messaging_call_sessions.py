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


def _item_from_record(record: CallSessionRecord) -> dict[str, object]:
    ts = int(record.updated_at if record.updated_at is not None else now_ts())
    return {
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
    }


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
) -> CallSessionRecord:
    record = CallSessionRecord(
        call_id=call_id,
        conversation_id=conversation_id,
        caller_user_id=caller_user_id,
        callee_user_id=callee_user_id,
        initial_mode=initial_mode,
        state=state,
        start_ts=int(start_ts if start_ts is not None else now_ts()),
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
