from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional

from app.core.time import now_ts
from app.metrics import (
    record_webrtc_call_duration,
    record_webrtc_call_connected,
    record_webrtc_call_failure,
    record_webrtc_call_setup,
)
from app.services.messaging_call_timeline import emit_call_timeline_event
from app.services.messaging_call_sessions import (
    CallSessionRecord,
    create_call_session,
    get_call_session,
    list_call_sessions_for_conversation,
    update_call_session_state,
)


TERMINAL_STATES = {"declined", "busy", "missed", "ended", "failed", "canceled"}
ALLOWED_TRANSITIONS = {
    "invited": {"accepted", "declined", "busy", "canceled", "failed", "missed"},
    "accepted": {"connected", "ended", "failed", "canceled"},
    "connected": {"ended", "failed"},
}


@dataclass(frozen=True)
class LifecycleEvent:
    call_id: str
    conversation_id: str
    actor_user_id: str
    event_type: str
    from_state: Optional[str]
    to_state: str
    event_ts: int
    reason: Optional[str] = None


class CallLifecycleError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _load_conversation_participants(conversation_id: str) -> set[str]:
    from app.core.aws import ddb

    table_name = "Conversations"
    row = ddb.Table(table_name).get_item(Key={"conversation_id": conversation_id}).get("Item") or {}
    members = row.get("participant_ids") or []
    return {str(m).strip() for m in members if str(m).strip()}


def _ensure_participant(*, user_id: str, participants: set[str]) -> None:
    if user_id not in participants:
        raise CallLifecycleError("forbidden", "user is not a conversation participant")


def _build_event(
    *,
    record: CallSessionRecord,
    actor_user_id: str,
    event_type: str,
    from_state: Optional[str],
    to_state: str,
    reason: Optional[str],
) -> LifecycleEvent:
    return LifecycleEvent(
        call_id=record.call_id,
        conversation_id=record.conversation_id,
        actor_user_id=actor_user_id,
        event_type=event_type,
        from_state=from_state,
        to_state=to_state,
        reason=reason,
        event_ts=int(now_ts()),
    )


def _check_transition(current_state: str, next_state: str) -> None:
    if current_state in TERMINAL_STATES:
        raise CallLifecycleError("invalid_state_transition", f"call already terminal: {current_state}")
    if next_state not in ALLOWED_TRANSITIONS.get(current_state, set()):
        raise CallLifecycleError("invalid_state_transition", f"cannot transition {current_state} -> {next_state}")


def _idempotent_entry(*, action: str, event: LifecycleEvent) -> dict[str, object]:
    return {
        "action": action,
        "event_type": event.event_type,
        "to_state": event.to_state,
        "event_ts": int(event.event_ts),
        "reason": event.reason,
    }


def _dedupe_if_retried(
    *,
    record: Optional[CallSessionRecord],
    idempotency_key: Optional[str],
    action: str,
) -> Optional[tuple[CallSessionRecord, LifecycleEvent]]:
    if not idempotency_key or not record:
        return None
    entry = (record.idempotency_records or {}).get(idempotency_key)
    if not isinstance(entry, dict):
        return None
    if str(entry.get("action") or "") != action:
        raise CallLifecycleError("idempotency_conflict", "idempotency key reused for different action")

    event = LifecycleEvent(
        call_id=record.call_id,
        conversation_id=record.conversation_id,
        actor_user_id=record.caller_user_id,
        event_type=str(entry.get("event_type") or action),
        from_state=record.state,
        to_state=str(entry.get("to_state") or record.state),
        event_ts=int(entry.get("event_ts") or now_ts()),
        reason=str(entry.get("reason")) if entry.get("reason") is not None else None,
    )
    return record, event


def create_invite(
    *,
    call_id: str,
    conversation_id: str,
    actor_user_id: str,
    caller_user_id: str,
    callee_user_id: str,
    initial_mode: str,
    participant_resolver: Callable[[str], set[str]] = _load_conversation_participants,
    idempotency_key: Optional[str] = None,
    client_platform: str = "unknown",
    client_browser: str = "unknown",
    timeline_emitter: Callable[..., dict[str, object]] = emit_call_timeline_event,
) -> tuple[CallSessionRecord, LifecycleEvent]:
    participants = participant_resolver(conversation_id)
    _ensure_participant(user_id=caller_user_id, participants=participants)
    _ensure_participant(user_id=callee_user_id, participants=participants)
    if actor_user_id != caller_user_id:
        raise CallLifecycleError("forbidden", "only caller can create invite")

    active_states = {"invited", "accepted", "connected"}
    recent_sessions = list_call_sessions_for_conversation(conversation_id, limit=25)
    for session in recent_sessions:
        if session.call_id == call_id:
            continue
        if session.state not in active_states:
            continue
        participants = {session.caller_user_id, session.callee_user_id}
        if callee_user_id in participants:
            raise CallLifecycleError("callee_busy", "callee is already on an active call")
        if caller_user_id in participants:
            raise CallLifecycleError("caller_busy", "caller is already on an active call")

    existing = get_call_session(call_id)
    deduped = _dedupe_if_retried(record=existing, idempotency_key=idempotency_key, action="create_invite")
    if deduped:
        return deduped
    if existing:
        raise CallLifecycleError("duplicate_call_id", "call_id already exists")

    record = create_call_session(
        call_id=call_id,
        conversation_id=conversation_id,
        caller_user_id=caller_user_id,
        callee_user_id=callee_user_id,
        initial_mode=initial_mode,  # type: ignore[arg-type]
        state="invited",  # type: ignore[arg-type]
    )
    event = _build_event(
        record=record,
        actor_user_id=actor_user_id,
        event_type="call.invite",
        from_state=None,
        to_state="invited",
        reason=None,
    )
    updated = update_call_session_state(
        call_id=call_id,
        state="invited",  # type: ignore[arg-type]
        lifecycle_event=event.__dict__,
        idempotency_entry=(idempotency_key, _idempotent_entry(action="create_invite", event=event))
        if idempotency_key
        else None,
    )
    committed = (updated or record)
    record_webrtc_call_setup(
        outcome="attempt",
        reason="invite_created",
        platform=client_platform,
        browser=client_browser,
    )
    timeline_emitter(
        call_id=committed.call_id,
        conversation_id=committed.conversation_id,
        actor_user_id=actor_user_id,
        event_type=event.event_type,
        call_state=event.to_state,
        reason=event.reason,
        event_ts=event.event_ts,
    )
    return committed, event


def accept_invite(
    *,
    call_id: str,
    actor_user_id: str,
    idempotency_key: Optional[str] = None,
    client_platform: str = "unknown",
    client_browser: str = "unknown",
    timeline_emitter: Callable[..., dict[str, object]] = emit_call_timeline_event,
) -> tuple[CallSessionRecord, LifecycleEvent]:
    record = get_call_session(call_id)
    if not record:
        raise CallLifecycleError("call_not_found", "call session not found")
    deduped = _dedupe_if_retried(record=record, idempotency_key=idempotency_key, action="accept_invite")
    if deduped:
        return deduped
    if actor_user_id != record.callee_user_id:
        record_webrtc_call_failure(reason="forbidden_actor", stage="accept", platform=client_platform, browser=client_browser)
        raise CallLifecycleError("forbidden", "only callee can accept invite")

    _check_transition(record.state, "accepted")
    event = _build_event(
        record=record,
        actor_user_id=actor_user_id,
        event_type="call.accept",
        from_state=record.state,
        to_state="accepted",
        reason=None,
    )
    updated = update_call_session_state(
        call_id=call_id,
        state="accepted",  # type: ignore[arg-type]
        lifecycle_event=event.__dict__,
        idempotency_entry=(idempotency_key, _idempotent_entry(action="accept_invite", event=event))
        if idempotency_key
        else None,
    )
    if not updated:
        record_webrtc_call_failure(reason="call_not_found", stage="accept_update", platform=client_platform, browser=client_browser)
        raise CallLifecycleError("call_not_found", "call session not found during update")
    record_webrtc_call_setup(
        outcome="success",
        reason="accepted",
        platform=client_platform,
        browser=client_browser,
        latency_seconds=max(0.0, float(int(now_ts()) - int(updated.start_ts))),
    )
    timeline_emitter(
        call_id=updated.call_id,
        conversation_id=updated.conversation_id,
        actor_user_id=actor_user_id,
        event_type=event.event_type,
        call_state=event.to_state,
        reason=event.reason,
        event_ts=event.event_ts,
    )
    return updated, event


def decline_invite(
    *,
    call_id: str,
    actor_user_id: str,
    reason: str = "declined",
    client_platform: str = "unknown",
    client_browser: str = "unknown",
    timeline_emitter: Callable[..., dict[str, object]] = emit_call_timeline_event,
) -> tuple[CallSessionRecord, LifecycleEvent]:
    record = get_call_session(call_id)
    if not record:
        raise CallLifecycleError("call_not_found", "call session not found")
    if actor_user_id != record.callee_user_id:
        record_webrtc_call_failure(reason="forbidden_actor", stage="decline", platform=client_platform, browser=client_browser)
        raise CallLifecycleError("forbidden", "only callee can decline invite")

    next_state = "busy" if reason == "busy" else "declined"
    _check_transition(record.state, next_state)
    event = _build_event(
        record=record,
        actor_user_id=actor_user_id,
        event_type="call.decline",
        from_state=record.state,
        to_state=next_state,
        reason=reason,
    )
    updated = update_call_session_state(
        call_id=call_id,
        state=next_state,  # type: ignore[arg-type]
        end_reason=reason,
        end_ts=int(now_ts()),
        lifecycle_event=event.__dict__,
    )
    if not updated:
        record_webrtc_call_failure(reason="call_not_found", stage="decline_update", platform=client_platform, browser=client_browser)
        raise CallLifecycleError("call_not_found", "call session not found during update")
    record_webrtc_call_setup(
        outcome="failure",
        reason=reason or next_state,
        platform=client_platform,
        browser=client_browser,
        latency_seconds=max(0.0, float(int(now_ts()) - int(updated.start_ts))),
    )
    timeline_emitter(
        call_id=updated.call_id,
        conversation_id=updated.conversation_id,
        actor_user_id=actor_user_id,
        event_type=event.event_type,
        call_state=event.to_state,
        reason=event.reason,
        event_ts=event.event_ts,
    )
    return updated, event


def end_call(
    *,
    call_id: str,
    actor_user_id: str,
    reason: str = "ended",
    idempotency_key: Optional[str] = None,
    client_platform: str = "unknown",
    client_browser: str = "unknown",
    timeline_emitter: Callable[..., dict[str, object]] = emit_call_timeline_event,
) -> tuple[CallSessionRecord, LifecycleEvent]:
    record = get_call_session(call_id)
    if not record:
        raise CallLifecycleError("call_not_found", "call session not found")
    deduped = _dedupe_if_retried(record=record, idempotency_key=idempotency_key, action="end_call")
    if deduped:
        return deduped
    if actor_user_id not in {record.caller_user_id, record.callee_user_id}:
        record_webrtc_call_failure(reason="forbidden_actor", stage="end", platform=client_platform, browser=client_browser)
        raise CallLifecycleError("forbidden", "only call participants can end call")

    next_state = "ended" if record.state in {"connected", "accepted"} else "canceled"
    _check_transition(record.state, next_state)
    event = _build_event(
        record=record,
        actor_user_id=actor_user_id,
        event_type="call.end",
        from_state=record.state,
        to_state=next_state,
        reason=reason,
    )
    updated = update_call_session_state(
        call_id=call_id,
        state=next_state,  # type: ignore[arg-type]
        end_reason=reason,
        end_ts=int(now_ts()),
        lifecycle_event=event.__dict__,
        idempotency_entry=(idempotency_key, _idempotent_entry(action="end_call", event=event))
        if idempotency_key
        else None,
    )
    if not updated:
        record_webrtc_call_failure(reason="call_not_found", stage="end_update", platform=client_platform, browser=client_browser)
        raise CallLifecycleError("call_not_found", "call session not found during update")
    if updated.connect_ts is not None and updated.end_ts is not None:
        record_webrtc_call_connected(network_path=updated.network_path or "unknown")
        record_webrtc_call_duration(
            duration_seconds=max(0.0, float(updated.end_ts - updated.connect_ts)),
            end_reason=reason or next_state,
            network_path=updated.network_path or "unknown",
        )
    timeline_emitter(
        call_id=updated.call_id,
        conversation_id=updated.conversation_id,
        actor_user_id=actor_user_id,
        event_type=event.event_type,
        call_state=event.to_state,
        reason=event.reason,
        event_ts=event.event_ts,
    )
    return updated, event


def timeout_call(
    *,
    call_id: str,
    actor_user_id: str,
    reason: str = "no_answer",
    idempotency_key: Optional[str] = None,
    timeline_emitter: Callable[..., dict[str, object]] = emit_call_timeline_event,
) -> tuple[CallSessionRecord, LifecycleEvent]:
    """Transition an invited call to missed (ringing timeout)."""
    record = get_call_session(call_id)
    if not record:
        raise CallLifecycleError("call_not_found", "call session not found")
    deduped = _dedupe_if_retried(record=record, idempotency_key=idempotency_key, action="timeout_call")
    if deduped:
        return deduped
    # Only the caller or "system" (server background job) can timeout a call
    if actor_user_id not in {record.caller_user_id, "system"}:
        raise CallLifecycleError("forbidden", "only caller or system can timeout a call")

    _check_transition(record.state, "missed")
    event = _build_event(
        record=record,
        actor_user_id=actor_user_id,
        event_type="call.missed",
        from_state=record.state,
        to_state="missed",
        reason=reason,
    )
    updated = update_call_session_state(
        call_id=call_id,
        state="missed",  # type: ignore[arg-type]
        end_reason=reason,
        end_ts=int(now_ts()),
        lifecycle_event=event.__dict__,
        idempotency_entry=(idempotency_key, _idempotent_entry(action="timeout_call", event=event))
        if idempotency_key
        else None,
    )
    if not updated:
        raise CallLifecycleError("call_not_found", "call session not found during update")
    timeline_emitter(
        call_id=updated.call_id,
        conversation_id=updated.conversation_id,
        actor_user_id=actor_user_id,
        event_type=event.event_type,
        call_state=event.to_state,
        reason=event.reason,
        event_ts=event.event_ts,
    )
    return updated, event


__all__ = [
    "CallLifecycleError",
    "LifecycleEvent",
    "create_invite",
    "accept_invite",
    "decline_invite",
    "end_call",
    "timeout_call",
]
