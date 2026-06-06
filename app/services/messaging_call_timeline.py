from __future__ import annotations

import os
from typing import Any, Mapping, Optional

from app.core.time import now_ts


def _messages_table():
    from app.core.aws import ddb

    return ddb.Table(os.getenv("DDB_MESSAGES", "Messages"))


def _conversations_table():
    from app.core.aws import ddb

    return ddb.Table(os.getenv("DDB_CONVERSATIONS", "Conversations"))


def _preview_for_event(*, event_type: str, call_state: str, reason: Optional[str]) -> str:
    if event_type == "call.invite":
        return "Started a call"
    if event_type == "call.accept":
        return "Call accepted"
    if event_type == "call.decline":
        if reason == "busy":
            return "Call unavailable (busy)"
        return "Call declined"
    if event_type == "call.end":
        if reason:
            return f"Call ended ({reason})"
        return "Call ended"
    if event_type == "call.missed":
        return "Missed call"
    if event_type == "call.voicemail_start":
        return "Recording a voicemail"
    if event_type == "call.voicemail_complete":
        return "Left a voicemail"
    if event_type == "call.recording_available":
        return "Call recording available"
    if call_state == "voicemail" or event_type == "voicemail":
        return "Voicemail"
    return f"Call event: {call_state}"


def emit_call_timeline_event(
    *,
    call_id: str,
    conversation_id: str,
    actor_user_id: str,
    event_type: str,
    call_state: str,
    reason: Optional[str] = None,
    event_ts: Optional[int] = None,
    extra_payload: Optional[Mapping[str, Any]] = None,
    archive_emitter: Optional[Any] = None,
) -> dict[str, Any]:
    ts = int(event_ts if event_ts is not None else now_ts())
    message_id = f"sys_call_{call_id}_{event_type.replace('.', '_')}_{ts}"
    preview = _preview_for_event(event_type=event_type, call_state=call_state, reason=reason)

    item = {
        "conversation_id": conversation_id,
        "message_id": message_id,
        "sender_id": "system",
        "created_at": ts,
        "kind": "text",
        "text": preview,
        "subtype": "call_lifecycle",
        "call_id": call_id,
        "call_event_type": event_type,
        "call_state": call_state,
        "end_reason": reason,
        "timeline_state": {
            "call_id": call_id,
            "event_type": event_type,
            "state": call_state,
            "reason": reason,
            **dict(extra_payload or {}),
        },
    }

    tbl_msgs = _messages_table()
    try:
        tbl_msgs.put_item(Item=item, ConditionExpression="attribute_not_exists(message_id)")
    except Exception:
        # deterministic dedupe: if already inserted, continue as success
        pass

    try:
        _conversations_table().update_item(
            Key={"conversation_id": conversation_id},
            UpdateExpression="SET last_message_at=:ts, last_message_preview=:preview",
            ExpressionAttributeValues={":ts": ts, ":preview": preview},
        )
    except Exception:
        pass

    try:
        emit_archive = archive_emitter
        if emit_archive is None:
            from app.services.messaging_archive_writer import emit_messaging_archive_event

            emit_archive = emit_messaging_archive_event

        emit_archive(
            event_id=f"archive_{message_id}",
            event_ts=ts,
            tenant_id="default",
            conversation_id=conversation_id,
            message_id=message_id,
            actor_user_id=actor_user_id,
            effective_user_id=actor_user_id,
            event_type="call.lifecycle",
            payload={
                "call_id": call_id,
                "call_event_type": event_type,
                "state": call_state,
                "reason": reason,
                **dict(extra_payload or {}),
            },
        )
    except Exception:
        pass

    return item


__all__ = ["emit_call_timeline_event"]
