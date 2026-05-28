"""Multi-input MediaLive operations for BCAST-016.

In dev mode (LocalBroadcastProvider), returns mock results.
In production, extends broadcast_mediolive.py with additional RTMP_PUSH
input creation, channel attachment, input switching, and cleanup.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Dict
from uuid import uuid4

from app.core.settings import S

logger = logging.getLogger("broadcast.multi_input")


@dataclass(frozen=True)
class InputProvisionResult:
    input_id: str
    input_arn: str
    ingest_url: str
    stream_key: str  # One-time value, not persisted


def _is_dev() -> bool:
    return bool(S.dev_mode)


def create_additional_input(
    *,
    session_id: str,
    input_index: int,
    correlation_id: str = "",
    idempotency_key: str = "",
) -> InputProvisionResult:
    """Create a new RTMP_PUSH input.

    In dev mode, returns mock data without calling AWS.
    """
    input_name = f"broadcast-{session_id}-input-{input_index}"

    if _is_dev():
        mock_id = f"inp_{uuid4().hex[:12]}"
        return InputProvisionResult(
            input_id=mock_id,
            input_arn=f"arn:aws:medialive:us-east-1:000000000000:input:{mock_id}",
            ingest_url=f"rtmp://localhost:1935/live/{input_name}",
            stream_key=uuid4().hex,
        )

    from app.services.broadcast_mediolive import _client, _with_retry

    client = _client()
    idem_key = idempotency_key or f"{session_id}:input:{input_index}"
    create_resp = _with_retry(
        lambda: client.create_input(
            Name=input_name,
            Type="RTMP_PUSH",
            RequestId=idem_key,
            Tags={
                "broadcast-session-id": session_id,
                "input-index": str(input_index),
                "correlation-id": correlation_id,
            },
        )
    )
    input_data = create_resp.get("Input", {})
    input_id = str(input_data.get("Id") or "")
    input_arn = str(input_data.get("Arn") or "")
    destinations = input_data.get("Destinations", [])
    ingest_url = ""
    stream_key = ""
    if destinations:
        first = destinations[0]
        ingest_url = first.get("Url", "")
        stream_key = first.get("StreamName", uuid4().hex)
    return InputProvisionResult(
        input_id=input_id,
        input_arn=input_arn,
        ingest_url=ingest_url,
        stream_key=stream_key,
    )


def attach_input_to_channel(
    *,
    channel_id: str,
    input_id: str,
    attachment_name: str,
) -> Dict[str, Any]:
    """Attach an input to a running MediaLive channel."""
    if _is_dev():
        return {"attached": True, "channel_id": channel_id, "input_id": input_id}

    from app.services.broadcast_mediolive import _client, _with_retry

    client = _client()
    desc = _with_retry(lambda: client.describe_channel(ChannelId=channel_id))
    current_attachments = desc.get("InputAttachments", [])
    new_attachment = {"InputId": input_id, "InputAttachmentName": attachment_name}
    updated_attachments = current_attachments + [new_attachment]
    result = _with_retry(
        lambda: client.update_channel(ChannelId=channel_id, InputAttachments=updated_attachments)
    )
    return result


def schedule_input_switch(
    *,
    channel_id: str,
    input_attachment_name: str,
    action_name: str,
) -> Dict[str, Any]:
    """Switch active input on a running channel using ImmediateMode."""
    if _is_dev():
        return {"switched": True, "attachment": input_attachment_name}

    from app.services.broadcast_mediolive import _client, _with_retry

    client = _client()
    schedule_action = {
        "ActionName": action_name,
        "ScheduleActionStartSettings": {"ImmediateModeScheduleActionStartSettings": {}},
        "ScheduleActionSettings": {
            "InputSwitchSettings": {"InputAttachmentNameReference": input_attachment_name}
        },
    }
    result = _with_retry(
        lambda: client.batch_update_schedule(
            ChannelId=channel_id, Creates={"ScheduleActions": [schedule_action]}
        )
    )
    return result


def detach_input_from_channel(
    *,
    channel_id: str,
    input_attachment_name: str,
) -> Dict[str, Any]:
    """Remove an input from the channel."""
    if _is_dev():
        return {"detached": True, "attachment": input_attachment_name}

    from app.services.broadcast_mediolive import _client, _with_retry

    client = _client()
    desc = _with_retry(lambda: client.describe_channel(ChannelId=channel_id))
    current_attachments = desc.get("InputAttachments", [])
    filtered = [a for a in current_attachments if a.get("InputAttachmentName") != input_attachment_name]
    if len(filtered) == len(current_attachments):
        return {"detached": False}
    result = _with_retry(
        lambda: client.update_channel(ChannelId=channel_id, InputAttachments=filtered)
    )
    return {"detached": True, "result": result}


def delete_medialive_input(input_id: str) -> Dict[str, Any]:
    """Delete a MediaLive input resource."""
    if _is_dev():
        return {"deleted": True, "input_id": input_id}

    from app.services.broadcast_mediolive import _client, _with_retry

    client = _client()
    result = _with_retry(lambda: client.delete_input(InputId=input_id))
    return result
