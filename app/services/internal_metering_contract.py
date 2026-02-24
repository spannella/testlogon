from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional


@dataclass(frozen=True)
class InternalMeterBinding:
    namespace: str
    action: str
    meter: str
    unit: str
    description: str


# Canonical internal billable operation taxonomy (CCE-040).
_INTERNAL_BINDINGS: Dict[str, InternalMeterBinding] = {
    "messaging.send_message": InternalMeterBinding(
        namespace="messaging",
        action="send_message",
        meter="messaging.message.send.count",
        unit="count",
        description="Send a message in a conversation.",
    ),
    "messaging.upload_attachment": InternalMeterBinding(
        namespace="messaging",
        action="upload_attachment",
        meter="messaging.attachment.upload.bytes",
        unit="bytes",
        description="Upload messaging attachment payload bytes.",
    ),
    "messaging.download_attachment": InternalMeterBinding(
        namespace="messaging",
        action="download_attachment",
        meter="messaging.attachment.download.bytes",
        unit="bytes",
        description="Download messaging attachment payload bytes.",
    ),
    "messaging.stream_events": InternalMeterBinding(
        namespace="messaging",
        action="stream_events",
        meter="messaging.events.stream.connect.count",
        unit="count",
        description="Open messaging event stream connection.",
    ),
    "messaging.presence_heartbeat": InternalMeterBinding(
        namespace="messaging",
        action="presence_heartbeat",
        meter="messaging.presence.heartbeat.count",
        unit="count",
        description="Presence heartbeat updates.",
    ),
    "filemanager.upload_file": InternalMeterBinding(
        namespace="filemanager",
        action="upload_file",
        meter="filemanager.file.upload.bytes",
        unit="bytes",
        description="Upload file payload bytes.",
    ),
    "filemanager.download_file": InternalMeterBinding(
        namespace="filemanager",
        action="download_file",
        meter="filemanager.file.download.bytes",
        unit="bytes",
        description="Download file payload bytes.",
    ),
    "filemanager.preview_file": InternalMeterBinding(
        namespace="filemanager",
        action="preview_file",
        meter="filemanager.file.preview.count",
        unit="count",
        description="Render or request preview metadata.",
    ),
    "filemanager.delete_file": InternalMeterBinding(
        namespace="filemanager",
        action="delete_file",
        meter="filemanager.file.delete.count",
        unit="count",
        description="Delete file resource.",
    ),
    "filemanager.list_directory": InternalMeterBinding(
        namespace="filemanager",
        action="list_directory",
        meter="filemanager.directory.list.count",
        unit="count",
        description="List directory entries.",
    ),
}


_HTTP_ROUTE_TO_OPERATION_KEY: Dict[str, str] = {
    "POST:/messaging/conversations/{conversation_id}/messages": "messaging.send_message",
    "POST:/messaging/conversations/{conversation_id}/messages/image": "messaging.upload_attachment",
    "GET:/messaging/conversations/{conversation_id}/messages/image/{message_id}": "messaging.download_attachment",
    "GET:/messaging/events/stream": "messaging.stream_events",
    "POST:/messaging/presence/heartbeat": "messaging.presence_heartbeat",
    "POST:/v1/fs/upload": "filemanager.upload_file",
    "GET:/v1/fs/download": "filemanager.download_file",
    "GET:/v1/fs/shared-download": "filemanager.download_file",
    "GET:/v1/fs/preview": "filemanager.preview_file",
    "GET:/v1/fs/shared-preview": "filemanager.preview_file",
    "DELETE:/v1/fs": "filemanager.delete_file",
    "GET:/v1/fs/list": "filemanager.list_directory",
}

_REQUIRED_IDENTITY_FIELDS = (
    "x-user-sub",
    "x-service-name",
    "x-service-request-id",
)


def resolve_meter_binding(namespace: str, action: str) -> InternalMeterBinding:
    key = f"{(namespace or '').strip().lower()}.{(action or '').strip().lower()}"
    binding = _INTERNAL_BINDINGS.get(key)
    if binding is None:
        raise ValueError(f"unknown internal metering action: {key}")
    return binding


def resolve_route_meter_binding(route_id: str) -> Optional[InternalMeterBinding]:
    operation_key = _HTTP_ROUTE_TO_OPERATION_KEY.get((route_id or "").strip())
    if operation_key is None:
        return None
    return _INTERNAL_BINDINGS[operation_key]


def validate_identity_propagation(headers: Dict[str, str]) -> Dict[str, object]:
    normalized = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    missing = [field for field in _REQUIRED_IDENTITY_FIELDS if not normalized.get(field)]
    return {
        "ok": not missing,
        "missing": missing,
        "user_sub": normalized.get("x-user-sub", ""),
        "service_name": normalized.get("x-service-name", ""),
        "service_request_id": normalized.get("x-service-request-id", ""),
        "actor_type": normalized.get("x-actor-type", "service"),
    }


def contract_snapshot() -> Dict[str, object]:
    return {
        "required_identity_fields": list(_REQUIRED_IDENTITY_FIELDS),
        "operation_bindings": [
            {
                "namespace": b.namespace,
                "action": b.action,
                "meter": b.meter,
                "unit": b.unit,
                "description": b.description,
            }
            for b in sorted(_INTERNAL_BINDINGS.values(), key=lambda x: (x.namespace, x.action))
        ],
        "http_route_bindings": [
            {
                "route_id": route_id,
                "namespace": _INTERNAL_BINDINGS[op_key].namespace,
                "action": _INTERNAL_BINDINGS[op_key].action,
                "meter": _INTERNAL_BINDINGS[op_key].meter,
            }
            for route_id, op_key in sorted(_HTTP_ROUTE_TO_OPERATION_KEY.items())
        ],
    }
