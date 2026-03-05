from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, Final, Mapping

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

ARCHIVE_EVENT_SCHEMA_VERSION: Final[int] = 1

ARCHIVE_EVENT_TAXONOMY: Final[tuple[str, ...]] = (
    "message.sent",
    "message.edited",
    "message.deleted",
    "message.revoked",
    "attachment.added",
    "attachment.removed",
    "conversation.member_joined",
    "conversation.member_left",
    "conversation.role_changed",
    "report.submitted",
    "report.status_changed",
)


_HEX64_LEN: Final[int] = 64


def canonical_serialize_payload(payload: Mapping[str, Any]) -> str:
    """Return deterministic JSON encoding used for compliance archive hashing."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def compute_payload_hash(payload: Mapping[str, Any]) -> str:
    canonical_payload = canonical_serialize_payload(payload)
    return hashlib.sha256(canonical_payload.encode("utf-8")).hexdigest()


class MessagingArchiveEvent(BaseModel):
    """Canonical immutable archive envelope for messaging compliance records."""

    model_config = ConfigDict(extra="forbid")

    schema_version: int = Field(default=ARCHIVE_EVENT_SCHEMA_VERSION, ge=1)
    event_id: str = Field(min_length=1, max_length=128)
    event_ts: int = Field(ge=0)
    tenant_id: str = Field(min_length=1, max_length=128)
    conversation_id: str = Field(min_length=1, max_length=128)
    message_id: str = Field(min_length=1, max_length=128)
    actor_user_id: str = Field(min_length=1, max_length=128)
    effective_user_id: str = Field(min_length=1, max_length=128)
    event_type: str = Field(min_length=1, max_length=64)
    payload: Dict[str, Any]
    payload_hash: str = Field(min_length=_HEX64_LEN, max_length=_HEX64_LEN)
    prev_hash: str = Field(min_length=_HEX64_LEN, max_length=_HEX64_LEN)

    @field_validator("event_type")
    @classmethod
    def _validate_event_type(cls, value: str) -> str:
        normalized = (value or "").strip()
        if normalized not in ARCHIVE_EVENT_TAXONOMY:
            raise ValueError("event_type is not part of messaging archive taxonomy")
        return normalized

    @field_validator("payload_hash", "prev_hash")
    @classmethod
    def _validate_hash(cls, value: str) -> str:
        normalized = (value or "").strip().lower()
        if len(normalized) != _HEX64_LEN or any(ch not in "0123456789abcdef" for ch in normalized):
            raise ValueError("hash fields must be lowercase 64-char hex strings")
        return normalized

    @model_validator(mode="after")
    def _validate_payload_hash(self):
        expected = compute_payload_hash(self.payload)
        if self.payload_hash != expected:
            raise ValueError("payload_hash does not match canonical payload hash")
        return self


def build_archive_event(
    *,
    event_id: str,
    event_ts: int,
    tenant_id: str,
    conversation_id: str,
    message_id: str,
    actor_user_id: str,
    effective_user_id: str,
    event_type: str,
    payload: Mapping[str, Any],
    prev_hash: str,
    schema_version: int = ARCHIVE_EVENT_SCHEMA_VERSION,
) -> MessagingArchiveEvent:
    event_payload = dict(payload)
    return MessagingArchiveEvent(
        schema_version=schema_version,
        event_id=event_id,
        event_ts=event_ts,
        tenant_id=tenant_id,
        conversation_id=conversation_id,
        message_id=message_id,
        actor_user_id=actor_user_id,
        effective_user_id=effective_user_id,
        event_type=event_type,
        payload=event_payload,
        payload_hash=compute_payload_hash(event_payload),
        prev_hash=prev_hash,
    )
