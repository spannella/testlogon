from __future__ import annotations

import time
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

MAX_DESTINATIONS_PER_CAMPAIGN = 100
MAX_TEXT_LENGTH = 4000
MAX_IDEMPOTENCY_KEY_LENGTH = 128


class MassMessageContentPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: Literal["text"] = "text"
    text: str = Field(min_length=1, max_length=MAX_TEXT_LENGTH)

    @field_validator("text")
    @classmethod
    def _normalize_text(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("text must not be empty")
        return cleaned


class MassMessageCreateCampaignRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    conversation_ids: list[str] = Field(min_length=1, max_length=MAX_DESTINATIONS_PER_CAMPAIGN)
    content: MassMessageContentPayload
    mode: Literal["immediate", "scheduled"] = "immediate"
    send_at: int | None = None
    idempotency_key: str | None = Field(default=None, min_length=8, max_length=MAX_IDEMPOTENCY_KEY_LENGTH)

    @field_validator("conversation_ids")
    @classmethod
    def _normalize_conversation_ids(cls, value: list[str]) -> list[str]:
        normalized: list[str] = []
        seen: set[str] = set()
        for raw in value:
            cid = str(raw).strip()
            if not cid:
                raise ValueError("conversation_ids must contain non-empty values")
            if cid in seen:
                continue
            seen.add(cid)
            normalized.append(cid)
        if not normalized:
            raise ValueError("conversation_ids must not be empty")
        if len(normalized) > MAX_DESTINATIONS_PER_CAMPAIGN:
            raise ValueError(f"conversation_ids must contain at most {MAX_DESTINATIONS_PER_CAMPAIGN} entries")
        return normalized

    @field_validator("idempotency_key")
    @classmethod
    def _normalize_idempotency_key(cls, value: str | None) -> str | None:
        if value is None:
            return None
        cleaned = value.strip()
        if not cleaned:
            return None
        return cleaned

    @model_validator(mode="after")
    def _validate_schedule_fields(self) -> "MassMessageCreateCampaignRequest":
        if self.mode == "immediate":
            if self.send_at is not None:
                raise ValueError("send_at is not allowed in immediate mode")
            return self

        # scheduled mode
        if self.send_at is None:
            raise ValueError("send_at is required in scheduled mode")
        now_ts = int(time.time())
        if self.send_at <= now_ts:
            raise ValueError("send_at must be in the future")
        return self


class MassMessageCampaignCounters(BaseModel):
    model_config = ConfigDict(extra="forbid")

    total: int = Field(default=0, ge=0)
    queued: int = Field(default=0, ge=0)
    sent: int = Field(default=0, ge=0)
    failed: int = Field(default=0, ge=0)
    cancelled: int = Field(default=0, ge=0)


class MassMessageRejectedDestination(BaseModel):
    model_config = ConfigDict(extra="forbid")

    conversation_id: str = Field(min_length=1)
    reason: str = Field(min_length=1)


class MassMessageDestinationStatus(BaseModel):
    model_config = ConfigDict(extra="forbid")

    campaign_id: str = Field(min_length=1)
    conversation_id: str = Field(min_length=1)
    state: Literal["pending", "sent", "failed", "skipped", "cancelled"]
    message_id: str | None = None
    error_code: str | None = None
    attempt_count: int = Field(default=0, ge=0)
    updated_at: int | None = None
    created_at: int | None = None
    campaign_state: str = Field(min_length=1)


class MassMessageCreateCampaignResponse(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "examples": [
                {
                    "campaign_id": "mmc_123",
                    "mode": "immediate",
                    "status": "pending",
                    "send_at": None,
                    "accepted_count": 2,
                    "accepted_conversation_ids": ["c1", "c2"],
                    "rejected": [{"conversation_id": "c3", "reason": "not_a_participant"}],
                    "counters": {"total": 2, "queued": 2, "sent": 0, "failed": 0, "cancelled": 0},
                    "created_at": 1760000000,
                    "updated_at": 1760000000,
                }
            ]
        },
    )

    campaign_id: str = Field(min_length=1)
    mode: Literal["immediate", "scheduled"]
    status: Literal["pending", "scheduled", "processing", "completed", "failed", "cancelled"]
    send_at: int | None = None
    accepted_count: int = Field(ge=0)
    accepted_conversation_ids: list[str] = Field(default_factory=list)
    rejected: list[MassMessageRejectedDestination] = Field(default_factory=list)
    counters: MassMessageCampaignCounters = Field(default_factory=MassMessageCampaignCounters)
    created_at: int
    updated_at: int


class MassMessageCampaignDetailResponse(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "examples": [
                {
                    "campaign_id": "mmc_123",
                    "sender_id": "user_1",
                    "mode": "scheduled",
                    "status": "processing",
                    "send_at": 1760003600,
                    "counters": {"total": 3, "queued": 1, "sent": 1, "failed": 1, "cancelled": 0},
                    "destinations": [
                        {
                            "campaign_id": "mmc_123",
                            "conversation_id": "c1",
                            "state": "sent",
                            "message_id": "m_1",
                            "error_code": None,
                            "attempt_count": 1,
                            "updated_at": 1760003601,
                            "created_at": 1760003500,
                            "campaign_state": "mmc_123#sent",
                        }
                    ],
                    "next_cursor": "eyJjYW1wYWlnbl9pZCI6Im1tY18xMjMiLCJjb252ZXJzYXRpb25faWQiOiJjMiJ9",
                    "created_at": 1760003500,
                    "updated_at": 1760003601,
                }
            ]
        },
    )

    campaign_id: str = Field(min_length=1)
    sender_id: str = Field(min_length=1)
    mode: Literal["immediate", "scheduled"]
    status: Literal["pending", "scheduled", "processing", "completed", "failed", "cancelled"]
    send_at: int | None = None
    counters: MassMessageCampaignCounters = Field(default_factory=MassMessageCampaignCounters)
    destinations: list[MassMessageDestinationStatus] = Field(default_factory=list)
    next_cursor: str | None = None
    created_at: int
    updated_at: int


class MassMessageCancelCampaignResponse(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "examples": [
                {
                    "campaign_id": "mmc_123",
                    "status": "cancelled",
                    "cancelled_destinations": 4,
                    "counters": {"total": 10, "queued": 0, "sent": 6, "failed": 0, "cancelled": 4},
                    "updated_at": 1760005000,
                }
            ]
        },
    )

    campaign_id: str = Field(min_length=1)
    status: Literal["pending", "scheduled", "processing", "completed", "failed", "cancelled"]
    cancelled_destinations: int = Field(ge=0)
    counters: MassMessageCampaignCounters = Field(default_factory=MassMessageCampaignCounters)
    updated_at: int


class MassMessageCampaignSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    campaign_id: str = Field(min_length=1)
    mode: Literal["immediate", "scheduled"]
    status: Literal["pending", "scheduled", "processing", "completed", "failed", "cancelled"]
    send_at: int | None = None
    counters: MassMessageCampaignCounters = Field(default_factory=MassMessageCampaignCounters)
    created_at: int
    updated_at: int


class MassMessageCampaignListResponse(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "examples": [
                {
                    "items": [
                        {
                            "campaign_id": "mmc_123",
                            "mode": "scheduled",
                            "status": "processing",
                            "send_at": 1760003600,
                            "counters": {"total": 3, "queued": 1, "sent": 1, "failed": 0, "cancelled": 1},
                            "created_at": 1760003500,
                            "updated_at": 1760003600,
                        }
                    ],
                    "next_cursor": "eyJjYW1wYWlnbl9pZCI6Im1tY18xMjMiLCJzZW5kZXJfaWQiOiJ1c2VyXzEiLCJjcmVhdGVkX2F0IjoxNzYwMDAzNTAwfQ",
                }
            ]
        },
    )

    items: list[MassMessageCampaignSummary] = Field(default_factory=list)
    next_cursor: str | None = None
