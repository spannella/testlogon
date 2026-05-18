from __future__ import annotations

from enum import Enum


class CampaignMode(str, Enum):
    IMMEDIATE = "immediate"
    SCHEDULED = "scheduled"


class CampaignStatus(str, Enum):
    PENDING = "pending"
    SCHEDULED = "scheduled"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


ALLOWED_STATUS_TRANSITIONS: dict[CampaignStatus, set[CampaignStatus]] = {
    CampaignStatus.PENDING: {CampaignStatus.PROCESSING, CampaignStatus.FAILED, CampaignStatus.CANCELLED},
    CampaignStatus.SCHEDULED: {CampaignStatus.PROCESSING, CampaignStatus.FAILED, CampaignStatus.CANCELLED},
    CampaignStatus.PROCESSING: {CampaignStatus.COMPLETED, CampaignStatus.FAILED, CampaignStatus.CANCELLED},
    CampaignStatus.COMPLETED: set(),
    CampaignStatus.FAILED: set(),
    CampaignStatus.CANCELLED: set(),
}


def parse_campaign_mode(value: str | CampaignMode) -> CampaignMode:
    if isinstance(value, CampaignMode):
        return value
    try:
        return CampaignMode(str(value).strip().lower())
    except ValueError as exc:
        raise ValueError("invalid mode") from exc


def parse_campaign_status(value: str | CampaignStatus) -> CampaignStatus:
    if isinstance(value, CampaignStatus):
        return value
    try:
        return CampaignStatus(str(value).strip().lower())
    except ValueError as exc:
        raise ValueError("invalid status") from exc


def can_transition_status(current_status: str | CampaignStatus, next_status: str | CampaignStatus) -> bool:
    current = parse_campaign_status(current_status)
    nxt = parse_campaign_status(next_status)
    return nxt in ALLOWED_STATUS_TRANSITIONS[current]


def validate_status_transition(current_status: str | CampaignStatus, next_status: str | CampaignStatus) -> None:
    if not can_transition_status(current_status, next_status):
        raise ValueError("invalid status transition")
