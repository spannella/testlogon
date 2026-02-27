from __future__ import annotations

from enum import Enum
from typing import Final, FrozenSet, Mapping


class SignaturePacketStatus(str, Enum):
    DRAFT = "draft"
    SENT = "sent"
    PARTIALLY_SIGNED = "partially_signed"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    EXPIRED = "expired"


class SignatureSignerStatus(str, Enum):
    PENDING = "pending"
    COMPLETED = "completed"


class SignatureFieldType(str, Enum):
    SIGNATURE = "signature"
    INITIALS = "initials"
    DATE = "date"
    TEXT = "text"


_VALID_PACKET_TRANSITIONS: Final[Mapping[SignaturePacketStatus, FrozenSet[SignaturePacketStatus]]] = {
    SignaturePacketStatus.DRAFT: frozenset(
        {
            SignaturePacketStatus.SENT,
            SignaturePacketStatus.CANCELLED,
            SignaturePacketStatus.EXPIRED,
        }
    ),
    SignaturePacketStatus.SENT: frozenset(
        {
            SignaturePacketStatus.PARTIALLY_SIGNED,
            SignaturePacketStatus.COMPLETED,
            SignaturePacketStatus.CANCELLED,
            SignaturePacketStatus.EXPIRED,
        }
    ),
    SignaturePacketStatus.PARTIALLY_SIGNED: frozenset(
        {
            SignaturePacketStatus.COMPLETED,
            SignaturePacketStatus.CANCELLED,
            SignaturePacketStatus.EXPIRED,
        }
    ),
    SignaturePacketStatus.COMPLETED: frozenset(),
    SignaturePacketStatus.CANCELLED: frozenset(),
    SignaturePacketStatus.EXPIRED: frozenset(),
}

_VALID_SIGNER_TRANSITIONS: Final[Mapping[SignatureSignerStatus, FrozenSet[SignatureSignerStatus]]] = {
    SignatureSignerStatus.PENDING: frozenset({SignatureSignerStatus.COMPLETED}),
    SignatureSignerStatus.COMPLETED: frozenset(),
}


def can_transition_packet_status(
    current: SignaturePacketStatus,
    next_status: SignaturePacketStatus,
) -> bool:
    return next_status in _VALID_PACKET_TRANSITIONS[current]


def validate_packet_status_transition(
    current: SignaturePacketStatus,
    next_status: SignaturePacketStatus,
) -> None:
    if can_transition_packet_status(current, next_status):
        return
    raise ValueError(f"Invalid signature packet status transition: {current.value} -> {next_status.value}")


def can_transition_signer_status(
    current: SignatureSignerStatus,
    next_status: SignatureSignerStatus,
) -> bool:
    return next_status in _VALID_SIGNER_TRANSITIONS[current]


def validate_signer_status_transition(
    current: SignatureSignerStatus,
    next_status: SignatureSignerStatus,
) -> None:
    if can_transition_signer_status(current, next_status):
        return
    raise ValueError(f"Invalid signature signer status transition: {current.value} -> {next_status.value}")


def signer_status_sort_key(status: SignatureSignerStatus, packet_id: str) -> str:
    return f"{status.value}#{packet_id}"
