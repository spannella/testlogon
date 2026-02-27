from __future__ import annotations

import pytest

from app.services.signature_packet_domain import (
    SignatureFieldType,
    SignaturePacketStatus,
    SignatureSignerStatus,
    can_transition_packet_status,
    can_transition_signer_status,
    signer_status_sort_key,
    validate_packet_status_transition,
    validate_signer_status_transition,
)


def test_signature_packet_status_enum_values() -> None:
    assert SignaturePacketStatus.DRAFT.value == "draft"
    assert SignaturePacketStatus.SENT.value == "sent"
    assert SignaturePacketStatus.PARTIALLY_SIGNED.value == "partially_signed"
    assert SignaturePacketStatus.COMPLETED.value == "completed"
    assert SignaturePacketStatus.CANCELLED.value == "cancelled"
    assert SignaturePacketStatus.EXPIRED.value == "expired"


def test_signature_signer_status_enum_values() -> None:
    assert SignatureSignerStatus.PENDING.value == "pending"
    assert SignatureSignerStatus.COMPLETED.value == "completed"


def test_signature_field_type_enum_values() -> None:
    assert SignatureFieldType.SIGNATURE.value == "signature"
    assert SignatureFieldType.INITIALS.value == "initials"
    assert SignatureFieldType.DATE.value == "date"
    assert SignatureFieldType.TEXT.value == "text"


def test_packet_transition_guard_accepts_valid_transition() -> None:
    assert can_transition_packet_status(SignaturePacketStatus.DRAFT, SignaturePacketStatus.SENT)
    validate_packet_status_transition(SignaturePacketStatus.SENT, SignaturePacketStatus.PARTIALLY_SIGNED)


def test_packet_transition_guard_rejects_invalid_transition() -> None:
    assert not can_transition_packet_status(SignaturePacketStatus.DRAFT, SignaturePacketStatus.COMPLETED)
    with pytest.raises(ValueError):
        validate_packet_status_transition(SignaturePacketStatus.COMPLETED, SignaturePacketStatus.SENT)


def test_signer_transition_guard_rejects_invalid_transition() -> None:
    assert can_transition_signer_status(SignatureSignerStatus.PENDING, SignatureSignerStatus.COMPLETED)
    assert not can_transition_signer_status(SignatureSignerStatus.COMPLETED, SignatureSignerStatus.PENDING)
    with pytest.raises(ValueError):
        validate_signer_status_transition(SignatureSignerStatus.COMPLETED, SignatureSignerStatus.PENDING)


def test_signer_status_sort_key_is_canonical() -> None:
    assert signer_status_sort_key(SignatureSignerStatus.PENDING, "pkt-1") == "pending#pkt-1"
