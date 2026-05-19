from __future__ import annotations

import pytest
from fastapi import HTTPException

from app.routers import signature_packets as routes
from app.services.signature_packet_domain import SignaturePacketStatus, validate_packet_status_transition


def test_field_geometry_validation_rejects_page_zero():
    with pytest.raises(HTTPException) as exc:
        routes._validate_field_geometry(
            routes.SignaturePacketFieldMutationIn(
                action="create",
                page=0,
                x=0.1,
                y=0.1,
                width=0.2,
                height=0.2,
                field_type="signature",
            )
        )
    assert exc.value.detail["code"] == "invalid_field_page"


def test_normalize_field_value_date_and_signature_constraints():
    assert routes._normalize_field_value("date", routes.SignaturePacketFieldFillIn(value="2026-01-31"))["value"] == "2026-01-31"

    with pytest.raises(HTTPException) as empty_sig:
        routes._normalize_field_value("signature", routes.SignaturePacketFieldFillIn(value=" "))
    assert empty_sig.value.detail["code"] == "empty_signature_value"

    with pytest.raises(HTTPException) as bad_date:
        routes._normalize_field_value("date", routes.SignaturePacketFieldFillIn(value="31-01-2026"))
    assert bad_date.value.detail["code"] == "invalid_date_format"


def test_packet_state_transition_validation_blocks_direct_draft_to_completed():
    with pytest.raises(ValueError):
        validate_packet_status_transition(SignaturePacketStatus.DRAFT, SignaturePacketStatus.COMPLETED)
