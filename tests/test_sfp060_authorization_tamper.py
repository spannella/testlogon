from unittest.mock import patch

from fastapi import HTTPException

from app.routers import signature_packets
from app.services.signature_packet_domain import SignatureFieldType
from app.services import signature_packet_store


def test_store_blocks_field_geometry_mutation_when_packet_sent():
    with (
        patch.object(signature_packet_store, "require_signature_pdf_enabled"),
        patch.object(signature_packet_store, "get_packet", return_value={"packet_id": "sp_1", "status": "sent"}),
    ):
        try:
            signature_packet_store.upsert_packet_field(
                packet_id="sp_1",
                field_id="f1",
                page=1,
                x=0.1,
                y=0.1,
                width=0.2,
                height=0.1,
                field_type=SignatureFieldType.SIGNATURE,
                assigned_signer_id="u2",
                required=True,
            )
            assert False, "expected ValueError"
        except ValueError as exc:
            assert str(exc) == "packet_not_draft"


def test_non_participant_access_is_denied_and_audited_for_detail():
    with (
        patch.object(signature_packets, "get_packet", return_value={"packet_id": "sp_1", "owner_user_id": "owner", "status": "sent"}),
        patch.object(signature_packets, "get_packet_signer", return_value=None),
        patch.object(signature_packets, "append_packet_event") as append_event,
    ):
        try:
            signature_packets.get_signature_packet_detail("sp_1", user_sub="intruder")
            assert False, "expected HTTPException"
        except HTTPException as exc:
            assert exc.status_code == 403
            assert exc.detail["code"] == "signature_packet_not_participant"

    append_event.assert_called_once()
    kwargs = append_event.call_args.kwargs
    assert kwargs["event_type"] == "packet_authorization_failed"
    assert kwargs["event_payload"]["code"] == "signature_packet_not_participant"


def test_fill_tamper_attempt_is_denied_and_audited():
    with (
        patch.object(signature_packets, "get_packet", return_value={"packet_id": "sp_1", "owner_user_id": "owner", "status": "sent"}),
        patch.object(signature_packets, "get_packet_signer", return_value={"signer_id": "u1", "status": "pending"}),
        patch.object(signature_packets, "get_packet_field", return_value={"field_id": "f1", "field_type": "signature", "assigned_signer_id": "u2"}),
        patch.object(signature_packets, "append_packet_event") as append_event,
    ):
        try:
            signature_packets.fill_signature_packet_field("sp_1", "f1", signature_packets.SignaturePacketFieldFillIn(value="X"), user_sub="u1")
            assert False, "expected HTTPException"
        except HTTPException as exc:
            assert exc.status_code == 403
            assert exc.detail["code"] == "signature_packet_field_not_assigned_to_signer"

    kwargs = append_event.call_args.kwargs
    assert kwargs["event_type"] == "packet_authorization_failed"
    assert kwargs["event_payload"]["field_id"] == "f1"


def test_sender_cannot_edit_fields_after_send_and_attempt_is_audited():
    with (
        patch.object(signature_packets, "get_packet", return_value={"packet_id": "sp_1", "owner_user_id": "owner", "status": "sent"}),
        patch.object(signature_packets, "append_packet_event") as append_event,
    ):
        try:
            signature_packets.mutate_signature_packet_field(
                "sp_1",
                signature_packets.SignaturePacketFieldMutationIn(
                    action="update",
                    field_id="f1",
                    page=1,
                    x=0.1,
                    y=0.1,
                    width=0.2,
                    height=0.1,
                    field_type="signature",
                    assigned_signer_id="u2",
                    required=True,
                ),
                user_sub="owner",
            )
            assert False, "expected HTTPException"
        except HTTPException as exc:
            assert exc.status_code == 409
            assert exc.detail["code"] == "signature_packet_not_draft"

    kwargs = append_event.call_args.kwargs
    assert kwargs["event_type"] == "packet_validation_failed"
    assert kwargs["event_payload"]["code"] == "signature_packet_not_draft"
