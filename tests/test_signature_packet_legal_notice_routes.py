from __future__ import annotations

from unittest.mock import patch

import pytest
from fastapi import HTTPException

from app.routers import signature_packets as routes


def test_detail_for_signer_requires_legal_notice_and_emits_shown() -> None:
    with (
        patch.object(routes, "get_packet", return_value={"packet_id": "sp_1", "owner_user_id": "owner-1", "status": "sent", "source_path": "/nda.pdf"}),
        patch.object(routes, "get_packet_signer", return_value={"signer_id": "user-2", "status": "pending"}),
        patch.object(routes, "list_packet_signers", return_value=[]),
        patch.object(routes, "list_packet_fields", return_value=[]),
        patch.object(routes, "mark_signer_notice_shown", return_value=True) as shown_mock,
        patch.object(routes, "append_packet_event") as event_mock,
    ):
        out = routes.get_signature_packet_detail("sp_1", user_sub="user-2")

    assert out["legal_notice"]["required"] is True
    assert out["capabilities"]["can_fill_fields"] is False
    shown_mock.assert_called_once_with("sp_1", "user-2", routes.S.signature_packet_legal_notice_version)
    event_mock.assert_called_once()
    assert event_mock.call_args.kwargs["event_type"] == "legal_notice_shown"


def test_detail_for_signer_after_acceptance_does_not_show_notice_again() -> None:
    with (
        patch.object(routes, "get_packet", return_value={"packet_id": "sp_1", "owner_user_id": "owner-1", "status": "sent", "source_path": "/nda.pdf"}),
        patch.object(
            routes,
            "get_packet_signer",
            return_value={
                "signer_id": "user-2",
                "status": "pending",
                "legal_notice_accepted_version": routes.S.signature_packet_legal_notice_version,
            },
        ),
        patch.object(routes, "list_packet_signers", return_value=[]),
        patch.object(routes, "list_packet_fields", return_value=[]),
        patch.object(routes, "mark_signer_notice_shown") as shown_mock,
        patch.object(routes, "append_packet_event") as event_mock,
    ):
        out = routes.get_signature_packet_detail("sp_1", user_sub="user-2")

    assert out["legal_notice"]["required"] is False
    assert out["capabilities"]["can_fill_fields"] is True
    shown_mock.assert_not_called()
    event_mock.assert_not_called()


def test_acknowledge_legal_notice_emits_event_once() -> None:
    with (
        patch.object(routes, "get_packet", return_value={"packet_id": "sp_1", "owner_user_id": "owner-1", "status": "sent"}),
        patch.object(routes, "get_packet_signer", return_value={"signer_id": "user-2", "status": "pending"}),
        patch.object(routes, "mark_signer_notice_accepted", return_value=True),
        patch.object(routes, "append_packet_event") as event_mock,
    ):
        out = routes.acknowledge_signature_packet_legal_notice("sp_1", user_sub="user-2")

    assert out["accepted"] is True
    assert out["notice_version"] == routes.S.signature_packet_legal_notice_version
    event_mock.assert_called_once()
    assert event_mock.call_args.kwargs["event_type"] == "legal_notice_accepted"


def test_fill_rejected_until_legal_notice_accepted() -> None:
    with (
        patch.object(routes, "get_packet", return_value={"packet_id": "sp_1", "status": "sent"}),
        patch.object(routes, "get_packet_signer", return_value={"signer_id": "user-2", "status": "pending"}),
    ):
        with pytest.raises(HTTPException) as exc:
            routes.fill_signature_packet_field(
                "sp_1",
                "sf_1",
                routes.SignaturePacketFieldFillIn(value="Jane Doe", input_mode="typed"),
                user_sub="user-2",
            )

    assert exc.value.status_code == 409
    assert exc.value.detail["code"] == "signature_packet_legal_notice_required"
