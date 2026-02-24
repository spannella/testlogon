from __future__ import annotations

from unittest.mock import patch

import pytest
from fastapi import HTTPException

from app.routers import signature_packets as routes


def test_get_signature_packet_detail_for_sender_returns_sender_capabilities() -> None:
    with (
        patch.object(
            routes,
            "get_packet",
            return_value={
                "packet_id": "sp_1",
                "owner_user_id": "owner-1",
                "status": "draft",
                "source_path": "/nda.pdf",
                "origin_channel": "share",
            },
        ),
        patch.object(routes, "get_packet_signer", return_value=None),
        patch.object(routes, "list_packet_signers", return_value=[{"signer_id": "user-2", "status": "pending", "legal_notice_accepted_version": "2026-01"}]),
        patch.object(
            routes,
            "list_packet_fields",
            return_value=[{"field_id": "sf_1", "field_type": "signature", "required": True, "assigned_signer_id": "user-2"}],
        ),
    ):
        out = routes.get_signature_packet_detail("sp_1", user_sub="owner-1")

    assert out["role"] == "sender"
    assert out["capabilities"]["can_edit_fields"] is True
    assert out["capabilities"]["can_send"] is True
    assert out["capabilities"]["can_fill_fields"] is False


def test_get_signature_packet_detail_for_signer_returns_signer_capabilities() -> None:
    with (
        patch.object(
            routes,
            "get_packet",
            return_value={"packet_id": "sp_1", "owner_user_id": "owner-1", "status": "sent", "source_path": "/nda.pdf"},
        ),
        patch.object(routes, "get_packet_signer", return_value={"signer_id": "user-2", "status": "pending", "legal_notice_accepted_version": "2026-01"}),
        patch.object(routes, "list_packet_signers", return_value=[{"signer_id": "user-2", "status": "pending", "legal_notice_accepted_version": "2026-01"}]),
        patch.object(
            routes,
            "list_packet_fields",
            return_value=[{"field_id": "sf_1", "field_type": "signature", "required": True, "assigned_signer_id": "user-2"}],
        ),
    ):
        out = routes.get_signature_packet_detail("sp_1", user_sub="user-2")

    assert out["role"] == "signer"
    assert out["signer_status"] == "pending"
    assert out["capabilities"]["can_edit_fields"] is False
    assert out["capabilities"]["can_send"] is False
    assert out["capabilities"]["can_fill_fields"] is True
    assert out["fields"][0]["is_assigned_to_viewer"] is True


def test_get_signature_packet_detail_denies_non_participant() -> None:
    with (
        patch.object(routes, "get_packet", return_value={"packet_id": "sp_1", "owner_user_id": "owner-1", "status": "sent"}),
        patch.object(routes, "get_packet_signer", return_value=None),
    ):
        with pytest.raises(HTTPException) as exc:
            routes.get_signature_packet_detail("sp_1", user_sub="intruder")

    assert exc.value.status_code == 403
    assert exc.value.detail["code"] == "signature_packet_not_participant"
