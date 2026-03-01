from __future__ import annotations

from unittest.mock import patch

import pytest
from fastapi import HTTPException

from app.routers import signature_packets as routes


def _draft_packet(owner: str = "user-1"):
    return {"packet_id": "sp_1", "owner_user_id": owner, "status": "draft"}


def test_send_signature_packet_sends_and_emits_invites() -> None:
    with (
        patch.object(routes, "get_packet", return_value=_draft_packet()),
        patch.object(routes, "list_packet_signers", return_value=[{"signer_id": "user-2"}, {"signer_id": "user-3"}]),
        patch.object(
            routes,
            "list_packet_fields",
            return_value=[
                {"field_id": "sf_1", "required": True, "assigned_signer_id": "user-2"},
                {"field_id": "sf_2", "required": True, "assigned_signer_id": "user-3"},
            ],
        ),
        patch.object(routes, "mark_packet_sent", return_value={"status": "sent", "sent_at": "2026-01-01T00:00:00+00:00"}),
        patch.object(routes, "append_packet_event") as event_mock,
    ):
        out = routes.send_signature_packet("sp_1", user_sub="user-1")

    assert out["status"] == "sent"
    assert out["invited_signers"] == 2
    assert event_mock.call_count == 3


def test_send_signature_packet_rejects_when_no_signers() -> None:
    with (
        patch.object(routes, "get_packet", return_value=_draft_packet()),
        patch.object(routes, "list_packet_signers", return_value=[]),
    ):
        with pytest.raises(HTTPException) as exc:
            routes.send_signature_packet("sp_1", user_sub="user-1")
    assert exc.value.status_code == 400
    assert exc.value.detail["code"] == "signature_packet_no_signers"


def test_send_signature_packet_rejects_when_required_field_unassigned() -> None:
    with (
        patch.object(routes, "get_packet", return_value=_draft_packet()),
        patch.object(routes, "list_packet_signers", return_value=[{"signer_id": "user-2"}]),
        patch.object(routes, "list_packet_fields", return_value=[{"field_id": "sf_1", "required": True}]),
    ):
        with pytest.raises(HTTPException) as exc:
            routes.send_signature_packet("sp_1", user_sub="user-1")
    assert exc.value.status_code == 400
    assert exc.value.detail["code"] == "required_field_unassigned"


def test_send_signature_packet_rejects_when_required_field_assignee_missing() -> None:
    with (
        patch.object(routes, "get_packet", return_value=_draft_packet()),
        patch.object(routes, "list_packet_signers", return_value=[{"signer_id": "user-2"}]),
        patch.object(routes, "list_packet_fields", return_value=[{"field_id": "sf_1", "required": True, "assigned_signer_id": "user-9"}]),
    ):
        with pytest.raises(HTTPException) as exc:
            routes.send_signature_packet("sp_1", user_sub="user-1")
    assert exc.value.status_code == 400
    assert exc.value.detail["code"] == "required_field_invalid_assignee"
