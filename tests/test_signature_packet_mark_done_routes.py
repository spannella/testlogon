from __future__ import annotations

from unittest.mock import patch

import pytest
from fastapi import HTTPException

from app.routers import signature_packets as routes


def test_mark_done_completes_signer_and_transitions_packet() -> None:
    with (
        patch.object(routes, "get_packet", return_value={"packet_id": "sp_1", "status": "sent"}),
        patch.object(routes, "get_packet_signer", return_value={"signer_id": "user-2", "status": "pending", "legal_notice_accepted_version": "2026-01"}),
        patch.object(
            routes,
            "list_packet_fields",
            return_value=[
                {"field_id": "sf_1", "required": True, "assigned_signer_id": "user-2", "filled_at": "2026-01-01T00:00:00+00:00"}
            ],
        ),
        patch.object(routes, "mark_signer_completed", return_value={"status": "completed", "completed_at": "2026-01-01T01:00:00+00:00"}),
        patch.object(routes, "append_packet_event") as event_mock,
        patch.object(routes, "are_required_signers_completed", return_value=False),
        patch.object(routes, "mark_packet_partially_signed", return_value={"status": "partially_signed"}),
    ):
        out = routes.mark_signature_packet_done("sp_1", user_sub="user-2", request_ip="203.0.113.15")

    assert out["signer_status"] == "completed"
    assert out["packet_status"] == "partially_signed"
    assert event_mock.call_args.kwargs["event_payload"]["source_ip"] == "203.0.113.15"
    event_mock.assert_called_once()


def test_mark_done_rejects_when_required_fields_remaining() -> None:
    with (
        patch.object(routes, "get_packet", return_value={"packet_id": "sp_1", "status": "sent"}),
        patch.object(routes, "get_packet_signer", return_value={"signer_id": "user-2", "status": "pending", "legal_notice_accepted_version": "2026-01"}),
        patch.object(
            routes,
            "list_packet_fields",
            return_value=[
                {"field_id": "sf_1", "required": True, "assigned_signer_id": "user-2", "filled_at": None},
                {"field_id": "sf_2", "required": True, "assigned_signer_id": "user-2", "filled_at": "2026-01-01T00:00:00+00:00"},
            ],
        ),
    ):
        with pytest.raises(HTTPException) as exc:
            routes.mark_signature_packet_done("sp_1", user_sub="user-2")

    assert exc.value.status_code == 400
    assert exc.value.detail["code"] == "required_fields_incomplete"
    assert exc.value.detail["remaining_required_count"] == 1


def test_mark_done_rejects_non_signer() -> None:
    with (
        patch.object(routes, "get_packet", return_value={"packet_id": "sp_1", "status": "sent"}),
        patch.object(routes, "get_packet_signer", return_value=None),
    ):
        with pytest.raises(HTTPException) as exc:
            routes.mark_signature_packet_done("sp_1", user_sub="intruder")

    assert exc.value.status_code == 403
    assert exc.value.detail["code"] == "signature_packet_not_signer"


def test_mark_done_rejects_atomic_conflict_when_signer_not_pending() -> None:
    with (
        patch.object(routes, "get_packet", return_value={"packet_id": "sp_1", "status": "sent"}),
        patch.object(routes, "get_packet_signer", return_value={"signer_id": "user-2", "status": "pending", "legal_notice_accepted_version": "2026-01"}),
        patch.object(routes, "list_packet_fields", return_value=[]),
        patch.object(routes, "mark_signer_completed", side_effect=ValueError("signer_not_pending")),
        patch.object(routes, "are_required_signers_completed", return_value=False),
    ):
        # empty required set is valid, conflict should still surface deterministically
        out_exc = None
        try:
            routes.mark_signature_packet_done("sp_1", user_sub="user-2")
        except HTTPException as exc:
            out_exc = exc

    assert out_exc is not None
    assert out_exc.status_code == 409
    assert out_exc.detail["code"] == "signer_not_pending"


def test_mark_done_completes_packet_and_triggers_finalize_once() -> None:
    with (
        patch.object(routes, "get_packet", return_value={"packet_id": "sp_1", "status": "partially_signed", "owner_user_id": "owner-1"}),
        patch.object(routes, "get_packet_signer", return_value={"signer_id": "user-2", "status": "pending", "legal_notice_accepted_version": "2026-01"}),
        patch.object(routes, "list_packet_fields", return_value=[]),
        patch.object(routes, "mark_signer_completed", return_value={"status": "completed", "completed_at": "2026-01-01T01:00:00+00:00"}),
        patch.object(routes, "are_required_signers_completed", return_value=True),
        patch.object(routes, "mark_packet_completed", return_value={"status": "completed"}),
        patch.object(routes, "list_packet_signers", return_value=[{"signer_id": "user-2", "status": "completed"}, {"signer_id": "user-3", "status": "completed"}]),
        patch.object(routes, "mark_completion_notices_sent", return_value=True),
        patch.object(routes, "append_packet_event") as event_mock,
    ):
        out = routes.mark_signature_packet_done("sp_1", user_sub="user-2")

    assert out["packet_status"] == "completed"
    assert event_mock.call_count == 6
    event_types = [call.kwargs["event_type"] for call in event_mock.call_args_list]
    assert event_types == [
        "signer_completed",
        "packet_completed",
        "packet_finalize_requested",
        "completion_notice_sent",
        "completion_notice_sent",
        "completion_notice_sent",
    ]


def test_mark_done_duplicate_finalize_attempt_is_idempotent() -> None:
    with (
        patch.object(routes, "get_packet", return_value={"packet_id": "sp_1", "status": "partially_signed", "owner_user_id": "owner-1"}),
        patch.object(routes, "get_packet_signer", return_value={"signer_id": "user-2", "status": "pending", "legal_notice_accepted_version": "2026-01"}),
        patch.object(routes, "list_packet_fields", return_value=[]),
        patch.object(routes, "mark_signer_completed", return_value={"status": "completed", "completed_at": "2026-01-01T01:00:00+00:00"}),
        patch.object(routes, "are_required_signers_completed", return_value=True),
        patch.object(routes, "mark_packet_completed", return_value=None),
        patch.object(routes, "mark_packet_partially_signed", return_value={"status": "partially_signed"}),
        patch.object(routes, "append_packet_event") as event_mock,
    ):
        out = routes.mark_signature_packet_done("sp_1", user_sub="user-2")

    assert out["packet_status"] == "partially_signed"
    assert event_mock.call_count == 1
    assert event_mock.call_args.kwargs["event_type"] == "signer_completed"


def test_mark_done_completion_notices_not_duplicated_when_already_sent() -> None:
    with (
        patch.object(routes, "get_packet", return_value={"packet_id": "sp_1", "status": "partially_signed", "owner_user_id": "owner-1"}),
        patch.object(routes, "get_packet_signer", return_value={"signer_id": "user-2", "status": "pending", "legal_notice_accepted_version": "2026-01"}),
        patch.object(routes, "list_packet_fields", return_value=[]),
        patch.object(routes, "mark_signer_completed", return_value={"status": "completed", "completed_at": "2026-01-01T01:00:00+00:00"}),
        patch.object(routes, "are_required_signers_completed", return_value=True),
        patch.object(routes, "mark_packet_completed", return_value={"status": "completed"}),
        patch.object(routes, "list_packet_signers", return_value=[{"signer_id": "user-2", "status": "completed"}]),
        patch.object(routes, "mark_completion_notices_sent", return_value=False),
        patch.object(routes, "append_packet_event") as event_mock,
    ):
        out = routes.mark_signature_packet_done("sp_1", user_sub="user-2")

    assert out["packet_status"] == "completed"
    event_types = [call.kwargs["event_type"] for call in event_mock.call_args_list]
    assert event_types == ["signer_completed", "packet_completed", "packet_finalize_requested"]
