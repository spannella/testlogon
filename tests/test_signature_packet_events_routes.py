from __future__ import annotations

from unittest.mock import patch

import pytest
from fastapi import HTTPException

from app.routers import signature_packets as routes


def test_get_signature_packet_events_for_participant() -> None:
    with (
        patch.object(routes, "get_packet", return_value={"packet_id": "sp_1", "owner_user_id": "owner-1"}),
        patch.object(routes, "get_packet_signer", return_value={"signer_id": "user-2", "status": "pending"}),
        patch.object(routes, "list_packet_events", return_value=[{"event_id": "ev_1", "packet_id": "sp_1", "actor_user_id": "owner-1", "event_type": "packet_created", "event_payload": {}, "created_at": "2026-01-01T00:00:00+00:00"}]),
    ):
        out = routes.get_signature_packet_events("sp_1", user_sub="user-2")

    assert out["packet_id"] == "sp_1"
    assert out["events"][0]["event_type"] == "packet_created"


def test_get_signature_packet_events_denies_non_participant_and_audits() -> None:
    with (
        patch.object(routes, "get_packet", return_value={"packet_id": "sp_1", "owner_user_id": "owner-1"}),
        patch.object(routes, "get_packet_signer", return_value=None),
        patch.object(routes, "append_packet_event") as event_mock,
    ):
        with pytest.raises(HTTPException) as exc:
            routes.get_signature_packet_events("sp_1", user_sub="intruder")

    assert exc.value.status_code == 403
    assert exc.value.detail["code"] == "signature_packet_not_participant"
    assert event_mock.call_args.kwargs["event_type"] == "packet_authorization_failed"
