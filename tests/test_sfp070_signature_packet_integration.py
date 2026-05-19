from __future__ import annotations

from copy import deepcopy
from unittest.mock import patch

import pytest
from fastapi import HTTPException

from app.routers import signature_packets as routes


def _base_state(multi_signer: bool = False):
    signers = [
        {"packet_id": "sp_1", "signer_id": "signer-1", "status": "pending", "required": True},
    ]
    if multi_signer:
        signers.append({"packet_id": "sp_1", "signer_id": "signer-2", "status": "pending", "required": True})
    return {
        "packet": {
            "packet_id": "sp_1",
            "owner_user_id": "owner-1",
            "status": "draft",
            "source_path": "/nda.pdf",
            "origin_channel": "share",
            "origin_ref": "shr-1",
            "created_at": "2026-01-01T00:00:00+00:00",
        },
        "signers": signers,
        "fields": [
            {
                "packet_id": "sp_1",
                "field_id": "sf_1",
                "field_type": "signature",
                "required": True,
                "assigned_signer_id": "signer-1",
                "page": 1,
                "x": 0.1,
                "y": 0.1,
                "width": 0.2,
                "height": 0.1,
            }
        ],
        "events": [],
    }


def _wire_state(state):
    def _append_packet_event(**kwargs):
        state["events"].append({**kwargs})
        return kwargs

    def _get_packet(packet_id: str):
        return state["packet"] if packet_id == state["packet"]["packet_id"] else None

    def _get_signer(packet_id: str, signer_id: str):
        for s in state["signers"]:
            if s["packet_id"] == packet_id and s["signer_id"] == signer_id:
                return s
        return None

    def _list_signers(packet_id: str):
        return [deepcopy(s) for s in state["signers"] if s["packet_id"] == packet_id]

    def _list_fields(packet_id: str):
        return [deepcopy(f) for f in state["fields"] if f["packet_id"] == packet_id]

    def _get_field(packet_id: str, field_id: str):
        for f in state["fields"]:
            if f["packet_id"] == packet_id and f["field_id"] == field_id:
                return deepcopy(f)
        return None

    def _mark_sent(packet_id: str):
        state["packet"]["status"] = "sent"
        state["packet"]["sent_at"] = "2026-01-01T00:05:00+00:00"
        return deepcopy(state["packet"])

    def _fill_field(*, packet_id: str, field_id: str, value: str, filled_by_signer_id: str, **kwargs):
        for f in state["fields"]:
            if f["packet_id"] == packet_id and f["field_id"] == field_id:
                f["value"] = value
                f["filled_at"] = "2026-01-01T00:06:00+00:00"
                f["filled_by_signer_id"] = filled_by_signer_id
                return deepcopy(f)
        raise AssertionError("field not found")

    def _mark_signer_completed(packet_id: str, signer_id: str, **kwargs):
        signer = _get_signer(packet_id, signer_id)
        signer["status"] = "completed"
        signer["completed_at"] = "2026-01-01T00:07:00+00:00"
        return deepcopy(signer)

    def _are_required_signers_completed(packet_id: str):
        required = [s for s in state["signers"] if s["packet_id"] == packet_id and s.get("required", True)]
        return all(s.get("status") == "completed" for s in required)

    def _mark_packet_completed(packet_id: str):
        if state["packet"]["status"] == "completed":
            return None
        state["packet"]["status"] = "completed"
        state["packet"]["completed_at"] = "2026-01-01T00:08:00+00:00"
        return deepcopy(state["packet"])

    def _mark_packet_partially_signed(packet_id: str):
        if state["packet"]["status"] in {"sent", "partially_signed"}:
            state["packet"]["status"] = "partially_signed"
            return deepcopy(state["packet"])
        return None

    return {
        "append": _append_packet_event,
        "get_packet": _get_packet,
        "get_signer": _get_signer,
        "list_signers": _list_signers,
        "list_fields": _list_fields,
        "get_field": _get_field,
        "mark_sent": _mark_sent,
        "fill": _fill_field,
        "mark_signer_completed": _mark_signer_completed,
        "all_required_done": _are_required_signers_completed,
        "mark_completed": _mark_packet_completed,
        "mark_partial": _mark_packet_partially_signed,
    }


def test_integration_single_signer_completion_flow():
    state = _base_state(multi_signer=False)
    fx = _wire_state(state)

    with (
        patch.object(routes, "get_packet", side_effect=fx["get_packet"]),
        patch.object(routes, "list_packet_signers", side_effect=fx["list_signers"]),
        patch.object(routes, "list_packet_fields", side_effect=fx["list_fields"]),
        patch.object(routes, "mark_packet_sent", side_effect=fx["mark_sent"]),
        patch.object(routes, "append_packet_event", side_effect=fx["append"]),
        patch.object(routes, "get_packet_signer", side_effect=fx["get_signer"]),
        patch.object(routes, "get_packet_field", side_effect=fx["get_field"]),
        patch.object(routes, "fill_packet_field", side_effect=fx["fill"]),
        patch.object(routes, "mark_signer_completed", side_effect=fx["mark_signer_completed"]),
        patch.object(routes, "are_required_signers_completed", side_effect=fx["all_required_done"]),
        patch.object(routes, "mark_packet_completed", side_effect=fx["mark_completed"]),
        patch.object(routes, "mark_packet_partially_signed", side_effect=fx["mark_partial"]),
        patch.object(routes, "mark_completion_notices_sent", return_value=True),
        patch.object(routes, "_signer_requires_legal_notice_ack", return_value=False),
    ):
        send = routes.send_signature_packet("sp_1", user_sub="owner-1")
        assert send["status"] == "sent"

        fill = routes.fill_signature_packet_field(
            "sp_1",
            "sf_1",
            routes.SignaturePacketFieldFillIn(value="Jane Sender"),
            user_sub="signer-1",
        )
        assert fill["filled_by_signer_id"] == "signer-1"

        done = routes.mark_signature_packet_done("sp_1", user_sub="signer-1")
        assert done["packet_status"] == "completed"

    event_types = [e["event_type"] for e in state["events"]]
    assert "packet_sent" in event_types
    assert "field_filled" in event_types
    assert "signer_completed" in event_types
    assert "packet_completed" in event_types


def test_integration_multi_signer_completion_gate_blocks_early_completion():
    state = _base_state(multi_signer=True)
    state["fields"].append(
        {
            "packet_id": "sp_1",
            "field_id": "sf_2",
            "field_type": "signature",
            "required": True,
            "assigned_signer_id": "signer-2",
            "filled_at": "2026-01-01T00:06:30+00:00",
            "page": 1,
            "x": 0.2,
            "y": 0.2,
            "width": 0.2,
            "height": 0.1,
        }
    )
    state["packet"]["status"] = "sent"
    state["fields"][0]["filled_at"] = "2026-01-01T00:06:00+00:00"

    fx = _wire_state(state)
    with (
        patch.object(routes, "get_packet", side_effect=fx["get_packet"]),
        patch.object(routes, "get_packet_signer", side_effect=fx["get_signer"]),
        patch.object(routes, "list_packet_fields", side_effect=fx["list_fields"]),
        patch.object(routes, "mark_signer_completed", side_effect=fx["mark_signer_completed"]),
        patch.object(routes, "are_required_signers_completed", side_effect=fx["all_required_done"]),
        patch.object(routes, "mark_packet_completed", side_effect=fx["mark_completed"]),
        patch.object(routes, "mark_packet_partially_signed", side_effect=fx["mark_partial"]),
        patch.object(routes, "append_packet_event", side_effect=fx["append"]),
        patch.object(routes, "list_packet_signers", side_effect=fx["list_signers"]),
        patch.object(routes, "mark_completion_notices_sent", return_value=True),
        patch.object(routes, "_signer_requires_legal_notice_ack", return_value=False),
    ):
        first = routes.mark_signature_packet_done("sp_1", user_sub="signer-1")
        assert first["packet_status"] == "partially_signed"
        assert state["packet"]["status"] == "partially_signed"

        second = routes.mark_signature_packet_done("sp_1", user_sub="signer-2")
        assert second["packet_status"] == "completed"
        assert state["packet"]["status"] == "completed"


def test_integration_authorization_boundaries_non_participant_blocked():
    packet = {"packet_id": "sp_1", "owner_user_id": "owner-1", "status": "sent"}
    with (
        patch.object(routes, "get_packet", return_value=packet),
        patch.object(routes, "get_packet_signer", return_value=None),
        patch.object(routes, "append_packet_event"),
    ):
        with pytest.raises(HTTPException) as detail_exc:
            routes.get_signature_packet_detail("sp_1", user_sub="intruder")
        with pytest.raises(HTTPException) as events_exc:
            routes.get_signature_packet_events("sp_1", user_sub="intruder")

    assert detail_exc.value.status_code == 403
    assert events_exc.value.status_code == 403


def test_integration_share_and_message_origin_packet_created_event_payloads():
    created = []
    events = []

    def _create_draft_packet(**kwargs):
        packet = {
            "packet_id": f"sp_{len(created)+1}",
            "status": "draft",
            "owner_user_id": kwargs["owner_user_id"],
            "source_path": kwargs["source_path"],
            "origin_channel": kwargs["origin_channel"],
            "origin_ref": kwargs.get("origin_ref"),
            "created_at": "2026-01-01T00:00:00+00:00",
        }
        created.append(packet)
        return packet

    def _append_packet_event(**kwargs):
        events.append(kwargs)
        return kwargs

    with (
        patch.object(routes, "get_node", return_value={"type": "file", "content_type": "application/pdf", "name": "nda.pdf"}),
        patch.object(routes, "create_draft_packet", side_effect=_create_draft_packet),
        patch.object(routes, "append_packet_event", side_effect=_append_packet_event),
    ):
        routes.create_signature_packet(
            routes.CreateSignaturePacketIn(source_path="/nda.pdf", origin_channel="share", origin_ref="shr-7"),
            user_sub="owner-1",
        )
        routes.create_signature_packet(
            routes.CreateSignaturePacketIn(source_path="/nda.pdf", origin_channel="message", origin_ref="msg-9"),
            user_sub="owner-1",
        )

    payloads = [e["event_payload"] for e in events if e["event_type"] == "packet_created"]
    assert {p["origin_channel"] for p in payloads} == {"share", "message"}
    assert {p["origin_ref"] for p in payloads} == {"shr-7", "msg-9"}
