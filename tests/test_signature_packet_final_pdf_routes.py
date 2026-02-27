from __future__ import annotations

import base64
from unittest.mock import patch

import pytest
from fastapi import HTTPException

from app.routers import signature_packets as routes


def test_get_final_pdf_allows_owner_participant_download() -> None:
    pdf = b"%PDF-1.4\n%%EOF"
    with (
        patch.object(routes, "get_packet", return_value={"packet_id": "sp_1", "owner_user_id": "owner-1", "status": "completed"}),
        patch.object(routes, "get_packet_signer", return_value=None),
        patch.object(
            routes,
            "get_packet_artifact",
            return_value={"packet_id": "sp_1", "status": "ready", "final_pdf_base64": base64.b64encode(pdf).decode("ascii"), "sha256": "abc"},
        ),
        patch.object(routes, "append_packet_event") as event_mock,
    ):
        resp = routes.get_signature_packet_final_pdf("sp_1", user_sub="owner-1")

    assert resp.status_code == 200
    assert resp.media_type == "application/pdf"
    assert resp.body == pdf
    assert resp.headers["x-signature-packet-sha256"] == "abc"
    assert event_mock.call_args.kwargs["event_type"] == "packet_final_pdf_downloaded"


def test_get_final_pdf_allows_signer_participant_download() -> None:
    pdf = b"%PDF-1.4\n%%EOF"
    with (
        patch.object(routes, "get_packet", return_value={"packet_id": "sp_1", "owner_user_id": "owner-1", "status": "completed"}),
        patch.object(routes, "get_packet_signer", return_value={"signer_id": "user-2", "status": "completed"}),
        patch.object(
            routes,
            "get_packet_artifact",
            return_value={"packet_id": "sp_1", "status": "ready", "final_pdf_base64": base64.b64encode(pdf).decode("ascii"), "sha256": "abc"},
        ),
        patch.object(routes, "append_packet_event") as event_mock,
    ):
        resp = routes.get_signature_packet_final_pdf("sp_1", user_sub="user-2")

    assert resp.status_code == 200
    assert resp.body == pdf
    assert event_mock.call_args.kwargs["event_type"] == "packet_final_pdf_downloaded"


def test_get_final_pdf_denies_non_participant() -> None:
    with (
        patch.object(routes, "get_packet", return_value={"packet_id": "sp_1", "owner_user_id": "owner-1", "status": "completed"}),
        patch.object(routes, "get_packet_signer", return_value=None),
    ):
        with pytest.raises(HTTPException) as exc:
            routes.get_signature_packet_final_pdf("sp_1", user_sub="intruder")

    assert exc.value.status_code == 403
    assert exc.value.detail["code"] == "signature_packet_not_participant"


def test_get_final_pdf_rejects_when_not_completed() -> None:
    with (
        patch.object(routes, "get_packet", return_value={"packet_id": "sp_1", "owner_user_id": "owner-1", "status": "sent"}),
        patch.object(routes, "get_packet_signer", return_value=None),
    ):
        with pytest.raises(HTTPException) as exc:
            routes.get_signature_packet_final_pdf("sp_1", user_sub="owner-1")

    assert exc.value.status_code == 409
    assert exc.value.detail["code"] == "signature_packet_not_completed"
