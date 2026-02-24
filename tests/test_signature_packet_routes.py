from __future__ import annotations

from unittest.mock import patch

import pytest
from fastapi import HTTPException

from app.routers import signature_packets as routes


def test_create_signature_packet_creates_draft_for_pdf() -> None:
    with (
        patch.object(routes, "get_node", return_value={"type": "file", "content_type": "application/pdf", "name": "nda.pdf"}),
        patch.object(
            routes,
            "create_draft_packet",
            return_value={
                "packet_id": "sp_123",
                "status": "draft",
                "owner_user_id": "user-1",
                "source_path": "/nda.pdf",
                "origin_channel": "share",
                "origin_ref": "share-1",
                "created_at": "2026-01-01T00:00:00+00:00",
            },
        ) as create_mock,
        patch.object(routes, "append_packet_event") as event_mock,
    ):
        out = routes.create_signature_packet(
            routes.CreateSignaturePacketIn(source_path="/nda.pdf", origin_channel="share", origin_ref="share-1"),
            user_sub="user-1",
        )

    assert out["packet_id"] == "sp_123"
    assert out["status"] == "draft"
    create_mock.assert_called_once_with(
        owner_user_id="user-1",
        source_path="/nda.pdf",
        source_content_type="application/pdf",
        source_name="nda.pdf",
        origin_channel="share",
        origin_ref="share-1",
    )
    event_mock.assert_called_once()
    assert event_mock.call_args.kwargs["event_type"] == "packet_created"


def test_create_signature_packet_rejects_non_pdf_upload() -> None:
    with patch.object(routes, "get_node", return_value={"type": "file", "content_type": "text/plain", "name": "notes.txt"}):
        with pytest.raises(HTTPException) as exc:
            routes.create_signature_packet(
                routes.CreateSignaturePacketIn(source_path="/notes.txt", origin_channel="message"),
                user_sub="user-1",
            )

    assert exc.value.status_code == 400
    assert exc.value.detail["code"] == "invalid_source_file_type"
    assert exc.value.detail["expected_content_type"] == "application/pdf"


def test_create_signature_packet_rejects_non_file_source() -> None:
    with patch.object(routes, "get_node", return_value={"type": "folder"}):
        with pytest.raises(HTTPException) as exc:
            routes.create_signature_packet(
                routes.CreateSignaturePacketIn(source_path="/docs/", origin_channel="share"),
                user_sub="user-1",
            )

    assert exc.value.status_code == 400
    assert exc.value.detail["code"] == "invalid_source_file"
