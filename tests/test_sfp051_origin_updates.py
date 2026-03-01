from unittest.mock import Mock, patch

from app.routers import messaging
from app.services import filemanager
from app.services.signature_packet_store import get_signature_packet_progress_for_user


def test_signature_packet_progress_for_signer_and_completed_download_url():
    with (
        patch("app.services.signature_packet_store.require_signature_pdf_enabled"),
        patch("app.services.signature_packet_store.get_packet", return_value={"packet_id": "sp_1", "owner_user_id": "owner", "status": "completed", "completed_at": "2026-01-01T00:00:00+00:00"}),
        patch("app.services.signature_packet_store.get_packet_signer", return_value={"signer_id": "signer", "status": "completed"}),
        patch("app.services.signature_packet_store.get_packet_artifact", return_value={"status": "ready"}),
    ):
        progress = get_signature_packet_progress_for_user("sp_1", "signer")

    assert progress is not None
    assert progress["signature_packet_status_chip"] == "completed"
    assert progress["signature_packet_final_pdf_url"] == "/v1/signature-packets/sp_1/final-pdf"


def test_list_shared_with_me_includes_signature_packet_progress_metadata():
    tbl = Mock()
    tbl.query.return_value = {
        "Items": [
            {
                "owner": "alice",
                "path": "/a.pdf",
                "shared_at": "now",
                "permission": "read",
                "signature_packet_id": "sp_1",
            }
        ]
    }
    with (
        patch.object(filemanager, "_table", return_value=tbl),
        patch.object(filemanager, "get_node", return_value={"type": "file", "name": "a.pdf", "size": 1, "content_type": "application/pdf"}),
        patch.object(filemanager, "_signature_packet_progress", return_value={"signature_packet_status_chip": "awaiting_your_signature", "signature_packet_status_text": "Awaiting your signature"}) as progress_fn,
    ):
        items = filemanager.list_shared_with_me("bob")

    assert items[0]["signature_packet_status_chip"] == "awaiting_your_signature"
    progress_fn.assert_called_once_with("sp_1", "bob")


def test_message_projection_includes_signature_packet_progress_metadata():
    message_item = {
        "conversation_id": "c1",
        "message_id": "m1",
        "sender_id": "u1",
        "created_at": 10,
        "kind": "file",
        "file": {"path": "/a.pdf", "signature_packet_id": "sp_1"},
        "reactions": {},
        "deleted_for": [],
    }

    with (
        patch.object(messaging, "_merge_consumption_state", return_value=dict(message_item)),
        patch.object(messaging, "_reaction_summaries", return_value=({}, [])),
        patch.object(messaging, "_project_message_sender_id", return_value="u1"),
        patch.object(messaging, "get_signature_packet_progress_for_user", return_value={"signature_packet_status_chip": "waiting_on_others", "signature_packet_status_text": "Waiting on others", "signature_packet_final_pdf_url": "/v1/signature-packets/sp_1/final-pdf"}),
    ):
        out = messaging._message_out_from_item(message_item, "u2")

    assert out.file is not None
    assert out.file["signature_packet_status_chip"] == "waiting_on_others"
    assert out.file["signature_packet_final_pdf_url"] == "/v1/signature-packets/sp_1/final-pdf"
