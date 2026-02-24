from unittest.mock import Mock, patch

from app.routers import filemanager, messaging


def test_share_fs_node_accepts_signature_packet_id():
    with patch.object(filemanager, "share_node") as share_node:
        resp = filemanager.share_fs_node(path="/a", to_user="bob", signature_packet_id="sp_123", user="user")

    assert resp["ok"] is True
    share_node.assert_called_once_with(
        "user",
        "/a",
        "bob",
        permission="read",
        expires_at=None,
        signature_packet_id="sp_123",
    )


def test_create_file_message_persists_signature_packet_id():
    tbl_msgs = Mock()
    tbl_convos = Mock()
    tbl_parts = Mock()
    tbl_parts.query.return_value = {"Items": [{"user_id": "u1"}, {"user_id": "u2"}]}

    with (
        patch.object(messaging, "require_participant_active"),
        patch.object(messaging, "_get_conversation_or_404", return_value={}),
        patch.object(messaging, "_enforce_helpdesk_send_constraints"),
        patch.object(messaging, "require_subscription_access"),
        patch.object(messaging, "_enforce_message_send_quota_precheck"),
        patch.object(messaging, "_validate_reply_target"),
        patch.object(messaging, "norm_path", return_value="/a.pdf"),
        patch.object(
            messaging,
            "get_node",
            return_value={
                "type": "file",
                "path": "/a.pdf",
                "name": "a.pdf",
                "size": 10,
                "content_type": "application/pdf",
            },
        ),
        patch.object(messaging, "new_id", return_value="file"),
        patch.object(messaging, "now_ts", return_value=10),
        patch.object(messaging, "tbl_parts", tbl_parts),
        patch.object(messaging, "tbl_msgs", tbl_msgs),
        patch.object(messaging, "tbl_convos", tbl_convos),
        patch.object(messaging, "_sync_gallery_index_message"),
        patch.object(messaging, "_bump_unread_counts"),
        patch.object(messaging, "_record_delivery_receipts"),
        patch.object(messaging, "_put_message_consumption_records"),
        patch.object(messaging, "_meter_message_send"),
    ):
        messaging.create_file_message(
            "c1",
            messaging.CreateFileMessageIn(path="/a.pdf", signature_packet_id="sp_123"),
            user_id="u1",
        )

    persisted = tbl_msgs.put_item.call_args.kwargs["Item"]
    assert persisted["file"]["signature_packet_id"] == "sp_123"
