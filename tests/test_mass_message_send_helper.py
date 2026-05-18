from __future__ import annotations

from unittest.mock import patch

from app.routers import messaging


def test_send_single_destination_message_applies_delivery_effects() -> None:
    message_item = {"conversation_id": "c_1", "message_id": "m_1", "sender_id": "u_1", "kind": "text", "text": "hello"}
    participants = [{"user_id": "u_1", "status": "active"}, {"user_id": "u_2", "status": "active"}]
    with (
        patch.object(messaging, "_bump_unread_counts") as bump,
        patch.object(messaging, "_record_delivery_receipts") as receipts,
        patch.object(messaging, "index_message_search") as index_search,
        patch.object(messaging, "_put_message_consumption_records") as put_consumption,
        patch.object(messaging, "fanout_event_to_conversation") as fanout,
        patch.object(messaging, "tbl_convos") as tbl_convos,
        patch.object(messaging, "_serialize_message_event_payload", return_value={"message_id": "m_1"}),
    ):
        messaging._send_single_destination_message(
            conversation_id="c_1",
            sender_id="u_1",
            message_id="m_1",
            created_at=123,
            message_item=message_item,
            participants=participants,
            is_scheduled=False,
            preview_text="hello",
            search_text="hello",
            search_kind="text",
            consumption_policy="delete_after_read",
            media_kind="image",
        )

    bump.assert_called_once_with("c_1", "u_1", participants)
    receipts.assert_called_once_with("c_1", "m_1", "u_1", participants)
    index_search.assert_called_once_with("c_1", "m_1", "u_1", 123, "hello", kind="text")
    put_consumption.assert_called_once()
    tbl_convos.update_item.assert_called_once()
    fanout.assert_called_once()


def test_send_single_destination_message_is_noop_for_scheduled() -> None:
    with (
        patch.object(messaging, "_bump_unread_counts") as bump,
        patch.object(messaging, "_record_delivery_receipts") as receipts,
        patch.object(messaging, "index_message_search") as index_search,
        patch.object(messaging, "_put_message_consumption_records") as put_consumption,
        patch.object(messaging, "fanout_event_to_conversation") as fanout,
        patch.object(messaging, "tbl_convos") as tbl_convos,
    ):
        messaging._send_single_destination_message(
            conversation_id="c_1",
            sender_id="u_1",
            message_id="m_1",
            created_at=123,
            message_item={"kind": "text", "text": "hello"},
            participants=[],
            is_scheduled=True,
            preview_text="hello",
            search_text="hello",
            search_kind="text",
        )

    bump.assert_not_called()
    receipts.assert_not_called()
    index_search.assert_not_called()
    put_consumption.assert_not_called()
    tbl_convos.update_item.assert_not_called()
    fanout.assert_not_called()


def test_send_mass_message_destination_uses_shared_single_destination_helper() -> None:
    message_item = {"kind": "text", "text": "campaign body"}
    participants = [{"user_id": "u_2", "status": "active"}]
    with patch.object(messaging, "_send_single_destination_message") as helper:
        messaging._send_mass_message_destination(
            conversation_id="c_1",
            sender_id="u_1",
            message_id="m_1",
            created_at=123,
            message_item=message_item,
            participants=participants,
            preview_text="campaign body",
        )

    helper.assert_called_once()
    kwargs = helper.call_args.kwargs
    assert kwargs["conversation_id"] == "c_1"
    assert kwargs["sender_id"] == "u_1"
    assert kwargs["message_id"] == "m_1"
    assert kwargs["is_scheduled"] is False
    assert kwargs["search_text"] == "campaign body"
    assert kwargs["search_kind"] == "text"
