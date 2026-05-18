from __future__ import annotations

from unittest.mock import patch

from app.routers import messaging


def test_fanout_new_message_event_uses_thread_event_type_for_thread_messages() -> None:
    message_item = {
        "conversation_id": "c1",
        "message_id": "m2",
        "thread_id": "thr_m1",
        "thread_root_message_id": "m1",
    }
    with patch.object(messaging, "fanout_event_to_conversation") as fanout:
        messaging._fanout_new_message_event(
            conversation_id="c1",
            sender_id="u1",
            message_item=message_item,
            payload={"message_id": "m2"},
            respect_mute=False,
        )

    fanout.assert_called_once()
    kwargs = fanout.call_args.kwargs
    assert kwargs["event_type"] == "message:thread_new"
    assert kwargs["payload"]["thread_id"] == "thr_m1"
    assert kwargs["payload"]["thread_root_message_id"] == "m1"
    assert kwargs["payload"]["notification_scope"] == "thread"


def test_fanout_new_message_event_keeps_conversation_event_type_for_non_thread_messages() -> None:
    message_item = {
        "conversation_id": "c1",
        "message_id": "m1",
    }
    with patch.object(messaging, "fanout_event_to_conversation") as fanout:
        messaging._fanout_new_message_event(
            conversation_id="c1",
            sender_id="u1",
            message_item=message_item,
            payload={"message_id": "m1"},
            respect_mute=False,
        )

    fanout.assert_called_once()
    kwargs = fanout.call_args.kwargs
    assert kwargs["event_type"] == "message:new"
    assert kwargs["payload"]["notification_scope"] == "conversation"
