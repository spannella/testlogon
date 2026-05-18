from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import Mock, patch

from app.services import messaging_thread_backfill as svc


def _conversation_items_without_thread_fields() -> list[dict]:
    return [
        {"conversation_id": "c1", "message_id": "m1", "created_at": 1, "sender_id": "u1", "kind": "text"},
        {"conversation_id": "c1", "message_id": "m2", "created_at": 2, "sender_id": "u2", "kind": "text", "parent_message_id": "m1", "reply_to_message_id": "m1"},
        {"conversation_id": "c1", "message_id": "m3", "created_at": 3, "sender_id": "u3", "kind": "text", "parent_message_id": "m1", "reply_to_message_id": "m1"},
        {"conversation_id": "c1", "message_id": "m4", "created_at": 4, "sender_id": "u4", "kind": "text", "parent_message_id": "m2", "reply_to_message_id": "m2"},
    ]


def test_reconcile_promotes_historical_reply_tree_and_updates_subtree() -> None:
    items = _conversation_items_without_thread_fields()
    tbl_msgs = Mock()
    with (
        patch.object(svc.messaging, "tbl_msgs", tbl_msgs),
        patch.object(svc, "find_thread_for_root_message", return_value=None),
        patch.object(svc, "create_message_thread_record", return_value=SimpleNamespace(id="thr_m1")) as create_thread,
    ):
        stats = svc.reconcile_conversation_reply_threads("c1", items)

    assert stats.conversations_scanned == 1
    assert stats.eligible_roots == 1
    assert stats.threads_created == 1
    assert stats.messages_updated == 4
    create_thread.assert_called_once_with(
        thread_id="thr_m1",
        conversation_id="c1",
        root_message_id="m1",
        created_at=1,
        created_by="u1",
    )
    updated_ids = {c.kwargs["Key"]["message_id"] for c in tbl_msgs.update_item.call_args_list}
    assert updated_ids == {"m1", "m2", "m3", "m4"}


def test_reconcile_is_idempotent_for_already_correct_data() -> None:
    items = _conversation_items_without_thread_fields()
    for item in items:
        item["thread_id"] = "thr_m1"
        item["thread_root_message_id"] = "m1"

    tbl_msgs = Mock()
    with (
        patch.object(svc.messaging, "tbl_msgs", tbl_msgs),
        patch.object(svc, "find_thread_for_root_message", return_value=SimpleNamespace(id="thr_m1")),
        patch.object(svc, "create_message_thread_record") as create_thread,
    ):
        stats = svc.reconcile_conversation_reply_threads("c1", items)

    assert stats.threads_created == 0
    assert stats.messages_updated == 0
    create_thread.assert_not_called()
    tbl_msgs.update_item.assert_not_called()


def test_run_backfill_for_conversation_aggregates_paged_query_results() -> None:
    tbl_msgs = Mock()
    tbl_msgs.query.side_effect = [
        {"Items": [{"conversation_id": "c1", "message_id": "m1"}], "LastEvaluatedKey": {"k": "1"}},
        {"Items": [{"conversation_id": "c1", "message_id": "m2"}], "LastEvaluatedKey": None},
    ]
    with (
        patch.object(svc.messaging, "tbl_msgs", tbl_msgs),
        patch.object(
            svc,
            "reconcile_conversation_reply_threads",
            return_value=svc.ThreadBackfillStats(conversations_scanned=1, eligible_roots=0, threads_created=0, messages_updated=0),
        ) as reconcile,
    ):
        svc.run_thread_backfill_for_conversation("c1")

    reconcile.assert_called_once()
    passed_items = reconcile.call_args.args[1]
    assert len(passed_items) == 2


def test_root_resolution_records_anomaly_for_missing_ancestor() -> None:
    by_id = {"m2": {"message_id": "m2", "parent_message_id": "m_missing"}}
    with patch.object(svc, "record_messaging_thread_reconciliation_anomaly") as rec_anomaly:
        out = svc._root_for_message("m2", by_id)

    assert out == "m2"
    rec_anomaly.assert_called_once_with(reason="missing_ancestor")
