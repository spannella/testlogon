from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from unittest.mock import Mock, patch

from botocore.exceptions import ClientError

from app.routers import messaging


def _retryable_conflict() -> ClientError:
    return ClientError({"Error": {"Code": "TransactionCanceledException"}}, "TransactWriteItems")


def test_parallel_thread_record_resolution_creates_single_thread_per_root() -> None:
    lock = threading.Lock()
    state = {
        "thread": None,
        "successful_creates": 0,
    }

    def find_thread(_root_message_id: str):
        with lock:
            return state["thread"]

    def create_thread(*, thread_id: str, conversation_id: str, root_message_id: str, created_at: int, created_by: str):
        with lock:
            if state["thread"] is not None:
                raise _retryable_conflict()
            state["thread"] = SimpleNamespace(id=thread_id, conversation_id=conversation_id, root_message_id=root_message_id)
            state["successful_creates"] += 1
            return state["thread"]

    with (
        patch.object(messaging, "find_thread_for_root_message", side_effect=find_thread),
        patch.object(messaging, "create_message_thread_record", side_effect=create_thread),
    ):
        def _worker(_idx: int):
            out = messaging._ensure_thread_record_for_root(
                conversation_id="c1",
                root_message_id="m_root",
                actor_user_id="u1",
                created_at=123,
                max_attempts=3,
            )
            return out.id

        with ThreadPoolExecutor(max_workers=12) as pool:
            ids = list(pool.map(_worker, range(50)))

    assert len(set(ids)) == 1
    assert state["successful_creates"] == 1


def test_parallel_reply_promotion_reuses_single_thread_id_under_contention() -> None:
    parent = {"conversation_id": "c1", "message_id": "m_root"}
    lock = threading.Lock()
    state = {
        "thread": None,
        "successful_creates": 0,
    }

    def find_thread(_root_message_id: str):
        with lock:
            return state["thread"]

    def create_thread(*, thread_id: str, conversation_id: str, root_message_id: str, created_at: int, created_by: str):
        with lock:
            if state["thread"] is not None:
                raise _retryable_conflict()
            state["thread"] = SimpleNamespace(id=thread_id, conversation_id=conversation_id, root_message_id=root_message_id)
            state["successful_creates"] += 1
            return state["thread"]

    with (
        patch.object(messaging, "_get_message_or_404", return_value=parent),
        patch.object(messaging, "_resolve_thread_root_message_id", return_value="m_root"),
        patch.object(messaging, "_count_direct_replies", return_value=1),
        patch.object(messaging, "find_thread_for_root_message", side_effect=find_thread),
        patch.object(messaging, "create_message_thread_record", side_effect=create_thread),
        patch.object(messaging, "_promote_existing_subtree"),
    ):
        def _worker(_idx: int):
            out = messaging._build_reply_linkage_fields(
                conversation_id="c1",
                reply_to_message_id="m_root",
                actor_user_id="u1",
                created_at=456,
            )
            return out["thread_id"]

        with ThreadPoolExecutor(max_workers=10) as pool:
            ids = list(pool.map(_worker, range(40)))

    assert len(set(ids)) == 1
    assert state["successful_creates"] == 1


def test_thread_read_query_performance_baseline_under_representative_page_size() -> None:
    thread = SimpleNamespace(id="thr_m1", conversation_id="c1")
    parts_tbl = Mock()
    parts_tbl.query.return_value = {"Items": []}

    raw_items = []
    for i in range(200):
        raw_items.append(
            {
                "conversation_id": "c1",
                "message_id": f"m{i}",
                "sender_id": "u2" if i % 3 else "u1",
                "created_at": i,
                "kind": "text",
                "text": f"msg-{i}",
                "thread_id": "thr_m1",
                "thread_root_message_id": "m0",
                "reactions": {},
            }
        )
    msgs_tbl = Mock()
    msgs_tbl.query.return_value = {"Items": raw_items}

    with (
        patch.object(messaging, "get_message_thread_record", return_value=thread),
        patch.object(messaging, "require_participant_active", return_value={"user_id": "u1", "last_read_at": 150}),
        patch.object(messaging, "tbl_parts", parts_tbl),
        patch.object(messaging, "tbl_msgs", msgs_tbl),
        patch.object(messaging, "_load_hidden_message_ids_for_user", return_value=set()),
        patch.object(
            messaging,
            "_message_out_from_item",
            side_effect=lambda raw, _uid: messaging.MessageOut(
                conversation_id=raw["conversation_id"],
                message_id=raw["message_id"],
                sender_id=raw["sender_id"],
                created_at=raw["created_at"],
                kind="text",
                text=raw["text"],
            ),
        ),
        patch.object(messaging, "_apply_message_receipts", side_effect=lambda msg, *_args: msg),
    ):
        started = time.perf_counter()
        out = messaging.list_thread_messages("thr_m1", limit=200, user_id="u1")
        elapsed = time.perf_counter() - started

    assert len(out.items) == 200
    # Baseline threshold for mocked-path regression guard (kept intentionally generous).
    assert elapsed < 1.0
