from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

import pytest
from botocore.exceptions import ClientError
from fastapi import HTTPException

from app.routers import messaging


def test_first_direct_reply_keeps_compat_and_parent_without_promotion() -> None:
    parent = {"conversation_id": "c1", "message_id": "m_root"}
    with (
        patch.object(messaging, "_get_message_or_404", return_value=parent),
        patch.object(messaging, "_resolve_thread_root_message_id", return_value="m_root"),
        patch.object(messaging, "_count_direct_replies", return_value=0),
        patch.object(messaging, "find_thread_for_root_message", return_value=None),
        patch.object(messaging, "create_message_thread_record") as create_thread,
        patch.object(messaging, "_promote_existing_subtree") as promote_subtree,
    ):
        out = messaging._build_reply_linkage_fields(
            conversation_id="c1",
            reply_to_message_id="m_root",
            actor_user_id="u1",
            created_at=123,
        )

    assert out["reply_to_message_id"] == "m_root"
    assert out["parent_message_id"] == "m_root"
    assert "thread_id" not in out
    assert "thread_root_message_id" not in out
    create_thread.assert_not_called()
    promote_subtree.assert_not_called()


def test_first_direct_reply_records_no_promotion_metric() -> None:
    parent = {"conversation_id": "c1", "message_id": "m_root"}
    with (
        patch.object(messaging, "_get_message_or_404", return_value=parent),
        patch.object(messaging, "_resolve_thread_root_message_id", return_value="m_root"),
        patch.object(messaging, "_count_direct_replies", return_value=0),
        patch.object(messaging, "find_thread_for_root_message", return_value=None),
        patch.object(messaging, "record_messaging_thread_promotion_event") as rec_metric,
    ):
        messaging._build_reply_linkage_fields(
            conversation_id="c1",
            reply_to_message_id="m_root",
            actor_user_id="u1",
            created_at=123,
        )

    assert any(
        c.kwargs.get("stage") == "linkage" and c.kwargs.get("outcome") == "no_promotion"
        for c in rec_metric.call_args_list
    )


def test_second_direct_reply_promotes_and_assigns_stable_thread_id() -> None:
    parent = {"conversation_id": "c1", "message_id": "m_root"}
    with (
        patch.object(messaging, "_get_message_or_404", return_value=parent),
        patch.object(messaging, "_resolve_thread_root_message_id", return_value="m_root"),
        patch.object(messaging, "_count_direct_replies", return_value=1),
        patch.object(messaging, "find_thread_for_root_message", return_value=None),
        patch.object(messaging, "create_message_thread_record", return_value=SimpleNamespace(id="thr_m_root")) as create_thread,
        patch.object(messaging, "_promote_existing_subtree") as promote_subtree,
    ):
        out = messaging._build_reply_linkage_fields(
            conversation_id="c1",
            reply_to_message_id="m_root",
            actor_user_id="u1",
            created_at=456,
        )

    assert out["thread_id"] == "thr_m_root"
    assert out["thread_root_message_id"] == "m_root"
    create_thread.assert_called_once_with(
        thread_id="thr_m_root",
        conversation_id="c1",
        root_message_id="m_root",
        created_at=456,
        created_by="u1",
    )
    promote_subtree.assert_called_once_with("c1", "m_root", "thr_m_root")


def test_second_direct_reply_records_promoted_metric() -> None:
    parent = {"conversation_id": "c1", "message_id": "m_root"}
    with (
        patch.object(messaging, "_get_message_or_404", return_value=parent),
        patch.object(messaging, "_resolve_thread_root_message_id", return_value="m_root"),
        patch.object(messaging, "_count_direct_replies", return_value=1),
        patch.object(messaging, "find_thread_for_root_message", return_value=None),
        patch.object(messaging, "create_message_thread_record", return_value=SimpleNamespace(id="thr_m_root")),
        patch.object(messaging, "_promote_existing_subtree"),
        patch.object(messaging, "record_messaging_thread_promotion_event") as rec_metric,
    ):
        messaging._build_reply_linkage_fields(
            conversation_id="c1",
            reply_to_message_id="m_root",
            actor_user_id="u1",
            created_at=456,
        )

    assert any(
        c.kwargs.get("stage") == "linkage" and c.kwargs.get("outcome") == "promoted"
        for c in rec_metric.call_args_list
    )


def test_second_direct_reply_rollout_disabled_skips_promotion(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MESSAGING_THREAD_PROMOTION_MODE", "disabled")
    parent = {"conversation_id": "c1", "message_id": "m_root"}
    with (
        patch.object(messaging, "_get_message_or_404", return_value=parent),
        patch.object(messaging, "_resolve_thread_root_message_id", return_value="m_root"),
        patch.object(messaging, "_count_direct_replies", return_value=1),
        patch.object(messaging, "create_message_thread_record") as create_thread,
        patch.object(messaging, "_promote_existing_subtree") as promote_subtree,
        patch.object(messaging, "record_messaging_thread_promotion_event") as rec_metric,
    ):
        out = messaging._build_reply_linkage_fields(
            conversation_id="c1",
            reply_to_message_id="m_root",
            actor_user_id="u1",
            created_at=456,
        )

    assert "thread_id" not in out
    assert "thread_root_message_id" not in out
    create_thread.assert_not_called()
    promote_subtree.assert_not_called()
    assert any(
        c.kwargs.get("stage") == "linkage" and c.kwargs.get("outcome") == "rollout_disabled"
        for c in rec_metric.call_args_list
    )


def test_second_direct_reply_rollout_selective_promotes_enabled_tenant(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MESSAGING_THREAD_PROMOTION_MODE", "selective")
    monkeypatch.setenv("MESSAGING_THREAD_PROMOTION_ENABLED_TENANT_IDS", "tenant-a")
    parent = {"conversation_id": "c1", "message_id": "m_root"}
    with (
        patch.object(messaging, "_get_message_or_404", return_value=parent),
        patch.object(messaging, "_resolve_thread_root_message_id", return_value="m_root"),
        patch.object(messaging, "_count_direct_replies", return_value=1),
        patch.object(messaging, "_resolve_user_tenant_id", return_value="tenant-a"),
        patch.object(messaging, "find_thread_for_root_message", return_value=None),
        patch.object(messaging, "create_message_thread_record", return_value=SimpleNamespace(id="thr_m_root")) as create_thread,
        patch.object(messaging, "_promote_existing_subtree") as promote_subtree,
    ):
        out = messaging._build_reply_linkage_fields(
            conversation_id="c1",
            reply_to_message_id="m_root",
            actor_user_id="u1",
            created_at=456,
        )

    assert out["thread_id"] == "thr_m_root"
    assert out["thread_root_message_id"] == "m_root"
    create_thread.assert_called_once()
    promote_subtree.assert_called_once_with("c1", "m_root", "thr_m_root")


def test_reply_to_reply_promotes_even_without_second_direct_reply() -> None:
    parent = {"conversation_id": "c1", "message_id": "m_child", "parent_message_id": "m_root"}
    with (
        patch.object(messaging, "_get_message_or_404", return_value=parent),
        patch.object(messaging, "_resolve_thread_root_message_id", return_value="m_root"),
        patch.object(messaging, "_count_direct_replies", return_value=0),
        patch.object(messaging, "find_thread_for_root_message", return_value=SimpleNamespace(id="thr_m_root")),
        patch.object(messaging, "_promote_existing_subtree") as promote_subtree,
    ):
        out = messaging._build_reply_linkage_fields(
            conversation_id="c1",
            reply_to_message_id="m_child",
            actor_user_id="u1",
            created_at=789,
        )

    assert out["thread_id"] == "thr_m_root"
    assert out["thread_root_message_id"] == "m_root"
    promote_subtree.assert_called_once_with("c1", "m_root", "thr_m_root")


def test_existing_parent_thread_is_reused_without_new_creation() -> None:
    parent = {
        "conversation_id": "c1",
        "message_id": "m_child",
        "parent_message_id": "m_root",
        "thread_id": "thr_existing",
        "thread_root_message_id": "m_root",
    }
    with (
        patch.object(messaging, "_get_message_or_404", return_value=parent),
        patch.object(
            messaging,
            "get_message_thread_record",
            return_value=SimpleNamespace(id="thr_existing", conversation_id="c1", root_message_id="m_root"),
        ),
        patch.object(messaging, "create_message_thread_record") as create_thread,
        patch.object(messaging, "_promote_existing_subtree") as promote_subtree,
    ):
        out = messaging._build_reply_linkage_fields(
            conversation_id="c1",
            reply_to_message_id="m_child",
            actor_user_id="u1",
            created_at=999,
        )

    assert out["thread_id"] == "thr_existing"
    assert out["thread_root_message_id"] == "m_root"
    create_thread.assert_not_called()
    promote_subtree.assert_not_called()


def test_ensure_thread_record_retries_retryable_conflict_then_returns_existing() -> None:
    retryable = ClientError({"Error": {"Code": "TransactionCanceledException"}}, "TransactWriteItems")
    with (
        patch.object(messaging, "find_thread_for_root_message", side_effect=[None, None, SimpleNamespace(id="thr_m1")]),
        patch.object(messaging, "create_message_thread_record", side_effect=retryable),
    ):
        out = messaging._ensure_thread_record_for_root(
            conversation_id="c1",
            root_message_id="m1",
            actor_user_id="u1",
            created_at=123,
            max_attempts=2,
        )

    assert out.id == "thr_m1"


def test_ensure_thread_record_records_retry_metric_on_retryable_conflict() -> None:
    retryable = ClientError({"Error": {"Code": "TransactionCanceledException"}}, "TransactWriteItems")
    with (
        patch.object(messaging, "find_thread_for_root_message", side_effect=[None, None, SimpleNamespace(id="thr_m1")]),
        patch.object(messaging, "create_message_thread_record", side_effect=retryable),
        patch.object(messaging, "record_messaging_thread_promotion_retry") as retry_metric,
    ):
        messaging._ensure_thread_record_for_root(
            conversation_id="c1",
            root_message_id="m1",
            actor_user_id="u1",
            created_at=123,
            max_attempts=2,
        )

    retry_metric.assert_called()


def test_ensure_thread_record_raises_non_retryable_error() -> None:
    non_retryable = ClientError({"Error": {"Code": "ValidationException"}}, "PutItem")
    with (
        patch.object(messaging, "find_thread_for_root_message", return_value=None),
        patch.object(messaging, "create_message_thread_record", side_effect=non_retryable),
    ):
        with pytest.raises(ClientError):
            messaging._ensure_thread_record_for_root(
                conversation_id="c1",
                root_message_id="m1",
                actor_user_id="u1",
                created_at=123,
                max_attempts=1,
            )


def test_ensure_thread_record_raises_runtime_when_exhausted_without_existing() -> None:
    retryable = ClientError({"Error": {"Code": "TransactionCanceledException"}}, "TransactWriteItems")
    with (
        patch.object(messaging, "find_thread_for_root_message", return_value=None),
        patch.object(messaging, "create_message_thread_record", side_effect=retryable),
    ):
        with pytest.raises(RuntimeError) as exc:
            messaging._ensure_thread_record_for_root(
                conversation_id="c1",
                root_message_id="m1",
                actor_user_id="u1",
                created_at=123,
                max_attempts=2,
            )
    assert "Failed to resolve thread record for root=m1" in str(exc.value)


def test_competing_attempts_reuse_single_stable_thread_id() -> None:
    parent = {"conversation_id": "c1", "message_id": "m_root"}
    with (
        patch.object(messaging, "_get_message_or_404", return_value=parent),
        patch.object(messaging, "_resolve_thread_root_message_id", return_value="m_root"),
        patch.object(messaging, "_count_direct_replies", return_value=1),
        patch.object(
            messaging,
            "find_thread_for_root_message",
            side_effect=[None, SimpleNamespace(id="thr_m_root"), SimpleNamespace(id="thr_m_root"), SimpleNamespace(id="thr_m_root")],
        ),
        patch.object(messaging, "create_message_thread_record", return_value=SimpleNamespace(id="thr_m_root")) as create_thread,
        patch.object(messaging, "_promote_existing_subtree"),
    ):
        first = messaging._build_reply_linkage_fields(
            conversation_id="c1",
            reply_to_message_id="m_root",
            actor_user_id="u1",
            created_at=100,
        )
        second = messaging._build_reply_linkage_fields(
            conversation_id="c1",
            reply_to_message_id="m_root",
            actor_user_id="u2",
            created_at=101,
        )

    assert first["thread_id"] == "thr_m_root"
    assert second["thread_id"] == "thr_m_root"
    create_thread.assert_called_once()


def test_existing_parent_thread_validation_rejects_cross_conversation_thread() -> None:
    parent = {
        "conversation_id": "c1",
        "message_id": "m_child",
        "thread_id": "thr_foreign",
        "thread_root_message_id": "m_root",
    }
    thread = SimpleNamespace(id="thr_foreign", conversation_id="c_other", root_message_id="m_root")
    with (
        patch.object(messaging, "_get_message_or_404", return_value=parent),
        patch.object(messaging, "get_message_thread_record", return_value=thread),
    ):
        with pytest.raises(HTTPException) as exc:
            messaging._build_reply_linkage_fields(
                conversation_id="c1",
                reply_to_message_id="m_child",
                actor_user_id="u1",
                created_at=999,
            )

    assert exc.value.status_code == 400
    assert exc.value.detail == "Reply target thread is not in this conversation"


def test_existing_parent_thread_validation_rejects_root_mismatch() -> None:
    parent = {
        "conversation_id": "c1",
        "message_id": "m_child",
        "thread_id": "thr_existing",
        "thread_root_message_id": "m_declared",
    }
    thread = SimpleNamespace(id="thr_existing", conversation_id="c1", root_message_id="m_actual")
    with (
        patch.object(messaging, "_get_message_or_404", return_value=parent),
        patch.object(messaging, "get_message_thread_record", return_value=thread),
    ):
        with pytest.raises(HTTPException) as exc:
            messaging._build_reply_linkage_fields(
                conversation_id="c1",
                reply_to_message_id="m_child",
                actor_user_id="u1",
                created_at=1000,
            )

    assert exc.value.status_code == 409
    assert exc.value.detail == "Reply target thread root mismatch"


def test_resolve_thread_root_rejects_cross_conversation_ancestry() -> None:
    parent = {
        "conversation_id": "c1",
        "message_id": "m_child",
        "parent_message_id": "m_foreign",
    }
    with patch.object(
        messaging,
        "_load_message_item",
        return_value={"conversation_id": "c_other", "message_id": "m_foreign", "parent_message_id": ""},
    ):
        with pytest.raises(HTTPException) as exc:
            messaging._resolve_thread_root_message_id("c1", parent)

    assert exc.value.status_code == 400
    assert exc.value.detail == "Reply target ancestry crosses conversations"


def test_resolve_thread_root_rejects_missing_ancestor() -> None:
    parent = {
        "conversation_id": "c1",
        "message_id": "m_child",
        "parent_message_id": "m_missing",
    }
    with patch.object(messaging, "_load_message_item", return_value=None):
        with pytest.raises(HTTPException) as exc:
            messaging._resolve_thread_root_message_id("c1", parent)

    assert exc.value.status_code == 400
    assert exc.value.detail == "Reply target ancestry is invalid"


def test_resolve_thread_root_rejects_cycle() -> None:
    parent = {
        "conversation_id": "c1",
        "message_id": "m1",
        "parent_message_id": "m2",
    }

    def _load(_conversation_id: str, message_id: str):
        if message_id == "m1":
            return {"conversation_id": "c1", "message_id": "m1", "parent_message_id": "m2"}
        return {"conversation_id": "c1", "message_id": "m2", "parent_message_id": "m1"}

    with patch.object(messaging, "_load_message_item", side_effect=_load):
        with pytest.raises(HTTPException) as exc:
            messaging._resolve_thread_root_message_id("c1", parent)

    assert exc.value.status_code == 400
    assert exc.value.detail == "Reply target ancestry contains a cycle"
