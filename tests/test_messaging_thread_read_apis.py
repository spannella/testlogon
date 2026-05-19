from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest
from fastapi import HTTPException

from app.routers import messaging


def _decode_signed_cursor_payload(cursor: str) -> dict:
    payload_b64 = cursor.split(".", 1)[0]
    pad = "=" * ((4 - (len(payload_b64) % 4)) % 4)
    raw = messaging.base64.urlsafe_b64decode((payload_b64 + pad).encode("utf-8"))
    return messaging.json.loads(raw.decode("utf-8"))


def test_safe_int_env_returns_default_and_logs_warning_on_invalid(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("THREAD_CURSOR_TEST_INT", "not-an-int")
    with patch.object(messaging.logger, "warning") as warn:
        out = messaging._safe_int_env("THREAD_CURSOR_TEST_INT", 123)
    assert out == 123
    warn.assert_called_once()


def test_safe_int_env_parses_valid_integer(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("THREAD_CURSOR_TEST_INT", "42")
    assert messaging._safe_int_env("THREAD_CURSOR_TEST_INT", 123) == 42


def test_normalize_cursor_error_reason_sanitizes_non_alnum_chars() -> None:
    reason = messaging._normalize_cursor_error_reason({"message": "bad\ncursor\t\x00value!!"})
    assert reason == "bad?cursor??value??"


def test_normalize_cursor_error_reason_uses_unknown_for_empty_values() -> None:
    assert messaging._normalize_cursor_error_reason({"message": ""}) == "unknown"
    assert messaging._normalize_cursor_error_reason(None) == "unknown"


def test_message_out_includes_thread_summary_metadata_for_threaded_messages() -> None:
    item = {
        "conversation_id": "c1",
        "message_id": "m2",
        "sender_id": "u2",
        "created_at": 20,
        "kind": "text",
        "text": "reply",
        "thread_id": "thr_m1",
        "thread_root_message_id": "m1",
        "reactions": {},
    }
    with (
        patch.object(messaging, "_merge_consumption_state", return_value=item),
        patch.object(messaging, "_reaction_summaries", return_value=({}, [])),
        patch.object(messaging, "_thread_summary", return_value=(3, 20)),
    ):
        out = messaging._message_out_from_item(item, "u1")

    assert out.has_thread is True
    assert out.thread_reply_count == 2
    assert out.thread_last_reply_at == 20


def test_list_thread_messages_returns_paginated_ordered_thread_items() -> None:
    thread = SimpleNamespace(id="thr_m1", conversation_id="c1")
    parts_tbl = Mock()
    parts_tbl.query.return_value = {"Items": []}
    msgs_tbl = Mock()
    msgs_tbl.query.return_value = {
        "Items": [
            {
                "conversation_id": "c1",
                "message_id": "m1",
                "sender_id": "u1",
                "created_at": 10,
                "kind": "text",
                "text": "root",
                "thread_id": "thr_m1",
                "thread_root_message_id": "m1",
                "reactions": {},
            }
        ],
        "LastEvaluatedKey": {"conversation_id": "c1", "message_id": "m1", "thread_id": "thr_m1", "created_at": 10},
    }
    with (
        patch.object(messaging, "get_message_thread_record", return_value=thread),
        patch.object(messaging, "require_participant_active", return_value={"user_id": "u1", "last_read_at": 0}),
        patch.object(messaging, "tbl_parts", parts_tbl),
        patch.object(messaging, "tbl_msgs", msgs_tbl),
        patch.object(messaging, "_load_hidden_message_ids_for_user", return_value=set()),
        patch.object(messaging, "_thread_summary", return_value=(1, 10)),
    ):
        out = messaging.list_thread_messages("thr_m1", limit=10, user_id="u1")

    assert len(out.items) == 1
    assert out.items[0].message_id == "m1"
    assert out.unread_count == 0
    assert out.next_cursor is not None
    assert "." in out.next_cursor
    payload = _decode_signed_cursor_payload(out.next_cursor)
    assert payload["version"] == messaging.MESSAGING_THREAD_CURSOR_VERSION
    assert payload["alg"] == messaging.MESSAGING_THREAD_CURSOR_ALG
    assert msgs_tbl.query.call_args.kwargs["IndexName"] == "ByThreadCreatedAt"


def test_list_thread_messages_records_latency_metric_for_success() -> None:
    thread = SimpleNamespace(id="thr_m1", conversation_id="c1")
    parts_tbl = Mock()
    parts_tbl.query.return_value = {"Items": []}
    msgs_tbl = Mock()
    msgs_tbl.query.return_value = {"Items": []}
    with (
        patch.object(messaging, "get_message_thread_record", return_value=thread),
        patch.object(messaging, "require_participant_active", return_value={"user_id": "u1", "last_read_at": 0}),
        patch.object(messaging, "tbl_parts", parts_tbl),
        patch.object(messaging, "tbl_msgs", msgs_tbl),
        patch.object(messaging, "_load_hidden_message_ids_for_user", return_value=set()),
        patch.object(messaging, "record_messaging_thread_query_latency") as rec_latency,
    ):
        messaging.list_thread_messages("thr_m1", limit=10, user_id="u1")

    rec_latency.assert_called_once()
    assert rec_latency.call_args.kwargs["endpoint"] == "list_thread_messages"
    assert rec_latency.call_args.kwargs["outcome"] == "success"


def test_list_thread_messages_unread_count_tracks_participant_last_read_at() -> None:
    thread = SimpleNamespace(id="thr_m1", conversation_id="c1")
    parts_tbl = Mock()
    parts_tbl.query.return_value = {"Items": []}
    msgs_tbl = Mock()
    msgs_tbl.query.return_value = {
        "Items": [
            {
                "conversation_id": "c1",
                "message_id": "m_old",
                "sender_id": "u2",
                "created_at": 100,
                "kind": "text",
                "text": "old",
                "thread_id": "thr_m1",
                "thread_root_message_id": "m1",
                "reactions": {},
            },
            {
                "conversation_id": "c1",
                "message_id": "m_new",
                "sender_id": "u2",
                "created_at": 200,
                "kind": "text",
                "text": "new",
                "thread_id": "thr_m1",
                "thread_root_message_id": "m1",
                "reactions": {},
            },
            {
                "conversation_id": "c1",
                "message_id": "m_self",
                "sender_id": "u1",
                "created_at": 220,
                "kind": "text",
                "text": "mine",
                "thread_id": "thr_m1",
                "thread_root_message_id": "m1",
                "reactions": {},
            },
        ],
    }
    with (
        patch.object(messaging, "get_message_thread_record", return_value=thread),
        patch.object(messaging, "require_participant_active", return_value={"user_id": "u1", "last_read_at": 150}),
        patch.object(messaging, "tbl_parts", parts_tbl),
        patch.object(messaging, "tbl_msgs", msgs_tbl),
        patch.object(messaging, "_load_hidden_message_ids_for_user", return_value=set()),
        patch.object(messaging, "_thread_summary", return_value=(3, 220)),
    ):
        out = messaging.list_thread_messages("thr_m1", limit=50, user_id="u1")

    assert [m.message_id for m in out.items] == ["m_old", "m_new", "m_self"]
    assert out.unread_count == 1


def test_list_thread_messages_rejects_unknown_thread() -> None:
    with (
        patch.object(messaging, "get_message_thread_record", return_value=None),
        patch.object(messaging, "record_messaging_thread_query_latency") as rec_latency,
    ):
        with pytest.raises(HTTPException) as exc:
            messaging.list_thread_messages("missing", limit=10, user_id="u1")

    assert exc.value.status_code == 404
    assert exc.value.detail == "Thread not found"
    rec_latency.assert_called_once()
    assert rec_latency.call_args.kwargs["outcome"] == "not_found"


def test_list_thread_messages_requires_active_participant() -> None:
    thread = SimpleNamespace(id="thr_m1", conversation_id="c1")
    with (
        patch.object(messaging, "get_message_thread_record", return_value=thread),
        patch.object(messaging, "require_participant_active", side_effect=HTTPException(status_code=403, detail="Not an active participant")),
        patch.object(messaging, "record_messaging_thread_query_latency") as rec_latency,
    ):
        with pytest.raises(HTTPException) as exc:
            messaging.list_thread_messages("thr_m1", limit=10, user_id="u1")

    assert exc.value.status_code == 403
    rec_latency.assert_called_once()
    assert rec_latency.call_args.kwargs["outcome"] == "forbidden"


def test_list_thread_messages_rejects_invalid_cursor_shape() -> None:
    thread = SimpleNamespace(id="thr_m1", conversation_id="c1")
    msgs_tbl = Mock()
    with (
        patch.object(messaging, "get_message_thread_record", return_value=thread),
        patch.object(messaging, "require_participant_active", return_value={"user_id": "u1", "last_read_at": 0}),
        patch.object(messaging, "tbl_parts", Mock(query=Mock(return_value={"Items": []}))),
        patch.object(messaging, "tbl_msgs", msgs_tbl),
        patch.object(messaging, "record_messaging_thread_query_latency") as rec_latency,
        patch.object(messaging, "record_messaging_thread_invalid_cursor") as rec_invalid_cursor,
        patch.object(messaging, "audit_event") as audit,
    ):
        with pytest.raises(HTTPException) as exc:
            messaging.list_thread_messages("thr_m1", limit=10, cursor="not-valid!!!", user_id="u1")

    assert exc.value.status_code == 400
    assert exc.value.detail["code"] == "invalid_cursor"
    assert "urlsafe base64" in exc.value.detail["message"]
    msgs_tbl.query.assert_not_called()
    rec_latency.assert_called_once()
    assert rec_latency.call_args.kwargs["outcome"] == "invalid_cursor"
    rec_invalid_cursor.assert_called_once_with(
        endpoint="list_thread_messages",
        reason_category="payload",
    )
    audit.assert_called_once()
    assert audit.call_args.args[0] == "messaging_thread_query_invalid_cursor"
    assert audit.call_args.kwargs["reason"] == "cursor must be urlsafe base64 encoded JSON for thread pagination"
    assert audit.call_args.kwargs["reason_category"] == "payload"


def test_list_thread_messages_rejects_oversized_cursor() -> None:
    thread = SimpleNamespace(id="thr_m1", conversation_id="c1")
    oversized_cursor = "a" * (messaging.MESSAGING_THREAD_CURSOR_MAX_CHARS + 1)
    msgs_tbl = Mock()
    with (
        patch.object(messaging, "get_message_thread_record", return_value=thread),
        patch.object(messaging, "require_participant_active", return_value={"user_id": "u1", "last_read_at": 0}),
        patch.object(messaging, "tbl_parts", Mock(query=Mock(return_value={"Items": []}))),
        patch.object(messaging, "tbl_msgs", msgs_tbl),
        patch.object(messaging, "record_messaging_thread_query_latency") as rec_latency,
        patch.object(messaging, "record_messaging_thread_invalid_cursor") as rec_invalid_cursor,
        patch.object(messaging, "audit_event") as audit,
    ):
        with pytest.raises(HTTPException) as exc:
            messaging.list_thread_messages("thr_m1", limit=10, cursor=oversized_cursor, user_id="u1")

    assert exc.value.status_code == 400
    assert exc.value.detail == {
        "code": "invalid_cursor",
        "message": "cursor is too long",
    }
    msgs_tbl.query.assert_not_called()
    rec_latency.assert_called_once()
    assert rec_latency.call_args.kwargs["outcome"] == "invalid_cursor"
    rec_invalid_cursor.assert_called_once_with(
        endpoint="list_thread_messages",
        reason_category="too_long",
    )
    audit.assert_called_once()
    assert audit.call_args.args[0] == "messaging_thread_query_invalid_cursor"
    assert audit.call_args.kwargs["reason"] == "cursor is too long"
    assert audit.call_args.kwargs["reason_category"] == "too_long"


def test_list_thread_messages_rejects_cursor_for_different_thread() -> None:
    thread = SimpleNamespace(id="thr_m1", conversation_id="c1")
    mismatched_cursor = messaging.encode_cursor(
        {
            "conversation_id": "c1",
            "message_id": "m1",
            "thread_id": "thr_other",
            "created_at": 10,
        }
    )
    msgs_tbl = Mock()
    with (
        patch.object(messaging, "get_message_thread_record", return_value=thread),
        patch.object(messaging, "require_participant_active", return_value={"user_id": "u1", "last_read_at": 0}),
        patch.object(messaging, "tbl_parts", Mock(query=Mock(return_value={"Items": []}))),
        patch.object(messaging, "tbl_msgs", msgs_tbl),
        patch.object(messaging, "record_messaging_thread_query_latency") as rec_latency,
    ):
        with pytest.raises(HTTPException) as exc:
            messaging.list_thread_messages("thr_m1", limit=10, cursor=mismatched_cursor, user_id="u1")

    assert exc.value.status_code == 400
    assert exc.value.detail == {
        "code": "invalid_cursor",
        "message": "cursor signature is invalid",
    }
    msgs_tbl.query.assert_not_called()
    rec_latency.assert_called_once()
    assert rec_latency.call_args.kwargs["outcome"] == "invalid_cursor"


def test_list_thread_messages_rejects_legacy_cursor_for_different_conversation() -> None:
    thread = SimpleNamespace(id="thr_m1", conversation_id="c1")
    mismatched_cursor = messaging.encode_cursor(
        {
            "conversation_id": "c2",
            "message_id": "m1",
            "thread_id": "thr_m1",
            "created_at": 10,
        }
    )
    msgs_tbl = Mock()
    with (
        patch.object(messaging, "get_message_thread_record", return_value=thread),
        patch.object(messaging, "require_participant_active", return_value={"user_id": "u1", "last_read_at": 0}),
        patch.object(messaging, "tbl_parts", Mock(query=Mock(return_value={"Items": []}))),
        patch.object(messaging, "tbl_msgs", msgs_tbl),
        patch.object(messaging, "record_messaging_thread_query_latency") as rec_latency,
    ):
        with pytest.raises(HTTPException) as exc:
            messaging.list_thread_messages("thr_m1", limit=10, cursor=mismatched_cursor, user_id="u1")

    assert exc.value.status_code == 400
    assert exc.value.detail == {
        "code": "invalid_cursor",
        "message": "cursor signature is invalid",
    }
    msgs_tbl.query.assert_not_called()
    rec_latency.assert_called_once()
    assert rec_latency.call_args.kwargs["outcome"] == "invalid_cursor"


def test_list_thread_messages_rejects_legacy_cursor_missing_message_id() -> None:
    thread = SimpleNamespace(id="thr_m1", conversation_id="c1")
    malformed_cursor = messaging.encode_cursor(
        {
            "conversation_id": "c1",
            "thread_id": "thr_m1",
            "created_at": 10,
        }
    )
    msgs_tbl = Mock()
    with (
        patch.object(messaging, "get_message_thread_record", return_value=thread),
        patch.object(messaging, "require_participant_active", return_value={"user_id": "u1", "last_read_at": 0}),
        patch.object(messaging, "tbl_parts", Mock(query=Mock(return_value={"Items": []}))),
        patch.object(messaging, "tbl_msgs", msgs_tbl),
        patch.object(messaging, "record_messaging_thread_query_latency") as rec_latency,
    ):
        with pytest.raises(HTTPException) as exc:
            messaging.list_thread_messages("thr_m1", limit=10, cursor=malformed_cursor, user_id="u1")

    assert exc.value.status_code == 400
    assert exc.value.detail == {
        "code": "invalid_cursor",
        "message": "cursor signature is invalid",
    }
    msgs_tbl.query.assert_not_called()
    rec_latency.assert_called_once()
    assert rec_latency.call_args.kwargs["outcome"] == "invalid_cursor"


def test_list_thread_messages_handles_query_failure_with_503() -> None:
    thread = SimpleNamespace(id="thr_m1", conversation_id="c1")
    parts_tbl = Mock()
    parts_tbl.query.return_value = {"Items": []}
    msgs_tbl = Mock()
    msgs_tbl.query.side_effect = RuntimeError("ddb unavailable")
    with (
        patch.object(messaging, "get_message_thread_record", return_value=thread),
        patch.object(messaging, "require_participant_active", return_value={"user_id": "u1", "last_read_at": 0}),
        patch.object(messaging, "tbl_parts", parts_tbl),
        patch.object(messaging, "tbl_msgs", msgs_tbl),
        patch.object(messaging, "record_messaging_thread_query_latency") as rec_latency,
        patch.object(messaging, "audit_event") as audit,
    ):
        with pytest.raises(HTTPException) as exc:
            messaging.list_thread_messages("thr_m1", limit=10, user_id="u1")

    assert exc.value.status_code == 503
    assert exc.value.detail == {
        "code": "thread_query_failed",
        "message": "thread message query temporarily unavailable",
    }
    rec_latency.assert_called_once()
    assert rec_latency.call_args.kwargs["outcome"] == "error"
    audit.assert_called_once()
    assert audit.call_args.args[0] == "messaging_thread_query_failed"


def test_decode_thread_cursor_rejects_user_scope_mismatch() -> None:
    cursor = messaging._encode_thread_messages_cursor(
        last_evaluated_key={"conversation_id": "c1", "message_id": "m1", "thread_id": "thr_m1"},
        thread_id="thr_m1",
        conversation_id="c1",
        user_id="u1",
    )
    with pytest.raises(HTTPException) as exc:
        messaging._decode_thread_messages_cursor_or_400(
            thread_id="thr_m1",
            conversation_id="c1",
            user_id="u2",
            cursor=cursor or "",
        )

    assert exc.value.status_code == 400
    assert exc.value.detail == {
        "code": "invalid_cursor",
        "message": "cursor does not match current user",
    }


def test_decode_thread_cursor_rejects_expired_cursor() -> None:
    with patch.object(messaging.time, "time", return_value=100):
        cursor = messaging._encode_thread_messages_cursor(
            last_evaluated_key={"conversation_id": "c1", "message_id": "m1", "thread_id": "thr_m1"},
            thread_id="thr_m1",
            conversation_id="c1",
            user_id="u1",
        )
    with patch.object(messaging.time, "time", return_value=100 + messaging.MESSAGING_THREAD_CURSOR_TTL_SECONDS + 1):
        with pytest.raises(HTTPException) as exc:
            messaging._decode_thread_messages_cursor_or_400(
                thread_id="thr_m1",
                conversation_id="c1",
                user_id="u1",
                cursor=cursor or "",
            )

    assert exc.value.status_code == 400
    assert exc.value.detail == {
        "code": "invalid_cursor",
        "message": "cursor has expired",
    }


def test_decode_thread_cursor_accepts_previous_rotation_secret() -> None:
    payload = {
        "v": messaging.MESSAGING_THREAD_CURSOR_VERSION,
        "version": messaging.MESSAGING_THREAD_CURSOR_VERSION,
        "alg": messaging.MESSAGING_THREAD_CURSOR_ALG,
        "tid": "thr_m1",
        "cid": "c1",
        "uid": "u1",
        "exp": 4_000_000_000,
        "lek": {"conversation_id": "c1", "message_id": "m1", "thread_id": "thr_m1"},
    }
    payload_raw = messaging.json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    payload_b64 = messaging.base64.urlsafe_b64encode(payload_raw).decode("utf-8").rstrip("=")
    rotated_signature = messaging._sign_thread_cursor_payload(payload_b64, secret="old-secret")
    cursor = f"{payload_b64}.{rotated_signature}"

    with patch.object(messaging, "_thread_cursor_signing_secrets", return_value=["new-secret", "old-secret"]):
        out = messaging._decode_thread_messages_cursor_or_400(
            thread_id="thr_m1",
            conversation_id="c1",
            user_id="u1",
            cursor=cursor,
        )

    assert out == payload["lek"]


def test_decode_thread_cursor_rejects_unsupported_version() -> None:
    payload = {
        "version": 999,
        "alg": messaging.MESSAGING_THREAD_CURSOR_ALG,
        "tid": "thr_m1",
        "cid": "c1",
        "uid": "u1",
        "exp": 4_000_000_000,
        "lek": {"conversation_id": "c1", "message_id": "m1", "thread_id": "thr_m1"},
    }
    payload_raw = messaging.json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    payload_b64 = messaging.base64.urlsafe_b64encode(payload_raw).decode("utf-8").rstrip("=")
    signature = messaging._sign_thread_cursor_payload(payload_b64)
    with pytest.raises(HTTPException) as exc:
        messaging._decode_thread_messages_cursor_or_400(
            thread_id="thr_m1",
            conversation_id="c1",
            user_id="u1",
            cursor=f"{payload_b64}.{signature}",
        )
    assert exc.value.status_code == 400
    assert exc.value.detail == {
        "code": "invalid_cursor",
        "message": "cursor version is unsupported",
    }


def test_decode_thread_cursor_rejects_unsupported_algorithm() -> None:
    payload = {
        "version": messaging.MESSAGING_THREAD_CURSOR_VERSION,
        "alg": "MD5",
        "tid": "thr_m1",
        "cid": "c1",
        "uid": "u1",
        "exp": 4_000_000_000,
        "lek": {"conversation_id": "c1", "message_id": "m1", "thread_id": "thr_m1"},
    }
    payload_raw = messaging.json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    payload_b64 = messaging.base64.urlsafe_b64encode(payload_raw).decode("utf-8").rstrip("=")
    signature = messaging._sign_thread_cursor_payload(payload_b64)
    with pytest.raises(HTTPException) as exc:
        messaging._decode_thread_messages_cursor_or_400(
            thread_id="thr_m1",
            conversation_id="c1",
            user_id="u1",
            cursor=f"{payload_b64}.{signature}",
        )
    assert exc.value.status_code == 400
    assert exc.value.detail == {
        "code": "invalid_cursor",
        "message": "cursor algorithm is unsupported",
    }


def test_decode_thread_cursor_rejects_missing_version_field() -> None:
    payload = {
        "v": messaging.MESSAGING_THREAD_CURSOR_VERSION,
        "alg": messaging.MESSAGING_THREAD_CURSOR_ALG,
        "tid": "thr_m1",
        "cid": "c1",
        "uid": "u1",
        "exp": 4_000_000_000,
        "lek": {"conversation_id": "c1", "message_id": "m1", "thread_id": "thr_m1"},
    }
    payload_raw = messaging.json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    payload_b64 = messaging.base64.urlsafe_b64encode(payload_raw).decode("utf-8").rstrip("=")
    signature = messaging._sign_thread_cursor_payload(payload_b64)
    with pytest.raises(HTTPException) as exc:
        messaging._decode_thread_messages_cursor_or_400(
            thread_id="thr_m1",
            conversation_id="c1",
            user_id="u1",
            cursor=f"{payload_b64}.{signature}",
        )

    assert exc.value.status_code == 400
    assert exc.value.detail == {
        "code": "invalid_cursor",
        "message": "cursor version is missing",
    }


def test_decode_thread_cursor_rejects_missing_algorithm_field() -> None:
    payload = {
        "version": messaging.MESSAGING_THREAD_CURSOR_VERSION,
        "tid": "thr_m1",
        "cid": "c1",
        "uid": "u1",
        "exp": 4_000_000_000,
        "lek": {"conversation_id": "c1", "message_id": "m1", "thread_id": "thr_m1"},
    }
    payload_raw = messaging.json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    payload_b64 = messaging.base64.urlsafe_b64encode(payload_raw).decode("utf-8").rstrip("=")
    signature = messaging._sign_thread_cursor_payload(payload_b64)
    with pytest.raises(HTTPException) as exc:
        messaging._decode_thread_messages_cursor_or_400(
            thread_id="thr_m1",
            conversation_id="c1",
            user_id="u1",
            cursor=f"{payload_b64}.{signature}",
        )

    assert exc.value.status_code == 400
    assert exc.value.detail == {
        "code": "invalid_cursor",
        "message": "cursor algorithm is missing",
    }


def test_decode_thread_cursor_rejects_malformed_version_field() -> None:
    payload = {
        "version": "not-an-int",
        "alg": messaging.MESSAGING_THREAD_CURSOR_ALG,
        "tid": "thr_m1",
        "cid": "c1",
        "uid": "u1",
        "exp": 4_000_000_000,
        "lek": {"conversation_id": "c1", "message_id": "m1", "thread_id": "thr_m1"},
    }
    payload_raw = messaging.json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    payload_b64 = messaging.base64.urlsafe_b64encode(payload_raw).decode("utf-8").rstrip("=")
    signature = messaging._sign_thread_cursor_payload(payload_b64)
    with pytest.raises(HTTPException) as exc:
        messaging._decode_thread_messages_cursor_or_400(
            thread_id="thr_m1",
            conversation_id="c1",
            user_id="u1",
            cursor=f"{payload_b64}.{signature}",
        )

    assert exc.value.status_code == 400
    assert exc.value.detail == {
        "code": "invalid_cursor",
        "message": "cursor version is malformed",
    }


def test_decode_thread_cursor_rejects_malformed_expiry_field() -> None:
    payload = {
        "version": messaging.MESSAGING_THREAD_CURSOR_VERSION,
        "alg": messaging.MESSAGING_THREAD_CURSOR_ALG,
        "tid": "thr_m1",
        "cid": "c1",
        "uid": "u1",
        "exp": "tomorrow",
        "lek": {"conversation_id": "c1", "message_id": "m1", "thread_id": "thr_m1"},
    }
    payload_raw = messaging.json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    payload_b64 = messaging.base64.urlsafe_b64encode(payload_raw).decode("utf-8").rstrip("=")
    signature = messaging._sign_thread_cursor_payload(payload_b64)
    with pytest.raises(HTTPException) as exc:
        messaging._decode_thread_messages_cursor_or_400(
            thread_id="thr_m1",
            conversation_id="c1",
            user_id="u1",
            cursor=f"{payload_b64}.{signature}",
        )

    assert exc.value.status_code == 400
    assert exc.value.detail == {
        "code": "invalid_cursor",
        "message": "cursor expiry is malformed",
    }


def test_decode_thread_cursor_rejects_lek_thread_scope_mismatch() -> None:
    payload = {
        "version": messaging.MESSAGING_THREAD_CURSOR_VERSION,
        "alg": messaging.MESSAGING_THREAD_CURSOR_ALG,
        "tid": "thr_m1",
        "cid": "c1",
        "uid": "u1",
        "exp": 4_000_000_000,
        "lek": {"conversation_id": "c1", "message_id": "m1", "thread_id": "thr_other"},
    }
    payload_raw = messaging.json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    payload_b64 = messaging.base64.urlsafe_b64encode(payload_raw).decode("utf-8").rstrip("=")
    signature = messaging._sign_thread_cursor_payload(payload_b64)
    with pytest.raises(HTTPException) as exc:
        messaging._decode_thread_messages_cursor_or_400(
            thread_id="thr_m1",
            conversation_id="c1",
            user_id="u1",
            cursor=f"{payload_b64}.{signature}",
        )

    assert exc.value.status_code == 400
    assert exc.value.detail == {
        "code": "invalid_cursor",
        "message": "cursor does not match requested thread_id",
    }


def test_decode_thread_cursor_rejects_lek_without_message_id() -> None:
    payload = {
        "version": messaging.MESSAGING_THREAD_CURSOR_VERSION,
        "alg": messaging.MESSAGING_THREAD_CURSOR_ALG,
        "tid": "thr_m1",
        "cid": "c1",
        "uid": "u1",
        "exp": 4_000_000_000,
        "lek": {"conversation_id": "c1", "thread_id": "thr_m1"},
    }
    payload_raw = messaging.json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    payload_b64 = messaging.base64.urlsafe_b64encode(payload_raw).decode("utf-8").rstrip("=")
    signature = messaging._sign_thread_cursor_payload(payload_b64)
    with pytest.raises(HTTPException) as exc:
        messaging._decode_thread_messages_cursor_or_400(
            thread_id="thr_m1",
            conversation_id="c1",
            user_id="u1",
            cursor=f"{payload_b64}.{signature}",
        )

    assert exc.value.status_code == 400
    assert exc.value.detail == {
        "code": "invalid_cursor",
        "message": "cursor payload is malformed",
    }
