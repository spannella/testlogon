"""Unit tests for broadcast live chat (BCAST-005)."""
from __future__ import annotations

import time
import threading
from types import SimpleNamespace
from unittest.mock import patch, MagicMock

import pytest

from app.services import broadcast_chat_store
from app.services import broadcast_sse


def _extract_key_conditions(expr):
    """Extract session_id and sort_key conditions from a boto3 Key condition expression."""
    session_id = None
    sort_key_op = None  # ("<", "value") or (">", "value")

    if expr is None:
        return session_id, sort_key_op

    def _visit(node):
        nonlocal session_id, sort_key_op
        if not hasattr(node, "_values"):
            return
        op = getattr(node, "expression_operator", "")
        vals = node._values

        # AND compound condition
        if op == "AND":
            for child in vals:
                _visit(child)
        elif op in ("=", "<", ">", "<=", ">="):
            # Leaf comparison: _values = (Key('name'), value)
            if len(vals) >= 2:
                key_obj = vals[0]
                cmp_val = vals[1]
                key_name = getattr(key_obj, "name", None)
                if key_name == "session_id" and op == "=":
                    session_id = cmp_val
                elif key_name == "sort_key":
                    sort_key_op = (op, cmp_val)

    _visit(expr)
    return session_id, sort_key_op


class _FakeChatTable:
    """In-memory DynamoDB table mock for chat messages."""

    def __init__(self):
        self.items = []  # list of items (ordered by insertion)

    def put_item(self, *, Item):
        self.items.append(dict(Item))

    def query(self, *, KeyConditionExpression=None, FilterExpression=None,
              Limit=None, ScanIndexForward=True, **kwargs):
        results = list(self.items)

        session_id, sort_key_op = _extract_key_conditions(KeyConditionExpression)

        # Filter by session_id
        if session_id:
            results = [i for i in results if i.get("session_id") == session_id]

        # Filter by sort_key condition
        if sort_key_op:
            op, val = sort_key_op
            if op == "<":
                results = [i for i in results if i.get("sort_key", "") < val]
            elif op == ">":
                results = [i for i in results if i.get("sort_key", "") > val]

        # Apply FilterExpression for non-deleted
        if FilterExpression is not None:
            results = [i for i in results if not i.get("deleted", False)]

        # Sort by sort_key
        results.sort(key=lambda x: x.get("sort_key", ""), reverse=not ScanIndexForward)

        if Limit:
            has_more = len(results) > Limit
            results = results[:Limit]
        else:
            has_more = False

        resp = {"Items": results}
        if has_more:
            resp["LastEvaluatedKey"] = {"dummy": "key"}
        return resp

    def update_item(self, *, Key, UpdateExpression, ExpressionAttributeValues, **kwargs):
        for item in self.items:
            if item["session_id"] == Key["session_id"] and item["sort_key"] == Key["sort_key"]:
                if "deleted" in UpdateExpression:
                    item["deleted"] = ExpressionAttributeValues.get(":t", True)
                    item["deleted_by"] = ExpressionAttributeValues.get(":u", "")
                break

    def get_item(self, *, Key):
        for item in self.items:
            match_key = list(Key.values())[0] if len(Key) == 1 else None
            if match_key and item.get(list(Key.keys())[0]) == match_key:
                return {"Item": item}
        return {}


class _FakeMutesTable:
    """In-memory DynamoDB table mock for mutes."""

    def __init__(self):
        self.items = {}

    def put_item(self, *, Item):
        self.items[Item["session_user"]] = dict(Item)

    def get_item(self, *, Key):
        item = self.items.get(Key["session_user"])
        if item:
            return {"Item": item}
        return {}


class _FakeProfileTable:
    """In-memory DynamoDB table mock for profiles."""

    def __init__(self):
        self.items = {}

    def get_item(self, *, Key):
        item = self.items.get(Key.get("user_sub"))
        if item:
            return {"Item": item}
        return {}


@pytest.fixture(autouse=True)
def reset_rate_limits():
    """Clear rate limits before and after each test."""
    broadcast_chat_store.reset_rate_limits()
    yield
    broadcast_chat_store.reset_rate_limits()


@pytest.fixture
def mock_tables():
    chat_table = _FakeChatTable()
    mutes_table = _FakeMutesTable()
    profile_table = _FakeProfileTable()

    mock_T = SimpleNamespace(
        broadcast_chat_messages=chat_table,
        broadcast_chat_mutes=mutes_table,
        profile=profile_table,
    )
    with patch.object(broadcast_chat_store, "T", mock_T):
        yield {
            "chat": chat_table,
            "mutes": mutes_table,
            "profile": profile_table,
        }


@pytest.fixture
def mock_sse():
    with patch.object(broadcast_sse, "broadcast_sse_publish") as pub:
        with patch.object(broadcast_chat_store, "broadcast_sse_publish", pub):
            yield pub


class TestSendChatMessage:
    def test_send_creates_message(self, mock_tables, mock_sse):
        result = broadcast_chat_store.send_chat_message(
            "sess1", "user1", "Alice", "Hello chat!"
        )
        assert result["message_id"].startswith("cm_")
        assert result["text"] == "Hello chat!"
        assert result["sender_id"] == "user1"
        assert result["sender_display_name"] == "Alice"
        assert result["session_id"] == "sess1"
        assert result["deleted"] is False

    def test_send_publishes_sse_event(self, mock_tables, mock_sse):
        broadcast_chat_store.send_chat_message("sess1", "user1", "Alice", "Hi!")
        mock_sse.assert_called_once()
        args = mock_sse.call_args[0]
        assert args[0] == "sess1"
        assert args[1]["_type"] == "chat:message"
        assert args[1]["text"] == "Hi!"

    def test_send_rate_limited(self, mock_tables, mock_sse):
        broadcast_chat_store.send_chat_message(
            "sess1", "user1", "Alice", "msg1", skip_rate_limit=False
        )
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            broadcast_chat_store.send_chat_message(
                "sess1", "user1", "Alice", "msg2", skip_rate_limit=False
            )
        assert exc_info.value.status_code == 429
        assert "BROADCAST_CHAT_RATE_LIMITED" in str(exc_info.value.detail)

    def test_send_after_rate_limit_window(self, mock_tables, mock_sse):
        broadcast_chat_store.send_chat_message(
            "sess1", "user1", "Alice", "msg1", skip_rate_limit=False
        )
        # Manually reset the bucket to simulate time passage
        key = "sess1#user1"
        with broadcast_chat_store._CHAT_RATE_LOCK:
            broadcast_chat_store._CHAT_RATE_BUCKETS[key] = int(time.time() * 1000) - 3000
        # Should succeed now
        result = broadcast_chat_store.send_chat_message(
            "sess1", "user1", "Alice", "msg2", skip_rate_limit=False
        )
        assert result["text"] == "msg2"

    def test_send_strips_whitespace(self, mock_tables, mock_sse):
        result = broadcast_chat_store.send_chat_message(
            "sess1", "user1", "Alice", "  hello  "
        )
        assert result["text"] == "hello"


class TestGetChatHistory:
    def test_get_history_returns_messages(self, mock_tables, mock_sse):
        for i in range(5):
            broadcast_chat_store.send_chat_message(
                "sess1", "user1", "Alice", f"msg {i}", skip_rate_limit=True
            )
        history = broadcast_chat_store.get_chat_history("sess1", limit=10)
        # All 5 messages should appear
        texts = sorted([m["text"] for m in history["messages"]])
        assert texts == ["msg 0", "msg 1", "msg 2", "msg 3", "msg 4"]

    def test_get_history_sorted_by_sort_key(self, mock_tables, mock_sse):
        # Send 3 messages with small time gap
        import time as real_time
        msgs = []
        for i in range(3):
            real_time.sleep(0.002)  # 2ms gap to ensure distinct sort keys
            m = broadcast_chat_store.send_chat_message(
                "sess1", "user1", "Alice", f"msg {i}", skip_rate_limit=True
            )
            msgs.append(m)
        # Verify sort_keys are in ascending order (matching insertion order)
        sort_keys = [m["sort_key"] for m in msgs]
        assert sort_keys == sorted(sort_keys)

    def test_get_history_respects_limit(self, mock_tables, mock_sse):
        for i in range(10):
            broadcast_chat_store.send_chat_message(
                "sess1", "user1", "Alice", f"msg {i}", skip_rate_limit=True
            )
        history = broadcast_chat_store.get_chat_history("sess1", limit=3)
        assert len(history["messages"]) == 3

    def test_get_history_excludes_deleted(self, mock_tables, mock_sse):
        msg = broadcast_chat_store.send_chat_message(
            "sess1", "user1", "Alice", "bad msg", skip_rate_limit=True
        )
        broadcast_chat_store.send_chat_message(
            "sess1", "user1", "Alice", "good msg", skip_rate_limit=True
        )
        # Directly mark the item as deleted in the mock table
        for item in mock_tables["chat"].items:
            if item["message_id"] == msg["message_id"]:
                item["deleted"] = True
                break
        history = broadcast_chat_store.get_chat_history("sess1", limit=100)
        msg_ids = [m["message_id"] for m in history["messages"]]
        assert msg["message_id"] not in msg_ids
        texts = [m["text"] for m in history["messages"]]
        assert "good msg" in texts


class TestDeleteChatMessage:
    def test_delete_marks_as_deleted(self, mock_tables, mock_sse):
        msg = broadcast_chat_store.send_chat_message(
            "sess1", "user1", "Alice", "to delete", skip_rate_limit=True
        )
        result = broadcast_chat_store.delete_chat_message("sess1", msg["message_id"], "admin1")
        assert result is True

    def test_delete_publishes_sse_event(self, mock_tables, mock_sse):
        msg = broadcast_chat_store.send_chat_message(
            "sess1", "user1", "Alice", "del me", skip_rate_limit=True
        )
        mock_sse.reset_mock()
        broadcast_chat_store.delete_chat_message("sess1", msg["message_id"], "admin1")
        # Should have published a chat:delete event
        calls = mock_sse.call_args_list
        assert any(c[0][1]["_type"] == "chat:delete" for c in calls)

    def test_delete_nonexistent_returns_false(self, mock_tables, mock_sse):
        result = broadcast_chat_store.delete_chat_message("sess1", "nonexistent", "admin1")
        assert result is False


class TestMuteUser:
    def test_get_mute_status_none_when_not_muted(self, mock_tables):
        status = broadcast_chat_store.get_mute_status("sess1", "user1")
        assert status is None

    def test_set_mute_returns_expiry(self, mock_tables, mock_sse):
        result = broadcast_chat_store.set_mute("sess1", "user1", 300, "broadcaster1")
        assert result["target_user_id"] == "user1"
        assert result["muted_until"] > int(time.time())
        assert result["session_id"] == "sess1"

    def test_get_mute_status_returns_expiry_when_muted(self, mock_tables, mock_sse):
        broadcast_chat_store.set_mute("sess1", "user1", 300, "broadcaster1")
        status = broadcast_chat_store.get_mute_status("sess1", "user1")
        assert status is not None
        assert status > int(time.time())

    def test_muted_user_cannot_send(self, mock_tables, mock_sse):
        broadcast_chat_store.set_mute("sess1", "user1", 300, "broadcaster1")
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            broadcast_chat_store.send_chat_message(
                "sess1", "user1", "Alice", "hello", skip_rate_limit=True
            )
        assert exc_info.value.status_code == 403
        assert "BROADCAST_CHAT_MUTED" in str(exc_info.value.detail)

    def test_expired_mute_returns_none(self, mock_tables, mock_sse):
        # Set mute with already-expired time
        mock_tables["mutes"].items["sess1#user1"] = {
            "session_user": "sess1#user1",
            "muted_until": int(time.time()) - 10,
            "muted_by": "broadcaster1",
        }
        status = broadcast_chat_store.get_mute_status("sess1", "user1")
        assert status is None

    def test_set_mute_publishes_sse(self, mock_tables, mock_sse):
        broadcast_chat_store.set_mute("sess1", "user1", 300, "broadcaster1")
        mock_sse.assert_called_once()
        args = mock_sse.call_args[0]
        assert args[1]["_type"] == "chat:mute"
        assert args[1]["target_user_id"] == "user1"


class TestFetchAfterCursor:
    def test_fetch_after_returns_newer_messages(self, mock_tables, mock_sse):
        msgs = []
        # Use mocked time to ensure distinct timestamps
        with patch("app.services.broadcast_chat_store.time") as mock_time:
            base = 1000000.0
            call_count = [0]
            def time_side_effect():
                call_count[0] += 1
                return base + call_count[0]
            mock_time.time = time_side_effect
            for i in range(5):
                msg = broadcast_chat_store.send_chat_message(
                    "sess1", "user1", "Alice", f"m{i}", skip_rate_limit=True
                )
                msgs.append(msg)

        # Sort msgs by sort_key to find the correct cursor
        msgs_sorted = sorted(msgs, key=lambda m: m["sort_key"])
        # Use cursor from third message — should return items after it
        cursor = msgs_sorted[2]["sort_key"]
        after = broadcast_chat_store.fetch_chat_messages_after("sess1", cursor, 50)
        # Should return messages with sort_key > cursor (2 messages)
        assert len(after) == 2
        after_texts = sorted([m["text"] for m in after])
        # The 2 messages after cursor are the last 2 in sorted order
        expected_texts = sorted([msgs_sorted[3]["text"], msgs_sorted[4]["text"]])
        assert after_texts == expected_texts
