"""Unit tests for broadcast viewer tracking."""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch, MagicMock

import pytest
from botocore.exceptions import ClientError

from app.services import broadcast_viewers
from app.services import broadcast_sse


class _FakeViewersTable:
    """In-memory DynamoDB table mock for viewer records."""

    def __init__(self):
        self.items = {}

    def put_item(self, *, Item):
        key = (Item["session_id"], Item["viewer_id"])
        self.items[key] = Item

    def update_item(self, *, Key, UpdateExpression, ExpressionAttributeValues, ConditionExpression=None):
        key = (Key["session_id"], Key["viewer_id"])
        if ConditionExpression and key not in self.items:
            raise ClientError(
                {"Error": {"Code": "ConditionalCheckFailedException", "Message": ""}},
                "UpdateItem",
            )
        if key in self.items:
            item = self.items[key]
            item["last_heartbeat"] = ExpressionAttributeValues[":hb"]
            item["expires_at"] = ExpressionAttributeValues[":exp"]

    def delete_item(self, *, Key):
        key = (Key["session_id"], Key["viewer_id"])
        self.items.pop(key, None)

    def query(self, *, KeyConditionExpression, Select=None, Limit=None, ScanIndexForward=None):
        # Simple implementation: match by session_id
        session_id = KeyConditionExpression._values[1]
        matching = [v for k, v in self.items.items() if k[0] == session_id]
        if Select == "COUNT":
            return {"Count": len(matching)}
        if Limit:
            matching = matching[:Limit]
        return {"Items": matching}


@pytest.fixture
def mock_ddb():
    table = _FakeViewersTable()
    with patch.object(broadcast_viewers, "T", SimpleNamespace(broadcast_viewers=table)):
        yield table


@pytest.fixture
def mock_sse_publish():
    with patch.object(broadcast_sse, "broadcast_sse_publish") as mock_pub:
        with patch.object(broadcast_viewers, "broadcast_sse_publish", mock_pub):
            yield mock_pub


class TestRegisterViewer:
    def test_register_creates_item_and_returns_count(self, mock_ddb):
        result = broadcast_viewers.register_viewer("session-1", "user-alice", user_agent="Chrome/120")
        assert result["viewer_id"].startswith("user-alice#")
        assert result["session_id"] == "session-1"
        assert result["viewer_count"] >= 1

    def test_register_publishes_sse_event(self, mock_ddb, mock_sse_publish):
        broadcast_viewers.register_viewer("session-1", "user-alice")
        mock_sse_publish.assert_called_once()
        call_args = mock_sse_publish.call_args[0]
        assert call_args[0] == "session-1"
        assert call_args[1]["_type"] == "viewer_count"
        assert call_args[1]["delta"] == 1

    def test_multiple_tabs_same_user_creates_unique_viewer_ids(self, mock_ddb):
        r1 = broadcast_viewers.register_viewer("session-1", "user-alice")
        r2 = broadcast_viewers.register_viewer("session-1", "user-alice")
        assert r1["viewer_id"] != r2["viewer_id"]


class TestTouchViewer:
    def test_touch_extends_ttl(self, mock_ddb):
        result = broadcast_viewers.register_viewer("session-1", "user-alice")
        count = broadcast_viewers.touch_viewer("session-1", result["viewer_id"])
        assert isinstance(count, int)
        assert count == 1

    def test_touch_nonexistent_raises(self, mock_ddb):
        with pytest.raises(ClientError):
            broadcast_viewers.touch_viewer("session-1", "nonexistent#abc")


class TestUnregisterViewer:
    def test_unregister_decrements_count(self, mock_ddb):
        r1 = broadcast_viewers.register_viewer("session-1", "user-alice")
        r2 = broadcast_viewers.register_viewer("session-1", "user-bob")
        count_after = broadcast_viewers.unregister_viewer("session-1", r1["viewer_id"])
        assert count_after == 1  # Only bob remains

    def test_unregister_publishes_negative_delta(self, mock_ddb, mock_sse_publish):
        r = broadcast_viewers.register_viewer("session-1", "user-alice")
        mock_sse_publish.reset_mock()
        broadcast_viewers.unregister_viewer("session-1", r["viewer_id"])
        call_args = mock_sse_publish.call_args[0]
        assert call_args[1]["delta"] == -1


class TestGetViewerCount:
    def test_empty_session_returns_zero(self, mock_ddb):
        assert broadcast_viewers.get_viewer_count("nonexistent-session") == 0

    def test_count_matches_registered_viewers(self, mock_ddb):
        broadcast_viewers.register_viewer("session-1", "user-alice")
        broadcast_viewers.register_viewer("session-1", "user-bob")
        broadcast_viewers.register_viewer("session-1", "user-charlie")
        assert broadcast_viewers.get_viewer_count("session-1") == 3
