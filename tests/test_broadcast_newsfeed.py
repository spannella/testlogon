"""Tests for broadcast newsfeed promotion (BCAST-010).

Tests the service layer: announcement post creation, live post creation/update,
VOD post creation, post deletion, and post_type in _post_to_dict.
"""

from __future__ import annotations

import os
from decimal import Decimal
from types import SimpleNamespace
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Lightweight in-memory DynamoDB table stub
# ---------------------------------------------------------------------------

class _FakeTable:
    """Minimal DynamoDB Table stub that stores items in a dict keyed by (pk, sk)."""

    def __init__(self) -> None:
        self.items: Dict[tuple, Dict[str, Any]] = {}

    def put_item(self, *, Item: Dict[str, Any], **kwargs) -> None:
        pk = Item.get("pk", Item.get("session_id", ""))
        sk = Item.get("sk", "")
        self.items[(pk, sk)] = Item

    def get_item(self, *, Key: Dict[str, Any], **kwargs) -> Dict[str, Any]:
        pk = Key.get("pk", "")
        sk = Key.get("sk", "")
        item = self.items.get((pk, sk))
        return {"Item": item} if item else {}

    def update_item(self, *, Key: Dict[str, Any], UpdateExpression: str = "",
                    ExpressionAttributeNames: Optional[Dict] = None,
                    ExpressionAttributeValues: Optional[Dict] = None, **kwargs) -> None:
        pk = Key.get("pk", "")
        sk = Key.get("sk", "")
        item = self.items.get((pk, sk))
        if item is None:
            item = dict(Key)
            self.items[(pk, sk)] = item
        # Simple SET parser
        if "SET" in UpdateExpression:
            vals = ExpressionAttributeValues or {}
            names = ExpressionAttributeNames or {}
            # Extract "field = :val" pairs from SET clause
            set_part = UpdateExpression.split("SET", 1)[1].strip()
            if " REMOVE " in set_part:
                set_part = set_part.split(" REMOVE ")[0].strip()
            for assignment in set_part.split(","):
                assignment = assignment.strip()
                if "=" not in assignment:
                    continue
                lhs, rhs = assignment.split("=", 1)
                lhs = lhs.strip()
                rhs = rhs.strip()
                # Resolve attribute name aliases
                resolved_name = names.get(lhs, lhs)
                value = vals.get(rhs, rhs)
                item[resolved_name] = value

    def delete_item(self, *, Key: Dict[str, Any], **kwargs) -> None:
        pk = Key.get("pk", "")
        sk = Key.get("sk", "")
        self.items.pop((pk, sk), None)

    def query(self, **kwargs) -> Dict[str, Any]:
        # Return all items matching the pk
        kce = kwargs.get("KeyConditionExpression")
        items = list(self.items.values())
        return {"Items": items, "Count": len(items)}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _patch_env():
    """Ensure APP_TABLE env var is set."""
    with patch.dict(os.environ, {"APP_TABLE": "app_single_table"}):
        yield


@pytest.fixture()
def fake_table():
    """Create a shared fake table and patch the broadcast_newsfeed module's tbl."""
    table = _FakeTable()
    import app.services.broadcast_newsfeed as mod
    original_tbl = mod.tbl
    mod.tbl = table
    yield table
    mod.tbl = original_tbl


@pytest.fixture()
def no_fanout():
    """Patch out fan-out functions so they don't try to hit real DDB."""
    with patch("app.services.newsfeed_fanout.fan_out_post_to_followers", return_value=0) as mock_fo, \
         patch("app.services.newsfeed_fanout.fan_out_delete_post", return_value=0) as mock_del:
        yield mock_fo, mock_del


# ---------------------------------------------------------------------------
# Tests: Announcement Post
# ---------------------------------------------------------------------------

class TestAnnouncementPost:

    def test_creates_post_with_correct_fields(self, fake_table, no_fanout):
        from app.services.broadcast_newsfeed import create_announcement_post
        post_id = create_announcement_post(
            session_id="s1",
            creator_id="alice",
            session_name="Test Stream",
            session_description="A test broadcast",
            scheduled_at=1700000000,
        )
        assert post_id is not None
        item = fake_table.get_item(Key={"pk": f"POST#{post_id}", "sk": "META"}).get("Item")
        assert item is not None
        assert item["post_type"] == "broadcast_announcement"
        assert item["broadcast_meta"]["session_id"] == "s1"
        assert item["broadcast_meta"]["scheduled_at"] == 1700000000
        assert item["broadcast_meta"]["is_live"] is False

    def test_text_includes_schedule(self, fake_table, no_fanout):
        from app.services.broadcast_newsfeed import create_announcement_post
        post_id = create_announcement_post(
            session_id="s1",
            creator_id="alice",
            session_name="Demo",
            scheduled_at=1700000000,
        )
        item = fake_table.get_item(Key={"pk": f"POST#{post_id}", "sk": "META"}).get("Item")
        assert "Upcoming broadcast" in item["text"]
        assert "Demo" in item["text"]

    def test_text_without_schedule(self, fake_table, no_fanout):
        from app.services.broadcast_newsfeed import create_announcement_post
        post_id = create_announcement_post(
            session_id="s1",
            creator_id="alice",
            session_name="Quick Live",
        )
        item = fake_table.get_item(Key={"pk": f"POST#{post_id}", "sk": "META"}).get("Item")
        assert "New broadcast" in item["text"]

    def test_creates_feed_ref(self, fake_table, no_fanout):
        from app.services.broadcast_newsfeed import create_announcement_post
        post_id = create_announcement_post(
            session_id="s1",
            creator_id="alice",
            session_name="Demo",
        )
        ref = fake_table.get_item(Key={"pk": f"POST#{post_id}", "sk": "FEEDREF#alice"}).get("Item")
        assert ref is not None
        assert ref["GSI1PK"] == "FEED#alice"

    def test_triggers_fanout(self, fake_table, no_fanout):
        mock_fo, _ = no_fanout
        from app.services.broadcast_newsfeed import create_announcement_post
        post_id = create_announcement_post(
            session_id="s1",
            creator_id="alice",
            session_name="Demo",
        )
        mock_fo.assert_called_once()
        assert mock_fo.call_args[1]["author_id"] == "alice"

    def test_failure_returns_none(self, fake_table, no_fanout):
        """If DDB write fails, create_announcement_post returns None."""
        from app.services.broadcast_newsfeed import create_announcement_post
        with patch.object(fake_table, "put_item", side_effect=Exception("DDB timeout")):
            post_id = create_announcement_post(
                session_id="s1",
                creator_id="alice",
                session_name="Demo",
            )
            assert post_id is None


# ---------------------------------------------------------------------------
# Tests: Live Post
# ---------------------------------------------------------------------------

class TestLivePost:

    def test_updates_existing_announcement(self, fake_table, no_fanout):
        from app.services.broadcast_newsfeed import create_announcement_post, create_live_post
        ann_id = create_announcement_post(
            session_id="s1",
            creator_id="alice",
            session_name="Demo",
            scheduled_at=1700000000,
        )
        live_id = create_live_post(
            session_id="s1",
            creator_id="alice",
            announcement_post_id=ann_id,
            session_name="Demo",
        )
        assert live_id == ann_id  # Same post ID
        item = fake_table.get_item(Key={"pk": f"POST#{ann_id}", "sk": "META"}).get("Item")
        assert item["post_type"] == "broadcast_live"
        assert "LIVE NOW" in item["text"]
        assert item["broadcast_meta"]["is_live"] is True

    def test_creates_new_when_no_announcement(self, fake_table, no_fanout):
        from app.services.broadcast_newsfeed import create_live_post
        live_id = create_live_post(
            session_id="s1",
            creator_id="alice",
            session_name="Demo",
        )
        assert live_id is not None
        item = fake_table.get_item(Key={"pk": f"POST#{live_id}", "sk": "META"}).get("Item")
        assert item["post_type"] == "broadcast_live"


# ---------------------------------------------------------------------------
# Tests: VOD Post
# ---------------------------------------------------------------------------

class TestVodPost:

    def test_includes_duration_and_viewers(self, fake_table, no_fanout):
        from app.services.broadcast_newsfeed import create_vod_post
        post_id = create_vod_post(
            session_id="s1",
            creator_id="alice",
            session_name="Demo",
            recording_duration_seconds=4980,
            peak_viewer_count=1234,
        )
        item = fake_table.get_item(Key={"pk": f"POST#{post_id}", "sk": "META"}).get("Item")
        assert item["post_type"] == "broadcast_vod"
        assert "1h 23m" in item["text"]
        assert "1,234" in item["text"]

    def test_meta_has_recording_fields(self, fake_table, no_fanout):
        from app.services.broadcast_newsfeed import create_vod_post
        post_id = create_vod_post(
            session_id="s1",
            creator_id="alice",
            recording_id="rec_123",
            recording_duration_seconds=3600,
        )
        item = fake_table.get_item(Key={"pk": f"POST#{post_id}", "sk": "META"}).get("Item")
        meta = item["broadcast_meta"]
        assert meta["recording_id"] == "rec_123"
        assert meta["recording_duration_seconds"] == 3600


# ---------------------------------------------------------------------------
# Tests: Post Deletion
# ---------------------------------------------------------------------------

class TestDeletePost:

    def test_removes_post_and_refs(self, fake_table, no_fanout):
        from app.services.broadcast_newsfeed import create_announcement_post, delete_broadcast_post
        post_id = create_announcement_post(
            session_id="s1",
            creator_id="alice",
            session_name="Demo",
        )
        result = delete_broadcast_post(post_id=post_id, user_id="alice")
        assert result is True
        item = fake_table.get_item(Key={"pk": f"POST#{post_id}", "sk": "META"}).get("Item")
        assert item is None


# ---------------------------------------------------------------------------
# Tests: _post_to_dict post_type field
# ---------------------------------------------------------------------------

class TestPostToDict:

    def test_post_type_defaults_to_standard(self):
        """Regular posts without post_type should default to 'standard'."""
        # Minimal post dict simulating DDB item
        post = {
            "pk": "POST#test1",
            "sk": "META",
            "post_id": "test1",
            "user_id": "alice",
            "created_at": "2024-01-01T00:00:00",
            "body": "hello",
            "visibility": "public",
            "like_count": 0,
            "comment_count": 0,
        }
        from app.routers.newsfeed import _post_to_dict
        result = _post_to_dict(post, viewer_id="bob")
        assert result["post_type"] == "standard"
        assert result["broadcast_meta"] is None

    def test_post_type_broadcast_announcement(self):
        """Posts with post_type set should return that type."""
        post = {
            "pk": "POST#test2",
            "sk": "META",
            "post_id": "test2",
            "user_id": "alice",
            "created_at": "2024-01-01T00:00:00",
            "body": "Upcoming broadcast",
            "visibility": "public",
            "like_count": 0,
            "comment_count": 0,
            "post_type": "broadcast_announcement",
            "broadcast_meta": {
                "session_id": "s1",
                "post_type": "broadcast_announcement",
                "session_name": "Demo",
                "is_live": False,
            },
        }
        from app.routers.newsfeed import _post_to_dict
        result = _post_to_dict(post, viewer_id="bob")
        assert result["post_type"] == "broadcast_announcement"
        assert result["broadcast_meta"] is not None
        assert result["broadcast_meta"]["session_id"] == "s1"
