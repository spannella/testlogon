from __future__ import annotations

from decimal import Decimal
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from fastapi import HTTPException

from app.services import video_metadata_store
from app.services.video_metadata_store import (
    create_video,
    get_video,
    get_video_by_broadcast_session,
    list_videos_by_owner,
    list_videos_by_status,
    soft_delete_video,
    transition_video_status,
    update_video,
    video_from_item,
    video_to_item,
)
from app.models_video import UpdateVideoIn, VideoMetadataModel


class _FakeTable:
    """In-memory DynamoDB table stub for unit tests."""

    def __init__(self) -> None:
        self.items: dict = {}

    def put_item(self, *, Item, ConditionExpression=None):  # noqa: N803
        key = Item.get("video_id")
        if ConditionExpression and "attribute_not_exists" in ConditionExpression:
            if key in self.items:
                raise AssertionError("duplicate insert")
        self.items[key] = Item

    def get_item(self, *, Key, ConsistentRead=False):  # noqa: N803
        key = Key.get("video_id")
        item = self.items.get(key)
        return {"Item": item} if item else {}

    def query(self, **kwargs):
        index = kwargs.get("IndexName")
        limit = kwargs.get("Limit", 200)
        all_items = list(self.items.values())

        if index == "ByOwnerCreatedAt":
            owner = kwargs["KeyConditionExpression"]._values[1]
            items = [i for i in all_items if i.get("owner_user_id") == owner]
        elif index == "ByStatusCreatedAt":
            status = kwargs["KeyConditionExpression"]._values[1]
            items = [i for i in all_items if i.get("status") == status]
        elif index == "BySourceBroadcast":
            session_id = kwargs["KeyConditionExpression"]._values[1]
            items = [i for i in all_items if i.get("source_broadcast_session_id") == session_id]
        else:
            items = all_items

        # Sort by created_at descending (simulate ScanIndexForward=False)
        items.sort(key=lambda x: x.get("created_at", 0), reverse=True)

        # Apply pagination
        result_items = items[:limit]
        last_key = {"video_id": result_items[-1]["video_id"]} if len(items) > limit else None
        return {"Items": result_items, "LastEvaluatedKey": last_key}


def _make_ns():
    return SimpleNamespace(video_metadata=_FakeTable())


def test_create_and_get_roundtrip() -> None:
    """Create a video and retrieve it, verifying all fields match."""
    with patch.object(video_metadata_store, "T", _make_ns()):
        video = create_video(
            owner_user_id="user-1",
            title="My Test Video",
            description="A test description",
            source_type="upload",
            source_s3_key="uploads/raw/test.mp4",
            visibility="private",
        )
        loaded = get_video(video.id)

    assert loaded.id == video.id
    assert loaded.owner_user_id == "user-1"
    assert loaded.title == "My Test Video"
    assert loaded.description == "A test description"
    assert loaded.source_type == "upload"
    assert loaded.source_s3_key == "uploads/raw/test.mp4"
    assert loaded.visibility == "private"
    assert loaded.status == "created"


def test_get_missing_raises_404() -> None:
    """get_video raises 404 for nonexistent video_id."""
    with patch.object(video_metadata_store, "T", _make_ns()):
        with pytest.raises(HTTPException) as exc:
            get_video("nonexistent")
    assert exc.value.status_code == 404


def test_create_generates_uuid_and_timestamps() -> None:
    """Created video has a v_ prefixed ID and non-zero timestamps."""
    with patch.object(video_metadata_store, "T", _make_ns()):
        video = create_video(
            owner_user_id="user-2",
            title="Timestamp Test",
        )

    assert video.id.startswith("v_")
    assert len(video.id) > 3
    assert video.created_at > 0
    assert video.updated_at > 0
    assert video.created_at == video.updated_at


def test_list_by_owner_returns_items() -> None:
    """List videos for a specific owner returns only that owner's videos."""
    ns = _make_ns()
    with patch.object(video_metadata_store, "T", ns):
        create_video(owner_user_id="user-a", title="Video A1")
        create_video(owner_user_id="user-a", title="Video A2")
        create_video(owner_user_id="user-a", title="Video A3")
        create_video(owner_user_id="user-b", title="Video B1")

        result = list_videos_by_owner("user-a")

    assert len(result["items"]) == 3
    for item in result["items"]:
        assert item.owner_user_id == "user-a"


def test_list_by_owner_pagination() -> None:
    """Pagination returns cursor when more items exist."""
    ns = _make_ns()
    with patch.object(video_metadata_store, "T", ns):
        for i in range(10):
            create_video(owner_user_id="user-p", title=f"Video {i}")

        result = list_videos_by_owner("user-p", limit=2)

    assert len(result["items"]) == 2
    assert result["cursor"] is not None


def test_list_by_status() -> None:
    """List by status filters correctly."""
    ns = _make_ns()
    with patch.object(video_metadata_store, "T", ns):
        v1 = create_video(owner_user_id="user-s", title="V1")
        v2 = create_video(owner_user_id="user-s", title="V2")
        # Transition v1 to probing
        transition_video_status(video_id=v1.id, to_status="probing")

        result_created = list_videos_by_status("created")
        result_probing = list_videos_by_status("probing")

    assert len(result_created["items"]) == 1
    assert result_created["items"][0].id == v2.id
    assert len(result_probing["items"]) == 1
    assert result_probing["items"][0].id == v1.id


def test_update_video_partial() -> None:
    """Updating only title leaves description unchanged and advances updated_at."""
    ns = _make_ns()
    with patch.object(video_metadata_store, "T", ns):
        video = create_video(
            owner_user_id="user-u",
            title="Original Title",
            description="Keep this",
        )
        original_updated_at = video.updated_at

        updated = update_video(video.id, UpdateVideoIn(title="New Title"))

    assert updated.title == "New Title"
    assert updated.description == "Keep this"
    assert updated.updated_at >= original_updated_at


def test_delete_soft_deletes() -> None:
    """Soft-delete sets status=deleted and deleted_at."""
    ns = _make_ns()
    with patch.object(video_metadata_store, "T", ns):
        video = create_video(owner_user_id="user-d", title="To Delete")
        deleted = soft_delete_video(video.id)

    assert deleted.status == "deleted"
    assert deleted.deleted_at is not None
    assert deleted.deleted_at > 0


def test_transition_legal() -> None:
    """Legal transition created -> probing succeeds."""
    ns = _make_ns()
    with patch.object(video_metadata_store, "T", ns):
        video = create_video(owner_user_id="user-t", title="Transition Test")
        updated = transition_video_status(video_id=video.id, to_status="probing")

    assert updated.status == "probing"


def test_transition_illegal_raises_409() -> None:
    """Illegal transition created -> published raises 409."""
    ns = _make_ns()
    with patch.object(video_metadata_store, "T", ns):
        video = create_video(owner_user_id="user-t2", title="Illegal Transition")
        with pytest.raises(HTTPException) as exc:
            transition_video_status(video_id=video.id, to_status="published")

    assert exc.value.status_code == 409
    assert exc.value.detail["code"] == "VIDEO_INVALID_STATE_TRANSITION"


def test_transition_deleted_is_terminal() -> None:
    """Cannot transition out of deleted state."""
    ns = _make_ns()
    with patch.object(video_metadata_store, "T", ns):
        video = create_video(owner_user_id="user-t3", title="Terminal Test")
        soft_delete_video(video.id)
        with pytest.raises(HTTPException) as exc:
            transition_video_status(video_id=video.id, to_status="created")

    assert exc.value.status_code == 409


def test_source_broadcast_gsi_none_omitted() -> None:
    """When source_broadcast_session_id is None, it's omitted from the DDB item."""
    video = VideoMetadataModel(
        id="v_test123",
        owner_user_id="user-x",
        title="No Broadcast",
        source_broadcast_session_id=None,
        created_at=1000,
        updated_at=1000,
    )
    item = video_to_item(video)
    assert "source_broadcast_session_id" not in item


def test_decimal_coercion() -> None:
    """DynamoDB Decimal values are coerced to int/float in video_from_item."""
    raw_item = {
        "video_id": "v_decimal_test",
        "owner_user_id": "user-dec",
        "title": "Decimal Test",
        "status": "created",
        "created_at": Decimal("1716566400"),
        "updated_at": Decimal("1716566400"),
        "source_type": "upload",
        "visibility": "private",
        "width": Decimal("1920"),
        "height": Decimal("1080"),
        "duration_seconds": Decimal("123.45"),
        "bitrate_kbps": Decimal("5000"),
        "file_size_bytes": Decimal("104857600"),
    }
    video = video_from_item(raw_item)

    assert isinstance(video.created_at, int)
    assert video.created_at == 1716566400
    assert isinstance(video.width, int)
    assert video.width == 1920
    assert isinstance(video.height, int)
    assert video.height == 1080
    assert isinstance(video.duration_seconds, float)
    assert video.duration_seconds == 123.45
    assert isinstance(video.bitrate_kbps, int)
    assert video.bitrate_kbps == 5000
    assert isinstance(video.file_size_bytes, int)
    assert video.file_size_bytes == 104857600


def test_get_video_by_broadcast_session() -> None:
    """Look up video by broadcast session ID."""
    ns = _make_ns()
    with patch.object(video_metadata_store, "T", ns):
        video = create_video(
            owner_user_id="user-bc",
            title="From Broadcast",
            source_type="broadcast_archive",
            source_broadcast_session_id="session-abc",
        )
        found = get_video_by_broadcast_session("session-abc")
        not_found = get_video_by_broadcast_session("session-nonexistent")

    assert found is not None
    assert found.id == video.id
    assert not_found is None
