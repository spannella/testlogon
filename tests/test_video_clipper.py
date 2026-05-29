"""Unit tests for video clipping service (VOD-015).

Tests clip creation validation, owner check, status check, and duration constraints.
"""

from __future__ import annotations

from decimal import Decimal
from types import SimpleNamespace
from typing import Any, Dict, List, Optional
from unittest.mock import patch, MagicMock

import pytest
from fastapi import HTTPException

from app.services import video_metadata_store, transcode_job_store
from app.services.video_metadata_store import (
    create_video,
    get_video,
    update_clip_fields,
    video_from_item,
    video_to_item,
)
from app.models_video import VideoMetadataModel


# ─── In-memory DynamoDB table stubs ──────────────────────────────────────────


class _FakeTable:
    """In-memory DynamoDB table stub for unit tests."""

    def __init__(self) -> None:
        self.items: dict = {}

    def put_item(self, *, Item, ConditionExpression=None):
        key = Item.get("video_id") or Item.get("job_id")
        if ConditionExpression and "attribute_not_exists" in str(ConditionExpression):
            if key in self.items:
                from botocore.exceptions import ClientError
                raise ClientError(
                    {"Error": {"Code": "ConditionalCheckFailedException"}},
                    "PutItem",
                )
        self.items[key] = Item

    def get_item(self, *, Key, ConsistentRead=False):
        key = Key.get("video_id") or Key.get("job_id")
        item = self.items.get(key)
        return {"Item": item} if item else {}

    def update_item(self, *, Key, UpdateExpression="", **kwargs):
        key = Key.get("video_id") or Key.get("job_id")
        item = self.items.get(key)
        if item is None:
            item = dict(Key)
            self.items[key] = item
        # Simple expression parsing for SET
        expr_values = kwargs.get("ExpressionAttributeValues", {})
        for placeholder, val in expr_values.items():
            # extract field name from the SET clause
            # e.g., "SET source_video_id = :svid, ..." -> need to map :svid to source_video_id
            clean = placeholder.lstrip(":")
            # find the field name in the expression
            for part in UpdateExpression.replace("SET ", "").split(","):
                part = part.strip()
                if placeholder in part:
                    field_name = part.split("=")[0].strip().lstrip("#")
                    # resolve expression attribute names
                    expr_names = kwargs.get("ExpressionAttributeNames", {})
                    if f"#{field_name}" in expr_names:
                        field_name = expr_names[f"#{field_name}"]
                    elif field_name.startswith("#"):
                        resolved = expr_names.get(field_name, field_name.lstrip("#"))
                        field_name = resolved
                    item[field_name] = val
                    break

    def query(self, **kwargs):
        return {"Items": list(self.items.values()), "Count": len(self.items)}


class _FakeJobTable:
    """In-memory DDB stub for transcode_jobs."""

    def __init__(self) -> None:
        self.items: dict = {}

    def put_item(self, *, Item, **kwargs):
        key = Item.get("job_id")
        self.items[key] = Item

    def get_item(self, *, Key, **kwargs):
        key = Key.get("job_id")
        item = self.items.get(key)
        return {"Item": item} if item else {}


def _make_tables():
    return SimpleNamespace(
        video_metadata=_FakeTable(),
        transcode_jobs=_FakeJobTable(),
    )


def _seed_source_video(tables, *, video_id="v_source1", owner="user-1",
                        status="published", duration=120.0,
                        source_s3_key="videos/user-1/v_source1/source.mp4"):
    """Seed a source video into the fake table."""
    from app.core.time import now_ts
    ts = now_ts()
    item = {
        "video_id": video_id,
        "owner_user_id": owner,
        "title": "Source Video",
        "status": status,
        "created_at": ts,
        "updated_at": ts,
        "source_type": "upload",
        "visibility": "public",
        "drm_enabled": False,
        "allow_download": False,
    }
    if duration is not None:
        item["duration_seconds"] = Decimal(str(duration))
    if source_s3_key:
        item["source_s3_key"] = source_s3_key
    tables.video_metadata.items[video_id] = item


# ─── Tests ────────────────────────────────────────────────────────────────────


def test_clip_valid_range_creates_new_video():
    """A valid clip request creates a new video + job and returns correct fields."""
    tables = _make_tables()
    _seed_source_video(tables)

    with patch.object(video_metadata_store, "T", tables), \
         patch.object(transcode_job_store, "T", tables):
        from app.services.video_clipper import create_clip
        result = create_clip(
            owner_user_id="user-1",
            source_video_id="v_source1",
            start_seconds=10.0,
            end_seconds=40.0,
            title="My Clip",
        )

    assert result["created_via"] == "clip"
    assert result["source_video_id"] == "v_source1"
    assert result["clip_start_seconds"] == 10.0
    assert result["clip_end_seconds"] == 40.0
    assert result["title"] == "My Clip"
    assert result["video_id"].startswith("v_")
    assert result["clip_job_id"].startswith("tj_")


def test_clip_default_title():
    """When no title is provided, default to '{source title} (clip)'."""
    tables = _make_tables()
    _seed_source_video(tables)

    with patch.object(video_metadata_store, "T", tables), \
         patch.object(transcode_job_store, "T", tables):
        from app.services.video_clipper import create_clip
        result = create_clip(
            owner_user_id="user-1",
            source_video_id="v_source1",
            start_seconds=0,
            end_seconds=30.0,
        )

    assert result["title"] == "Source Video (clip)"


def test_clip_start_ge_end_raises_400():
    """start_seconds >= end_seconds should raise 400."""
    tables = _make_tables()
    _seed_source_video(tables)

    with patch.object(video_metadata_store, "T", tables), \
         patch.object(transcode_job_store, "T", tables):
        from app.services.video_clipper import create_clip
        with pytest.raises(HTTPException) as exc_info:
            create_clip(
                owner_user_id="user-1",
                source_video_id="v_source1",
                start_seconds=60.0,
                end_seconds=30.0,
            )
    assert exc_info.value.status_code == 400
    assert "start_seconds must be less than end_seconds" in str(exc_info.value.detail)


def test_clip_duration_too_short_raises_400():
    """Clip duration below minimum should raise 400."""
    tables = _make_tables()
    _seed_source_video(tables)

    with patch.object(video_metadata_store, "T", tables), \
         patch.object(transcode_job_store, "T", tables):
        from app.services.video_clipper import create_clip

        # Default min is 1.0s in settings, but let's test with a very short clip
        # The settings default is video_clip_min_duration_seconds=1.0
        # We need to exceed 0 but be less than min. Use start=10, end=10.5 (0.5s)
        with pytest.raises(HTTPException) as exc_info:
            create_clip(
                owner_user_id="user-1",
                source_video_id="v_source1",
                start_seconds=10.0,
                end_seconds=10.5,
            )
    assert exc_info.value.status_code == 400
    assert "minimum clip length" in str(exc_info.value.detail)


def test_clip_non_owner_raises_403():
    """Non-owner trying to clip should get 403."""
    tables = _make_tables()
    _seed_source_video(tables, owner="user-1")

    with patch.object(video_metadata_store, "T", tables), \
         patch.object(transcode_job_store, "T", tables):
        from app.services.video_clipper import create_clip
        with pytest.raises(HTTPException) as exc_info:
            create_clip(
                owner_user_id="user-2",
                source_video_id="v_source1",
                start_seconds=10.0,
                end_seconds=40.0,
            )
    assert exc_info.value.status_code == 403


def test_clip_unpublished_video_raises_400():
    """Clipping a video not in published/approved status should raise 400."""
    tables = _make_tables()
    _seed_source_video(tables, status="encoding")

    with patch.object(video_metadata_store, "T", tables), \
         patch.object(transcode_job_store, "T", tables):
        from app.services.video_clipper import create_clip
        with pytest.raises(HTTPException) as exc_info:
            create_clip(
                owner_user_id="user-1",
                source_video_id="v_source1",
                start_seconds=10.0,
                end_seconds=40.0,
            )
    assert exc_info.value.status_code == 400
    assert "published or approved" in str(exc_info.value.detail)


def test_clip_end_exceeds_duration_raises_400():
    """end_seconds > source duration should raise 400."""
    tables = _make_tables()
    _seed_source_video(tables, duration=60.0)

    with patch.object(video_metadata_store, "T", tables), \
         patch.object(transcode_job_store, "T", tables):
        from app.services.video_clipper import create_clip
        with pytest.raises(HTTPException) as exc_info:
            create_clip(
                owner_user_id="user-1",
                source_video_id="v_source1",
                start_seconds=10.0,
                end_seconds=90.0,
            )
    assert exc_info.value.status_code == 400
    assert "exceeds video duration" in str(exc_info.value.detail)


def test_clip_no_source_key_raises_409():
    """Video with no source_s3_key should raise 409."""
    tables = _make_tables()
    _seed_source_video(tables, source_s3_key=None)

    with patch.object(video_metadata_store, "T", tables), \
         patch.object(transcode_job_store, "T", tables):
        from app.services.video_clipper import create_clip
        with pytest.raises(HTTPException) as exc_info:
            create_clip(
                owner_user_id="user-1",
                source_video_id="v_source1",
                start_seconds=10.0,
                end_seconds=40.0,
            )
    assert exc_info.value.status_code == 409
    assert "source file not available" in str(exc_info.value.detail)


def test_clip_video_not_found_raises_404():
    """Clipping a non-existent video should raise 404."""
    tables = _make_tables()

    with patch.object(video_metadata_store, "T", tables), \
         patch.object(transcode_job_store, "T", tables):
        from app.services.video_clipper import create_clip
        with pytest.raises(HTTPException) as exc_info:
            create_clip(
                owner_user_id="user-1",
                source_video_id="v_nonexistent",
                start_seconds=10.0,
                end_seconds=40.0,
            )
    assert exc_info.value.status_code == 404


def test_clip_job_has_correct_type():
    """The enqueued job should have job_type='clip' and clip metadata."""
    tables = _make_tables()
    _seed_source_video(tables)

    with patch.object(video_metadata_store, "T", tables), \
         patch.object(transcode_job_store, "T", tables):
        from app.services.video_clipper import create_clip
        result = create_clip(
            owner_user_id="user-1",
            source_video_id="v_source1",
            start_seconds=10.0,
            end_seconds=40.0,
        )

    # Find the job in the fake table
    job_id = result["clip_job_id"]
    job = tables.transcode_jobs.items[job_id]
    assert job["job_type"] == "clip"
    assert job["clip_source_video_id"] == "v_source1"
    assert float(job["clip_start_seconds"]) == 10.0
    assert float(job["clip_end_seconds"]) == 40.0


def test_clip_roundtrip_serialization():
    """Clip provenance fields survive video_to_item -> video_from_item roundtrip."""
    video = VideoMetadataModel(
        id="v_clip1",
        owner_user_id="user-1",
        title="Clipped Video",
        source_video_id="v_source1",
        clip_start_seconds=30.0,
        clip_end_seconds=90.0,
        created_via="clip",
    )

    item = video_to_item(video)
    assert item["source_video_id"] == "v_source1"
    assert float(item["clip_start_seconds"]) == 30.0
    assert float(item["clip_end_seconds"]) == 90.0
    assert item["created_via"] == "clip"

    restored = video_from_item(item)
    assert restored.source_video_id == "v_source1"
    assert restored.clip_start_seconds == 30.0
    assert restored.clip_end_seconds == 90.0
    assert restored.created_via == "clip"
