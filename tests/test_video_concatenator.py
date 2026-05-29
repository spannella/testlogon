"""Unit tests for video concatenation service (VOD-016).

Tests concat creation validation, owner check, status check, count constraints,
codec compatibility detection, and job type.
"""

from __future__ import annotations

from decimal import Decimal
from types import SimpleNamespace
from typing import Any, Dict, List, Optional
from unittest.mock import patch

import pytest
from fastapi import HTTPException

from app.services import video_metadata_store, transcode_job_store
from app.services.video_metadata_store import (
    video_from_item,
    video_to_item,
)
from app.models_video import VideoMetadataModel


# ─── In-memory DynamoDB table stubs ──────────────────────────────────────────


class _FakeTable:
    """In-memory DynamoDB table stub for unit tests."""

    def __init__(self) -> None:
        self.items: dict = {}

    def put_item(self, *, Item, ConditionExpression=None, **kwargs):
        key = Item.get("video_id") or Item.get("job_id")
        if ConditionExpression and "attribute_not_exists" in str(ConditionExpression):
            if key in self.items:
                from botocore.exceptions import ClientError
                raise ClientError(
                    {"Error": {"Code": "ConditionalCheckFailedException"}},
                    "PutItem",
                )
        self.items[key] = Item

    def get_item(self, *, Key, ConsistentRead=False, **kwargs):
        key = Key.get("video_id") or Key.get("job_id")
        item = self.items.get(key)
        return {"Item": item} if item else {}

    def update_item(self, *, Key, UpdateExpression="", **kwargs):
        key = Key.get("video_id") or Key.get("job_id")
        item = self.items.get(key)
        if item is None:
            item = dict(Key)
            self.items[key] = item
        expr_values = kwargs.get("ExpressionAttributeValues", {})
        expr_names = kwargs.get("ExpressionAttributeNames", {})
        for placeholder, val in expr_values.items():
            for part in UpdateExpression.replace("SET ", "").split(","):
                part = part.strip()
                if placeholder in part:
                    field_name = part.split("=")[0].strip()
                    # Resolve expression attribute names
                    if field_name.startswith("#"):
                        field_name = expr_names.get(field_name, field_name.lstrip("#"))
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


def _seed_video(tables, *, video_id="v_src1", owner="user-1",
                status="published", duration=120.0,
                source_s3_key="videos/user-1/v_src1/source.mp4",
                video_codec="h264", width=1920, height=1080,
                frame_rate=30.0, audio_codec="aac",
                file_size_bytes=50_000_000):
    """Seed a source video into the fake table."""
    from app.core.time import now_ts
    ts = now_ts()
    item: Dict[str, Any] = {
        "video_id": video_id,
        "owner_user_id": owner,
        "title": f"Video {video_id}",
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
    if video_codec:
        item["video_codec"] = video_codec
    if audio_codec:
        item["audio_codec"] = audio_codec
    if width:
        item["width"] = width
    if height:
        item["height"] = height
    if frame_rate is not None:
        item["frame_rate"] = Decimal(str(frame_rate))
    if file_size_bytes:
        item["file_size_bytes"] = file_size_bytes
    tables.video_metadata.items[video_id] = item


def _seed_two_compatible(tables, owner="user-1"):
    """Seed two compatible videos (same codec, resolution, framerate)."""
    _seed_video(tables, video_id="v_a", owner=owner)
    _seed_video(tables, video_id="v_b", owner=owner)


def _run_concat(tables, **overrides):
    """Run create_concat_job with default args, applying overrides."""
    defaults = {
        "owner_user_id": "user-1",
        "source_video_ids": ["v_a", "v_b"],
        "title": "Combined Video",
    }
    defaults.update(overrides)
    with patch.object(video_metadata_store, "T", tables), \
         patch.object(transcode_job_store, "T", tables):
        from app.services.video_concatenator import create_concat_job
        return create_concat_job(**defaults)


# ─── Tests ────────────────────────────────────────────────────────────────────


def test_concat_valid_two_videos():
    """A valid concat request with 2 videos creates a new video + job."""
    tables = _make_tables()
    _seed_two_compatible(tables)

    result = _run_concat(tables)

    assert result["video_id"].startswith("v_")
    assert result["created_via"] == "concat"
    assert result["source_video_ids"] == ["v_a", "v_b"]
    assert result["concat_job_id"].startswith("tj_")
    assert result["title"] == "Combined Video"
    assert result["status"] == "created"
    assert result["estimated_duration_seconds"] == 240.0  # 120 + 120


def test_concat_too_few_videos_raises_400():
    """Fewer than 2 video IDs should raise 400."""
    tables = _make_tables()
    _seed_video(tables, video_id="v_a")

    with pytest.raises(HTTPException) as exc_info:
        _run_concat(tables, source_video_ids=["v_a"])
    assert exc_info.value.status_code == 400
    assert "at least 2" in str(exc_info.value.detail)


def test_concat_too_many_videos_raises_400():
    """More than max_inputs video IDs should raise 400."""
    tables = _make_tables()
    ids = []
    for i in range(11):
        vid = f"v_{i}"
        _seed_video(tables, video_id=vid)
        ids.append(vid)

    with pytest.raises(HTTPException) as exc_info:
        _run_concat(tables, source_video_ids=ids)
    assert exc_info.value.status_code == 400
    assert "at most" in str(exc_info.value.detail)


def test_concat_duplicate_ids_raises_400():
    """Duplicate video IDs should raise 400."""
    tables = _make_tables()
    _seed_two_compatible(tables)

    with pytest.raises(HTTPException) as exc_info:
        _run_concat(tables, source_video_ids=["v_a", "v_a"])
    assert exc_info.value.status_code == 400
    assert "duplicates" in str(exc_info.value.detail)


def test_concat_non_owner_raises_403():
    """A video not owned by the requester should raise 403."""
    tables = _make_tables()
    _seed_video(tables, video_id="v_a", owner="user-1")
    _seed_video(tables, video_id="v_b", owner="user-2")

    with pytest.raises(HTTPException) as exc_info:
        _run_concat(tables, owner_user_id="user-1", source_video_ids=["v_a", "v_b"])
    assert exc_info.value.status_code == 403
    assert "not owned by you" in str(exc_info.value.detail)


def test_concat_mixed_owners_raises_403():
    """Both videos must be owned by the requester."""
    tables = _make_tables()
    _seed_video(tables, video_id="v_a", owner="user-2")
    _seed_video(tables, video_id="v_b", owner="user-2")

    with pytest.raises(HTTPException) as exc_info:
        _run_concat(tables, owner_user_id="user-1", source_video_ids=["v_a", "v_b"])
    assert exc_info.value.status_code == 403


def test_concat_non_published_raises_409():
    """A video not in published/approved status should raise 409."""
    tables = _make_tables()
    _seed_video(tables, video_id="v_a", owner="user-1", status="published")
    _seed_video(tables, video_id="v_b", owner="user-1", status="encoding")

    with pytest.raises(HTTPException) as exc_info:
        _run_concat(tables, source_video_ids=["v_a", "v_b"])
    assert exc_info.value.status_code == 409
    assert "published or approved" in str(exc_info.value.detail)


def test_concat_video_not_found_raises_404():
    """A non-existent video ID should raise 404."""
    tables = _make_tables()
    _seed_video(tables, video_id="v_a")

    with pytest.raises(HTTPException) as exc_info:
        _run_concat(tables, source_video_ids=["v_a", "v_nonexistent"])
    assert exc_info.value.status_code == 404
    assert "not found" in str(exc_info.value.detail)


def test_concat_job_type_is_combine():
    """The enqueued job should have job_type='combine'."""
    tables = _make_tables()
    _seed_two_compatible(tables)

    result = _run_concat(tables)

    job_id = result["concat_job_id"]
    job = tables.transcode_jobs.items[job_id]
    assert job["job_type"] == "combine"
    assert job["concat_source_video_ids"] == ["v_a", "v_b"]
    assert job["concat_method"] in ("demuxer", "filter")


def test_concat_source_video_ids_on_created_video():
    """The new video should have source_video_ids set."""
    tables = _make_tables()
    _seed_two_compatible(tables)

    result = _run_concat(tables)

    new_video_id = result["video_id"]
    item = tables.video_metadata.items[new_video_id]
    assert item.get("source_video_ids") == ["v_a", "v_b"]
    assert item.get("created_via") == "concat"


def test_codec_compatibility_same_params():
    """Videos with same codec, resolution, framerate are compatible."""
    from app.services.video_concatenator import _check_codec_compatibility
    v1 = VideoMetadataModel(
        id="v_1", owner_user_id="u", title="V1",
        video_codec="h264", audio_codec="aac",
        width=1920, height=1080, frame_rate=30.0,
    )
    v2 = VideoMetadataModel(
        id="v_2", owner_user_id="u", title="V2",
        video_codec="h264", audio_codec="aac",
        width=1920, height=1080, frame_rate=30.0,
    )
    assert _check_codec_compatibility([v1, v2]) is True


def test_codec_compatibility_different_codec():
    """Videos with different video codecs are incompatible."""
    from app.services.video_concatenator import _check_codec_compatibility
    v1 = VideoMetadataModel(
        id="v_1", owner_user_id="u", title="V1",
        video_codec="h264", audio_codec="aac",
        width=1920, height=1080, frame_rate=30.0,
    )
    v2 = VideoMetadataModel(
        id="v_2", owner_user_id="u", title="V2",
        video_codec="vp9", audio_codec="aac",
        width=1920, height=1080, frame_rate=30.0,
    )
    assert _check_codec_compatibility([v1, v2]) is False


def test_codec_compatibility_different_resolution():
    """Videos with different resolutions are incompatible."""
    from app.services.video_concatenator import _check_codec_compatibility
    v1 = VideoMetadataModel(
        id="v_1", owner_user_id="u", title="V1",
        video_codec="h264", audio_codec="aac",
        width=1920, height=1080, frame_rate=30.0,
    )
    v2 = VideoMetadataModel(
        id="v_2", owner_user_id="u", title="V2",
        video_codec="h264", audio_codec="aac",
        width=1280, height=720, frame_rate=30.0,
    )
    assert _check_codec_compatibility([v1, v2]) is False


def test_codec_compatibility_missing_probe_data():
    """Videos with missing probe data are treated as incompatible."""
    from app.services.video_concatenator import _check_codec_compatibility
    v1 = VideoMetadataModel(
        id="v_1", owner_user_id="u", title="V1",
        video_codec="h264", audio_codec="aac",
        width=1920, height=1080, frame_rate=30.0,
    )
    v2 = VideoMetadataModel(
        id="v_2", owner_user_id="u", title="V2",
        video_codec=None, audio_codec="aac",
        width=1920, height=1080, frame_rate=30.0,
    )
    assert _check_codec_compatibility([v1, v2]) is False


def test_concat_demuxer_for_compatible_videos():
    """Compatible videos should result in concat_method='demuxer'."""
    tables = _make_tables()
    _seed_two_compatible(tables)

    result = _run_concat(tables)
    assert result["concat_method"] == "demuxer"


def test_concat_filter_for_incompatible_videos():
    """Incompatible videos should result in concat_method='filter'."""
    tables = _make_tables()
    _seed_video(tables, video_id="v_a", owner="user-1",
                video_codec="h264", width=1920, height=1080)
    _seed_video(tables, video_id="v_b", owner="user-1",
                video_codec="vp9", width=1280, height=720)

    result = _run_concat(tables)
    assert result["concat_method"] == "filter"


def test_concat_roundtrip_serialization():
    """source_video_ids survives video_to_item -> video_from_item roundtrip."""
    video = VideoMetadataModel(
        id="v_concat1",
        owner_user_id="user-1",
        title="Combined Video",
        source_video_ids=["v_a", "v_b", "v_c"],
        created_via="concat",
    )

    item = video_to_item(video)
    assert item["source_video_ids"] == ["v_a", "v_b", "v_c"]
    assert item["created_via"] == "concat"

    restored = video_from_item(item)
    assert restored.source_video_ids == ["v_a", "v_b", "v_c"]
    assert restored.created_via == "concat"
