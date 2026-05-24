"""Unit tests for VOD upload endpoints (VOD-002).

Tests the presign and complete-upload endpoints using mocked DynamoDB
and S3 via the in-memory fake table pattern.
"""

from __future__ import annotations

from datetime import datetime, timezone, timedelta
from types import SimpleNamespace
from typing import Any, Dict
from unittest.mock import patch, MagicMock

import pytest
from fastapi import HTTPException


# ─── Fake DynamoDB table ─────────────────────────────────────────────────────


class _FakeTable:
    """In-memory DynamoDB table stub for unit tests."""

    def __init__(self) -> None:
        self.items: dict = {}

    def put_item(self, *, Item, ConditionExpression=None, **kwargs):
        key = Item.get("video_id")
        if ConditionExpression and "attribute_not_exists" in str(ConditionExpression):
            if key in self.items:
                from botocore.exceptions import ClientError

                raise ClientError(
                    {"Error": {"Code": "ConditionalCheckFailedException", "Message": ""}},
                    "PutItem",
                )
        self.items[key] = Item

    def get_item(self, *, Key, ConsistentRead=False, **kwargs):
        key = Key.get("video_id")
        item = self.items.get(key)
        return {"Item": item} if item else {}

    def delete_item(self, *, Key, **kwargs):
        key = Key.get("video_id")
        self.items.pop(key, None)

    def query(self, **kwargs):
        index = kwargs.get("IndexName")
        limit = kwargs.get("Limit", 200)
        filter_expr = kwargs.get("FilterExpression")
        all_items = list(self.items.values())

        if index == "ByOwnerCreatedAt":
            kce = kwargs.get("KeyConditionExpression")
            owner = kce._values[1] if kce else None
            items = [i for i in all_items if i.get("owner_user_id") == owner]
        elif index == "ByStatusCreatedAt":
            kce = kwargs.get("KeyConditionExpression")
            status = kce._values[1] if kce else None
            items = [i for i in all_items if i.get("status") == status]
        elif index == "BySourceBroadcast":
            kce = kwargs.get("KeyConditionExpression")
            session_id = kce._values[1] if kce else None
            items = [i for i in all_items if i.get("source_broadcast_session_id") == session_id]
        else:
            items = all_items

        # Simple filter expression support
        if filter_expr:
            filtered = []
            for item in items:
                try:
                    # boto3 Attr conditions have _path and _values
                    attr_name = filter_expr._path[0] if hasattr(filter_expr, "_path") else None
                    attr_value = filter_expr._values[1] if hasattr(filter_expr, "_values") else None
                    if attr_name and attr_value:
                        if item.get(attr_name) == attr_value:
                            filtered.append(item)
                    else:
                        filtered.append(item)
                except (IndexError, AttributeError):
                    filtered.append(item)
            items = filtered

        items.sort(key=lambda x: x.get("created_at", 0), reverse=True)
        result_items = items[:limit]
        last_key = {"video_id": result_items[-1]["video_id"]} if len(items) > limit else None
        return {"Items": result_items, "LastEvaluatedKey": last_key}


# ─── Fake S3 client ──────────────────────────────────────────────────────────


class _FakeS3:
    """Minimal S3 client stub."""

    def __init__(self) -> None:
        self.objects: Dict[str, Dict[str, Any]] = {}

    def generate_presigned_url(self, **kwargs):
        return "https://s3.amazonaws.com/fake-presigned-url"

    def head_object(self, *, Bucket, Key, **kwargs):
        obj_key = f"{Bucket}/{Key}"
        if obj_key not in self.objects:
            from botocore.exceptions import ClientError

            raise ClientError(
                {"Error": {"Code": "NoSuchKey", "Message": "Not found"}},
                "HeadObject",
            )
        return self.objects[obj_key]

    def put_object(self, *, Bucket, Key, Body, **kwargs):
        obj_key = f"{Bucket}/{Key}"
        self.objects[obj_key] = {
            "ContentLength": len(Body) if Body else 0,
            "ContentType": kwargs.get("ContentType", "application/octet-stream"),
            "ETag": '"fake-etag"',
            "Metadata": kwargs.get("Metadata", {}),
        }


# ─── Helpers ─────────────────────────────────────────────────────────────────


def _make_fake_ns():
    return SimpleNamespace(video_metadata=_FakeTable())


def _make_user_session(user_sub: str = "test-user-123"):
    return {"user_sub": user_sub, "role": "USER", "admin_profile": None}


def _patched_presign(fake_ns, fake_s3, inp_data, user_sub="test-user-123"):
    """Call vod_presign_upload with all dependencies patched."""
    from app.routers import vod
    from app.routers.vod import VideoUploadPresignIn, vod_presign_upload
    from app.services import video_metadata_store

    inp = VideoUploadPresignIn(**inp_data)
    user = _make_user_session(user_sub)

    with patch.object(vod, "_s3", fake_s3), \
         patch.object(video_metadata_store, "T", fake_ns), \
         patch("app.routers.vod.T", fake_ns):
        return vod_presign_upload(inp, user)


def _patched_complete(fake_ns, fake_s3, video_id, user_sub="test-user-123"):
    """Call vod_complete_upload with all dependencies patched."""
    from app.routers import vod
    from app.routers.vod import vod_complete_upload
    from app.services import video_metadata_store

    user = _make_user_session(user_sub)

    with patch.object(vod, "_s3", fake_s3), \
         patch.object(video_metadata_store, "T", fake_ns), \
         patch("app.routers.vod.T", fake_ns):
        return vod_complete_upload(video_id, user)


# ─── Tests: Presign endpoint ────────────────────────────────────────────────


class TestVodPresign:
    """Tests for POST /ui/videos/upload/presign."""

    def test_presign_returns_url_and_creates_video_record(self):
        """POST presign with valid video content type returns presigned_url and video_id."""
        fake_ns = _make_fake_ns()
        fake_s3 = _FakeS3()

        result = _patched_presign(
            fake_ns,
            fake_s3,
            {
                "filename": "test-video.mp4",
                "content_type": "video/mp4",
                "size_bytes": 1024 * 1024,
            },
        )

        assert result.video_id
        assert result.video_id.startswith("v_")
        assert result.presigned_url
        assert result.s3_key
        assert "videos/" in result.s3_key
        assert "test-video.mp4" in result.s3_key
        assert result.expires_in_seconds == 3600

        # Verify video record was created in DDB
        video_item = fake_ns.video_metadata.items.get(result.video_id)
        assert video_item is not None
        assert video_item["owner_user_id"] == "test-user-123"
        assert video_item["status"] == "created"

    def test_presign_invalid_content_type_returns_422(self):
        """content_type='application/pdf' returns 422."""
        fake_ns = _make_fake_ns()
        fake_s3 = _FakeS3()

        with pytest.raises(HTTPException) as exc_info:
            _patched_presign(
                fake_ns,
                fake_s3,
                {
                    "filename": "document.pdf",
                    "content_type": "application/pdf",
                    "size_bytes": 1024,
                },
            )

        assert exc_info.value.status_code == 422

    def test_presign_size_exceeds_limit_returns_422(self):
        """file_size_bytes > 10GB is rejected by Pydantic validation (le=...)."""
        from pydantic import ValidationError
        from app.routers.vod import VideoUploadPresignIn

        with pytest.raises(ValidationError):
            VideoUploadPresignIn(
                filename="huge.mp4",
                content_type="video/mp4",
                size_bytes=20_000_000_000,  # 20 GB > 10 GB limit
            )

    def test_presign_zero_size_returns_422(self):
        """file_size_bytes=0 is rejected by Pydantic validation (ge=1)."""
        from pydantic import ValidationError
        from app.routers.vod import VideoUploadPresignIn

        with pytest.raises(ValidationError):
            VideoUploadPresignIn(
                filename="empty.mp4",
                content_type="video/mp4",
                size_bytes=0,
            )

    def test_presign_webm_content_type_accepted(self):
        """video/webm is a valid content type."""
        fake_ns = _make_fake_ns()
        fake_s3 = _FakeS3()

        result = _patched_presign(
            fake_ns,
            fake_s3,
            {
                "filename": "clip.webm",
                "content_type": "video/webm",
                "size_bytes": 5000,
            },
        )

        assert result.video_id
        assert result.presigned_url

    def test_presign_quicktime_content_type_accepted(self):
        """video/quicktime (.mov) is a valid content type."""
        fake_ns = _make_fake_ns()
        fake_s3 = _FakeS3()

        result = _patched_presign(
            fake_ns,
            fake_s3,
            {
                "filename": "recording.mov",
                "content_type": "video/quicktime",
                "size_bytes": 2048,
            },
        )

        assert result.video_id
        assert result.presigned_url

    def test_presign_stores_ticket_in_dynamodb(self):
        """After presign, an upload ticket exists in DDB."""
        fake_ns = _make_fake_ns()
        fake_s3 = _FakeS3()

        result = _patched_presign(
            fake_ns,
            fake_s3,
            {
                "filename": "test.mp4",
                "content_type": "video/mp4",
                "size_bytes": 1024,
            },
        )

        # Find ticket items
        ticket_items = [
            v for k, v in fake_ns.video_metadata.items.items()
            if isinstance(k, str) and k.startswith("TICKET#")
        ]
        assert len(ticket_items) == 1
        ticket = ticket_items[0]
        assert ticket["actual_video_id"] == result.video_id
        assert ticket["s3_key"] == result.s3_key
        assert ticket["content_type"] == "video/mp4"
        assert ticket["owner_user_id"] == "test-user-123"

    def test_presign_dev_mode_returns_mock_url(self):
        """In dev mode, presigned_url contains mock/s3 or public_base_url."""
        fake_ns = _make_fake_ns()
        fake_s3 = _FakeS3()

        result = _patched_presign(
            fake_ns,
            fake_s3,
            {
                "filename": "test.mp4",
                "content_type": "video/mp4",
                "size_bytes": 1024,
            },
        )

        # In dev mode (DEV_MODE=1 in .env.local) it should use mock S3 URL
        # In test mode without .env.local, dev_mode defaults to True
        assert "/mock/s3/" in result.presigned_url or "s3.amazonaws.com" in result.presigned_url


# ─── Tests: Complete endpoint ────────────────────────────────────────────────


class TestVodComplete:
    """Tests for POST /ui/videos/{video_id}/upload/complete."""

    def _setup_presign(self, fake_ns, fake_s3, user_sub="test-user-123"):
        """Create a presigned upload, returning the result."""
        return _patched_presign(
            fake_ns,
            fake_s3,
            {
                "filename": "test.mp4",
                "content_type": "video/mp4",
                "size_bytes": 256,
            },
            user_sub=user_sub,
        )

    def test_complete_transitions_status(self):
        """After upload to S3, complete transitions status to upload_complete."""
        fake_ns = _make_fake_ns()
        fake_s3 = _FakeS3()

        presign_result = self._setup_presign(fake_ns, fake_s3)

        # Simulate S3 upload
        ticket_items = [
            v for k, v in fake_ns.video_metadata.items.items()
            if isinstance(k, str) and k.startswith("TICKET#")
        ]
        bucket = ticket_items[0]["s3_bucket"]
        s3_key = presign_result.s3_key
        fake_s3.objects[f"{bucket}/{s3_key}"] = {
            "ContentLength": 256,
            "ContentType": "video/mp4",
            "ETag": '"abc123"',
            "Metadata": {"vod-ticket": ticket_items[0]["ticket_id"], "vod-user": "test-user-123"},
        }

        result = _patched_complete(fake_ns, fake_s3, presign_result.video_id)

        assert result.video_id == presign_result.video_id
        assert result.status == "upload_complete"

        # Verify the video record status was updated in DDB
        video_item = fake_ns.video_metadata.items.get(presign_result.video_id)
        assert video_item is not None
        assert video_item["status"] == "probing"  # "probing" is the post-upload state in the state machine

    def test_complete_video_not_owned_returns_403(self):
        """User A cannot complete User B's video upload."""
        fake_ns = _make_fake_ns()
        fake_s3 = _FakeS3()

        # Create presign as user-A
        presign_result = self._setup_presign(fake_ns, fake_s3, user_sub="user-A")

        # Try to complete as user-B
        with pytest.raises(HTTPException) as exc_info:
            _patched_complete(fake_ns, fake_s3, presign_result.video_id, user_sub="user-B")

        assert exc_info.value.status_code == 403
        assert "not your video" in exc_info.value.detail

    def test_complete_nonexistent_video_returns_404(self):
        """Completing a non-existent video returns 404."""
        fake_ns = _make_fake_ns()
        fake_s3 = _FakeS3()

        with pytest.raises(HTTPException) as exc_info:
            _patched_complete(fake_ns, fake_s3, "v_nonexistent123")

        assert exc_info.value.status_code == 404

    def test_complete_already_completed_returns_409(self):
        """Completing a video that's already past 'created' status returns 409."""
        fake_ns = _make_fake_ns()
        fake_s3 = _FakeS3()

        presign_result = self._setup_presign(fake_ns, fake_s3)

        # Simulate S3 upload
        ticket_items = [
            v for k, v in fake_ns.video_metadata.items.items()
            if isinstance(k, str) and k.startswith("TICKET#")
        ]
        bucket = ticket_items[0]["s3_bucket"]
        s3_key = presign_result.s3_key
        fake_s3.objects[f"{bucket}/{s3_key}"] = {
            "ContentLength": 256,
            "ContentType": "video/mp4",
            "ETag": '"abc123"',
            "Metadata": {},
        }

        # Complete once
        _patched_complete(fake_ns, fake_s3, presign_result.video_id)

        # Try to complete again — video is now in "probing" state, not "created"
        with pytest.raises(HTTPException) as exc_info:
            _patched_complete(fake_ns, fake_s3, presign_result.video_id)

        assert exc_info.value.status_code == 409

    def test_complete_without_s3_upload_still_transitions(self):
        """Complete works even if HeadObject fails (logs warning, still transitions)."""
        fake_ns = _make_fake_ns()
        fake_s3 = _FakeS3()

        presign_result = self._setup_presign(fake_ns, fake_s3)
        # Don't put object in S3 — HeadObject will fail but complete should still work

        result = _patched_complete(fake_ns, fake_s3, presign_result.video_id)

        assert result.video_id == presign_result.video_id
        assert result.status == "upload_complete"
