"""GAP-0367 regression: VideoUploadPresignIn.title max_length must match
VideoMetadataModel.title (256), so an over-long title is rejected at the API
boundary with a clean 422 instead of blowing up downstream in create_video
(an unhandled Pydantic ValidationError -> HTTP 500).

Offline / pure-pydantic. No AWS, no TestClient (broken in this env).
"""
import pytest
from pydantic import ValidationError

from app.routers.vod import VideoUploadPresignIn
from app.models_video import VideoMetadataModel


_REQUIRED = {"filename": "clip.mp4", "content_type": "video/mp4", "file_size_bytes": 1024}


def test_title_256_chars_is_valid():
    m = VideoUploadPresignIn(title="x" * 256, **_REQUIRED)
    assert m.title == "x" * 256


def test_title_257_chars_rejected_at_boundary():
    # Fails-before: 257 was accepted at the presign boundary (max_length=500)
    # then raised a ValidationError inside create_video -> unhandled 500.
    with pytest.raises(ValidationError):
        VideoUploadPresignIn(title="x" * 257, **_REQUIRED)


def test_title_500_chars_rejected_at_boundary():
    with pytest.raises(ValidationError):
        VideoUploadPresignIn(title="x" * 500, **_REQUIRED)


def test_presign_and_metadata_title_limits_agree():
    presign_max = VideoUploadPresignIn.model_fields["title"].metadata
    meta_max = VideoMetadataModel.model_fields["title"].metadata

    def _max_len(metadata):
        for c in metadata:
            if getattr(c, "max_length", None) is not None:
                return c.max_length
        return None

    assert _max_len(presign_max) == _max_len(meta_max) == 256
