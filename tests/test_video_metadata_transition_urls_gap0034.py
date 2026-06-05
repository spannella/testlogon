"""Regression tests for GAP-0034.

`VideoMetadata.hls_manifest_url` (and `thumbnail_url` / `renditions`) were never
populated after transcode because `transition_video_status` could not carry the
output URLs. These tests verify the extended `transition_video_status` persists
the playback URL, thumbnail, and rendition metadata on the → published transition.

Offline only: uses an in-memory DynamoDB table stub (no real AWS / moto network).
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

import pytest

from app.models_video import VideoRendition
from app.services import video_metadata_store
from app.services.video_metadata_store import (
    create_video,
    get_video,
    transition_video_status,
)


class _FakeTable:
    """In-memory DynamoDB table stub (matches tests/test_video_metadata_store.py)."""

    def __init__(self) -> None:
        self.items: dict = {}

    def put_item(self, *, Item, ConditionExpression=None):  # noqa: N803
        key = Item.get("video_id")
        if ConditionExpression and "attribute_not_exists" in ConditionExpression:
            if key in self.items:
                raise AssertionError("duplicate insert")
        self.items[key] = Item

    def get_item(self, *, Key, ConsistentRead=False):  # noqa: N803
        item = self.items.get(Key.get("video_id"))
        return {"Item": item} if item else {}


def _make_ns():
    return SimpleNamespace(video_metadata=_FakeTable())


def _advance_to_approved(video_id: str) -> None:
    """Walk the legal state machine path created -> ... -> approved."""
    for to_status in (
        "probing",
        "pending_encoding",
        "encoding",
        "pending_review",
        "approved",
    ):
        transition_video_status(video_id=video_id, to_status=to_status)


def test_publish_transition_populates_output_urls() -> None:
    """After fix: publishing with output URLs persists them on the record.

    Before fix: transition_video_status accepted no URL params, so
    hls_manifest_url / thumbnail_url / renditions stayed None -> every video
    unplayable.
    """
    ns = _make_ns()
    with patch.object(video_metadata_store, "T", ns):
        video = create_video(owner_user_id="user-1", title="VOD")
        _advance_to_approved(video.id)

        result = transition_video_status(
            video_id=video.id,
            to_status="published",
            hls_manifest_url="https://cdn.example.com/v1/index.m3u8",
            thumbnail_url="https://cdn.example.com/v1/thumb_0.jpg",
            renditions=[
                VideoRendition(label="720p", width=1280, height=720, bitrate_kbps=2500),
                VideoRendition(label="360p", width=640, height=360, bitrate_kbps=800),
            ],
        )

        # Returned model carries the URLs...
        assert result.status == "published"
        assert result.hls_manifest_url == "https://cdn.example.com/v1/index.m3u8"
        assert result.thumbnail_url == "https://cdn.example.com/v1/thumb_0.jpg"
        assert len(result.renditions) == 2
        assert result.renditions[0].label == "720p"

        # ...and they survive a round-trip through the (stubbed) DDB store.
        loaded = get_video(video.id)

    assert loaded.hls_manifest_url == "https://cdn.example.com/v1/index.m3u8"
    assert loaded.thumbnail_url == "https://cdn.example.com/v1/thumb_0.jpg"
    assert len(loaded.renditions) == 2
    assert {r.label for r in loaded.renditions} == {"720p", "360p"}


def test_transition_without_urls_leaves_existing_unchanged() -> None:
    """Re-transition without URLs must not clobber a previously stored URL."""
    ns = _make_ns()
    with patch.object(video_metadata_store, "T", ns):
        video = create_video(owner_user_id="user-2", title="VOD2")
        _advance_to_approved(video.id)
        transition_video_status(
            video_id=video.id,
            to_status="published",
            hls_manifest_url="https://cdn.example.com/v2/index.m3u8",
        )
        # archived -> published again, this time with no URL supplied
        transition_video_status(video_id=video.id, to_status="archived")
        transition_video_status(video_id=video.id, to_status="published")
        loaded = get_video(video.id)

    assert loaded.hls_manifest_url == "https://cdn.example.com/v2/index.m3u8"


def test_baseline_publish_without_urls_yields_none() -> None:
    """Sanity check: the plain publish path (no URLs) leaves fields None.

    Documents the pre-fix behaviour the worker now avoids by passing URLs.
    """
    ns = _make_ns()
    with patch.object(video_metadata_store, "T", ns):
        video = create_video(owner_user_id="user-3", title="VOD3")
        _advance_to_approved(video.id)
        result = transition_video_status(video_id=video.id, to_status="published")

    assert result.status == "published"
    assert result.hls_manifest_url is None
    assert result.thumbnail_url is None


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__, "-q"])
