"""Regression test for GAP-0302.

In DEV_MODE (moto S3, no real FFmpeg transcode) the ABR pipeline never
populates ``thumbnail_url`` / ``hls_manifest_url``, so the review/moderation UI
showed a blank preview pane. The fix synthesises a ``/mock/s3/{bucket}/{key}``
URL from the stored S3 keys when in dev mode and the real URL is falsy.

This test exercises the two passthrough helpers directly (offline, no AWS):
- ``app/routers/admin_video_review.py:_video_to_queue_item``
- ``app/routers/moderation_video_queue.py:_to_item``

Asserts:
- dev mode + null url + s3 key  -> synthesised /mock/s3/... url
- dev mode + real url present    -> real url passes through unchanged
- dev mode off (prod)           -> nulls stay null (SECOPS-007 parity)
- dev mode + no url + no key     -> stays null
"""

from __future__ import annotations

from types import SimpleNamespace

from app.core import settings as _settings_mod
from app.routers.admin_video_review import _video_to_queue_item
from app.routers.moderation_video_queue import _to_item

S = _settings_mod.S


def _set_dev_mode(value: bool) -> None:
    object.__setattr__(S, "dev_mode", value)


def _fake_video(**overrides):
    base = dict(
        id="vid_abc123",
        owner_user_id="user_1",
        title="Test video",
        description=None,
        status="pending_review",
        created_at=1700000000,
        updated_at=1700000000,
        duration_seconds=30.0,
        width=1920,
        height=1080,
        thumbnail_url=None,
        hls_manifest_url=None,
        thumbnail_s3_key="videos/vid_abc123/thumb.jpg",
        hls_manifest_s3_key="videos/vid_abc123/hls/master.m3u8",
        file_size_bytes=1024 * 1024,
        source_type="upload",
        visibility="private",
    )
    base.update(overrides)
    return SimpleNamespace(**base)


def _fake_raw(**overrides):
    base = dict(
        entry_id="ent_1",
        video_id="vid_abc123",
        owner_user_id="user_1",
        title="Test video",
        description="",
        status="pending_review",
        priority="normal",
        priority_rank=2,
        source="manual",
        created_at=1700000000,
        updated_at=1700000000,
        duration_seconds=30.0,
        thumbnail_url=None,
        hls_manifest_url=None,
        thumbnail_s3_key="videos/vid_abc123/thumb.jpg",
        hls_manifest_s3_key="videos/vid_abc123/hls/master.m3u8",
    )
    base.update(overrides)
    return base


# --------------------------------------------------------------------------
# admin_video_review._video_to_queue_item
# --------------------------------------------------------------------------


def test_admin_synthesises_urls_in_dev_mode():
    orig = S.dev_mode
    try:
        _set_dev_mode(True)
        item = _video_to_queue_item(_fake_video())
    finally:
        _set_dev_mode(orig)

    assert item.thumbnail_url is not None
    assert item.hls_manifest_url is not None
    assert item.thumbnail_url == (
        f"/mock/s3/{S.video_upload_bucket}/videos/vid_abc123/thumb.jpg"
    )
    assert item.hls_manifest_url == (
        f"/mock/s3/{S.video_upload_bucket}/videos/vid_abc123/hls/master.m3u8"
    )


def test_admin_real_url_passes_through_in_dev_mode():
    orig = S.dev_mode
    try:
        _set_dev_mode(True)
        item = _video_to_queue_item(
            _fake_video(
                thumbnail_url="https://cdn.example.com/thumb.jpg",
                hls_manifest_url="https://cdn.example.com/master.m3u8",
            )
        )
    finally:
        _set_dev_mode(orig)

    assert item.thumbnail_url == "https://cdn.example.com/thumb.jpg"
    assert item.hls_manifest_url == "https://cdn.example.com/master.m3u8"


def test_admin_no_synthesis_in_prod():
    orig = S.dev_mode
    try:
        _set_dev_mode(False)
        item = _video_to_queue_item(_fake_video())
    finally:
        _set_dev_mode(orig)

    assert item.thumbnail_url is None
    assert item.hls_manifest_url is None


def test_admin_no_key_stays_null_in_dev_mode():
    orig = S.dev_mode
    try:
        _set_dev_mode(True)
        item = _video_to_queue_item(
            _fake_video(thumbnail_s3_key=None, hls_manifest_s3_key=None)
        )
    finally:
        _set_dev_mode(orig)

    assert item.thumbnail_url is None
    assert item.hls_manifest_url is None


# --------------------------------------------------------------------------
# moderation_video_queue._to_item
# --------------------------------------------------------------------------


def test_moderation_synthesises_urls_in_dev_mode():
    orig = S.dev_mode
    try:
        _set_dev_mode(True)
        item = _to_item(_fake_raw())
    finally:
        _set_dev_mode(orig)

    assert item.thumbnail_url is not None
    assert item.hls_manifest_url is not None
    assert item.thumbnail_url == (
        f"/mock/s3/{S.video_upload_bucket}/videos/vid_abc123/thumb.jpg"
    )
    assert item.hls_manifest_url == (
        f"/mock/s3/{S.video_upload_bucket}/videos/vid_abc123/hls/master.m3u8"
    )


def test_moderation_real_url_passes_through_in_dev_mode():
    orig = S.dev_mode
    try:
        _set_dev_mode(True)
        item = _to_item(
            _fake_raw(
                thumbnail_url="https://cdn.example.com/thumb.jpg",
                hls_manifest_url="https://cdn.example.com/master.m3u8",
            )
        )
    finally:
        _set_dev_mode(orig)

    assert item.thumbnail_url == "https://cdn.example.com/thumb.jpg"
    assert item.hls_manifest_url == "https://cdn.example.com/master.m3u8"


def test_moderation_no_synthesis_in_prod():
    orig = S.dev_mode
    try:
        _set_dev_mode(False)
        item = _to_item(_fake_raw())
    finally:
        _set_dev_mode(orig)

    assert item.thumbnail_url is None
    assert item.hls_manifest_url is None


def test_moderation_no_key_stays_null_in_dev_mode():
    orig = S.dev_mode
    try:
        _set_dev_mode(True)
        item = _to_item(
            _fake_raw(thumbnail_s3_key=None, hls_manifest_s3_key=None)
        )
    finally:
        _set_dev_mode(orig)

    assert item.thumbnail_url is None
    assert item.hls_manifest_url is None
