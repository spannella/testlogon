"""Unit tests for the transcode job store (VOD-003)."""

from __future__ import annotations

import time
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from botocore.exceptions import ClientError


# ─── Fixtures ────────────────────────────────────────────────────────────────


def _make_mock_table():
    """Create a mock DynamoDB table with in-memory storage."""
    table = MagicMock()
    items: dict = {}

    def _put_item(Item):
        items[Item["job_id"]] = dict(Item)

    def _get_item(Key):
        item = items.get(Key["job_id"])
        if item:
            return {"Item": dict(item)}
        return {}

    def _update_item(Key, UpdateExpression="", ConditionExpression="", ExpressionAttributeNames=None, ExpressionAttributeValues=None, **kwargs):
        job_id = Key["job_id"]
        item = items.get(job_id)
        if item is None:
            raise ClientError(
                {"Error": {"Code": "ConditionalCheckFailedException", "Message": ""}},
                "UpdateItem",
            )

        # Simple condition check simulation
        if ConditionExpression and ExpressionAttributeValues:
            names = ExpressionAttributeNames or {}
            if "#s" in names:
                status_attr = names["#s"]
                current_status = item.get(status_attr, "")

                # claim_job: requires status == queued
                if ":queued" in ExpressionAttributeValues and ":running" in ExpressionAttributeValues:
                    expected = ExpressionAttributeValues.get(":queued", "")
                    if current_status != expected:
                        raise ClientError(
                            {"Error": {"Code": "ConditionalCheckFailedException", "Message": ""}},
                            "UpdateItem",
                        )
                    # Check next_retry_at
                    next_retry = item.get("next_retry_at")
                    now_val = ExpressionAttributeValues.get(":now")
                    if next_retry is not None and now_val is not None and int(next_retry) > int(now_val):
                        raise ClientError(
                            {"Error": {"Code": "ConditionalCheckFailedException", "Message": ""}},
                            "UpdateItem",
                        )
                # complete_job: requires status == running
                elif ":running" in ExpressionAttributeValues and ":completed" in ExpressionAttributeValues:
                    expected = ExpressionAttributeValues.get(":running", "")
                    if current_status != expected:
                        raise ClientError(
                            {"Error": {"Code": "ConditionalCheckFailedException", "Message": ""}},
                            "UpdateItem",
                        )

        # Apply SET assignments
        vals = ExpressionAttributeValues or {}
        names = ExpressionAttributeNames or {}

        set_part = ""
        if "SET " in UpdateExpression:
            set_part = UpdateExpression.split("SET ", 1)[1]

        if set_part:
            for assignment in set_part.split(","):
                assignment = assignment.strip()
                if "=" not in assignment:
                    continue
                attr, val_ref = assignment.split("=", 1)
                attr = attr.strip()
                val_ref = val_ref.strip()
                resolved_attr = names.get(attr, attr)
                if val_ref in vals:
                    item[resolved_attr] = vals[val_ref]

        items[job_id] = item

    def _query(IndexName="", KeyConditionExpression=None, ScanIndexForward=True, Limit=None, ExclusiveStartKey=None, **kwargs):
        all_items = list(items.values())

        if IndexName == "ByStatusCreatedAt":
            # Extract filter value from the Key condition
            filter_val = _extract_condition_value(KeyConditionExpression)
            filtered = [i for i in all_items if i.get("status") == filter_val]
            filtered.sort(key=lambda x: int(x.get("created_at", 0)), reverse=not ScanIndexForward)
        elif IndexName == "ByVideoId":
            filter_val = _extract_condition_value(KeyConditionExpression)
            filtered = [i for i in all_items if i.get("video_id") == filter_val]
            filtered.sort(key=lambda x: int(x.get("created_at", 0)), reverse=not ScanIndexForward)
        else:
            filtered = all_items

        if Limit:
            filtered = filtered[:Limit]

        return {"Items": filtered}

    table.put_item = _put_item
    table.get_item = _get_item
    table.update_item = _update_item
    table.query = _query

    return table, items


def _extract_condition_value(condition):
    """Extract the equality value from a boto3 Key().eq() condition."""
    if condition is None:
        return ""
    # boto3 Key conditions store values in _values list
    if hasattr(condition, "_values"):
        for v in condition._values:
            if hasattr(v, "_value"):
                return v._value
            if isinstance(v, str):
                return v
    # Try the expression_values dict
    if hasattr(condition, "expression_values"):
        for v in condition.expression_values.values():
            return v
    return ""


@pytest.fixture(autouse=True)
def mock_store(monkeypatch):
    """Patch the transcode_job_store module to use mock table and settings."""
    import app.services.transcode_job_store as store_mod

    table, items = _make_mock_table()

    # Create a fake T namespace
    fake_t = SimpleNamespace(transcode_jobs=table)
    monkeypatch.setattr(store_mod, "T", fake_t)

    # Create a mutable settings-like object
    fake_s = SimpleNamespace(transcode_max_attempts=3)
    monkeypatch.setattr(store_mod, "S", fake_s)

    return table, items, fake_s


# ─── Tests ────────────────────────────────────────────────────────────────────


class TestCreateJob:
    def test_create_returns_job_with_queued_status(self, mock_store):
        from app.services.transcode_job_store import create_job

        job = create_job(
            video_id="vid_123",
            tenant_id="tenant_abc",
            rendition_profiles=[{"name": "720p", "width": 1280, "height": 720, "video_bitrate_kbps": 3000, "audio_bitrate_kbps": 128}],
            source_uri="s3://uploads/raw/test.mp4",
        )

        assert job["status"] == "queued"
        assert job["job_id"].startswith("tj_")
        assert job["video_id"] == "vid_123"
        assert job["tenant_id"] == "tenant_abc"
        assert job["attempt"] == 0
        assert job["progress_pct"] == 0
        assert job["created_at"] > 0
        assert job["updated_at"] > 0
        assert "queued#" in job["status_created_at"]

    def test_create_stores_rendition_profiles(self, mock_store):
        from app.services.transcode_job_store import create_job

        profiles = [
            {"name": "1080p", "width": 1920, "height": 1080, "video_bitrate_kbps": 5000, "audio_bitrate_kbps": 192},
            {"name": "720p", "width": 1280, "height": 720, "video_bitrate_kbps": 3000, "audio_bitrate_kbps": 128},
        ]
        job = create_job(
            video_id="vid_456",
            tenant_id="tenant_abc",
            rendition_profiles=profiles,
            source_uri="s3://uploads/raw/test.mp4",
        )

        assert job["renditions"] == profiles

    def test_create_stores_watermark_and_drm(self, mock_store):
        from app.services.transcode_job_store import create_job

        wm = {"mode": "dynamic_text", "text_template": "test"}
        drm = {"profile": "widevine"}
        job = create_job(
            video_id="vid_789",
            tenant_id="tenant_abc",
            rendition_profiles=[{"name": "360p", "width": 640, "height": 360, "video_bitrate_kbps": 800, "audio_bitrate_kbps": 64}],
            watermark_policy=wm,
            drm_policy=drm,
        )

        assert job["watermark"] == wm
        assert job["drm"] == drm


class TestClaimJob:
    def test_claim_transitions_to_running(self, mock_store):
        from app.services.transcode_job_store import create_job, claim_job, get_job

        job = create_job(
            video_id="vid_1",
            tenant_id="t1",
            rendition_profiles=[{"name": "720p", "width": 1280, "height": 720, "video_bitrate_kbps": 3000, "audio_bitrate_kbps": 128}],
        )

        result = claim_job(job["job_id"], "worker-1")
        assert result is True

        updated = get_job(job["job_id"])
        assert updated["status"] == "running"
        assert updated["worker_id"] == "worker-1"
        assert updated["started_at"] > 0

    def test_double_claim_returns_false(self, mock_store):
        from app.services.transcode_job_store import create_job, claim_job

        job = create_job(
            video_id="vid_2",
            tenant_id="t1",
            rendition_profiles=[{"name": "720p", "width": 1280, "height": 720, "video_bitrate_kbps": 3000, "audio_bitrate_kbps": 128}],
        )

        # First claim succeeds
        assert claim_job(job["job_id"], "worker-1") is True

        # Second claim fails (status is now "running")
        assert claim_job(job["job_id"], "worker-2") is False

    def test_claim_respects_next_retry_at_in_future(self, mock_store):
        from app.services.transcode_job_store import create_job, claim_job

        _, items, _ = mock_store
        job = create_job(
            video_id="vid_3",
            tenant_id="t1",
            rendition_profiles=[{"name": "720p", "width": 1280, "height": 720, "video_bitrate_kbps": 3000, "audio_bitrate_kbps": 128}],
        )

        # Set next_retry_at far in the future
        items[job["job_id"]]["next_retry_at"] = int(time.time()) + 9999

        result = claim_job(job["job_id"], "worker-1")
        assert result is False


class TestCompleteJob:
    def test_complete_transitions_to_completed(self, mock_store):
        from app.services.transcode_job_store import create_job, claim_job, complete_job, get_job

        job = create_job(
            video_id="vid_c1",
            tenant_id="t1",
            rendition_profiles=[{"name": "720p", "width": 1280, "height": 720, "video_bitrate_kbps": 3000, "audio_bitrate_kbps": 128}],
        )
        claim_job(job["job_id"], "worker-1")

        complete_job(job["job_id"], "s3://output/master.m3u8", ["720p"])

        updated = get_job(job["job_id"])
        assert updated["status"] == "completed"
        assert updated["output_hls_manifest_uri"] == "s3://output/master.m3u8"
        assert updated["progress_pct"] == 100
        assert updated["completed_at"] > 0
        assert updated["renditions_completed"] == ["720p"]


class TestFailJob:
    def test_fail_with_retries_remaining_goes_back_to_queued(self, mock_store):
        from app.services.transcode_job_store import create_job, claim_job, fail_job

        _, _, fake_s = mock_store
        fake_s.transcode_max_attempts = 3

        job = create_job(
            video_id="vid_f1",
            tenant_id="t1",
            rendition_profiles=[{"name": "720p", "width": 1280, "height": 720, "video_bitrate_kbps": 3000, "audio_bitrate_kbps": 128}],
        )
        claim_job(job["job_id"], "worker-1")

        # Fail at attempt 0, max_attempts=3 => should retry
        updated = fail_job(job["job_id"], "FFmpeg crashed", attempt=0)

        assert updated["status"] == "queued"
        assert updated["attempt"] == 1
        assert updated["error_message"] == "FFmpeg crashed"
        assert updated.get("next_retry_at") is not None
        assert updated["next_retry_at"] > int(time.time())

    def test_fail_at_max_attempts_stays_failed(self, mock_store):
        from app.services.transcode_job_store import create_job, claim_job, fail_job

        _, _, fake_s = mock_store
        fake_s.transcode_max_attempts = 3

        job = create_job(
            video_id="vid_f2",
            tenant_id="t1",
            rendition_profiles=[{"name": "720p", "width": 1280, "height": 720, "video_bitrate_kbps": 3000, "audio_bitrate_kbps": 128}],
        )
        claim_job(job["job_id"], "worker-1")

        # Fail at attempt 2 (third attempt), max_attempts=3 => terminal
        updated = fail_job(job["job_id"], "Disk full", attempt=2)

        assert updated["status"] == "failed"
        assert updated["attempt"] == 3
        assert updated["error_message"] == "Disk full"
        assert updated["completed_at"] > 0

    def test_fail_increments_attempt(self, mock_store):
        from app.services.transcode_job_store import create_job, claim_job, fail_job

        _, _, fake_s = mock_store
        fake_s.transcode_max_attempts = 5

        job = create_job(
            video_id="vid_f3",
            tenant_id="t1",
            rendition_profiles=[{"name": "720p", "width": 1280, "height": 720, "video_bitrate_kbps": 3000, "audio_bitrate_kbps": 128}],
        )
        claim_job(job["job_id"], "worker-1")

        updated = fail_job(job["job_id"], "Timeout", attempt=1)
        assert updated["attempt"] == 2


class TestListJobsByStatus:
    def test_list_returns_correct_jobs(self, mock_store):
        from app.services.transcode_job_store import create_job, claim_job, list_jobs_by_status

        # Create multiple jobs
        job1 = create_job(video_id="v1", tenant_id="t1", rendition_profiles=[{"name": "720p", "width": 1280, "height": 720, "video_bitrate_kbps": 3000, "audio_bitrate_kbps": 128}])
        job2 = create_job(video_id="v2", tenant_id="t1", rendition_profiles=[{"name": "720p", "width": 1280, "height": 720, "video_bitrate_kbps": 3000, "audio_bitrate_kbps": 128}])
        job3 = create_job(video_id="v3", tenant_id="t1", rendition_profiles=[{"name": "720p", "width": 1280, "height": 720, "video_bitrate_kbps": 3000, "audio_bitrate_kbps": 128}])

        # Claim one to make it running
        claim_job(job2["job_id"], "worker-1")

        # List queued jobs
        result = list_jobs_by_status("queued")
        queued_ids = [j["job_id"] for j in result["items"]]

        assert job1["job_id"] in queued_ids
        assert job3["job_id"] in queued_ids
        assert job2["job_id"] not in queued_ids

    def test_list_respects_limit(self, mock_store):
        from app.services.transcode_job_store import create_job, list_jobs_by_status

        for i in range(5):
            create_job(video_id=f"v{i}", tenant_id="t1", rendition_profiles=[{"name": "720p", "width": 1280, "height": 720, "video_bitrate_kbps": 3000, "audio_bitrate_kbps": 128}])

        result = list_jobs_by_status("queued", limit=3)
        assert len(result["items"]) <= 3


class TestListJobsByVideo:
    def test_returns_jobs_for_video(self, mock_store):
        from app.services.transcode_job_store import create_job, list_jobs_by_video

        create_job(video_id="target_vid", tenant_id="t1", rendition_profiles=[{"name": "720p", "width": 1280, "height": 720, "video_bitrate_kbps": 3000, "audio_bitrate_kbps": 128}])
        create_job(video_id="other_vid", tenant_id="t1", rendition_profiles=[{"name": "720p", "width": 1280, "height": 720, "video_bitrate_kbps": 3000, "audio_bitrate_kbps": 128}])
        create_job(video_id="target_vid", tenant_id="t1", rendition_profiles=[{"name": "360p", "width": 640, "height": 360, "video_bitrate_kbps": 800, "audio_bitrate_kbps": 64}])

        results = list_jobs_by_video("target_vid")
        assert len(results) == 2
        assert all(j["video_id"] == "target_vid" for j in results)


class TestUpdateProgress:
    def test_update_progress_sets_fields(self, mock_store):
        from app.services.transcode_job_store import create_job, claim_job, update_job_progress, get_job

        job = create_job(
            video_id="vid_p1",
            tenant_id="t1",
            rendition_profiles=[{"name": "720p", "width": 1280, "height": 720, "video_bitrate_kbps": 3000, "audio_bitrate_kbps": 128}],
        )
        claim_job(job["job_id"], "worker-1")

        update_job_progress(
            job["job_id"],
            progress_pct=45,
            current_rendition="720p",
            renditions_completed=["360p"],
            eta_seconds=120,
        )

        updated = get_job(job["job_id"])
        assert updated["progress_pct"] == 45
        assert updated["current_rendition"] == "720p"
        assert updated["renditions_completed"] == ["360p"]
        assert updated["eta_seconds"] == 120


class TestRetryBackoff:
    def test_compute_next_retry_at_increases_with_attempt(self):
        from app.services.transcode_job_store import _compute_next_retry_at

        now = int(time.time())

        retry_0 = _compute_next_retry_at(0)
        retry_1 = _compute_next_retry_at(1)
        retry_2 = _compute_next_retry_at(2)

        # Each retry should be further in the future (with some jitter tolerance)
        assert retry_0 >= now + 30  # base_delay=30, attempt=0 => delay=30
        assert retry_1 >= now + 60  # attempt=1 => delay=60
        assert retry_2 >= now + 120  # attempt=2 => delay=120

    def test_compute_next_retry_at_caps_at_max(self):
        from app.services.transcode_job_store import _compute_next_retry_at, MAX_RETRY_DELAY

        now = int(time.time())

        # Very high attempt should still cap
        retry_high = _compute_next_retry_at(20)
        # Should be at most now + MAX_RETRY_DELAY + jitter (jitter <= MAX_RETRY_DELAY//4)
        assert retry_high <= now + MAX_RETRY_DELAY + (MAX_RETRY_DELAY // 4) + 2  # +2 for timing
