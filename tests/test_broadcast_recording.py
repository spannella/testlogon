"""Unit tests for broadcast recording service and worker (BCAST-006)."""
from __future__ import annotations

import time
from types import SimpleNamespace
from typing import Any, Dict, List
from unittest.mock import patch, MagicMock

import pytest

from app.services import broadcast_recording
from app.services import broadcast_recording_worker


# ─── Fake DynamoDB Table ─────────────────────────────────────────────


class _FakeRecordingsTable:
    def __init__(self) -> None:
        self.items: Dict[str, Dict[str, Any]] = {}

    def put_item(self, *, Item: Dict[str, Any], **kwargs) -> None:
        self.items[Item["recording_id"]] = Item

    def get_item(self, *, Key: Dict[str, str], **kwargs) -> Dict[str, Any]:
        item = self.items.get(Key["recording_id"])
        return {"Item": item} if item else {}

    def update_item(self, *, Key: Dict[str, str], UpdateExpression: str, ExpressionAttributeNames: Dict, ExpressionAttributeValues: Dict, **kwargs) -> None:
        item = self.items.get(Key["recording_id"])
        if not item:
            return
        # Parse simple "SET #field = :field" expressions
        for attr_name, real_name in ExpressionAttributeNames.items():
            val_key = f":{real_name}"
            if val_key in ExpressionAttributeValues:
                item[real_name] = ExpressionAttributeValues[val_key]

    def query(self, *, IndexName: str = "", KeyConditionExpression=None, ScanIndexForward: bool = True, Limit: int = 100, **kwargs) -> Dict[str, Any]:
        items = list(self.items.values())
        if IndexName == "BySessionId":
            # Filter by session_id
            session_id = KeyConditionExpression._values[1]
            items = [i for i in items if i.get("session_id") == session_id]
            items.sort(key=lambda x: x.get("created_at", 0), reverse=not ScanIndexForward)
        elif IndexName == "ByStatusCreatedAt":
            status = KeyConditionExpression._values[1]
            items = [i for i in items if i.get("status") == status]
            items.sort(key=lambda x: x.get("created_at", 0), reverse=not ScanIndexForward)
        elif IndexName == "ByExpiresAt":
            # Filter scope=ALL and expires_at <= threshold
            items = [i for i in items if i.get("scope") == "ALL"]
            # In real DDB this uses lte condition; we simulate
            items.sort(key=lambda x: x.get("expires_at", 0))
        return {"Items": items[:Limit]}


# Patch Key condition to capture values for our fake
class _FakeCondition:
    def __init__(self, *args) -> None:
        self._values = list(args)

    def __and__(self, other):
        combined = _FakeCondition(*self._values, *other._values)
        return combined

    def eq(self, value):
        return _FakeCondition(self._values[0] if self._values else "", value)

    def lte(self, value):
        return _FakeCondition(self._values[0] if self._values else "", value)


@pytest.fixture()
def fake_table():
    table = _FakeRecordingsTable()
    fake_tables = SimpleNamespace(broadcast_recordings=table)
    with patch.object(broadcast_recording, "T", fake_tables):
        yield table


@pytest.fixture()
def fake_key(monkeypatch):
    """Patch boto3 Key so our fake table can parse conditions."""
    monkeypatch.setattr(broadcast_recording, "Key", lambda field: _FakeCondition(field))


# ─── CRUD Tests ──────────────────────────────────────────────────────


class TestRecordingCRUD:
    def test_create_recording(self, fake_table, fake_key) -> None:
        rec = broadcast_recording.create_recording(
            session_id="sess-001",
            profile_id="prof-001",
            created_by="user-1",
            s3_archive_prefix="s3://bucket/sessions/sess-001/",
            retention_days=30,
        )
        assert rec.recording_id.startswith("rec_")
        assert rec.session_id == "sess-001"
        assert rec.profile_id == "prof-001"
        assert rec.status == "pending"
        assert rec.created_at > 0
        assert rec.expires_at > rec.created_at

    def test_get_recording(self, fake_table, fake_key) -> None:
        rec = broadcast_recording.create_recording(
            session_id="sess-002",
            profile_id="prof-001",
            created_by="user-1",
        )
        loaded = broadcast_recording.get_recording(rec.recording_id)
        assert loaded is not None
        assert loaded.recording_id == rec.recording_id
        assert loaded.session_id == "sess-002"

    def test_get_recording_not_found(self, fake_table, fake_key) -> None:
        result = broadcast_recording.get_recording("nonexistent")
        assert result is None

    def test_get_recording_by_session(self, fake_table, fake_key) -> None:
        broadcast_recording.create_recording(
            session_id="sess-003",
            profile_id="prof-001",
            created_by="user-1",
        )
        result = broadcast_recording.get_recording_by_session("sess-003")
        assert result is not None
        assert result.session_id == "sess-003"

    def test_get_recording_by_session_not_found(self, fake_table, fake_key) -> None:
        result = broadcast_recording.get_recording_by_session("no-session")
        assert result is None

    def test_update_recording_status(self, fake_table, fake_key) -> None:
        rec = broadcast_recording.create_recording(
            session_id="sess-004",
            profile_id="prof-001",
            created_by="user-1",
        )
        updated = broadcast_recording.update_recording_status(
            rec.recording_id, "processing"
        )
        assert updated is not None
        assert updated.status == "processing"

    def test_update_recording_status_with_extras(self, fake_table, fake_key) -> None:
        rec = broadcast_recording.create_recording(
            session_id="sess-005",
            profile_id="prof-001",
            created_by="user-1",
        )
        updated = broadcast_recording.update_recording_status(
            rec.recording_id,
            "failed",
            error_code="TestError",
            error_message="Something went wrong",
        )
        assert updated is not None
        assert updated.status == "failed"
        assert updated.error_code == "TestError"
        assert updated.error_message == "Something went wrong"

    def test_list_recordings_by_status(self, fake_table, fake_key) -> None:
        broadcast_recording.create_recording(
            session_id="sess-006a",
            profile_id="prof-001",
            created_by="user-1",
        )
        broadcast_recording.create_recording(
            session_id="sess-006b",
            profile_id="prof-001",
            created_by="user-1",
        )
        results = broadcast_recording.list_recordings_by_status("pending")
        assert len(results) == 2

    def test_list_expired_recordings(self, fake_table, fake_key) -> None:
        rec = broadcast_recording.create_recording(
            session_id="sess-007",
            profile_id="prof-001",
            created_by="user-1",
            retention_days=0,  # expires immediately
        )
        # Manually set expires_at to past
        fake_table.items[rec.recording_id]["expires_at"] = int(time.time()) - 100
        results = broadcast_recording.list_expired_recordings(int(time.time()))
        assert len(results) >= 1

    def test_mint_recording_playback_url(self, fake_table, fake_key) -> None:
        rec = broadcast_recording.create_recording(
            session_id="sess-008",
            profile_id="prof-001",
            created_by="user-1",
        )
        # Manually set manifest key
        fake_table.items[rec.recording_id]["s3_manifest_key"] = "sess-008/recording/master.m3u8"
        loaded = broadcast_recording.get_recording(rec.recording_id)
        result = broadcast_recording.mint_recording_playback_url(loaded)
        assert "playback_url" in result
        assert "playback_expires_at" in result
        assert "master.m3u8" in result["playback_url"]

    def test_mint_recording_thumbnail_url(self, fake_table, fake_key) -> None:
        rec = broadcast_recording.create_recording(
            session_id="sess-009",
            profile_id="prof-001",
            created_by="user-1",
        )
        fake_table.items[rec.recording_id]["s3_thumbnail_key"] = "sess-009/recording/thumbnail.jpg"
        loaded = broadcast_recording.get_recording(rec.recording_id)
        url = broadcast_recording.mint_recording_thumbnail_url(loaded)
        assert url is not None
        assert "thumbnail.jpg" in url

    def test_mint_thumbnail_url_none_when_no_key(self, fake_table, fake_key) -> None:
        rec = broadcast_recording.create_recording(
            session_id="sess-010",
            profile_id="prof-001",
            created_by="user-1",
        )
        loaded = broadcast_recording.get_recording(rec.recording_id)
        url = broadcast_recording.mint_recording_thumbnail_url(loaded)
        assert url is None


# ─── Worker Pipeline Tests ───────────────────────────────────────────


class TestRecordingWorker:
    @pytest.fixture(autouse=True)
    def setup_table(self, fake_table, fake_key):
        self.table = fake_table

    def test_process_recording_mock_pipeline(self) -> None:
        """Full pipeline in mock mode produces a ready recording."""
        with patch.object(broadcast_recording_worker, "_should_mock", return_value=True):
            rec = broadcast_recording.create_recording(
                session_id="sess-w01",
                profile_id="prof-001",
                created_by="user-1",
                s3_archive_prefix="s3://bucket/sessions/sess-w01/",
            )
            with patch.object(broadcast_recording_worker, "get_recording", side_effect=broadcast_recording.get_recording):
                with patch.object(broadcast_recording_worker, "update_recording_status", side_effect=broadcast_recording.update_recording_status):
                    result = broadcast_recording_worker.process_recording(rec.recording_id)

            assert result is not None
            assert result.status == "ready"
            assert result.s3_manifest_key == "sess-w01/recording/master.m3u8"
            assert result.s3_thumbnail_key == "sess-w01/recording/thumbnail.jpg"

    def test_process_recording_not_found(self) -> None:
        """Processing a nonexistent recording returns None."""
        with patch.object(broadcast_recording_worker, "get_recording", return_value=None):
            result = broadcast_recording_worker.process_recording("nonexistent")
        assert result is None

    def test_inventory_segments_mock(self) -> None:
        """Mock inventory returns empty list."""
        rec = broadcast_recording.RecordingRecord(
            recording_id="rec_test",
            session_id="sess-test",
            profile_id="prof-test",
            created_by="user",
            status="processing",
        )
        with patch.object(broadcast_recording_worker, "_should_mock", return_value=True):
            segments = broadcast_recording_worker.inventory_segments(rec)
        assert segments == []

    def test_concatenate_segments_mock(self) -> None:
        """Mock concatenation returns None."""
        rec = broadcast_recording.RecordingRecord(
            recording_id="rec_test",
            session_id="sess-test",
            profile_id="prof-test",
            created_by="user",
            status="processing",
        )
        with patch.object(broadcast_recording_worker, "_should_mock", return_value=True):
            result = broadcast_recording_worker.concatenate_segments(rec, [])
        assert result is None

    def test_transcode_recording_mock(self) -> None:
        """Mock transcode returns rendition metadata."""
        rec = broadcast_recording.RecordingRecord(
            recording_id="rec_test",
            session_id="sess-test",
            profile_id="prof-test",
            created_by="user",
            status="processing",
        )
        with patch.object(broadcast_recording_worker, "_should_mock", return_value=True):
            result = broadcast_recording_worker.transcode_recording(rec, None)
        assert "renditions" in result
        assert len(result["renditions"]) == 1
        assert result["renditions"][0]["label"] == "720p"

    def test_generate_thumbnail_mock(self) -> None:
        """Mock thumbnail generation returns a key."""
        rec = broadcast_recording.RecordingRecord(
            recording_id="rec_test",
            session_id="sess-test",
            profile_id="prof-test",
            created_by="user",
            status="processing",
        )
        with patch.object(broadcast_recording_worker, "_should_mock", return_value=True):
            key = broadcast_recording_worker.generate_thumbnail(rec, None)
        assert key is not None
        assert "thumbnail.jpg" in key

    def test_process_recording_failure_sets_failed_status(self) -> None:
        """If a step raises, status transitions to failed."""
        rec = broadcast_recording.create_recording(
            session_id="sess-fail",
            profile_id="prof-001",
            created_by="user-1",
        )
        with patch.object(broadcast_recording_worker, "get_recording", side_effect=broadcast_recording.get_recording):
            with patch.object(broadcast_recording_worker, "update_recording_status", side_effect=broadcast_recording.update_recording_status):
                with patch.object(broadcast_recording_worker, "inventory_segments", side_effect=RuntimeError("S3 error")):
                    result = broadcast_recording_worker.process_recording(rec.recording_id)

        assert result is not None
        assert result.status == "failed"
        assert result.error_code == "RuntimeError"
        assert "S3 error" in result.error_message


# ─── API Endpoint Tests ──────────────────────────────────────────────


class TestRecordingAPIEndpoint:
    """Test the recording API endpoint via FastAPI test client."""

    @pytest.fixture()
    def client(self, fake_table, fake_key):
        """Create a test client with the broadcast router."""
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        from app.routers.broadcast import router

        app = FastAPI()
        app.include_router(router)

        # Override auth dependency
        from app.routers import broadcast as broadcast_module
        app.dependency_overrides[broadcast_module._ctx] = lambda: {"user_sub": "test-user", "role": "root"}

        return TestClient(app)

    def test_recording_not_found(self, client) -> None:
        with patch("app.routers.broadcast.get_recording_by_session", return_value=None):
            resp = client.get("/broadcast/sessions/no-session/recording")
        assert resp.status_code == 404
        assert resp.json()["detail"]["code"] == "BROADCAST_RECORDING_NOT_FOUND"

    def test_recording_expired(self, client) -> None:
        expired_rec = broadcast_recording.RecordingRecord(
            recording_id="rec_expired",
            session_id="sess-expired",
            profile_id="prof-001",
            created_by="user-1",
            status="expired",
            created_at=int(time.time()) - 86400,
        )
        with patch("app.routers.broadcast.get_recording_by_session", return_value=expired_rec):
            resp = client.get("/broadcast/sessions/sess-expired/recording")
        assert resp.status_code == 410
        assert resp.json()["detail"]["code"] == "BROADCAST_RECORDING_EXPIRED"

    def test_recording_processing(self, client) -> None:
        processing_rec = broadcast_recording.RecordingRecord(
            recording_id="rec_proc",
            session_id="sess-proc",
            profile_id="prof-001",
            created_by="user-1",
            status="processing",
            created_at=int(time.time()),
        )
        with patch("app.routers.broadcast.get_recording_by_session", return_value=processing_rec):
            resp = client.get("/broadcast/sessions/sess-proc/recording")
        assert resp.status_code == 202
        data = resp.json()
        assert data["code"] == "BROADCAST_RECORDING_PROCESSING"
        assert data["status"] == "processing"

    def test_recording_ready(self, client) -> None:
        now = int(time.time())
        ready_rec = broadcast_recording.RecordingRecord(
            recording_id="rec_ready",
            session_id="sess-ready",
            profile_id="prof-001",
            created_by="user-1",
            status="ready",
            s3_manifest_key="sess-ready/recording/master.m3u8",
            s3_thumbnail_key="sess-ready/recording/thumbnail.jpg",
            duration_seconds=120.0,
            segment_count=5,
            total_bytes=50000,
            renditions=[{"label": "720p", "bitrate_kbps": 3000}],
            created_at=now - 3600,
            completed_at=now - 3500,
            expires_at=now + 86400,
        )
        with patch("app.routers.broadcast.get_recording_by_session", return_value=ready_rec):
            with patch("app.routers.broadcast.mint_recording_playback_url", return_value={"playback_url": "/mock/s3/broadcast-vod/master.m3u8?expires=999", "playback_expires_at": 999}):
                with patch("app.routers.broadcast.mint_recording_thumbnail_url", return_value="/mock/s3/broadcast-vod/thumbnail.jpg"):
                    resp = client.get("/broadcast/sessions/sess-ready/recording")
        assert resp.status_code == 200
        data = resp.json()
        assert data["recording_id"] == "rec_ready"
        assert data["status"] == "ready"
        assert data["playback_url"] == "/mock/s3/broadcast-vod/master.m3u8?expires=999"
        assert data["thumbnail_url"] == "/mock/s3/broadcast-vod/thumbnail.jpg"
        assert data["duration_seconds"] == 120.0
        assert data["segment_count"] == 5

    def test_recording_pending(self, client) -> None:
        pending_rec = broadcast_recording.RecordingRecord(
            recording_id="rec_pending",
            session_id="sess-pending",
            profile_id="prof-001",
            created_by="user-1",
            status="pending",
            created_at=int(time.time()),
        )
        with patch("app.routers.broadcast.get_recording_by_session", return_value=pending_rec):
            resp = client.get("/broadcast/sessions/sess-pending/recording")
        assert resp.status_code == 202
