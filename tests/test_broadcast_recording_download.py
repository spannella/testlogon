"""Unit tests for broadcast recording MP4 download (BCAST-008)."""
from __future__ import annotations

import time
from types import SimpleNamespace
from typing import Any, Dict
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
        for attr_name, real_name in ExpressionAttributeNames.items():
            val_key = f":{real_name}"
            if val_key in ExpressionAttributeValues:
                item[real_name] = ExpressionAttributeValues[val_key]

    def query(self, *, IndexName: str = "", KeyConditionExpression=None, ScanIndexForward: bool = True, Limit: int = 100, **kwargs) -> Dict[str, Any]:
        items = list(self.items.values())
        if IndexName == "BySessionId":
            session_id = KeyConditionExpression._values[1]
            items = [i for i in items if i.get("session_id") == session_id]
            items.sort(key=lambda x: x.get("created_at", 0), reverse=not ScanIndexForward)
        elif IndexName == "ByStatusCreatedAt":
            status_val = KeyConditionExpression._values[1]
            items = [i for i in items if i.get("status") == status_val]
            items.sort(key=lambda x: x.get("created_at", 0), reverse=not ScanIndexForward)
        elif IndexName == "ByExpiresAt":
            items = [i for i in items if i.get("scope") == "ALL"]
            items.sort(key=lambda x: x.get("expires_at", 0))
        return {"Items": items[:Limit]}


class _FakeCondition:
    def __init__(self, *args) -> None:
        self._values = list(args)

    def __and__(self, other):
        return _FakeCondition(*self._values, *other._values)

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
    monkeypatch.setattr(broadcast_recording, "Key", lambda field: _FakeCondition(field))


@pytest.fixture()
def ready_recording(fake_table, fake_key):
    """Create a recording in 'ready' status with mp4_s3_key set."""
    rec = broadcast_recording.create_recording(
        session_id="sess_download_test",
        profile_id="prof_1",
        created_by="user_broadcaster",
    )
    broadcast_recording.update_recording_status(
        rec.recording_id,
        "ready",
        mp4_s3_key="sess_download_test/recording/full.mp4",
        mp4_size_bytes=1048576,
        mp4_generated_at=int(time.time()),
        s3_manifest_key="sess_download_test/recording/master.m3u8",
    )
    return broadcast_recording.get_recording(rec.recording_id)


# ─── MP4 Generation Tests ────────────────────────────────────────────


class TestGenerateMp4:
    def test_generate_mp4_mock_mode_returns_placeholder(self):
        """In mock mode, generate_mp4 returns mock metadata without calling FFmpeg."""
        rec = broadcast_recording.RecordingRecord(
            recording_id="rec_test",
            session_id="sess-mp4-mock",
            profile_id="prof-test",
            created_by="user",
            status="processing",
        )
        with patch.object(broadcast_recording_worker, "_should_mock", return_value=True):
            result = broadcast_recording_worker.generate_mp4(rec, None)
        assert result["mp4_s3_key"] == "sess-mp4-mock/recording/full.mp4"
        assert result["mp4_size_bytes"] == 0
        assert result["mp4_generated_at"] > 0

    def test_generate_mp4_no_concat_path_returns_mock(self):
        """When concat_path is None, mock metadata is returned."""
        rec = broadcast_recording.RecordingRecord(
            recording_id="rec_test",
            session_id="sess-mp4-none",
            profile_id="prof-test",
            created_by="user",
            status="processing",
        )
        with patch.object(broadcast_recording_worker, "_should_mock", return_value=False):
            result = broadcast_recording_worker.generate_mp4(rec, None)
        assert result["mp4_s3_key"] == "sess-mp4-none/recording/full.mp4"
        assert result["mp4_size_bytes"] == 0

    def test_generate_mp4_with_concat_path_calls_ffmpeg(self, tmp_path):
        """When concat_path is provided, subprocess.run is called with correct args."""
        rec = broadcast_recording.RecordingRecord(
            recording_id="rec_test",
            session_id="sess-mp4-real",
            profile_id="prof-test",
            created_by="user",
            status="processing",
        )
        ts_file = tmp_path / "full.ts"
        ts_file.write_bytes(b"\x00" * 1024)
        mp4_file = tmp_path / "full.mp4"

        import subprocess
        fake_result = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")

        with patch.object(broadcast_recording_worker, "_should_mock", return_value=False):
            with patch("subprocess.run", return_value=fake_result) as mock_run:
                with patch("os.path.getsize", return_value=2048):
                    with patch.object(broadcast_recording_worker, "_upload_to_s3"):
                        result = broadcast_recording_worker.generate_mp4(rec, str(ts_file))

        assert result["mp4_s3_key"] == "sess-mp4-real/recording/full.mp4"
        assert result["mp4_size_bytes"] == 2048
        # Verify ffmpeg args
        call_args = mock_run.call_args[0][0]
        assert "-c" in call_args
        assert "copy" in call_args
        assert "-movflags" in call_args
        assert "+faststart" in call_args

    def test_generate_mp4_ffmpeg_failure_raises(self, tmp_path):
        """If FFmpeg returns non-zero, RuntimeError is raised."""
        rec = broadcast_recording.RecordingRecord(
            recording_id="rec_test",
            session_id="sess-mp4-fail",
            profile_id="prof-test",
            created_by="user",
            status="processing",
        )
        ts_file = tmp_path / "full.ts"
        ts_file.write_bytes(b"\x00" * 1024)

        import subprocess
        fake_result = subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="Error encoding")

        with patch.object(broadcast_recording_worker, "_should_mock", return_value=False):
            with patch("subprocess.run", return_value=fake_result):
                with pytest.raises(RuntimeError, match="FFmpeg MP4 remux failed"):
                    broadcast_recording_worker.generate_mp4(rec, str(ts_file))

    def test_generate_mp4_output_key_format(self):
        """MP4 S3 key follows format: {session_id}/recording/full.mp4."""
        rec = broadcast_recording.RecordingRecord(
            recording_id="rec_test",
            session_id="my-session-xyz",
            profile_id="prof-test",
            created_by="user",
            status="processing",
        )
        with patch.object(broadcast_recording_worker, "_should_mock", return_value=True):
            result = broadcast_recording_worker.generate_mp4(rec, None)
        assert result["mp4_s3_key"] == "my-session-xyz/recording/full.mp4"


# ─── Download URL Minting Tests ──────────────────────────────────────


class TestMintDownloadUrl:
    def test_mint_download_url_dev_mode_returns_mock_path(self, fake_table, fake_key, ready_recording):
        """In dev mode, URL is /mock/s3/... with expires and disposition params."""
        with patch.object(broadcast_recording, "S", SimpleNamespace(
            dev_mode=True,
            broadcast_recording_download_ttl_seconds=14400,
            broadcast_recording_vod_bucket="broadcast-vod",
        )):
            result = broadcast_recording.mint_recording_download_url(ready_recording)
        assert "/mock/s3/broadcast-vod/" in result["download_url"]
        assert "disposition=attachment" in result["download_url"]
        assert "full.mp4" in result["download_url"]

    def test_mint_download_url_respects_ttl_setting(self, fake_table, fake_key, ready_recording):
        """download_expires_at = now + ttl."""
        now = int(time.time())
        with patch.object(broadcast_recording, "S", SimpleNamespace(
            dev_mode=True,
            broadcast_recording_download_ttl_seconds=7200,
            broadcast_recording_vod_bucket="broadcast-vod",
        )):
            result = broadcast_recording.mint_recording_download_url(ready_recording)
        # Within tolerance
        assert abs(result["download_expires_at"] - (now + 7200)) < 5

    def test_mint_download_url_filename_contains_session_id(self, fake_table, fake_key, ready_recording):
        """Filename is 'recording-{session_id_prefix}.mp4'."""
        with patch.object(broadcast_recording, "S", SimpleNamespace(
            dev_mode=True,
            broadcast_recording_download_ttl_seconds=14400,
            broadcast_recording_vod_bucket="broadcast-vod",
        )):
            result = broadcast_recording.mint_recording_download_url(ready_recording)
        assert result["filename"] == "recording-sess_downloa.mp4"
        assert result["content_type"] == "video/mp4"

    def test_mint_download_url_file_size_bytes(self, fake_table, fake_key, ready_recording):
        """file_size_bytes matches recording's mp4_size_bytes."""
        with patch.object(broadcast_recording, "S", SimpleNamespace(
            dev_mode=True,
            broadcast_recording_download_ttl_seconds=14400,
            broadcast_recording_vod_bucket="broadcast-vod",
        )):
            result = broadcast_recording.mint_recording_download_url(ready_recording)
        assert result["file_size_bytes"] == 1048576


# ─── Download Endpoint Tests ─────────────────────────────────────────


class TestDownloadEndpoint:
    @pytest.fixture()
    def client(self, fake_table, fake_key):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        from app.routers.broadcast import router
        from app.routers import broadcast as broadcast_module

        app = FastAPI()
        app.include_router(router)
        app.dependency_overrides[broadcast_module._ctx] = lambda: {"user_sub": "user_broadcaster", "role": "root"}
        return TestClient(app)

    @pytest.fixture()
    def client_viewer(self, fake_table, fake_key):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        from app.routers.broadcast import router
        from app.routers import broadcast as broadcast_module

        app = FastAPI()
        app.include_router(router)
        app.dependency_overrides[broadcast_module._ctx] = lambda: {"user_sub": "user_viewer", "role": "user"}
        return TestClient(app)

    def test_download_returns_404_no_recording(self, client):
        with patch("app.routers.broadcast.get_recording_by_session", return_value=None):
            resp = client.get("/broadcast/sessions/no-session/recording/download")
        assert resp.status_code == 404
        assert resp.json()["detail"]["code"] == "BROADCAST_RECORDING_NOT_FOUND"

    def test_download_returns_410_expired_recording(self, client):
        expired_rec = broadcast_recording.RecordingRecord(
            recording_id="rec_expired",
            session_id="sess-expired",
            profile_id="prof-001",
            created_by="user_broadcaster",
            status="expired",
            created_at=int(time.time()) - 86400,
        )
        with patch("app.routers.broadcast.get_recording_by_session", return_value=expired_rec):
            resp = client.get("/broadcast/sessions/sess-expired/recording/download")
        assert resp.status_code == 410
        assert resp.json()["detail"]["code"] == "BROADCAST_RECORDING_EXPIRED"

    def test_download_returns_202_processing_recording(self, client):
        processing_rec = broadcast_recording.RecordingRecord(
            recording_id="rec_proc",
            session_id="sess-proc",
            profile_id="prof-001",
            created_by="user_broadcaster",
            status="processing",
            created_at=int(time.time()),
        )
        with patch("app.routers.broadcast.get_recording_by_session", return_value=processing_rec):
            resp = client.get("/broadcast/sessions/sess-proc/recording/download")
        assert resp.status_code == 202
        assert resp.json()["code"] == "BROADCAST_RECORDING_PROCESSING"

    def test_download_returns_404_no_mp4(self, client):
        ready_no_mp4 = broadcast_recording.RecordingRecord(
            recording_id="rec_no_mp4",
            session_id="sess-no-mp4",
            profile_id="prof-001",
            created_by="user_broadcaster",
            status="ready",
            mp4_s3_key="",
            created_at=int(time.time()),
        )
        with patch("app.routers.broadcast.get_recording_by_session", return_value=ready_no_mp4):
            resp = client.get("/broadcast/sessions/sess-no-mp4/recording/download")
        assert resp.status_code == 404
        assert resp.json()["detail"]["code"] == "BROADCAST_RECORDING_MP4_NOT_AVAILABLE"

    def test_broadcaster_can_download_own_recording(self, client):
        ready_rec = broadcast_recording.RecordingRecord(
            recording_id="rec_ready",
            session_id="sess-ready",
            profile_id="prof-001",
            created_by="user_broadcaster",
            status="ready",
            mp4_s3_key="sess-ready/recording/full.mp4",
            mp4_size_bytes=5000000,
            created_at=int(time.time()),
        )
        with patch("app.routers.broadcast.get_recording_by_session", return_value=ready_rec):
            with patch("app.routers.broadcast.mint_recording_download_url", return_value={
                "download_url": "/mock/s3/broadcast-vod/sess-ready/recording/full.mp4?expires=9999&disposition=attachment",
                "download_expires_at": 9999,
                "file_size_bytes": 5000000,
                "filename": "recording-sess-ready.mp4",
                "content_type": "video/mp4",
            }):
                resp = client.get("/broadcast/sessions/sess-ready/recording/download")
        assert resp.status_code == 200
        data = resp.json()
        assert "download_url" in data
        assert data["file_size_bytes"] == 5000000
        assert data["filename"] == "recording-sess-ready.mp4"
        assert data["content_type"] == "video/mp4"

    def test_other_user_cannot_download_broadcaster_recording(self, client_viewer):
        ready_rec = broadcast_recording.RecordingRecord(
            recording_id="rec_ready",
            session_id="sess-ready",
            profile_id="prof-001",
            created_by="user_broadcaster",
            status="ready",
            mp4_s3_key="sess-ready/recording/full.mp4",
            mp4_size_bytes=5000000,
            created_at=int(time.time()),
        )
        with patch("app.routers.broadcast.get_recording_by_session", return_value=ready_rec):
            resp = client_viewer.get("/broadcast/sessions/sess-ready/recording/download")
        assert resp.status_code == 403
        assert resp.json()["detail"]["code"] == "BROADCAST_RECORDING_DOWNLOAD_FORBIDDEN"

    def test_viewer_download_forbidden_when_disabled(self, client_viewer):
        ready_rec = broadcast_recording.RecordingRecord(
            recording_id="rec_ready",
            session_id="sess-ready",
            profile_id="prof-001",
            created_by="user_broadcaster",
            status="ready",
            mp4_s3_key="sess-ready/recording/full.mp4",
            mp4_size_bytes=5000000,
            allow_viewer_download=False,
            created_at=int(time.time()),
        )
        with patch("app.routers.broadcast.get_recording_by_session", return_value=ready_rec):
            resp = client_viewer.get("/broadcast/sessions/sess-ready/recording/download?viewer=true")
        assert resp.status_code == 403
        assert resp.json()["detail"]["code"] == "BROADCAST_RECORDING_DOWNLOAD_FORBIDDEN"

    def test_viewer_download_allowed_when_enabled(self, client_viewer):
        ready_rec = broadcast_recording.RecordingRecord(
            recording_id="rec_ready",
            session_id="sess-ready",
            profile_id="prof-001",
            created_by="user_broadcaster",
            status="ready",
            mp4_s3_key="sess-ready/recording/full.mp4",
            mp4_size_bytes=5000000,
            allow_viewer_download=True,
            created_at=int(time.time()),
        )
        with patch("app.routers.broadcast.get_recording_by_session", return_value=ready_rec):
            with patch("app.routers.broadcast.mint_recording_download_url", return_value={
                "download_url": "/mock/s3/broadcast-vod/sess-ready/recording/full.mp4?expires=9999&disposition=attachment",
                "download_expires_at": 9999,
                "file_size_bytes": 5000000,
                "filename": "recording-sess-ready.mp4",
                "content_type": "video/mp4",
            }):
                resp = client_viewer.get("/broadcast/sessions/sess-ready/recording/download?viewer=true")
        assert resp.status_code == 200
        data = resp.json()
        assert "download_url" in data

    def test_download_disabled_returns_503(self, fake_table, fake_key):
        """When BROADCAST_RECORDING_DOWNLOAD_ENABLED=false, returns 503."""
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        from app.routers.broadcast import router
        from app.routers import broadcast as broadcast_module
        import app.core.settings as settings_module

        app = FastAPI()
        app.include_router(router)
        app.dependency_overrides[broadcast_module._ctx] = lambda: {"user_sub": "user_broadcaster", "role": "root"}

        # Create a mock settings object with download disabled
        mock_s = MagicMock()
        mock_s.broadcast_recording_download_enabled = False

        tc = TestClient(app)
        with patch.object(settings_module, "S", mock_s):
            resp = tc.get("/broadcast/sessions/sess-any/recording/download")
        assert resp.status_code == 503


# ─── Download Settings Endpoint Tests ────────────────────────────────


class TestDownloadSettingsEndpoint:
    @pytest.fixture()
    def client(self, fake_table, fake_key):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        from app.routers.broadcast import router
        from app.routers import broadcast as broadcast_module

        app = FastAPI()
        app.include_router(router)
        app.dependency_overrides[broadcast_module._ctx] = lambda: {"user_sub": "user_broadcaster", "role": "root"}
        return TestClient(app)

    @pytest.fixture()
    def client_viewer(self, fake_table, fake_key):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        from app.routers.broadcast import router
        from app.routers import broadcast as broadcast_module

        app = FastAPI()
        app.include_router(router)
        app.dependency_overrides[broadcast_module._ctx] = lambda: {"user_sub": "user_viewer", "role": "user"}
        return TestClient(app)

    def test_toggle_viewer_download_on(self, client, ready_recording):
        with patch("app.routers.broadcast.get_recording_by_session", return_value=ready_recording):
            with patch("app.services.broadcast_recording.update_recording_status") as mock_update:
                mock_update.return_value = ready_recording
                resp = client.patch(
                    "/broadcast/sessions/sess_download_test/recording/download-settings",
                    json={"allow_viewer_download": True},
                )
        assert resp.status_code == 200
        assert resp.json()["ok"] is True
        assert resp.json()["allow_viewer_download"] is True

    def test_toggle_viewer_download_off(self, client, ready_recording):
        with patch("app.routers.broadcast.get_recording_by_session", return_value=ready_recording):
            with patch("app.services.broadcast_recording.update_recording_status") as mock_update:
                mock_update.return_value = ready_recording
                resp = client.patch(
                    "/broadcast/sessions/sess_download_test/recording/download-settings",
                    json={"allow_viewer_download": False},
                )
        assert resp.status_code == 200
        assert resp.json()["allow_viewer_download"] is False

    def test_toggle_requires_ownership(self, client_viewer, ready_recording):
        with patch("app.routers.broadcast.get_recording_by_session", return_value=ready_recording):
            resp = client_viewer.patch(
                "/broadcast/sessions/sess_download_test/recording/download-settings",
                json={"allow_viewer_download": True},
            )
        assert resp.status_code == 403

    def test_toggle_returns_404_no_recording(self, client):
        with patch("app.routers.broadcast.get_recording_by_session", return_value=None):
            resp = client.patch(
                "/broadcast/sessions/no-session/recording/download-settings",
                json={"allow_viewer_download": True},
            )
        assert resp.status_code == 404


# ─── Pipeline Integration Tests ──────────────────────────────────────


class TestPipelineWithMp4:
    def test_pipeline_generates_mp4_when_enabled(self, fake_table, fake_key):
        """Full pipeline in mock mode produces mp4_s3_key in finalized recording."""
        with patch.object(broadcast_recording_worker, "_should_mock", return_value=True):
            rec = broadcast_recording.create_recording(
                session_id="sess-pipeline-mp4",
                profile_id="prof-001",
                created_by="user-1",
            )
            with patch.object(broadcast_recording_worker, "get_recording", side_effect=broadcast_recording.get_recording):
                with patch.object(broadcast_recording_worker, "update_recording_status", side_effect=broadcast_recording.update_recording_status):
                    result = broadcast_recording_worker.process_recording(rec.recording_id)

        assert result is not None
        assert result.status == "ready"
        assert result.mp4_s3_key == "sess-pipeline-mp4/recording/full.mp4"
        assert result.mp4_generated_at > 0

    def test_pipeline_skips_mp4_when_disabled(self, fake_table, fake_key):
        """When mp4_auto_generate is False, pipeline still completes but no mp4."""
        with patch.object(broadcast_recording_worker, "_should_mock", return_value=True):
            with patch.object(broadcast_recording_worker, "S", SimpleNamespace(
                broadcast_recording_mp4_auto_generate=False,
                ffmpeg_binary_path="ffmpeg",
                broadcast_recording_mock_on_no_ffmpeg=True,
            )):
                rec = broadcast_recording.create_recording(
                    session_id="sess-pipeline-no-mp4",
                    profile_id="prof-001",
                    created_by="user-1",
                )
                with patch.object(broadcast_recording_worker, "get_recording", side_effect=broadcast_recording.get_recording):
                    with patch.object(broadcast_recording_worker, "update_recording_status", side_effect=broadcast_recording.update_recording_status):
                        result = broadcast_recording_worker.process_recording(rec.recording_id)

        assert result is not None
        assert result.status == "ready"
        assert result.mp4_s3_key == ""
