"""Unit tests for CALL-009 call recording integration (endpoint wiring).

Tests the call_recording router endpoints using mocked DDB store functions
and mocked call sessions, following the pattern in test_call_recording.py.
These tests focus on the HTTP-level integration: routing, auth checks,
status transitions, and response shapes. Low-level store behaviour is
already covered by test_call_recording.py.
"""
from __future__ import annotations

import os
import sys
import time
import uuid
from dataclasses import dataclass
from typing import Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)


# ─── Env / settings fixture ───────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _mock_env(monkeypatch):
    monkeypatch.setenv("DEV_MODE", "1")
    monkeypatch.setenv("DDB_ENDPOINT_URL", "http://localhost:8001")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "test")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "test")
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    monkeypatch.setenv("UI_ACCESS_TOKEN_SECRET", "test-secret")
    monkeypatch.setenv("API_KEY_PEPPER", "test-pepper")
    monkeypatch.setenv("CALL_RECORDING_ENABLED", "1")
    monkeypatch.setenv("DDB_CALL_RECORDINGS_TABLE", "CallRecordings")
    monkeypatch.setenv("CALL_RECORDING_RETENTION_DAYS", "90")
    monkeypatch.setenv("CALL_RECORDING_S3_PREFIX", "call-recordings/")
    monkeypatch.setenv("CALL_RECORDING_UPLOAD_TTL_SECONDS", "3600")
    monkeypatch.setenv("CALL_RECORDING_DOWNLOAD_TTL_SECONDS", "3600")
    monkeypatch.setenv("CALL_RECORDING_MAX_FILE_SIZE_BYTES", "5368709120")


# ─── Fixtures / helpers ───────────────────────────────────────────────────────


@pytest.fixture()
def ddb_table():
    """Create an in-memory moto DynamoDB table for CallRecordings."""
    import boto3
    from moto import mock_aws

    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        ddb.create_table(
            TableName="CallRecordings",
            KeySchema=[{"AttributeName": "recording_id", "KeyType": "HASH"}],
            AttributeDefinitions=[
                {"AttributeName": "recording_id", "AttributeType": "S"},
                {"AttributeName": "call_id", "AttributeType": "S"},
                {"AttributeName": "conversation_id", "AttributeType": "S"},
                {"AttributeName": "status", "AttributeType": "S"},
                {"AttributeName": "created_at", "AttributeType": "N"},
            ],
            GlobalSecondaryIndexes=[
                {
                    "IndexName": "ByCallIdCreatedAt",
                    "KeySchema": [
                        {"AttributeName": "call_id", "KeyType": "HASH"},
                        {"AttributeName": "created_at", "KeyType": "RANGE"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                },
                {
                    "IndexName": "ByConversationCreatedAt",
                    "KeySchema": [
                        {"AttributeName": "conversation_id", "KeyType": "HASH"},
                        {"AttributeName": "created_at", "KeyType": "RANGE"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                },
                {
                    "IndexName": "ByStatus",
                    "KeySchema": [
                        {"AttributeName": "status", "KeyType": "HASH"},
                        {"AttributeName": "created_at", "KeyType": "RANGE"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                },
            ],
            BillingMode="PAY_PER_REQUEST",
        )
        table = ddb.Table("CallRecordings")
        yield table


@pytest.fixture()
def mock_table(ddb_table, monkeypatch):
    """Patch call_recording_store._table to use the moto table."""
    from app.services import call_recording_store
    monkeypatch.setattr(call_recording_store, "_table", lambda: ddb_table)
    return ddb_table


def _make_call_session(
    *,
    call_id: str = "call_int001",
    caller: str = "alice",
    callee: str = "bob",
    conversation_id: str = "c_conv_int001",
    state: str = "connected",
):
    """Build a fake CallSessionRecord."""
    from app.services.messaging_call_sessions import CallSessionRecord
    return CallSessionRecord(
        call_id=call_id,
        conversation_id=conversation_id,
        caller_user_id=caller,
        callee_user_id=callee,
        initial_mode="video",
        state=state,
        start_ts=int(time.time()) - 60,
        connect_ts=int(time.time()) - 30,
    )


def _make_recording(mock_table, *, call_id: str = "call_int001", conversation_id: str = "c_conv_int001", initiator: str = "alice", status_override: Optional[str] = None):
    """Seed a recording record in the moto table via the store."""
    from app.services.call_recording_store import create_recording, consent_recording, start_upload, complete_upload

    rec = create_recording(
        call_id=call_id,
        conversation_id=conversation_id,
        initiated_by=initiator,
        participants=["alice", "bob"],
    )
    if status_override in ("recording", "uploading", "ready"):
        consent_recording(rec.recording_id, "bob")
    if status_override in ("uploading", "ready"):
        start_upload(rec.recording_id)
    if status_override == "ready":
        complete_upload(
            rec.recording_id,
            s3_key=f"call-recordings/{rec.recording_id}/recording.webm",
            s3_bucket="local-uploads",
            file_size_bytes=512000,
            duration_seconds=60.5,
            mime_type="video/webm",
        )
    return rec


# ─── Listing endpoint tests ───────────────────────────────────────────────────


class TestListRecordings:

    def test_list_recordings_without_filter_returns_all(self, mock_table):
        """GET /messages/recordings without filter returns all recordings for this user."""
        import asyncio
        from app.routers import call_recording

        # Seed two recordings for alice
        _make_recording(mock_table, call_id="call_a1", conversation_id="c_ca1")
        _make_recording(mock_table, call_id="call_a2", conversation_id="c_ca2")

        mock_request = MagicMock()

        with patch.object(call_recording, "S") as mock_s:
            mock_s.call_recording_enabled = True
            mock_s.dev_mode = True
            mock_s.call_recording_download_ttl_seconds = 3600
            result = asyncio.run(
                call_recording.list_user_recordings(request=mock_request, user_id="alice", conversation_id=None)
            )

        assert len(result.items) >= 2
        recording_ids = {r.recording_id for r in result.items}
        assert len(recording_ids) >= 2

    def test_list_recordings_with_conversation_filter(self, mock_table):
        """GET /messages/recordings?conversation_id=X only returns recordings from that conversation."""
        import asyncio
        from app.routers import call_recording

        target_conv = "c_filtered_conv001"
        other_conv = "c_other_conv999"

        _make_recording(mock_table, call_id="call_f1", conversation_id=target_conv)
        _make_recording(mock_table, call_id="call_f2", conversation_id=other_conv)

        mock_request = MagicMock()

        with patch.object(call_recording, "S") as mock_s:
            mock_s.call_recording_enabled = True
            mock_s.dev_mode = True
            mock_s.call_recording_download_ttl_seconds = 3600
            result = asyncio.run(
                call_recording.list_user_recordings(
                    request=mock_request,
                    user_id="alice",
                    conversation_id=target_conv,
                )
            )

        assert all(r.conversation_id == target_conv for r in result.items)
        conv_ids = {r.conversation_id for r in result.items}
        assert other_conv not in conv_ids


# ─── Request recording tests ──────────────────────────────────────────────────


class TestRequestRecording:

    def test_request_recording_on_connected_call(self, mock_table):
        """Requesting recording on a connected call returns 200 with recording_id."""
        import asyncio
        from app.routers import call_recording

        call_id = "call_req001"
        call_session = _make_call_session(call_id=call_id, state="connected")
        mock_request = MagicMock()

        with (
            patch.object(call_recording, "S") as mock_s,
            patch.object(call_recording, "_get_call_session", return_value=call_session),
            patch("app.services.call_recording_store._table", return_value=mock_table),
        ):
            mock_s.call_recording_enabled = True
            mock_s.call_recordings_table_name = "CallRecordings"
            mock_s.call_recording_retention_days = 90
            result = asyncio.run(
                call_recording.request_recording(
                    call_id=call_id,
                    request=mock_request,
                    user_id="alice",
                )
            )

        assert result.recording_id.startswith("rec_")
        assert result.status == "pending_consent"
        assert result.created_at > 0

    def test_request_recording_not_connected_409(self, mock_table):
        """Requesting recording on a non-connected call returns 409."""
        import asyncio
        from app.routers import call_recording

        call_id = "call_req002"
        call_session = _make_call_session(call_id=call_id, state="invited")  # not connected
        mock_request = MagicMock()

        with (
            patch.object(call_recording, "S") as mock_s,
            patch.object(call_recording, "_get_call_session", return_value=call_session),
        ):
            mock_s.call_recording_enabled = True
            with pytest.raises(HTTPException) as exc_info:
                asyncio.run(
                    call_recording.request_recording(
                        call_id=call_id,
                        request=mock_request,
                        user_id="alice",
                    )
                )
        assert exc_info.value.status_code == 409


# ─── Consent / decline tests ──────────────────────────────────────────────────


class TestConsentRecording:

    def test_consent_transitions_to_recording(self, mock_table):
        """Consenting to a recording request transitions status to 'recording'."""
        import asyncio
        from app.routers import call_recording

        call_id = "call_consent001"
        call_session = _make_call_session(call_id=call_id, state="connected")
        rec = _make_recording(mock_table, call_id=call_id, initiator="alice")

        mock_request = MagicMock()

        with (
            patch.object(call_recording, "S") as mock_s,
            patch.object(call_recording, "_get_call_session", return_value=call_session),
            patch("app.services.call_recording_store._table", return_value=mock_table),
        ):
            mock_s.call_recording_enabled = True
            mock_s.call_recordings_table_name = "CallRecordings"
            mock_s.call_recording_retention_days = 90
            result = asyncio.run(
                call_recording.consent_recording_endpoint(
                    call_id=call_id,
                    request=mock_request,
                    user_id="bob",  # bob consents (alice initiated)
                )
            )

        assert result.status == "recording"
        assert result.started_at > 0

    def test_decline_removes_recording(self, mock_table):
        """Declining a recording request soft-deletes it."""
        import asyncio
        from app.routers import call_recording
        from app.services.call_recording_store import get_recording

        call_id = "call_decline001"
        call_session = _make_call_session(call_id=call_id, state="connected")
        rec = _make_recording(mock_table, call_id=call_id, initiator="alice")

        mock_request = MagicMock()

        with (
            patch.object(call_recording, "S") as mock_s,
            patch.object(call_recording, "_get_call_session", return_value=call_session),
            patch("app.services.call_recording_store._table", return_value=mock_table),
        ):
            mock_s.call_recording_enabled = True
            mock_s.call_recordings_table_name = "CallRecordings"
            mock_s.call_recording_retention_days = 90
            result = asyncio.run(
                call_recording.decline_recording_endpoint(
                    call_id=call_id,
                    request=mock_request,
                    user_id="bob",
                )
            )

        assert result.ok is True
        # Verify the recording is now deleted
        updated = get_recording(rec.recording_id)
        assert updated is not None
        assert updated.status == "deleted"


# ─── Upload presign tests ─────────────────────────────────────────────────────


class TestPresignUpload:

    def test_presign_upload_returns_upload_url(self, mock_table):
        """POST .../recording/upload/presign returns a presigned upload URL."""
        import asyncio
        from app.routers import call_recording

        call_id = "call_presign001"
        call_session = _make_call_session(call_id=call_id, state="connected")
        _make_recording(mock_table, call_id=call_id, initiator="alice", status_override="recording")

        mock_request = MagicMock()

        with (
            patch.object(call_recording, "S") as mock_s,
            patch.object(call_recording, "_get_call_session", return_value=call_session),
            patch("app.services.call_recording_store._table", return_value=mock_table),
        ):
            mock_s.call_recording_enabled = True
            mock_s.dev_mode = True
            mock_s.call_recordings_table_name = "CallRecordings"
            mock_s.call_recording_retention_days = 90
            mock_s.call_recording_s3_prefix = "call-recordings/"
            mock_s.call_recording_upload_ttl_seconds = 3600
            mock_s.call_recording_max_file_size_bytes = 5 * 1024 ** 3
            mock_s.filemgr_bucket = "local-uploads"

            body = call_recording.RecordingUploadPresignIn(
                content_type="video/webm",
                file_size_bytes=512000,
            )
            result = asyncio.run(
                call_recording.presign_recording_upload(
                    call_id=call_id,
                    body=body,
                    request=mock_request,
                    user_id="alice",
                )
            )

        assert result.upload_url is not None
        assert result.recording_id.startswith("rec_")
        assert result.s3_key is not None
        assert result.expires_at > 0

    def test_presign_upload_file_too_large_400(self, mock_table):
        """Presign upload with oversized file returns 400."""
        import asyncio
        from app.routers import call_recording

        call_id = "call_presign002"
        call_session = _make_call_session(call_id=call_id, state="connected")
        _make_recording(mock_table, call_id=call_id, initiator="alice", status_override="recording")

        mock_request = MagicMock()

        with (
            patch.object(call_recording, "S") as mock_s,
            patch.object(call_recording, "_get_call_session", return_value=call_session),
            patch("app.services.call_recording_store._table", return_value=mock_table),
        ):
            mock_s.call_recording_enabled = True
            mock_s.dev_mode = True
            mock_s.call_recordings_table_name = "CallRecordings"
            mock_s.call_recording_retention_days = 90
            mock_s.call_recording_s3_prefix = "call-recordings/"
            mock_s.call_recording_upload_ttl_seconds = 3600
            mock_s.call_recording_max_file_size_bytes = 1000  # tiny limit
            mock_s.filemgr_bucket = "local-uploads"

            body = call_recording.RecordingUploadPresignIn(
                content_type="video/webm",
                file_size_bytes=999_999_999,  # way over limit
            )
            with pytest.raises(HTTPException) as exc_info:
                asyncio.run(
                    call_recording.presign_recording_upload(
                        call_id=call_id,
                        body=body,
                        request=mock_request,
                        user_id="alice",
                    )
                )
        assert exc_info.value.status_code == 400


# ─── Complete upload tests ────────────────────────────────────────────────────


class TestCompleteUpload:

    def test_complete_upload_transitions_to_ready(self, mock_table):
        """POST .../recording/upload/complete transitions status to 'ready'."""
        import asyncio
        from app.routers import call_recording

        call_id = "call_complete001"
        call_session = _make_call_session(call_id=call_id, state="connected")
        rec = _make_recording(mock_table, call_id=call_id, initiator="alice", status_override="uploading")

        mock_request = MagicMock()

        with (
            patch.object(call_recording, "S") as mock_s,
            patch.object(call_recording, "_get_call_session", return_value=call_session),
            patch("app.services.call_recording_store._table", return_value=mock_table),
        ):
            mock_s.call_recording_enabled = True
            mock_s.dev_mode = True
            mock_s.call_recordings_table_name = "CallRecordings"
            mock_s.call_recording_retention_days = 90
            mock_s.call_recording_s3_prefix = "call-recordings/"
            mock_s.call_recording_download_ttl_seconds = 3600
            mock_s.filemgr_bucket = "local-uploads"

            body = call_recording.RecordingUploadCompleteIn(
                recording_id=rec.recording_id,
                duration_seconds=60.5,
            )
            result = asyncio.run(
                call_recording.complete_recording_upload(
                    call_id=call_id,
                    body=body,
                    request=mock_request,
                    user_id="alice",
                )
            )

        assert result.status == "ready"
        assert result.download_url is not None


# ─── Download tests ───────────────────────────────────────────────────────────


class TestDownloadRecording:

    def test_download_by_participant_returns_download_url(self, mock_table):
        """GET /messages/recordings/{id}/download returns a download URL for a participant."""
        import asyncio
        from app.routers import call_recording

        rec = _make_recording(mock_table, call_id="call_dl001", initiator="alice", status_override="ready")
        mock_request = MagicMock()

        with (
            patch.object(call_recording, "S") as mock_s,
            patch("app.services.call_recording_store._table", return_value=mock_table),
        ):
            mock_s.call_recording_enabled = True
            mock_s.dev_mode = True
            mock_s.call_recordings_table_name = "CallRecordings"
            mock_s.call_recording_retention_days = 90
            mock_s.call_recording_s3_prefix = "call-recordings/"
            mock_s.call_recording_download_ttl_seconds = 3600
            mock_s.filemgr_bucket = "local-uploads"

            result = asyncio.run(
                call_recording.download_recording(
                    recording_id=rec.recording_id,
                    request=mock_request,
                    user_id="alice",
                )
            )

        assert result.download_url is not None
        assert result.download_expires_at > 0
        assert result.file_size_bytes >= 0
        assert result.filename is not None

    def test_download_by_non_participant_403(self, mock_table):
        """Non-participant cannot download a recording."""
        import asyncio
        from app.routers import call_recording

        rec = _make_recording(mock_table, call_id="call_dl002", initiator="alice", status_override="ready")
        mock_request = MagicMock()

        with (
            patch.object(call_recording, "S") as mock_s,
            patch("app.services.call_recording_store._table", return_value=mock_table),
        ):
            mock_s.call_recording_enabled = True
            mock_s.dev_mode = True
            mock_s.call_recordings_table_name = "CallRecordings"
            mock_s.call_recording_retention_days = 90
            mock_s.call_recording_download_ttl_seconds = 3600
            mock_s.filemgr_bucket = "local-uploads"

            with pytest.raises(HTTPException) as exc_info:
                asyncio.run(
                    call_recording.download_recording(
                        recording_id=rec.recording_id,
                        request=mock_request,
                        user_id="carol",   # not a participant
                    )
                )
        assert exc_info.value.status_code == 403

    def test_download_not_ready_404(self, mock_table):
        """GET /messages/recordings/{id}/download returns 404 if recording is not ready."""
        import asyncio
        from app.routers import call_recording

        # pending_consent, not ready
        rec = _make_recording(mock_table, call_id="call_dl003", initiator="alice")
        mock_request = MagicMock()

        with (
            patch.object(call_recording, "S") as mock_s,
            patch("app.services.call_recording_store._table", return_value=mock_table),
        ):
            mock_s.call_recording_enabled = True
            mock_s.call_recordings_table_name = "CallRecordings"
            mock_s.call_recording_retention_days = 90

            with pytest.raises(HTTPException) as exc_info:
                asyncio.run(
                    call_recording.download_recording(
                        recording_id=rec.recording_id,
                        request=mock_request,
                        user_id="alice",
                    )
                )
        assert exc_info.value.status_code == 404
