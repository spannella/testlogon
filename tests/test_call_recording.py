"""Unit tests for call recording (CALL-009)."""
from __future__ import annotations

import os
import sys
import time
import uuid
from unittest.mock import MagicMock, patch

import pytest

# Ensure project root on path
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)


@pytest.fixture(autouse=True)
def _mock_env(monkeypatch):
    """Set env vars for test settings."""
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


@pytest.fixture()
def ddb_table():
    """Create an in-memory DynamoDB table for CallRecordings using moto."""
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


# ---------------------------------------------------------------------------
# Store tests
# ---------------------------------------------------------------------------


class TestCallRecordingStore:
    def test_create_recording(self, mock_table):
        from app.services.call_recording_store import create_recording

        rec = create_recording(
            call_id="call_001",
            conversation_id="conv_001",
            initiated_by="alice",
            participants=["alice", "bob"],
        )
        assert rec.recording_id.startswith("rec_")
        assert rec.call_id == "call_001"
        assert rec.conversation_id == "conv_001"
        assert rec.initiated_by == "alice"
        assert rec.participants == ["alice", "bob"]
        assert rec.status == "pending_consent"
        assert rec.created_at > 0

    def test_get_recording(self, mock_table):
        from app.services.call_recording_store import create_recording, get_recording

        rec = create_recording(
            call_id="call_002",
            conversation_id="conv_002",
            initiated_by="alice",
            participants=["alice", "bob"],
        )
        fetched = get_recording(rec.recording_id)
        assert fetched is not None
        assert fetched.recording_id == rec.recording_id
        assert fetched.call_id == "call_002"

    def test_get_recording_not_found(self, mock_table):
        from app.services.call_recording_store import get_recording

        result = get_recording("nonexistent_id")
        assert result is None

    def test_consent_recording(self, mock_table):
        from app.services.call_recording_store import create_recording, consent_recording

        rec = create_recording(
            call_id="call_003",
            conversation_id="conv_003",
            initiated_by="alice",
            participants=["alice", "bob"],
        )
        updated = consent_recording(rec.recording_id, "bob")
        assert updated is not None
        assert updated.status == "recording"
        assert updated.consent_ts > 0
        assert updated.started_at > 0

    def test_start_upload(self, mock_table):
        from app.services.call_recording_store import create_recording, consent_recording, start_upload

        rec = create_recording(
            call_id="call_004",
            conversation_id="conv_004",
            initiated_by="alice",
            participants=["alice", "bob"],
        )
        consent_recording(rec.recording_id, "bob")
        updated = start_upload(rec.recording_id)
        assert updated is not None
        assert updated.status == "uploading"
        assert updated.upload_ticket_id.startswith("tkt_")

    def test_complete_upload(self, mock_table):
        from app.services.call_recording_store import (
            create_recording,
            consent_recording,
            start_upload,
            complete_upload,
        )

        rec = create_recording(
            call_id="call_005",
            conversation_id="conv_005",
            initiated_by="alice",
            participants=["alice", "bob"],
        )
        consent_recording(rec.recording_id, "bob")
        start_upload(rec.recording_id)
        updated = complete_upload(
            rec.recording_id,
            s3_key="call-recordings/rec_123/recording.webm",
            s3_bucket="local-uploads",
            file_size_bytes=1024000,
            duration_seconds=120.5,
            mime_type="video/webm",
        )
        assert updated is not None
        assert updated.status == "ready"
        assert updated.s3_key == "call-recordings/rec_123/recording.webm"
        assert updated.file_size_bytes == 1024000
        assert updated.duration_seconds == 120.5
        assert updated.completed_at > 0

    def test_fail_recording(self, mock_table):
        from app.services.call_recording_store import create_recording, consent_recording, fail_recording

        rec = create_recording(
            call_id="call_006",
            conversation_id="conv_006",
            initiated_by="alice",
            participants=["alice", "bob"],
        )
        consent_recording(rec.recording_id, "bob")
        updated = fail_recording(rec.recording_id, "upload failed")
        assert updated is not None
        assert updated.status == "failed"
        assert updated.error_message == "upload failed"

    def test_soft_delete_recording(self, mock_table):
        from app.services.call_recording_store import create_recording, soft_delete_recording

        rec = create_recording(
            call_id="call_007",
            conversation_id="conv_007",
            initiated_by="alice",
            participants=["alice", "bob"],
        )
        updated = soft_delete_recording(rec.recording_id)
        assert updated is not None
        assert updated.status == "deleted"

    def test_invalid_status_transition(self, mock_table):
        from app.services.call_recording_store import (
            create_recording,
            consent_recording,
            start_upload,
            complete_upload,
            update_recording_status,
        )

        rec = create_recording(
            call_id="call_008",
            conversation_id="conv_008",
            initiated_by="alice",
            participants=["alice", "bob"],
        )
        consent_recording(rec.recording_id, "bob")
        start_upload(rec.recording_id)
        complete_upload(
            rec.recording_id,
            s3_key="key",
            s3_bucket="bucket",
            file_size_bytes=100,
            duration_seconds=10.0,
        )
        # ready -> recording is invalid
        with pytest.raises(ValueError, match="Invalid status transition"):
            update_recording_status(rec.recording_id, "recording")

    def test_get_recordings_for_call(self, mock_table):
        from app.services.call_recording_store import create_recording, get_recordings_for_call

        create_recording(
            call_id="call_010",
            conversation_id="conv_010",
            initiated_by="alice",
            participants=["alice", "bob"],
        )
        create_recording(
            call_id="call_010",
            conversation_id="conv_010",
            initiated_by="bob",
            participants=["alice", "bob"],
        )
        recs = get_recordings_for_call("call_010")
        assert len(recs) == 2
        assert all(r.call_id == "call_010" for r in recs)

    def test_get_active_recording_for_call(self, mock_table):
        from app.services.call_recording_store import (
            create_recording,
            get_active_recording_for_call,
            soft_delete_recording,
        )

        rec = create_recording(
            call_id="call_011",
            conversation_id="conv_011",
            initiated_by="alice",
            participants=["alice", "bob"],
        )
        active = get_active_recording_for_call("call_011")
        assert active is not None
        assert active.recording_id == rec.recording_id

        soft_delete_recording(rec.recording_id)
        active = get_active_recording_for_call("call_011")
        assert active is None

    def test_ttl_calculated_from_retention(self, mock_table):
        from app.services.call_recording_store import create_recording

        rec = create_recording(
            call_id="call_012",
            conversation_id="conv_012",
            initiated_by="alice",
            participants=["alice", "bob"],
        )
        expected_ttl = rec.created_at + 90 * 86400
        assert rec.ttl == expected_ttl


# ---------------------------------------------------------------------------
# Signaling tests
# ---------------------------------------------------------------------------


class TestRecordingSignaling:
    def test_recording_types_in_allowed_set(self):
        from app.services.messaging_call_signaling import ALLOWED_SIGNALING_TYPES

        recording_types = {
            "call.recording_request",
            "call.recording_accept",
            "call.recording_decline",
            "call.recording_started",
            "call.recording_stopped",
        }
        for rt in recording_types:
            assert rt in ALLOWED_SIGNALING_TYPES, f"{rt} not in ALLOWED_SIGNALING_TYPES"

    def test_recording_types_in_connected_state(self):
        from app.services.messaging_call_signaling import STATE_ALLOWED_SIGNALING_TYPES

        connected = STATE_ALLOWED_SIGNALING_TYPES.get("connected", set())
        recording_types = {
            "call.recording_request",
            "call.recording_accept",
            "call.recording_decline",
            "call.recording_started",
            "call.recording_stopped",
        }
        for rt in recording_types:
            assert rt in connected, f"{rt} not in STATE_ALLOWED_SIGNALING_TYPES['connected']"

    def test_recording_types_not_in_invited_state(self):
        from app.services.messaging_call_signaling import STATE_ALLOWED_SIGNALING_TYPES

        invited = STATE_ALLOWED_SIGNALING_TYPES.get("invited", set())
        assert "call.recording_request" not in invited

    def test_recording_types_not_in_accepted_state(self):
        from app.services.messaging_call_signaling import STATE_ALLOWED_SIGNALING_TYPES

        accepted = STATE_ALLOWED_SIGNALING_TYPES.get("accepted", set())
        assert "call.recording_request" not in accepted
