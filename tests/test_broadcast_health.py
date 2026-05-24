"""Unit tests for broadcast health metrics."""
from __future__ import annotations

import time
from decimal import Decimal
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from app.services import broadcast_health
from app.services import broadcast_sse
from app.services import broadcast_viewers


class _FakeHealthTable:
    """In-memory DynamoDB table mock for health snapshots."""

    def __init__(self):
        self.items = []

    def put_item(self, *, Item):
        self.items.append(Item)

    def query(self, *, KeyConditionExpression, ScanIndexForward=None, Limit=None):
        session_id = KeyConditionExpression._values[1]
        matching = [i for i in self.items if i["session_id"] == session_id]
        # Sort by snapshot_ts
        matching.sort(key=lambda x: x["snapshot_ts"], reverse=(ScanIndexForward is False))
        if Limit:
            matching = matching[:Limit]
        return {"Items": matching}


class _FakeViewersTable:
    """In-memory DynamoDB table mock for viewer count queries."""

    def __init__(self):
        self.items = {}

    def put_item(self, *, Item):
        key = (Item["session_id"], Item["viewer_id"])
        self.items[key] = Item

    def query(self, *, KeyConditionExpression, Select=None, **kwargs):
        session_id = KeyConditionExpression._values[1]
        matching = [v for k, v in self.items.items() if k[0] == session_id]
        if Select == "COUNT":
            return {"Count": len(matching)}
        return {"Items": matching}


@pytest.fixture
def mock_ddb():
    health_table = _FakeHealthTable()
    viewers_table = _FakeViewersTable()
    tables = SimpleNamespace(
        broadcast_health_snapshots=health_table,
        broadcast_viewers=viewers_table,
    )
    with patch.object(broadcast_health, "T", tables):
        with patch.object(broadcast_viewers, "T", SimpleNamespace(broadcast_viewers=viewers_table)):
            yield {"health": health_table, "viewers": viewers_table}


@pytest.fixture
def mock_sse_publish():
    with patch.object(broadcast_sse, "broadcast_sse_publish") as mock_pub:
        with patch.object(broadcast_health, "broadcast_sse_publish", mock_pub):
            with patch.object(broadcast_viewers, "broadcast_sse_publish", mock_pub):
                yield mock_pub


class TestClassifyConnectionQuality:
    @pytest.mark.parametrize("drop,bitrate,loss,expected", [
        (0.05, 6000, 0, "excellent"),
        (0.3, 3000, 0, "good"),
        (1.5, 1500, 1, "fair"),
        (4.0, 800, 3, "poor"),
        (10.0, 200, 10, "critical"),
        (0.0, 500, 0, "good"),  # low bitrate but no drops — still "good" since >= 500 kbps... wait no: needs >=2000
        (6.0, 8000, 0, "critical"),  # high drops despite good bitrate
    ])
    def test_quality_classification(self, drop, bitrate, loss, expected):
        result = broadcast_health.classify_connection_quality(drop, bitrate, loss)
        # Special case: 0.0% drops, 500 kbps, 0 loss => check thresholds
        # excellent: needs >=4000 kbps -> no
        # good: needs >=2000 kbps -> no (500 < 2000)
        # fair: needs >=1000 kbps -> no (500 < 1000)
        # poor: needs >=500 kbps -> yes, drop=0 <= 5.0, loss=0 <= 5 -> poor
        if drop == 0.0 and bitrate == 500 and loss == 0:
            assert result == "poor"
        else:
            assert result == expected


class TestStoreHealthSnapshot:
    def test_stores_and_returns_snapshot(self, mock_ddb):
        result = broadcast_health.store_health_snapshot(
            "session-1",
            ingest_bitrate_kbps=4500,
            ingest_framerate=30.0,
            dropped_frames=5,
            dropped_frames_pct=0.02,
        )
        assert result["session_id"] == "session-1"
        assert result["connection_quality"] == "excellent"
        assert result["viewer_count"] >= 0

    def test_publishes_health_update_sse(self, mock_ddb, mock_sse_publish):
        broadcast_health.store_health_snapshot(
            "session-1",
            ingest_bitrate_kbps=1200,
            ingest_framerate=24.0,
            dropped_frames=100,
            dropped_frames_pct=1.5,
        )
        call_args = mock_sse_publish.call_args[0]
        assert call_args[1]["_type"] == "health_update"
        assert call_args[1]["connection_quality"] == "fair"


class TestGetLatestHealth:
    def test_returns_most_recent_snapshot(self, mock_ddb):
        # Use patched now_ts to guarantee different timestamps
        with patch.object(broadcast_health, "now_ts", return_value=1000):
            broadcast_health.store_health_snapshot(
                "s1", ingest_bitrate_kbps=1000, ingest_framerate=30,
                dropped_frames=0, dropped_frames_pct=0,
            )
        with patch.object(broadcast_health, "now_ts", return_value=2000):
            broadcast_health.store_health_snapshot(
                "s1", ingest_bitrate_kbps=2000, ingest_framerate=30,
                dropped_frames=0, dropped_frames_pct=0,
            )
        latest = broadcast_health.get_latest_health("s1")
        assert latest is not None
        assert latest["ingest_bitrate_kbps"] == 2000

    def test_returns_none_for_nonexistent(self, mock_ddb):
        assert broadcast_health.get_latest_health("nonexistent") is None


class TestGetHealthHistory:
    def test_returns_snapshots(self, mock_ddb):
        for i in range(10):
            broadcast_health.store_health_snapshot(
                "s1",
                ingest_bitrate_kbps=1000 + i * 100,
                ingest_framerate=30,
                dropped_frames=i,
                dropped_frames_pct=i * 0.1,
            )
        history = broadcast_health.get_health_history("s1", limit=5)
        assert len(history) == 5
