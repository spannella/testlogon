from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch
from fastapi import HTTPException

from app.services import google_calendar_client as client
from app.services import google_calendar_sync_incremental as incremental

FIXTURES = Path(__file__).parent / "fixtures" / "google_calendar"


def _load_fixture(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


def test_integration_token_expiry_refresh_fixture_flow():
    fixture = _load_fixture("token_expiry_case.json")
    ok = Mock(status_code=200)
    ok.content = b'{"items": []}'
    ok.json.return_value = {"items": []}

    with (
        patch.object(client, "get_calendar_provider_connection", return_value=fixture["connection"]),
        patch.object(client, "refresh_google_calendar_access_token", return_value=fixture["refresh_result"]) as refresh,
        patch.object(client.requests, "request", return_value=ok),
        patch.object(client, "update_calendar_provider_connection_sync_status"),
        patch.object(client, "S", SimpleNamespace(google_calendar_api_base_url="https://www.googleapis.com/calendar/v3", google_calendar_api_timeout_seconds=20)),
    ):
        out = client.list_google_calendars(user_sub="user-1", connection_id="google-primary")

    refresh.assert_called_once()
    assert out["items"] == []


def test_integration_incremental_sync_token_invalidation_fixture_flow():
    fixture = _load_fixture("sync_token_invalidation_case.json")
    err = fixture["incremental_error"]
    invalid_exc = HTTPException(status_code=err["status_code"], detail=err["detail"])

    with (
        patch.object(incremental, "get_calendar_provider_connection", return_value={"sync_cursor": json.dumps({"gcal-1": "stale-token"})}),
        patch.object(incremental, "list_calendar_provider_mappings", return_value=[fixture["calendar_mapping"]]),
        patch.object(incremental, "list_google_calendar_events", side_effect=[invalid_exc, {"items": [], "nextSyncToken": "fresh-token"}]),
        patch.object(incremental, "run_google_calendar_full_import_job", return_value={"calendars_processed": 1}) as full_import,
        patch.object(incremental, "update_calendar_provider_connection_sync_status"),
    ):
        metrics = incremental.run_google_calendar_incremental_sync_job(user_sub="user-1", connection_id="google-primary")

    assert metrics["fallback_full_syncs"] == 1
    full_import.assert_called_once()
