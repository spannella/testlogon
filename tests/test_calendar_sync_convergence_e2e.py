from __future__ import annotations

import json
import unittest
from copy import deepcopy
from pathlib import Path
from unittest.mock import patch

from app.services.calendar_integrations.apple_caldav import AppleCalDavSyncService
from app.services.calendar_integrations.base import CalendarProvider, CalendarProviderConfig
from app.services.calendar_integrations import credentials


class _MemTable:
    def __init__(self) -> None:
        self.items: list[dict] = []

    def put_item(self, *, Item):
        Item = deepcopy(Item)
        for idx, row in enumerate(self.items):
            if all(row.get(k) == v for k, v in Item.items() if k in {"connection_id", "external_calendar_id", "connection_uid_key", "run_id"}):
                self.items[idx] = Item
                return
        self.items.append(Item)

    def get_item(self, *, Key):
        for row in self.items:
            if all(row.get(k) == v for k, v in Key.items()):
                return {"Item": deepcopy(row)}
        return {}

    def delete_item(self, *, Key):
        self.items = [row for row in self.items if not all(row.get(k) == v for k, v in Key.items())]

    def scan(self):
        return {"Items": deepcopy(self.items)}


class _MemSecretAdapter:
    def __init__(self) -> None:
        self.secrets: dict[str, dict] = {}

    def put_secret(self, *, provider: str, secret_payload: dict, credential_ref: str | None = None, tags: dict | None = None):
        ref = credential_ref or f"cred_{len(self.secrets) + 1}"
        self.secrets[ref] = deepcopy(secret_payload)
        return {"credential_ref": ref, "provider": provider, "has_secret": True}

    def get_secret(self, *, credential_ref: str):
        if credential_ref not in self.secrets:
            return None
        return deepcopy(self.secrets[credential_ref])

    def delete_secret(self, *, credential_ref: str):
        self.secrets.pop(credential_ref, None)


class TestCalendarSyncConvergenceE2E(unittest.TestCase):
    def _config(self) -> CalendarProviderConfig:
        return CalendarProviderConfig(
            provider=CalendarProvider.APPLE_CALDAV,
            enabled=True,
            base_url="https://caldav.icloud.com",
            connect_timeout_seconds=5.0,
            read_timeout_seconds=10.0,
            retry_max_attempts=3,
            poll_interval_seconds=300,
            poll_jitter_seconds=30,
            poll_batch_size=50,
        )

    def _with_diagnostics(self, name: str, fn):
        diagnostics: dict[str, object] = {}
        try:
            fn(diagnostics)
        except Exception as exc:  # pragma: no cover - diagnostic path
            path = Path("/tmp") / f"{name}_diagnostics.json"
            path.write_text(json.dumps(diagnostics, indent=2, default=str), encoding="utf-8")
            raise AssertionError(f"{name} failed, diagnostics written to {path}: {exc}") from exc

    def test_connect_import_pull_push_rotate_disconnect_converges(self):
        def _scenario(diag: dict[str, object]):
            connections = _MemTable()
            calendars = _MemTable()
            runs = _MemTable()
            links = _MemTable()
            adapter = _MemSecretAdapter()

            service = AppleCalDavSyncService(config=self._config())
            remote_store = {
                "uid-1": {
                    "remote_uid": "uid-1",
                    "resource_url": "https://caldav.icloud.com/cal/work/uid-1.ics",
                    "etag": "e1",
                    "name": "Design Review",
                    "start_utc": "2026-04-06T14:00:00Z",
                    "end_utc": "2026-04-06T15:00:00Z",
                    "all_day": False,
                    "status": "busy",
                }
            }
            internal_store: dict[str, dict] = {}

            def _upsert_from_remote(*, connection_id: str, calendar_id: str, remote_event: dict, existing_internal_event_id: str | None = None):
                event_id = existing_internal_event_id or f"int-{remote_event['remote_uid']}"
                internal_store[event_id] = {
                    "internal_event_id": event_id,
                    "name": remote_event.get("name"),
                    "remote_uid": remote_event.get("remote_uid"),
                }
                return event_id

            def _caldav_upsert(*, connection_id: str | None = None, calendar_id: str, resource_url: str, ical_payload: str, if_match: str | None):
                uid = "uid-1"
                current = remote_store.get(uid, {})
                next_etag = "e2" if current.get("etag") == "e1" else "e3"
                remote_store[uid] = {**current, "etag": next_etag, "resource_url": resource_url}
                return {"resource_url": resource_url, "etag": next_etag}

            with (
                patch("app.services.calendar_integrations.credentials._connections_table", return_value=connections),
                patch("app.services.calendar_integrations.credentials._external_calendars_table", return_value=calendars),
                patch("app.services.calendar_integrations.credentials._sync_runs_table", return_value=runs),
                patch("app.services.calendar_integrations.credentials._external_event_links_table", return_value=links),
                patch("app.services.calendar_integrations.credentials.get_calendar_secret_adapter", return_value=adapter),
                patch("app.services.calendar_integrations.apple_caldav.assert_apple_caldav_connection_active"),
                patch.object(service, "_upsert_internal_event_from_remote", side_effect=_upsert_from_remote),
                patch.object(service, "_pull_with_ctag_or_window", return_value={
                    "created": [remote_store["uid-1"]],
                    "updated": [],
                    "deleted": [],
                    "next_sync_token": "tok-1",
                    "next_ctag": "ct-1",
                }),
                patch.object(service, "_caldav_upsert_event", side_effect=_caldav_upsert),
                patch("app.services.calendar_integrations.apple_caldav.record_apple_caldav_sync_run_result"),
                patch("app.services.calendar_integrations.apple_caldav.record_apple_conflict_audit"),
            ):
                connected = credentials.upsert_apple_caldav_credential(
                    user_sub="user-1",
                    username="ada@example.com",
                    app_specific_password="app-pass",
                    credential_validation_status="valid",
                )
                diag["connected"] = connected

                calendars.put_item(
                    Item={
                        "external_calendar_id": "apple_caldav#user#user-1#external#work",
                        "connection_id": "apple_caldav#user#user-1",
                        "external_calendar_raw_id": "work",
                        "sync_enabled": True,
                        "sync_direction": "two_way",
                        "timezone": "UTC",
                    }
                )
                runs_out = credentials.enqueue_apple_caldav_initial_import(
                    user_sub="user-1",
                    external_calendar_ids=["work"],
                    lookback_days=30,
                    lookahead_days=30,
                )
                diag["import_runs"] = runs_out

                pull_stats = service.pull_changes(connection_id="apple_caldav#user#user-1", calendar_id="work")
                diag["pull_stats"] = pull_stats

                push_out = service.push_event(
                    connection_id="apple_caldav#user#user-1",
                    calendar_id="work",
                    event={
                        "operation": "update",
                        "internal_event_id": "int-uid-1",
                        "name": "Design Review (Updated)",
                        "start_utc": "2026-04-06T14:00:00Z",
                        "end_utc": "2026-04-06T15:00:00Z",
                        "all_day": False,
                        "status": "busy",
                    },
                )
                diag["push_out"] = push_out

                rotated = credentials.rotate_apple_caldav_credential(
                    user_sub="user-1",
                    username="ada@example.com",
                    app_specific_password="new-app-pass",
                )
                diag["rotated"] = rotated

                disconnected = credentials.disconnect_apple_caldav_credential(user_sub="user-1")
                diag["disconnected"] = disconnected

            self.assertEqual(connected["status"], "connected")
            self.assertEqual(len(runs_out), 1)
            self.assertEqual(pull_stats, {"created": 1, "updated": 0, "deleted": 0})
            self.assertEqual(push_out["status"], "ok")
            self.assertEqual(remote_store["uid-1"]["etag"], "e2")
            self.assertEqual(rotated["credential_validation_status"], "pending")
            self.assertEqual(disconnected["status"], "disconnected")

        self._with_diagnostics("cal_030_connect_import_pull_push_rotate_disconnect", _scenario)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
