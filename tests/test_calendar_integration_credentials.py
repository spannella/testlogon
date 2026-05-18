from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch

from app.services.calendar_integrations import credentials


class TestCalendarIntegrationCredentials(unittest.TestCase):
    def test_upsert_persists_reference_only_in_connections_table(self):
        connections = MagicMock()
        connections.get_item.return_value = {}

        adapter = MagicMock()
        adapter.put_secret.return_value = {
            "credential_ref": "cred_fixed",
            "version": 1,
            "created_at": "2026-01-01T00:00:00+00:00",
            "updated_at": "2026-01-01T00:00:00+00:00",
        }

        with (
            patch.object(credentials, "_connections_table", return_value=connections),
            patch.object(credentials, "get_calendar_secret_adapter", return_value=adapter),
        ):
            out = credentials.upsert_apple_caldav_credential(
                user_sub="user-1",
                username="user@example.com",
                app_specific_password="app-pass",
                credential_validation_status="valid",
            )

        adapter.put_secret.assert_called_once()
        put_call = adapter.put_secret.call_args.kwargs
        self.assertEqual(put_call["provider"], "apple_caldav")
        self.assertEqual(put_call["credential_ref"], None)
        self.assertEqual(put_call["tags"]["provider"], "apple_caldav")

        connections_item = connections.put_item.call_args.kwargs["Item"]
        self.assertEqual(connections_item["credential_ref"], "cred_fixed")
        self.assertNotIn("secret_ct_b64", connections_item)
        self.assertNotIn("credential_ct_b64", connections_item)
        self.assertNotIn("app_specific_password", connections_item)

        self.assertEqual(out["credential_validation_status"], "valid")
        self.assertTrue(out["has_secret"])
        self.assertNotIn("app_specific_password", out)

    def test_upsert_existing_connection_reuses_stable_reference(self):
        connections = MagicMock()
        connections.get_item.return_value = {
            "Item": {
                "created_at": "2026-01-01T00:00:00+00:00",
                "credential_last_validated_at": "2026-01-03T00:00:00+00:00",
                "credential_ref": "cred_existing",
            }
        }

        adapter = MagicMock()
        adapter.put_secret.return_value = {
            "credential_ref": "cred_existing",
            "version": 2,
            "created_at": "2026-01-01T00:00:00+00:00",
            "updated_at": "2026-01-02T00:00:00+00:00",
        }

        with (
            patch.object(credentials, "_connections_table", return_value=connections),
            patch.object(credentials, "get_calendar_secret_adapter", return_value=adapter),
        ):
            out = credentials.upsert_apple_caldav_credential(
                user_sub="user-1",
                username="user@example.com",
                app_specific_password="new-pass",
            )

        self.assertEqual(adapter.put_secret.call_args.kwargs["credential_ref"], "cred_existing")
        self.assertEqual(out["credential_ref"], "cred_existing")
        self.assertIsNotNone(out["credential_rotated_at"])

    def test_get_connection_with_secret_loads_from_adapter(self):
        connections = MagicMock()
        connections.get_item.return_value = {
            "Item": {
                "connection_id": "apple_caldav#user#user-1",
                "entity_type": "calendar_connection",
                "provider": "apple_caldav",
                "user_sub": "user-1",
                "status": "connected",
                "credential_ref": "cred_123",
                "credential_validation_status": "valid",
                "credential_last_validated_at": "2026-03-24T00:00:00+00:00",
                "credential_rotated_at": None,
                "created_at": "2026-03-24T00:00:00+00:00",
                "updated_at": "2026-03-24T00:00:00+00:00",
            }
        }

        adapter = MagicMock()
        adapter.get_secret.return_value = {
            "credential_ref": "cred_123",
            "secret_payload": {
                "username": "user@example.com",
                "app_specific_password": "app-pass",
            },
        }

        with (
            patch.object(credentials, "_connections_table", return_value=connections),
            patch.object(credentials, "get_calendar_secret_adapter", return_value=adapter),
        ):
            out = credentials.get_apple_caldav_connection(user_sub="user-1", include_secret=True)

        self.assertEqual(out["username"], "user@example.com")
        self.assertEqual(out["app_specific_password"], "app-pass")

    def test_get_connection_by_connection_id_with_secret(self):
        connections = MagicMock()
        connections.get_item.return_value = {
            "Item": {
                "connection_id": "apple_caldav#user#user-1",
                "entity_type": "calendar_connection",
                "provider": "apple_caldav",
                "user_sub": "user-1",
                "status": "connected",
                "credential_ref": "cred_123",
                "credential_validation_status": "valid",
                "created_at": "2026-03-24T00:00:00+00:00",
                "updated_at": "2026-03-24T00:00:00+00:00",
            }
        }
        adapter = MagicMock()
        adapter.get_secret.return_value = {
            "credential_ref": "cred_123",
            "secret_payload": {
                "username": "user@example.com",
                "app_specific_password": "app-pass",
            },
        }
        with (
            patch.object(credentials, "_connections_table", return_value=connections),
            patch.object(credentials, "get_calendar_secret_adapter", return_value=adapter),
        ):
            out = credentials.get_apple_caldav_connection_by_connection_id(
                connection_id="apple_caldav#user#user-1",
                include_secret=True,
            )
        self.assertEqual(out["connection_id"], "apple_caldav#user#user-1")
        self.assertEqual(out["username"], "user@example.com")

    def test_delete_connection_also_deletes_secret_reference(self):
        connections = MagicMock()
        connections.get_item.return_value = {
            "Item": {
                "connection_id": "apple_caldav#user#user-1",
                "credential_ref": "cred_123",
            }
        }
        adapter = MagicMock()

        with (
            patch.object(credentials, "_connections_table", return_value=connections),
            patch.object(credentials, "get_calendar_secret_adapter", return_value=adapter),
        ):
            out = credentials.delete_apple_caldav_credential(user_sub="user-1")

        self.assertEqual(out, {"deleted": True})
        adapter.delete_secret.assert_called_once_with(credential_ref="cred_123")
        connections.delete_item.assert_called_once_with(Key={"connection_id": "apple_caldav#user#user-1"})

    def test_upsert_requires_non_empty_fields(self):
        with self.assertRaises(ValueError):
            credentials.upsert_apple_caldav_credential(
                user_sub="",
                username="",
                app_specific_password="",
            )

    def test_status_returns_disconnected_when_connection_missing(self):
        connections = MagicMock()
        connections.get_item.return_value = {}
        calendars = MagicMock()
        calendars.scan.return_value = {"Items": []}
        runs = MagicMock()
        runs.scan.return_value = {"Items": []}

        with (
            patch.object(credentials, "_connections_table", return_value=connections),
            patch.object(credentials, "_external_calendars_table", return_value=calendars),
            patch.object(credentials, "_sync_runs_table", return_value=runs),
        ):
            out = credentials.get_apple_caldav_status(user_sub="user-1")

        self.assertEqual(out["connection_state"], "disconnected")
        self.assertFalse(out["is_connected"])
        self.assertEqual(out["selected_calendar_count"], 0)
        self.assertEqual(out["conflict_count"], 0)
        self.assertEqual(out["recent_conflicts"], [])

    def test_status_returns_connected_with_last_success_and_calendar_count(self):
        connections = MagicMock()
        connections.get_item.return_value = {
            "Item": {
                "connection_id": "apple_caldav#user#user-1",
                "status": "connected",
                "credential_validation_status": "valid",
                "updated_at": "2026-04-05T00:00:00+00:00",
            }
        }
        calendars = MagicMock()
        calendars.scan.return_value = {
            "Items": [
                {"connection_id": "apple_caldav#user#user-1"},
                {"connection_id": "apple_caldav#user#user-1"},
                {"connection_id": "apple_caldav#user#other"},
            ]
        }
        runs = MagicMock()
        runs.scan.return_value = {
            "Items": [
                {
                    "connection_id": "apple_caldav#user#user-1",
                    "status": "success",
                    "started_at": "2026-04-05T10:00:00+00:00",
                    "finished_at": "2026-04-05T10:01:00+00:00",
                }
            ]
        }

        with (
            patch.object(credentials, "_connections_table", return_value=connections),
            patch.object(credentials, "_external_calendars_table", return_value=calendars),
            patch.object(credentials, "_sync_runs_table", return_value=runs),
        ):
            out = credentials.get_apple_caldav_status(user_sub="user-1")

        self.assertEqual(out["connection_state"], "connected")
        self.assertTrue(out["is_connected"])
        self.assertEqual(out["selected_calendar_count"], 2)
        self.assertEqual(out["last_successful_sync_at"], "2026-04-05T10:01:00+00:00")
        self.assertEqual(out["conflict_count"], 0)

    def test_disconnect_marks_connection_disconnected_and_removes_secret_ref(self):
        connections = MagicMock()
        connections.get_item.return_value = {
            "Item": {
                "connection_id": "apple_caldav#user#user-1",
                "entity_type": "calendar_connection",
                "provider": "apple_caldav",
                "user_sub": "user-1",
                "status": "connected",
                "credential_ref": "cred_123",
                "credential_validation_status": "valid",
                "created_at": "2026-04-05T00:00:00+00:00",
                "updated_at": "2026-04-05T00:00:00+00:00",
            }
        }
        adapter = MagicMock()

        with (
            patch.object(credentials, "_connections_table", return_value=connections),
            patch.object(credentials, "get_calendar_secret_adapter", return_value=adapter),
        ):
            out = credentials.disconnect_apple_caldav_credential(user_sub="user-1")

        adapter.delete_secret.assert_called_once_with(credential_ref="cred_123")
        stored = connections.put_item.call_args.kwargs["Item"]
        self.assertEqual(stored["status"], "disconnected")
        self.assertEqual(stored["credential_ref"], "")
        self.assertEqual(stored["credential_validation_status"], "disconnected")
        self.assertFalse(out["has_secret"])

    def test_assert_connection_active_rejects_disconnected_connection(self):
        connections = MagicMock()
        connections.get_item.return_value = {
            "Item": {
                "connection_id": "apple_caldav#user#user-1",
                "status": "disconnected",
                "credential_ref": "",
            }
        }
        with patch.object(credentials, "_connections_table", return_value=connections):
            with self.assertRaises(ValueError):
                credentials.assert_apple_caldav_connection_active(connection_id="apple_caldav#user#user-1")

    def test_select_and_list_calendars_is_idempotent(self):
        external_table = MagicMock()
        # no existing rows first lookup, then existing rows for second call
        external_table.get_item.return_value = {}
        external_table.scan.return_value = {"Items": []}

        with (
            patch.object(credentials, "get_apple_caldav_connection", return_value={"connection_id": "apple_caldav#user#user-1"}),
            patch.object(credentials, "_external_calendars_table", return_value=external_table),
            patch.object(credentials, "list_apple_caldav_calendars") as list_calendars,
        ):
            list_calendars.return_value = [
                {
                    "external_calendar_id": "work",
                    "calendar_url": "https://caldav.icloud.com/cal/work/",
                    "display_name": "Work",
                    "sync_enabled": True,
                    "sync_direction": "two_way",
                    "timezone": "UTC",
                }
            ]
            first = credentials.select_apple_caldav_calendars(
                user_sub="user-1",
                calendars=[{"external_calendar_id": "work", "sync_enabled": True, "sync_direction": "two_way", "timezone": "UTC"}],
            )
            second = credentials.select_apple_caldav_calendars(
                user_sub="user-1",
                calendars=[{"external_calendar_id": "work", "sync_enabled": True, "sync_direction": "two_way", "timezone": "UTC"}],
            )

        self.assertEqual(first, second)
        self.assertEqual(external_table.put_item.call_count, 2)

    def test_list_calendars_merges_discovery_with_saved_selection(self):
        external_table = MagicMock()
        external_table.scan.return_value = {
            "Items": [
                {
                    "connection_id": "apple_caldav#user#user-1",
                    "external_calendar_raw_id": "work",
                    "sync_enabled": True,
                    "sync_direction": "two_way",
                    "timezone": "UTC",
                }
            ]
        }
        provider = MagicMock()
        provider.connection.discover_calendars.return_value = [
            {"calendar_id": "work", "calendar_url": "https://caldav.icloud.com/cal/work/", "display_name": "Work"},
            {"calendar_id": "home", "calendar_url": "https://caldav.icloud.com/cal/home/", "display_name": "Home"},
        ]

        with (
            patch.object(
                credentials,
                "get_apple_caldav_connection",
                return_value={
                    "connection_id": "apple_caldav#user#user-1",
                    "username": "user@example.com",
                    "app_specific_password": "app-pass",
                },
            ),
            patch.object(credentials, "_external_calendars_table", return_value=external_table),
            patch("app.services.calendar_integrations.registry.get_provider_services", return_value=provider),
        ):
            out = credentials.list_apple_caldav_calendars(user_sub="user-1")

        work = next(x for x in out if x["external_calendar_id"] == "work")
        home = next(x for x in out if x["external_calendar_id"] == "home")
        self.assertTrue(work["sync_enabled"])
        self.assertEqual(work["sync_direction"], "two_way")
        self.assertFalse(home["sync_enabled"])

    def test_enqueue_initial_import_creates_one_run_per_enabled_calendar(self):
        external_table = MagicMock()
        external_table.scan.return_value = {
            "Items": [
                {"connection_id": "apple_caldav#user#user-1", "external_calendar_raw_id": "work", "sync_enabled": True},
                {"connection_id": "apple_caldav#user#user-1", "external_calendar_raw_id": "home", "sync_enabled": True},
                {"connection_id": "apple_caldav#user#user-1", "external_calendar_raw_id": "ignored", "sync_enabled": False},
            ]
        }
        runs_table = MagicMock()

        with (
            patch.object(credentials, "get_apple_caldav_connection", return_value={"connection_id": "apple_caldav#user#user-1"}),
            patch.object(credentials, "_external_calendars_table", return_value=external_table),
            patch.object(credentials, "_sync_runs_table", return_value=runs_table),
        ):
            runs = credentials.enqueue_apple_caldav_initial_import(
                user_sub="user-1",
                lookback_days=180,
                lookahead_days=14,
            )

        self.assertEqual(len(runs), 2)
        self.assertEqual(runs_table.put_item.call_count, 2)
        self.assertTrue(all(run["run_type"] == "initial_import" for run in runs))
        self.assertTrue(all(run["status"] == "queued" for run in runs))
        self.assertEqual(sorted([run["external_calendar_id"] for run in runs]), ["home", "work"])

    def test_reimport_does_not_duplicate_external_event_links(self):
        store: dict[str, dict] = {}
        links_table = MagicMock()

        def _get_item(*, Key):
            key = Key["connection_uid_key"]
            item = store.get(key)
            return {"Item": item} if item else {}

        def _put_item(*, Item):
            store[Item["connection_uid_key"]] = dict(Item)
            return {}

        links_table.get_item.side_effect = _get_item
        links_table.put_item.side_effect = _put_item

        imported = [
            {"remote_uid": "uid-1", "internal_event_id": "evt-1"},
            {"remote_uid": "uid-2", "internal_event_id": "evt-2"},
        ]
        with patch.object(credentials, "_external_event_links_table", return_value=links_table):
            first = credentials.register_apple_caldav_imported_links(
                run_id="run-1",
                connection_id="apple_caldav#user#user-1",
                external_calendar_id="work",
                imported_events=imported,
            )
            second = credentials.register_apple_caldav_imported_links(
                run_id="run-2",
                connection_id="apple_caldav#user#user-1",
                external_calendar_id="work",
                imported_events=imported,
            )

        self.assertEqual(first, {"created": 2, "updated": 0})
        self.assertEqual(second, {"created": 0, "updated": 2})
        self.assertEqual(len(store), 2)

    def test_successful_sync_run_persists_sync_token_and_ctag(self):
        runs_table = MagicMock()
        runs_table.get_item.return_value = {}
        external_table = MagicMock()
        external_table.get_item.return_value = {
            "Item": {
                "external_calendar_id": "apple_caldav#user#user-1#calendar#work",
                "connection_id": "apple_caldav#user#user-1",
                "external_calendar_raw_id": "work",
                "sync_enabled": True,
                "sync_direction": "two_way",
                "created_at": "2026-01-01T00:00:00+00:00",
            }
        }

        with (
            patch.object(credentials, "_sync_runs_table", return_value=runs_table),
            patch.object(credentials, "_external_calendars_table", return_value=external_table),
        ):
            credentials.record_apple_caldav_sync_run_result(
                run_id="run-1",
                connection_id="apple_caldav#user#user-1",
                external_calendar_id="work",
                status="success",
                sync_token="token-v1",
                ctag="ctag-v1",
                started_at="2026-04-05T00:00:00+00:00",
                finished_at="2026-04-05T00:01:00+00:00",
            )

        run_item = runs_table.put_item.call_args.kwargs["Item"]
        self.assertEqual(run_item["status"], "success")
        self.assertEqual(run_item["status_key"], "STATUS#success")
        calendar_item = external_table.put_item.call_args.kwargs["Item"]
        self.assertEqual(calendar_item["sync_token"], "token-v1")
        self.assertEqual(calendar_item["ctag"], "ctag-v1")
        self.assertEqual(calendar_item["last_synced_at"], "2026-04-05T00:01:00+00:00")

    def test_get_calendar_sync_state_includes_calendar_url(self):
        external_table = MagicMock()
        external_table.get_item.return_value = {
            "Item": {
                "external_calendar_id": "apple_caldav#user#user-1#calendar#work",
                "connection_id": "apple_caldav#user#user-1",
                "external_calendar_raw_id": "work",
                "calendar_url": "https://caldav.icloud.com/custom/work/",
                "sync_token": "tok-1",
                "ctag": "ct-1",
                "last_synced_at": "2026-04-05T00:01:00+00:00",
            }
        }
        with patch.object(credentials, "_external_calendars_table", return_value=external_table):
            out = credentials.get_apple_caldav_calendar_sync_state(
                connection_id="apple_caldav#user#user-1",
                external_calendar_id="work",
            )
        self.assertEqual(out["calendar_url"], "https://caldav.icloud.com/custom/work/")

    def test_event_link_upsert_updates_latest_etag_without_duplicate_keys(self):
        store: dict[str, dict] = {
            "apple_caldav#user#user-1#calendar#work#uid#uid-1": {
                "connection_uid_key": "apple_caldav#user#user-1#calendar#work#uid#uid-1",
                "etag": "old-etag",
                "resource_url": "https://caldav.example/work/uid-1.ics",
                "created_at": "2026-04-05T00:00:00+00:00",
            }
        }
        links_table = MagicMock()

        def _get_item(*, Key):
            item = store.get(Key["connection_uid_key"])
            return {"Item": item} if item else {}

        def _put_item(*, Item):
            store[Item["connection_uid_key"]] = dict(Item)
            return {}

        links_table.get_item.side_effect = _get_item
        links_table.put_item.side_effect = _put_item

        with patch.object(credentials, "_external_event_links_table", return_value=links_table):
            credentials.upsert_apple_caldav_event_link(
                connection_id="apple_caldav#user#user-1",
                external_calendar_id="work",
                remote_uid="uid-1",
                internal_event_id="evt-1",
                run_id="run-2",
                etag="new-etag",
                resource_url=None,
            )

        self.assertEqual(len(store), 1)
        row = store["apple_caldav#user#user-1#calendar#work#uid#uid-1"]
        self.assertEqual(row["etag"], "new-etag")
        self.assertEqual(row["resource_url"], "https://caldav.example/work/uid-1.ics")
        self.assertEqual(
            row["connection_internal_event_key"],
            "apple_caldav#user#user-1#calendar#work#event#evt-1",
        )

    def test_get_event_link_by_internal_event_uses_direct_key_lookup(self):
        links_table = MagicMock()
        links_table.get_item.side_effect = [
            {
                "Item": {
                    "connection_uid_key": "apple_caldav#user#user-1#calendar#work#event#evt-1",
                    "connection_id": "apple_caldav#user#user-1",
                    "external_calendar_id": "work",
                    "internal_event_id": "evt-1",
                }
            }
        ]
        with patch.object(credentials, "_external_event_links_table", return_value=links_table):
            out = credentials.get_apple_caldav_event_link_by_internal_event(
                connection_id="apple_caldav#user#user-1",
                external_calendar_id="work",
                internal_event_id="evt-1",
            )
        self.assertEqual(out["internal_event_id"], "evt-1")
        links_table.scan.assert_not_called()

    def test_get_event_link_by_internal_event_falls_back_to_scan_for_legacy_rows(self):
        links_table = MagicMock()
        links_table.get_item.return_value = {}
        links_table.scan.return_value = {
            "Items": [
                {
                    "connection_uid_key": "apple_caldav#user#user-1#calendar#work#uid#uid-1",
                    "connection_id": "apple_caldav#user#user-1",
                    "external_calendar_id": "work",
                    "internal_event_id": "evt-1",
                }
            ]
        }
        with patch.object(credentials, "_external_event_links_table", return_value=links_table):
            out = credentials.get_apple_caldav_event_link_by_internal_event(
                connection_id="apple_caldav#user#user-1",
                external_calendar_id="work",
                internal_event_id="evt-1",
            )
        self.assertEqual(out["connection_uid_key"], "apple_caldav#user#user-1#calendar#work#uid#uid-1")
        links_table.scan.assert_called_once()

    def test_get_event_link_by_resource_url_returns_matching_row(self):
        links_table = MagicMock()
        links_table.scan.return_value = {
            "Items": [
                {
                    "connection_id": "apple_caldav#user#user-1",
                    "external_calendar_id": "work",
                    "resource_url": "https://caldav.icloud.com/cal/work/evt-1.ics",
                    "remote_uid": "uid-1",
                }
            ]
        }
        with patch.object(credentials, "_external_event_links_table", return_value=links_table):
            out = credentials.get_apple_caldav_event_link_by_resource_url(
                connection_id="apple_caldav#user#user-1",
                external_calendar_id="work",
                resource_url="https://caldav.icloud.com/cal/work/evt-1.ics",
            )
        self.assertIsNotNone(out)
        self.assertEqual(out["remote_uid"], "uid-1")

    def test_should_run_pull_respects_poll_interval(self):
        runs_table = MagicMock()
        runs_table.scan.return_value = {
            "Items": [
                {
                    "connection_id": "apple_caldav#user#user-1",
                    "run_type": "incremental_pull",
                    "started_at": "2026-04-05T11:58:00+00:00",
                }
            ]
        }
        now = credentials.datetime(2026, 4, 5, 12, 0, 0, tzinfo=credentials.timezone.utc)
        with patch.object(credentials, "_sync_runs_table", return_value=runs_table):
            should_skip = credentials.should_run_apple_caldav_pull(
                connection_id="apple_caldav#user#user-1",
                poll_interval_seconds=300,
                now=now,
            )
            should_run = credentials.should_run_apple_caldav_pull(
                connection_id="apple_caldav#user#user-1",
                poll_interval_seconds=60,
                now=now,
            )

        self.assertFalse(should_skip)
        self.assertTrue(should_run)

    def test_status_surfaces_dead_letter_snapshot_for_support(self):
        connections = MagicMock()
        connections.get_item.return_value = {
            "Item": {
                "connection_id": "apple_caldav#user#user-1",
                "status": "connected",
                "credential_validation_status": "valid",
                "updated_at": "2026-04-05T00:00:00+00:00",
            }
        }
        calendars = MagicMock()
        calendars.scan.return_value = {"Items": []}
        runs = MagicMock()
        runs.scan.return_value = {"Items": []}

        with (
            patch.object(credentials, "_connections_table", return_value=connections),
            patch.object(credentials, "_external_calendars_table", return_value=calendars),
            patch.object(credentials, "_sync_runs_table", return_value=runs),
            patch.object(
                credentials,
                "list_apple_push_dead_letters",
                return_value=[{"outbox_id": "o-dead", "operation": "update", "last_error": "etag_mismatch", "updated_at": "2026-04-05T00:02:00+00:00"}],
            ),
        ):
            out = credentials.get_apple_caldav_status(user_sub="user-1")

        self.assertEqual(out["last_error_snapshot"]["status"], "dead_letter")
        self.assertEqual(out["last_error_snapshot"]["outbox_id"], "o-dead")

    def test_trigger_sync_now_returns_success_and_failure_counts(self):
        provider = MagicMock()
        provider.sync.pull_changes.side_effect = [
            {"created": 1, "updated": 0, "deleted": 0},
            RuntimeError("boom"),
        ]
        with (
            patch.object(credentials, "get_apple_caldav_connection", return_value={"connection_id": "apple_caldav#user#user-1"}),
            patch.object(credentials, "list_enabled_apple_caldav_external_calendar_ids", return_value=["work", "home"]),
            patch("app.services.calendar_integrations.registry.get_provider_services", return_value=provider),
        ):
            out = credentials.trigger_apple_caldav_sync_now(user_sub="user-1")

        self.assertEqual(out["triggered_calendar_count"], 2)
        self.assertEqual(out["success_count"], 1)
        self.assertEqual(out["failure_count"], 1)

    def test_status_includes_user_friendly_conflict_messages(self):
        connections = MagicMock()
        connections.get_item.return_value = {
            "Item": {
                "connection_id": "apple_caldav#user#user-1",
                "status": "connected",
                "credential_validation_status": "valid",
                "updated_at": "2026-04-05T00:00:00+00:00",
            }
        }
        calendars = MagicMock()
        calendars.scan.return_value = {"Items": []}
        runs = MagicMock()
        runs.scan.return_value = {"Items": []}
        with (
            patch.object(credentials, "_connections_table", return_value=connections),
            patch.object(credentials, "_external_calendars_table", return_value=calendars),
            patch.object(credentials, "_sync_runs_table", return_value=runs),
            patch.object(
                credentials,
                "list_apple_conflict_audits",
                return_value=[
                    {
                        "audit_id": "conflict_1",
                        "internal_event_id": "evt_123",
                        "external_calendar_id": "work",
                        "resolution": "remote_wins_etag_conflict",
                        "details": {"operation": "update"},
                        "updated_at": "2026-04-05T12:00:00+00:00",
                    }
                ],
            ),
        ):
            out = credentials.get_apple_caldav_status(user_sub="user-1")

        self.assertEqual(out["conflict_count"], 1)
        self.assertEqual(out["recent_conflicts"][0]["event_ref"], "evt_123")
        self.assertIn("kept the version from Apple Calendar", out["recent_conflicts"][0]["message"])

    def test_admin_troubleshooting_bundle_includes_runs_errors_and_recommendations(self):
        with (
            patch.object(credentials, "get_apple_caldav_connection", return_value={"connection_id": "apple_caldav#user#user-1", "status": "connected"}),
            patch.object(credentials, "get_apple_caldav_status", return_value={"connection_state": "degraded", "last_error_snapshot": {"error": "auth failed"}}),
            patch.object(
                credentials,
                "_external_calendars_table",
                return_value=MagicMock(
                    scan=MagicMock(
                        return_value={
                            "Items": [
                                {"connection_id": "apple_caldav#user#user-1", "external_calendar_raw_id": "work", "sync_enabled": True},
                            ]
                        }
                    )
                ),
            ),
            patch.object(credentials, "list_apple_sync_runs", return_value=[{"run_id": "run_1", "status": "failed"}]),
            patch.object(credentials, "list_apple_push_dead_letters", return_value=[{"outbox_id": "o-1", "last_error": "etag_mismatch"}]),
            patch.object(credentials, "list_apple_conflict_audits", return_value=[{"audit_id": "c-1"}]),
        ):
            out = credentials.admin_get_apple_caldav_troubleshooting_bundle(user_sub="user-1", limit=20)

        self.assertEqual(out["user_sub"], "user-1")
        self.assertEqual(out["status"]["connection_state"], "degraded")
        self.assertEqual(len(out["run_history"]), 1)
        self.assertEqual(len(out["dead_letters"]), 1)
        self.assertTrue(out["recommendations"])

    def test_admin_safe_relink_updates_event_link(self):
        with (
            patch.object(credentials, "get_apple_caldav_connection", return_value={"connection_id": "apple_caldav#user#user-1"}),
            patch.object(
                credentials,
                "upsert_apple_caldav_event_link",
                return_value=(
                    {
                        "connection_id": "apple_caldav#user#user-1",
                        "external_calendar_id": "work",
                        "remote_uid": "uid-1",
                        "internal_event_id": "evt-1",
                    },
                    True,
                ),
            ),
        ):
            out = credentials.admin_safe_relink_apple_event(
                user_sub="user-1",
                external_calendar_id="work",
                remote_uid="uid-1",
                internal_event_id="evt-1",
            )

        self.assertTrue(out["updated_existing"])
        self.assertEqual(out["link"]["internal_event_id"], "evt-1")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
