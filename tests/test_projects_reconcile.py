from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from fastapi import HTTPException

from app.services import projects_reconcile


class TestProjectsReconcile(unittest.TestCase):
    def _tracked_item(self, *, status: str = "active", owner: str = "user-1", tracked_id: str = "tf-1"):
        return {
            "entity_type": "tracked_file",
            "id": tracked_id,
            "project_id": "p1",
            "owner": owner,
            "provider": "local",
            "provider_ref": "/docs/a.txt",
            "display_path": "/docs/a.txt",
            "status": status,
            "metadata": {"saved": 1},
            "created_at": "2026-01-01T00:00:00+00:00",
            "updated_at": "2026-01-01T00:00:00+00:00",
            "last_seen_at": "2026-01-01T00:00:00+00:00",
            "archived_at": None,
        }

    def _project_item(self, *, owner: str = "user-1", project_id: str = "p1"):
        return {
            "entity_type": "project",
            "id": project_id,
            "owner": owner,
            "name": "Alpha",
            "description": None,
            "tags": [],
            "settings": {},
            "created_at": "2026-01-01T00:00:00+00:00",
            "updated_at": "2026-01-01T00:00:00+00:00",
        }

    def test_reconcile_marks_missing_when_provider_target_absent(self):
        table = MagicMock()
        table.scan.return_value = {"Items": [self._tracked_item(status="active")], "LastEvaluatedKey": None}
        table.get_item.return_value = {"Item": self._project_item()}

        provider = MagicMock()
        provider.resolve.return_value = "/docs/a.txt"
        provider.exists.return_value = False
        registry = MagicMock()
        registry.get.return_value = provider

        with (
            patch.object(projects_reconcile, "T", SimpleNamespace(projects=table)),
            patch.object(projects_reconcile, "now_iso", return_value="2026-01-02T00:00:00+00:00"),
            patch.object(projects_reconcile, "emit_project_event") as emit_project_event,
            patch.object(projects_reconcile, "record_provider_latency") as record_provider_latency,
            patch.object(projects_reconcile, "record_provider_failure_streak") as record_provider_failure_streak,
        ):
            out = projects_reconcile.reconcile_tracked_files_batch(registry=registry, sleep_fn=lambda _: None)

        self.assertEqual(out["checked"], 1)
        self.assertEqual(out["missing"], 1)
        self.assertEqual(out["errors"], 0)
        put_item = table.put_item.call_args.kwargs["Item"]
        self.assertEqual(put_item["status"], "missing")
        self.assertEqual(put_item["last_seen_at"], "2026-01-01T00:00:00+00:00")
        emit_project_event.assert_called_once()
        self.assertEqual(emit_project_event.call_args.args[2], "sync_ran")
        record_provider_latency.assert_called_once()
        record_provider_failure_streak.assert_called_with("local", 0)

    def test_reconcile_marks_active_and_refreshes_metadata_when_present(self):
        table = MagicMock()
        table.scan.return_value = {"Items": [self._tracked_item(status="missing")], "LastEvaluatedKey": None}
        table.get_item.return_value = {"Item": self._project_item()}

        provider = MagicMock()
        provider.resolve.return_value = "/docs/a.txt"
        provider.exists.return_value = True
        provider.get_metadata.return_value = {"size": 42}
        registry = MagicMock()
        registry.get.return_value = provider

        with (
            patch.object(projects_reconcile, "T", SimpleNamespace(projects=table)),
            patch.object(projects_reconcile, "now_iso", return_value="2026-01-03T00:00:00+00:00"),
            patch.object(projects_reconcile, "emit_project_event") as emit_project_event,
            patch.object(projects_reconcile, "record_provider_latency") as record_provider_latency,
            patch.object(projects_reconcile, "record_provider_failure_streak") as record_provider_failure_streak,
        ):
            out = projects_reconcile.reconcile_tracked_files_batch(registry=registry, sleep_fn=lambda _: None)

        self.assertEqual(out["updated"], 1)
        put_item = table.put_item.call_args.kwargs["Item"]
        self.assertEqual(put_item["status"], "active")
        self.assertEqual(put_item["last_seen_at"], "2026-01-03T00:00:00+00:00")
        self.assertEqual(put_item["metadata"]["saved"], 1)
        self.assertEqual(put_item["metadata"]["size"], 42)
        emit_project_event.assert_called_once()
        self.assertEqual(emit_project_event.call_args.args[2], "sync_ran")
        record_provider_latency.assert_called_once()
        record_provider_failure_streak.assert_called_with("local", 0)

    def test_reconcile_retries_transient_provider_error_with_backoff(self):
        table = MagicMock()
        table.scan.return_value = {"Items": [self._tracked_item(status="active")], "LastEvaluatedKey": None}
        table.get_item.return_value = {"Item": self._project_item()}

        provider = MagicMock()
        provider.resolve.return_value = "/docs/a.txt"
        provider.exists.side_effect = [HTTPException(status_code=503, detail="busy"), True]
        provider.get_metadata.return_value = {"size": 9}
        registry = MagicMock()
        registry.get.return_value = provider

        sleeps: list[float] = []

        with (
            patch.object(projects_reconcile, "T", SimpleNamespace(projects=table)),
            patch.object(projects_reconcile, "now_iso", return_value="2026-01-03T00:00:00+00:00"),
            patch.object(projects_reconcile, "emit_project_event") as emit_project_event,
            patch.object(projects_reconcile, "record_provider_latency") as record_provider_latency,
            patch.object(projects_reconcile, "record_provider_failure_streak") as record_provider_failure_streak,
        ):
            out = projects_reconcile.reconcile_tracked_files_batch(
                registry=registry,
                sleep_fn=lambda value: sleeps.append(value),
                max_attempts=2,
                base_backoff_seconds=0.1,
            )

        self.assertEqual(out["errors"], 0)
        self.assertEqual(out["updated"], 1)
        self.assertEqual(sleeps, [0.1])
        emit_project_event.assert_called_once()
        self.assertEqual(emit_project_event.call_args.args[2], "sync_ran")
        record_provider_latency.assert_called_once()
        record_provider_failure_streak.assert_called_with("local", 0)

    def test_reconcile_continues_across_projects_when_one_errors(self):
        table = MagicMock()
        table.scan.return_value = {
            "Items": [
                self._tracked_item(tracked_id="tf-1", owner="user-1"),
                self._tracked_item(tracked_id="tf-2", owner="user-2"),
            ],
            "LastEvaluatedKey": None,
        }
        table.get_item.side_effect = [
            {"Item": self._project_item(owner="user-1")},
            {"Item": self._project_item(owner="user-2")},
        ]

        provider_ok = MagicMock()
        provider_ok.resolve.return_value = "/docs/a.txt"
        provider_ok.exists.return_value = True
        provider_ok.get_metadata.return_value = {"size": 11}

        provider_error = MagicMock()
        provider_error.resolve.return_value = "/docs/a.txt"
        provider_error.exists.side_effect = RuntimeError("boom")

        registry = MagicMock()
        registry.get.side_effect = [provider_ok, provider_error]

        with (
            patch.object(projects_reconcile, "T", SimpleNamespace(projects=table)),
            patch.object(projects_reconcile, "now_iso", return_value="2026-01-03T00:00:00+00:00"),
            patch.object(projects_reconcile, "emit_project_event") as emit_project_event,
            patch.object(projects_reconcile, "record_provider_latency") as record_provider_latency,
            patch.object(projects_reconcile, "record_reconcile_failure") as record_reconcile_failure,
            patch.object(projects_reconcile, "record_provider_failure_streak") as record_provider_failure_streak,
            patch.object(projects_reconcile, "record_provider_failure_alert") as record_provider_failure_alert,
            patch.object(
                projects_reconcile,
                "S",
                SimpleNamespace(
                    projects_provider_failure_alert_threshold=2,
                    projects_reconcile_scan_limit=200,
                    projects_reconcile_max_attempts=3,
                    projects_reconcile_backoff_seconds=0.2,
                ),
            ),
        ):
            out = projects_reconcile.reconcile_tracked_files_batch(registry=registry, sleep_fn=lambda _: None)

        self.assertEqual(out["checked"], 2)
        self.assertEqual(out["updated"], 1)
        self.assertEqual(out["errors"], 1)
        self.assertEqual(table.put_item.call_count, 1)
        self.assertEqual(emit_project_event.call_count, 2)
        event_types = [call.args[2] for call in emit_project_event.call_args_list]
        self.assertIn("sync_ran", event_types)
        self.assertIn("provider_error", event_types)
        self.assertEqual(record_provider_latency.call_count, 2)
        record_reconcile_failure.assert_called_once()
        self.assertGreaterEqual(record_provider_failure_streak.call_count, 2)
        record_provider_failure_alert.assert_not_called()

    def test_reconcile_triggers_provider_failure_alert_threshold(self):
        table = MagicMock()
        table.scan.return_value = {
            "Items": [
                self._tracked_item(tracked_id="tf-1", owner="user-1"),
                self._tracked_item(tracked_id="tf-2", owner="user-1"),
            ],
            "LastEvaluatedKey": None,
        }
        table.get_item.return_value = {"Item": self._project_item(owner="user-1")}

        provider_error = MagicMock()
        provider_error.resolve.return_value = "/docs/a.txt"
        provider_error.exists.side_effect = RuntimeError("boom")

        registry = MagicMock()
        registry.get.side_effect = [provider_error, provider_error]

        with (
            patch.object(projects_reconcile, "T", SimpleNamespace(projects=table)),
            patch.object(projects_reconcile, "now_iso", return_value="2026-01-03T00:00:00+00:00"),
            patch.object(projects_reconcile, "emit_project_event"),
            patch.object(projects_reconcile, "record_provider_latency"),
            patch.object(projects_reconcile, "record_reconcile_failure"),
            patch.object(projects_reconcile, "record_provider_failure_streak"),
            patch.object(projects_reconcile, "record_provider_failure_alert") as record_provider_failure_alert,
            patch.object(
                projects_reconcile,
                "S",
                SimpleNamespace(
                    projects_provider_failure_alert_threshold=2,
                    projects_reconcile_scan_limit=200,
                    projects_reconcile_max_attempts=3,
                    projects_reconcile_backoff_seconds=0.2,
                ),
            ),
            patch.object(projects_reconcile, "_PROVIDER_FAILURE_STREAKS", {}),
        ):
            out = projects_reconcile.reconcile_tracked_files_batch(registry=registry, sleep_fn=lambda _: None)

        self.assertEqual(out["errors"], 2)
        record_provider_failure_alert.assert_called_once_with("local")

    def test_reconcile_skips_when_project_owner_scope_is_invalid(self):
        table = MagicMock()
        table.scan.return_value = {
            "Items": [self._tracked_item(status="active", owner="user-1", tracked_id="tf-3")],
            "LastEvaluatedKey": None,
        }
        table.get_item.return_value = {"Item": self._project_item(owner="user-2")}

        provider = MagicMock()
        registry = MagicMock()
        registry.get.return_value = provider

        with patch.object(projects_reconcile, "T", SimpleNamespace(projects=table)):
            out = projects_reconcile.reconcile_tracked_files_batch(registry=registry, sleep_fn=lambda _: None)

        self.assertEqual(out["checked"], 1)
        self.assertEqual(out["skipped"], 1)
        self.assertEqual(out["updated"], 0)
        self.assertEqual(out["missing"], 0)
        self.assertEqual(out["errors"], 0)
        provider.resolve.assert_not_called()
        provider.exists.assert_not_called()
        table.put_item.assert_not_called()


if __name__ == "__main__":
    unittest.main()
