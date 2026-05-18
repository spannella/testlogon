from __future__ import annotations

import unittest
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from app.services.calendar_integrations import credentials
from app.services.calendar_integrations import scheduler


class TestCalendarPullScheduler(unittest.TestCase):
    def test_same_connection_cannot_overlap_due_to_lock(self):
        sync_runs = MagicMock()
        sync_runs.get_item.return_value = {
            "Item": {
                "run_id": "lock#conn-1",
                "lock_expires_at": "2099-01-01T00:00:00+00:00",
            }
        }
        with patch.object(credentials, "_sync_runs_table", return_value=sync_runs):
            acquired = credentials.acquire_apple_caldav_pull_lock(connection_id="conn-1")

        self.assertFalse(acquired)
        sync_runs.put_item.assert_not_called()

    def test_poll_interval_is_enforced_and_due_connections_run(self):
        provider = SimpleNamespace(
            config=SimpleNamespace(poll_interval_seconds=300),
            sync=SimpleNamespace(pull_changes=MagicMock(return_value={"created": 0, "updated": 0, "deleted": 0})),
        )
        now = datetime(2026, 4, 5, 12, 0, 0, tzinfo=timezone.utc)

        with (
            patch.object(scheduler, "get_provider_services", return_value=provider),
            patch.object(scheduler, "list_connected_apple_caldav_connections", return_value=["conn-due", "conn-recent"]),
            patch.object(scheduler, "should_run_apple_caldav_pull", side_effect=[True, False]),
            patch.object(scheduler, "acquire_apple_caldav_pull_lock", return_value=True),
            patch.object(scheduler, "list_enabled_apple_caldav_external_calendar_ids", return_value=["work"]),
            patch.object(scheduler, "release_apple_caldav_pull_lock"),
        ):
            out = scheduler.run_apple_caldav_pull_scheduler(now=now)

        self.assertEqual(provider.sync.pull_changes.call_count, 1)
        provider.sync.pull_changes.assert_called_once_with(connection_id="conn-due", calendar_id="work")
        self.assertEqual(out["jobs_started"], 1)
        self.assertEqual(out["jobs_skipped_interval"], 1)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
