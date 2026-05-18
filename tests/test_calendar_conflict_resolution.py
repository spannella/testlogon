from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch

from app.services.calendar_integrations import conflict, credentials


class TestCalendarConflictResolution(unittest.TestCase):
    def test_resolution_is_deterministic(self):
        local = {"name": "Local", "updated_at": "2026-04-05T10:00:00+00:00", "internal_notes": "keep me"}
        remote = {"name": "Remote", "updated_at": "2026-04-05T11:00:00+00:00", "internal_notes": "overwrite"}

        first = conflict.resolve_apple_event_conflict(local_event=local, remote_event=remote)
        second = conflict.resolve_apple_event_conflict(local_event=local, remote_event=remote)

        self.assertEqual(first, second)
        self.assertEqual(first["winner"], "remote")

    def test_protected_local_metadata_is_preserved(self):
        local = {"name": "Local", "updated_at": "2026-04-05T10:00:00+00:00", "internal_notes": "private", "color": "blue"}
        remote = {"name": "Remote", "updated_at": "2026-04-05T11:00:00+00:00", "internal_notes": "public", "color": "red"}

        resolved = conflict.resolve_apple_event_conflict(local_event=local, remote_event=remote)
        self.assertEqual(resolved["merged_event"]["name"], "Remote")
        self.assertEqual(resolved["merged_event"]["internal_notes"], "private")
        self.assertEqual(resolved["merged_event"]["color"], "blue")

    def test_conflict_audits_are_queryable(self):
        store: dict[str, dict] = {}
        sync_runs = MagicMock()

        def _put_item(*, Item):
            store[Item["run_id"]] = dict(Item)
            return {}

        def _scan():
            return {"Items": list(store.values())}

        sync_runs.put_item.side_effect = _put_item
        sync_runs.scan.side_effect = _scan

        with patch.object(credentials, "_sync_runs_table", return_value=sync_runs):
            credentials.record_apple_conflict_audit(
                connection_id="conn-1",
                external_calendar_id="work",
                internal_event_id="evt-1",
                remote_uid="uid-1",
                resolution="remote_wins_lww",
                local_updated_at="2026-04-05T10:00:00+00:00",
                remote_updated_at="2026-04-05T11:00:00+00:00",
                details={"reason": "etag_mismatch"},
            )
            out = credentials.list_apple_conflict_audits(connection_id="conn-1")

        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["resolution"], "remote_wins_lww")
        self.assertEqual(out[0]["details"]["reason"], "etag_mismatch")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
