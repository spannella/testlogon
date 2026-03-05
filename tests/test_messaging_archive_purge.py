from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.services.messaging_archive_purge import run_archive_retention_purge
from app.services.messaging_archive_writer import FileArchiveWriter, emit_messaging_archive_event


class TestMessagingArchivePurge(unittest.TestCase):
    def _write_two_events(self, tmp: str) -> tuple[str, str]:
        writer = FileArchiveWriter(root_dir=tmp)
        with patch("app.services.messaging_archive_writer._archive_enabled", return_value=True):
            key1 = emit_messaging_archive_event(
                event_id="evt_1",
                event_ts=100,
                tenant_id="tenant-1",
                conversation_id="c1",
                message_id="m1",
                actor_user_id="u1",
                effective_user_id="u1",
                event_type="message.sent",
                payload={"text": "hello"},
                writer=writer,
            )
            key2 = emit_messaging_archive_event(
                event_id="evt_2",
                event_ts=100,
                tenant_id="tenant-1",
                conversation_id="c1",
                message_id="m2",
                actor_user_id="u1",
                effective_user_id="u1",
                event_type="message.sent",
                payload={"text": "hello2"},
                writer=writer,
            )
        assert key1 and key2
        return key1, key2

    def test_dry_run_logs_without_deleting(self):
        with tempfile.TemporaryDirectory() as tmp:
            key1, _ = self._write_two_events(tmp)
            summary = run_archive_retention_purge(
                root_dir=tmp,
                now_ts=100 + 3000 * 86400,
                dry_run=True,
                active_holds=set(),
            )
            self.assertTrue((Path(tmp) / key1).exists())
            self.assertEqual(summary.deleted, 0)
            self.assertGreaterEqual(summary.skipped, 1)

            ledger = Path(tmp) / ".purge_ledger.jsonl"
            self.assertTrue(ledger.exists())
            rows = [json.loads(x) for x in ledger.read_text(encoding="utf-8").splitlines() if x.strip()]
            self.assertTrue(any(r["action"] == "dry_run_would_purge" for r in rows))

    def test_purge_never_deletes_held_records(self):
        with tempfile.TemporaryDirectory() as tmp:
            key1, key2 = self._write_two_events(tmp)
            summary = run_archive_retention_purge(
                root_dir=tmp,
                now_ts=100 + 3000 * 86400,
                dry_run=False,
                active_holds={("tenant-1", "c1", "m2")},
            )
            self.assertTrue((Path(tmp) / key2).exists())
            self.assertFalse((Path(tmp) / key1).exists())
            self.assertGreaterEqual(summary.held_skips, 1)

            rows = [json.loads(x) for x in (Path(tmp) / ".purge_ledger.jsonl").read_text(encoding="utf-8").splitlines() if x.strip()]
            held_rows = [r for r in rows if r["reason"] == "legal_hold_active"]
            self.assertTrue(held_rows)


if __name__ == "__main__":
    unittest.main()
