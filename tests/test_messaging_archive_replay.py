from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.services.messaging_archive_replay import replay_failed_archive_events
from app.services.messaging_archive_writer import emit_messaging_archive_event


class _WriterFail:
    def write_event(self, _event):
        raise RuntimeError("sink_down")


class TestMessagingArchiveReplay(unittest.TestCase):
    def test_failed_event_is_spooled_and_replayed(self):
        with tempfile.TemporaryDirectory() as tmp:
            with (
                patch("app.services.messaging_archive_writer._archive_enabled", return_value=True),
                patch("app.services.messaging_archive_writer._archive_root_dir", return_value=tmp),
            ):
                out = emit_messaging_archive_event(
                    event_id="evt_1",
                    event_ts=1700000000,
                    tenant_id="tenant-1",
                    conversation_id="c1",
                    message_id="m1",
                    actor_user_id="u1",
                    effective_user_id="u1",
                    event_type="message.sent",
                    payload={"text": "hello"},
                    writer=_WriterFail(),
                )

            self.assertIsNone(out)
            failed_path = Path(tmp) / ".failed_archive_events.jsonl"
            self.assertTrue(failed_path.exists())

            summary = replay_failed_archive_events(root_dir=tmp)
            self.assertEqual(summary.attempted, 1)
            self.assertEqual(summary.replayed, 1)
            self.assertEqual(summary.failed, 0)
            self.assertEqual(summary.remaining, 0)
            self.assertFalse(failed_path.exists())



    def test_replay_dry_run_does_not_modify_backlog(self):
        with tempfile.TemporaryDirectory() as tmp:
            failed = Path(tmp) / ".failed_archive_events.jsonl"
            failed.write_text(
                json.dumps(
                    {
                        "event": {
                            "event_id": "e1",
                            "event_ts": 1,
                            "tenant_id": "t1",
                            "conversation_id": "c1",
                            "message_id": "m1",
                            "actor_user_id": "u1",
                            "effective_user_id": "u1",
                            "event_type": "message.sent",
                            "payload": {"text": "x"},
                            "payload_hash": "0" * 64,
                            "prev_hash": "0" * 64,
                            "schema_version": 1,
                        },
                        "error": "x",
                        "failed_at": 1,
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            summary = replay_failed_archive_events(root_dir=tmp, dry_run=True)
            self.assertEqual(summary.attempted, 1)
            self.assertEqual(summary.replayed, 1)
            self.assertTrue(failed.exists())


if __name__ == "__main__":
    unittest.main()
