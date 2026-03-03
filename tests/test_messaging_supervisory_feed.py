from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.services.messaging_supervisory_feed import build_supervisory_review_message, publish_supervisory_review_message


class TestMessagingSupervisoryFeed(unittest.TestCase):
    def test_build_review_message_matches_rule_and_assignment_metadata(self):
        out = build_supervisory_review_message(
            archive_object_key="default/2025/01/01/00/e1.json",
            event={
                "event_id": "e1",
                "event_ts": 123,
                "event_type": "report.submitted",
                "tenant_id": "default",
                "conversation_id": "c1",
                "message_id": "m1",
                "actor_user_id": "u1",
                "effective_user_id": "u2",
            },
        )
        self.assertIsNotNone(out)
        assert out is not None
        self.assertEqual(out["review_assignment"]["priority"], "high")
        self.assertEqual(out["review_assignment"]["assignment_queue"], "moderation")
        self.assertIn("event_type_prefix:report.", out["review_assignment"]["rule_trigger"])

    def test_publish_file_mode_writes_event_without_affecting_archive(self):
        with tempfile.TemporaryDirectory() as tmp:
            out_file = Path(tmp) / "feed.jsonl"
            with patch.dict(
                "os.environ",
                {
                    "MESSAGING_SUPERVISORY_FEED_ENABLED": "true",
                    "MESSAGING_SUPERVISORY_FEED_MODE": "file",
                    "MESSAGING_SUPERVISORY_FEED_FILE_PATH": str(out_file),
                },
                clear=False,
            ):
                ok = publish_supervisory_review_message(
                    archive_object_key="default/2025/01/01/00/e1.json",
                    event={
                        "event_id": "e1",
                        "event_ts": 123,
                        "event_type": "report.submitted",
                        "tenant_id": "default",
                        "conversation_id": "c1",
                        "message_id": "m1",
                        "actor_user_id": "u1",
                        "effective_user_id": "u2",
                    },
                )

            self.assertTrue(ok)
            rows = [json.loads(x) for x in out_file.read_text(encoding="utf-8").splitlines() if x.strip()]
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["event_id"], "e1")


if __name__ == "__main__":
    unittest.main()
