from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.services.messaging_archive_writer import (
    FileArchiveWriter,
    LogArchiveWriter,
    MessagingArchiveWriteError,
    _default_archive_writer,
    emit_messaging_archive_event,
    verify_partition_chain,
)
from app.services.messaging_compliance_archive_schema import build_archive_event


class _WriterOK:
    def __init__(self):
        self.calls = []

    def write_event(self, event):
        self.calls.append(event)
        return "k1"


class _WriterFail:
    def write_event(self, event):
        raise RuntimeError("boom")


class TestMessagingArchiveWriter(unittest.TestCase):
    def test_emit_returns_none_when_archive_disabled(self):
        with patch("app.services.messaging_archive_writer._archive_enabled", return_value=False):
            out = emit_messaging_archive_event(
                event_id="e1",
                event_ts=1,
                tenant_id="t1",
                conversation_id="c1",
                message_id="m1",
                actor_user_id="u1",
                effective_user_id="u1",
                event_type="message.sent",
                payload={"text": "hi"},
            )
        self.assertIsNone(out)

    def test_emit_writes_using_writer_in_non_blocking_mode(self):
        w = _WriterOK()
        with (
            patch("app.services.messaging_archive_writer._archive_enabled", return_value=True),
            patch("app.services.messaging_archive_writer.publish_supervisory_review_message") as feed_mock,
            patch("app.services.messaging_archive_writer.record_messaging_archive_write") as write_metric,
        ):
            out = emit_messaging_archive_event(
                event_id="e2",
                event_ts=2,
                tenant_id="t1",
                conversation_id="c1",
                message_id="m1",
                actor_user_id="u1",
                effective_user_id="u1",
                event_type="message.sent",
                payload={"text": "hi"},
                writer=w,
            )
        feed_mock.assert_called_once()
        write_metric.assert_called_once()
        self.assertEqual(write_metric.call_args.kwargs["result"], "success")
        self.assertEqual(out, "k1")
        self.assertEqual(len(w.calls), 1)

    def test_emit_swallow_failure_when_not_enforced(self):
        with (
            patch("app.services.messaging_archive_writer._archive_enabled", return_value=True),
            patch("app.services.messaging_archive_writer._archive_enforce_write_success", return_value=False),
            patch("app.services.messaging_archive_writer.record_messaging_archive_write") as write_metric,
        ):
            out = emit_messaging_archive_event(
                event_id="e3",
                event_ts=3,
                tenant_id="t1",
                conversation_id="c1",
                message_id="m1",
                actor_user_id="u1",
                effective_user_id="u1",
                event_type="message.sent",
                payload={"text": "hi"},
                writer=_WriterFail(),
            )
        self.assertIsNone(out)

    def test_emit_raises_when_enforced(self):
        with (
            patch("app.services.messaging_archive_writer._archive_enabled", return_value=True),
            patch("app.services.messaging_archive_writer._archive_enforce_write_success", return_value=True),
        ):
            with self.assertRaises(MessagingArchiveWriteError):
                emit_messaging_archive_event(
                    event_id="e4",
                    event_ts=4,
                    tenant_id="t1",
                    conversation_id="c1",
                    message_id="m1",
                    actor_user_id="u1",
                    effective_user_id="u1",
                    event_type="message.sent",
                    payload={"text": "hi"},
                    writer=_WriterFail(),
                )

    def test_file_archive_writer_uses_partitioned_object_key_and_manifest_checksum(self):
        with tempfile.TemporaryDirectory() as tmp:
            writer = FileArchiveWriter(root_dir=tmp)
            with patch("app.services.messaging_archive_writer._archive_enabled", return_value=True):
                out = emit_messaging_archive_event(
                    event_id="evt_abc",
                    event_ts=1700000000,
                    tenant_id="tenant-1",
                    conversation_id="c1",
                    message_id="m1",
                    actor_user_id="u1",
                    effective_user_id="u1",
                    event_type="message.sent",
                    payload={"text": "hello"},
                    writer=writer,
                )

            self.assertEqual(out, "tenant-1/2023/11/14/22/evt_abc.json")
            obj_path = Path(tmp) / out
            self.assertTrue(obj_path.exists())

            obj_bytes = obj_path.read_bytes()
            obj_sha = hashlib.sha256(obj_bytes).hexdigest()

            manifest_path = Path(tmp) / "tenant-1/2023/11/14/22/manifest.jsonl"
            self.assertTrue(manifest_path.exists())
            lines = [ln for ln in manifest_path.read_text().splitlines() if ln.strip()]
            self.assertEqual(len(lines), 1)
            entry = json.loads(lines[0])
            self.assertEqual(entry["object_key"], out)
            self.assertEqual(entry["object_sha256"], obj_sha)
            self.assertIn("retention", entry)
            self.assertEqual(entry["retention"]["tenant_id"], "tenant-1")
            self.assertEqual(entry["retention"]["product"], "messaging")
            self.assertIn("policy_fingerprint", entry["retention"])

    def test_file_archive_writer_is_append_only_for_event_object(self):
        with tempfile.TemporaryDirectory() as tmp:
            writer = FileArchiveWriter(root_dir=tmp)
            event = build_archive_event(
                event_id="evt_dup",
                event_ts=1700000000,
                tenant_id="tenant-1",
                conversation_id="c1",
                message_id="m1",
                actor_user_id="u1",
                effective_user_id="u1",
                event_type="message.sent",
                payload={"text": "hello"},
                prev_hash="0" * 64,
            )
            writer.write_event(event)
            with self.assertRaises(FileExistsError):
                writer.write_event(event)

    def test_default_writer_respects_storage_mode(self):
        with patch("app.services.messaging_archive_writer._archive_storage_mode", return_value="filesystem"):
            self.assertIsInstance(_default_archive_writer(), FileArchiveWriter)

        with patch("app.services.messaging_archive_writer._archive_storage_mode", return_value="log"):
            self.assertIsInstance(_default_archive_writer(), LogArchiveWriter)


    def test_chain_manifest_links_prev_and_chain_hashes_deterministically(self):
        with tempfile.TemporaryDirectory() as tmp:
            writer = FileArchiveWriter(root_dir=tmp)
            with patch("app.services.messaging_archive_writer._archive_enabled", return_value=True):
                emit_messaging_archive_event(
                    event_id="evt_a",
                    event_ts=1700000000,
                    tenant_id="tenant-1",
                    conversation_id="c1",
                    message_id="m1",
                    actor_user_id="u1",
                    effective_user_id="u1",
                    event_type="message.sent",
                    payload={"text": "hello"},
                    writer=writer,
                )
                emit_messaging_archive_event(
                    event_id="evt_b",
                    event_ts=1700000001,
                    tenant_id="tenant-1",
                    conversation_id="c1",
                    message_id="m2",
                    actor_user_id="u1",
                    effective_user_id="u1",
                    event_type="message.edited",
                    payload={"text": "hello2"},
                    writer=writer,
                )
                emit_messaging_archive_event(
                    event_id="evt_c",
                    event_ts=1700000002,
                    tenant_id="tenant-1",
                    conversation_id="c1",
                    message_id="m3",
                    actor_user_id="u1",
                    effective_user_id="u1",
                    event_type="message.deleted",
                    payload={"reason": "cleanup"},
                    writer=writer,
                )

            manifest_path = Path(tmp) / "tenant-1/2023/11/14/22/manifest.jsonl"
            rows = [json.loads(x) for x in manifest_path.read_text(encoding="utf-8").splitlines() if x.strip()]
            self.assertEqual(len(rows), 3)

            self.assertEqual(rows[0]["prev_hash"], "0" * 64)
            self.assertEqual(rows[1]["prev_hash"], rows[0]["chain_hash"])
            self.assertEqual(rows[2]["prev_hash"], rows[1]["chain_hash"])

            recomputed = []
            prev = "0" * 64
            for row in rows:
                ch = FileArchiveWriter._compute_chain_hash(
                    prev_hash=prev,
                    payload_hash=row["payload_hash"],
                    event_id=row["event_id"],
                    event_ts=int(row["event_ts"]),
                )
                recomputed.append(ch)
                prev = ch

            self.assertEqual(rows[0]["chain_hash"], recomputed[0])
            self.assertEqual(rows[1]["chain_hash"], recomputed[1])
            self.assertEqual(rows[2]["chain_hash"], recomputed[2])

            chain_heads = json.loads((Path(tmp) / ".chain_heads_table.json").read_text(encoding="utf-8"))
            self.assertEqual(chain_heads["tenant-1/2023/11/14/22"]["head_hash"], rows[2]["chain_hash"])

    def test_chain_verification_detects_tampering(self):
        with tempfile.TemporaryDirectory() as tmp:
            writer = FileArchiveWriter(root_dir=tmp)
            with patch("app.services.messaging_archive_writer._archive_enabled", return_value=True):
                emit_messaging_archive_event(
                    event_id="evt_1",
                    event_ts=1700000000,
                    tenant_id="tenant-1",
                    conversation_id="c1",
                    message_id="m1",
                    actor_user_id="u1",
                    effective_user_id="u1",
                    event_type="message.sent",
                    payload={"text": "hello"},
                    writer=writer,
                )
                emit_messaging_archive_event(
                    event_id="evt_2",
                    event_ts=1700000001,
                    tenant_id="tenant-1",
                    conversation_id="c1",
                    message_id="m2",
                    actor_user_id="u1",
                    effective_user_id="u1",
                    event_type="message.edited",
                    payload={"text": "hello2"},
                    writer=writer,
                )

            ok, reason = verify_partition_chain(
                root_dir=tmp,
                tenant_id="tenant-1",
                year=2023,
                month=11,
                day=14,
                hour=22,
            )
            self.assertTrue(ok)
            self.assertEqual(reason, "ok")

            obj_path = Path(tmp) / "tenant-1/2023/11/14/22/evt_2.json"
            obj_path.write_text("tampered", encoding="utf-8")

            ok2, reason2 = verify_partition_chain(
                root_dir=tmp,
                tenant_id="tenant-1",
                year=2023,
                month=11,
                day=14,
                hour=22,
            )
            self.assertFalse(ok2)
            self.assertIn("object_checksum_mismatch", reason2)

    def test_emit_does_not_fail_when_supervisory_publish_fails(self):
        w = _WriterOK()
        with (
            patch("app.services.messaging_archive_writer._archive_enabled", return_value=True),
            patch("app.services.messaging_archive_writer.publish_supervisory_review_message", side_effect=RuntimeError("feed down")),
        ):
            out = emit_messaging_archive_event(
                event_id="e2b",
                event_ts=2,
                tenant_id="t1",
                conversation_id="c1",
                message_id="m1",
                actor_user_id="u1",
                effective_user_id="u1",
                event_type="message.sent",
                payload={"text": "hi"},
                writer=w,
            )
        self.assertEqual(out, "k1")


    def test_verify_partition_chain_records_integrity_metric_on_missing_manifest(self):
        with tempfile.TemporaryDirectory() as tmp, patch("app.services.messaging_archive_writer.record_messaging_archive_integrity_error") as integrity_metric:
            ok, reason = verify_partition_chain(
                root_dir=tmp,
                tenant_id="tenant-1",
                year=2025,
                month=1,
                day=1,
                hour=0,
            )
        self.assertFalse(ok)
        self.assertEqual(reason, "manifest_missing")
        integrity_metric.assert_called_once_with(reason="manifest_missing")



if __name__ == "__main__":
    unittest.main()
