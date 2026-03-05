from __future__ import annotations

import base64
import hashlib
import hmac
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.services.messaging_archive_export import build_case_export_bundle
from app.services.messaging_archive_writer import FileArchiveWriter, emit_messaging_archive_event


class TestMessagingArchiveExport(unittest.TestCase):
    def test_build_case_export_bundle_generates_signed_manifest_and_checksums(self):
        with tempfile.TemporaryDirectory() as archive_tmp, tempfile.TemporaryDirectory() as export_tmp:
            writer = FileArchiveWriter(root_dir=archive_tmp)
            with patch("app.services.messaging_archive_writer._archive_enabled", return_value=True):
                emit_messaging_archive_event(
                    event_id="evt_1",
                    event_ts=100,
                    tenant_id="default",
                    conversation_id="c1",
                    message_id="m1",
                    actor_user_id="u1",
                    effective_user_id="u1",
                    event_type="message.sent",
                    payload={"text": "hello"},
                    writer=writer,
                )

            artifact = build_case_export_bundle(
                export_id="exp_1",
                case_id="CASE-1",
                tenant_id="default",
                requested_by_user_id="compliance-1",
                generated_at=120,
                expires_at=999,
                archive_root_dir=archive_tmp,
                export_root_dir=export_tmp,
                manifest_signing_key="secret-key",
                manifest_signing_key_id="k1",
                query_snapshot={"from_ts": 0, "to_ts": 200, "include_payload": True, "sort": "asc"},
            )

            manifest = json.loads(Path(artifact.manifest_path).read_text(encoding="utf-8"))
            self.assertEqual(manifest["case_id"], "CASE-1")
            self.assertEqual(manifest["export_id"], "exp_1")
            self.assertEqual(manifest["records_file"]["record_count"], 1)

            records_bytes = Path(artifact.records_path).read_bytes()
            self.assertEqual(manifest["records_file"]["sha256"], hashlib.sha256(records_bytes).hexdigest())

            unsigned_manifest = dict(manifest)
            unsigned_manifest.pop("signature", None)
            unsigned_manifest["bundle_checksums"]["manifest_sha256"] = ""
            payload = json.dumps(unsigned_manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
            expected_sig = base64.b64encode(hmac.new(b"secret-key", payload, hashlib.sha256).digest()).decode("ascii")
            self.assertEqual(manifest["signature"]["value"], expected_sig)


if __name__ == "__main__":
    unittest.main()
