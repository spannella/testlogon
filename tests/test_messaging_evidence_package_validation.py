from __future__ import annotations

import base64
import hashlib
import hmac
import json
import tempfile
import unittest
from pathlib import Path

from app.services.messaging_archive_query import query_archive_records
from app.services.messaging_archive_replay import replay_failed_archive_events


class TestMessagingEvidencePackageValidation(unittest.TestCase):
    def test_golden_export_fixture_integrity_is_independently_verifiable(self):
        fixture_dir = Path("tests/fixtures/messaging_evidence_package")
        manifest = json.loads((fixture_dir / "manifest.json").read_text(encoding="utf-8"))
        verification = json.loads((fixture_dir / "verification_material.json").read_text(encoding="utf-8"))
        records_bytes = (fixture_dir / "records.jsonl").read_bytes()

        lines = [ln for ln in records_bytes.decode("utf-8").splitlines() if ln.strip()]
        per_record_hashes = []
        for ln in lines:
            row = json.loads(ln)
            event_bytes = json.dumps(row["event"], sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
            expected_record_sha = hashlib.sha256(event_bytes).hexdigest()
            self.assertEqual(row["record_sha256"], expected_record_sha)
            per_record_hashes.append(expected_record_sha)

        self.assertEqual(per_record_hashes, verification["record_checksums"])

        expected_records_sha = hashlib.sha256(records_bytes).hexdigest()
        self.assertEqual(manifest["records_file"]["sha256"], expected_records_sha)
        self.assertEqual(manifest["bundle_checksums"]["records_sha256"], expected_records_sha)

        expected_aggregate = hashlib.sha256("\n".join(per_record_hashes).encode("utf-8")).hexdigest()
        self.assertEqual(manifest["record_checksums"]["aggregate_digest"], expected_aggregate)

        unsigned = dict(manifest)
        unsigned.pop("signature", None)
        unsigned["bundle_checksums"] = dict(unsigned["bundle_checksums"])
        unsigned["bundle_checksums"]["manifest_sha256"] = ""
        unsigned_bytes = json.dumps(unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

        expected_manifest_sha = hashlib.sha256(unsigned_bytes).hexdigest()
        self.assertEqual(manifest["bundle_checksums"]["manifest_sha256"], expected_manifest_sha)

        expected_signature = base64.b64encode(
            hmac.new(verification["manifest_signing_key"].encode("utf-8"), unsigned_bytes, hashlib.sha256).digest()
        ).decode("ascii")
        self.assertEqual(manifest["signature"]["key_id"], verification["manifest_signing_key_id"])
        self.assertEqual(manifest["signature"]["value"], expected_signature)

    def test_replay_of_golden_fixture_events_is_consistent_with_export_records(self):
        fixture_dir = Path("tests/fixtures/messaging_evidence_package")
        records_path = fixture_dir / "records.jsonl"

        rows = [json.loads(ln) for ln in records_path.read_text(encoding="utf-8").splitlines() if ln.strip()]
        expected_event_ids = [str(row["event"]["event_id"]) for row in rows]
        expected_payload_hashes = [str(row["event"]["payload_hash"]) for row in rows]

        with tempfile.TemporaryDirectory() as tmp:
            failed_path = Path(tmp) / ".failed_archive_events.jsonl"
            with failed_path.open("w", encoding="utf-8") as f:
                for row in rows:
                    f.write(json.dumps({"event": row["event"]}, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n")

            summary = replay_failed_archive_events(root_dir=tmp)
            self.assertEqual(summary.attempted, len(rows))
            self.assertEqual(summary.replayed, len(rows))
            self.assertEqual(summary.failed, 0)
            self.assertEqual(summary.remaining, 0)
            self.assertFalse(failed_path.exists())

            queried = query_archive_records(
                root_dir=tmp,
                tenant_id="default",
                conversation_id="c_e2e",
                user_id="u_alice",
                from_ts=1700000000,
                to_ts=1700001000,
                sort_order="asc",
                limit=100,
                offset=0,
                include_payload=True,
            )

            actual_event_ids = [str(item["event_id"]) for item in queried.items]
            actual_payload_hashes = [str(item["payload_hash"]) for item in queried.items]
            self.assertEqual(actual_event_ids, expected_event_ids)
            self.assertEqual(actual_payload_hashes, expected_payload_hashes)


if __name__ == "__main__":
    unittest.main()
