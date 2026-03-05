from __future__ import annotations

import unittest

from pydantic import ValidationError

from app.models import FileMountModel
from app.services.file_mounts_store import file_mount_from_item, file_mount_to_item


class TestFileMountModel(unittest.TestCase):
    def test_file_mount_round_trip(self):
        model = FileMountModel(
            id="m-1",
            owner="user-1",
            provider="s3",
            mount_path="/mounts/acme",
            bucket="Acme-Bucket",
            prefix="/docs/team/",
            mode="read_only",
            auth_ref="cred-1",
            status="active",
            created_at="2026-01-01T00:00:00+00:00",
            updated_at="2026-01-01T00:00:00+00:00",
            last_check_at="2026-01-02T00:00:00+00:00",
        )

        item = file_mount_to_item(model)
        restored = file_mount_from_item(item)

        self.assertEqual(restored.id, "m-1")
        self.assertEqual(restored.mount_path, "/mounts/acme/")
        self.assertEqual(restored.bucket, "acme-bucket")
        self.assertEqual(restored.prefix, "docs/team")
        self.assertEqual(restored.mode, "read_only")
        self.assertEqual(item["entity_type"], "file_mount")
        self.assertEqual(item["PK"], "OWNER#user-1")
        self.assertEqual(item["SK"], "FILE_MOUNT#m-1")

    def test_invalid_mount_path_rejected(self):
        with self.assertRaises(ValidationError):
            FileMountModel(
                id="m-1",
                owner="user-1",
                provider="s3",
                mount_path="relative/path",
                bucket="acme-bucket",
                mode="read_only",
                auth_ref="cred-1",
                status="active",
                created_at="2026-01-01T00:00:00+00:00",
                updated_at="2026-01-01T00:00:00+00:00",
            )

    def test_invalid_mode_rejected(self):
        with self.assertRaises(ValidationError):
            FileMountModel(
                id="m-1",
                owner="user-1",
                provider="s3",
                mount_path="/mounts/acme",
                bucket="acme-bucket",
                mode="write_only",
                auth_ref="cred-1",
                status="active",
                created_at="2026-01-01T00:00:00+00:00",
                updated_at="2026-01-01T00:00:00+00:00",
            )


if __name__ == "__main__":
    unittest.main()
