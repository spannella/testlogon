from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from fastapi import HTTPException

from app.services import file_mounts


def _mount_item(*, mount_id: str, owner: str, mount_path: str) -> dict:
    return {
        "PK": f"OWNER#{owner}",
        "SK": f"FILE_MOUNT#{mount_id}",
        "entity_type": "file_mount",
        "id": mount_id,
        "owner": owner,
        "provider": "s3",
        "mount_path": mount_path,
        "bucket": "acme-bucket",
        "prefix": None,
        "mode": "read_only",
        "auth_ref": "cred-1",
        "status": "active",
        "created_at": "2026-01-01T00:00:00+00:00",
        "updated_at": "2026-01-01T00:00:00+00:00",
        "last_check_at": None,
        "last_error": None,
    }


class TestFileMountsService(unittest.TestCase):
    def test_create_mount_rejects_overlap(self):
        table = MagicMock()
        table.query.return_value = {"Items": [_mount_item(mount_id="m1", owner="user-1", mount_path="/mounts/acme/")]}

        with (
            patch.object(file_mounts, "T", SimpleNamespace(projects=table)),
            patch.object(file_mounts.filemanager, "get_node", side_effect=HTTPException(status_code=404, detail="not found")),
        ):
            with self.assertRaises(HTTPException) as ctx:
                file_mounts.create_file_mount(
                    "user-1",
                    mount_path="/mounts/acme/sub",
                    bucket="acme-bucket",
                    prefix=None,
                    mode="read_only",
                    auth_ref="cred-1",
                )
        self.assertEqual(ctx.exception.status_code, 409)

    def test_create_mount_rejects_local_node_conflict(self):
        table = MagicMock()
        table.query.return_value = {"Items": []}
        with (
            patch.object(file_mounts, "T", SimpleNamespace(projects=table)),
            patch.object(file_mounts.filemanager, "get_node", return_value={"path": "/mounts/acme/", "type": "folder"}),
        ):
            with self.assertRaises(HTTPException) as ctx:
                file_mounts.create_file_mount(
                    "user-1",
                    mount_path="/mounts/acme",
                    bucket="acme-bucket",
                    prefix=None,
                    mode="read_only",
                    auth_ref="cred-1",
                )
        self.assertEqual(ctx.exception.status_code, 409)


    def test_create_mount_rejects_bucket_not_allowlisted(self):
        table = MagicMock()
        table.query.return_value = {"Items": []}
        original_patterns = file_mounts.S.filemgr_s3_mounts_allowed_bucket_patterns
        object.__setattr__(file_mounts.S, "filemgr_s3_mounts_allowed_bucket_patterns", "allowed-*")
        try:
            with (
                patch.object(file_mounts, "T", SimpleNamespace(projects=table)),
                patch.object(file_mounts.filemanager, "get_node", side_effect=HTTPException(status_code=404, detail="not found")),
            ):
                with self.assertRaises(HTTPException) as ctx:
                    file_mounts.create_file_mount(
                        "user-1",
                        mount_path="/mounts/acme",
                        bucket="blocked-bucket",
                        prefix=None,
                        mode="read_only",
                        auth_ref="cred-1",
                    )
            self.assertEqual(ctx.exception.status_code, 403)
            self.assertEqual(ctx.exception.detail["code"], "mount_bucket_not_allowed")
        finally:
            object.__setattr__(file_mounts.S, "filemgr_s3_mounts_allowed_bucket_patterns", original_patterns)

    def test_create_update_delete_are_audited(self):
        table = MagicMock()
        table.query.return_value = {"Items": []}
        table.get_item.return_value = {"Item": _mount_item(mount_id="m1", owner="user-1", mount_path="/mounts/acme/")}

        with (
            patch.object(file_mounts, "T", SimpleNamespace(projects=table)),
            patch.object(file_mounts.filemanager, "get_node", side_effect=HTTPException(status_code=404, detail="not found")),
            patch.object(file_mounts, "audit_event") as audit_event,
        ):
            created = file_mounts.create_file_mount(
                "user-1",
                mount_path="/mounts/new",
                bucket="acme-bucket",
                prefix=None,
                mode="read_only",
                auth_ref="cred-1",
            )
            self.assertEqual(created.owner, "user-1")

            updated = file_mounts.update_file_mount("user-1", "m1", mode="read_write")
            self.assertEqual(updated.mode, "read_write")

            deleted = file_mounts.delete_file_mount("user-1", "m1")
            self.assertTrue(deleted["deleted"])

        self.assertEqual(audit_event.call_count, 3)
        events = [c.args[0] for c in audit_event.call_args_list]
        self.assertIn("file_mount_created", events)
        self.assertIn("file_mount_updated", events)
        self.assertIn("file_mount_deleted", events)

    def test_delete_idempotent(self):
        table = MagicMock()
        table.get_item.return_value = {}

        with patch.object(file_mounts, "T", SimpleNamespace(projects=table)):
            out = file_mounts.delete_file_mount("user-1", "missing")

        self.assertEqual(out, {"ok": True, "deleted": False})


    def test_health_worker_marks_degraded_and_active_independently(self):
        table = MagicMock()
        table.scan.return_value = {
            "Items": [
                _mount_item(mount_id="m1", owner="user-1", mount_path="/mounts/a/"),
                _mount_item(mount_id="m2", owner="user-2", mount_path="/mounts/b/"),
            ]
        }

        with (
            patch.object(file_mounts, "T", SimpleNamespace(projects=table)),
            patch.object(
                file_mounts,
                "check_mount_health",
                side_effect=[
                    {"ok": False, "status": "degraded", "error": "s3 access denied"},
                    {"ok": True, "status": "active", "error": None},
                ],
            ),
        ):
            out = file_mounts.run_file_mount_health_check_worker()

        self.assertEqual(out["checked"], 2)
        self.assertEqual(out["degraded"], 1)
        self.assertEqual(out["healthy"], 1)
        self.assertEqual(table.put_item.call_count, 2)

    def test_health_worker_continues_after_probe_exception(self):
        table = MagicMock()
        table.scan.return_value = {
            "Items": [
                _mount_item(mount_id="m1", owner="user-1", mount_path="/mounts/a/"),
                _mount_item(mount_id="m2", owner="user-2", mount_path="/mounts/b/"),
            ]
        }

        with (
            patch.object(file_mounts, "T", SimpleNamespace(projects=table)),
            patch.object(file_mounts, "check_mount_health", side_effect=[RuntimeError("boom"), {"ok": True, "status": "active", "error": None}]),
        ):
            out = file_mounts.run_file_mount_health_check_worker()

        self.assertEqual(out["checked"], 2)
        self.assertEqual(out["errors"], 1)
        self.assertEqual(out["healthy"], 1)
        self.assertGreaterEqual(table.put_item.call_count, 1)


if __name__ == "__main__":
    unittest.main()
