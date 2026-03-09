from __future__ import annotations

import io
import unittest
from contextlib import ExitStack
from types import SimpleNamespace
from unittest.mock import patch

import boto3
from fastapi import HTTPException, UploadFile

from app.services import file_mounts, filemanager

try:
    from moto import mock_aws
except Exception:  # pragma: no cover
    mock_aws = None


class _ProjectsTable:
    def __init__(self):
        self._items = {}

    def put_item(self, Item, ConditionExpression=None):
        key = (Item["PK"], Item["SK"])
        exists = key in self._items
        if ConditionExpression == "attribute_not_exists(PK) AND attribute_not_exists(SK)" and exists:
            raise AssertionError("conditional put failed: item exists")
        if ConditionExpression == "attribute_exists(PK) AND attribute_exists(SK)" and not exists:
            raise AssertionError("conditional put failed: item missing")
        self._items[key] = dict(Item)

    def get_item(self, Key, ConsistentRead=False):
        item = self._items.get((Key["PK"], Key["SK"]))
        return {"Item": dict(item)} if item else {}

    def query(self, KeyConditionExpression=None, ScanIndexForward=False):
        # test-only table used for mount rows only
        items = [
            dict(item)
            for item in self._items.values()
            if item.get("entity_type") == "file_mount"
        ]
        return {"Items": items}

    def delete_item(self, Key, ConditionExpression=None):
        self._items.pop((Key["PK"], Key["SK"]), None)

    def scan(self, **kwargs):
        return {"Items": [dict(v) for v in self._items.values()]}


@unittest.skipIf(mock_aws is None, "moto is not installed")
class TestFileMountsMotoIntegration(unittest.TestCase):
    def setUp(self):
        self.owner = "user-1"
        self.bucket = "acme-bucket"
        self.table = _ProjectsTable()
        self.stack = ExitStack()
        self.stack.enter_context(mock_aws())
        self.s3 = boto3.client("s3", region_name="us-east-1")
        self.s3.create_bucket(Bucket=self.bucket)

        self.stack.enter_context(
            patch.object(file_mounts, "T", SimpleNamespace(projects=self.table))
        )
        self.stack.enter_context(
            patch.object(file_mounts.filemanager, "get_node", side_effect=HTTPException(status_code=404, detail="not found"))
        )
        self.stack.enter_context(patch.object(file_mounts, "audit_event"))

        self.stack.enter_context(
            patch("app.services.file_mounts_adapter.get_provider_auth_context", return_value={
                "access_key_id": "test",
                "secret_access_key": "test",
                "session_token": None,
                "metadata": {"region": "us-east-1", "endpoint_url": None, "path_style": False},
            })
        )

        self.old_upload_rate = filemanager.S.filemgr_s3_mounts_upload_rate_per_minute
        self.old_download_rate = filemanager.S.filemgr_s3_mounts_download_rate_per_minute
        self.old_max_upload = filemanager.S.filemgr_s3_mounts_max_upload_bytes
        self.old_max_download = filemanager.S.filemgr_s3_mounts_max_download_bytes
        object.__setattr__(filemanager.S, "filemgr_s3_mounts_upload_rate_per_minute", 0)
        object.__setattr__(filemanager.S, "filemgr_s3_mounts_download_rate_per_minute", 0)
        object.__setattr__(filemanager.S, "filemgr_s3_mounts_max_upload_bytes", 0)
        object.__setattr__(filemanager.S, "filemgr_s3_mounts_max_download_bytes", 0)
        filemanager._MOUNT_RATE_WINDOWS.clear()

    def tearDown(self):
        object.__setattr__(filemanager.S, "filemgr_s3_mounts_upload_rate_per_minute", self.old_upload_rate)
        object.__setattr__(filemanager.S, "filemgr_s3_mounts_download_rate_per_minute", self.old_download_rate)
        object.__setattr__(filemanager.S, "filemgr_s3_mounts_max_upload_bytes", self.old_max_upload)
        object.__setattr__(filemanager.S, "filemgr_s3_mounts_max_download_bytes", self.old_max_download)
        filemanager._MOUNT_RATE_WINDOWS.clear()
        self.stack.close()

    def _create_mount(self, *, mode: str = "read_write"):
        return file_mounts.create_file_mount(
            self.owner,
            mount_path="/mnt",
            bucket=self.bucket,
            prefix="team/root",
            mode=mode,
            auth_ref="cred-1",
        )

    def test_create_mount_then_list_and_read(self):
        self._create_mount(mode="read_write")
        self.s3.put_object(Bucket=self.bucket, Key="team/root/docs/hello.txt", Body=b"hello", ContentType="text/plain")

        listed = filemanager.list_mounted_directory(self.owner, "/mnt/docs/")
        self.assertEqual(listed["path"], "/mnt/docs/")
        self.assertEqual([item["name"] for item in listed["items"]], ["hello.txt"])
        self.assertEqual(listed["items"][0]["type"], "file")

        downloaded = filemanager.download_mounted_file(self.owner, "/mnt/docs/hello.txt")
        self.assertEqual(downloaded["node"]["path"], "/mnt/docs/hello.txt")
        self.assertEqual(downloaded["object"]["Body"].read(), b"hello")

    def test_upload_read_back_and_delete(self):
        self._create_mount(mode="read_write")

        upload = UploadFile(filename="new.txt", file=io.BytesIO(b"payload"), headers={"content-type": "text/plain"})
        written = filemanager.upload_mounted_file(self.owner, "/mnt/docs/new.txt", upload)
        self.assertEqual(written["path"], "/mnt/docs/new.txt")

        downloaded = filemanager.download_mounted_file(self.owner, "/mnt/docs/new.txt")
        self.assertEqual(downloaded["object"]["Body"].read(), b"payload")

        deleted = filemanager.delete_mounted_file(self.owner, "/mnt/docs/new.txt")
        self.assertTrue(deleted["deleted"])

        with self.assertRaises(HTTPException) as ctx:
            filemanager.download_mounted_file(self.owner, "/mnt/docs/new.txt")
        self.assertEqual(ctx.exception.status_code, 404)

    def test_read_only_mount_denies_write_and_delete(self):
        self._create_mount(mode="read_only")
        upload = UploadFile(filename="blocked.txt", file=io.BytesIO(b"blocked"), headers={"content-type": "text/plain"})

        with self.assertRaises(HTTPException) as write_ctx:
            filemanager.upload_mounted_file(self.owner, "/mnt/docs/blocked.txt", upload)
        self.assertEqual(write_ctx.exception.status_code, 403)
        self.assertEqual(write_ctx.exception.detail["code"], "mount_read_only")

        with self.assertRaises(HTTPException) as delete_ctx:
            filemanager.delete_mounted_file(self.owner, "/mnt/docs/blocked.txt")
        self.assertEqual(delete_ctx.exception.status_code, 403)
        self.assertEqual(delete_ctx.exception.detail["code"], "mount_read_only")


if __name__ == "__main__":
    unittest.main()
