from __future__ import annotations

import io
import unittest
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from fastapi import HTTPException

from app.models import FileMountModel
from app.services import file_mounts_adapter


def _mount() -> FileMountModel:
    return FileMountModel(
        id="m1",
        owner="user-1",
        provider="s3",
        mount_path="/mounts/acme",
        bucket="acme-bucket",
        prefix="tenant/root",
        mode="read_only",
        auth_ref="cred-1",
        status="active",
        created_at="2026-01-01T00:00:00+00:00",
        updated_at="2026-01-01T00:00:00+00:00",
    )


class TestFileMountsAdapter(unittest.TestCase):
    def test_safe_relative_rejects_outside_mount(self):
        with self.assertRaises(HTTPException) as ctx:
            file_mounts_adapter._safe_relative_from_virtual(_mount(), "/other/path", expect_dir=False)
        self.assertEqual(ctx.exception.status_code, 400)


    def test_safe_relative_rejects_path_traversal(self):
        with self.assertRaises(HTTPException) as ctx:
            file_mounts_adapter._safe_relative_from_virtual(_mount(), "/mounts/acme/../secret.txt", expect_dir=False)
        self.assertEqual(ctx.exception.status_code, 400)

    def test_map_s3_error_codes(self):
        from botocore.exceptions import ClientError

        not_found = ClientError({"Error": {"Code": "NoSuchKey", "Message": "missing"}}, "GetObject")
        denied = ClientError({"Error": {"Code": "AccessDenied", "Message": "denied"}}, "GetObject")
        throttled = ClientError({"Error": {"Code": "SlowDown", "Message": "slow down"}}, "GetObject")

        not_found_exc = file_mounts_adapter._map_s3_error(not_found)
        denied_exc = file_mounts_adapter._map_s3_error(denied)
        throttled_exc = file_mounts_adapter._map_s3_error(throttled)

        self.assertEqual(not_found_exc.status_code, 404)
        self.assertEqual(denied_exc.status_code, 403)
        self.assertEqual(throttled_exc.status_code, 502)

    def test_list_dir_supports_pagination(self):
        client = MagicMock()
        client.list_objects_v2.return_value = {
            "CommonPrefixes": [{"Prefix": "tenant/root/docs/sub/"}],
            "Contents": [
                {
                    "Key": "tenant/root/docs/a.txt",
                    "Size": 12,
                    "LastModified": datetime(2026, 1, 1, tzinfo=timezone.utc),
                    "ETag": '"abc"',
                }
            ],
            "IsTruncated": True,
            "NextContinuationToken": "token-2",
        }
        with (
            patch.object(file_mounts_adapter, "_build_s3_client_for_mount", return_value=client),
        ):
            out = file_mounts_adapter.list_dir(_mount(), "/mounts/acme/docs/", limit=50, cursor="token-1")

        self.assertEqual(out["cursor"], "token-2")
        self.assertTrue(out["truncated"])
        self.assertEqual(len(out["items"]), 2)
        self.assertEqual(out["items"][0]["type"], "folder")
        self.assertEqual(out["items"][1]["type"], "file")

    def test_stat_file_then_dir_probe(self):
        client = MagicMock()
        client.head_object.side_effect = HTTPException(status_code=404, detail="not found")
        with (
            patch.object(file_mounts_adapter, "_build_s3_client_for_mount", return_value=client),
            patch.object(file_mounts_adapter, "_map_s3_error", return_value=HTTPException(status_code=404, detail="x")),
        ):
            # simulate head not found then dir exists
            from botocore.exceptions import ClientError

            client.head_object.side_effect = ClientError({"Error": {"Code": "404", "Message": "nope"}}, "HeadObject")
            client.list_objects_v2.return_value = {"KeyCount": 1}
            out = file_mounts_adapter.stat(_mount(), "/mounts/acme/docs")
        self.assertEqual(out["type"], "dir")



    def test_write_file_read_only_mount_returns_mount_read_only(self):
        with self.assertRaises(HTTPException) as ctx:
            file_mounts_adapter.write_file(
                _mount().model_copy(update={"mode": "read_only"}),
                "/mounts/acme/docs/a.txt",
                body=io.BytesIO(b"abc"),
                content_type="text/plain",
            )
        self.assertEqual(ctx.exception.status_code, 403)
        self.assertEqual(ctx.exception.detail["code"], "mount_read_only")

    def test_delete_file_read_only_mount_returns_mount_read_only(self):
        with self.assertRaises(HTTPException) as ctx:
            file_mounts_adapter.delete_file(
                _mount().model_copy(update={"mode": "read_only"}),
                "/mounts/acme/docs/a.txt",
            )
        self.assertEqual(ctx.exception.status_code, 403)
        self.assertEqual(ctx.exception.detail["code"], "mount_read_only")

    def test_write_file_small_put_object(self):
        client = MagicMock()
        client.put_object.return_value = {"ETag": '"etag-put"'}
        payload = io.BytesIO(b"hello")
        with (
            patch.object(file_mounts_adapter, "_build_s3_client_for_mount", return_value=client),
            patch.object(file_mounts_adapter, "_multipart_threshold_bytes", return_value=1024),
        ):
            out = file_mounts_adapter.write_file(
                _mount().model_copy(update={"mode": "read_write"}),
                "/mounts/acme/docs/a.txt",
                body=payload,
                content_type="text/plain",
                metadata={"source": "unit"},
            )

        self.assertEqual(out["etag"], "etag-put")
        self.assertEqual(out["content_length"], 5)
        client.put_object.assert_called_once()
        self.assertEqual(client.put_object.call_args.kwargs["Metadata"]["source"], "unit")

    def test_write_file_large_uses_multipart(self):
        client = MagicMock()
        client.create_multipart_upload.return_value = {"UploadId": "u1"}
        client.upload_part.side_effect = [{"ETag": '"p1"'}, {"ETag": '"p2"'}]
        client.complete_multipart_upload.return_value = {"ETag": '"final"'}
        payload = io.BytesIO(b"a" * 12)
        with (
            patch.object(file_mounts_adapter, "_build_s3_client_for_mount", return_value=client),
            patch.object(file_mounts_adapter, "_multipart_threshold_bytes", return_value=5),
            patch.object(file_mounts_adapter, "_multipart_chunk_bytes", return_value=6),
        ):
            out = file_mounts_adapter.write_file(
                _mount().model_copy(update={"mode": "read_write"}),
                "/mounts/acme/docs/big.bin",
                body=payload,
                content_type="application/octet-stream",
            )

        self.assertEqual(out["etag"], "final")
        self.assertEqual(out["content_length"], 12)
        client.create_multipart_upload.assert_called_once()
        self.assertEqual(client.upload_part.call_count, 2)
        client.complete_multipart_upload.assert_called_once()

    def test_delete_file_calls_s3(self):
        client = MagicMock()
        with patch.object(file_mounts_adapter, "_build_s3_client_for_mount", return_value=client):
            out = file_mounts_adapter.delete_file(
                _mount().model_copy(update={"mode": "read_write"}),
                "/mounts/acme/docs/a.txt",
            )
        self.assertTrue(out["deleted"])
        client.delete_object.assert_called_once()


    def test_mount_metrics_recorded_for_list_and_read(self):
        client = MagicMock()
        client.list_objects_v2.return_value = {
            "CommonPrefixes": [],
            "Contents": [{"Key": "tenant/root/docs/a.txt", "Size": 3, "ETag": '"e1"'}],
            "IsTruncated": False,
        }
        client.get_object.return_value = {
            "Body": io.BytesIO(b"abc"),
            "ContentType": "text/plain",
            "ContentLength": 3,
            "ETag": '"e1"',
        }
        with (
            patch.object(file_mounts_adapter, "_build_s3_client_for_mount", return_value=client),
            patch.object(file_mounts_adapter, "record_filemgr_mount_operation_latency") as op_latency,
            patch.object(file_mounts_adapter, "record_filemgr_mount_bytes") as bytes_metric,
        ):
            file_mounts_adapter.list_dir(_mount(), "/mounts/acme/docs/")
            file_mounts_adapter.read_file(_mount(), "/mounts/acme/docs/a.txt")

        self.assertGreaterEqual(op_latency.call_count, 2)
        self.assertTrue(any(c.kwargs.get("operation") == "list" for c in op_latency.call_args_list))
        self.assertTrue(any(c.kwargs.get("operation") == "read" for c in op_latency.call_args_list))
        self.assertTrue(any(c.kwargs.get("direction") == "out" for c in bytes_metric.call_args_list))

    def test_mount_error_metric_records_aws_code(self):
        from botocore.exceptions import ClientError

        client = MagicMock()
        client.delete_object.side_effect = ClientError({"Error": {"Code": "AccessDenied", "Message": "denied"}}, "DeleteObject")
        with (
            patch.object(file_mounts_adapter, "_build_s3_client_for_mount", return_value=client),
            patch.object(file_mounts_adapter, "record_filemgr_mount_error") as error_metric,
        ):
            with self.assertRaises(HTTPException):
                file_mounts_adapter.delete_file(
                    _mount().model_copy(update={"mode": "read_write"}),
                    "/mounts/acme/docs/a.txt",
                )
        self.assertTrue(error_metric.called)
        self.assertEqual(error_metric.call_args.kwargs.get("aws_error_code"), "AccessDenied")

    def test_read_file_returns_streaming_body(self):
        client = MagicMock()
        body = io.BytesIO(b"hello world")
        client.get_object.return_value = {
            "Body": body,
            "ContentType": "text/plain",
            "ContentLength": 11,
            "ETag": '"etag1"',
        }
        with patch.object(file_mounts_adapter, "_build_s3_client_for_mount", return_value=client):
            out = file_mounts_adapter.read_file(_mount(), "/mounts/acme/docs/a.txt")

        self.assertEqual(out["content_length"], 11)
        self.assertEqual(out["content_type"], "text/plain")
        self.assertIs(out["body"], body)


if __name__ == "__main__":
    unittest.main()
