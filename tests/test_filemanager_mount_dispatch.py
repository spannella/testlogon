from datetime import datetime, timezone
import io
import unittest
from unittest.mock import patch

from fastapi import HTTPException

from app.services import filemanager as svc


def _mount_data() -> dict:
    ts = datetime.now(timezone.utc).isoformat()
    return {
        "id": "m1",
        "owner": "u1",
        "provider": "s3",
        "mount_path": "/mnt/",
        "bucket": "example-bucket",
        "prefix": "base",
        "mode": "read_only",
        "auth_ref": "auth1",
        "status": "active",
        "created_at": ts,
        "updated_at": ts,
    }


class TestFileManagerMountedReadMapping(unittest.TestCase):
    def test_list_mounted_directory_maps_errors(self):
        cases = [
            (404, "missing", 404, "not found"),
            (403, "denied", 403, "access denied"),
            (400, "bad request", 400, "bad request"),
            (500, "boom", 502, "provider error"),
        ]
        for src_code, src_detail, out_code, out_detail in cases:
            with self.subTest(status=src_code):
                with (
                    patch.object(svc, "resolve_path_mount", return_value=_mount_data()),
                    patch("app.services.file_mounts_adapter.list_dir", side_effect=HTTPException(src_code, src_detail)),
                ):
                    with self.assertRaises(HTTPException) as ctx:
                        svc.list_mounted_directory("u1", "/mnt/")
                self.assertEqual(ctx.exception.status_code, out_code)
                self.assertEqual(ctx.exception.detail, out_detail)

    def test_download_mounted_file_maps_errors(self):
        cases = [
            (404, "missing", 404, "not found"),
            (403, "denied", 403, "access denied"),
            (400, "bad request", 400, "bad request"),
            (503, "upstream", 502, "provider error"),
        ]
        for src_code, src_detail, out_code, out_detail in cases:
            with self.subTest(status=src_code):
                with (
                    patch.object(svc, "resolve_path_mount", return_value=_mount_data()),
                    patch("app.services.file_mounts_adapter.read_file", side_effect=HTTPException(src_code, src_detail)),
                ):
                    with self.assertRaises(HTTPException) as ctx:
                        svc.download_mounted_file("u1", "/mnt/a.txt")
                self.assertEqual(ctx.exception.status_code, out_code)
                self.assertEqual(ctx.exception.detail, out_detail)

    def test_download_mounted_file_requires_stream_body(self):
        with (
            patch.object(svc, "resolve_path_mount", return_value=_mount_data()),
            patch(
                "app.services.file_mounts_adapter.read_file",
                return_value={
                    "body": None,
                    "content_length": 12,
                    "content_type": "text/plain",
                    "bucket": "example-bucket",
                    "key": "base/a.txt",
                },
            ),
        ):
            with self.assertRaises(HTTPException) as ctx:
                svc.download_mounted_file("u1", "/mnt/a.txt")
        self.assertEqual(ctx.exception.status_code, 502)
        self.assertEqual(ctx.exception.detail, "provider error")


    def test_upload_mounted_file_maps_mount_read_only(self):
        with (
            patch.object(svc, "resolve_path_mount", return_value=_mount_data()),
            patch(
                "app.services.file_mounts_adapter.write_file",
                side_effect=HTTPException(403, {"code": "mount_read_only", "message": "mount is read-only"}),
            ),
        ):
            upload = type("Upload", (), {"file": object(), "content_type": "text/plain"})()
            with self.assertRaises(HTTPException) as ctx:
                svc.upload_mounted_file("u1", "/mnt/a.txt", upload)
        self.assertEqual(ctx.exception.status_code, 403)
        self.assertEqual(ctx.exception.detail["code"], "mount_read_only")

    def test_delete_mounted_file_maps_mount_read_only(self):
        with (
            patch.object(svc, "resolve_path_mount", return_value=_mount_data()),
            patch(
                "app.services.file_mounts_adapter.delete_file",
                side_effect=HTTPException(403, {"code": "mount_read_only", "message": "mount is read-only"}),
            ),
        ):
            with self.assertRaises(HTTPException) as ctx:
                svc.delete_mounted_file("u1", "/mnt/a.txt")
        self.assertEqual(ctx.exception.status_code, 403)
        self.assertEqual(ctx.exception.detail["code"], "mount_read_only")


    def test_upload_mounted_file_enforces_size_limit(self):
        upload = type("Upload", (), {"content_type": "text/plain", "file": io.BytesIO(b"abcdef")})()
        original_max = svc.S.filemgr_s3_mounts_max_upload_bytes
        try:
            object.__setattr__(svc.S, "filemgr_s3_mounts_max_upload_bytes", 4)
            with patch.object(svc, "resolve_path_mount", return_value={**_mount_data(), "mode": "read_write"}):
                with self.assertRaises(HTTPException) as ctx:
                    svc.upload_mounted_file("u1", "/mnt/a.txt", upload)
            self.assertEqual(ctx.exception.status_code, 413)
            self.assertEqual(ctx.exception.detail["code"], "mount_upload_too_large")
        finally:
            object.__setattr__(svc.S, "filemgr_s3_mounts_max_upload_bytes", original_max)

    def test_download_mounted_file_enforces_size_limit(self):
        original_max = svc.S.filemgr_s3_mounts_max_download_bytes
        try:
            object.__setattr__(svc.S, "filemgr_s3_mounts_max_download_bytes", 4)
            with (
                patch.object(svc, "resolve_path_mount", return_value=_mount_data()),
                patch(
                    "app.services.file_mounts_adapter.read_file",
                    return_value={
                        "body": io.BytesIO(b"abcdef"),
                        "content_length": 6,
                        "content_type": "text/plain",
                        "bucket": "example-bucket",
                        "key": "base/a.txt",
                    },
                ),
            ):
                with self.assertRaises(HTTPException) as ctx:
                    svc.download_mounted_file("u1", "/mnt/a.txt")
            self.assertEqual(ctx.exception.status_code, 413)
            self.assertEqual(ctx.exception.detail["code"], "mount_download_too_large")
        finally:
            object.__setattr__(svc.S, "filemgr_s3_mounts_max_download_bytes", original_max)

    def test_upload_mounted_file_rate_limited(self):
        original_rate = svc.S.filemgr_s3_mounts_upload_rate_per_minute
        try:
            object.__setattr__(svc.S, "filemgr_s3_mounts_upload_rate_per_minute", 1)
            svc._MOUNT_RATE_WINDOWS.clear()
            with (
                patch.object(svc, "resolve_path_mount", return_value={**_mount_data(), "mode": "read_write"}),
                patch("app.services.file_mounts_adapter.write_file", side_effect=HTTPException(500, "boom")),
            ):
                with self.assertRaises(HTTPException):
                    svc.upload_mounted_file("u1", "/mnt/a.txt", type("Upload", (), {"file": io.BytesIO(b"a"), "content_type": "text/plain"})())
            with (
                patch.object(svc, "resolve_path_mount", return_value={**_mount_data(), "mode": "read_write"}),
                patch("app.services.file_mounts_adapter.write_file", side_effect=HTTPException(500, "boom")),
            ):
                with self.assertRaises(HTTPException) as ctx2:
                    svc.upload_mounted_file("u1", "/mnt/b.txt", type("Upload", (), {"file": io.BytesIO(b"a"), "content_type": "text/plain"})())
            self.assertEqual(ctx2.exception.status_code, 429)
            self.assertEqual(ctx2.exception.detail["code"], "mount_rate_limited")
        finally:
            object.__setattr__(svc.S, "filemgr_s3_mounts_upload_rate_per_minute", original_rate)
            svc._MOUNT_RATE_WINDOWS.clear()
