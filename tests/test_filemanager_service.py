import io
import tarfile
from types import SimpleNamespace
import unittest
import warnings
import zipfile
from unittest.mock import Mock, patch

from botocore.exceptions import ClientError
from fastapi import HTTPException, UploadFile

from app.services import filemanager


class TestFileManagerService(unittest.TestCase):

    def test_resolve_user_usage_plan_from_db(self):
        table = Mock()
        table.get_item.return_value = {"Item": {"plan_id": "pro"}}
        with (
            patch.object(filemanager, "_table", return_value=table),
            patch.object(filemanager, "S") as settings,
        ):
            settings.filemgr_usage_default_plan = "default"
            settings.filemgr_usage_plan_limits = '{"pro":{"upload_limit_bytes":300,"download_limit_bytes":400,"storage_limit_bytes":500}}'
            settings.filemgr_usage_user_plan_overrides = ""
            out = filemanager.resolve_user_usage_plan("u1")
        self.assertEqual(out["plan_id"], "pro")
        self.assertEqual(out["upload_limit_bytes"], 300)
        self.assertEqual(out["source"], "db")

    def test_upload_file_hard_quota_enforcement_returns_machine_readable_detail(self):
        upload = UploadFile(filename="a.txt", file=io.BytesIO(b"hello"))
        with (
            patch.object(filemanager, "_bucket", return_value="bucket"),
            patch.object(filemanager, "ensure_folder_exists"),
            patch.object(filemanager, "require_not_exists"),
            patch.object(filemanager, "S") as settings,
            patch.object(filemanager, "_s3") as s3,
            patch.object(filemanager, "get_usage_summary", return_value={
                "upload": {"used_bytes": 95, "limit_bytes": 100},
                "storage": {"used_bytes": 10, "limit_bytes": 1000},
            }),
        ):
            settings.filemgr_table_name = "tbl"
            s3.head_object.return_value = {"ContentLength": 10, "ETag": "etag"}
            with self.assertRaises(HTTPException) as ctx:
                filemanager.upload_file("user", "/docs/a.txt", upload)
        self.assertEqual(ctx.exception.status_code, 403)
        self.assertEqual(ctx.exception.detail["code"], "upload_quota_exceeded")
        self.assertEqual(ctx.exception.detail["remaining_bytes"], 5)
        s3.delete_object.assert_called_once()

    def test_assert_download_allowed_enforced(self):
        with (
            patch.object(filemanager, "S") as settings,
            patch.object(filemanager, "get_usage_summary", return_value={
                "download": {"used_bytes": 100, "limit_bytes": 100},
            }),
        ):
            settings.filemgr_download_policy_mode = "enforce"
            with self.assertRaises(HTTPException) as ctx:
                filemanager.assert_download_allowed("user", requested_bytes=1)
        self.assertEqual(ctx.exception.status_code, 403)
        self.assertEqual(ctx.exception.detail["code"], "download_quota_exceeded")

    def test_upload_file_rejects_existing_path(self):
        upload = UploadFile(filename="a.txt", file=io.BytesIO(b"hello"))
        with (
            patch.object(filemanager, "_bucket", return_value="bucket"),
            patch.object(filemanager, "ensure_folder_exists"),
            patch.object(filemanager, "require_not_exists") as require_not_exists,
            patch.object(filemanager, "put_node") as put_node,
            patch.object(filemanager, "_s3") as s3,
        ):
            s3.head_object.return_value = {"ContentLength": 5, "ETag": "etag"}
            filemanager.upload_file("user", "/docs/a.txt", upload)
        require_not_exists.assert_called_once()


    def test_upload_file_persists_encrypted_flags(self):
        upload = UploadFile(filename="a.txt", file=io.BytesIO(b"hello"), headers={"content-type": "application/octet-stream"})
        with (
            patch.object(filemanager, "_bucket", return_value="bucket"),
            patch.object(filemanager, "ensure_folder_exists"),
            patch.object(filemanager, "require_not_exists"),
            patch.object(filemanager, "put_node") as put_node,
            patch.object(filemanager, "_put_token_entries"),
            patch.object(filemanager, "_s3") as s3,
        ):
            s3.head_object.return_value = {"ContentLength": 5, "ETag": "etag"}
            filemanager.upload_file(
                "user",
                "/docs/a.txt",
                upload,
                encryption_meta={
                    "version": 1,
                    "alg": "AES-256-GCM",
                    "kdf": "PBKDF2-SHA256",
                    "iterations": 600000,
                    "salt_b64": "c2FsdA==",
                    "iv_b64": "aXY=",
                    "orig_name": "a.txt",
                    "orig_size": 5,
                    "mime": "text/plain",
                },
            )
        stored = put_node.call_args.kwargs["item"] if "item" in put_node.call_args.kwargs else put_node.call_args.args[0]
        self.assertTrue(stored["is_encrypted"])
        self.assertIn("enc_metadata", stored)
        self.assertEqual(stored["enc_version"], 1)
        self.assertEqual(stored["enc_alg"], "AES-256-GCM")

    def test_upload_file_rejects_invalid_encryption_meta(self):
        upload = UploadFile(filename="a.txt", file=io.BytesIO(b"hello"), headers={"content-type": "application/octet-stream"})
        with (
            patch.object(filemanager, "_bucket", return_value="bucket"),
            patch.object(filemanager, "ensure_folder_exists"),
            patch.object(filemanager, "require_not_exists"),
            patch.object(filemanager, "_s3") as s3,
        ):
            s3.head_object.return_value = {"ContentLength": 5, "ETag": "etag"}
            with self.assertRaises(HTTPException) as ctx:
                filemanager.upload_file(
                    "user",
                    "/docs/a.txt",
                    upload,
                    encryption_meta={
                        "version": 2,
                        "alg": "AES-256-GCM",
                        "kdf": "PBKDF2-SHA256",
                        "iterations": 10,
                        "salt_b64": "%%%",
                        "iv_b64": "i",
                        "orig_name": "a.txt",
                        "orig_size": -1,
                        "mime": "text/plain",
                    },
                )
        self.assertEqual(ctx.exception.status_code, 400)

    def test_upload_file_rejects_missing_encryption_meta_keys(self):
        upload = UploadFile(filename="a.txt", file=io.BytesIO(b"hello"), headers={"content-type": "application/octet-stream"})
        with (
            patch.object(filemanager, "_bucket", return_value="bucket"),
            patch.object(filemanager, "ensure_folder_exists"),
            patch.object(filemanager, "require_not_exists"),
            patch.object(filemanager, "_s3") as s3,
        ):
            s3.head_object.return_value = {"ContentLength": 5, "ETag": "etag"}
            with self.assertRaises(HTTPException) as ctx:
                filemanager.upload_file(
                    "user",
                    "/docs/a.txt",
                    upload,
                    encryption_meta={"version": 1, "alg": "AES-256-GCM"},
                )
        self.assertEqual(ctx.exception.status_code, 400)

    def test_preview_kind_normalization_prefers_extension_for_ambiguous_content_type(self):
        self.assertEqual(
            filemanager._detect_preview_kind({"name": "report.docx", "content_type": "application/octet-stream"}),
            "word",
        )
        self.assertEqual(
            filemanager._detect_preview_kind({"name": "sheet.xlsx", "content_type": "application/octet-stream"}),
            "excel",
        )
        self.assertEqual(
            filemanager._detect_preview_kind({"name": "data.csv", "content_type": "application/vnd.ms-excel"}),
            "csv",
        )

    def test_detect_preview_kind_mapping_matrix(self):
        cases = [
            ({"name": "diagram.PNG", "content_type": "application/octet-stream"}, "image"),
            ({"name": "photo.bin", "content_type": "image/jpeg"}, "image"),
            ({"name": "manual.pdf", "content_type": "application/octet-stream"}, "pdf"),
            ({"name": "notes.docx", "content_type": "application/octet-stream"}, "word"),
            ({"name": "legacy.doc", "content_type": "application/msword"}, "word"),
            ({"name": "table.xlsx", "content_type": "application/octet-stream"}, "excel"),
            ({"name": "records.csv", "content_type": "application/vnd.ms-excel"}, "csv"),
            ({"name": "warehouse.parquet", "content_type": "application/octet-stream"}, "parquet"),
            ({"name": "server.log", "content_type": "application/octet-stream"}, "text"),
            ({"name": "payload.bin", "content_type": "application/json"}, "text"),
            ({"name": "payload.bin", "content_type": "text/plain"}, "text"),
        ]
        for node, expected_kind in cases:
            with self.subTest(node=node):
                self.assertEqual(filemanager._detect_preview_kind(node), expected_kind)

    def test_preview_kind_normalization_unknown_type_resolves_none(self):
        kind = filemanager._detect_preview_kind({"name": "archive.bin", "content_type": "application/octet-stream"})
        self.assertEqual(kind, "none")
        info = filemanager.preview_capability_from_node(
            {"type": "file", "name": "archive.bin", "content_type": "application/octet-stream", "is_encrypted": False}
        )
        self.assertEqual(info["preview_kind"], "none")
        self.assertFalse(info["preview_supported"])
        self.assertEqual(info["preview_reason"], "unsupported_type")

    def test_preview_capability_rejects_non_file_nodes(self):
        info = filemanager.preview_capability_from_node(
            {"type": "folder", "name": "docs", "content_type": None, "is_encrypted": False}
        )

        self.assertEqual(info["preview_kind"], "none")
        self.assertFalse(info["preview_supported"])
        self.assertEqual(info["preview_reason"], "not_file")

    def test_preview_capability_rejection_reasons_matrix(self):
        cases = [
            (
                {
                    "type": "file",
                    "name": "secret.csv",
                    "content_type": "text/csv",
                    "size": 1,
                    "is_encrypted": True,
                },
                "csv",
                "encrypted",
            ),
            (
                {
                    "type": "file",
                    "name": "unknown.bin",
                    "content_type": "application/octet-stream",
                    "size": 1,
                    "is_encrypted": False,
                },
                "none",
                "unsupported_type",
            ),
            (
                {
                    "type": "file",
                    "name": "named.csv",
                    "content_type": "application/octet-stream",
                    "size": 1,
                    "is_encrypted": False,
                },
                "csv",
                "not_enabled",
            ),
        ]

        for node, expected_kind, expected_reason in cases:
            with self.subTest(node=node):
                info = filemanager.preview_capability_from_node(node)
                self.assertEqual(info["preview_kind"], expected_kind)
                self.assertFalse(info["preview_supported"])
                self.assertEqual(info["preview_reason"], expected_reason)

    def test_is_previewable_rejects_encrypted(self):
        self.assertFalse(filemanager.is_previewable({"is_encrypted": True, "content_type": "image/png"}))

    def test_is_previewable_allows_extended_tabular_and_word_types(self):
        self.assertTrue(filemanager.is_previewable({"is_encrypted": False, "content_type": "text/csv"}))
        self.assertTrue(
            filemanager.is_previewable(
                {
                    "is_encrypted": False,
                    "content_type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                }
            )
        )
        self.assertTrue(filemanager.is_previewable({"is_encrypted": False, "content_type": "application/parquet"}))
        self.assertTrue(
            filemanager.is_previewable(
                {
                    "is_encrypted": False,
                    "content_type": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                }
            )
        )

    def test_is_previewable_matrix_rejects_unknown_binary(self):
        cases = [
            ({"is_encrypted": False, "content_type": "image/webp"}, True),
            ({"is_encrypted": False, "content_type": "application/pdf"}, True),
            ({"is_encrypted": False, "content_type": "application/json"}, True),
            ({"is_encrypted": False, "content_type": "application/octet-stream"}, False),
            ({"is_encrypted": False, "content_type": "application/x-7z-compressed"}, False),
            ({"is_encrypted": True, "content_type": "text/plain"}, False),
        ]
        for node, expected in cases:
            with self.subTest(node=node):
                self.assertEqual(filemanager.is_previewable(node), expected)

    def test_preview_capability_marks_file_too_large(self):
        info = filemanager.preview_capability_from_node(
            {
                "type": "file",
                "name": "big.csv",
                "content_type": "text/csv",
                "size": 20 * 1024 * 1024,
                "is_encrypted": False,
            }
        )

        self.assertEqual(info["preview_kind"], "csv")
        self.assertFalse(info["preview_supported"])
        self.assertEqual(info["preview_reason"], "too_large")

    def test_preview_capability_allows_file_at_size_limit(self):
        with patch.object(filemanager, "S", SimpleNamespace(filemgr_preview_max_bytes=1024)):
            info = filemanager.preview_capability_from_node(
                {
                    "type": "file",
                    "name": "exact.csv",
                    "content_type": "text/csv",
                    "size": 1024,
                    "is_encrypted": False,
                }
            )

        self.assertEqual(info["preview_kind"], "csv")
        self.assertTrue(info["preview_supported"])
        self.assertIsNone(info["preview_reason"])

    def test_download_thumbnail_rejects_encrypted_file(self):
        with patch.object(filemanager, "get_node", return_value={"type": "file", "is_encrypted": True}):
            with self.assertRaises(HTTPException) as ctx:
                filemanager.download_thumbnail("user", "/docs/a.txt")
        self.assertEqual(ctx.exception.status_code, 415)

    def test_upload_zip_rejects_duplicate_paths(self):
        buf = io.BytesIO()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(buf, "w") as zf:
                zf.writestr("dup.txt", b"one")
                zf.writestr("dup.txt", b"two")
        buf.seek(0)
        upload = UploadFile(filename="files.zip", file=buf)

        with (
            patch.object(filemanager, "_bucket", return_value="bucket"),
            patch.object(filemanager, "ensure_folder_exists"),
            patch.object(filemanager, "require_not_exists"),
            patch.object(filemanager, "_auto_create_parents"),
            patch.object(filemanager, "put_node") as put_node,
            patch.object(filemanager, "_s3") as s3,
        ):
            s3.put_object = Mock()
            with self.assertRaises(HTTPException) as ctx:
                filemanager.upload_zip("user", "/", upload)
        self.assertEqual(ctx.exception.status_code, 409)



    def test_upload_archive_tar_extracts_file(self):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tf:
            data = b"hello"
            info = tarfile.TarInfo(name="a.txt")
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
        buf.seek(0)
        upload = UploadFile(filename="files.tar", file=buf)

        with (
            patch.object(filemanager, "_bucket", return_value="bucket"),
            patch.object(filemanager, "ensure_folder_exists"),
            patch.object(filemanager, "require_not_exists"),
            patch.object(filemanager, "_auto_create_parents"),
            patch.object(filemanager, "put_node") as put_node,
            patch.object(filemanager, "_put_token_entries"),
            patch.object(filemanager, "_s3") as s3,
        ):
            s3.upload_fileobj = Mock()
            created = filemanager.upload_archive("user", "/", upload)
        self.assertEqual(created, ["/a.txt"])

    def test_upload_archive_rejects_unsupported_extension(self):
        upload = UploadFile(filename="files.7z", file=io.BytesIO(b"x"))
        with self.assertRaises(HTTPException) as ctx:
            filemanager.upload_archive("user", "/", upload)
        self.assertEqual(ctx.exception.status_code, 400)

    def test_upload_archive_rar_unavailable(self):
        upload = UploadFile(filename="files.rar", file=io.BytesIO(b"x"))
        with patch.object(filemanager, "rarfile", None):
            with self.assertRaises(HTTPException) as ctx:
                filemanager.upload_archive("user", "/", upload)
        self.assertEqual(ctx.exception.status_code, 501)

    def test_upload_zip_rejects_too_many_entries(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("a.txt", b"a")
            zf.writestr("b.txt", b"b")
        buf.seek(0)
        upload = UploadFile(filename="files.zip", file=buf)

        with (
            patch.object(filemanager, "_bucket", return_value="bucket"),
            patch.object(filemanager, "ensure_folder_exists"),
            patch.object(filemanager, "S") as settings,
        ):
            settings.filemgr_zip_extract_timeout_seconds = 30
            settings.filemgr_zip_max_entries = 1
            settings.filemgr_zip_max_entry_uncompressed_bytes = 1024
            settings.filemgr_zip_max_total_uncompressed_bytes = 2048
            settings.filemgr_zip_max_compression_ratio = 100.0
            with self.assertRaises(HTTPException) as ctx:
                filemanager.upload_zip("user", "/", upload)
        self.assertEqual(ctx.exception.status_code, 413)

    def test_upload_zip_rejects_large_entry_and_total_size(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("a.txt", b"12345")
        buf.seek(0)
        upload = UploadFile(filename="files.zip", file=buf)

        with (
            patch.object(filemanager, "_bucket", return_value="bucket"),
            patch.object(filemanager, "ensure_folder_exists"),
            patch.object(filemanager, "S") as settings,
        ):
            settings.filemgr_zip_extract_timeout_seconds = 30
            settings.filemgr_zip_max_entries = 10
            settings.filemgr_zip_max_entry_uncompressed_bytes = 4
            settings.filemgr_zip_max_total_uncompressed_bytes = 100
            settings.filemgr_zip_max_compression_ratio = 100.0
            with self.assertRaises(HTTPException) as ctx:
                filemanager.upload_zip("user", "/", upload)
        self.assertEqual(ctx.exception.status_code, 413)

        buf.seek(0)
        upload2 = UploadFile(filename="files.zip", file=buf)
        with (
            patch.object(filemanager, "_bucket", return_value="bucket"),
            patch.object(filemanager, "ensure_folder_exists"),
            patch.object(filemanager, "S") as settings,
        ):
            settings.filemgr_zip_extract_timeout_seconds = 30
            settings.filemgr_zip_max_entries = 10
            settings.filemgr_zip_max_entry_uncompressed_bytes = 10
            settings.filemgr_zip_max_total_uncompressed_bytes = 4
            settings.filemgr_zip_max_compression_ratio = 100.0
            with self.assertRaises(HTTPException) as ctx2:
                filemanager.upload_zip("user", "/", upload2)
        self.assertEqual(ctx2.exception.status_code, 413)

    def test_upload_zip_rejects_high_compression_ratio(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("bomb.txt", b"a" * 5000)
        buf.seek(0)
        upload = UploadFile(filename="files.zip", file=buf)

        with (
            patch.object(filemanager, "_bucket", return_value="bucket"),
            patch.object(filemanager, "ensure_folder_exists"),
            patch.object(filemanager, "S") as settings,
        ):
            settings.filemgr_zip_extract_timeout_seconds = 30
            settings.filemgr_zip_max_entries = 10
            settings.filemgr_zip_max_entry_uncompressed_bytes = 10000
            settings.filemgr_zip_max_total_uncompressed_bytes = 10000
            settings.filemgr_zip_max_compression_ratio = 1.1
            with self.assertRaises(HTTPException) as ctx:
                filemanager.upload_zip("user", "/", upload)
        self.assertEqual(ctx.exception.status_code, 413)

    def test_upload_zip_rejects_timeout_budget(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("a.txt", b"ok")
        buf.seek(0)
        upload = UploadFile(filename="files.zip", file=buf)

        with (
            patch.object(filemanager, "_bucket", return_value="bucket"),
            patch.object(filemanager, "ensure_folder_exists"),
            patch.object(filemanager, "S") as settings,
            patch.object(filemanager.time, "monotonic", side_effect=[0.0, 5.0]),
        ):
            settings.filemgr_zip_extract_timeout_seconds = 1
            settings.filemgr_zip_max_entries = 10
            settings.filemgr_zip_max_entry_uncompressed_bytes = 1024
            settings.filemgr_zip_max_total_uncompressed_bytes = 2048
            settings.filemgr_zip_max_compression_ratio = 100.0
            with self.assertRaises(HTTPException) as ctx:
                filemanager.upload_zip("user", "/", upload)
        self.assertEqual(ctx.exception.status_code, 413)


    def test_move_node_folder_creates_checkpoint_and_move_id(self):
        src_node = {"path": "/docs/", "type": "folder", "name": "docs"}
        child = {"path": "/docs/a.txt", "type": "file", "name": "a.txt"}
        with (
            patch.object(filemanager, "get_node", return_value=src_node),
            patch.object(filemanager, "ensure_folder_exists"),
            patch.object(filemanager, "_list_move_tree_items", return_value=[child]),
            patch.object(filemanager, "_execute_checkpoint_move", return_value={"status": "completed"}),
            patch.object(filemanager, "_table") as table_factory,
        ):
            table = Mock()
            table_factory.return_value = table
            table.get_item.return_value = {}
            out = filemanager.move_node("user", "/docs/", "/archive/docs/")

        self.assertEqual(out["type"], "folder")
        self.assertIn("move_id", out)
        self.assertGreaterEqual(table.put_item.call_count, 1)

    def test_resume_and_rollback_move_delegate(self):
        with patch.object(filemanager, "_execute_checkpoint_move", return_value={"status": "completed"}) as exec_move:
            filemanager.resume_move("user", "m1")
            exec_move.assert_called_once_with("user", "m1", reverse=False)

        with patch.object(filemanager, "_execute_checkpoint_move", return_value={"status": "rolled_back"}) as exec_move:
            filemanager.rollback_move("user", "m1")
            exec_move.assert_called_once_with("user", "m1", reverse=True)

    def test_register_presigned_upload_rejects_wrong_prefix(self):
        with (
            patch.object(filemanager, "ensure_folder_exists"),
            patch.object(filemanager, "require_not_exists"),
        ):
            with self.assertRaises(HTTPException) as ctx:
                filemanager.register_presigned_upload(
                    "user",
                    "/docs/a.txt",
                    s3_key="other/objects/abc",
                    ticket_id="ticket",
                    content_type="text/plain",
                )
        self.assertEqual(ctx.exception.status_code, 403)

    def test_register_presigned_upload_requires_matching_ticket_and_metadata(self):
        with (
            patch.object(filemanager, "_bucket", return_value="bucket"),
            patch.object(filemanager, "ensure_folder_exists"),
            patch.object(filemanager, "require_not_exists"),
            patch.object(filemanager, "put_node") as put_node,
            patch.object(filemanager, "_put_token_entries"),
            patch.object(filemanager, "_maybe_probe_duration", return_value=None),
            patch.object(filemanager, "_maybe_generate_thumbnail", return_value=None),
            patch.object(filemanager, "_table") as table_factory,
            patch.object(filemanager, "_s3") as s3,
        ):
            table = Mock()
            table_factory.return_value = table
            table.get_item.return_value = {
                "Item": {
                    "path": "/docs/a.txt",
                    "s3_key": "user/objects/abc",
                    "content_type": "text/plain",
                    "expires_at": "2999-01-01T00:00:00+00:00",
                }
            }
            s3.head_object.return_value = {
                "ContentLength": 5,
                "ETag": "etag",
                "ContentType": "text/plain",
                "Metadata": {"filemgr-ticket": "ticket-1", "filemgr-user": "user"},
            }

            out = filemanager.register_presigned_upload(
                "user",
                "/docs/a.txt",
                s3_key="user/objects/abc",
                ticket_id="ticket-1",
                content_type=None,
                encryption_meta={
                    "version": 1,
                    "alg": "AES-256-GCM",
                    "kdf": "PBKDF2-SHA256",
                    "iterations": 600000,
                    "salt_b64": "c2FsdA==",
                    "iv_b64": "aXY=",
                    "orig_name": "a.txt",
                    "orig_size": 5,
                    "mime": "text/plain",
                },
            )

        self.assertEqual(out["path"], "/docs/a.txt")
        stored = put_node.call_args.kwargs["item"] if "item" in put_node.call_args.kwargs else put_node.call_args.args[0]
        self.assertEqual(stored["enc_version"], 1)

    def test_register_presigned_upload_rejects_invalid_ticket(self):
        with (
            patch.object(filemanager, "_bucket", return_value="bucket"),
            patch.object(filemanager, "ensure_folder_exists"),
            patch.object(filemanager, "require_not_exists"),
            patch.object(filemanager, "_table") as table_factory,
        ):
            table = Mock()
            table_factory.return_value = table
            table.get_item.return_value = {}
            with self.assertRaises(HTTPException) as ctx:
                filemanager.register_presigned_upload(
                    "user",
                    "/docs/a.txt",
                    s3_key="user/objects/abc",
                    ticket_id="missing",
                    content_type=None,
                )
        self.assertEqual(ctx.exception.status_code, 403)

    def test_register_presigned_upload_rejects_expired_ticket(self):
        with (
            patch.object(filemanager, "_bucket", return_value="bucket"),
            patch.object(filemanager, "ensure_folder_exists"),
            patch.object(filemanager, "require_not_exists"),
            patch.object(filemanager, "_table") as table_factory,
        ):
            table = Mock()
            table_factory.return_value = table
            table.get_item.return_value = {
                "Item": {
                    "path": "/docs/a.txt",
                    "s3_key": "user/objects/abc",
                    "expires_at": "2000-01-01T00:00:00+00:00",
                }
            }
            with self.assertRaises(HTTPException) as ctx:
                filemanager.register_presigned_upload(
                    "user",
                    "/docs/a.txt",
                    s3_key="user/objects/abc",
                    ticket_id="expired",
                    content_type=None,
                )
        self.assertEqual(ctx.exception.status_code, 403)

    def test_register_presigned_upload_rejects_metadata_mismatch(self):
        with (
            patch.object(filemanager, "_bucket", return_value="bucket"),
            patch.object(filemanager, "ensure_folder_exists"),
            patch.object(filemanager, "require_not_exists"),
            patch.object(filemanager, "_table") as table_factory,
            patch.object(filemanager, "_s3") as s3,
        ):
            table = Mock()
            table_factory.return_value = table
            table.get_item.return_value = {
                "Item": {
                    "path": "/docs/a.txt",
                    "s3_key": "user/objects/abc",
                    "content_type": "text/plain",
                    "expires_at": "2999-01-01T00:00:00+00:00",
                }
            }
            s3.head_object.return_value = {
                "ContentLength": 5,
                "ETag": "etag",
                "ContentType": "text/plain",
                "Metadata": {"filemgr-ticket": "wrong", "filemgr-user": "user"},
            }
            with self.assertRaises(HTTPException) as ctx:
                filemanager.register_presigned_upload(
                    "user",
                    "/docs/a.txt",
                    s3_key="user/objects/abc",
                    ticket_id="ticket-1",
                    content_type=None,
                )
        self.assertEqual(ctx.exception.status_code, 403)



    def test_search_text_records_fallback_metric(self):
        with (
            patch.object(filemanager, "_query_token_items", return_value=[]),
            patch.object(filemanager, "_search_text_scan", return_value=[]),
            patch.object(filemanager, "record_filemgr_search_path") as record_path,
            patch.object(filemanager, "record_filemgr_operation_latency") as record_latency,
        ):
            out = filemanager.search_text("user", "doc", limit=5)

        self.assertEqual(out, [])
        record_path.assert_called_once_with("search_text", "scan_fallback")
        record_latency.assert_called()

    def test_search_text_scan_skips_encrypted_items(self):
        encrypted_item = {
            "path": "/docs/enc.bin",
            "type": "file",
            "name": "enc.bin",
            "name_lc": "enc.bin",
            "parent": "/docs/",
            "is_encrypted": True,
            "updated_at": "t1",
            "size": 5,
        }
        plain_item = {
            "path": "/docs/plain.txt",
            "type": "file",
            "name": "plain.txt",
            "name_lc": "plain.txt",
            "parent": "/docs/",
            "is_encrypted": False,
            "updated_at": "t2",
            "size": 4,
        }
        with patch.object(filemanager, "_table") as table_factory:
            table = Mock()
            table_factory.return_value = table
            table.query.return_value = {"Items": [encrypted_item, plain_item]}
            out = filemanager._search_text_scan("user", "plain", limit=10)
        self.assertEqual([x["path"] for x in out], ["/docs/plain.txt"])

    def test_purge_deleted_nodes_global_records_purge_run_metric(self):
        with (
            patch.object(filemanager, "_table") as table_factory,
            patch.object(filemanager, "_purge_node_item", return_value="purged"),
            patch.object(filemanager, "record_filemgr_purge_run") as record_purge_run,
        ):
            table = Mock()
            table_factory.return_value = table
            table.query.return_value = {"Items": [{"PK": "USER#u", "SK": "NODE#/a", "deleted_at": "t", "purge_after": "2000-01-01T00:00:00+00:00"}]}

            out = filemanager.purge_deleted_nodes_global(limit=10)

        self.assertEqual(out["purged"], 1)
        record_purge_run.assert_called_once()

    def test_purge_deleted_nodes_global_uses_purge_index(self):
        with patch.object(filemanager, "_table") as table_factory, patch.object(
            filemanager,
            "_purge_node_item",
            return_value="purged",
        ):
            table = Mock()
            table_factory.return_value = table
            table.query.return_value = {
                "Items": [{"PK": "USER#u", "SK": "NODE#/a", "deleted_at": "t", "purge_after": "2000-01-01T00:00:00+00:00"}],
            }

            out = filemanager.purge_deleted_nodes_global(limit=10)

        self.assertEqual(out["mode"], "index")
        table.query.assert_called()
        self.assertEqual(table.scan.call_count, 0)

    def test_purge_deleted_nodes_global_falls_back_to_scan(self):
        with patch.object(filemanager, "_table") as table_factory, patch.object(
            filemanager,
            "_purge_node_item",
            return_value="skipped",
        ):
            table = Mock()
            table_factory.return_value = table
            table.query.side_effect = ClientError({"Error": {"Code": "ValidationException", "Message": "missing index"}}, "Query")
            table.scan.return_value = {"Items": [{"PK": "USER#u", "SK": "NODE#/a", "deleted_at": "t"}]}

            out = filemanager.purge_deleted_nodes_global(limit=10)

        self.assertEqual(out["mode"], "scan_fallback")
        table.scan.assert_called()

    def test_purge_deleted_nodes_counts_error_and_skipped(self):
        with patch.object(filemanager, "_table") as table_factory, patch.object(
            filemanager,
            "_purge_node_item",
            side_effect=["error", "skipped"],
        ):
            table = Mock()
            table_factory.return_value = table
            table.query.return_value = {
                "Items": [
                    {"path": "/a", "deleted_at": "t"},
                    {"path": "/b", "deleted_at": "t"},
                ]
            }
            out = filemanager.purge_deleted_nodes("user", limit=10)

        self.assertEqual(out["errors"], 1)
        self.assertEqual(out["skipped"], 1)

    def test_purge_node_item_records_retry_error(self):
        tbl = Mock()
        item = {
            "PK": "USER#u",
            "SK": "NODE#/a",
            "path": "/a",
            "deleted_at": "2024-01-01T00:00:00+00:00",
            "purge_after": "2024-01-02T00:00:00+00:00",
            "s3_bucket": "bucket",
            "s3_key": "key",
        }
        with patch.object(
            filemanager._s3,
            "delete_object",
            side_effect=ClientError({"Error": {"Code": "InternalError", "Message": "boom"}}, "DeleteObject"),
        ):
            result = filemanager._purge_node_item(tbl, item, filemanager.datetime.now(filemanager.timezone.utc))

        self.assertEqual(result, "error")
        tbl.update_item.assert_called_once()

    def test_execute_checkpoint_move_interrupted_then_resume_idempotent(self):
        checkpoint = {
            "entries": [
                {"src": "/docs/", "dst": "/archive/docs/", "type": "folder"},
                {"src": "/docs/a.txt", "dst": "/archive/docs/a.txt", "type": "file"},
            ],
            "moved": 0,
            "already_done": 0,
        }
        with patch.object(filemanager, "_table") as table_factory, patch.object(
            filemanager,
            "_transact_move_item",
            side_effect=["moved", RuntimeError("boom")],
        ):
            table = Mock()
            table_factory.return_value = table
            table.get_item.return_value = {"Item": checkpoint}
            with self.assertRaises(RuntimeError):
                filemanager._execute_checkpoint_move("user", "m1", reverse=False)

        # Resume path with idempotency marker: first already moved, second moved now
        with patch.object(filemanager, "_table") as table_factory2, patch.object(
            filemanager,
            "_transact_move_item",
            side_effect=["already_moved", "moved"],
        ):
            table2 = Mock()
            table_factory2.return_value = table2
            table2.get_item.return_value = {"Item": checkpoint}
            out = filemanager._execute_checkpoint_move("user", "m1", reverse=False)

        self.assertEqual(out["status"], "completed")
        self.assertEqual(out["already_done"], 1)
        self.assertEqual(out["moved_now"], 1)

    def test_upload_file_records_metering_with_authoritative_size(self):
        upload = UploadFile(filename="a.txt", file=io.BytesIO(b"hello"))
        with (
            patch.object(filemanager, "_bucket", return_value="bucket"),
            patch.object(filemanager, "ensure_folder_exists"),
            patch.object(filemanager, "require_not_exists"),
            patch.object(filemanager, "put_node"),
            patch.object(filemanager, "_put_token_entries"),
            patch.object(filemanager, "_record_usage_event_safe") as record_usage,
            patch.object(filemanager, "_s3") as s3,
        ):
            s3.head_object.return_value = {"ContentLength": 11, "ETag": "etag-1"}
            filemanager.upload_file("user", "/docs/a.txt", upload)

        upload_events = [c.args[0] for c in record_usage.call_args_list if c.args[0].get("source") == "api_upload"]
        self.assertEqual(len(upload_events), 1)
        event = upload_events[0]
        self.assertEqual(event["event_type"], "upload")
        self.assertEqual(event["bytes"], 11)

    def test_register_presigned_upload_records_metering_once(self):
        with (
            patch.object(filemanager, "_bucket", return_value="bucket"),
            patch.object(filemanager, "ensure_folder_exists"),
            patch.object(filemanager, "require_not_exists"),
            patch.object(filemanager, "put_node"),
            patch.object(filemanager, "_put_token_entries"),
            patch.object(filemanager, "_maybe_probe_duration", return_value=None),
            patch.object(filemanager, "_maybe_generate_thumbnail", return_value=None),
            patch.object(filemanager, "_record_usage_event_safe") as record_usage,
            patch.object(filemanager, "_table") as table_factory,
            patch.object(filemanager, "_s3") as s3,
        ):
            table = Mock()
            table_factory.return_value = table
            table.get_item.return_value = {
                "Item": {
                    "path": "/docs/a.txt",
                    "s3_key": "user/objects/abc",
                    "content_type": "text/plain",
                    "expires_at": "2999-01-01T00:00:00+00:00",
                }
            }
            s3.head_object.return_value = {
                "ContentLength": 17,
                "ETag": "etag-2",
                "ContentType": "text/plain",
                "Metadata": {"filemgr-ticket": "ticket-1", "filemgr-user": "user"},
            }

            filemanager.register_presigned_upload(
                "user",
                "/docs/a.txt",
                s3_key="user/objects/abc",
                ticket_id="ticket-1",
                content_type=None,
            )

        upload_events = [c.args[0] for c in record_usage.call_args_list if c.args[0].get("source") == "presign_complete"]
        self.assertEqual(len(upload_events), 1)
        event = upload_events[0]
        self.assertEqual(event["event_type"], "upload")
        self.assertEqual(event["bytes"], 17)

    def test_upload_archive_emits_per_entry_and_total_metering_events(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("one.txt", b"abc")
            zf.writestr("two.txt", b"defg")
        buf.seek(0)
        upload = UploadFile(filename="files.zip", file=buf)

        with (
            patch.object(filemanager, "_bucket", return_value="bucket"),
            patch.object(filemanager, "ensure_folder_exists"),
            patch.object(filemanager, "require_not_exists"),
            patch.object(filemanager, "_auto_create_parents"),
            patch.object(filemanager, "put_node"),
            patch.object(filemanager, "_put_token_entries"),
            patch.object(filemanager, "_record_usage_event_safe") as record_usage,
            patch.object(filemanager, "_record_usage_event_non_aggregating_safe") as record_usage_total,
            patch.object(filemanager, "_s3") as s3,
        ):
            s3.head_object.side_effect = [
                {"ContentLength": 3, "ETag": "etag-1"},
                {"ContentLength": 4, "ETag": "etag-2"},
            ]
            created = filemanager.upload_archive("user", "/", upload)

        self.assertEqual(len(created), 2)
        entry_events = [c.args[0] for c in record_usage.call_args_list if c.args[0].get("source") == "upload_zip_entry"]
        self.assertEqual(len(entry_events), 2)
        entry_bytes = [e["bytes"] for e in entry_events]
        self.assertEqual(entry_bytes, [3, 4])
        total_event = record_usage_total.call_args.args[0]
        self.assertEqual(total_event["bytes"], 7)
        self.assertEqual(total_event["source"], "upload_zip_total")

    def test_get_usage_summary_and_limits(self):
        table = Mock()
        table.get_item.return_value = {
            "Item": {
                "upload_bytes_total": 50,
                "download_bytes_total": 100,
                "storage_bytes_current": 25,
                "updated_at": "2026-02-01T00:00:00+00:00",
            }
        }
        with (
            patch.object(filemanager, "_table", return_value=table),
            patch.object(filemanager, "S") as settings,
        ):
            settings.filemgr_usage_upload_limit_bytes = 100
            settings.filemgr_usage_download_limit_bytes = 200
            settings.filemgr_usage_storage_limit_bytes = 50
            out = filemanager.get_usage_summary("user", period_id="2026-02")

        self.assertEqual(out["upload"]["used_bytes"], 50)
        self.assertEqual(out["upload"]["percent_used"], 50.0)
        self.assertEqual(out["download"]["percent_used"], 50.0)
        self.assertEqual(out["storage"]["percent_used"], 50.0)

    def test_get_usage_daily_range_filter(self):
        table = Mock()
        table.query.return_value = {
            "Items": [
                {"day_utc": "2026-02-01", "upload_bytes_total": 1, "download_bytes_total": 2, "storage_bytes_end_of_day": 3},
                {"day_utc": "2026-02-10", "upload_bytes_total": 4, "download_bytes_total": 5, "storage_bytes_end_of_day": 6},
                {"day_utc": "2026-03-01", "upload_bytes_total": 7, "download_bytes_total": 8, "storage_bytes_end_of_day": 9},
            ]
        }
        with patch.object(filemanager, "_table", return_value=table):
            out = filemanager.get_usage_daily("user", from_day="2026-02-01", to_day="2026-02-28")
        self.assertEqual(len(out["items"]), 2)

    def test_get_usage_storage_top_files(self):
        table = Mock()
        table.query.return_value = {
            "Items": [
                {"type": "file", "path": "/a", "size": 10},
                {"type": "file", "path": "/b", "size": 20},
                {"type": "folder", "path": "/docs/"},
                {"type": "file", "path": "/c", "size": 5, "deleted_at": "t"},
            ]
        }
        with patch.object(filemanager, "_table", return_value=table):
            out = filemanager.get_usage_storage("user", top_n=1)
        self.assertEqual(out["storage_bytes_current"], 30)
        self.assertEqual(len(out["top_files"]), 1)
        self.assertEqual(out["top_files"][0]["path"], "/b")

    def test_recompute_usage_aggregates_admin_report_only(self):
        table = Mock()
        table.scan.side_effect = [
            {
                "Items": [
                    {"entity_type": "usage_event", "user_id": "u1", "timestamp": "2026-02-10T00:00:00+00:00", "bytes": 3, "event_type": "upload", "period_id": "2026-02"},
                    {"entity_type": "usage_event", "user_id": "u1", "timestamp": "2026-02-10T01:00:00+00:00", "bytes": 2, "event_type": "download", "period_id": "2026-02"},
                ]
            }
        ]
        table.get_item.return_value = {"Item": {"upload_bytes_total": 0, "download_bytes_total": 0, "storage_bytes_current": 0}}
        with patch.object(filemanager, "_table", return_value=table):
            out = filemanager.recompute_usage_aggregates_admin(scope="all", period_id="2026-02", apply=False)
        self.assertEqual(out["events_scanned"], 2)
        self.assertGreaterEqual(out["mismatches"], 1)

    def test_finalize_billing_period_admin_creates_snapshot(self):
        table = Mock()
        table.scan.side_effect = [
            {"Items": [{"PK": "USER#u1", "SK": "USAGE#PERIOD#2026-02", "user_id": "u1"}]}
        ]
        table.get_item.return_value = {"Item": {"upload_bytes_total": 10, "download_bytes_total": 20, "storage_bytes_peak": 30, "storage_byte_seconds": 40}}
        table.query.return_value = {"Items": []}
        with patch.object(filemanager, "_table", return_value=table):
            out = filemanager.finalize_billing_period_admin(period_id="2026-02")
        self.assertEqual(out["finalized_count"], 1)
        table.put_item.assert_called()


    def test_admin_user_usage_detail_redacts_paths_by_default(self):
        table = Mock()
        table.query.return_value = {"Items": []}
        with (
            patch.object(filemanager, "get_usage_summary", return_value={"period_id": "2026-02"}),
            patch.object(filemanager, "get_usage_daily", return_value={"items": []}),
            patch.object(filemanager, "get_usage_storage", return_value={"storage_bytes_current": 10, "top_files": [{"path": "/a", "size": 10}]}),
            patch.object(filemanager, "_table", return_value=table),
        ):
            out = filemanager.get_admin_user_usage_detail("u1", period_id="2026-02", top_n=5)
        self.assertTrue(out["storage"]["paths_redacted"])
        self.assertEqual(out["storage"]["top_files"], [{"size": 10}])

    def test_get_admin_user_usage_detail(self):
        table = Mock()
        table.query.return_value = {"Items": [{"period_id": "2026-02", "version": 1, "status": "finalized", "upload_bytes_total": 1, "download_bytes_total": 2, "storage_bytes_peak": 3}]}
        with (
            patch.object(filemanager, "get_usage_summary", return_value={"period_id": "2026-02"}),
            patch.object(filemanager, "get_usage_daily", return_value={"items": []}),
            patch.object(filemanager, "get_usage_storage", return_value={"storage_bytes_current": 1}),
            patch.object(filemanager, "_table", return_value=table),
        ):
            out = filemanager.get_admin_user_usage_detail("u1", period_id="2026-02", top_n=5)
        self.assertEqual(out["user_id"], "u1")
        self.assertEqual(out["summary"]["period_id"], "2026-02")
        self.assertEqual(len(out["snapshots"]), 1)


    def test_generate_invoice_line_items_for_snapshot_admin(self):
        table = Mock()
        table.get_item.return_value = {
            "Item": {
                "upload_bytes_total": 20,
                "download_bytes_total": 10,
                "storage_bytes_peak": 5,
            }
        }
        with (
            patch.object(filemanager, "_table", return_value=table),
            patch.object(filemanager, "S") as settings,
        ):
            settings.filemgr_usage_pricing_catalog = '{"v2":{"upload_included_bytes":0,"download_included_bytes":0,"storage_included_bytes":0,"upload_overage_cents_per_gb":100,"download_overage_cents_per_gb":100,"storage_overage_cents_per_gb":100}}'
            settings.filemgr_usage_default_pricing_catalog_version = "v2"
            out = filemanager.generate_invoice_line_items_for_snapshot_admin(
                user_id="u1",
                period_id="2026-02",
                snapshot_version=1,
            )
        self.assertEqual(out["pricing_catalog_version"], "v2")
        self.assertEqual(len(out["line_items"]), 3)
        table.put_item.assert_called_once()

    def test_create_billing_adjustment_admin_credit(self):
        table = Mock()
        table.get_item.return_value = {"Item": {"SK": "USAGE#SNAPSHOT#2026-02#V0001"}}
        with patch.object(filemanager, "_table", return_value=table):
            out = filemanager.create_billing_adjustment_admin(
                user_id="u1",
                period_id="2026-02",
                snapshot_version=1,
                adjustment_type="credit",
                amount_cents=25,
                reason="manual correction",
            )
        self.assertTrue(out["ok"])
        self.assertEqual(out["amount_cents"], -25)
        table.put_item.assert_called_once()

    def test_finalize_billing_period_admin_version_increments_on_repeated_finalize(self):
        table = Mock()
        table.scan.side_effect = [
            {"Items": [{"PK": "USER#u1", "SK": "USAGE#PERIOD#2026-02", "user_id": "u1"}]},
            {"Items": [{"PK": "USER#u1", "SK": "USAGE#PERIOD#2026-02", "user_id": "u1"}]},
        ]
        table.get_item.return_value = {"Item": {"upload_bytes_total": 10, "download_bytes_total": 20, "storage_bytes_peak": 30, "storage_byte_seconds": 40}}
        table.query.side_effect = [
            {"Items": [{"version": 1}]},
            {"Items": [{"version": 1}, {"version": 2}]},
        ]
        with patch.object(filemanager, "_table", return_value=table):
            out1 = filemanager.finalize_billing_period_admin(period_id="2026-02")
            out2 = filemanager.finalize_billing_period_admin(period_id="2026-02")

        self.assertEqual(out1["snapshots"][0]["version"], 2)
        self.assertEqual(out2["snapshots"][0]["version"], 3)
