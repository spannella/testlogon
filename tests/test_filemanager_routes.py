import asyncio
import io
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from fastapi import HTTPException
from fastapi import UploadFile
from fastapi import HTTPException
from fastapi.responses import StreamingResponse
from app.routers import filemanager


class TestFileManagerRoutes(unittest.TestCase):
    def test_list_files_rejects_invalid_cursor_payloads(self):
        bad = filemanager._encode_cursor({"mode": "invalid", "offset": 0})
        with self.assertRaises(HTTPException) as ctx:
            filemanager.list_files(path="/", cursor=bad, user="user")
        self.assertEqual(ctx.exception.status_code, 400)

        bad2 = filemanager._encode_cursor({"mode": "offset", "offset": 0})
        with self.assertRaises(HTTPException) as ctx2:
            filemanager.list_files(path="/", cursor=bad2, sort_by="name", user="user")
        self.assertEqual(ctx2.exception.status_code, 400)

    def test_filemanager_internal_entitlement_hook_applied(self):
        with (
            patch.object(filemanager, "_enforce_filemanager_internal_entitlement") as enforce_internal,
            patch.object(filemanager, "list_children", return_value=[]),
        ):
            filemanager.list_files(path="/", user="user")
        enforce_internal.assert_called_once_with(user="user", action="list_directory")

    def test_filemanager_internal_entitlement_denial_propagates(self):
        with patch.object(
            filemanager,
            "_enforce_filemanager_internal_entitlement",
            side_effect=HTTPException(status_code=403, detail={"code": "internal_api_entitlement_denied", "reason": "exhausted"}),
        ):
            with self.assertRaises(HTTPException) as ctx:
                filemanager.list_files(path="/", user="user")
        self.assertEqual(ctx.exception.status_code, 403)
        self.assertEqual(ctx.exception.detail["reason"], "exhausted")

    def test_list_and_info(self):
        items = [
            {"path": "/docs/", "type": "folder", "name": "docs", "parent": "/", "updated_at": "t1"},
            {"path": "/docs/a.txt", "type": "file", "name": "a.txt", "parent": "/docs/", "updated_at": "t2", "size": 12, "content_type": "text/plain", "is_encrypted": True},
            {"path": "/docs/sub/b.txt", "type": "file", "name": "b.txt", "parent": "/docs/sub/", "updated_at": "t3", "size": 1},
        ]
        with patch.object(filemanager, "list_children", return_value=items), patch.object(
            filemanager,
            "get_node",
            return_value={
                "path": "/docs/a.txt",
                "type": "file",
                "name": "a.txt",
                "parent": "/docs/",
                "created_at": "t0",
                "updated_at": "t2",
                "is_encrypted": True,
                "enc_metadata": {
                    "version": 1,
                    "alg": "AES-256-GCM",
                    "kdf": "PBKDF2-SHA256",
                    "iterations": 600000,
                    "salt_b64": "c2FsdA==",
                    "iv_b64": "aXY=",
                    "orig_name": "a.txt",
                    "orig_size": 12,
                    "mime": "text/plain",
                },
            },
        ):
            resp = filemanager.list_files(path="/docs", user="user")
            self.assertEqual(resp["path"], "/docs/")
            self.assertEqual(len(resp["items"]), 1)
            self.assertEqual(resp["items"][0]["path"], "/docs/a.txt")
            self.assertEqual(resp["items"][0]["name"], "a.txt")
            self.assertEqual(resp["items"][0]["preview_kind"], "document")
            self.assertFalse(resp["items"][0]["preview_supported"])
            self.assertEqual(resp["items"][0]["preview_status"], "unsupported")
            self.assertIsNone(resp["items"][0]["poster_url"])
            self.assertIsNone(resp["items"][0]["hover_preview_url"])
            self.assertIsNone(resp["items"][0]["waveform_url"])
            self.assertEqual(resp["items"][0]["preview_reason"], "encrypted")

            info = filemanager.file_info(path="/docs/a.txt", user="user")
            self.assertEqual(info["path"], "/docs/a.txt")
            self.assertEqual(info["type"], "file")
            self.assertTrue(info["is_encrypted"])
            self.assertEqual(info["enc_version"], 1)
            self.assertEqual(info["enc_alg"], "AES-256-GCM")
            self.assertEqual(info["preview_kind"], "document")
            self.assertEqual(info["preview_status"], "unsupported")
            self.assertIsNone(info["poster_url"])
            self.assertIsNone(info["hover_preview_url"])
            self.assertIsNone(info["waveform_url"])
            self.assertFalse(info["preview_supported"])
            self.assertEqual(info["preview_reason"], "encrypted")

    def test_file_info_falls_back_to_flattened_encryption_fields(self):
        with patch.object(
            filemanager,
            "get_node",
            return_value={
                "path": "/docs/a.txt",
                "type": "file",
                "name": "a.txt",
                "parent": "/docs/",
                "is_encrypted": True,
                "enc_version": 1,
                "enc_alg": "AES-256-GCM",
                "enc_kdf": "PBKDF2-SHA256",
                "enc_kdf_iterations": 600000,
                "enc_salt_b64": "c2FsdA==",
                "enc_iv_b64": "aXY=",
                "enc_orig_name": "a.txt",
                "enc_orig_size": 12,
                "enc_orig_content_type": "text/plain",
            },
        ):
            info = filemanager.file_info(path="/docs/a.txt", user="user")
            self.assertIsInstance(info["enc_metadata"], dict)
            self.assertEqual(info["enc_metadata"]["version"], 1)
            self.assertEqual(info["enc_metadata"]["orig_name"], "a.txt")


    def test_list_files_mount_dispatch(self):
        original_enabled = filemanager.S.filemgr_s3_mounts_enabled
        try:
            object.__setattr__(filemanager.S, "filemgr_s3_mounts_enabled", True)
            listing = {
                "path": "/mounts/a/",
                "items": [
                    {
                        "path": "/mounts/a/docs/",
                        "type": "folder",
                        "name": "docs",
                        "size": None,
                        "updated_at": None,
                        "content_type": None,
                        "enc_metadata": None,
                        "is_encrypted": False,
                        "enc_version": None,
                        "enc_alg": None,
                        "enc_kdf": None,
                        "enc_kdf_iterations": None,
                        "enc_salt_b64": None,
                        "enc_iv_b64": None,
                        "enc_orig_name": None,
                        "enc_orig_size": None,
                        "enc_orig_content_type": None,
                        "preview_kind": "none",
                        "preview_supported": False,
                        "preview_status": "unsupported",
                        "preview_reason": "folder",
                        "poster_url": None,
                        "hover_preview_url": None,
                        "waveform_url": None,
                    }
                ],
                "cursor": "next-token",
            }
            with (
                patch.object(filemanager, "resolve_path_mount", return_value={"id": "m1"}),
                patch.object(filemanager, "list_mounted_directory", return_value=listing) as list_mounted,
            ):
                resp = filemanager.list_files(path="/mounts/a", user="user")
            self.assertEqual(resp["path"], "/mounts/a/")
            self.assertEqual(len(resp["items"]), 1)
            self.assertIsNotNone(resp["cursor"])
            list_mounted.assert_called_once()
        finally:
            object.__setattr__(filemanager.S, "filemgr_s3_mounts_enabled", original_enabled)

    def test_download_file_mount_dispatch(self):
        node = {"path": "/mounts/a/file.txt", "name": "file.txt", "content_type": "text/plain", "size": 5, "is_encrypted": False}
        obj = {"Body": io.BytesIO(b"hello")}
        with (
            patch.object(filemanager, "resolve_path_mount", return_value={"id": "m1"}),
            patch.object(filemanager, "download_mounted_file", return_value={"node": node, "object": obj}) as download_mounted,
            patch.object(filemanager, "assert_file_bundle_access") as assert_bundle,
            patch.object(filemanager, "assert_download_allowed") as assert_allowed,
            patch.object(filemanager, "record_filemgr_encryption_event"),
            patch.object(filemanager, "audit_event"),
            patch.object(filemanager, "record_download_usage"),
        ):
            resp = filemanager.download_fs_file(path="/mounts/a/file.txt", user="user")
        self.assertEqual(resp.media_type, "text/plain")
        download_mounted.assert_called_once()
        assert_bundle.assert_called_once()
        assert_allowed.assert_called_once()

    def test_search_and_create(self):
        with patch.object(filemanager, "search_prefix", return_value=[{"path": "/a", "type": "file", "name": "a"}]):
            resp = filemanager.search_filenames(prefix="a", limit=10, user="user")
            self.assertEqual(resp["prefix"], "a")
            self.assertEqual(resp["results"][0]["path"], "/a")

        with patch.object(filemanager, "search_text", return_value=[{"path": "/docs/a.txt", "type": "file", "name": "a.txt"}]):
            resp = filemanager.search_text_files(q="docs", limit=10, user="user")
            self.assertEqual(resp["query"], "docs")
            self.assertEqual(resp["results"][0]["path"], "/docs/a.txt")
            filemanager.search_text.assert_called_once_with("user", "docs", limit=10)

        with patch.object(filemanager, "create_empty_folder", return_value="/docs/"):
            resp = filemanager.create_folder(path="/docs", user="user")
            self.assertTrue(resp["ok"])
            self.assertEqual(resp["path"], "/docs/")

    def test_admin_metadata_list_and_search(self):
        rows = [{"owner": "u1", "path": "/docs/a.txt", "type": "file", "name": "a.txt"}]
        with patch.object(filemanager, "admin_search_metadata", return_value=rows) as search_meta:
            ctx = {"user_sub": "admin1", "role": "admin"}
            listed = filemanager.admin_list_files(path="/docs", owner=None, limit=50, ctx=ctx)
            self.assertEqual(len(listed["items"]), 1)
            self.assertEqual(listed["items"][0]["owner"], "u1")

            searched = filemanager.admin_search_files(q="a", prefix=None, owner=None, limit=50, ctx=ctx)
            self.assertEqual(len(searched["items"]), 1)
            self.assertEqual(searched["items"][0]["path"], "/docs/a.txt")
            self.assertTrue(search_meta.called)

    def test_admin_read_content_policy_tier(self):
        ctx_admin = {"user_sub": "admin1", "role": "admin"}
        node = {"path": "/docs/a.txt", "type": "file", "name": "a.txt", "size": 5, "content_type": "text/plain", "updated_at": "t1"}
        with patch.object(filemanager, "get_node", return_value=node):
            meta = filemanager.admin_read_file(owner="u1", path="/docs/a.txt", include_content=False, ctx=ctx_admin)
            self.assertEqual(meta["path"], "/docs/a.txt")

        original_tier = filemanager.S.filemgr_admin_content_access_tier
        object.__setattr__(filemanager.S, "filemgr_admin_content_access_tier", "none")
        try:
            with self.assertRaises(HTTPException) as exc:
                filemanager.admin_read_file(owner="u1", path="/docs/a.txt", include_content=True, ctx=ctx_admin)
            self.assertEqual(exc.exception.status_code, 403)
        finally:
            object.__setattr__(filemanager.S, "filemgr_admin_content_access_tier", original_tier)

    def test_bulk_operations_emit_correlation_id(self):
        captured = []

        def _audit(_event, _user, _req=None, **fields):
            captured.append(fields)

        with patch.object(filemanager, "audit_event", side_effect=_audit), \
             patch.object(filemanager, "download_zip", return_value=(iter([b"zip"]), 1)):
            filemanager.download_multiple_as_zip(paths=["/a"], user="user")

        self.assertTrue(captured)
        self.assertTrue(captured[-1].get("correlation_id"))

    def test_admin_file_audit_query_filters(self):
        alerts = [
            {
                "event": "filemgr_file_downloaded",
                "ts": 100,
                "outcome": "success",
                "details": {"actor_sub": "admin1", "target_user_sub": "u1", "file_path": "/a", "correlation_id": "c1"},
            },
            {
                "event": "billing_charge_once",
                "ts": 101,
                "outcome": "success",
                "details": {"actor_sub": "admin1"},
            },
        ]
        fake_alerts = type("A", (), {"scan": lambda self, **kwargs: {"Items": alerts}})()
        tables = type("T", (), {"alerts": fake_alerts})()
        with patch.object(filemanager, "T", tables):
            resp = filemanager.admin_file_audit(
                actor_sub="admin1",
                target_user_sub="u1",
                file_path="/a",
                start_ts=90,
                end_ts=110,
                limit=10,
                cursor=None,
                _ctx={"user_sub": "root", "role": "root"},
            )
        self.assertEqual(len(resp["items"]), 1)
        self.assertEqual(resp["items"][0]["event"], "filemgr_file_downloaded")

    def test_upload_encrypted_file_passes_metadata(self):
        upload = UploadFile(filename="a.txt", file=io.BytesIO(b"hello"))
        enc_meta = '{"version":1,"alg":"AES-256-GCM"}'
        with (
            patch.object(filemanager, "upload_file", return_value={"path": "/docs/a.txt", "size": 5}) as upload_file,
            patch.object(filemanager, "record_filemgr_encryption_event") as record_encryption_event,
        ):
            resp = filemanager.upload_fs_file(path="/docs/a.txt", file=upload, encrypted=True, enc_meta=enc_meta, user="user")
            self.assertTrue(resp["ok"])
            upload_file.assert_called_once()
            self.assertEqual(upload_file.call_args.kwargs["encryption_meta"], {"version": 1, "alg": "AES-256-GCM"})
            record_encryption_event.assert_called_once_with("upload", encrypted=True)


    def test_upload_mount_dispatch(self):
        upload = UploadFile(filename="a.txt", file=io.BytesIO(b"hello"))
        original_enabled = filemanager.S.filemgr_s3_mounts_enabled
        original_write = filemanager.S.filemgr_s3_mounts_write_enabled
        object.__setattr__(filemanager.S, "filemgr_s3_mounts_enabled", True)
        object.__setattr__(filemanager.S, "filemgr_s3_mounts_write_enabled", True)
        try:
            with (
                patch.object(filemanager, "resolve_path_mount", return_value={"id": "m1"}),
                patch.object(filemanager, "upload_mounted_file", return_value={"path": "/mounts/a.txt", "size": 5}) as upload_mounted,
                patch.object(filemanager, "upload_file") as upload_local,
                patch.object(filemanager, "record_filemgr_encryption_event"),
            ):
                resp = filemanager.upload_fs_file(path="/mounts/a.txt", file=upload, user="user")
            self.assertTrue(resp["ok"])
            upload_mounted.assert_called_once_with("user", "/mounts/a.txt", upload)
            upload_local.assert_not_called()
        finally:
            object.__setattr__(filemanager.S, "filemgr_s3_mounts_enabled", original_enabled)
            object.__setattr__(filemanager.S, "filemgr_s3_mounts_write_enabled", original_write)

    def test_upload_and_download(self):
        upload = UploadFile(filename="a.txt", file=io.BytesIO(b"hello"))
        with (
            patch.object(filemanager, "upload_file", return_value={"path": "/docs/a.txt", "size": 5}),
            patch.object(filemanager, "record_filemgr_encryption_event") as record_encryption_event,
        ):
            resp = filemanager.upload_fs_file(path="/docs/a.txt", file=upload, user="user")
            self.assertTrue(resp["ok"])
            self.assertEqual(resp["size"], 5)
            record_encryption_event.assert_called_once_with("upload", encrypted=False)

        obj = {"Body": io.BytesIO(b"hello")}
        node = {"name": "a.txt", "content_type": "text/plain", "is_encrypted": True, "path": "/docs/a.txt", "size": 5}
        with (
            patch.object(filemanager, "download_file", return_value={"node": node, "object": obj}),
            patch.object(filemanager, "assert_download_allowed") as assert_download_allowed,
            patch.object(filemanager, "record_filemgr_encryption_event") as record_encryption_event,
            patch.object(filemanager, "record_download_usage") as record_download_usage,
        ):
            resp = filemanager.download_fs_file(path="/docs/a.txt", user="user")
            self.assertIsInstance(resp, StreamingResponse)
            self.assertEqual(resp.media_type, "text/plain")
            self.assertIn("attachment; filename=\"a.txt\"", resp.headers.get("Content-Disposition", ""))
            async def _consume():
                async for _ in resp.body_iterator:
                    pass
            asyncio.run(_consume())
            record_encryption_event.assert_called_once_with("download_attempt", encrypted=True)
            record_download_usage.assert_called_once_with("user", "/docs/a.txt", 5, source="download", request_id=None)
            assert_download_allowed.assert_called_once_with("user", requested_bytes=5)

    def test_preview_blocks_encrypted_file(self):
        obj = {"Body": io.BytesIO(b"cipher")}
        node = {"name": "a.txt", "type": "file", "content_type": "application/octet-stream", "is_encrypted": True, "path": "/docs/a.txt"}
        with (
            patch.object(filemanager, "download_file", return_value={"node": node, "object": obj}),
            patch.object(filemanager, "audit_event") as audit_event,
            patch.object(filemanager, "record_filemgr_preview_attempt") as preview_attempt,
            patch.object(filemanager, "record_filemgr_preview_fallback") as preview_fallback,
            patch.object(filemanager, "record_filemgr_preview_latency") as preview_latency,
        ):
            with self.assertRaises(HTTPException) as ctx:
                filemanager.preview_fs_file(path="/docs/a.txt", user="user")
        self.assertEqual(ctx.exception.status_code, 415)
        preview_attempt.assert_called_once_with(kind="document", outcome="fallback", reason="encrypted")
        preview_fallback.assert_called_once_with(kind="document", reason="encrypted")
        preview_latency.assert_called_once()
        self.assertEqual(audit_event.call_args.kwargs["preview_kind"], "document")
        self.assertEqual(audit_event.call_args.kwargs["preview_supported"], False)
        self.assertEqual(audit_event.call_args.kwargs["preview_reason"], "encrypted")
        self.assertEqual(audit_event.call_args.kwargs["is_encrypted"], True)
        self.assertEqual(audit_event.call_args.kwargs["preview_kind"], "document")
        self.assertEqual(audit_event.call_args.kwargs["preview_supported"], False)
        self.assertEqual(audit_event.call_args.kwargs["preview_reason"], "encrypted")
        self.assertEqual(audit_event.call_args.kwargs["is_encrypted"], True)
        self.assertEqual(audit_event.call_args.kwargs["preview_kind"], "document")
        self.assertEqual(audit_event.call_args.kwargs["preview_supported"], False)
        self.assertEqual(audit_event.call_args.kwargs["preview_reason"], "encrypted")
        self.assertEqual(audit_event.call_args.kwargs["is_encrypted"], True)

    def test_preview_success_emits_metrics(self):
        obj = {"Body": io.BytesIO(b"hello")}
        node = {"name": "a.txt", "type": "file", "content_type": "text/plain", "is_encrypted": False, "path": "/docs/a.txt", "size": 5}
        with (
            patch.object(filemanager, "download_file", return_value={"node": node, "object": obj}),
            patch.object(filemanager, "audit_event") as audit_event,
            patch.object(filemanager, "record_filemgr_preview_attempt") as preview_attempt,
            patch.object(filemanager, "record_filemgr_preview_bytes") as preview_bytes,
            patch.object(filemanager, "record_filemgr_preview_latency") as preview_latency,
        ):
            resp = filemanager.preview_fs_file(path="/docs/a.txt", user="user")
            self.assertIsInstance(resp, StreamingResponse)
            preview_attempt.assert_called_once_with(kind="document", outcome="success", reason="none")
            preview_bytes.assert_called_once_with(kind="document", nbytes=5)
            preview_latency.assert_called_once()
            self.assertEqual(audit_event.call_args.kwargs["preview_kind"], "document")
            self.assertEqual(audit_event.call_args.kwargs["preview_supported"], True)
            self.assertEqual(audit_event.call_args.kwargs["preview_reason"], "none")
            self.assertEqual(audit_event.call_args.kwargs["is_encrypted"], False)

    def test_thumbnail_blocks_encrypted_file(self):
        obj = {"Body": io.BytesIO(b"thumb")}
        node = {"name": "a.txt", "type": "file", "content_type": "image/png", "is_encrypted": True, "path": "/docs/a.txt", "thumbnail": {"bucket": "b", "key": "k"}}
        with (
            patch.object(filemanager, "download_thumbnail", return_value={"node": node, "thumbnail": node["thumbnail"], "object": obj}),
            patch.object(filemanager, "audit_event") as audit_event,
            patch.object(filemanager, "record_filemgr_preview_attempt") as preview_attempt,
            patch.object(filemanager, "record_filemgr_preview_fallback") as preview_fallback,
            patch.object(filemanager, "record_filemgr_preview_latency") as preview_latency,
        ):
            with self.assertRaises(HTTPException) as ctx:
                filemanager.thumbnail_fs_file(path="/docs/a.txt", user="user")
        self.assertEqual(ctx.exception.status_code, 415)
        preview_attempt.assert_called_once_with(kind="document", outcome="fallback", reason="encrypted")
        preview_fallback.assert_called_once_with(kind="document", reason="encrypted")
        preview_latency.assert_called_once()

    def test_shared_thumbnail_blocks_encrypted_file(self):
        obj = {"Body": io.BytesIO(b"thumb")}
        node = {"name": "a.txt", "type": "file", "content_type": "image/png", "is_encrypted": True, "path": "/docs/a.txt", "thumbnail": {"bucket": "b", "key": "k"}}
        with (
            patch.object(filemanager, "require_shared_access"),
            patch.object(filemanager, "download_thumbnail", return_value={"node": node, "thumbnail": node["thumbnail"], "object": obj}),
            patch.object(filemanager, "audit_event") as audit_event,
            patch.object(filemanager, "record_filemgr_preview_attempt") as preview_attempt,
            patch.object(filemanager, "record_filemgr_preview_fallback") as preview_fallback,
            patch.object(filemanager, "record_filemgr_preview_latency") as preview_latency,
        ):
            with self.assertRaises(HTTPException) as ctx:
                filemanager.shared_thumbnail_fs_file(owner="owner", path="/docs/a.txt", user="user")
        self.assertEqual(ctx.exception.status_code, 415)
        preview_attempt.assert_called_once_with(kind="document", outcome="fallback", reason="encrypted")
        preview_fallback.assert_called_once_with(kind="document", reason="encrypted")
        preview_latency.assert_called_once()

    def test_file_crypto_client_telemetry_records_metrics(self):
        with (
            patch.object(filemanager, "record_filemgr_encryption_event") as record_encryption_event,
            patch.object(filemanager, "audit_event") as audit_event,
        ):
            resp = filemanager.file_crypto_client_telemetry(
                inp=filemanager.FileCryptoTelemetryIn(
                    event="decrypt_failure",
                    path="/docs/a.txt",
                    reason="wrong_password",
                    remembered_password_used=True,
                ),
                user="user",
            )
            self.assertTrue(resp["ok"])
            record_encryption_event.assert_called_once_with("decrypt_failure", encrypted=True, reason="wrong_password")
            audit_event.assert_called_once()

    def test_file_preview_hover_telemetry_records_metrics(self):
        with (
            patch.object(filemanager, "record_filemgr_preview_hover_play_start") as record_start,
            patch.object(filemanager, "record_filemgr_preview_hover_play_failure") as record_failure,
            patch.object(filemanager, "audit_event") as audit_event,
        ):
            start_resp = filemanager.file_crypto_client_telemetry(
                inp=filemanager.FileCryptoTelemetryIn(
                    event="hover_play_start",
                    path="/docs/clip.mp4",
                ),
                user="user",
            )
            self.assertTrue(start_resp["ok"])
            record_start.assert_called_once_with()

            failure_resp = filemanager.file_crypto_client_telemetry(
                inp=filemanager.FileCryptoTelemetryIn(
                    event="hover_play_failure",
                    path="/docs/clip.mp4",
                    reason="playback_error",
                ),
                user="user",
            )
            self.assertTrue(failure_resp["ok"])
            record_failure.assert_called_once_with(reason="playback_error")
            self.assertEqual(audit_event.call_count, 2)

    def test_presign_and_complete_upload(self):
        with patch.object(
            filemanager,
            "presign_upload",
            return_value={
                "upload_url": "https://example.test/upload",
                "bucket": "bucket",
                "key": "user/objects/abc",
                "ticket_id": "ticket-1",
                "path": "/docs/a.txt",
                "content_type": "text/plain",
            },
        ):
            resp = filemanager.presign_fs_upload(
                inp=filemanager.PresignUploadIn(path="/docs/a.txt", content_type="text/plain"),
                user="user",
            )
            self.assertEqual(resp.ticket_id, "ticket-1")

        with patch.object(filemanager, "register_presigned_upload", return_value={"path": "/docs/a.txt", "size": 5}):
            resp = filemanager.complete_fs_upload(
                inp=filemanager.CompleteUploadIn(path="/docs/a.txt", key="user/objects/abc", ticket_id="ticket-1"),
                user="user",
            )
            self.assertTrue(resp["ok"])
            filemanager.register_presigned_upload.assert_called_once_with(
                "user",
                "/docs/a.txt",
                s3_key="user/objects/abc",
                ticket_id="ticket-1",
                content_type=None,
                encryption_meta=None,
            )


    def test_presign_upload_rejects_mounted_path(self):
        original_enabled = filemanager.S.filemgr_s3_mounts_enabled
        original_write = filemanager.S.filemgr_s3_mounts_write_enabled
        object.__setattr__(filemanager.S, "filemgr_s3_mounts_enabled", True)
        object.__setattr__(filemanager.S, "filemgr_s3_mounts_write_enabled", True)
        try:
            with (
                patch.object(filemanager, "resolve_path_mount", return_value={"id": "m1"}),
                patch.object(filemanager, "presign_upload") as presign_upload,
            ):
                with self.assertRaises(HTTPException) as ctx:
                    filemanager.presign_fs_upload(filemanager.PresignUploadIn(path="/mounts/a.txt"), user="user")
            self.assertEqual(ctx.exception.status_code, 400)
            presign_upload.assert_not_called()
        finally:
            object.__setattr__(filemanager.S, "filemgr_s3_mounts_enabled", original_enabled)
            object.__setattr__(filemanager.S, "filemgr_s3_mounts_write_enabled", original_write)

    def test_complete_upload_rejects_mounted_path(self):
        original_enabled = filemanager.S.filemgr_s3_mounts_enabled
        original_write = filemanager.S.filemgr_s3_mounts_write_enabled
        object.__setattr__(filemanager.S, "filemgr_s3_mounts_enabled", True)
        object.__setattr__(filemanager.S, "filemgr_s3_mounts_write_enabled", True)
        try:
            with (
                patch.object(filemanager, "resolve_path_mount", return_value={"id": "m1"}),
                patch.object(filemanager, "register_presigned_upload") as complete_upload,
            ):
                with self.assertRaises(HTTPException) as ctx:
                    filemanager.complete_fs_upload(
                        inp=filemanager.CompleteUploadIn(path="/mounts/a.txt", key="user/objects/abc", ticket_id="ticket-1"),
                        user="user",
                    )
            self.assertEqual(ctx.exception.status_code, 400)
            complete_upload.assert_not_called()
        finally:
            object.__setattr__(filemanager.S, "filemgr_s3_mounts_enabled", original_enabled)
            object.__setattr__(filemanager.S, "filemgr_s3_mounts_write_enabled", original_write)

    def test_complete_upload_bubbles_validation_errors(self):
        with patch.object(
            filemanager,
            "register_presigned_upload",
            side_effect=HTTPException(status_code=403, detail="invalid upload ticket"),
        ):
            with self.assertRaises(HTTPException) as ctx:
                filemanager.complete_fs_upload(
                    inp=filemanager.CompleteUploadIn(path="/docs/a.txt", key="user/objects/abc", ticket_id="bad"),
                    user="user",
                )
        self.assertEqual(ctx.exception.status_code, 403)



    def test_delete_root_route_dispatch(self):
        with (
            patch.object(filemanager, "remove_fs_file", return_value={"ok": True}) as remove_file_route,
            patch.object(filemanager, "remove_fs_folder", return_value={"ok": True, "deleted_count": 1}) as remove_folder_route,
        ):
            out_file = filemanager.remove_fs(path="/docs/a.txt", user="user")
            out_folder = filemanager.remove_fs(path="/docs/", user="user")
        self.assertTrue(out_file["ok"])
        self.assertTrue(out_folder["ok"])
        remove_file_route.assert_called_once()
        remove_folder_route.assert_called_once()

    def test_delete_root_route_blocks_mounted_folder(self):
        with patch.object(filemanager, "resolve_path_mount", return_value={"id": "m1"}):
            with self.assertRaises(HTTPException) as ctx:
                filemanager.remove_fs(path="/mounts/a/", user="user")
        self.assertEqual(ctx.exception.status_code, 400)

    def test_delete_mount_dispatch(self):
        original_enabled = filemanager.S.filemgr_s3_mounts_enabled
        original_write = filemanager.S.filemgr_s3_mounts_write_enabled
        object.__setattr__(filemanager.S, "filemgr_s3_mounts_enabled", True)
        object.__setattr__(filemanager.S, "filemgr_s3_mounts_write_enabled", True)
        try:
            with (
                patch.object(filemanager, "resolve_path_mount", return_value={"id": "m1"}),
                patch.object(filemanager, "delete_mounted_file") as delete_mounted,
                patch.object(filemanager, "remove_file") as remove_local,
                patch.object(filemanager, "_enforce_filemanager_internal_entitlement"),
            ):
                resp = filemanager.remove_fs_file(path="/mounts/a.txt", user="user")
            self.assertTrue(resp["ok"])
            delete_mounted.assert_called_once_with("user", "/mounts/a.txt")
            remove_local.assert_not_called()
        finally:
            object.__setattr__(filemanager.S, "filemgr_s3_mounts_enabled", original_enabled)
            object.__setattr__(filemanager.S, "filemgr_s3_mounts_write_enabled", original_write)

    def test_delete_and_move(self):
        with patch.object(filemanager, "remove_file") as remove_file, patch.object(
            filemanager, "_enforce_filemanager_internal_entitlement"
        ) as enforce_internal:
            resp = filemanager.remove_fs_file(path="/docs/a.txt", user="user")
            self.assertTrue(resp["ok"])
            remove_file.assert_called_once_with("user", "/docs/a.txt")
            enforce_internal.assert_called_once_with(user="user", action="delete_file", request_id=None)

        with patch.object(filemanager, "remove_folder", return_value=3):
            resp = filemanager.remove_fs_folder(path="/docs/", user="user")
            self.assertEqual(resp["deleted_count"], 3)

        with patch.object(filemanager, "move_node", return_value={"type": "file", "src": "/a", "dst": "/b"}):
            resp = filemanager.move_fs_node(src="/a", dst="/b", user="user")
            self.assertEqual(resp["type"], "file")


    def test_move_resume_and_rollback(self):
        with patch.object(filemanager, "resume_move", return_value={"move_id": "m1", "status": "completed", "moved_now": 2, "already_done": 1}):
            resp = filemanager.resume_fs_move(inp=filemanager.MoveCheckpointIn(move_id="m1"), user="user")
            self.assertTrue(resp["ok"])
            self.assertEqual(resp["move_id"], "m1")

        with patch.object(filemanager, "rollback_move", return_value={"move_id": "m1", "status": "rolled_back", "moved_now": 3, "already_done": 0}):
            resp = filemanager.rollback_fs_move(inp=filemanager.MoveCheckpointIn(move_id="m1"), user="user")
            self.assertTrue(resp["ok"])
            self.assertEqual(resp["status"], "rolled_back")



    def test_shared_preview_records_encrypted_access_dimensions(self):
        obj = {"Body": io.BytesIO(b"hello")}
        node = {"name": "a.txt", "type": "file", "content_type": "text/plain", "is_encrypted": False, "path": "/docs/a.txt", "size": 5}
        with (
            patch.object(filemanager, "require_shared_access"),
            patch.object(filemanager, "download_file", return_value={"node": node, "object": obj}),
            patch.object(filemanager, "audit_event") as audit_event,
            patch.object(filemanager, "record_filemgr_preview_attempt") as preview_attempt,
            patch.object(filemanager, "record_filemgr_preview_bytes") as preview_bytes,
            patch.object(filemanager, "record_filemgr_preview_latency") as preview_latency,
        ):
            resp = filemanager.shared_preview_fs_file(owner="owner", path="/docs/a.txt", user="user")
            self.assertIsInstance(resp, StreamingResponse)
            self.assertEqual(audit_event.call_args.kwargs["encrypted_shared_access_attempt"], False)
            self.assertEqual(audit_event.call_args.kwargs["share_scope"], "direct")
            self.assertEqual(audit_event.call_args.kwargs["preview_kind"], "document")
            self.assertEqual(audit_event.call_args.kwargs["preview_supported"], True)
            self.assertEqual(audit_event.call_args.kwargs["preview_reason"], "none")
            self.assertEqual(audit_event.call_args.kwargs["is_encrypted"], False)
            preview_attempt.assert_called_once_with(kind="document", outcome="success", reason="none")
            preview_bytes.assert_called_once_with(kind="document", nbytes=5)
            preview_latency.assert_called_once()

    def test_upload_archive_routes(self):
        upload = UploadFile(filename="files.tar", file=io.BytesIO(b"tar"))
        with patch.object(filemanager, "upload_archive", return_value=["/a.txt"]):
            resp = filemanager.upload_archive_and_extract(dest_folder="/", archive_file=upload, user="user")
            self.assertEqual(resp["count"], 1)

        with (
            patch.object(filemanager, "upload_archive", return_value=["/a.txt"]),
            patch.object(filemanager, "require_shared_access"),
        ):
            resp = filemanager.upload_shared_archive(owner="owner", dest_folder="/", archive_file=upload, user="user")
            self.assertTrue(resp["ok"])

    def test_rename_and_zip(self):
        with patch.object(filemanager, "move_node", return_value={"type": "file", "src": "/a", "dst": "/b"}) as move_node:
            resp = filemanager.rename_file(path="/a", new_name="b", user="user")
            self.assertTrue(resp["ok"])
            move_node.assert_called_once_with("user", "/a", "/b")

        with patch.object(filemanager, "move_node", return_value={"type": "folder", "src": "/a/", "dst": "/b/"}) as move_node:
            resp = filemanager.rename_folder(path="/a/", new_name="b", user="user")
            self.assertTrue(resp["ok"])
            move_node.assert_called_once_with("user", "/a/", "/b/")

        zip_stream = iter([b"zipdata"])
        with (
            patch.object(filemanager, "download_zip", return_value=zip_stream),
            patch.object(filemanager, "assert_download_allowed") as assert_download_allowed,
            patch.object(filemanager, "record_download_usage") as record_download_usage,
        ):
            resp = filemanager.download_multiple_as_zip(paths=["/a"], user="user")
            self.assertIsInstance(resp, StreamingResponse)
            self.assertEqual(resp.media_type, "application/zip")
            async def _consume_zip():
                async for _ in resp.body_iterator:
                    pass
            asyncio.run(_consume_zip())
            record_download_usage.assert_called_once_with("user", "/_zip/download.zip", 7, source="download_zip", request_id=None)
            assert_download_allowed.assert_called_once_with("user", requested_bytes=0)

        upload = UploadFile(filename="files.zip", file=io.BytesIO(b"zipdata"))
        with patch.object(filemanager, "upload_zip", return_value=["/a.txt"]):
            resp = filemanager.upload_zip_and_extract(dest_folder="/", zip_file=upload, user="user")
            self.assertEqual(resp["count"], 1)

    def test_sharing(self):
        with patch.object(filemanager, "share_node") as share_node:
            resp = filemanager.share_fs_node(path="/a", to_user="bob", user="user")
            self.assertTrue(resp["ok"])
            share_node.assert_called_once_with(
                "user",
                "/a",
                "bob",
                permission="read",
                expires_at=None,
                signature_packet_id=None,
            )

        with patch.object(filemanager, "share_node") as share_node:
            resp = filemanager.share_fs_node(path="/a", to_user="bob", signature_packet_id="sp_123", user="user")
            self.assertTrue(resp["ok"])
            share_node.assert_called_once_with(
                "user",
                "/a",
                "bob",
                permission="read",
                expires_at=None,
                signature_packet_id="sp_123",
            )

        with patch.object(filemanager, "list_shared_with", return_value=["bob"]):
            resp = filemanager.list_shared(path="/a", user="user")
            self.assertEqual(resp["shared_with"], ["bob"])

        with patch.object(filemanager, "list_shared_with_me", return_value=[{
            "owner": "alice",
            "path": "/a",
            "is_encrypted": True,
            "enc_version": 1,
            "enc_alg": "AES-256-GCM",
            "signature_packet_id": "sp_123",
        }]):
            resp = filemanager.list_shared_me(user="user")
            self.assertEqual(resp["items"][0]["owner"], "alice")
            self.assertTrue(resp["items"][0]["is_encrypted"])
            self.assertEqual(resp["items"][0]["enc_alg"], "AES-256-GCM")
            self.assertEqual(resp["items"][0]["signature_packet_id"], "sp_123")


    def test_shared_list_and_info_include_preview_contract(self):
        shared_node = {
            "path": "/docs/table.csv",
            "type": "file",
            "name": "table.csv",
            "parent": "/docs/",
            "content_type": "text/csv",
            "is_encrypted": False,
            "size": 100,
        }
        with (
            patch.object(filemanager, "require_shared_access"),
            patch.object(filemanager, "list_children_page", return_value=([shared_node], None)),
            patch.object(filemanager, "get_node", return_value=shared_node),
        ):
            listed = filemanager.list_shared_files(owner="owner", path="/docs", sort_by="name", user="user")
            self.assertEqual(listed["items"][0]["preview_kind"], "document")
            self.assertEqual(listed["items"][0]["preview_status"], "ready")
            self.assertIsNone(listed["items"][0]["poster_url"])
            self.assertIsNone(listed["items"][0]["hover_preview_url"])
            self.assertIsNone(listed["items"][0]["waveform_url"])
            self.assertTrue(listed["items"][0]["preview_supported"])
            self.assertIsNone(listed["items"][0]["preview_reason"])

            info = filemanager.shared_file_info(owner="owner", path="/docs/table.csv", user="user")
            self.assertEqual(info["preview_kind"], "document")
            self.assertEqual(info["preview_status"], "ready")
            self.assertIsNone(info["poster_url"])
            self.assertIsNone(info["hover_preview_url"])
            self.assertIsNone(info["waveform_url"])
            self.assertTrue(info["preview_supported"])
            self.assertIsNone(info["preview_reason"])

    def test_shared_download_and_shared_zip_metering(self):
        obj = {"Body": io.BytesIO(b"hello")}
        node = {"name": "a.txt", "type": "file", "content_type": "text/plain", "is_encrypted": False, "path": "/docs/a.txt", "size": 5}
        with (
            patch.object(filemanager, "require_shared_access"),
            patch.object(filemanager, "download_file", return_value={"node": node, "object": obj}),
            patch.object(filemanager, "assert_download_allowed") as assert_download_allowed,
            patch.object(filemanager, "record_download_usage") as record_download_usage,
            patch.object(filemanager, "record_filemgr_encryption_event") as record_encryption_event,
            patch.object(filemanager, "record_filemgr_shared_download") as record_shared_download,
            patch.object(filemanager, "audit_event") as audit_event,
        ):
            resp = filemanager.shared_download_fs_file(owner="owner", path="/docs/a.txt", user="user")
            self.assertIsInstance(resp, StreamingResponse)
            async def _consume():
                async for _ in resp.body_iterator:
                    pass
            asyncio.run(_consume())
            record_download_usage.assert_called_once_with("user", "/docs/a.txt", 5, source="shared_download", request_id=None)
            assert_download_allowed.assert_called_once_with("user", requested_bytes=5)
            record_encryption_event.assert_called_once_with("download_attempt", encrypted=False)
            record_shared_download.assert_called_once_with(encrypted=False, outcome="attempt")
            self.assertEqual(audit_event.call_args.kwargs["encrypted_shared_access_attempt"], False)
            self.assertEqual(audit_event.call_args.kwargs["share_scope"], "direct")

        with (
            patch.object(filemanager, "require_shared_access"),
            patch.object(filemanager, "download_zip", return_value=(iter([b"ab", b"cd"]), 2)),
            patch.object(filemanager, "assert_download_allowed") as assert_download_allowed,
            patch.object(filemanager, "record_download_usage") as record_download_usage,
        ):
            resp = filemanager.shared_download_zip(owner="owner", paths=["/docs/a.txt"], user="user")
            self.assertIsInstance(resp, StreamingResponse)
            async def _consume_zip():
                async for _ in resp.body_iterator:
                    pass
            asyncio.run(_consume_zip())
            record_download_usage.assert_called_once_with("user", "/_zip/shared-download.zip", 4, source="shared_download_zip", request_id=None)
            assert_download_allowed.assert_called_once_with("user", requested_bytes=0)

    def test_list_files_shows_ready_video_and_audio_artifacts(self):
        items = [
            {
                "path": "/docs/clip.mp4",
                "type": "file",
                "name": "clip.mp4",
                "parent": "/docs/",
                "content_type": "video/mp4",
                "size": 100,
                "s3_bucket": "bucket",
                "media_preview_status": "ready",
                "media_inspection": {"container": "mp4", "primary_video_codec": "h264", "duration_seconds": 8},
                "media_preview_keys": {
                    "poster_image": "owner/derived/media/ver/poster_image.webp",
                    "hover_clip": "owner/derived/media/ver/hover_clip.mp4",
                },
                "is_encrypted": False,
            },
            {
                "path": "/docs/track.mp3",
                "type": "file",
                "name": "track.mp3",
                "parent": "/docs/",
                "content_type": "audio/mpeg",
                "size": 80,
                "s3_bucket": "bucket",
                "media_preview_status": "ready",
                "media_inspection": {"container": "mp3", "primary_audio_codec": "mp3", "duration_seconds": 12},
                "media_preview_keys": {
                    "waveform_image": "owner/derived/media/ver/waveform_image.png",
                },
                "is_encrypted": False,
            },
        ]
        with (
            patch.object(filemanager, "list_children_page", return_value=(items, None)),
            patch(
                "app.services.filemanager.S",
                SimpleNamespace(
                    filemgr_media_previews_v1=True,
                    filemgr_video_hover_clip_enabled=True,
                    filemgr_audio_waveform_enabled=True,
                    filemgr_preview_max_bytes=10485760,
                    filemgr_video_preview_max_mb=200,
                    filemgr_video_preview_max_duration_seconds=600,
                    filemgr_audio_waveform_max_mb=100,
                    filemgr_media_preview_cdn_base_url="https://cdn.example",
                    filemgr_media_preview_private=False,
                    filemgr_media_preview_url_ttl_seconds=900,
                ),
            ),
        ):
            resp = filemanager.list_files(path="/docs", sort_by="name", user="owner")

        by_name = {item["name"]: item for item in resp["items"]}
        self.assertEqual(by_name["clip.mp4"]["poster_url"], "https://cdn.example/owner/derived/media/ver/poster_image.webp")
        self.assertEqual(by_name["clip.mp4"]["hover_preview_url"], "https://cdn.example/owner/derived/media/ver/hover_clip.mp4")
        self.assertEqual(by_name["track.mp3"]["waveform_url"], "https://cdn.example/owner/derived/media/ver/waveform_image.png")

    def test_shared_media_preview_access_denied_without_permission(self):
        with patch.object(filemanager, "require_shared_access", side_effect=HTTPException(status_code=403, detail="forbidden")):
            with self.assertRaises(HTTPException) as list_ctx:
                filemanager.list_shared_files(owner="owner", path="/docs", user="intruder")
            with self.assertRaises(HTTPException) as info_ctx:
                filemanager.shared_file_info(owner="owner", path="/docs/clip.mp4", user="intruder")

        self.assertEqual(list_ctx.exception.status_code, 403)
        self.assertEqual(info_ctx.exception.status_code, 403)

    def test_usage_endpoints(self):
        with patch.object(filemanager, "get_usage_summary", return_value={"period_id": "2026-02"}) as summary:
            resp = filemanager.usage_summary(period="2026-02", user="user")
            self.assertEqual(resp["period_id"], "2026-02")
            summary.assert_called_once_with("user", period_id="2026-02")

        with patch.object(filemanager, "get_usage_daily", return_value={"items": []}) as daily:
            resp = filemanager.usage_daily(from_day="2026-02-01", to_day="2026-02-28", user="user")
            self.assertEqual(resp["items"], [])
            daily.assert_called_once_with("user", from_day="2026-02-01", to_day="2026-02-28")

        with patch.object(filemanager, "get_usage_storage", return_value={"storage_bytes_current": 123}) as storage:
            resp = filemanager.usage_storage(top_n=5, user="user")
            self.assertEqual(resp["storage_bytes_current"], 123)
            storage.assert_called_once_with("user", top_n=5)


    def test_download_denied_by_file_bundle_entitlement_payload(self):
        obj = {"Body": io.BytesIO(b"hello")}
        node = {"name": "a.txt", "content_type": "text/plain", "is_encrypted": False, "path": "/docs/a.txt", "size": 5}
        deny = HTTPException(
            status_code=403,
            detail={
                "code": "file_bundle_access_denied",
                "reason": "out_of_scope",
                "message": "File timestamp is outside entitled date range",
                "required_product_type": "file_bundle",
            },
        )
        with (
            patch.object(filemanager, "download_file", return_value={"node": node, "object": obj}),
            patch.object(filemanager, "assert_file_bundle_access", side_effect=deny),
        ):
            with self.assertRaises(HTTPException) as ctx:
                filemanager.download_fs_file(path="/docs/a.txt", user="user")
        self.assertEqual(ctx.exception.status_code, 403)
        self.assertEqual(ctx.exception.detail["code"], "file_bundle_access_denied")
        self.assertEqual(ctx.exception.detail["reason"], "out_of_scope")

    def test_preview_denied_by_expired_file_bundle_entitlement_payload(self):
        obj = {"Body": io.BytesIO(b"hello")}
        node = {"name": "a.txt", "type": "file", "content_type": "text/plain", "is_encrypted": False, "path": "/docs/a.txt", "size": 5}
        deny = HTTPException(
            status_code=403,
            detail={
                "code": "file_bundle_access_denied",
                "reason": "expired_entitlement",
                "message": "File bundle entitlement has expired",
                "required_product_type": "file_bundle",
            },
        )
        with (
            patch.object(filemanager, "download_file", return_value={"node": node, "object": obj}),
            patch.object(filemanager, "assert_file_bundle_access", side_effect=deny),
        ):
            with self.assertRaises(HTTPException) as ctx:
                filemanager.preview_fs_file(path="/docs/a.txt", user="user")
        self.assertEqual(ctx.exception.status_code, 403)
        self.assertEqual(ctx.exception.detail["code"], "file_bundle_access_denied")
        self.assertEqual(ctx.exception.detail["reason"], "expired_entitlement")

    def test_file_mount_routes_disabled_by_flag(self):
        original_enabled = filemanager.S.filemgr_s3_mounts_enabled
        try:
            object.__setattr__(filemanager.S, "filemgr_s3_mounts_enabled", False)
            with self.assertRaises(HTTPException) as exc:
                filemanager.list_file_mounts(user="user")
            self.assertEqual(exc.exception.status_code, 404)
        finally:
            object.__setattr__(filemanager.S, "filemgr_s3_mounts_enabled", original_enabled)

    def test_file_mount_list_enabled_uses_service(self):
        original_enabled = filemanager.S.filemgr_s3_mounts_enabled
        try:
            object.__setattr__(filemanager.S, "filemgr_s3_mounts_enabled", True)
            rows = [
                {
                    "id": "m1",
                    "owner": "user",
                    "provider": "s3",
                    "mount_path": "/mounts/a/",
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
            ]
            with patch.object(filemanager, "list_file_mounts_records", return_value=[SimpleNamespace(model_dump=lambda: r) for r in rows]):
                resp = filemanager.list_file_mounts(user="user")
            self.assertEqual(len(resp.items), 1)
            self.assertEqual(resp.items[0].id, "m1")
            self.assertEqual(resp.items[0].status, "active")

            degraded = {**rows[0], "status": "degraded", "last_error": "s3 access denied", "last_check_at": "2026-01-02T00:00:00+00:00"}
            with patch.object(filemanager, "list_file_mounts_records", return_value=[SimpleNamespace(model_dump=lambda: degraded)]):
                degraded_resp = filemanager.list_file_mounts(user="user")
            self.assertEqual(degraded_resp.items[0].status, "degraded")
            self.assertEqual(degraded_resp.items[0].last_error, "s3 access denied")
        finally:
            object.__setattr__(filemanager.S, "filemgr_s3_mounts_enabled", original_enabled)


    def test_file_mount_crud_routes_enabled(self):
        original_enabled = filemanager.S.filemgr_s3_mounts_enabled
        original_write = filemanager.S.filemgr_s3_mounts_write_enabled
        payload = {
            "id": "m1",
            "owner": "user",
            "provider": "s3",
            "mount_path": "/mounts/a/",
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
        try:
            object.__setattr__(filemanager.S, "filemgr_s3_mounts_enabled", True)
            object.__setattr__(filemanager.S, "filemgr_s3_mounts_write_enabled", True)
            with (
                patch.object(filemanager, "create_file_mount_record", return_value=SimpleNamespace(model_dump=lambda: payload)) as create_mount,
                patch.object(filemanager, "get_file_mount_record", return_value=SimpleNamespace(model_dump=lambda: payload, id="m1", status="active")) as get_mount,
                patch.object(filemanager, "update_file_mount_record", return_value=SimpleNamespace(model_dump=lambda: {**payload, "mode": "read_write"})) as update_mount,
                patch.object(filemanager, "delete_file_mount_record", return_value={"ok": True, "deleted": True}) as delete_mount,
            ):
                created = filemanager.create_file_mount(filemanager.FileMountCreateIn(mount_path="/mounts/a", bucket="acme-bucket", mode="read_only", auth_ref="cred-1"), user="user")
                fetched = filemanager.get_file_mount("m1", user="user")
                updated = filemanager.update_file_mount("m1", filemanager.FileMountUpdateIn(mode="read_write"), user="user")
                validated = filemanager.validate_file_mount("m1", user="user")
                deleted = filemanager.delete_file_mount("m1", user="user")

            self.assertEqual(created.id, "m1")
            self.assertEqual(fetched.id, "m1")
            self.assertEqual(updated.mode, "read_write")
            self.assertTrue(validated.ok)
            self.assertTrue(deleted.deleted)
            create_mount.assert_called_once()
            get_mount.assert_called()
            update_mount.assert_called_once()
            delete_mount.assert_called_once()
        finally:
            object.__setattr__(filemanager.S, "filemgr_s3_mounts_enabled", original_enabled)
            object.__setattr__(filemanager.S, "filemgr_s3_mounts_write_enabled", original_write)

    def test_file_mount_create_requires_write_flag(self):
        original_enabled = filemanager.S.filemgr_s3_mounts_enabled
        original_write = filemanager.S.filemgr_s3_mounts_write_enabled
        try:
            object.__setattr__(filemanager.S, "filemgr_s3_mounts_enabled", True)
            object.__setattr__(filemanager.S, "filemgr_s3_mounts_write_enabled", False)
            with self.assertRaises(HTTPException) as exc:
                filemanager.create_file_mount(filemanager.FileMountCreateIn(mount_path="/mounts/a", bucket="acme-bucket", mode="read_only", auth_ref="cred-1"), user="user")
            self.assertEqual(exc.exception.status_code, 403)
            self.assertEqual(exc.exception.detail.get("feature"), "filemgr_s3_mounts_write")
        finally:
            object.__setattr__(filemanager.S, "filemgr_s3_mounts_enabled", original_enabled)
            object.__setattr__(filemanager.S, "filemgr_s3_mounts_write_enabled", original_write)



    def test_openapi_includes_mount_paths(self):
        from app.main import create_app

        app = create_app()
        schema = app.openapi()
        paths = schema.get("paths", {})
        self.assertIn("/v1/fs/mounts", paths)
        self.assertIn("/v1/fs/mounts/{mount_id}", paths)
        self.assertIn("/v1/fs/mounts/{mount_id}/validate", paths)
