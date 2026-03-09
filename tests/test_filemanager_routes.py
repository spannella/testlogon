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




    def test_upload_route_passes_overwrite_to_dispatched_upload(self):
        upload = UploadFile(filename="a.txt", file=io.BytesIO(b"hello"), headers={"content-type": "text/plain"})
        with (
            patch.object(filemanager, "S", SimpleNamespace(filemgr_google_drive_mounts_enabled=True)),
            patch.object(filemanager, "upload_file_dispatched", return_value={"path": "/integrations/drive/a.txt", "size": 5}) as upload_file_dispatched,
            patch.object(filemanager, "record_filemgr_encryption_event"),
        ):
            resp = filemanager.upload_fs_file(path="/integrations/drive/a.txt", file=upload, overwrite=True, user="user")
            self.assertTrue(resp["ok"])
        self.assertTrue(upload_file_dispatched.call_args.kwargs["overwrite"])


    def test_write_routes_reject_read_only_mount(self):
        denied = HTTPException(status_code=403, detail={"code": "mount_read_only", "mode": "read_only"})
        with patch.object(filemanager, "assert_mount_write_allowed", side_effect=denied):
            with self.assertRaises(HTTPException) as create_exc:
                filemanager.create_folder(path="/integrations/drive/new/", user="user")
            with self.assertRaises(HTTPException) as upload_exc:
                filemanager.upload_fs_file(path="/integrations/drive/a.txt", file=UploadFile(filename="a.txt", file=io.BytesIO(b"a")), user="user")
            with self.assertRaises(HTTPException) as delete_exc:
                filemanager.remove_fs_file(path="/integrations/drive/a.txt", user="user")

        self.assertEqual(create_exc.exception.status_code, 403)
        self.assertEqual(upload_exc.exception.detail["code"], "mount_read_only")
        self.assertEqual(delete_exc.exception.status_code, 403)


    def test_download_route_uses_dispatched_download_when_mounts_enabled(self):
        obj = {"Body": io.BytesIO(b"hello")}
        node = {"name": "a.txt", "content_type": "text/plain", "is_encrypted": False, "path": "/integrations/drive/a.txt", "size": 5}
        with (
            patch.object(filemanager, "S", SimpleNamespace(filemgr_google_drive_mounts_enabled=True)),
            patch.object(filemanager, "download_file_dispatched", return_value={"node": node, "object": obj}) as download_file_dispatched,
            patch.object(filemanager, "assert_download_allowed"),
            patch.object(filemanager, "record_download_usage"),
            patch.object(filemanager, "record_filemgr_encryption_event"),
        ):
            resp = filemanager.download_fs_file(path="/integrations/drive/a.txt", user="user")
            self.assertIsInstance(resp, StreamingResponse)
        download_file_dispatched.assert_called_once_with("user", "/integrations/drive/a.txt")


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



    def test_move_route_uses_dispatched_move_when_mounts_enabled(self):
        with (
            patch.object(filemanager, "S", SimpleNamespace(filemgr_google_drive_mounts_enabled=True)),
            patch.object(filemanager, "move_node_dispatched", return_value={"type": "file", "src": "/integrations/drive/a.txt", "dst": "/integrations/drive/b.txt"}) as move_node_dispatched,
        ):
            resp = filemanager.move_fs_node(src="/integrations/drive/a.txt", dst="/integrations/drive/b.txt", user="user")
        self.assertTrue(resp["ok"])
        move_node_dispatched.assert_called_once_with("user", "/integrations/drive/a.txt", "/integrations/drive/b.txt")


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

    def test_mount_create_route_validates_provider_root_and_persists(self):
        body = filemanager.MountCreateIn(
            provider="google_drive",
            mount_path="/integrations/drive",
            provider_root_ref="gdrive://me/items/root",
            mode="read_only",
        )
        provider_client = SimpleNamespace(
            resolve=lambda ref: "gdrive://me/items/root",
            exists=lambda ref: True,
        )
        stored = SimpleNamespace(
            model_dump=lambda: {
                "mount_id": "m-1",
                "owner": "user-1",
                "provider": "google_drive",
                "mount_path": "/integrations/drive/",
                "provider_root_ref": "gdrive://me/items/root",
                "mode": "read_only",
                "created_at": "2026-01-01T00:00:00+00:00",
                "updated_at": "2026-01-01T00:00:00+00:00",
            }
        )
        registry = SimpleNamespace(get=lambda owner, provider: provider_client)
        with (
            patch.object(filemanager, "S", SimpleNamespace(filemgr_google_drive_mounts_enabled=True)),
            patch.object(filemanager, "_enforce_filemanager_internal_entitlement") as enforce_internal,
            patch.object(filemanager, "default_provider_registry", return_value=registry),
            patch.object(filemanager, "create_mount", return_value=stored) as create_mount,
        ):
            out = filemanager.create_mount_route(body, user="user-1")

        self.assertEqual(out.provider, "google_drive")
        enforce_internal.assert_called_once_with(user="user-1", action="mount_create")
        create_mount.assert_called_once()

    def test_mount_create_route_raises_404_when_provider_root_missing(self):
        body = filemanager.MountCreateIn(
            provider="google_drive",
            mount_path="/integrations/drive",
            provider_root_ref="gdrive://me/items/missing",
            mode="read_only",
        )
        provider_client = SimpleNamespace(
            resolve=lambda ref: "gdrive://me/items/missing",
            exists=lambda ref: False,
        )
        registry = SimpleNamespace(get=lambda owner, provider: provider_client)
        with (
            patch.object(filemanager, "S", SimpleNamespace(filemgr_google_drive_mounts_enabled=True)),
            patch.object(filemanager, "_enforce_filemanager_internal_entitlement"),
            patch.object(filemanager, "default_provider_registry", return_value=registry),
        ):
            with self.assertRaises(HTTPException) as ctx:
                filemanager.create_mount_route(body, user="user-1")

        self.assertEqual(ctx.exception.status_code, 404)

    def test_mount_list_update_delete_routes(self):
        listed = [
            SimpleNamespace(
                model_dump=lambda: {
                    "mount_id": "m-1",
                    "owner": "user-1",
                    "provider": "google_drive",
                    "mount_path": "/integrations/drive/",
                    "provider_root_ref": "gdrive://me/items/root",
                    "mode": "read_only",
                    "created_at": "2026-01-01T00:00:00+00:00",
                    "updated_at": "2026-01-01T00:00:00+00:00",
                }
            )
        ]
        updated = SimpleNamespace(
            model_dump=lambda: {
                "mount_id": "m-1",
                "owner": "user-1",
                "provider": "google_drive",
                "mount_path": "/integrations/drive/",
                "provider_root_ref": "gdrive://me/items/root2",
                "mode": "read_write",
                "created_at": "2026-01-01T00:00:00+00:00",
                "updated_at": "2026-01-02T00:00:00+00:00",
            }
        )
        provider_client = SimpleNamespace(
            resolve=lambda ref: "gdrive://me/items/root2",
            exists=lambda ref: True,
        )
        registry = SimpleNamespace(get=lambda owner, provider: provider_client)
        existing = SimpleNamespace(provider="google_drive")
        with (
            patch.object(filemanager, "S", SimpleNamespace(filemgr_google_drive_mounts_enabled=True)),
            patch.object(filemanager, "_enforce_filemanager_internal_entitlement"),
            patch.object(filemanager, "list_mounts", return_value=listed),
            patch.object(filemanager, "get_mount", return_value=existing),
            patch.object(filemanager, "default_provider_registry", return_value=registry),
            patch.object(filemanager, "update_mount", return_value=updated),
            patch.object(filemanager, "delete_mount", return_value={"ok": True, "deleted": True}),
        ):
            list_out = filemanager.list_mounts_route(user="user-1")
            self.assertEqual(len(list_out.items), 1)

            body = filemanager.MountUpdateIn(provider_root_ref="gdrive://me/items/root2", mode="read_write")
            patch_out = filemanager.update_mount_route("m-1", body, user="user-1")
            self.assertEqual(patch_out.mode, "read_write")

            delete_out = filemanager.delete_mount_route("m-1", user="user-1")
            self.assertTrue(delete_out.deleted)

    def test_mount_conflict_propagates_clear_409(self):
        body = filemanager.MountCreateIn(
            provider="google_drive",
            mount_path="/integrations/drive",
            provider_root_ref="gdrive://me/items/root",
            mode="read_only",
        )
        provider_client = SimpleNamespace(
            resolve=lambda ref: "gdrive://me/items/root",
            exists=lambda ref: True,
        )
        registry = SimpleNamespace(get=lambda owner, provider: provider_client)
        with (
            patch.object(filemanager, "S", SimpleNamespace(filemgr_google_drive_mounts_enabled=True)),
            patch.object(filemanager, "_enforce_filemanager_internal_entitlement"),
            patch.object(filemanager, "default_provider_registry", return_value=registry),
            patch.object(filemanager, "create_mount", side_effect=HTTPException(status_code=409, detail="mount path overlaps existing mount")),
        ):
            with self.assertRaises(HTTPException) as ctx:
                filemanager.create_mount_route(body, user="user-1")

        self.assertEqual(ctx.exception.status_code, 409)
        self.assertIn("overlaps", ctx.exception.detail)


    def test_mount_routes_reject_when_feature_flag_disabled(self):
        body = filemanager.MountCreateIn(
            provider="google_drive",
            mount_path="/integrations/drive",
            provider_root_ref="gdrive://me/items/root",
            mode="read_only",
        )
        with (
            patch.object(filemanager, "S", SimpleNamespace(filemgr_google_drive_mounts_enabled=False)),
            patch.object(filemanager, "_enforce_filemanager_internal_entitlement"),
        ):
            with self.assertRaises(HTTPException) as create_exc:
                filemanager.create_mount_route(body, user="user-1")
            with self.assertRaises(HTTPException) as list_exc:
                filemanager.list_mounts_route(user="user-1")
            with self.assertRaises(HTTPException) as patch_exc:
                filemanager.update_mount_route("m-1", filemanager.MountUpdateIn(mode="read_only"), user="user-1")
            with self.assertRaises(HTTPException) as delete_exc:
                filemanager.delete_mount_route("m-1", user="user-1")

        self.assertEqual(create_exc.exception.status_code, 501)
        self.assertEqual(create_exc.exception.detail["code"], "feature_not_enabled")
        self.assertEqual(list_exc.exception.status_code, 501)
        self.assertEqual(patch_exc.exception.status_code, 501)
        self.assertEqual(delete_exc.exception.status_code, 501)

    def test_admin_reconcile_mounts_route_returns_stale_items(self):
        rows = [
            {
                "owner": "user-1",
                "mount_id": "m-1",
                "provider": "google_drive",
                "mount_path": "/integrations/drive/",
                "provider_root_ref": "gdrive://me/items/root",
                "stale": True,
                "issues": ["revoked_credential"],
                "recommended_actions": ["disable_mount", "prompt_reconnect"],
                "status": "active",
                "reconnect_required": True,
            }
        ]
        ctx = {"user_sub": "admin-1", "role": "admin"}
        with (
            patch.object(filemanager, "S", SimpleNamespace(filemgr_google_drive_mounts_enabled=True)),
            patch.object(filemanager, "reconcile_mounts", return_value=rows) as reconcile_mounts,
            patch.object(filemanager, "audit_event") as audit_event,
        ):
            out = filemanager.admin_reconcile_mounts_route(owner="user-1", ctx=ctx)
        self.assertEqual(len(out.items), 1)
        self.assertTrue(out.items[0].stale)
        reconcile_mounts.assert_called_once_with("user-1")
        audit_event.assert_called_once()

    def test_admin_disable_mount_route_sets_disabled(self):
        updated = SimpleNamespace(
            model_dump=lambda: {
                "mount_id": "m-1",
                "owner": "user-1",
                "provider": "google_drive",
                "mount_path": "/integrations/drive/",
                "provider_root_ref": "gdrive://me/items/root",
                "mode": "read_only",
                "status": "disabled",
                "status_reason": "revoked_credential",
                "reconnect_required": True,
                "last_checked_at": "2026-01-02T00:00:00+00:00",
                "created_at": "2026-01-01T00:00:00+00:00",
                "updated_at": "2026-01-02T00:00:00+00:00",
            }
        )
        ctx = {"user_sub": "admin-1", "role": "admin"}
        with (
            patch.object(filemanager, "S", SimpleNamespace(filemgr_google_drive_mounts_enabled=True)),
            patch.object(filemanager, "set_mount_status", return_value=updated) as set_mount_status,
            patch.object(filemanager, "audit_event") as audit_event,
        ):
            out = filemanager.admin_disable_mount_route("m-1", owner="user-1", reason="revoked_credential", ctx=ctx)
        self.assertEqual(out.status, "disabled")
        set_mount_status.assert_called_once_with(
            "user-1",
            "m-1",
            status="disabled",
            status_reason="revoked_credential",
            reconnect_required=True,
        )
        audit_event.assert_called_once()
