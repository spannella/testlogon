import unittest
import asyncio
from unittest.mock import patch

from fastapi import HTTPException

from app.routers import filemanager as routes


class _Mount:
    def __init__(self, **kwargs):
        self.id = kwargs.get("id", "m1")
        self.owner = kwargs.get("owner", "u1")
        self.host = kwargs.get("host", "sftp.example.com")
        self.port = kwargs.get("port", 22)
        self.auth_credential_ref = kwargs.get("auth_credential_ref", "cred-1")
        self.remote_root = kwargs.get("remote_root", "/")
        self.read_only = kwargs.get("read_only", False)
        self.status = kwargs.get("status", "healthy")
        self.created_at = kwargs.get("created_at", "t1")
        self.updated_at = kwargs.get("updated_at", "t1")
        self.last_tested_at = kwargs.get("last_tested_at")
        self.last_status_change_at = kwargs.get("last_status_change_at")
        self.last_error_code = kwargs.get("last_error_code")
        self.last_error_message = kwargs.get("last_error_message")


async def _consume_response(resp):
    chunks = []
    async for c in resp.body_iterator:
        chunks.append(c)
    return b"".join(chunks)


class TestSftpMountLifecycleRoutes(unittest.TestCase):

    def test_share_endpoint_rejects_mounted_paths_explicitly(self):
        with (
            patch.object(routes, 'S') as settings,
            patch.object(routes, 'get_sftp_mount', return_value=_Mount(id='m1', owner='u1', status='healthy')),
        ):
            settings.filemgr_sftp_mounts_enabled = True
            settings.filemgr_sftp_mounts_share_enabled = True
            settings.filemgr_sftp_mounts_write_enabled = True
            with self.assertRaises(HTTPException) as exc:
                routes.share_fs_node(path='/mounts/m1/file.txt', to_user='u2', user='u1')
        self.assertEqual(exc.exception.status_code, 403)
        self.assertEqual(exc.exception.detail.get('code'), 'sftp_mount_share_not_allowed')

    def test_mock_files_endpoint_returns_listing_for_mock_backend(self):
        ctx = {"user_sub": "u1", "role": "user"}
        with (
            patch.object(routes, "get_sftp_mount", return_value=_Mount(id="m1", owner="u1")),
            patch.object(routes, "_list_mock_sftp_dir", return_value={"backend": "mock", "path": "/", "items": [{"name": "readme.txt", "path": "/readme.txt", "type": "file", "size": 4, "modified_at": 1}], "limit": 200, "cursor": None, "filesystem_path": "/tmp/filemgr-sftp-mock/u1/m1"}) as ls,
        ):
            out = routes.list_sftp_mount_mock_files_endpoint("m1", path="/", limit=200, cursor=None, ctx=ctx)

        self.assertEqual(out["mount_id"], "m1")
        self.assertEqual(len(out["items"]), 1)
        self.assertEqual(out.get("filesystem_path"), "/tmp/filemgr-sftp-mock/u1/m1")
        ls.assert_called_once_with(owner="u1", mount_id="m1", sub_path="/", limit=200, cursor=None, actor_sub="u1")


    def test_mock_files_endpoint_supports_limit_and_cursor_shape(self):
        ctx = {"user_sub": "u1", "role": "user"}
        with (
            patch.object(routes, "get_sftp_mount", return_value=_Mount(id="m1", owner="u1")),
            patch.object(
                routes,
                "_list_mock_sftp_dir",
                return_value={
                    "backend": "mock",
                    "path": "/",
                    "items": [{"name": "a.txt", "path": "/a.txt", "type": "file", "size": 1, "modified_at": 1}],
                    "limit": 1,
                    "cursor": "next-cursor",
                },
            ) as ls,
        ):
            out = routes.list_sftp_mount_mock_files_endpoint("m1", path="/", limit=1, cursor="c0", ctx=ctx)

        self.assertEqual(out["limit"], 1)
        self.assertEqual(out["cursor"], "next-cursor")
        ls.assert_called_once_with(owner="u1", mount_id="m1", sub_path="/", limit=1, cursor="c0", actor_sub="u1")

    def test_mock_files_helper_paginates_and_returns_stable_errors(self):
        import os
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            base = os.path.join(tmp, "u1", "m1", "root")
            os.makedirs(base, exist_ok=True)
            for idx in range(3):
                with open(os.path.join(base, f"f{idx}.txt"), "wb") as fp:
                    fp.write(b"x")

            with patch.object(routes, "S") as settings:
                settings.filemgr_sftp_backend = "mock"
                settings.filemgr_sftp_mock_root_dir = tmp
                settings.filemgr_sftp_mock_path_max_depth = 32
                settings.filemgr_sftp_mock_scan_max_entries = 1000
                settings.filemgr_sftp_mock_rate_limit_per_minute = 1000

                first = routes._list_mock_sftp_dir(owner="u1", mount_id="m1", sub_path="/root", limit=2, actor_sub="u1")
                self.assertEqual(first["limit"], 2)
                self.assertEqual(len(first["items"]), 2)
                self.assertTrue(first["cursor"])

                second = routes._list_mock_sftp_dir(owner="u1", mount_id="m1", sub_path="/root", limit=2, cursor=first["cursor"], actor_sub="u1")
                self.assertEqual(len(second["items"]), 1)
                self.assertIsNone(second["cursor"])

                with self.assertRaises(HTTPException) as bad_path:
                    routes._list_mock_sftp_dir(owner="u1", mount_id="m1", sub_path="../oops", limit=2, actor_sub="u1")
                self.assertEqual(bad_path.exception.status_code, 400)
                self.assertEqual(bad_path.exception.detail.get("code"), "mock_path_invalid")

                file_path = os.path.join(tmp, "u1", "m1", "single.txt")
                with open(file_path, "wb") as fp:
                    fp.write(b"x")
                with self.assertRaises(HTTPException) as not_dir:
                    routes._list_mock_sftp_dir(owner="u1", mount_id="m1", sub_path="/single.txt", limit=2, actor_sub="u1")
                self.assertEqual(not_dir.exception.detail.get("code"), "mock_path_not_directory")

                with self.assertRaises(HTTPException) as missing:
                    routes._list_mock_sftp_dir(owner="u1", mount_id="m1", sub_path="/missing", limit=2, actor_sub="u1")
                self.assertEqual(missing.exception.status_code, 404)
                self.assertEqual(missing.exception.detail.get("code"), "mock_path_not_found")

    def test_mock_files_endpoint_rejects_when_not_mock_backend(self):
        with patch.object(routes, "S") as settings:
            settings.filemgr_sftp_backend = "paramiko"
            with self.assertRaises(HTTPException) as exc:
                routes._list_mock_sftp_dir(owner="u1", mount_id="m1", sub_path="/", actor_sub="u1")
        self.assertEqual(exc.exception.status_code, 409)
        self.assertEqual(exc.exception.detail.get("code"), "sftp_mock_backend_disabled")

    def test_mock_files_endpoint_admin_scoped_owner_and_audit(self):
        ctx = {"user_sub": "admin1", "role": "admin"}
        with (
            patch.object(routes, "get_sftp_mount", return_value=_Mount(id="m1", owner="u2")),
            patch.object(routes, "_list_mock_sftp_dir", return_value={"backend": "mock", "path": "/", "items": [], "limit": 200, "cursor": None, "filesystem_path": "/tmp/filemgr-sftp-mock/u2/m1"}) as ls,
            patch.object(routes, "audit_event") as audit,
        ):
            out = routes.list_sftp_mount_mock_files_endpoint("m1", owner="u2", path="/", limit=200, cursor=None, ctx=ctx)

        self.assertEqual(out["owner"], "u2")
        ls.assert_called_once_with(owner="u2", mount_id="m1", sub_path="/", limit=200, cursor=None, actor_sub="admin1")
        self.assertEqual(audit.call_args.kwargs.get("owner_scope"), "admin_scoped")

    def test_mock_files_endpoint_rejects_non_admin_owner_scope(self):
        ctx = {"user_sub": "u1", "role": "user"}
        with self.assertRaises(HTTPException) as exc:
            routes.list_sftp_mount_mock_files_endpoint("m1", owner="u2", path="/", limit=200, cursor=None, ctx=ctx)
        self.assertEqual(exc.exception.status_code, 403)

    def test_mock_files_helper_enforces_depth_and_scan_guardrails(self):
        import os
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            base = os.path.join(tmp, "u1", "m1", "root")
            os.makedirs(base, exist_ok=True)
            for idx in range(3):
                with open(os.path.join(base, f"f{idx}.txt"), "wb") as fp:
                    fp.write(b"x")

            with patch.object(routes, "S") as settings:
                settings.filemgr_sftp_backend = "mock"
                settings.filemgr_sftp_mock_root_dir = tmp
                settings.filemgr_sftp_mock_path_max_depth = 2
                settings.filemgr_sftp_mock_scan_max_entries = 2
                settings.filemgr_sftp_mock_rate_limit_per_minute = 100

                with self.assertRaises(HTTPException) as depth:
                    routes._list_mock_sftp_dir(owner="u1", mount_id="m1", sub_path="/a/b/c", limit=1, actor_sub="u1")
                self.assertEqual(depth.exception.detail.get("code"), "mock_path_invalid")

                with self.assertRaises(HTTPException) as scan:
                    routes._list_mock_sftp_dir(owner="u1", mount_id="m1", sub_path="/root", limit=1, actor_sub="u1")
                self.assertEqual(scan.exception.status_code, 413)
                self.assertEqual(scan.exception.detail.get("code"), "mock_path_scan_limit_exceeded")

    def test_mock_files_rate_limit_guardrail(self):
        import os
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            base = os.path.join(tmp, "u1", "m1", "root")
            os.makedirs(base, exist_ok=True)
            with open(os.path.join(base, "f0.txt"), "wb") as fp:
                fp.write(b"x")

            with patch.object(routes, "S") as settings:
                settings.filemgr_sftp_backend = "mock"
                settings.filemgr_sftp_mock_root_dir = tmp
                settings.filemgr_sftp_mock_path_max_depth = 10
                settings.filemgr_sftp_mock_scan_max_entries = 100
                settings.filemgr_sftp_mock_rate_limit_per_minute = 1

                routes._SFTP_MOCK_INSPECT_RATE.clear()
                routes._list_mock_sftp_dir(owner="u1", mount_id="m1", sub_path="/root", limit=1, actor_sub="u1")
                with self.assertRaises(HTTPException) as limited:
                    routes._list_mock_sftp_dir(owner="u1", mount_id="m1", sub_path="/root", limit=1, actor_sub="u1")
                self.assertEqual(limited.exception.status_code, 429)
                self.assertEqual(limited.exception.detail.get("code"), "sftp_mock_rate_limited")

    def test_create_list_update_delete_workflow(self):
        ctx = {"user_sub": "u1", "role": "user"}
        mount = _Mount()
        with (
            patch.object(routes, "create_sftp_mount", return_value=mount) as create_mount,
            patch.object(routes, "list_sftp_mount_records", return_value=[mount]) as list_mounts,
            patch.object(routes, "update_sftp_mount", return_value=mount) as update_mount,
            patch.object(routes, "delete_sftp_mount") as delete_mount,
            patch.object(routes, "audit_event"),
        ):
            c = routes.CreateSftpMountIn(host="sftp.example.com", port=22, auth_credential_ref="cred-1", remote_root="/", read_only=False)
            created = routes.create_sftp_mount_endpoint(c, ctx=ctx)
            listed = routes.list_sftp_mounts_endpoint(ctx=ctx)
            updated = routes.update_sftp_mount_endpoint("m1", routes.UpdateSftpMountIn(status="degraded"), ctx=ctx)
            deleted = routes.delete_sftp_mount_endpoint("m1", ctx=ctx)

        self.assertTrue(created["ok"])
        self.assertEqual(created["mount"]["id"], "m1")
        self.assertEqual(len(listed["items"]), 1)
        self.assertEqual(updated["mount"]["status"], "healthy")
        self.assertTrue(deleted["ok"])
        create_mount.assert_called_once()
        list_mounts.assert_called_once_with(owner="u1", limit=100)
        update_mount.assert_called_once()
        delete_mount.assert_called_once_with(owner="u1", mount_id="m1")

    def test_admin_can_scope_owner_query(self):
        ctx = {"user_sub": "admin", "role": "admin"}
        mount = _Mount(owner="u2")
        with (
            patch.object(routes, "list_sftp_mount_records", return_value=[mount]) as list_mounts,
            patch.object(routes, "audit_event"),
        ):
            out = routes.list_sftp_mounts_endpoint(owner="u2", ctx=ctx)
        self.assertEqual(out["items"][0]["owner"], "u2")
        list_mounts.assert_called_once_with(owner="u2", limit=100)


    def test_list_mounts_runs_background_health_refresh_when_enabled(self):
        ctx = {"user_sub": "u1", "role": "user"}
        mount = _Mount(id="m1", owner="u1", status="healthy")
        fake_settings = type("Cfg", (), {
            "filemgr_sftp_health_refresh_enabled": True,
            "filemgr_sftp_health_refresh_interval_seconds": 1,
            "filemgr_sftp_health_refresh_limit": 10,
        })()
        with (
            patch.object(routes, "S", fake_settings),
            patch.object(routes, "list_sftp_mount_records", return_value=[mount]) as list_mounts,
            patch.object(routes, "_probe_sftp_mount_health", return_value={"ok": True, "mount": mount, "previous_status": "healthy", "status_changed": False}) as probe,
            patch.object(routes, "audit_event") as audit_event,
        ):
            routes._SFTP_HEALTH_REFRESH_LAST_RUN_TS = 0.0
            out = routes.list_sftp_mounts_endpoint(ctx=ctx)

        self.assertEqual(len(out["items"]), 1)
        self.assertGreaterEqual(list_mounts.call_count, 2)
        probe.assert_called_once_with(owner="u1", mount_id="m1", actor_sub="u1")
        self.assertTrue(any(c.args and c.args[0] == "filemgr_sftp_mount_health_refresh" for c in audit_event.call_args_list))

    def test_non_admin_cannot_scope_other_owner(self):
        ctx = {"user_sub": "u1", "role": "user"}
        with self.assertRaises(HTTPException) as exc:
            routes.list_sftp_mounts_endpoint(owner="u2", ctx=ctx)
        self.assertEqual(exc.exception.status_code, 403)

    def test_test_endpoint_sets_actionable_error_when_credential_missing(self):
        ctx = {"user_sub": "u1", "role": "user"}
        mount_failed = _Mount(id="m1", owner="u1", status="auth_failed", last_error_code="credential_not_found", last_error_message="credential reference for mount could not be resolved")
        with (
            patch.object(routes, "_probe_sftp_mount_health", return_value={"ok": False, "mount": mount_failed, "previous_status": "healthy", "status_changed": True}) as probe,
            patch.object(routes, "audit_event") as audit_event,
        ):
            out = routes.test_sftp_mount_endpoint("m1", ctx=ctx)

        self.assertFalse(out["ok"])
        self.assertEqual(out["mount"]["status"], "auth_failed")
        self.assertEqual(out["mount"]["last_error_code"], "credential_not_found")
        probe.assert_called_once()
        audit_kwargs = audit_event.call_args.kwargs
        self.assertEqual(audit_kwargs.get("previous_status"), "healthy")
        self.assertTrue(audit_kwargs.get("status_changed"))

    def test_rotate_credential_updates_mount_without_remount(self):
        ctx = {"user_sub": "u1", "role": "user"}
        mount = _Mount(id="m1", owner="u1", auth_credential_ref="cred-old")
        mount_updated = _Mount(id="m1", owner="u1", auth_credential_ref="cred-new")
        with (
            patch.object(routes, "get_sftp_mount", return_value=mount),
            patch.object(routes, "upsert_sftp_credential") as upsert_cred,
            patch.object(routes, "update_sftp_mount", return_value=mount_updated) as update_mount,
            patch.object(routes, "audit_event"),
        ):
            out = routes.rotate_sftp_mount_credential_endpoint(
                "m1",
                routes.RotateSftpMountCredentialIn(
                    auth_mode="password",
                    username="alice",
                    password="next-secret",
                    auth_credential_ref="cred-new",
                ),
                ctx=ctx,
            )

        self.assertTrue(out["ok"])
        self.assertEqual(out["mount"]["id"], "m1")
        self.assertEqual(out["auth_credential_ref"], "cred-new")
        upsert_cred.assert_called_once()
        update_mount.assert_called_once_with(owner="u1", mount_id="m1", auth_credential_ref="cred-new")

    def test_revoke_disables_mount_and_revokes_credential(self):
        ctx = {"user_sub": "u1", "role": "user"}
        mount = _Mount(id="m1", owner="u1", auth_credential_ref="cred-1", status="healthy")
        mount_disabled = _Mount(id="m1", owner="u1", status="disabled", last_error_code="mount_revoked")
        with (
            patch.object(routes, "get_sftp_mount", return_value=mount),
            patch.object(routes, "delete_sftp_credential") as delete_cred,
            patch.object(routes, "update_sftp_mount", return_value=mount_disabled) as update_mount,
            patch.object(routes, "audit_event"),
        ):
            out = routes.revoke_sftp_mount_endpoint("m1", routes.RevokeSftpMountIn(revoke_credential=True, disable_mount=True), ctx=ctx)

        self.assertTrue(out["ok"])
        self.assertTrue(out["credential_revoked"])
        self.assertEqual(out["mount"]["status"], "disabled")
        delete_cred.assert_called_once()
        update_mount.assert_called_once()

    def test_list_info_download_use_provider_for_mounted_paths(self):
        ctx_user = "u1"
        mounted_items = [{"path": "/mounts/m1/readme.txt", "type": "file", "name": "readme.txt", "parent": "/mounts/m1/", "size": 7, "updated_at": "2024-01-01T00:00:00+00:00", "content_type": None}]
        mounted_node = {
            "path": "/mounts/m1/readme.txt",
            "type": "file",
            "name": "readme.txt",
            "parent": "/mounts/m1/",
            "size": 7,
            "updated_at": "2024-01-01T00:00:00+00:00",
            "content_type": None,
            "is_encrypted": False,
        }
        class _Body:
            def read(self, _n=-1):
                if getattr(self, "_done", False):
                    return b""
                self._done = True
                return b"payload"
        mounted_result = {"node": mounted_node, "object": {"Body": _Body()}}
        provider = type("P", (), {
            "list_dir": lambda self, owner, path: mounted_items,
            "stat": lambda self, owner, path: mounted_node,
            "read_stream": lambda self, owner, path: mounted_result,
        })()
        resolved = type("R", (), {"backend": "sftp", "provider": provider})()

        with (
            patch.object(routes, "resolve_storage_provider", return_value=resolved),
            patch.object(routes, "_enforce_filemanager_internal_entitlement"),
            patch.object(routes, "_enforce_sftp_mount_flags_for_path"),
            patch.object(routes, "_enforce_sftp_mount_status_for_path"),
            patch.object(routes, "encryption_info_from_node", return_value={"is_encrypted": False, "enc_metadata": None}),
            patch.object(routes, "preview_capability_from_node", return_value={"preview_kind": "none", "preview_status": "unsupported"}),
            patch.object(routes, "assert_download_allowed"),
            patch.object(routes, "audit_event") as audit_event,
            patch.object(routes, "record_filemgr_encryption_event"),
            patch.object(routes, "record_operation_usage") as record_op,
            patch.object(routes, "record_download_usage") as record_dl,
        ):
            listed = routes.list_files(path="/mounts/m1/", user=ctx_user)
            info = routes.file_info(path="/mounts/m1/readme.txt", user=ctx_user)
            resp = routes.download_fs_file(path="/mounts/m1/readme.txt", user=ctx_user)
            _ = asyncio.run(_consume_response(resp))

        self.assertEqual(listed["items"][0]["name"], "readme.txt")
        self.assertEqual(info["name"], "readme.txt")
        self.assertIn('attachment; filename="readme.txt"', resp.headers.get("content-disposition", ""))
        self.assertTrue(any(c.kwargs.get("operation") == "list" for c in record_op.call_args_list))
        self.assertTrue(any(c.kwargs.get("operation") == "read" for c in record_op.call_args_list))
        self.assertTrue(any(c.kwargs.get("source") == "download_sftp" for c in record_dl.call_args_list))
        events = [c.args[0] for c in audit_event.call_args_list]
        self.assertIn("filemgr_sftp_data_listed", events)
        self.assertIn("filemgr_sftp_data_read", events)

    def test_mutating_routes_use_provider_for_mounted_paths(self):
        ctx_user = "u1"
        provider = type("P", (), {
            "mkdir": lambda self, owner, path: {"ok": True, "path": "/mounts/m1/new/", "type": "folder"},
            "write_stream": lambda self, owner, path, content, content_type=None, overwrite=True: {"path": path, "type": "file", "name": "new.txt", "size": len(content)},
            "delete": lambda self, owner, path: {"ok": True, "deleted_count": 1, "type": "folder" if path.endswith("/") else "file"},
            "move": lambda self, owner, src, dst, overwrite=False: {"src": src, "dst": dst, "type": "folder" if src.endswith("/") else "file"},
        })()
        resolved = type("R", (), {"backend": "sftp", "provider": provider})()

        class _Upload:
            content_type = "text/plain"
            file = __import__("io").BytesIO(b"hello")

        with (
            patch.object(routes, "resolve_storage_provider", return_value=resolved),
            patch.object(routes, "_enforce_filemanager_internal_entitlement"),
            patch.object(routes, "_enforce_sftp_mount_flags_for_path"),
            patch.object(routes, "_enforce_sftp_mount_status_for_path"),
            patch.object(routes, "audit_event") as audit_event,
            patch.object(routes, "record_filemgr_encryption_event"),
            patch.object(routes, "record_upload_usage") as record_upload_usage,
            patch.object(routes, "record_operation_usage") as record_operation_usage,
            patch.object(routes, "assert_upload_allowed"),
        ):
            created = routes.create_folder(path="/mounts/m1/new/", user=ctx_user)
            uploaded = routes.upload_fs_file(path="/mounts/m1/new.txt", file=_Upload(), encrypted=False, user=ctx_user)
            removed_file = routes.remove_fs_file(path="/mounts/m1/new.txt", user=ctx_user)
            removed_folder = routes.remove_fs_folder(path="/mounts/m1/new/", user=ctx_user)
            moved = routes.move_fs_node(src="/mounts/m1/a.txt", dst="/mounts/m1/b.txt", user=ctx_user)
            renamed_file = routes.rename_file(path="/mounts/m1/b.txt", new_name="c.txt", user=ctx_user)
            renamed_folder = routes.rename_folder(path="/mounts/m1/new/", new_name="renamed", user=ctx_user)

        self.assertTrue(created["ok"])
        self.assertTrue(uploaded["ok"])
        self.assertTrue(removed_file["ok"])
        self.assertTrue(removed_folder["ok"])
        self.assertTrue(moved["ok"])
        self.assertTrue(renamed_file["ok"])
        self.assertTrue(renamed_folder["ok"])
        self.assertTrue(any(c.kwargs.get("source") == "upload_sftp" for c in record_upload_usage.call_args_list))
        self.assertTrue(any(c.kwargs.get("operation") == "write" for c in record_operation_usage.call_args_list))
        self.assertTrue(any(c.kwargs.get("operation") == "delete" for c in record_operation_usage.call_args_list))
        self.assertTrue(any(c.kwargs.get("operation") == "move" for c in record_operation_usage.call_args_list))

        audit_kwargs = [c.kwargs for c in audit_event.call_args_list]
        self.assertTrue(any(k.get("storage_backend") == "sftp" and k.get("mount_id") == "m1" for k in audit_kwargs))
        self.assertTrue(any(k.get("storage_backend") == "sftp" and k.get("src_mount_id") == "m1" and k.get("dst_mount_id") == "m1" for k in audit_kwargs))
        events = [c.args[0] for c in audit_event.call_args_list]
        self.assertIn("filemgr_sftp_data_written", events)
        self.assertIn("filemgr_sftp_data_deleted", events)
        self.assertIn("filemgr_sftp_data_moved", events)

    def test_mounted_read_routes_propagate_forbidden_mount_access(self):
        ctx_user = "u1"
        with (
            patch.object(routes, "_enforce_filemanager_internal_entitlement"),
            patch.object(routes, "_enforce_sftp_mount_flags_for_path"),
            patch.object(routes, "_enforce_sftp_mount_status_for_path"),
            patch.object(routes, "resolve_storage_provider", side_effect=HTTPException(status_code=403, detail={"code": "mount_forbidden", "message": "you do not have access to this mount", "mount_id": "m1"})),
        ):
            with self.assertRaises(HTTPException) as list_exc:
                routes.list_files(path="/mounts/m1/", user=ctx_user)
            with self.assertRaises(HTTPException) as info_exc:
                routes.file_info(path="/mounts/m1/readme.txt", user=ctx_user)
            with self.assertRaises(HTTPException) as dl_exc:
                routes.download_fs_file(path="/mounts/m1/readme.txt", user=ctx_user)

        self.assertEqual(list_exc.exception.status_code, 403)
        self.assertEqual(list_exc.exception.detail["code"], "mount_forbidden")
        self.assertEqual(info_exc.exception.status_code, 403)
        self.assertEqual(dl_exc.exception.status_code, 403)



if __name__ == "__main__":
    unittest.main()
