import io
import unittest
from unittest.mock import patch

from fastapi import HTTPException

from app.routers import filemanager as routes
from app.services import filemanager_storage


class _Mount:
    def __init__(self, **kwargs):
        self.id = kwargs.get("id", "m1")
        self.owner = kwargs.get("owner", "u1")
        self.host = kwargs.get("host", "sftp.example.com")
        self.port = kwargs.get("port", 22)
        self.auth_credential_ref = kwargs.get("auth_credential_ref", "cred-1")
        self.remote_root = kwargs.get("remote_root", "/team")
        self.read_only = kwargs.get("read_only", False)
        self.status = kwargs.get("status", "healthy")
        self.created_at = kwargs.get("created_at", "t1")
        self.updated_at = kwargs.get("updated_at", "t1")
        self.last_tested_at = kwargs.get("last_tested_at")
        self.last_status_change_at = kwargs.get("last_status_change_at")
        self.last_error_code = kwargs.get("last_error_code")
        self.last_error_message = kwargs.get("last_error_message")


class _Attr:
    def __init__(self, filename, st_mode, st_size=0, st_mtime=1700000000):
        self.filename = filename
        self.st_mode = st_mode
        self.st_size = st_size
        self.st_mtime = st_mtime


class _FakeSftpFs:
    def __init__(self):
        self.files = {"/team/readme.txt": b"payload"}
        self.dirs = {"/team", "/team/docs"}

    def listdir_attr(self, remote_dir):
        return [
            _Attr("docs", 0o040755, 0, 1700000000),
            _Attr("readme.txt", 0o100644, len(self.files.get("/team/readme.txt", b"")), 1700000010),
        ]

    def stat(self, remote):
        key = remote.rstrip("/")
        if key in self.dirs:
            return _Attr(key.split("/")[-1], 0o040755, 0, 1700000000)
        if key in self.files:
            return _Attr(key.split("/")[-1], 0o100644, len(self.files[key]), 1700000010)
        raise FileNotFoundError("not found")

    def open(self, remote, mode):
        key = remote.rstrip("/")
        if "w" in mode:
            class _Writer(io.BytesIO):
                def close(inner_self):
                    self.files[key] = inner_self.getvalue()
                    super().close()
            return _Writer()
        return io.BytesIO(self.files[key])

    def mkdir(self, remote):
        self.dirs.add(remote.rstrip("/"))

    def remove(self, remote):
        self.files.pop(remote.rstrip("/"), None)

    def rmdir(self, remote):
        self.dirs.discard(remote.rstrip("/"))

    def rename(self, src, dst):
        src_key, dst_key = src.rstrip("/"), dst.rstrip("/")
        if src_key in self.files:
            self.files[dst_key] = self.files.pop(src_key)
        elif src_key in self.dirs:
            self.dirs.discard(src_key)
            self.dirs.add(dst_key)


class _Sess:
    def __init__(self):
        self.sftp = _FakeSftpFs()


class TestSftpEndToEndValidationSuite(unittest.TestCase):
    def test_mount_crud_status_transition_and_auth_failure_path(self):
        ctx = {"user_sub": "u1", "role": "user"}
        mount = _Mount(status="healthy")
        auth_failed = _Mount(status="auth_failed", last_error_code="sftp_auth_failed", last_error_message="bad credentials")
        with (
            patch.object(routes, "create_sftp_mount", return_value=mount),
            patch.object(routes, "list_sftp_mount_records", return_value=[mount]),
            patch.object(routes, "_probe_sftp_mount_health", return_value={"ok": False, "mount": auth_failed, "previous_status": "healthy", "status_changed": True}),
            patch.object(routes, "delete_sftp_mount"),
            patch.object(routes, "audit_event"),
        ):
            created = routes.create_sftp_mount_endpoint(routes.CreateSftpMountIn(host="sftp.example.com", port=22, auth_credential_ref="cred-1", remote_root="/", read_only=False), ctx=ctx)
            listed = routes.list_sftp_mounts_endpoint(ctx=ctx)
            tested = routes.test_sftp_mount_endpoint("m1", ctx=ctx)
            deleted = routes.delete_sftp_mount_endpoint("m1", ctx=ctx)

        self.assertTrue(created["ok"])
        self.assertEqual(len(listed["items"]), 1)
        self.assertFalse(tested["ok"])
        self.assertEqual(tested["mount"]["status"], "auth_failed")
        self.assertEqual(tested["mount"]["last_error_code"], "sftp_auth_failed")
        self.assertTrue(deleted["ok"])

    def test_browse_upload_delete_rename_flow_for_mounted_content(self):
        provider = type("P", (), {
            "list_dir": lambda self, owner, path: [{"path": "/mounts/m1/readme.txt", "type": "file", "name": "readme.txt", "parent": "/mounts/m1/", "size": 7, "updated_at": "2024-01-01T00:00:00+00:00", "content_type": "text/plain"}],
            "write_stream": lambda self, owner, path, content, content_type=None, overwrite=True: {"path": path, "type": "file", "name": "new.txt", "size": len(content)},
            "delete": lambda self, owner, path: {"ok": True, "deleted_count": 1, "type": "file"},
            "move": lambda self, owner, src, dst, overwrite=False: {"src": src, "dst": dst, "type": "file"},
            "mkdir": lambda self, owner, path: {"ok": True, "path": path, "type": "folder"},
        })()
        resolved = type("R", (), {"backend": "sftp", "provider": provider})()

        class _Upload:
            content_type = "text/plain"
            file = io.BytesIO(b"hello")

        with (
            patch.object(routes, "resolve_storage_provider", return_value=resolved),
            patch.object(routes, "_enforce_filemanager_internal_entitlement"),
            patch.object(routes, "_enforce_sftp_mount_flags_for_path"),
            patch.object(routes, "_enforce_sftp_mount_status_for_path"),
            patch.object(routes, "record_filemgr_encryption_event"),
            patch.object(routes, "record_upload_usage"),
            patch.object(routes, "record_operation_usage"),
            patch.object(routes, "assert_upload_allowed"),
            patch.object(routes, "audit_event"),
        ):
            listing = routes.list_files(path="/mounts/m1/", user="u1")
            upload = routes.upload_fs_file(path="/mounts/m1/new.txt", file=_Upload(), encrypted=False, user="u1")
            renamed = routes.rename_file(path="/mounts/m1/new.txt", new_name="renamed.txt", user="u1")
            removed = routes.remove_fs_file(path="/mounts/m1/renamed.txt", user="u1")

        self.assertEqual(listing["items"][0]["name"], "readme.txt")
        self.assertTrue(upload["ok"])
        self.assertTrue(renamed["ok"])
        self.assertTrue(removed["ok"])

    def test_non_functional_large_file_write(self):
        provider = filemanager_storage.SftpMountStorageProvider(mount_id="m1")
        mount = _Mount(id="m1", remote_root="/team", status="healthy", read_only=False)
        cred = {"username": "alice", "auth_mode": "password", "secret": {"password": "pw"}}
        sess = _Sess()
        payload = b"a" * (8 * 1024 * 1024)
        with (
            patch.object(filemanager_storage, "get_sftp_mount", return_value=mount),
            patch.object(filemanager_storage, "get_sftp_credential", return_value=cred),
            patch.object(filemanager_storage, "acquire_sftp_session", return_value=sess),
            patch.object(filemanager_storage, "release_sftp_session"),
        ):
            out = provider.write_stream("u1", "/mounts/m1/large.bin", payload, overwrite=True)
        self.assertEqual(out["size"], len(payload))

    def test_non_functional_latency_spike_retries_then_success(self):
        provider = filemanager_storage.SftpMountStorageProvider(mount_id="m1")
        mount = _Mount(id="m1", remote_root="/team", status="healthy", read_only=False)
        cred = {"username": "alice", "auth_mode": "password", "secret": {"password": "pw"}}
        sess = _Sess()
        timeout = HTTPException(status_code=502, detail={"code": "network_timeout", "message": "timed out"})
        with filemanager_storage._MOUNT_CIRCUITS_LOCK:
            filemanager_storage._MOUNT_CIRCUITS.clear()
        with (
            patch.object(filemanager_storage, "get_sftp_mount", return_value=mount),
            patch.object(filemanager_storage, "get_sftp_credential", return_value=cred),
            patch.object(filemanager_storage, "acquire_sftp_session", side_effect=[timeout, sess]) as acquire,
            patch.object(filemanager_storage, "release_sftp_session"),
            patch.object(filemanager_storage, "update_sftp_mount"),
            patch.object(provider, "_retry_max_attempts", return_value=2),
            patch.object(provider, "_retry_backoff_seconds", return_value=0.0),
            patch.object(provider, "_operation_timeout_budget_seconds", return_value=10.0),
        ):
            items = provider.list_dir("u1", "/mounts/m1/")
        self.assertGreaterEqual(len(items), 1)
        self.assertEqual(acquire.call_count, 2)

    def test_non_functional_remote_outage_opens_circuit(self):
        provider = filemanager_storage.SftpMountStorageProvider(mount_id="m1")
        mount = _Mount(id="m1", remote_root="/team", status="healthy", read_only=False)
        cred = {"username": "alice", "auth_mode": "password", "secret": {"password": "pw"}}
        outage = HTTPException(status_code=502, detail={"code": "network_timeout", "message": "host unreachable"})
        with filemanager_storage._MOUNT_CIRCUITS_LOCK:
            filemanager_storage._MOUNT_CIRCUITS.clear()
        with (
            patch.object(filemanager_storage, "get_sftp_mount", return_value=mount),
            patch.object(filemanager_storage, "get_sftp_credential", return_value=cred),
            patch.object(filemanager_storage, "acquire_sftp_session", side_effect=outage),
            patch.object(filemanager_storage, "release_sftp_session"),
            patch.object(filemanager_storage, "update_sftp_mount"),
            patch.object(provider, "_retry_max_attempts", return_value=1),
            patch.object(provider, "_operation_timeout_budget_seconds", return_value=5.0),
            patch.object(provider, "_circuit_failure_threshold", return_value=1),
            patch.object(provider, "_circuit_open_seconds", return_value=60),
        ):
            with self.assertRaises(HTTPException):
                provider.list_dir("u1", "/mounts/m1/")
            with self.assertRaises(HTTPException) as second:
                provider.list_dir("u1", "/mounts/m1/")
        self.assertEqual(second.exception.status_code, 503)
        self.assertEqual(second.exception.detail.get("code"), "sftp_mount_circuit_open")


if __name__ == "__main__":
    unittest.main()
