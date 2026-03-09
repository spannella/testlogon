import unittest
from unittest.mock import patch

from fastapi import HTTPException

from app.services import filemanager_storage


class _Mount:
    def __init__(self, mount_id="m1"):
        self.id = mount_id




class _Attr:
    def __init__(self, filename, st_mode, st_size=0, st_mtime=1700000000):
        self.filename = filename
        self.st_mode = st_mode
        self.st_size = st_size
        self.st_mtime = st_mtime


class _FakeSftpFs:
    def __init__(self):
        self.open_calls = []
        self.mkdir_calls = []
        self.remove_calls = []
        self.rmdir_calls = []
        self.rename_calls = []
        self.files = {"/team/readme.txt": b"payload"}
        self.dirs = {"/team", "/team/docs"}

    def listdir_attr(self, remote_dir):
        self.last_list_dir = remote_dir
        if remote_dir.rstrip("/") == "/team/docs":
            return []
        return [
            _Attr("docs", 0o040755, 0, 1700000000),
            _Attr("readme.txt", 0o100644, 7, 1700000010),
        ]

    def stat(self, remote):
        self.last_stat = remote
        key = remote.rstrip("/")
        if key in self.dirs:
            return _Attr(key.split("/")[-1] or "team", 0o040755, 0, 1700000000)
        if key in self.files:
            return _Attr(key.split("/")[-1], 0o100644, len(self.files[key]), 1700000010)
        raise FileNotFoundError("no such file")

    def open(self, remote, mode):
        self.open_calls.append((remote, mode))
        import io
        key = remote.rstrip("/")
        if "w" in mode:
            class _Writer(io.BytesIO):
                def close(inner_self):
                    self.files[key] = inner_self.getvalue()
                    super().close()
            return _Writer()
        return io.BytesIO(self.files.get(key, b"payload"))

    def mkdir(self, remote):
        key = remote.rstrip("/")
        self.mkdir_calls.append(key)
        self.dirs.add(key)

    def remove(self, remote):
        key = remote.rstrip("/")
        self.remove_calls.append(key)
        self.files.pop(key, None)

    def rmdir(self, remote):
        key = remote.rstrip("/")
        self.rmdir_calls.append(key)
        self.dirs.discard(key)

    def rename(self, src, dst):
        src_key, dst_key = src.rstrip("/"), dst.rstrip("/")
        self.rename_calls.append((src_key, dst_key))
        if src_key in self.files:
            self.files[dst_key] = self.files.pop(src_key)
        elif src_key in self.dirs:
            self.dirs.discard(src_key)
            self.dirs.add(dst_key)
        else:
            raise FileNotFoundError("no such file")


class _Sess:
    def __init__(self):
        self.sftp = _FakeSftpFs()


class TestFileManagerStorageProvider(unittest.TestCase):
    def setUp(self):
        with filemanager_storage._MOUNT_CIRCUITS_LOCK:
            filemanager_storage._MOUNT_CIRCUITS.clear()
    def test_resolve_storage_provider_non_mount_path_uses_s3(self):
        resolved = filemanager_storage.resolve_storage_provider("u1", "/docs/a.txt")
        self.assertEqual(resolved.backend, "s3")
        self.assertIsNone(resolved.mount_id)
        self.assertEqual(resolved.provider.provider_name, "s3")

    def test_resolve_storage_provider_mount_path_uses_sftp(self):
        with patch.object(filemanager_storage, "get_sftp_mount", return_value=_Mount("m1")) as get_mount:
            resolved = filemanager_storage.resolve_storage_provider("u1", "/mounts/m1/docs/a.txt")
        self.assertEqual(resolved.backend, "sftp")
        self.assertEqual(resolved.mount_id, "m1")
        self.assertEqual(resolved.provider.provider_name, "sftp")
        get_mount.assert_called_once_with(owner="u1", mount_id="m1")

    def test_resolve_storage_provider_mount_path_forbidden_mount_owner_raises_403(self):
        foreign_mount = _Mount("m1")
        foreign_mount.owner = "u2"
        with (
            patch.object(filemanager_storage, "get_sftp_mount", side_effect=HTTPException(status_code=404, detail="sftp mount not found")),
            patch.object(filemanager_storage, "find_sftp_mount_by_id", return_value=foreign_mount),
        ):
            with self.assertRaises(HTTPException) as ctx:
                filemanager_storage.resolve_storage_provider("u1", "/mounts/m1/docs/a.txt")
        self.assertEqual(ctx.exception.status_code, 403)
        self.assertEqual(ctx.exception.detail["code"], "mount_forbidden")

    def test_resolve_storage_provider_mount_path_not_found_returns_stable_error(self):
        with (
            patch.object(filemanager_storage, "get_sftp_mount", side_effect=HTTPException(status_code=404, detail="sftp mount not found")),
            patch.object(filemanager_storage, "find_sftp_mount_by_id", return_value=None),
        ):
            with self.assertRaises(HTTPException) as ctx:
                filemanager_storage.resolve_storage_provider("u1", "/mounts/missing/docs/a.txt")
        self.assertEqual(ctx.exception.status_code, 404)
        self.assertEqual(ctx.exception.detail["code"], "mount_not_found")
        self.assertEqual(ctx.exception.detail["mount_id"], "missing")

    def test_s3_provider_adapter_dispatches_existing_filemanager_functions(self):
        provider = filemanager_storage.S3FileManagerStorageProvider()
        with (
            patch.object(filemanager_storage.filemanager, "list_children", return_value=[{"path": "/docs/a.txt"}]) as list_children,
            patch.object(filemanager_storage.filemanager, "norm_path", side_effect=lambda p, is_folder=None: p if p.startswith("/") else "/"+p) as norm,
            patch.object(filemanager_storage.filemanager, "get_node", return_value={"path": "/docs/a.txt"}) as get_node,
            patch.object(filemanager_storage.filemanager, "download_file", return_value={"node": {"path": "/docs/a.txt"}}) as dl,
            patch.object(filemanager_storage.filemanager, "create_empty_folder", return_value="/docs/new/") as mkdir,
            patch.object(filemanager_storage.filemanager, "remove_file") as rm_file,
            patch.object(filemanager_storage.filemanager, "remove_folder", return_value=3) as rm_folder,
            patch.object(filemanager_storage.filemanager, "move_node", return_value={"src": "/a", "dst": "/b"}) as mv,
            patch.object(filemanager_storage.filemanager, "upload_file", return_value={"path": "/docs/new.txt"}) as upload,
            patch.object(filemanager_storage.filemanager, "split_parent_name", return_value=("/docs/", "new.txt")),
        ):
            self.assertEqual(provider.list_dir("u1", "/docs/")[0]["path"], "/docs/a.txt")
            self.assertEqual(provider.stat("u1", "/docs/a.txt")["path"], "/docs/a.txt")
            self.assertEqual(provider.read_stream("u1", "/docs/a.txt")["node"]["path"], "/docs/a.txt")
            self.assertEqual(provider.write_stream("u1", "/docs/new.txt", b"abc")["path"], "/docs/new.txt")
            self.assertEqual(provider.mkdir("u1", "/docs/new/")["path"], "/docs/new/")
            self.assertTrue(provider.delete("u1", "/docs/a.txt")["ok"])
            self.assertTrue(provider.delete("u1", "/docs/")["ok"])
            self.assertEqual(provider.move("u1", "/a", "/b")["dst"], "/b")

        list_children.assert_called_once()
        get_node.assert_called_once()
        dl.assert_called_once()
        upload.assert_called_once()
        mkdir.assert_called_once()
        rm_file.assert_called_once()
        rm_folder.assert_called_once()
        mv.assert_called_once()
        self.assertGreaterEqual(norm.call_count, 1)

    def test_sftp_provider_read_ops_and_metadata_normalization(self):
        provider = filemanager_storage.SftpMountStorageProvider(mount_id="m1")
        mount = type("M", (), {"id": "m1", "host": "sftp.example.com", "port": 22, "remote_root": "/team", "auth_credential_ref": "cred-1"})()
        cred = {"username": "alice", "auth_mode": "password", "secret": {"password": "pw"}}
        sess = _Sess()
        with (
            patch.object(filemanager_storage, "get_sftp_mount", return_value=mount),
            patch.object(filemanager_storage, "get_sftp_credential", return_value=cred),
            patch.object(filemanager_storage, "acquire_sftp_session", return_value=sess),
            patch.object(filemanager_storage, "release_sftp_session"),
        ):
            items = provider.list_dir("u1", "/mounts/m1/")
            info = provider.stat("u1", "/mounts/m1/readme.txt")
            dl = provider.read_stream("u1", "/mounts/m1/readme.txt")

        self.assertEqual(items[0]["type"], "folder")
        self.assertEqual(items[1]["type"], "file")
        self.assertEqual(items[1]["size"], 7)
        self.assertEqual(info["name"], "readme.txt")
        self.assertEqual(info["type"], "file")
        self.assertEqual(dl["object"]["Body"].read(), b"payload")


    def test_sftp_provider_write_ops_and_read_only_policy(self):
        provider = filemanager_storage.SftpMountStorageProvider(mount_id="m1")
        mount_rw = type("M", (), {"id": "m1", "host": "sftp.example.com", "port": 22, "remote_root": "/team", "auth_credential_ref": "cred-1", "read_only": False})()
        mount_ro = type("M", (), {"id": "m1", "host": "sftp.example.com", "port": 22, "remote_root": "/team", "auth_credential_ref": "cred-1", "read_only": True})()
        cred = {"username": "alice", "auth_mode": "password", "secret": {"password": "pw"}}
        sess = _Sess()
        with (
            patch.object(filemanager_storage, "get_sftp_mount", return_value=mount_rw),
            patch.object(filemanager_storage, "get_sftp_credential", return_value=cred),
            patch.object(filemanager_storage, "acquire_sftp_session", return_value=sess),
            patch.object(filemanager_storage, "release_sftp_session"),
        ):
            uploaded = provider.write_stream("u1", "/mounts/m1/new.txt", b"new-data", overwrite=True)
            created = provider.mkdir("u1", "/mounts/m1/newdir/")
            moved = provider.move("u1", "/mounts/m1/new.txt", "/mounts/m1/newer.txt", overwrite=False)
            deleted = provider.delete("u1", "/mounts/m1/newer.txt")

        self.assertEqual(uploaded["path"], "/mounts/m1/new.txt")
        self.assertEqual(created["path"], "/mounts/m1/newdir/")
        self.assertEqual(moved["dst"], "/mounts/m1/newer.txt")
        self.assertTrue(deleted["ok"])

        with (
            patch.object(filemanager_storage, "get_sftp_mount", return_value=mount_ro),
            patch.object(filemanager_storage, "get_sftp_credential", return_value=cred),
            patch.object(filemanager_storage, "acquire_sftp_session", return_value=sess),
            patch.object(filemanager_storage, "release_sftp_session"),
        ):
            with self.assertRaises(HTTPException) as ctx:
                provider.write_stream("u1", "/mounts/m1/blocked.txt", b"x")
        self.assertEqual(ctx.exception.status_code, 403)
        self.assertEqual(ctx.exception.detail["code"], "mount_read_only")


    def test_sftp_provider_retries_transient_errors_within_budget(self):
        provider = filemanager_storage.SftpMountStorageProvider(mount_id="m1")
        mount = type("M", (), {"id": "m1", "host": "sftp.example.com", "port": 22, "remote_root": "/team", "auth_credential_ref": "cred-1", "read_only": False, "status": "healthy"})()
        cred = {"username": "alice", "auth_mode": "password", "secret": {"password": "pw"}}
        sess = _Sess()
        transient = HTTPException(status_code=502, detail={"code": "network_timeout", "message": "timed out"})
        with filemanager_storage._MOUNT_CIRCUITS_LOCK:
            filemanager_storage._MOUNT_CIRCUITS.clear()
        with (
            patch.object(filemanager_storage, "get_sftp_mount", return_value=mount),
            patch.object(filemanager_storage, "get_sftp_credential", return_value=cred),
            patch.object(filemanager_storage, "acquire_sftp_session", side_effect=[transient, sess]) as acquire,
            patch.object(filemanager_storage, "release_sftp_session"),
            patch.object(filemanager_storage, "update_sftp_mount"),
            patch.object(provider, "_retry_max_attempts", return_value=2),
            patch.object(provider, "_operation_timeout_budget_seconds", return_value=10.0),
            patch.object(provider, "_retry_backoff_seconds", return_value=0.0),
        ):
            items = provider.list_dir("u1", "/mounts/m1/")
        self.assertEqual(acquire.call_count, 2)
        self.assertGreaterEqual(len(items), 1)

    def test_sftp_provider_circuit_breaker_opens_after_repeated_failures(self):
        provider = filemanager_storage.SftpMountStorageProvider(mount_id="m1")
        mount = type("M", (), {"id": "m1", "host": "sftp.example.com", "port": 22, "remote_root": "/team", "auth_credential_ref": "cred-1", "read_only": False, "status": "healthy"})()
        cred = {"username": "alice", "auth_mode": "password", "secret": {"password": "pw"}}
        transient = HTTPException(status_code=502, detail={"code": "network_timeout", "message": "timed out"})
        with filemanager_storage._MOUNT_CIRCUITS_LOCK:
            filemanager_storage._MOUNT_CIRCUITS.clear()
        with (
            patch.object(filemanager_storage, "get_sftp_mount", return_value=mount),
            patch.object(filemanager_storage, "get_sftp_credential", return_value=cred),
            patch.object(filemanager_storage, "acquire_sftp_session", side_effect=transient) as acquire,
            patch.object(filemanager_storage, "update_sftp_mount"),
            patch.object(provider, "_retry_max_attempts", return_value=1),
            patch.object(provider, "_operation_timeout_budget_seconds", return_value=5.0),
            patch.object(provider, "_circuit_failure_threshold", return_value=1),
            patch.object(provider, "_circuit_open_seconds", return_value=60),
        ):
            with self.assertRaises(HTTPException) as first_exc:
                provider.list_dir("u1", "/mounts/m1/")
            with self.assertRaises(HTTPException) as second_exc:
                provider.list_dir("u1", "/mounts/m1/")

        self.assertEqual(first_exc.exception.status_code, 502)
        self.assertEqual(second_exc.exception.status_code, 503)
        self.assertEqual(second_exc.exception.detail["code"], "sftp_mount_circuit_open")
        self.assertEqual(acquire.call_count, 1)

    def test_sftp_provider_path_escape_rejected(self):
        provider = filemanager_storage.SftpMountStorageProvider(mount_id="m1")
        mount = type("M", (), {"id": "m1", "host": "sftp.example.com", "port": 22, "remote_root": "/team", "auth_credential_ref": "cred-1"})()
        cred = {"username": "alice", "auth_mode": "password", "secret": {"password": "pw"}}
        with (
            patch.object(filemanager_storage, "get_sftp_mount", return_value=mount),
            patch.object(filemanager_storage, "get_sftp_credential", return_value=cred),
        ):
            with self.assertRaises(HTTPException) as ctx:
                provider.stat("u1", "/mounts/m2/readme.txt")
        self.assertEqual(ctx.exception.status_code, 400)


if __name__ == "__main__":
    unittest.main()
