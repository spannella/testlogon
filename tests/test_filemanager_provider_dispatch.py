import io
import unittest
from unittest.mock import patch

from fastapi import HTTPException, UploadFile

from app.services.filemanager_provider import (
    FileStorageDispatcher,
    ICloudAuthExpiredError,
    ICloudConflictError,
    ICloudNotFoundError,
    ICloudProvider,
    ICloudMFARequiredError,
    ICloudPermanentError,
    ICloudThrottledError,
    ICloudTransientError,
    ICloudTransportUnavailableError,
    MountResolution,
    S3FileStorageProvider,
    build_default_dispatcher,
)


class _StubProvider:
    def __init__(self, name: str):
        self.name = name
        self.calls = []

    def list(self, user: str, path: str, *, include_deleted: bool = False):
        self.calls.append(("list", user, path, include_deleted))
        return [{"provider": self.name, "path": path}]

    def stat(self, user: str, path: str):
        self.calls.append(("stat", user, path))
        return {"provider": self.name, "path": path}

    def read(self, user: str, path: str):
        self.calls.append(("read", user, path))
        return {"provider": self.name, "path": path}

    def write(self, user: str, path: str, upload: UploadFile, *, encryption_meta=None, idempotency_key=None):
        self.calls.append(("write", user, path, upload.filename))
        return {"provider": self.name, "path": path, "name": upload.filename}

    def delete(self, user: str, path: str):
        self.calls.append(("delete", user, path))

    def mkdir(self, user: str, path: str):
        self.calls.append(("mkdir", user, path))
        return path

    def move(self, user: str, src: str, dst: str):
        self.calls.append(("move", user, src, dst))
        return {"provider": self.name, "src": src, "dst": dst}


class _MockICloudTransport:
    def __init__(self):
        self.read_calls = 0
        self.objects = {
            "/icloud/": {"path": "/icloud/", "type": "folder", "name": "icloud"},
            "/icloud/docs/": {"path": "/icloud/docs/", "type": "folder", "name": "docs"},
            "/icloud/docs/a.txt": {
                "path": "/icloud/docs/a.txt",
                "type": "file",
                "name": "a.txt",
                "size": 3,
                "content_type": "text/plain",
                "data": b"abc",
            },
        }

    def list(self, *, user_sub: str, path: str):
        del user_sub
        if path == "/icloud/docs/":
            out = []
            for k, v in self.objects.items():
                if k.startswith("/icloud/docs/") and not k.endswith("/"):
                    out.append({k2: v2 for k2, v2 in v.items() if k2 != "data"})
            return out
        return []

    def stat(self, *, user_sub: str, path: str):
        del user_sub
        if path not in self.objects:
            raise ICloudNotFoundError("missing")
        return {k: v for k, v in self.objects[path].items() if k != "data"}

    def read(self, *, user_sub: str, path: str):
        del user_sub
        self.read_calls += 1
        if path not in self.objects or self.objects[path].get("type") != "file":
            raise ICloudNotFoundError("missing")
        blob = self.objects[path].get("data", b"")

        class _Body:
            def __init__(self, data: bytes):
                self._data = data
                self._sent = False

            def read(self, n=-1):
                del n
                if self._sent:
                    return b""
                self._sent = True
                return self._data

        node = {k: v for k, v in self.objects[path].items() if k != "data"}
        return {"node": node, "object": {"Body": _Body(blob)}}

    def write(self, *, user_sub: str, path: str, data: bytes, content_type: str | None, overwrite: bool = False):
        del user_sub
        if (not overwrite) and path in self.objects:
            raise ICloudThrottledError("duplicate for fail policy")
        name = path.rsplit("/", 1)[-1]
        self.objects[path] = {
            "path": path,
            "type": "file",
            "name": name,
            "size": len(data),
            "content_type": content_type or "application/octet-stream",
            "data": data,
        }
        return {"path": path, "name": name, "size": len(data), "content_type": content_type or "application/octet-stream"}

    def delete(self, *, user_sub: str, path: str):
        del user_sub
        if path not in self.objects:
            raise ICloudNotFoundError("missing")
        del self.objects[path]
        return {"ok": True}

    def move(self, *, user_sub: str, src: str, dst: str, overwrite: bool = False):
        del user_sub
        if src not in self.objects:
            raise ICloudNotFoundError("missing")
        if (not overwrite) and dst in self.objects:
            raise ICloudConflictError("destination exists")
        row = dict(self.objects[src])
        row["path"] = dst
        row["name"] = dst.rsplit("/", 1)[-1]
        self.objects[dst] = row
        del self.objects[src]
        return {"src": src, "dst": dst, "name": row["name"]}


class TestFileStorageDispatcher(unittest.TestCase):
    def test_dispatches_to_resolved_provider(self):
        default = _StubProvider("s3")
        icloud = _StubProvider("icloud")

        dispatcher = FileStorageDispatcher(
            default_provider=default,
            providers={"icloud": icloud},
            resolver=lambda user, path: MountResolution(provider="icloud") if path.startswith("/icloud/") else MountResolution(provider="s3"),
        )

        out = dispatcher.list("u1", "/icloud/docs/")
        self.assertEqual(out[0]["provider"], "icloud")
        self.assertEqual(icloud.calls[0][0], "list")

        out2 = dispatcher.stat("u1", "/docs/a.txt")
        self.assertEqual(out2["provider"], "s3")
        self.assertEqual(default.calls[-1][0], "stat")

    def test_falls_back_to_default_when_resolver_fails(self):
        default = _StubProvider("s3")
        icloud = _StubProvider("icloud")

        def _boom(user, path):
            raise RuntimeError("resolver unavailable")

        dispatcher = FileStorageDispatcher(default_provider=default, providers={"icloud": icloud}, resolver=_boom)
        out = dispatcher.read("u1", "/icloud/a.txt")

        self.assertEqual(out["provider"], "s3")
        self.assertEqual(default.calls[0][0], "read")
        self.assertEqual(len(icloud.calls), 0)

    def test_falls_back_to_default_when_provider_unknown(self):
        default = _StubProvider("s3")
        dispatcher = FileStorageDispatcher(
            default_provider=default,
            resolver=lambda user, path: MountResolution(provider="nonexistent"),
        )

        upload = UploadFile(filename="x.txt", file=io.BytesIO(b"abc"))
        out = dispatcher.write("u1", "/weird/x.txt", upload)

        self.assertEqual(out["provider"], "s3")
        self.assertEqual(default.calls[0][0], "write")


    def test_degraded_mount_is_read_only(self):
        default = _StubProvider("s3")
        icloud = _StubProvider("icloud")
        dispatcher = FileStorageDispatcher(
            default_provider=default,
            providers={"icloud": icloud},
            resolver=lambda _u, _p: MountResolution(provider="icloud", status="degraded", mount_id="m1", mount_path="/icloud/"),
        )

        self.assertEqual(dispatcher.list("u1", "/icloud/")[0]["provider"], "icloud")
        with self.assertRaises(HTTPException) as ctx:
            dispatcher.write("u1", "/icloud/a.txt", UploadFile(filename="a.txt", file=io.BytesIO(b"a")))
        self.assertEqual(ctx.exception.status_code, 503)

    def test_reauth_required_mount_is_unavailable(self):
        default = _StubProvider("s3")
        icloud = _StubProvider("icloud")
        dispatcher = FileStorageDispatcher(
            default_provider=default,
            providers={"icloud": icloud},
            resolver=lambda _u, _p: MountResolution(provider="icloud", status="reauth_required", mount_id="m1", mount_path="/icloud/"),
        )

        with self.assertRaises(HTTPException) as ctx:
            dispatcher.read("u1", "/icloud/a.txt")
        self.assertEqual(ctx.exception.status_code, 503)
        self.assertEqual(ctx.exception.detail["code"], "mount_unavailable")
        self.assertEqual(ctx.exception.detail["mount_status"], "reauth_required")

    def test_unavailable_mount_status_is_unavailable(self):
        default = _StubProvider("s3")
        icloud = _StubProvider("icloud")
        dispatcher = FileStorageDispatcher(
            default_provider=default,
            providers={"icloud": icloud},
            resolver=lambda _u, _p: MountResolution(provider="icloud", status="unavailable", mount_id="m1", mount_path="/icloud/"),
        )

        with self.assertRaises(HTTPException) as ctx:
            dispatcher.list("u1", "/icloud/")
        self.assertEqual(ctx.exception.status_code, 503)
        self.assertEqual(ctx.exception.detail["code"], "mount_unavailable")
        self.assertEqual(ctx.exception.detail["mount_status"], "unavailable")


class TestS3FileStorageProvider(unittest.TestCase):
    def test_s3_provider_delegates_to_filemanager_functions(self):
        provider = S3FileStorageProvider()
        upload = UploadFile(filename="a.txt", file=io.BytesIO(b"a"))

        with (
            patch("app.services.filemanager.norm_path", side_effect=lambda p, is_folder=None: p),
            patch("app.services.filemanager.list_children", return_value=[{"path": "/docs/"}]) as list_children,
            patch("app.services.filemanager.get_node", return_value={"path": "/docs/a.txt"}) as get_node,
            patch("app.services.filemanager.download_file", return_value={"stream": b"x"}) as download_file,
            patch("app.services.filemanager.upload_file", return_value={"ok": True}) as upload_file,
            patch("app.services.filemanager.remove_file") as remove_file,
            patch("app.services.filemanager.remove_folder") as remove_folder,
            patch("app.services.filemanager.create_empty_folder", return_value="/docs/") as mkdir,
            patch("app.services.filemanager.move_node", return_value={"ok": True}) as move,
        ):
            self.assertEqual(provider.list("u1", "/docs/"), [{"path": "/docs/"}])
            self.assertEqual(provider.stat("u1", "/docs/a.txt"), {"path": "/docs/a.txt"})
            self.assertEqual(provider.read("u1", "/docs/a.txt"), {"stream": b"x"})
            self.assertEqual(provider.write("u1", "/docs/a.txt", upload), {"ok": True})
            provider.delete("u1", "/docs/a.txt")
            provider.delete("u1", "/docs/")
            self.assertEqual(provider.mkdir("u1", "/docs/"), "/docs/")
            self.assertEqual(provider.move("u1", "/docs/a.txt", "/docs/b.txt"), {"ok": True})

        list_children.assert_called_once()
        get_node.assert_called_once()
        download_file.assert_called_once()
        upload_file.assert_called_once()
        remove_file.assert_called_once()
        remove_folder.assert_called_once()
        mkdir.assert_called_once()
        move.assert_called_once()


class TestICloudProviderContract(unittest.TestCase):
    def test_write_delete_move_available_when_write_enabled(self):
        provider = ICloudProvider(transport=_MockICloudTransport())
        with (
            patch.object(ICloudProvider, "_ensure_enabled", return_value=None),
            patch.object(ICloudProvider, "_ensure_write_enabled", return_value=None),
            patch("app.services.filemanager_mounts.resolve_mount_for_path", return_value={"conflict_policy": "last_write_wins"}),
        ):
            written = provider.write("u1", "/icloud/docs/new.txt", UploadFile(filename="new.txt", file=io.BytesIO(b"x")))
            self.assertEqual(written["path"], "/icloud/docs/new.txt")
            deleted = provider.delete("u1", "/icloud/docs/new.txt")
            self.assertTrue(deleted["ok"])
            moved = provider.move("u1", "/icloud/docs/a.txt", "/icloud/docs/b.txt")
            self.assertEqual(moved["dst"], "/icloud/docs/b.txt")

    def test_read_only_contract_list_stat_read(self):
        provider = ICloudProvider(transport=_MockICloudTransport())
        with patch.object(ICloudProvider, "_ensure_enabled", return_value=None):
            rows = provider.list("u1", "/icloud/docs/")
            node = provider.stat("u1", "/icloud/docs/a.txt")
            read = provider.read("u1", "/icloud/docs/a.txt")
        self.assertEqual(rows[0]["path"], "/icloud/docs/a.txt")
        self.assertEqual(node["type"], "file")
        self.assertIn("node", read)
        self.assertIn("object", read)

    def test_read_cache_hit_and_invalidation(self):
        transport = _MockICloudTransport()
        provider = ICloudProvider(transport=transport)
        with (
            patch.object(ICloudProvider, "_ensure_enabled", return_value=None),
            patch.object(ICloudProvider, "_ensure_write_enabled", return_value=None),
            patch.object(ICloudProvider, "_is_cache_enabled", return_value=True),
            patch.object(ICloudProvider, "_cache_policy", return_value=(120, 1, 1, 16)),
            patch("app.services.filemanager_provider.record_filemgr_icloud_read_cache") as rec_cache,
            patch("app.services.filemanager_mounts.resolve_mount_for_path", return_value={"conflict_policy": "last_write_wins"}),
        ):
            r1 = provider.read("u1", "/icloud/docs/a.txt")
            r2 = provider.read("u1", "/icloud/docs/a.txt")
            provider.write("u1", "/icloud/docs/a.txt", UploadFile(filename="a.txt", file=io.BytesIO(b"updated")))
            r3 = provider.read("u1", "/icloud/docs/a.txt")
            provider.move("u1", "/icloud/docs/a.txt", "/icloud/docs/moved.txt")
            provider.delete("u1", "/icloud/docs/moved.txt")

        self.assertEqual(r1["node"]["path"], "/icloud/docs/a.txt")
        self.assertEqual(r2["node"]["path"], "/icloud/docs/a.txt")
        self.assertEqual(r3["node"]["path"], "/icloud/docs/a.txt")
        self.assertGreaterEqual(transport.read_calls, 2)
        self.assertTrue(rec_cache.called)

    def test_read_cache_eviction_when_max_entries_reached(self):
        provider = ICloudProvider(transport=_MockICloudTransport())
        with (
            patch.object(ICloudProvider, "_is_cache_enabled", return_value=True),
            patch.object(ICloudProvider, "_cache_policy", return_value=(120, 1, 1, 1)),
            patch("app.services.filemanager_provider.record_filemgr_icloud_read_cache") as rec_cache,
        ):
            provider._read_cache = {
                "u1:/icloud/docs/old.txt": (1.0, {"path": "/icloud/docs/old.txt"}, b"old"),
            }
            provider._cache_put(
                user="u1",
                path="/icloud/docs/new.txt",
                node={"path": "/icloud/docs/new.txt"},
                blob=b"x" * 4,
            )
        calls = [call.kwargs for call in rec_cache.call_args_list]
        assert {"result": "invalidate", "reason": "evict"} in calls

    def test_read_cache_flag_disabled_records_bypass(self):
        provider = ICloudProvider(transport=_MockICloudTransport())
        with (
            patch.object(ICloudProvider, "_ensure_enabled", return_value=None),
            patch.object(ICloudProvider, "_is_cache_enabled", return_value=False),
            patch("app.services.filemanager_provider.record_filemgr_icloud_read_cache") as rec_cache,
        ):
            provider.read("u1", "/icloud/docs/a.txt")
        assert rec_cache.call_args_list[0].kwargs == {"result": "bypass", "reason": "disabled"}

    def test_error_mapping_is_stable(self):
        class _ErrorTransport:
            def list(self, *, user_sub: str, path: str):
                del user_sub, path
                raise ICloudThrottledError("down")

            def stat(self, *, user_sub: str, path: str):
                del user_sub, path
                raise ICloudAuthExpiredError("auth")

            def read(self, *, user_sub: str, path: str):
                del user_sub, path
                raise ICloudNotFoundError("missing")

        provider = ICloudProvider(transport=_ErrorTransport())
        with patch.object(ICloudProvider, "_ensure_enabled", return_value=None):
            with self.assertRaises(HTTPException) as unavailable:
                provider.list("u1", "/icloud/docs/")
            self.assertEqual(unavailable.exception.status_code, 429)
            self.assertEqual(unavailable.exception.detail["code"], "throttled")
            self.assertTrue(unavailable.exception.detail["retryable"])

            with self.assertRaises(HTTPException) as auth:
                provider.stat("u1", "/icloud/docs/a.txt")
            self.assertEqual(auth.exception.status_code, 401)
            self.assertEqual(auth.exception.detail["code"], "auth_expired")
            self.assertEqual(auth.exception.detail["action"], "reconnect")

            with self.assertRaises(HTTPException) as missing:
                provider.read("u1", "/icloud/docs/a.txt")
            self.assertEqual(missing.exception.status_code, 404)
            self.assertEqual(missing.exception.detail["code"], "not_found")

    def test_additional_taxonomy_codes_and_retry_backoff(self):
        class _MFAErrorTransport:
            def list(self, *, user_sub: str, path: str):
                del user_sub, path
                raise ICloudMFARequiredError("mfa")

            def stat(self, *, user_sub: str, path: str):
                del user_sub, path
                raise ICloudPermanentError("permanent")

            def read(self, *, user_sub: str, path: str):
                del user_sub, path
                raise ICloudTransientError("transient")

        provider = ICloudProvider(transport=_MFAErrorTransport())
        with patch.object(ICloudProvider, "_ensure_enabled", return_value=None):
            with self.assertRaises(HTTPException) as mfa:
                provider.list("u1", "/icloud/docs/")
            self.assertEqual(mfa.exception.status_code, 409)
            self.assertEqual(mfa.exception.detail["code"], "mfa_required")

            with self.assertRaises(HTTPException) as permanent:
                provider.stat("u1", "/icloud/docs/a.txt")
            self.assertEqual(permanent.exception.status_code, 502)
            self.assertEqual(permanent.exception.detail["code"], "permanent")

            with self.assertRaises(HTTPException) as transient:
                provider.read("u1", "/icloud/docs/a.txt")
            self.assertEqual(transient.exception.status_code, 503)
            self.assertEqual(transient.exception.detail["code"], "transient")

    def test_retry_uses_exponential_backoff_for_retryable_errors(self):
        class _RetryTransport:
            def __init__(self):
                self.calls = 0

            def list(self, *, user_sub: str, path: str):
                del user_sub, path
                self.calls += 1
                if self.calls < 3:
                    raise ICloudTransientError("temporary")
                return [{"path": "/icloud/docs/a.txt"}]

            def stat(self, *, user_sub: str, path: str):
                del user_sub, path
                return {"path": "/icloud/docs/a.txt"}

            def read(self, *, user_sub: str, path: str):
                del user_sub, path
                return {"node": {"path": "/icloud/docs/a.txt"}, "object": {}}

        transport = _RetryTransport()
        provider = ICloudProvider(transport=transport)
        with (
            patch.object(ICloudProvider, "_ensure_enabled", return_value=None),
            patch.object(ICloudProvider, "_retry_policy", return_value=(3, 0.1, 1.0)),
            patch("app.services.filemanager_provider.time.sleep") as sleep,
        ):
            rows = provider.list("u1", "/icloud/docs/")

        self.assertEqual(rows[0]["path"], "/icloud/docs/a.txt")
        self.assertEqual(transport.calls, 3)
        self.assertEqual([c.args[0] for c in sleep.call_args_list], [0.1, 0.2])

    def test_write_conflict_policies_and_idempotency(self):
        transport = _MockICloudTransport()
        provider = ICloudProvider(transport=transport)

        with (
            patch.object(ICloudProvider, "_ensure_enabled", return_value=None),
            patch.object(ICloudProvider, "_ensure_write_enabled", return_value=None),
            patch("app.services.filemanager_mounts.resolve_mount_for_path", return_value={"conflict_policy": "fail"}),
        ):
            with self.assertRaises(HTTPException) as fail_conflict:
                provider.write("u1", "/icloud/docs/a.txt", UploadFile(filename="a.txt", file=io.BytesIO(b"new")))
        self.assertEqual(fail_conflict.exception.status_code, 409)
        self.assertEqual(fail_conflict.exception.detail["code"], "conflict")

        with (
            patch.object(ICloudProvider, "_ensure_enabled", return_value=None),
            patch.object(ICloudProvider, "_ensure_write_enabled", return_value=None),
            patch("app.services.filemanager_mounts.resolve_mount_for_path", return_value={"conflict_policy": "rename"}),
        ):
            out_rename = provider.write("u1", "/icloud/docs/a.txt", UploadFile(filename="a.txt", file=io.BytesIO(b"new")))
        self.assertEqual(out_rename["path"], "/icloud/docs/a (1).txt")

        with (
            patch.object(ICloudProvider, "_ensure_enabled", return_value=None),
            patch.object(ICloudProvider, "_ensure_write_enabled", return_value=None),
            patch("app.services.filemanager_mounts.resolve_mount_for_path", return_value={"conflict_policy": "last_write_wins"}),
        ):
            out_overwrite = provider.write("u1", "/icloud/docs/a.txt", UploadFile(filename="a.txt", file=io.BytesIO(b"updated")))
            once = provider.write(
                "u1",
                "/icloud/docs/new.txt",
                UploadFile(filename="new.txt", file=io.BytesIO(b"v1")),
                idempotency_key="idem-1",
            )
            twice = provider.write(
                "u1",
                "/icloud/docs/new.txt",
                UploadFile(filename="new.txt", file=io.BytesIO(b"v2")),
                idempotency_key="idem-1",
            )
        self.assertEqual(out_overwrite["path"], "/icloud/docs/a.txt")
        self.assertEqual(once["size"], twice["size"])

    def test_delete_and_move_with_conflict_policy(self):
        transport = _MockICloudTransport()
        provider = ICloudProvider(transport=transport)

        with (
            patch.object(ICloudProvider, "_ensure_enabled", return_value=None),
            patch.object(ICloudProvider, "_ensure_write_enabled", return_value=None),
        ):
            deleted = provider.delete("u1", "/icloud/docs/a.txt")
            self.assertTrue(deleted["ok"])

        with (
            patch.object(ICloudProvider, "_ensure_enabled", return_value=None),
            patch.object(ICloudProvider, "_ensure_write_enabled", return_value=None),
            patch("app.services.filemanager_mounts.resolve_mount_for_path", return_value={"conflict_policy": "last_write_wins"}),
        ):
            provider.write("u1", "/icloud/docs/src.txt", UploadFile(filename="src.txt", file=io.BytesIO(b"src")), idempotency_key="m1")
            provider.write("u1", "/icloud/docs/dst.txt", UploadFile(filename="dst.txt", file=io.BytesIO(b"dst")), idempotency_key="m2")

        with (
            patch.object(ICloudProvider, "_ensure_enabled", return_value=None),
            patch.object(ICloudProvider, "_ensure_write_enabled", return_value=None),
            patch("app.services.filemanager_mounts.resolve_mount_for_path", return_value={"conflict_policy": "rename"}),
        ):
            moved = provider.move("u1", "/icloud/docs/src.txt", "/icloud/docs/dst.txt")
        self.assertEqual(moved["dst"], "/icloud/docs/dst (1).txt")



class TestDefaultDispatcher(unittest.TestCase):
    def test_default_dispatcher_routes_icloud_mount_to_remote_provider(self):
        with patch("app.services.filemanager_mounts.resolve_mount_for_path", return_value={"provider": "icloud", "mount_id": "m1", "mount_path": "/icloud/"}):
            dispatcher = build_default_dispatcher()
        with self.assertRaises(HTTPException) as ctx:
            dispatcher.list("u1", "/icloud/docs/")
        self.assertEqual(ctx.exception.status_code, 503)

    def test_default_dispatcher_non_mounted_uses_s3_provider(self):
        with patch("app.services.filemanager_mounts.resolve_mount_for_path", return_value=None):
            dispatcher = build_default_dispatcher()
        with patch("app.services.filemanager.list_children", return_value=[]):
            out = dispatcher.list("u1", "/docs/")
        self.assertEqual(out, [])

    def test_default_dispatcher_with_mock_transport_supports_browse_and_download(self):
        transport = _MockICloudTransport()
        with (
            patch("app.services.filemanager_mounts.resolve_mount_for_path", return_value={"provider": "icloud", "mount_id": "m1", "mount_path": "/icloud/"}),
            patch.object(ICloudProvider, "_ensure_enabled", return_value=None),
        ):
            dispatcher = build_default_dispatcher(icloud_transport=transport)
            rows = dispatcher.list("u1", "/icloud/docs/")
            blob = dispatcher.read("u1", "/icloud/docs/a.txt")
        self.assertEqual(rows[0]["path"], "/icloud/docs/a.txt")
        self.assertEqual(blob["node"]["name"], "a.txt")


if __name__ == "__main__":
    unittest.main()
