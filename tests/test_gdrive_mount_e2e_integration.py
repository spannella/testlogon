from __future__ import annotations

import io
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from fastapi import HTTPException, UploadFile

from app.services import filemanager, mounts_store, provider_credentials, provider_oauth


class _InMemoryProjectsTable:
    def __init__(self):
        self._items = {}

    def put_item(self, Item, **_kwargs):
        self._items[(Item["PK"], Item["SK"])] = dict(Item)

    def get_item(self, Key, **_kwargs):
        item = self._items.get((Key["PK"], Key["SK"]))
        return {"Item": dict(item)} if item else {}

    def delete_item(self, Key, **_kwargs):
        self._items.pop((Key["PK"], Key["SK"]), None)

    def query(self, **_kwargs):
        pk = None
        for k, _ in self._items.keys():
            pk = k
            break
        if not pk:
            return {"Items": []}
        items = [
            dict(v)
            for (k, sk), v in self._items.items()
            if k == pk and str(sk).startswith("MOUNT#")
        ]
        items.sort(key=lambda row: row["SK"], reverse=True)
        return {"Items": items}


class _FakeDriveProvider:
    def __init__(self):
        self.children = {
            "gdrive://me/items/root": ["gdrive://me/items/f1"],
            "gdrive://me/items/f1": [],
        }
        self.meta = {
            "gdrive://me/items/root": {"name": "root", "type": "dir", "modified_time": "2026-01-01T00:00:00+00:00"},
            "gdrive://me/items/f1": {"name": "a.txt", "type": "file", "size": 3, "mime_type": "text/plain", "modified_time": "2026-01-01T00:00:00+00:00"},
        }
        self.blobs = {"gdrive://me/items/f1": b"abc"}

    def resolve(self, ref: str) -> str:
        return ref

    def exists(self, canonical_ref: str) -> bool:
        return canonical_ref in self.meta

    def get_metadata(self, canonical_ref: str):
        if canonical_ref not in self.meta:
            raise HTTPException(status_code=404, detail="missing")
        out = dict(self.meta[canonical_ref])
        out.setdefault("parents", [])
        return out

    def list_children(self, canonical_ref: str):
        return list(self.children.get(canonical_ref, []))

    def stream_file(self, canonical_ref: str):
        payload = self.blobs.get(canonical_ref, b"")
        return SimpleNamespace(iter_content=lambda chunk_size=0: iter([payload]), close=lambda: None)

    def upload_file(self, parent_ref: str, name: str, *, file_obj, content_type, overwrite):
        existing = None
        for child in self.children.get(parent_ref, []):
            if self.meta[child]["name"] == name:
                existing = child
                break
        if existing and not overwrite:
            raise HTTPException(status_code=409, detail="mount path conflict: file already exists")
        ref = existing or f"gdrive://me/items/{name.replace('.', '_')}"
        data = file_obj.read()
        self.meta[ref] = {"name": name, "type": "file", "size": len(data), "mime_type": content_type or "application/octet-stream", "modified_time": "2026-01-02T00:00:00+00:00"}
        self.blobs[ref] = data
        if not existing:
            self.children.setdefault(parent_ref, []).append(ref)
            self.children.setdefault(ref, [])
        return {"ref": ref, "size": len(data), "content_type": content_type or "application/octet-stream"}

    def delete_item(self, canonical_ref: str):
        if canonical_ref not in self.meta:
            return
        for parent, kids in self.children.items():
            if canonical_ref in kids:
                kids.remove(canonical_ref)
        self.children.pop(canonical_ref, None)
        self.meta.pop(canonical_ref, None)
        self.blobs.pop(canonical_ref, None)


class TestGoogleDriveMountE2EIntegration(unittest.TestCase):
    def test_oauth_connect_flow_mocked_token_exchange(self):
        token_response = MagicMock()
        token_response.status_code = 200
        token_response.content = b"1"
        token_response.json.return_value = {
            "access_token": "access-token",
            "refresh_token": "refresh-token",
            "expires_in": 3600,
            "scope": "https://www.googleapis.com/auth/drive.file",
            "token_type": "Bearer",
        }
        with (
            patch.object(provider_oauth, "consume_google_oauth_state", return_value={"provider": "google_drive"}),
            patch.object(provider_oauth, "requests") as requests_mod,
            patch.object(provider_oauth, "upsert_provider_credential") as upsert,
            patch.object(provider_oauth, "S", SimpleNamespace(
                google_oauth_client_id="cid",
                google_oauth_client_secret="secret",
                google_oauth_redirect_uri="https://example.com/oauth/callback",
                google_oauth_redirect_uri_allowlist="https://example.com/oauth/callback",
                google_oauth_token_url="https://oauth2.googleapis.com/token",
            )),
            patch("app.core.crypto.kms_encrypt", return_value="enc-refresh"),
        ):
            requests_mod.post.return_value = token_response
            upsert.return_value = SimpleNamespace(
                provider="google_drive",
                scopes=["https://www.googleapis.com/auth/drive.file"],
                metadata={"refresh_token_ct_b64": "enc-refresh"},
                created_at="2026-01-01T00:00:00+00:00",
                updated_at="2026-01-01T00:00:00+00:00",
            )
            out = provider_oauth.complete_google_oauth_callback("u1", code="abc", state="state")

        self.assertEqual(out["provider"], "google_drive")
        self.assertIn("refresh_token_ct_b64", out["metadata"])

    def test_mount_lifecycle_roundtrip(self):
        table = _InMemoryProjectsTable()
        with patch.object(mounts_store, "T", SimpleNamespace(projects=table)):
            created = mounts_store.create_mount("u1", provider="google_drive", mount_path="/m/drive", provider_root_ref="gdrive://me/items/root")
            listed = mounts_store.list_mounts("u1")
            updated = mounts_store.update_mount("u1", created.mount_id, mode="read_write")
            deleted = mounts_store.delete_mount("u1", created.mount_id)

        self.assertEqual(len(listed), 1)
        self.assertEqual(updated.mode, "read_write")
        self.assertTrue(deleted["deleted"])

    def test_mount_list_download_write_delete_roundtrip(self):
        provider = _FakeDriveProvider()
        mount = SimpleNamespace(
            mount_id="m1",
            owner="u1",
            provider="google_drive",
            mount_path="/integrations/drive/",
            provider_root_ref="gdrive://me/items/root",
            mode="read_write",
            status="active",
        )
        registry = SimpleNamespace(get=lambda owner, name: provider)
        with (
            patch.object(filemanager, "S", SimpleNamespace(filemgr_google_drive_mounts_enabled=True)),
            patch("app.services.mounts_store.list_mounts", return_value=[mount]),
            patch("app.services.file_providers.default_provider_registry", return_value=registry),
        ):
            children = filemanager.list_children_dispatched("u1", "/integrations/drive/")
            self.assertEqual(len(children), 1)

            upload = UploadFile(filename="a.txt", file=io.BytesIO(b"hello"), headers={"content-type": "text/plain"})
            up = filemanager.upload_file_dispatched("u1", "/integrations/drive/a.txt", upload, overwrite=True)
            self.assertEqual(up["size"], 5)

            downloaded = filemanager.download_file_dispatched("u1", "/integrations/drive/a.txt")
            self.assertEqual(downloaded["object"]["Body"].read(), b"hello")

            filemanager.remove_file_dispatched("u1", "/integrations/drive/a.txt")
            children_after = filemanager.list_children_dispatched("u1", "/integrations/drive/")
            self.assertEqual(len(children_after), 0)

    def test_read_only_enforcement_under_mount(self):
        mount = SimpleNamespace(mount_id="m1", mount_path="/integrations/drive/", mode="read_only")
        mount_match = {
            "mount": mount,
            "mount_path": "/integrations/drive/",
            "relative_parts": ["a.txt"],
            "requested_path": "/integrations/drive/a.txt",
        }
        with patch.object(filemanager, "_mount_match_for_path", return_value=mount_match):
            with self.assertRaises(HTTPException) as ctx:
                filemanager.assert_mount_write_allowed("u1", "/integrations/drive/a.txt", action="upload")
        self.assertEqual(ctx.exception.status_code, 403)

    def test_token_refresh_and_revoked_behavior(self):
        expired = SimpleNamespace(
            provider="google_drive",
            scopes=["https://www.googleapis.com/auth/drive.file"],
            metadata={"expires_at": "2000-01-01T00:00:00+00:00", "refresh_token_ct_b64": "x"},
            token_ct_b64="token",
            org=None,
        )
        with (
            patch.object(provider_credentials, "get_provider_credential", return_value=expired),
            patch("app.services.provider_oauth.refresh_google_oauth_access_token", return_value={"token": "fresh", "provider": "google_drive", "org": None, "scopes": ["https://www.googleapis.com/auth/drive.file"], "metadata": {}}),
        ):
            out = provider_credentials.get_provider_auth_context("u1", "google_drive")
        self.assertEqual(out["token"], "fresh")

        revoked = SimpleNamespace(
            provider="google_drive",
            scopes=[],
            metadata={"reconnect_required": True, "auth_failure_reason": "revoked"},
            token_ct_b64="token",
            org=None,
        )
        with patch.object(provider_credentials, "get_provider_credential", return_value=revoked):
            with self.assertRaises(HTTPException) as ctx:
                provider_credentials.get_provider_auth_context("u1", "google_drive")
        self.assertEqual(ctx.exception.status_code, 401)

    def test_local_fs_regression_guard_non_mounted_paths(self):
        with (
            patch.object(filemanager, "resolve_path_dispatch", return_value={"kind": "local", "path": "/docs/a.txt"}),
            patch.object(filemanager, "get_node", return_value={"path": "/docs/a.txt", "type": "file", "name": "a.txt"}) as get_node,
        ):
            out = filemanager.get_node_dispatched("u1", "/docs/a.txt")
        self.assertEqual(out["path"], "/docs/a.txt")
        get_node.assert_called_once_with("u1", "/docs/a.txt")


if __name__ == "__main__":
    unittest.main()
