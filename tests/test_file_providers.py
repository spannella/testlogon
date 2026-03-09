from __future__ import annotations
import io

import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from fastapi import HTTPException

from app.services.file_providers import (
    GitHubProvider,
    GitLabProvider,
    GoogleDriveProvider,
    LocalFileProvider,
    ProviderRegistry,
    default_provider_registry,
)


class TestLocalFileProvider(unittest.TestCase):
    def test_resolve_canonicalizes_path(self):
        provider = LocalFileProvider("user-1")
        with patch("app.services.file_providers.filemanager.norm_path", return_value="/docs/a.txt") as norm_path:
            out = provider.resolve("docs//a.txt")
        self.assertEqual(out, "/docs/a.txt")
        norm_path.assert_called_once_with("docs//a.txt", is_folder=None)

    def test_exists_returns_false_for_missing_file(self):
        provider = LocalFileProvider("user-1")
        with patch(
            "app.services.file_providers.filemanager.get_node",
            side_effect=HTTPException(status_code=404, detail="not found"),
        ):
            self.assertFalse(provider.exists("/docs/missing.txt"))

    def test_get_metadata_reads_from_filemanager(self):
        provider = LocalFileProvider("user-1")
        node = {
            "path": "/docs/a.txt",
            "type": "file",
            "name": "a.txt",
            "size": 12,
            "content_type": "text/plain",
            "updated_at": "2026-01-01T00:00:00+00:00",
        }
        with patch("app.services.file_providers.filemanager.get_node", return_value=node):
            out = provider.get_metadata("/docs/a.txt")
        self.assertEqual(out["path"], "/docs/a.txt")
        self.assertEqual(out["type"], "file")
        self.assertEqual(out["size"], 12)


class TestProviderRegistry(unittest.TestCase):
    def test_default_registry_returns_local_provider(self):
        registry = default_provider_registry()
        provider = registry.get("user-1", "LOCAL")
        self.assertEqual(provider.provider_name, "local")

    def test_default_registry_returns_github_provider(self):
        registry = default_provider_registry()
        provider = registry.get("user-1", "github")
        self.assertEqual(provider.provider_name, "github")

    def test_default_registry_returns_gitlab_provider(self):
        registry = default_provider_registry()
        provider = registry.get("user-1", "gitlab")
        self.assertEqual(provider.provider_name, "gitlab")

    def test_default_registry_returns_google_drive_provider(self):
        registry = default_provider_registry()
        provider = registry.get("user-1", "google_drive")
        self.assertEqual(provider.provider_name, "google_drive")

    def test_registry_rejects_unknown_provider(self):
        registry = ProviderRegistry()
        with self.assertRaises(HTTPException) as ctx:
            registry.get("user-1", "github")
        self.assertEqual(ctx.exception.status_code, 400)


class TestGitHubProvider(unittest.TestCase):
    def test_resolve_canonicalizes_ref(self):
        provider = GitHubProvider("user-1")
        out = provider.resolve("octocat/hello-world/src/main.py?ref=main")
        self.assertEqual(out, "github://octocat/hello-world/src/main.py?ref=main")

    def test_exists_returns_false_on_404(self):
        provider = GitHubProvider("user-1")
        response = SimpleNamespace(status_code=404, headers={}, content=b"")
        with (
            patch("app.services.file_providers.get_provider_auth_context", return_value={"token": "token", "metadata": {}}),
            patch("app.services.file_providers.requests.get", return_value=response),
        ):
            self.assertFalse(provider.exists("github://octocat/hello-world/README.md?ref=main"))

    def test_get_metadata_handles_rate_limit(self):
        provider = GitHubProvider("user-1")
        response = SimpleNamespace(
            status_code=403,
            headers={"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "1700000000"},
            content=b"1",
            json=lambda: {},
        )
        with (
            patch("app.services.file_providers.get_provider_auth_context", return_value={"token": "token", "metadata": {}}),
            patch("app.services.file_providers.requests.get", return_value=response),
        ):
            with self.assertRaises(HTTPException) as ctx:
                provider.get_metadata("github://octocat/hello-world/README.md?ref=main")
        self.assertEqual(ctx.exception.status_code, 429)
        self.assertIn("rate limit", ctx.exception.detail)

    def test_get_metadata_parses_payload(self):
        provider = GitHubProvider("user-1")
        response = SimpleNamespace(
            status_code=200,
            headers={},
            content=b"1",
            json=lambda: {
                "type": "file",
                "size": 10,
                "sha": "abc",
                "name": "README.md",
                "path": "README.md",
                "html_url": "https://github.com/octocat/hello-world/blob/main/README.md",
                "download_url": "https://raw.githubusercontent.com/...",
            },
        )
        with (
            patch("app.services.file_providers.get_provider_auth_context", return_value={"token": "token", "metadata": {}}),
            patch("app.services.file_providers.requests.get", return_value=response),
        ):
            out = provider.get_metadata("github://octocat/hello-world/README.md?ref=main")
        self.assertEqual(out["type"], "file")
        self.assertEqual(out["size"], 10)

    def test_get_metadata_uses_enterprise_api_base_url_from_credential_metadata(self):
        provider = GitHubProvider("user-1")
        response = SimpleNamespace(
            status_code=200,
            headers={},
            content=b"1",
            json=lambda: {"type": "file", "size": 10, "path": "README.md"},
        )
        with (
            patch(
                "app.services.file_providers.get_provider_auth_context",
                return_value={"token": "token", "metadata": {"api_base_url": "https://ghe.local/api/v3"}},
            ),
            patch("app.services.file_providers.requests.get", return_value=response) as requests_get,
        ):
            provider.get_metadata("github://octocat/hello-world/README.md?ref=main")
        self.assertTrue(requests_get.call_args.args[0].startswith("https://ghe.local/api/v3"))


class TestGitLabProvider(unittest.TestCase):
    def test_resolve_canonicalizes_ref(self):
        provider = GitLabProvider("user-1")
        out = provider.resolve("group/project//src/main.py?ref=main")
        self.assertEqual(out, "gitlab://group/project//src/main.py?ref=main")

    def test_exists_returns_false_on_404(self):
        provider = GitLabProvider("user-1")
        response = SimpleNamespace(status_code=404, headers={}, content=b"")
        with (
            patch("app.services.file_providers.get_provider_auth_context", return_value={"token": "token", "metadata": {}}),
            patch("app.services.file_providers.requests.get", return_value=response),
        ):
            self.assertFalse(provider.exists("gitlab://group/project//README.md?ref=main"))

    def test_get_metadata_handles_rate_limit(self):
        provider = GitLabProvider("user-1")
        response = SimpleNamespace(
            status_code=429,
            headers={"Retry-After": "30"},
            content=b"1",
            json=lambda: {},
        )
        with (
            patch("app.services.file_providers.get_provider_auth_context", return_value={"token": "token", "metadata": {}}),
            patch("app.services.file_providers.requests.get", return_value=response),
        ):
            with self.assertRaises(HTTPException) as ctx:
                provider.get_metadata("gitlab://group/project//README.md?ref=main")
        self.assertEqual(ctx.exception.status_code, 429)
        self.assertIn("rate limit", ctx.exception.detail)

    def test_get_metadata_parses_payload(self):
        provider = GitLabProvider("user-1")
        response = SimpleNamespace(
            status_code=200,
            headers={},
            content=b"1",
            json=lambda: {
                "file_name": "README.md",
                "file_path": "README.md",
                "size": 5,
                "blob_id": "abc",
                "commit_id": "def",
                "last_commit_id": "ghi",
                "content_sha256": "zzz",
                "encoding": "base64",
                "ref": "main",
            },
        )
        with (
            patch("app.services.file_providers.get_provider_auth_context", return_value={"token": "token", "metadata": {}}),
            patch("app.services.file_providers.requests.get", return_value=response),
        ):
            out = provider.get_metadata("gitlab://group/project//README.md?ref=main")
        self.assertEqual(out["type"], "file")
        self.assertEqual(out["size"], 5)

    def test_get_metadata_uses_self_hosted_api_base_url_from_credential_metadata(self):
        provider = GitLabProvider("user-1")
        response = SimpleNamespace(
            status_code=200,
            headers={},
            content=b"1",
            json=lambda: {"file_name": "README.md", "file_path": "README.md", "size": 5},
        )
        with (
            patch(
                "app.services.file_providers.get_provider_auth_context",
                return_value={"token": "token", "metadata": {"api_base_url": "https://gitlab.local/api/v4"}},
            ),
            patch("app.services.file_providers.requests.get", return_value=response) as requests_get,
        ):
            provider.get_metadata("gitlab://group/project//README.md?ref=main")
        self.assertTrue(requests_get.call_args.args[0].startswith("https://gitlab.local/api/v4"))


class TestGoogleDriveProvider(unittest.TestCase):
    def test_resolve_canonicalizes_my_drive_ref(self):
        provider = GoogleDriveProvider("user-1")
        out = provider.resolve("gdrive://me/items/root")
        self.assertEqual(out, "gdrive://me/items/root")

    def test_resolve_canonicalizes_shared_drive_ref(self):
        provider = GoogleDriveProvider("user-1")
        out = provider.resolve("drive/abc123/items/item789")
        self.assertEqual(out, "gdrive://drive/abc123/items/item789")

    def test_parse_ref_rejects_malformed_ref(self):
        provider = GoogleDriveProvider("user-1")
        with self.assertRaises(HTTPException) as ctx:
            provider.resolve("gdrive://bad/ref")
        self.assertEqual(ctx.exception.status_code, 400)

    def test_get_metadata_parses_folder_payload(self):
        provider = GoogleDriveProvider("user-1")
        response = SimpleNamespace(
            status_code=200,
            headers={},
            content=b"1",
            json=lambda: {
                "id": "folder-1",
                "name": "Folder",
                "mimeType": "application/vnd.google-apps.folder",
                "modifiedTime": "2026-01-01T00:00:00Z",
                "parents": ["root"],
            },
        )
        with (
            patch("app.services.file_providers.get_provider_auth_context", return_value={"token": "token", "metadata": {}}),
            patch("app.services.file_providers.requests.get", return_value=response),
        ):
            out = provider.get_metadata("gdrive://me/items/folder-1")
        self.assertEqual(out["type"], "dir")
        self.assertEqual(out["name"], "Folder")

    def test_list_children_returns_canonical_child_refs(self):
        provider = GoogleDriveProvider("user-1")

        folder_response = SimpleNamespace(
            status_code=200,
            headers={},
            content=b"1",
            json=lambda: {
                "id": "folder-1",
                "name": "Folder",
                "mimeType": "application/vnd.google-apps.folder",
            },
        )
        list_response = SimpleNamespace(
            status_code=200,
            headers={},
            content=b"1",
            json=lambda: {
                "files": [
                    {"id": "child-1", "name": "a.txt", "driveId": "drive-99"},
                    {"id": "child-2", "name": "b.txt"},
                ]
            },
        )
        with (
            patch("app.services.file_providers.get_provider_auth_context", return_value={"token": "token", "metadata": {}}),
            patch("app.services.file_providers.requests.get", side_effect=[folder_response, list_response]),
        ):
            out = provider.list_children("gdrive://me/items/folder-1")

        self.assertEqual(out[0], "gdrive://drive/drive-99/items/child-1")
        self.assertEqual(out[1], "gdrive://me/items/child-2")



    def test_drive_request_retries_on_500_then_succeeds(self):
        provider = GoogleDriveProvider("user-1")
        first = SimpleNamespace(status_code=500, headers={}, content=b"1", json=lambda: {"error": {"message": "server error"}})
        second = SimpleNamespace(
            status_code=200,
            headers={},
            content=b"1",
            json=lambda: {
                "id": "file-1",
                "name": "Doc",
                "mimeType": "text/plain",
                "size": "12",
                "modifiedTime": "2026-01-01T00:00:00Z",
            },
        )
        with (
            patch("app.services.file_providers.get_provider_auth_context", return_value={"token": "token", "metadata": {}}),
            patch("app.services.file_providers.requests.get", side_effect=[first, second]) as requests_get,
            patch("app.services.file_providers.time.sleep") as sleep,
            patch("app.services.file_providers.random.uniform", return_value=0.0),
            patch("app.services.file_providers.S", SimpleNamespace(
                google_drive_api_retry_max_attempts=3,
                google_drive_api_timeout_seconds=10,
                google_drive_api_retry_base_delay_seconds=0.01,
                google_drive_api_retry_jitter_seconds=0.0,
            )),
        ):
            out = provider.get_metadata("gdrive://me/items/file-1")

        self.assertEqual(out["name"], "Doc")
        self.assertEqual(requests_get.call_count, 2)
        sleep.assert_called_once()

    def test_drive_request_non_retryable_403_raises_without_retry(self):
        provider = GoogleDriveProvider("user-1")
        forbidden = SimpleNamespace(
            status_code=403,
            headers={},
            content=b"1",
            json=lambda: {"error": {"message": "insufficient scope"}},
        )
        with (
            patch("app.services.file_providers.get_provider_auth_context", return_value={"token": "token", "metadata": {}}),
            patch("app.services.file_providers.requests.get", return_value=forbidden) as requests_get,
            patch("app.services.file_providers.time.sleep") as sleep,
            patch("app.services.file_providers.S", SimpleNamespace(
                google_drive_api_retry_max_attempts=3,
                google_drive_api_timeout_seconds=10,
                google_drive_api_retry_base_delay_seconds=0.01,
                google_drive_api_retry_jitter_seconds=0.0,
            )),
        ):
            with self.assertRaises(HTTPException) as ctx:
                provider.get_metadata("gdrive://me/items/file-1")

        self.assertEqual(ctx.exception.status_code, 403)
        self.assertEqual(ctx.exception.detail["reason"], "insufficient_scope")
        self.assertEqual(requests_get.call_count, 1)
        sleep.assert_not_called()

    def test_drive_request_retries_429_and_returns_retry_hint(self):
        provider = GoogleDriveProvider("user-1")
        first = SimpleNamespace(status_code=429, headers={"Retry-After": "1"}, content=b"1", json=lambda: {"error": {"message": "rate limited"}})
        second = SimpleNamespace(status_code=429, headers={"Retry-After": "2"}, content=b"1", json=lambda: {"error": {"message": "rate limited"}})
        with (
            patch("app.services.file_providers.get_provider_auth_context", return_value={"token": "token", "metadata": {}}),
            patch("app.services.file_providers.requests.get", side_effect=[first, second]) as requests_get,
            patch("app.services.file_providers.time.sleep") as sleep,
            patch("app.services.file_providers.random.uniform", return_value=0.0),
            patch("app.services.file_providers.S", SimpleNamespace(
                google_drive_api_retry_max_attempts=2,
                google_drive_api_timeout_seconds=10,
                google_drive_api_retry_base_delay_seconds=0.01,
                google_drive_api_retry_jitter_seconds=0.0,
            )),
        ):
            with self.assertRaises(HTTPException) as ctx:
                provider.get_metadata("gdrive://me/items/file-1")

        self.assertEqual(ctx.exception.status_code, 429)
        self.assertIn("retry_after=2", ctx.exception.detail)
        self.assertEqual(requests_get.call_count, 2)
        sleep.assert_called_once()



    def test_upload_file_conflict_and_overwrite_behavior(self):
        provider = GoogleDriveProvider("user-1")
        with patch.object(provider, "_find_child_ref_by_name", return_value="gdrive://me/items/existing"), patch.object(provider, "get_metadata", return_value={"type": "file"}):
            with self.assertRaises(HTTPException) as ctx:
                provider.upload_file("gdrive://me/items/parent", "a.txt", file_obj=io.BytesIO(b"x"), content_type="text/plain", overwrite=False)
        self.assertEqual(ctx.exception.status_code, 409)

        patched = SimpleNamespace(status_code=200, headers={}, content=b"1", json=lambda: {})
        with (
            patch.object(provider, "_find_child_ref_by_name", return_value="gdrive://me/items/existing"),
            patch.object(provider, "get_metadata", side_effect=[{"type": "file"}, {"size": 1, "mime_type": "text/plain", "name": "a.txt"}]),
            patch("app.services.file_providers.requests.patch", return_value=patched) as requests_patch,
            patch.object(provider, "_build_headers", return_value={"Authorization": "Bearer t"}),
            patch.object(provider, "_request_retry_config", return_value={"timeout_seconds": 10}),
        ):
            out = provider.upload_file("gdrive://me/items/parent", "a.txt", file_obj=io.BytesIO(b"x"), content_type="text/plain", overwrite=True)
        self.assertEqual(out["name"], "a.txt")
        self.assertTrue(requests_patch.called)


    def test_upload_file_uses_resumable_over_threshold_and_retries(self):
        provider = GoogleDriveProvider("user-1")
        file_obj = io.BytesIO(b"abcdef")
        init_response = SimpleNamespace(status_code=200, headers={"Location": "https://upload.example/session"}, content=b"1", json=lambda: {})
        transient_put = SimpleNamespace(status_code=503, headers={}, content=b"1", json=lambda: {"error": {"message": "retry"}})
        success_put = SimpleNamespace(status_code=200, headers={}, content=b"1", json=lambda: {"id": "new-id", "driveId": ""})

        with (
            patch.object(provider, "_find_child_ref_by_name", return_value=None),
            patch.object(provider, "_build_headers", return_value={"Authorization": "Bearer t"}),
            patch.object(provider, "_request_retry_config", return_value={"max_attempts": 3, "timeout_seconds": 10, "base_delay": 0.01, "jitter": 0.0}),
            patch("app.services.file_providers.S", SimpleNamespace(google_drive_resumable_upload_threshold_bytes=1)),
            patch("app.services.file_providers.requests.post", return_value=init_response) as requests_post,
            patch("app.services.file_providers.requests.put", side_effect=[transient_put, success_put]) as requests_put,
            patch("app.services.file_providers.time.sleep") as sleep,
            patch("app.services.file_providers.random.uniform", return_value=0.0),
            patch.object(provider, "get_metadata", return_value={"size": 6, "mime_type": "text/plain", "name": "a.txt"}),
            patch("app.services.file_providers.record_filemgr_mount_upload_method") as record_method,
        ):
            out = provider.upload_file("gdrive://me/items/parent", "a.txt", file_obj=file_obj, content_type="text/plain", overwrite=False)

        self.assertEqual(out["name"], "a.txt")
        self.assertTrue(requests_post.called)
        self.assertEqual(requests_put.call_count, 2)
        sleep.assert_called_once()
        record_method.assert_called_once_with("google_drive", "resumable", "success")

    def test_upload_file_uses_simple_path_below_threshold(self):
        provider = GoogleDriveProvider("user-1")
        file_obj = io.BytesIO(b"abc")
        create_resp = SimpleNamespace(status_code=200, headers={}, content=b"1", json=lambda: {"id": "new-id", "driveId": ""})
        with (
            patch.object(provider, "_find_child_ref_by_name", return_value=None),
            patch("app.services.file_providers.S", SimpleNamespace(google_drive_resumable_upload_threshold_bytes=10_000_000)),
            patch.object(provider, "_build_headers", return_value={"Authorization": "Bearer t"}),
            patch.object(provider, "_request_retry_config", return_value={"timeout_seconds": 10}),
            patch("app.services.file_providers.requests.post", return_value=create_resp) as requests_post,
            patch.object(provider, "get_metadata", return_value={"size": 3, "mime_type": "text/plain", "name": "a.txt"}),
            patch("app.services.file_providers.record_filemgr_mount_upload_method") as record_method,
        ):
            out = provider.upload_file("gdrive://me/items/parent", "a.txt", file_obj=file_obj, content_type="text/plain", overwrite=False)

        self.assertEqual(out["size"], 3)
        self.assertEqual(requests_post.call_args.kwargs["params"]["uploadType"], "multipart")
        record_method.assert_called_once_with("google_drive", "simple", "success")


    def test_stream_file_uses_streaming_request(self):
        provider = GoogleDriveProvider("user-1")
        response = SimpleNamespace(status_code=200, headers={}, content=b"", json=lambda: {})
        with (
            patch("app.services.file_providers.get_provider_auth_context", return_value={"token": "token", "metadata": {}}),
            patch("app.services.file_providers.requests.get", return_value=response) as requests_get,
            patch("app.services.file_providers.S", SimpleNamespace(
                google_drive_api_retry_max_attempts=2,
                google_drive_api_timeout_seconds=10,
                google_drive_api_retry_base_delay_seconds=0.01,
                google_drive_api_retry_jitter_seconds=0.0,
            )),
        ):
            out = provider.stream_file("gdrive://me/items/file-1")

        self.assertIs(out, response)
        self.assertTrue(requests_get.call_args.kwargs["stream"])


if __name__ == "__main__":
    unittest.main()
