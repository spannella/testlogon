from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import patch

from fastapi import HTTPException

from app.services.file_providers import (
    GitHubProvider,
    GitLabProvider,
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


if __name__ == "__main__":
    unittest.main()
