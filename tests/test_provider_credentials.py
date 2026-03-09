from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from fastapi import HTTPException

from app.services import provider_credentials


class TestProviderCredentials(unittest.TestCase):
    def test_upsert_encrypts_token_at_rest(self):
        table = MagicMock()
        table.get_item.return_value = {}

        response = MagicMock()
        response.status_code = 200
        response.headers = {"X-OAuth-Scopes": "repo, read:user"}
        response.content = b"1"
        response.json.return_value = {"login": "octocat", "id": 1}

        with (
            patch.object(provider_credentials, "T", SimpleNamespace(projects=table)),
            patch.object(provider_credentials.requests, "get", return_value=response),
            patch.object(provider_credentials, "kms_encrypt", return_value="ciphertext") as kms_encrypt,
        ):
            out = provider_credentials.upsert_provider_credential(
                "user-1",
                "github",
                "ghp_token",
                required_scopes=["repo"],
            )

        self.assertEqual(out.token_ct_b64, "ciphertext")
        kms_encrypt.assert_called_once_with("ghp_token")
        stored = table.put_item.call_args.kwargs["Item"]
        self.assertEqual(stored["token_ct_b64"], "ciphertext")
        self.assertNotIn("ghp_token", str(stored))
        self.assertEqual(stored["metadata"]["api_base_url"], "https://api.github.com")

    def test_validate_github_token_uses_enterprise_api_base_url(self):
        response = MagicMock()
        response.status_code = 200
        response.headers = {"X-OAuth-Scopes": "repo"}
        response.content = b"1"
        response.json.return_value = {"login": "octocat", "id": 1}

        with patch.object(provider_credentials.requests, "get", return_value=response) as requests_get:
            out = provider_credentials.validate_provider_token(
                "github",
                "ghp_token",
                required_scopes=["repo"],
                api_base_url="https://ghe.local/api/v3",
            )

        self.assertEqual(out["metadata"]["api_base_url"], "https://ghe.local/api/v3")
        requests_get.assert_called_once()
        self.assertTrue(requests_get.call_args.args[0].startswith("https://ghe.local/api/v3"))

    def test_validate_gitlab_token_uses_self_hosted_api_base_url(self):
        response = MagicMock()
        response.status_code = 200
        response.headers = {}
        response.content = b"1"
        response.json.return_value = {"id": 7, "active": True, "expires_at": None, "scopes": ["read_api"]}

        with patch.object(provider_credentials.requests, "get", return_value=response) as requests_get:
            out = provider_credentials.validate_provider_token(
                "gitlab",
                "glpat_token",
                required_scopes=["read_api"],
                api_base_url="https://gitlab.local/api/v4",
            )

        self.assertEqual(out["metadata"]["api_base_url"], "https://gitlab.local/api/v4")
        self.assertTrue(requests_get.call_args.args[0].startswith("https://gitlab.local/api/v4"))

    def test_missing_scope_returns_actionable_400(self):
        response = MagicMock()
        response.status_code = 200
        response.headers = {"X-OAuth-Scopes": "read:user"}
        response.content = b"1"
        response.json.return_value = {"login": "octocat", "id": 1}

        with patch.object(provider_credentials.requests, "get", return_value=response):
            with self.assertRaises(HTTPException) as ctx:
                provider_credentials.validate_provider_token("github", "ghp_token", required_scopes=["repo"])

        self.assertEqual(ctx.exception.status_code, 400)
        self.assertIn("missing required scopes", ctx.exception.detail)

    def test_invalid_token_returns_actionable_401(self):
        response = MagicMock()
        response.status_code = 401
        response.content = b""

        with patch.object(provider_credentials.requests, "get", return_value=response):
            with self.assertRaises(HTTPException) as ctx:
                provider_credentials.validate_provider_token("gitlab", "badtoken")

        self.assertEqual(ctx.exception.status_code, 401)
        self.assertIn("invalid/expired", ctx.exception.detail)


    def test_validate_google_drive_token_is_supported(self):
        out = provider_credentials.validate_provider_token("google_drive", "drive-token")

        self.assertEqual(out["scopes"], [])
        self.assertEqual(out["metadata"], {})

    def test_upsert_google_drive_credential_persists_provider(self):
        table = MagicMock()
        table.get_item.return_value = {}

        with (
            patch.object(provider_credentials, "T", SimpleNamespace(projects=table)),
            patch.object(provider_credentials, "kms_encrypt", return_value="ciphertext"),
        ):
            out = provider_credentials.upsert_provider_credential(
                "user-1",
                "google_drive",
                "drive-token",
            )

        self.assertEqual(out.provider, "google_drive")
        stored = table.put_item.call_args.kwargs["Item"]
        self.assertEqual(stored["provider"], "google_drive")


    def test_get_provider_auth_context_google_drive_refreshes_when_expired(self):
        table = MagicMock()
        table.get_item.return_value = {
            "Item": {
                "entity_type": "provider_credential",
                "owner": "user-1",
                "provider": "google_drive",
                "org": None,
                "token_ct_b64": "ciphertext",
                "scopes": ["https://www.googleapis.com/auth/drive.file"],
                "metadata": {"expires_at": "2000-01-01T00:00:00+00:00"},
                "created_at": "2026-01-01T00:00:00+00:00",
                "updated_at": "2026-01-01T00:00:00+00:00",
            }
        }

        with (
            patch.object(provider_credentials, "T", SimpleNamespace(projects=table)),
            patch("app.services.provider_oauth.refresh_google_oauth_access_token", return_value={
                "token": "fresh",
                "provider": "google_drive",
                "org": None,
                "scopes": ["https://www.googleapis.com/auth/drive.file"],
                "metadata": {"expires_at": "2099-01-01T00:00:00+00:00"},
            }) as refresh_google_oauth_access_token,
        ):
            ctx = provider_credentials.get_provider_auth_context("user-1", "google_drive")

        self.assertEqual(ctx["token"], "fresh")
        refresh_google_oauth_access_token.assert_called_once()

    def test_get_provider_auth_context_google_drive_reconnect_required_raises_401(self):
        table = MagicMock()
        table.get_item.return_value = {
            "Item": {
                "entity_type": "provider_credential",
                "owner": "user-1",
                "provider": "google_drive",
                "org": None,
                "token_ct_b64": "ciphertext",
                "scopes": ["https://www.googleapis.com/auth/drive.file"],
                "metadata": {"reconnect_required": True, "auth_failure_reason": "revoked"},
                "created_at": "2026-01-01T00:00:00+00:00",
                "updated_at": "2026-01-01T00:00:00+00:00",
            }
        }

        with patch.object(provider_credentials, "T", SimpleNamespace(projects=table)):
            with self.assertRaises(HTTPException) as ctx:
                provider_credentials.get_provider_auth_context("user-1", "google_drive")

        self.assertEqual(ctx.exception.status_code, 401)
        self.assertEqual(ctx.exception.detail["reason"], "revoked")

    def test_get_provider_token_decrypts_and_validates_required_scopes(self):
        table = MagicMock()
        table.get_item.return_value = {
            "Item": {
                "entity_type": "provider_credential",
                "owner": "user-1",
                "provider": "github",
                "org": None,
                "token_ct_b64": "ciphertext",
                "scopes": ["repo"],
                "metadata": {},
                "created_at": "2026-01-01T00:00:00+00:00",
                "updated_at": "2026-01-01T00:00:00+00:00",
            }
        }

        with (
            patch.object(provider_credentials, "T", SimpleNamespace(projects=table)),
            patch.object(provider_credentials, "kms_decrypt", return_value=b"clear-token") as kms_decrypt,
        ):
            token = provider_credentials.get_provider_token("user-1", "github", required_scopes=["repo"])

        self.assertEqual(token, "clear-token")
        kms_decrypt.assert_called_once_with("ciphertext")


if __name__ == "__main__":
    unittest.main()
