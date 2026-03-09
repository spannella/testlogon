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
            patch.object(provider_credentials, "_probe_s3_credentials") as probe,
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

    def test_upsert_s3_encrypts_secret_payload_and_metadata_only(self):
        table = MagicMock()
        table.get_item.return_value = {}

        with (
            patch.object(provider_credentials, "T", SimpleNamespace(projects=table)),
            patch.object(provider_credentials, "kms_encrypt", return_value="ciphertext") as kms_encrypt,
            patch.object(provider_credentials, "_probe_s3_credentials") as probe,
        ):
            out = provider_credentials.upsert_provider_credential(
                "user-1",
                "s3",
                None,
                access_key_id="AKIA123",
                secret_access_key="super-secret",
                session_token="sts-token",
                region="us-east-1",
                endpoint_url="https://s3.us-east-1.amazonaws.com",
                path_style=True,
                auth_mode="session_token",
                validation_bucket="acme-bucket",
            )

        self.assertEqual(out.provider, "s3")
        self.assertEqual(out.metadata["region"], "us-east-1")
        self.assertEqual(out.metadata["path_style"], True)
        self.assertEqual(out.metadata["auth_mode"], "session_token")

        encrypted_payload = kms_encrypt.call_args.args[0]
        self.assertIn('"access_key_id":"AKIA123"', encrypted_payload)
        self.assertIn('"secret_access_key":"super-secret"', encrypted_payload)

        stored = table.put_item.call_args.kwargs["Item"]
        self.assertNotIn("super-secret", str(stored))
        self.assertEqual(stored["metadata"]["region"], "us-east-1")
        probe.assert_called_once_with(
            access_key_id="AKIA123",
            secret_access_key="super-secret",
            session_token="sts-token",
            region="us-east-1",
            endpoint_url="https://s3.us-east-1.amazonaws.com",
            path_style=True,
            validation_bucket="acme-bucket",
        )

    def test_get_provider_auth_context_s3_exposes_parsed_secret_fields(self):
        table = MagicMock()
        table.get_item.return_value = {
            "Item": {
                "entity_type": "provider_credential",
                "owner": "user-1",
                "provider": "s3",
                "org": None,
                "token_ct_b64": "ciphertext",
                "scopes": [],
                "metadata": {"region": "us-east-1", "auth_mode": "access_key", "path_style": False, "endpoint_url": None},
                "created_at": "2026-01-01T00:00:00+00:00",
                "updated_at": "2026-01-01T00:00:00+00:00",
            }
        }

        with (
            patch.object(provider_credentials, "T", SimpleNamespace(projects=table)),
            patch.object(
                provider_credentials,
                "kms_decrypt",
                return_value=b'{"access_key_id":"AKIA123","secret_access_key":"super-secret","session_token":null}',
            ),
        ):
            ctx = provider_credentials.get_provider_auth_context("user-1", "s3")

        self.assertEqual(ctx["provider"], "s3")
        self.assertEqual(ctx["access_key_id"], "AKIA123")
        self.assertEqual(ctx["secret_access_key"], "super-secret")
        self.assertEqual(ctx["token"], "super-secret")

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


    def test_validate_s3_credentials_missing_validation_bucket(self):
        with self.assertRaises(HTTPException) as ctx:
            provider_credentials.validate_provider_token(
                "s3",
                None,
                access_key_id="AKIA123",
                secret_access_key="super-secret",
            )

        self.assertEqual(ctx.exception.status_code, 400)
        self.assertIn("validation_bucket", ctx.exception.detail)

    def test_probe_s3_credentials_maps_client_errors(self):
        from botocore.exceptions import ClientError

        client = MagicMock()
        client.head_bucket.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "denied"}},
            "HeadBucket",
        )
        with patch.object(provider_credentials.boto3, "client", return_value=client):
            with self.assertRaises(HTTPException) as ctx:
                provider_credentials._probe_s3_credentials(
                    access_key_id="AKIA123",
                    secret_access_key="super-secret",
                    session_token=None,
                    region="us-east-1",
                    endpoint_url=None,
                    path_style=False,
                    validation_bucket="acme-bucket",
                )

        self.assertEqual(ctx.exception.status_code, 403)
        self.assertIn("access denied", ctx.exception.detail.lower())


    def test_validate_s3_credentials_failure_from_probe_is_actionable(self):
        with patch.object(
            provider_credentials,
            "_probe_s3_credentials",
            side_effect=HTTPException(status_code=401, detail="s3 authentication failed"),
        ):
            with self.assertRaises(HTTPException) as ctx:
                provider_credentials.validate_provider_token(
                    "s3",
                    None,
                    access_key_id="AKIA123",
                    secret_access_key="super-secret",
                    validation_bucket="acme-bucket",
                )

        self.assertEqual(ctx.exception.status_code, 401)
        self.assertIn("authentication", str(ctx.exception.detail).lower())

    def test_validate_s3_credentials_accepts_token_json_payload(self):
        with patch.object(provider_credentials, "_probe_s3_credentials") as probe:
            out = provider_credentials.validate_provider_token(
                "s3",
                '{"access_key_id":"AKIAJSON","secret_access_key":"json-secret"}',
                validation_bucket="acme-bucket",
            )

        self.assertEqual(out["secret_payload"]["access_key_id"], "AKIAJSON")
        self.assertEqual(out["secret_payload"]["secret_access_key"], "json-secret")
        probe.assert_called_once()

    def test_validate_s3_credentials_success_uses_probe(self):
        with patch.object(provider_credentials, "_probe_s3_credentials") as probe:
            out = provider_credentials.validate_provider_token(
                "s3",
                None,
                access_key_id="AKIA123",
                secret_access_key="super-secret",
                region="us-east-1",
                endpoint_url="https://s3.us-east-1.amazonaws.com",
                path_style=True,
                auth_mode="access_key",
                validation_bucket="acme-bucket",
            )

        self.assertEqual(out["metadata"]["region"], "us-east-1")
        probe.assert_called_once()


    def test_upsert_s3_logs_redacted_fields_only(self):
        table = MagicMock()
        table.get_item.return_value = {}

        with (
            patch.object(provider_credentials, "T", SimpleNamespace(projects=table)),
            patch.object(provider_credentials, "kms_encrypt", return_value="ciphertext"),
            patch.object(provider_credentials, "_probe_s3_credentials"),
            patch.object(provider_credentials.logger, "info") as log_info,
        ):
            provider_credentials.upsert_provider_credential(
                "user-1",
                "s3",
                None,
                access_key_id="AKIA123",
                secret_access_key="super-secret",
                session_token="sts-token",
                region="us-east-1",
                validation_bucket="acme-bucket",
            )

        log_info.assert_called_once()
        args, kwargs = log_info.call_args
        self.assertNotIn("super-secret", str(args))
        self.assertNotIn("super-secret", str(kwargs))
        self.assertEqual(kwargs["extra"]["has_secret_access_key"], True)

    def test_delete_logs_without_secret_payload(self):
        table = MagicMock()
        table.get_item.return_value = {
            "Item": {
                "entity_type": "provider_credential",
                "owner": "user-1",
                "provider": "s3",
                "org": None,
                "token_ct_b64": "ciphertext",
            }
        }
        with (
            patch.object(provider_credentials, "T", SimpleNamespace(projects=table)),
            patch.object(provider_credentials.logger, "info") as log_info,
        ):
            out = provider_credentials.delete_provider_credential("user-1", "s3")

        self.assertTrue(out["deleted"])
        log_info.assert_called_once()
        self.assertNotIn("ciphertext", str(log_info.call_args))


if __name__ == "__main__":
    unittest.main()
