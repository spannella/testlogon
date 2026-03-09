from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from botocore.exceptions import ClientError
from fastapi import HTTPException

from app.services import provider_oauth


class TestProviderOAuth(unittest.TestCase):
    def test_build_google_oauth_start_returns_authorization_url_and_state(self):
        table = MagicMock()

        with (
            patch.object(provider_oauth, "T", SimpleNamespace(projects=table)),
            patch.object(provider_oauth, "S", SimpleNamespace(
                google_oauth_client_id="client-id",
                google_oauth_redirect_uri="https://example.com/oauth/google/callback",
                google_oauth_redirect_uri_allowlist="https://example.com/oauth/google/callback",
                google_oauth_scopes="https://www.googleapis.com/auth/drive.file",
                google_oauth_state_ttl_seconds=600,
                google_oauth_state_signing_secret="secret",
                ui_access_token_secret="",
            )),
            patch.object(provider_oauth, "_now_epoch", return_value=1_700_000_000),
        ):
            out = provider_oauth.build_google_oauth_start("user-1")

        self.assertEqual(out["provider"], "google_drive")
        self.assertIn("https://accounts.google.com/o/oauth2/v2/auth", out["authorization_url"])
        self.assertIn("client_id=client-id", out["authorization_url"])
        self.assertIn("redirect_uri=https%3A%2F%2Fexample.com%2Foauth%2Fgoogle%2Fcallback", out["authorization_url"])
        self.assertIn("state=", out["authorization_url"])
        self.assertTrue(out["state"])
        table.put_item.assert_called_once()

    def test_consume_google_oauth_state_rejects_replay(self):
        table = MagicMock()

        with (
            patch.object(provider_oauth, "T", SimpleNamespace(projects=table)),
            patch.object(provider_oauth, "S", SimpleNamespace(
                google_oauth_client_id="client-id",
                google_oauth_redirect_uri="https://example.com/oauth/google/callback",
                google_oauth_redirect_uri_allowlist="https://example.com/oauth/google/callback",
                google_oauth_scopes="https://www.googleapis.com/auth/drive.file",
                google_oauth_state_ttl_seconds=600,
                google_oauth_state_signing_secret="secret",
                ui_access_token_secret="",
            )),
            patch.object(provider_oauth, "_now_epoch", return_value=1_700_000_000),
        ):
            generated = provider_oauth.build_google_oauth_start("user-1")

        # first consume succeeds
        table.update_item.return_value = {
            "Attributes": {
                "state_sig": generated["state"].split(".", 1)[1],
                "provider": "google_drive",
                "consumed_at": "2026-01-01T00:00:00+00:00",
            }
        }
        with (
            patch.object(provider_oauth, "T", SimpleNamespace(projects=table)),
            patch.object(provider_oauth, "S", SimpleNamespace(
                google_oauth_state_signing_secret="secret",
                google_oauth_redirect_uri="https://example.com/oauth/google/callback",
                google_oauth_redirect_uri_allowlist="https://example.com/oauth/google/callback",
                ui_access_token_secret="",
            )),
            patch.object(provider_oauth, "_now_epoch", return_value=1_700_000_100),
        ):
            out = provider_oauth.consume_google_oauth_state("user-1", generated["state"])
        self.assertEqual(out["provider"], "google_drive")

        # second consume rejected as replay
        table.update_item.side_effect = ClientError(
            {"Error": {"Code": "ConditionalCheckFailedException", "Message": "boom"}},
            "UpdateItem",
        )
        table.get_item.return_value = {"Item": {"consumed_at": "2026-01-01T00:00:00+00:00"}}
        with (
            patch.object(provider_oauth, "T", SimpleNamespace(projects=table)),
            patch.object(provider_oauth, "S", SimpleNamespace(
                google_oauth_state_signing_secret="secret",
                google_oauth_redirect_uri="https://example.com/oauth/google/callback",
                google_oauth_redirect_uri_allowlist="https://example.com/oauth/google/callback",
                ui_access_token_secret="",
            )),
            patch.object(provider_oauth, "_now_epoch", return_value=1_700_000_100),
        ):
            with self.assertRaises(HTTPException) as ctx:
                provider_oauth.consume_google_oauth_state("user-1", generated["state"])
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertIn("already used", str(ctx.exception.detail))


    def test_complete_google_oauth_callback_stores_encrypted_tokens_and_metadata(self):
        table = MagicMock()

        token_response = MagicMock()
        token_response.status_code = 200
        token_response.content = b"1"
        token_response.json.return_value = {
            "access_token": "access-token",
            "refresh_token": "refresh-token",
            "expires_in": 3600,
            "scope": "https://www.googleapis.com/auth/drive.file openid",
            "token_type": "Bearer",
        }

        with (
            patch.object(provider_oauth, "consume_google_oauth_state", return_value={"provider": "google_drive"}),
            patch.object(provider_oauth.requests, "post", return_value=token_response) as requests_post,
            patch.object(provider_oauth, "upsert_provider_credential") as upsert_provider_credential,
            patch.object(provider_oauth, "_now_epoch", return_value=1_700_000_000),
            patch.object(provider_oauth, "S", SimpleNamespace(
                google_oauth_client_id="client-id",
                google_oauth_client_secret="client-secret",
                google_oauth_redirect_uri="https://example.com/oauth/google/callback",
                google_oauth_redirect_uri_allowlist="https://example.com/oauth/google/callback",
                google_oauth_token_url="https://oauth2.googleapis.com/token",
            )),
            patch.object(provider_oauth, "audit_event") as audit_event,
            patch("app.core.crypto.kms_encrypt", return_value="refresh-cipher"),
        ):
            upsert_provider_credential.return_value = SimpleNamespace(
                provider="google_drive",
                scopes=["https://www.googleapis.com/auth/drive.file", "openid"],
                metadata={"expires_at": "2023-11-14T23:13:20+00:00", "refresh_token_ct_b64": "refresh-cipher"},
                created_at="2026-01-01T00:00:00+00:00",
                updated_at="2026-01-01T00:00:00+00:00",
            )
            out = provider_oauth.complete_google_oauth_callback("user-1", code="abc", state="state")

        self.assertEqual(out["provider"], "google_drive")
        audit_event.assert_any_call("provider_oauth_connect", "user-1", None, outcome="success", provider="google_drive")
        requests_post.assert_called_once()
        upsert_provider_credential.assert_called_once()
        kwargs = upsert_provider_credential.call_args.kwargs
        self.assertIn("metadata_override", kwargs)
        self.assertIn("refresh_token_ct_b64", kwargs["metadata_override"])
        self.assertIn("expires_at", kwargs["metadata_override"])

    def test_complete_google_oauth_callback_invalid_code_returns_400(self):
        token_response = MagicMock()
        token_response.status_code = 400
        token_response.content = b"1"
        token_response.json.return_value = {
            "error": "invalid_grant",
            "error_description": "Bad Request",
        }

        with (
            patch.object(provider_oauth, "consume_google_oauth_state", return_value={"provider": "google_drive"}),
            patch.object(provider_oauth.requests, "post", return_value=token_response) as requests_post,
            patch.object(provider_oauth, "S", SimpleNamespace(
                google_oauth_client_id="client-id",
                google_oauth_client_secret="client-secret",
                google_oauth_redirect_uri="https://example.com/oauth/google/callback",
                google_oauth_token_url="https://oauth2.googleapis.com/token",
            )),
        ):
            with self.assertRaises(HTTPException) as ctx:
                provider_oauth.complete_google_oauth_callback("user-1", code="bad", state="state")

        self.assertEqual(ctx.exception.status_code, 400)
        self.assertIn("invalid_grant", str(ctx.exception.detail))


    def test_refresh_google_oauth_access_token_success_updates_expiry_metadata(self):
        token_response = MagicMock()
        token_response.status_code = 200
        token_response.content = b"1"
        token_response.json.return_value = {
            "access_token": "new-access-token",
            "expires_in": 1800,
            "scope": "https://www.googleapis.com/auth/drive.file",
            "token_type": "Bearer",
        }
        cred = SimpleNamespace(
            scopes=["https://www.googleapis.com/auth/drive.file"],
            metadata={"refresh_token_ct_b64": "refresh-cipher", "token_type": "Bearer"},
        )

        with (
            patch.object(provider_oauth, "get_provider_credential", return_value=cred),
            patch.object(provider_oauth.requests, "post", return_value=token_response),
            patch.object(provider_oauth, "rotate_provider_access_token") as rotate_provider_access_token,
            patch.object(provider_oauth, "record_filemgr_mount_refresh_attempt") as record_refresh_attempt,
            patch.object(provider_oauth, "S", SimpleNamespace(
                google_oauth_client_id="client-id",
                google_oauth_client_secret="client-secret",
                google_oauth_token_url="https://oauth2.googleapis.com/token",
            )),
            patch.object(provider_oauth, "_now_epoch", return_value=1_700_000_000),
            patch("app.core.crypto.kms_decrypt", side_effect=[b"refresh-token", b"new-access-token"]),
        ):
            rotate_provider_access_token.return_value = SimpleNamespace(
                token_ct_b64="new-access-cipher",
                provider="google_drive",
                org=None,
                scopes=["https://www.googleapis.com/auth/drive.file"],
                metadata={"expires_at": "2023-11-14T22:43:20+00:00"},
            )
            out = provider_oauth.refresh_google_oauth_access_token("user-1")

        self.assertEqual(out["provider"], "google_drive")
        self.assertIn("expires_at", out["metadata"])
        kwargs = rotate_provider_access_token.call_args.kwargs
        self.assertIn("metadata_override", kwargs)
        self.assertIn("expires_at", kwargs["metadata_override"])
        record_refresh_attempt.assert_any_call("google_drive", "attempt", "start")
        record_refresh_attempt.assert_any_call("google_drive", "success", "none")

    def test_refresh_google_oauth_access_token_invalid_grant_marks_reconnect_required(self):
        token_response = MagicMock()
        token_response.status_code = 400
        token_response.content = b"1"
        token_response.json.return_value = {
            "error": "invalid_grant",
            "error_description": "Token has been expired or revoked",
        }
        cred = SimpleNamespace(
            scopes=["https://www.googleapis.com/auth/drive.file"],
            metadata={"refresh_token_ct_b64": "refresh-cipher"},
        )

        with (
            patch.object(provider_oauth, "get_provider_credential", return_value=cred),
            patch.object(provider_oauth.requests, "post", return_value=token_response),
            patch.object(provider_oauth, "merge_provider_credential_metadata") as merge_provider_credential_metadata,
            patch.object(provider_oauth, "audit_event") as audit_event,
            patch.object(provider_oauth, "record_filemgr_mount_refresh_attempt") as record_refresh_attempt,
            patch.object(provider_oauth, "S", SimpleNamespace(
                google_oauth_client_id="client-id",
                google_oauth_client_secret="client-secret",
                google_oauth_token_url="https://oauth2.googleapis.com/token",
            )),
            patch("app.core.crypto.kms_decrypt", return_value=b"refresh-token"),
        ):
            with self.assertRaises(HTTPException) as ctx:
                provider_oauth.refresh_google_oauth_access_token("user-1")

        self.assertEqual(ctx.exception.status_code, 401)
        self.assertEqual(ctx.exception.detail["reason"], "revoked")
        merge_provider_credential_metadata.assert_called_once()
        audit_event.assert_any_call("provider_oauth_refresh", "user-1", None, outcome="failure", provider="google_drive", reason="revoked")
        record_refresh_attempt.assert_any_call("google_drive", "attempt", "start")
        record_refresh_attempt.assert_any_call("google_drive", "failure", "revoked")

    def test_consume_google_oauth_state_rejects_expired(self):
        table = MagicMock()

        with (
            patch.object(provider_oauth, "T", SimpleNamespace(projects=table)),
            patch.object(provider_oauth, "S", SimpleNamespace(
                google_oauth_client_id="client-id",
                google_oauth_redirect_uri="https://example.com/oauth/google/callback",
                google_oauth_redirect_uri_allowlist="https://example.com/oauth/google/callback",
                google_oauth_scopes="https://www.googleapis.com/auth/drive.file",
                google_oauth_state_ttl_seconds=60,
                google_oauth_state_signing_secret="secret",
                ui_access_token_secret="",
            )),
            patch.object(provider_oauth, "_now_epoch", return_value=1_700_000_000),
        ):
            generated = provider_oauth.build_google_oauth_start("user-1")

        with (
            patch.object(provider_oauth, "T", SimpleNamespace(projects=table)),
            patch.object(provider_oauth, "S", SimpleNamespace(
                google_oauth_state_signing_secret="secret",
                google_oauth_redirect_uri="https://example.com/oauth/google/callback",
                google_oauth_redirect_uri_allowlist="https://example.com/oauth/google/callback",
                ui_access_token_secret="",
            )),
            patch.object(provider_oauth, "_now_epoch", return_value=1_700_000_100),
        ):
            with self.assertRaises(HTTPException) as ctx:
                provider_oauth.consume_google_oauth_state("user-1", generated["state"])
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertIn("expired", str(ctx.exception.detail))


    def test_validate_google_drive_mount_oauth_configuration_requires_config_when_enabled(self):
        with patch.object(provider_oauth, "S", SimpleNamespace(
            filemgr_google_drive_mounts_enabled=True,
            google_oauth_client_id="",
            google_oauth_client_secret="",
            google_oauth_redirect_uri="",
            google_oauth_redirect_uri_allowlist="",
            google_oauth_state_signing_secret="",
            ui_access_token_secret="",
        )):
            with self.assertRaises(RuntimeError) as ctx:
                provider_oauth.validate_google_drive_mount_oauth_configuration()

        self.assertIn("GOOGLE_OAUTH_CLIENT_ID", str(ctx.exception))

    def test_validate_google_drive_mount_oauth_configuration_accepts_complete_config(self):
        with patch.object(provider_oauth, "S", SimpleNamespace(
            filemgr_google_drive_mounts_enabled=True,
            google_oauth_client_id="client-id",
            google_oauth_client_secret="client-secret",
            google_oauth_redirect_uri="https://example.com/callback",
            google_oauth_redirect_uri_allowlist="https://example.com/callback",
            google_oauth_state_signing_secret="state-secret",
            ui_access_token_secret="",
        )):
            provider_oauth.validate_google_drive_mount_oauth_configuration()

    def test_validate_google_drive_mount_oauth_configuration_skips_when_feature_disabled(self):
        with patch.object(provider_oauth, "S", SimpleNamespace(
            filemgr_google_drive_mounts_enabled=False,
            google_oauth_client_id="",
            google_oauth_client_secret="",
            google_oauth_redirect_uri="",
            google_oauth_redirect_uri_allowlist="",
            google_oauth_state_signing_secret="",
            ui_access_token_secret="",
        )):
            provider_oauth.validate_google_drive_mount_oauth_configuration()

    def test_consume_google_oauth_state_rejects_redirect_uri_mismatch(self):
        table = MagicMock()
        with (
            patch.object(provider_oauth, "T", SimpleNamespace(projects=table)),
            patch.object(provider_oauth, "S", SimpleNamespace(
                google_oauth_client_id="client-id",
                google_oauth_redirect_uri="https://example.com/oauth/google/callback",
                google_oauth_redirect_uri_allowlist="https://example.com/oauth/google/callback",
                google_oauth_scopes="https://www.googleapis.com/auth/drive.file",
                google_oauth_state_ttl_seconds=600,
                google_oauth_state_signing_secret="secret",
                ui_access_token_secret="",
            )),
            patch.object(provider_oauth, "_now_epoch", return_value=1_700_000_000),
        ):
            generated = provider_oauth.build_google_oauth_start("user-1")

        with (
            patch.object(provider_oauth, "T", SimpleNamespace(projects=table)),
            patch.object(provider_oauth, "S", SimpleNamespace(
                google_oauth_state_signing_secret="secret",
                google_oauth_redirect_uri="https://example.com/oauth/google/new-callback",
                google_oauth_redirect_uri_allowlist="https://example.com/oauth/google/new-callback",
                ui_access_token_secret="",
            )),
            patch.object(provider_oauth, "_now_epoch", return_value=1_700_000_100),
        ):
            with self.assertRaises(HTTPException) as ctx:
                provider_oauth.consume_google_oauth_state("user-1", generated["state"])

        self.assertEqual(ctx.exception.status_code, 400)
        self.assertIn("invalid oauth state", str(ctx.exception.detail))

    def test_build_google_oauth_start_rejects_redirect_uri_not_in_allowlist(self):
        with patch.object(provider_oauth, "S", SimpleNamespace(
            google_oauth_client_id="client-id",
            google_oauth_redirect_uri="https://example.com/oauth/google/callback",
            google_oauth_redirect_uri_allowlist="https://example.com/other/callback",
            google_oauth_scopes="https://www.googleapis.com/auth/drive.file",
            google_oauth_state_ttl_seconds=600,
            google_oauth_state_signing_secret="secret",
            ui_access_token_secret="",
        )):
            with self.assertRaises(HTTPException) as ctx:
                provider_oauth.build_google_oauth_start("user-1")

        self.assertEqual(ctx.exception.status_code, 500)
        self.assertIn("allowlist", str(ctx.exception.detail))


if __name__ == "__main__":
    unittest.main()
