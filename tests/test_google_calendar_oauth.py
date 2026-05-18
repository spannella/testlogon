from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from fastapi import HTTPException

from app.services import google_calendar_oauth as oauth


class _FakeTable:
    def __init__(self):
        self.items = {}

    def put_item(self, Item):
        self.items[(Item["calendar_id"], Item["sk"])] = dict(Item)

    def get_item(self, Key):
        item = self.items.get((Key["calendar_id"], Key["sk"]))
        return {"Item": dict(item)} if item else {}


class _FakeConditionalTable(_FakeTable):
    def __init__(self):
        super().__init__()
        self.force_conditional_failure = False

    def update_item(self, **kwargs):
        if self.force_conditional_failure:
            raise RuntimeError("ConditionalCheckFailedException")
        key = kwargs["Key"]
        item = self.items.get((key["calendar_id"], key["sk"]))
        if not item:
            return {}
        item = dict(item)
        item["consumed"] = True
        item["consumed_at_utc"] = kwargs["ExpressionAttributeValues"][":consumed_at"]
        self.items[(key["calendar_id"], key["sk"])] = item
        return {"Attributes": dict(item)}


class TestGoogleCalendarOAuth(unittest.TestCase):
    def test_create_connect_start_state_persists_state_and_returns_authorize_url(self):
        table = _FakeTable()
        with (
            patch.object(oauth, "T", SimpleNamespace(calendar=table)),
            patch.object(oauth.secrets, "token_urlsafe", side_effect=["state-token-1234567890", "nonce-token"]),
            patch.object(
                oauth,
                "S",
                SimpleNamespace(
                    google_calendar_oauth_client_id="client-1",
                    google_calendar_oauth_client_secret="secret-1",
                    google_calendar_oauth_redirect_uri="https://app.example.com/callback",
                    google_calendar_oauth_auth_base_url="https://accounts.google.com/o/oauth2/v2/auth",
                    google_calendar_oauth_token_url="https://oauth2.googleapis.com/token",
                    google_calendar_oauth_userinfo_url="https://openidconnect.googleapis.com/v1/userinfo",
                    google_calendar_oauth_scopes="openid,email,profile,https://www.googleapis.com/auth/calendar.events",
                    google_calendar_oauth_state_ttl_seconds=600,
                    google_calendar_connection_default_id="google-primary",
                ),
            ),
        ):
            out = oauth.create_connect_start_state(user_sub="user-1")

        self.assertEqual(out["state"], "state-token-1234567890")
        self.assertEqual(out["nonce"], "nonce-token")
        self.assertIn("response_type=code", out["authorization_url"])
        self.assertIn("client_id=client-1", out["authorization_url"])
        self.assertIn("scope=openid", out["authorization_url"])
        stored = table.items[("gcal_oauth_state#state-token-1234567890", "meta")]
        self.assertEqual(stored["user_sub"], "user-1")
        self.assertFalse(stored["consumed"])

    def test_consume_state_rejects_malformed_state(self):
        table = _FakeTable()
        with patch.object(oauth, "T", SimpleNamespace(calendar=table)):
            with self.assertRaises(HTTPException):
                oauth.consume_connect_state(user_sub="user-1", state="short")

    def test_consume_state_rejects_expired_state(self):
        table = _FakeTable()
        table.put_item(
            Item={
                "calendar_id": "gcal_oauth_state#state-token-123456789",
                "sk": "meta",
                "type": "google_oauth_state",
                "user_sub": "user-1",
                "expires_at_utc": "2020-01-01T00:00:00Z",
                "consumed": False,
            }
        )

        with patch.object(oauth, "T", SimpleNamespace(calendar=table)):
            with self.assertRaises(HTTPException):
                oauth.consume_connect_state(user_sub="user-1", state="state-token-123456789")

    def test_consume_state_rejects_replay(self):
        table = _FakeTable()
        table.put_item(
            Item={
                "calendar_id": "gcal_oauth_state#state-token-123456789",
                "sk": "meta",
                "type": "google_oauth_state",
                "user_sub": "user-1",
                "expires_at_utc": "2099-01-01T00:00:00Z",
                "consumed": True,
            }
        )

        with patch.object(oauth, "T", SimpleNamespace(calendar=table)):
            with self.assertRaises(HTTPException):
                oauth.consume_connect_state(user_sub="user-1", state="state-token-123456789")

    def test_consume_state_uses_atomic_update_when_supported(self):
        table = _FakeConditionalTable()
        table.put_item(
            Item={
                "calendar_id": "gcal_oauth_state#state-token-123456789",
                "sk": "meta",
                "type": "google_oauth_state",
                "user_sub": "user-1",
                "expires_at_utc": "2099-01-01T00:00:00Z",
                "consumed": False,
            }
        )
        with patch.object(oauth, "T", SimpleNamespace(calendar=table)):
            out = oauth.consume_connect_state(user_sub="user-1", state="state-token-123456789")
        self.assertTrue(out["consumed"])
        self.assertTrue(bool(out.get("consumed_at_utc")))

    def test_consume_state_surfaces_atomic_conditional_failure_as_replay(self):
        table = _FakeConditionalTable()
        table.put_item(
            Item={
                "calendar_id": "gcal_oauth_state#state-token-123456789",
                "sk": "meta",
                "type": "google_oauth_state",
                "user_sub": "user-1",
                "expires_at_utc": "2099-01-01T00:00:00Z",
                "consumed": False,
            }
        )
        table.force_conditional_failure = True
        with patch.object(oauth, "T", SimpleNamespace(calendar=table)):
            with self.assertRaises(HTTPException) as exc:
                oauth.consume_connect_state(user_sub="user-1", state="state-token-123456789")
        self.assertEqual(exc.exception.status_code, 400)

    def test_exchange_code_for_tokens_rejects_invalid_code(self):
        bad_response = Mock(status_code=400)
        bad_response.content = b'{"error":"invalid_grant"}'
        bad_response.json.return_value = {"error": "invalid_grant"}

        with (
            patch.object(oauth.requests, "post", return_value=bad_response),
            patch.object(
                oauth,
                "S",
                SimpleNamespace(
                    google_calendar_oauth_client_id="client-1",
                    google_calendar_oauth_client_secret="secret-1",
                    google_calendar_oauth_redirect_uri="https://app.example.com/callback",
                    google_calendar_oauth_token_url="https://oauth2.googleapis.com/token",
                ),
            ),
        ):
            with self.assertRaises(HTTPException):
                oauth.exchange_code_for_tokens(code="bad-code")

    def test_exchange_code_for_tokens_handles_network_errors(self):
        with (
            patch.object(oauth.requests, "post", side_effect=oauth.requests.RequestException("network down")),
            patch.object(
                oauth,
                "S",
                SimpleNamespace(
                    google_calendar_oauth_client_id="client-1",
                    google_calendar_oauth_client_secret="secret-1",
                    google_calendar_oauth_redirect_uri="https://app.example.com/callback",
                    google_calendar_oauth_token_url="https://oauth2.googleapis.com/token",
                ),
            ),
        ):
            with self.assertRaises(HTTPException) as exc:
                oauth.exchange_code_for_tokens(code="code-1")

        self.assertEqual(exc.exception.status_code, 502)

    def test_exchange_code_for_tokens_rejects_missing_required_google_scope(self):
        ok_response = Mock(status_code=200)
        ok_response.content = b'{"access_token":"access-1","scope":"openid email profile"}'
        ok_response.json.return_value = {
            "access_token": "access-1",
            "refresh_token": "refresh-1",
            "scope": "openid email profile",
            "expires_in": 3600,
        }
        with (
            patch.object(oauth.requests, "post", return_value=ok_response),
            patch.object(oauth, "record_google_calendar_oauth_callback_outcome") as outcome_metric,
            patch.object(oauth, "record_google_calendar_oauth_callback_rejection") as rejection_metric,
            patch.object(
                oauth,
                "S",
                SimpleNamespace(
                    google_calendar_oauth_client_id="client-1",
                    google_calendar_oauth_client_secret="secret-1",
                    google_calendar_oauth_redirect_uri="https://app.example.com/callback",
                    google_calendar_oauth_token_url="https://oauth2.googleapis.com/token",
                    google_calendar_oauth_scopes="openid,email,profile,https://www.googleapis.com/auth/calendar.events",
                    google_calendar_oauth_strict_scope_validation=False,
                ),
            ),
        ):
            with self.assertRaises(HTTPException) as exc:
                oauth.exchange_code_for_tokens(code="code-1")
        self.assertEqual(exc.exception.status_code, 400)
        rejection_metric.assert_called_once_with(reason="scope_validation_failed_missing_required")
        outcome_metric.assert_called_once_with(outcome="error", reason="scope_validation_failed_missing_required")

    def test_exchange_code_for_tokens_rejects_missing_refresh_token_by_default(self):
        ok_response = Mock(status_code=200)
        ok_response.content = b'{"access_token":"access-1","scope":"openid email profile https://www.googleapis.com/auth/calendar.events"}'
        ok_response.json.return_value = {
            "access_token": "access-1",
            "scope": "openid email profile https://www.googleapis.com/auth/calendar.events",
            "expires_in": 3600,
        }
        with (
            patch.object(oauth.requests, "post", return_value=ok_response),
            patch.object(
                oauth,
                "S",
                SimpleNamespace(
                    google_calendar_oauth_client_id="client-1",
                    google_calendar_oauth_client_secret="secret-1",
                    google_calendar_oauth_redirect_uri="https://app.example.com/callback",
                    google_calendar_oauth_token_url="https://oauth2.googleapis.com/token",
                    google_calendar_oauth_scopes="openid,email,profile,https://www.googleapis.com/auth/calendar.events",
                ),
            ),
        ):
            with self.assertRaises(HTTPException) as exc:
                oauth.exchange_code_for_tokens(code="code-1")
        self.assertEqual(exc.exception.status_code, 400)

    def test_exchange_code_for_tokens_allows_missing_refresh_token_when_disabled(self):
        ok_response = Mock(status_code=200)
        ok_response.content = b'{"access_token":"access-1","scope":"openid email profile https://www.googleapis.com/auth/calendar.events"}'
        ok_response.json.return_value = {
            "access_token": "access-1",
            "scope": "openid email profile https://www.googleapis.com/auth/calendar.events",
            "expires_in": 3600,
        }
        with (
            patch.object(oauth.requests, "post", return_value=ok_response),
            patch.object(
                oauth,
                "S",
                SimpleNamespace(
                    google_calendar_oauth_client_id="client-1",
                    google_calendar_oauth_client_secret="secret-1",
                    google_calendar_oauth_redirect_uri="https://app.example.com/callback",
                    google_calendar_oauth_token_url="https://oauth2.googleapis.com/token",
                    google_calendar_oauth_scopes="openid,email,profile,https://www.googleapis.com/auth/calendar.events",
                    google_calendar_oauth_require_refresh_token=False,
                ),
            ),
        ):
            out = oauth.exchange_code_for_tokens(code="code-1")
        self.assertEqual(out["access_token"], "access-1")
        self.assertEqual(out["refresh_token"], "")

    def test_exchange_code_for_tokens_rejects_unexpected_scope_when_strict_enabled(self):
        ok_response = Mock(status_code=200)
        ok_response.content = b'{"access_token":"access-1","scope":"openid email profile https://www.googleapis.com/auth/calendar.events https://www.googleapis.com/auth/calendar"}'
        ok_response.json.return_value = {
            "access_token": "access-1",
            "refresh_token": "refresh-1",
            "scope": "openid email profile https://www.googleapis.com/auth/calendar.events https://www.googleapis.com/auth/calendar",
            "expires_in": 3600,
        }
        with (
            patch.object(oauth.requests, "post", return_value=ok_response),
            patch.object(oauth, "record_google_calendar_oauth_callback_outcome") as outcome_metric,
            patch.object(oauth, "record_google_calendar_oauth_callback_rejection") as rejection_metric,
            patch.object(
                oauth,
                "S",
                SimpleNamespace(
                    google_calendar_oauth_client_id="client-1",
                    google_calendar_oauth_client_secret="secret-1",
                    google_calendar_oauth_redirect_uri="https://app.example.com/callback",
                    google_calendar_oauth_token_url="https://oauth2.googleapis.com/token",
                    google_calendar_oauth_scopes="openid,email,profile,https://www.googleapis.com/auth/calendar.events",
                    google_calendar_oauth_strict_scope_validation=True,
                ),
            ),
        ):
            with self.assertRaises(HTTPException) as exc:
                oauth.exchange_code_for_tokens(code="code-1")
        self.assertEqual(exc.exception.status_code, 400)
        rejection_metric.assert_called_once_with(reason="scope_validation_failed_unexpected_scope")
        outcome_metric.assert_called_once_with(outcome="error", reason="scope_validation_failed_unexpected_scope")

    def test_handle_connect_callback_links_account_and_upserts_connection(self):
        with (
            patch.object(oauth, "consume_connect_state"),
            patch.object(
                oauth,
                "exchange_code_for_tokens",
                return_value={
                    "access_token": "access",
                    "refresh_token": "refresh",
                    "token_type": "Bearer",
                    "scope": "calendar.events",
                    "id_token": "id",
                    "expires_at_utc": "2099-01-01T00:00:00Z",
                },
            ),
            patch.object(
                oauth,
                "fetch_google_account_profile",
                return_value={"sub": "google-sub-1", "email": "user@example.com", "email_verified": "true"},
            ),
            patch.object(
                oauth,
                "upsert_calendar_provider_connection",
                return_value={
                    "provider": "google",
                    "connection_id": "google-google-sub-1",
                    "account_email": "user@example.com",
                    "updated_at_utc": "2099-01-01T00:00:00Z",
                },
            ) as upsert,
            patch.object(oauth, "record_google_calendar_oauth_callback_outcome") as outcome_metric,
            patch.object(oauth, "S", SimpleNamespace(google_calendar_connection_default_id="google-primary")),
        ):
            out = oauth.handle_connect_callback(user_sub="user-1", state="state-token-123456789", code="code-1")

        upsert.assert_called_once()
        self.assertEqual(out["linked"], True)
        self.assertEqual(out["connection_id"], "google-google-sub-1")
        self.assertEqual(out["account_email"], "user@example.com")
        outcome_metric.assert_called_once_with(outcome="success", reason="linked")

    def test_handle_connect_callback_rejects_missing_google_subject(self):
        with (
            patch.object(oauth, "consume_connect_state"),
            patch.object(
                oauth,
                "exchange_code_for_tokens",
                return_value={
                    "access_token": "access",
                    "refresh_token": "refresh",
                    "token_type": "Bearer",
                    "scope": "calendar.events",
                    "id_token": "id",
                    "expires_at_utc": "2099-01-01T00:00:00Z",
                },
            ),
            patch.object(
                oauth,
                "fetch_google_account_profile",
                return_value={"sub": "", "email": "user@example.com", "email_verified": "true"},
            ),
            patch.object(oauth, "record_google_calendar_oauth_callback_outcome") as outcome_metric,
            patch.object(oauth, "record_google_calendar_oauth_callback_rejection") as rejection_metric,
            patch.object(oauth, "upsert_calendar_provider_connection") as upsert,
        ):
            with self.assertRaises(HTTPException) as exc:
                oauth.handle_connect_callback(user_sub="user-1", state="state-token-123456789", code="code-1")

        self.assertEqual(exc.exception.status_code, 400)
        rejection_metric.assert_called_once_with(reason="missing_google_subject")
        outcome_metric.assert_called_once_with(outcome="error", reason="missing_google_subject")
        upsert.assert_not_called()

    def test_handle_connect_callback_rejects_unverified_email(self):
        with (
            patch.object(oauth, "consume_connect_state"),
            patch.object(
                oauth,
                "exchange_code_for_tokens",
                return_value={
                    "access_token": "access",
                    "refresh_token": "refresh",
                    "token_type": "Bearer",
                    "scope": "calendar.events",
                    "id_token": "id",
                    "expires_at_utc": "2099-01-01T00:00:00Z",
                },
            ),
            patch.object(
                oauth,
                "fetch_google_account_profile",
                return_value={"sub": "google-sub-1", "email": "user@example.com", "email_verified": "false"},
            ),
            patch.object(oauth, "record_google_calendar_oauth_callback_outcome") as outcome_metric,
            patch.object(oauth, "record_google_calendar_oauth_callback_rejection") as rejection_metric,
            patch.object(oauth, "upsert_calendar_provider_connection") as upsert,
        ):
            with self.assertRaises(HTTPException) as exc:
                oauth.handle_connect_callback(user_sub="user-1", state="state-token-123456789", code="code-1")

        self.assertEqual(exc.exception.status_code, 400)
        rejection_metric.assert_called_once_with(reason="unverified_google_email")
        outcome_metric.assert_called_once_with(outcome="error", reason="unverified_google_email")
        upsert.assert_not_called()


    def test_handle_disconnect_revokes_and_marks_inactive(self):
        with (
            patch.object(
                oauth,
                "get_calendar_provider_connection",
                return_value={
                    "token_payload": {"refresh_token": "refresh-1", "access_token": "access-1"},
                },
            ),
            patch.object(oauth, "revoke_google_token") as revoke,
            patch.object(
                oauth,
                "disconnect_calendar_provider_connection",
                return_value={
                    "provider": "google",
                    "connection_id": "google-primary",
                    "account_email": "user@example.com",
                    "active": False,
                    "revoked": True,
                    "revoke_status": "revoked",
                    "disconnected_at_utc": "2099-01-01T00:00:00Z",
                },
            ) as deactivate,
        ):
            out = oauth.handle_disconnect(user_sub="user-1", connection_id="google-primary")

        revoke.assert_called_once_with(token="refresh-1")
        deactivate.assert_called_once()
        self.assertFalse(out["active"])

    def test_handle_disconnect_surfaces_retry_safe_revocation_error(self):
        with (
            patch.object(
                oauth,
                "get_calendar_provider_connection",
                return_value={"token_payload": {"refresh_token": "refresh-1"}},
            ),
            patch.object(
                oauth,
                "revoke_google_token",
                side_effect=HTTPException(status_code=502, detail="upstream down"),
            ),
        ):
            with self.assertRaises(HTTPException) as exc:
                oauth.handle_disconnect(user_sub="user-1", connection_id="google-primary")

        self.assertEqual(exc.exception.status_code, 502)

    def test_fetch_google_account_profile_handles_network_errors(self):
        with (
            patch.object(oauth.requests, "get", side_effect=oauth.requests.RequestException("network down")),
            patch.object(
                oauth,
                "S",
                SimpleNamespace(google_calendar_oauth_userinfo_url="https://openidconnect.googleapis.com/v1/userinfo"),
            ),
        ):
            with self.assertRaises(HTTPException) as exc:
                oauth.fetch_google_account_profile(access_token="access-1")
        self.assertEqual(exc.exception.status_code, 502)

    def test_revoke_google_token_handles_network_errors(self):
        with (
            patch.object(oauth.requests, "post", side_effect=oauth.requests.RequestException("network down")),
            patch.object(oauth, "S", SimpleNamespace(google_calendar_oauth_revoke_url="https://oauth2.googleapis.com/revoke")),
        ):
            with self.assertRaises(HTTPException) as exc:
                oauth.revoke_google_token(token="refresh-1")
        self.assertEqual(exc.exception.status_code, 502)

    def test_revoke_google_token_treats_invalid_token_as_success(self):
        invalid_token_resp = Mock(status_code=400)
        invalid_token_resp.content = b'{"error":"invalid_token"}'
        invalid_token_resp.json.return_value = {"error": "invalid_token"}
        with (
            patch.object(oauth.requests, "post", return_value=invalid_token_resp),
            patch.object(oauth, "S", SimpleNamespace(google_calendar_oauth_revoke_url="https://oauth2.googleapis.com/revoke")),
        ):
            out = oauth.revoke_google_token(token="refresh-1")
        self.assertIsNone(out)


if __name__ == "__main__":
    unittest.main()
