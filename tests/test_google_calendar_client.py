from __future__ import annotations

import unittest
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import Mock, patch

from fastapi import HTTPException

from app.services import google_calendar_client as client


class TestGoogleCalendarClient(unittest.TestCase):
    def test_refresh_access_token_updates_connection(self):
        token_response = Mock(status_code=200)
        token_response.content = b'{"access_token":"new-access"}'
        token_response.json.return_value = {
            "access_token": "new-access",
            "expires_in": 1200,
            "token_type": "Bearer",
            "scope": "calendar.events",
        }
        with (
            patch.object(
                client,
                "get_calendar_provider_connection",
                return_value={
                    "account_email": "user@example.com",
                    "token_payload": {
                        "refresh_token": "refresh-1",
                        "access_token": "old-access",
                        "expires_at_utc": "2020-01-01T00:00:00Z",
                    },
                },
            ),
            patch.object(client.requests, "post", return_value=token_response),
            patch.object(client, "upsert_calendar_provider_connection") as upsert,
            patch.object(client, "update_calendar_provider_connection_sync_status") as update_status,
            patch.object(
                client,
                "S",
                SimpleNamespace(
                    google_calendar_oauth_token_url="https://oauth2.googleapis.com/token",
                    google_calendar_oauth_client_id="client-1",
                    google_calendar_oauth_client_secret="secret-1",
                    google_calendar_api_timeout_seconds=20,
                ),
            ),
        ):
            out = client.refresh_google_calendar_access_token(user_sub="user-1", connection_id="google-primary")

        self.assertEqual(out["access_token"], "new-access")
        upsert.assert_called_once()
        update_status.assert_called()

    def test_list_calendars_refreshes_expired_token_before_request(self):
        with (
            patch.object(
                client,
                "get_calendar_provider_connection",
                return_value={
                    "token_payload": {"access_token": "old", "expires_at_utc": "2020-01-01T00:00:00Z"},
                },
            ),
            patch.object(
                client,
                "refresh_google_calendar_access_token",
                return_value={"access_token": "fresh-token"},
            ) as refresh,
            patch.object(client, "update_calendar_provider_connection_sync_status"),
            patch.object(client.requests, "request") as req,
            patch.object(client, "S", SimpleNamespace(google_calendar_api_base_url="https://www.googleapis.com/calendar/v3", google_calendar_api_timeout_seconds=20)),
        ):
            ok = Mock(status_code=200)
            ok.content = b'{"items":[]}'
            ok.json.return_value = {"items": []}
            req.return_value = ok
            out = client.list_google_calendars(user_sub="user-1", connection_id="google-primary")

        refresh.assert_called_once()
        self.assertEqual(out["items"], [])

    def test_list_events_classifies_retryable_errors(self):
        retryable = Mock(status_code=503)
        retryable.content = b'{"error":{"message":"backend unavailable"}}'
        retryable.json.return_value = {"error": {"message": "backend unavailable"}}
        with (
            patch.object(
                client,
                "get_calendar_provider_connection",
                return_value={"token_payload": {"access_token": "token", "expires_at_utc": "2099-01-01T00:00:00Z"}},
            ),
            patch.object(client.requests, "request", return_value=retryable),
            patch.object(client, "update_calendar_provider_connection_sync_status") as status_update,
            patch.object(client, "S", SimpleNamespace(google_calendar_api_base_url="https://www.googleapis.com/calendar/v3", google_calendar_api_timeout_seconds=20)),
        ):
            with self.assertRaises(HTTPException) as exc:
                client.list_google_calendar_events(
                    user_sub="user-1",
                    connection_id="google-primary",
                    google_calendar_id="gcal-1",
                )

        self.assertEqual(exc.exception.status_code, 502)
        self.assertTrue(exc.exception.detail["retryable"])
        status_update.assert_called()

    def test_list_events_retries_retryable_error_before_failing(self):
        retryable = Mock(status_code=503)
        retryable.content = b'{"error":{"message":"backend unavailable"}}'
        retryable.json.return_value = {"error": {"message": "backend unavailable"}}
        with (
            patch.object(
                client,
                "get_calendar_provider_connection",
                return_value={"token_payload": {"access_token": "token", "expires_at_utc": "2099-01-01T00:00:00Z"}},
            ),
            patch.object(client.requests, "request", return_value=retryable) as req,
            patch.object(client.time, "sleep") as sleep,
            patch.object(client, "record_google_calendar_api_retry") as retry_metric,
            patch.object(client, "update_calendar_provider_connection_sync_status"),
            patch.object(
                client,
                "S",
                SimpleNamespace(
                    google_calendar_api_base_url="https://www.googleapis.com/calendar/v3",
                    google_calendar_api_timeout_seconds=20,
                    google_calendar_api_retry_max_attempts=3,
                    google_calendar_api_retry_base_backoff_seconds=0.01,
                ),
            ),
        ):
            with self.assertRaises(HTTPException) as exc:
                client.list_google_calendar_events(
                    user_sub="user-1",
                    connection_id="google-primary",
                    google_calendar_id="gcal-1",
                )

        self.assertEqual(exc.exception.status_code, 502)
        self.assertEqual(req.call_count, 3)
        self.assertEqual(sleep.call_count, 2)
        self.assertEqual(retry_metric.call_count, 2)

    def test_list_events_retries_network_errors_before_failing(self):
        with (
            patch.object(
                client,
                "get_calendar_provider_connection",
                return_value={"token_payload": {"access_token": "token", "expires_at_utc": "2099-01-01T00:00:00Z"}},
            ),
            patch.object(client.requests, "request", side_effect=client.requests.RequestException("down")) as req,
            patch.object(client.time, "sleep") as sleep,
            patch.object(client, "record_google_calendar_api_retry") as retry_metric,
            patch.object(client, "update_calendar_provider_connection_sync_status") as status_update,
            patch.object(
                client,
                "S",
                SimpleNamespace(
                    google_calendar_api_base_url="https://www.googleapis.com/calendar/v3",
                    google_calendar_api_timeout_seconds=20,
                    google_calendar_api_retry_max_attempts=2,
                    google_calendar_api_retry_base_backoff_seconds=0.01,
                ),
            ),
        ):
            with self.assertRaises(HTTPException) as exc:
                client.list_google_calendar_events(
                    user_sub="user-1",
                    connection_id="google-primary",
                    google_calendar_id="gcal-1",
                )

        self.assertEqual(exc.exception.status_code, 502)
        self.assertEqual(req.call_count, 2)
        self.assertEqual(sleep.call_count, 1)
        retry_metric.assert_called_once_with(reason="network_exception")
        status_update.assert_called_once()

    def test_list_events_honors_retry_after_header_on_retryable_errors(self):
        retryable = Mock(status_code=429)
        retryable.content = b'{"error":{"message":"quota exceeded"}}'
        retryable.json.return_value = {"error": {"message": "quota exceeded"}}
        retryable.headers = {"Retry-After": "7"}

        with (
            patch.object(
                client,
                "get_calendar_provider_connection",
                return_value={"token_payload": {"access_token": "token", "expires_at_utc": "2099-01-01T00:00:00Z"}},
            ),
            patch.object(client.requests, "request", side_effect=[retryable, retryable]) as req,
            patch.object(client, "_retry_sleep_seconds", return_value=0.2),
            patch.object(client.time, "sleep") as sleep,
            patch.object(client, "record_google_calendar_api_retry"),
            patch.object(client, "update_calendar_provider_connection_sync_status"),
            patch.object(
                client,
                "S",
                SimpleNamespace(
                    google_calendar_api_base_url="https://www.googleapis.com/calendar/v3",
                    google_calendar_api_timeout_seconds=20,
                    google_calendar_api_retry_max_attempts=2,
                    google_calendar_api_retry_base_backoff_seconds=0.01,
                ),
            ),
        ):
            with self.assertRaises(HTTPException):
                client.list_google_calendar_events(
                    user_sub="user-1",
                    connection_id="google-primary",
                    google_calendar_id="gcal-1",
                )

        self.assertEqual(req.call_count, 2)
        sleep.assert_called_once_with(7.0)

    def test_list_events_honors_retry_after_http_date_header(self):
        retryable = Mock(status_code=503)
        retryable.content = b'{"error":{"message":"backend unavailable"}}'
        retryable.json.return_value = {"error": {"message": "backend unavailable"}}
        retryable.headers = {"Retry-After": "Wed, 21 Oct 2099 07:28:00 GMT"}

        fixed_now = datetime(2099, 10, 21, 7, 27, 30, tzinfo=timezone.utc)
        with (
            patch.object(
                client,
                "get_calendar_provider_connection",
                return_value={"token_payload": {"access_token": "token", "expires_at_utc": "2100-01-01T00:00:00Z"}},
            ),
            patch.object(client.requests, "request", side_effect=[retryable, retryable]) as req,
            patch.object(client, "_utc_now", return_value=fixed_now),
            patch.object(client, "_retry_sleep_seconds", return_value=0.2),
            patch.object(client.time, "sleep") as sleep,
            patch.object(client, "record_google_calendar_api_retry"),
            patch.object(client, "update_calendar_provider_connection_sync_status"),
            patch.object(
                client,
                "S",
                SimpleNamespace(
                    google_calendar_api_base_url="https://www.googleapis.com/calendar/v3",
                    google_calendar_api_timeout_seconds=20,
                    google_calendar_api_retry_max_attempts=2,
                    google_calendar_api_retry_base_backoff_seconds=0.01,
                ),
            ),
        ):
            with self.assertRaises(HTTPException):
                client.list_google_calendar_events(
                    user_sub="user-1",
                    connection_id="google-primary",
                    google_calendar_id="gcal-1",
                )

        self.assertEqual(req.call_count, 2)
        sleep.assert_called_once_with(30.0)

    def test_list_events_applies_retry_after_cap_setting(self):
        retryable = Mock(status_code=429)
        retryable.content = b'{"error":{"message":"quota exceeded"}}'
        retryable.json.return_value = {"error": {"message": "quota exceeded"}}
        retryable.headers = {"Retry-After": "120"}

        with (
            patch.object(
                client,
                "get_calendar_provider_connection",
                return_value={"token_payload": {"access_token": "token", "expires_at_utc": "2099-01-01T00:00:00Z"}},
            ),
            patch.object(client.requests, "request", side_effect=[retryable, retryable]) as req,
            patch.object(client, "_retry_sleep_seconds", return_value=0.2),
            patch.object(client.time, "sleep") as sleep,
            patch.object(client, "record_google_calendar_api_retry"),
            patch.object(client, "update_calendar_provider_connection_sync_status"),
            patch.object(
                client,
                "S",
                SimpleNamespace(
                    google_calendar_api_base_url="https://www.googleapis.com/calendar/v3",
                    google_calendar_api_timeout_seconds=20,
                    google_calendar_api_retry_max_attempts=2,
                    google_calendar_api_retry_base_backoff_seconds=0.01,
                    google_calendar_api_retry_after_max_seconds=15,
                ),
            ),
        ):
            with self.assertRaises(HTTPException):
                client.list_google_calendar_events(
                    user_sub="user-1",
                    connection_id="google-primary",
                    google_calendar_id="gcal-1",
                )

        self.assertEqual(req.call_count, 2)
        sleep.assert_called_once_with(15.0)

    def test_watch_events_sets_reauth_required_on_auth_failure(self):
        unauthorized = Mock(status_code=401)
        unauthorized.content = b'{"error":{"message":"Invalid Credentials","status":"UNAUTHENTICATED"}}'
        unauthorized.json.return_value = {"error": {"message": "Invalid Credentials", "status": "UNAUTHENTICATED"}}
        with (
            patch.object(
                client,
                "get_calendar_provider_connection",
                return_value={"token_payload": {"access_token": "token", "expires_at_utc": "2099-01-01T00:00:00Z"}},
            ),
            patch.object(client, "refresh_google_calendar_access_token", return_value={"access_token": "token-2"}),
            patch.object(client.requests, "request", side_effect=[unauthorized, unauthorized]),
            patch.object(client, "update_calendar_provider_connection_sync_status") as status_update,
            patch.object(client, "S", SimpleNamespace(google_calendar_api_base_url="https://www.googleapis.com/calendar/v3", google_calendar_api_timeout_seconds=20)),
        ):
            with self.assertRaises(HTTPException) as exc:
                client.watch_google_calendar_events(
                    user_sub="user-1",
                    connection_id="google-primary",
                    google_calendar_id="gcal-1",
                    channel_id="channel-1",
                    webhook_url="https://example.com/hooks/google",
                )

        self.assertEqual(exc.exception.status_code, 401)
        self.assertTrue(exc.exception.detail["reauth_required"])
        status_update.assert_called()

    def test_refresh_missing_token_records_metric(self):
        with (
            patch.object(
                client,
                "get_calendar_provider_connection",
                return_value={"account_email": "user@example.com", "token_payload": {}},
            ),
            patch.object(client, "record_google_calendar_token_refresh_failure") as refresh_failure_metric,
            patch.object(client, "update_calendar_provider_connection_sync_status"),
        ):
            with self.assertRaises(HTTPException):
                client.refresh_google_calendar_access_token(user_sub="user-1", connection_id="google-primary")

        refresh_failure_metric.assert_called_once_with(reason="missing_refresh_token")


if __name__ == "__main__":
    unittest.main()
