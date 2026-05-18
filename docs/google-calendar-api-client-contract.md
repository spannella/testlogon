# Google Calendar API Client Wrapper Contract (GCAL-009)

Module: `app/services/google_calendar_client.py`

## Responsibilities
- Resolve active Google provider connection + decrypted token payload.
- Refresh access tokens via OAuth refresh grant when expired/expiring.
- Execute typed Google Calendar API calls for:
  - calendar list (`/users/me/calendarList`)
  - event list (`/calendars/{calendarId}/events`)
  - event watch (`/calendars/{calendarId}/events/watch`)
- Normalize upstream failures into a consistent error payload:
  - `code`
  - `message`
  - `retryable`
  - `reauth_required`
  - `provider_status_code`

## Reauth and retry behavior
- Retryable provider errors: `408, 429, 500, 502, 503, 504`.
- Auth errors (`401/403`) trigger one token refresh + request retry.
- If auth still fails (or refresh grant fails with `invalid_grant`/`unauthorized_client`), connection sync status is updated with `reauth_required=true`.
- Retry loop uses exponential backoff with jitter and respects `Retry-After` from provider responses.
  - Supports both numeric seconds and RFC 7231 HTTP-date values.
  - `Retry-After` delay is capped by `GOOGLE_CALENDAR_API_RETRY_AFTER_MAX_SECONDS` (default `60`, max `600`).

## Operational configuration knobs
- `GOOGLE_CALENDAR_API_TIMEOUT_SECONDS`: per-request HTTP timeout budget.
- `GOOGLE_CALENDAR_API_RETRY_MAX_ATTEMPTS`: retry attempt ceiling for transient failures.
- `GOOGLE_CALENDAR_API_RETRY_BASE_BACKOFF_SECONDS`: base backoff interval before jitter/exponential scaling.
- `GOOGLE_CALENDAR_API_RETRY_AFTER_MAX_SECONDS`: upper bound for provider-directed `Retry-After` delays.

## Public API
- `refresh_google_calendar_access_token(user_sub, connection_id)`
- `list_google_calendars(user_sub, connection_id, page_token=None)`
- `list_google_calendar_events(user_sub, connection_id, google_calendar_id, sync_token=None, page_token=None, time_min=None, time_max=None)`
- `watch_google_calendar_events(user_sub, connection_id, google_calendar_id, channel_id, webhook_url, channel_token=None, ttl_seconds=None)`
