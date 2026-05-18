# Calendar Provider Connection Item Contract (GCAL-006)

Partition/key model (DynamoDB in `calendar` table):
- `calendar_id = gcal_conn#{user_sub}`
- `sk = meta#{connection_id}`
- `type = calendar_provider_connection`

Core fields:
- `provider` (`google`)
- `connection_id`, `user_sub`, `account_email`
- `active` (soft lifecycle state)
- `token_payload_redacted`, encrypted token envelope blobs

Token lifecycle expectations:
- OAuth callback should persist a long-lived refresh token for durable background sync.
- By default, missing refresh token responses are rejected during OAuth code exchange
  (`GOOGLE_CALENDAR_OAUTH_REQUIRE_REFRESH_TOKEN=true`).
- If refresh token becomes invalid/expired, connection should be marked `reauth_required=true`.

Sync metadata:
- `sync_health`: `healthy | degraded | error | unknown`
- `last_sync_status`: `never_synced | syncing | success | error`
- `last_sync_at_utc`, `last_sync_error`
- `sync_cursor`
- `reauth_required`

Lifecycle metadata:
- `created_at_utc`, `updated_at_utc`
- `disconnected_at_utc` (when disconnected)
- `revoke_status`

Repository/service methods:
- `upsert_calendar_provider_connection`
- `list_calendar_provider_connections`
- `get_calendar_provider_connection`
- `update_calendar_provider_connection_sync_status` (idempotent updates)
- `rotate_calendar_provider_connection_tokens`
- `disconnect_calendar_provider_connection`
