# Google Calendar Event Mapping + Tombstone Contract (GCAL-008)

Partition/key model (DynamoDB in `calendar` table):
- `calendar_id = gcal_evtmap#{user_sub}`
- `sk = map#{internal_calendar_id}#{internal_event_id}`
- `type = calendar_event_provider_mapping`

Core mapping fields:
- `internal_calendar_id`, `internal_event_id`
- `google_calendar_id`, `google_event_id`
- `provider_etag`, `sync_fingerprint`, `last_synced_at_utc`
- `active`

Tombstone fields:
- `tombstone` (boolean)
- `tombstone_reason`
- `tombstone_expires_at_utc`
- `updated_at_utc`

Validation/uniqueness:
- Active Google event (`google_calendar_id + google_event_id`) can map to only one active internal event per user.
- Tombstoned mapping cannot be recreated before expiry (prevents accidental recreation loops).

Retention policy:
- Tombstones are retained for `GOOGLE_CALENDAR_EVENT_TOMBSTONE_RETENTION_DAYS` (default `90`).
- `purge_expired_event_tombstones(user_sub)` permanently removes tombstones past `tombstone_expires_at_utc`.

Repository/service API:
- `upsert_event_mapping`
- `get_event_mapping`
- `get_event_mapping_by_google_event`
- `mark_event_tombstone`
- `purge_expired_event_tombstones`
