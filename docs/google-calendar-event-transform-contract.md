# Google Calendar Event Transformation Contract (GCAL-010)

Module: `app/services/google_calendar_transform.py`

## Inbound mapping (Google → internal)
- `map_google_event_to_internal(google_event, calendar_timezone='UTC')`
  - deterministically maps Google event payloads into validated internal event shape
  - supports timed and all-day events
  - maps recurrence from `RRULE` / `EXDATE` into internal recurrence fields
  - returns:
    - `event` (validated payload),
    - `source_metadata` (`etag`, `updated`, sequence, recurring IDs),
    - `warnings` for unsupported/degraded fields

## Outbound mapping (internal → Google)
- `map_internal_event_to_google(internal_event)`
  - maps internal status/time/recurrence fields to Google event payload shape
  - unsupported fields are omitted and surfaced via warnings

## Sync metadata helper
- `build_google_event_sync_fingerprint(google_event)`
  - canonicalizes selected fields and emits deterministic SHA-256 fingerprint for sync decisions.
