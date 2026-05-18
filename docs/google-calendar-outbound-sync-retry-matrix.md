# Google Calendar Outbound Sync Retry Matrix (GCAL-015)

Module: `app/services/google_calendar_sync_outbound.py`

## Classification
- **Success**: Google write succeeds → job `status=done`.
- **Conflict**: provider status `409` / `412` (etag mismatch/precondition failed) → job `status=conflict`.
- **Retryable error**: retryable upstream/transient failures → job `status=retry_pending` with incremented attempts and `next_attempt_at_utc`.
- **Failed**: non-retryable/non-conflict errors → job `status=failed`.
- **Dead-letter**: retry budget exhausted for retryable errors → job `status=dead_letter` with `dead_letter_reason`, `dead_lettered_at_utc`, and replay hint.

## Backoff
- Retries use jittered exponential backoff:
  - delay ~= `base_seconds * 2^(attempt-1)` bounded by `max_seconds`
  - jitter applied using `GOOGLE_CALENDAR_OUTBOUND_RETRY_JITTER_RATIO`
- Configuration:
  - `GOOGLE_CALENDAR_OUTBOUND_RETRY_MAX_ATTEMPTS`
  - `GOOGLE_CALENDAR_OUTBOUND_RETRY_BASE_SECONDS`
  - `GOOGLE_CALENDAR_OUTBOUND_RETRY_MAX_SECONDS`
  - `GOOGLE_CALENDAR_OUTBOUND_RETRY_JITTER_RATIO`

## Replay
- Dead-letter jobs can be replayed via:
  - `python scripts/google_calendar_replay_dead_letters.py --owner-user-sub <user_sub> --limit 100`
- Replay transitions jobs back to `pending`, sets `dead_letter_replayed_at_utc`, and increments `replay_count`.

## Etag behavior
- Update/Delete handlers send `If-Match` from stored mapping `provider_etag`.
- Etag mismatch is never silently overwritten; routed to `conflict` state.

## Mapping metadata updates
- Successful create/update writes call `upsert_event_mapping(...)` with latest:
  - `provider_etag`
  - `sync_fingerprint`
  - `last_synced_at_utc`
