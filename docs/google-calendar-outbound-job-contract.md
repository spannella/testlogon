# Google Calendar Outbound Job Contract (GCAL-014)

Module: `app/services/google_calendar_outbound_jobs.py`

## Producer API
- `enqueue_google_calendar_outbound_sync_job(...)`
  - called by event create/update/delete routes
  - writes one logical outbox item per dedup key

## Dedup/idempotency
- Stable dedup key derived from:
  - action
  - internal calendar/event ids
  - event version snapshot fields (`updated_at_utc`, status/time fields)
- Duplicate producer attempts collapse into the existing outbox item via conditional write.

## Payload fields
- actor/owner context: `actor_user_sub`, `owner_user_sub`
- mapping context: `internal_calendar_id`, `internal_event_id`, `google_calendar_ids`
- action context: `action`, `source`, `dedup_key`
- event snapshot: normalized event summary for outbound reconciliation

## Lifecycle fields (GCAL-020)
- Retry tracking: `attempts`, `next_attempt_at_utc`, `last_error`
- Retry states: `pending` → `retry_pending` → `done|conflict|failed|dead_letter`
- Dead-letter context: `dead_letter_reason`, `dead_lettered_at_utc`, `replay_hint`
- Replay markers: `dead_letter_replayed_at_utc`, `replay_count`
