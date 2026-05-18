# Google Calendar Full Import Sync Contract (GCAL-011)

Module: `app/services/google_calendar_sync_full_import.py`

## Job handler
- `handle_google_calendar_full_import_queue_job(job)`
  - validates queue payload
  - executes full import runner

## Full import runner
- `run_google_calendar_full_import_job(user_sub, connection_id, window_start_utc=None, window_end_utc=None)`
  - loads active internal↔Google calendar mappings
  - pulls Google events in the configured import window
  - transforms Google events to internal event schema
  - upserts internal events + event mappings
  - preserves idempotency via sync fingerprint checks

## Metrics / telemetry payload
- `calendars_total`, `calendars_processed`
- `google_events_scanned`
- `created`, `updated`, `skipped`, `errors`, `warnings`
- `error_samples` (bounded sample)
- `started_at_utc`, `finished_at_utc`, `duration_seconds`
