# Google Calendar DLQ Replay Runbook (GCAL-020)

Applies to outbound sync jobs in `app/services/google_calendar_sync_outbound.py`.

## Retry + DLQ behavior
- Retryable outbound failures are scheduled with jittered exponential backoff.
- Retry timing is stored in `next_attempt_at_utc` and status transitions to `retry_pending`.
- Once retry budget is exhausted (`GOOGLE_CALENDAR_OUTBOUND_RETRY_MAX_ATTEMPTS`), jobs transition to `dead_letter`.
- Dead-letter rows include:
  - `dead_letter_reason`
  - `dead_lettered_at_utc`
  - `last_error`
  - `replay_hint`

## Configuration
- `GOOGLE_CALENDAR_OUTBOUND_RETRY_MAX_ATTEMPTS` (default `5`)
- `GOOGLE_CALENDAR_OUTBOUND_RETRY_BASE_SECONDS` (default `5`)
- `GOOGLE_CALENDAR_OUTBOUND_RETRY_MAX_SECONDS` (default `300`)
- `GOOGLE_CALENDAR_OUTBOUND_RETRY_JITTER_RATIO` (default `0.2`)

## Replay procedure
1. Identify impacted user partition (`owner_user_sub`).
2. Replay dead letters:

```bash
python scripts/google_calendar_replay_dead_letters.py --owner-user-sub <user_sub> --limit 100
```

3. Re-run worker processing after replay:

```python
from app.services.google_calendar_sync_outbound import process_google_calendar_outbound_jobs
process_google_calendar_outbound_jobs(owner_user_sub="<user_sub>")
```

## Expected replay output
JSON with:
- `owner_user_sub`
- `replayed`
- `limit`

## Safety notes
- Replay only resets `dead_letter` jobs back to `pending` and increments `replay_count`.
- Replay keeps idempotency via existing dedup keys + mapping semantics.
