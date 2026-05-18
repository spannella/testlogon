# Google Calendar Conflict State Contract (GCAL-016)

## Conflict detector
Module: `app/services/google_calendar_conflicts.py`
- `detect_sync_conflict(...)` deterministically classifies concurrent-edit/etag conflict conditions.

## Persistence
Module: `app/services/google_calendar_event_mappings.py`
- `mark_event_sync_conflict(...)` persists:
  - `sync_state=conflict`
  - `conflict_reason`
  - `conflict_detected_at_utc`
  - internal/provider conflict snapshots

## API surfacing
Module: `app/routers/calendar.py` + `app/models.py`
- Event payloads expose:
  - `sync_state`
  - `sync_conflict_reason`
  - `sync_conflict_detected_at_utc`
Used by frontend badges/admin diagnostics.
