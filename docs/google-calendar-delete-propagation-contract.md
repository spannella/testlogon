# Google Calendar Delete/Cancelled Propagation Contract (GCAL-013)

Module: `app/services/google_calendar_delete_propagation.py`

## Behavior
- Interpret Google `cancelled` events as inbound deletions.
- Resolve Google event → internal mapping.
- Tombstone mapping via GCAL-008 API (`mark_event_tombstone`).
- Remove internal event row from calendar storage when present.
- Return idempotent no-op result when mapping/event already absent.

## Guarantees
- Duplicate cancelled notifications are safe and idempotent.
- Tombstone markers are retained to prevent accidental recreation loops.
