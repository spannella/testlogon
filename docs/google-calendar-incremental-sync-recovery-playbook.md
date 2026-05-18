# Google Calendar Incremental Sync Recovery Playbook (GCAL-012)

## Scenario: invalid `syncToken`
Google incremental event APIs can invalidate stored `syncToken` cursors (e.g. `410 Gone`).

## Expected system behavior
1. Incremental poll detects invalid token response.
2. Service automatically runs full import fallback for the affected connection.
3. Incremental cursor is refreshed from a successful subsequent incremental response (`nextSyncToken`).
4. Connection sync status is updated to healthy only when cursor commit succeeds.

## Operator checks
- Verify job metrics contain `fallback_full_syncs > 0`.
- Confirm `last_sync_status=success` and updated `sync_cursor` on provider connection.
- Confirm no persistent increase in incremental `errors`.

## Manual remediation (if auto-recovery fails)
- Clear connection cursor (`sync_cursor`) for impacted connection.
- Trigger one full import run.
- Re-enable incremental polling and verify `nextSyncToken` advances.
