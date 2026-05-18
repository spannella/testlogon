# Google Calendar Rollout Policy (GCAL-001)

This policy defines how `GOOGLE_CALENDAR_SYNC_ENABLED` and `GOOGLE_CALENDAR_WRITEBACK_ENABLED` are used for safe staged rollout.

## Flags
- `GOOGLE_CALENDAR_SYNC_ENABLED`
  - Global gate for all Google Calendar integration APIs.
  - When `false`, integration API endpoints return `403 feature_disabled`.
- `GOOGLE_CALENDAR_WRITEBACK_ENABLED`
  - Writeback kill switch for outbound sync behavior.
  - Can be disabled independently while read-only sync remains enabled.

## Cohort Controls
- `GOOGLE_CALENDAR_SYNC_ROLLOUT_MODE`
  - `off`: deny all users.
  - `all`: allow all authenticated users.
  - `cohort`: allowlist + percentage rollout.
- `GOOGLE_CALENDAR_SYNC_ROLLOUT_COHORT_USER_SUBS`
  - Comma-separated user_sub allowlist.
- `GOOGLE_CALENDAR_SYNC_ROLLOUT_PERCENT`
  - Deterministic user bucketing percentage (`0..100`) based on user_sub hash.

## Recommended Rollout Stages
1. **Stage A (Dark launch)**
   - `GOOGLE_CALENDAR_SYNC_ENABLED=false`
   - `GOOGLE_CALENDAR_WRITEBACK_ENABLED=false`
2. **Stage B (Internal cohort, read-only)**
   - `GOOGLE_CALENDAR_SYNC_ENABLED=true`
   - `GOOGLE_CALENDAR_SYNC_ROLLOUT_MODE=cohort`
   - `GOOGLE_CALENDAR_SYNC_ROLLOUT_COHORT_USER_SUBS=<internal-testers>`
   - `GOOGLE_CALENDAR_WRITEBACK_ENABLED=false`
3. **Stage C (Pilot % rollout, read-only)**
   - Keep `cohort` mode and increase `GOOGLE_CALENDAR_SYNC_ROLLOUT_PERCENT` gradually.
   - Keep writeback disabled.
4. **Stage D (Pilot writeback)**
   - Enable `GOOGLE_CALENDAR_WRITEBACK_ENABLED=true` for pilot cohorts only.
5. **Stage E (General availability)**
   - `GOOGLE_CALENDAR_SYNC_ROLLOUT_MODE=all`
   - `GOOGLE_CALENDAR_SYNC_ROLLOUT_PERCENT=100`
   - Keep writeback enabled unless incident response requires kill switch.
