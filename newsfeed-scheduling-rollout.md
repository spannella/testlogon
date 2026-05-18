# Newsfeed Scheduling Rollout Plan (NFS-027)

## Feature flags and controls

### Backend/API flags
- `NEWSFEED_SCHEDULING_API_ENABLED`
  - Controls schedule-aware API behavior:
    - `POST /posts` with scheduling fields (`publish_at`, `schedule_timezone`, `scheduled_at_local`)
    - `PATCH /posts/{post_id}` schedule metadata edits
    - `GET /posts/scheduled`
    - `POST /posts/{post_id}/cancel`
  - When disabled, schedule routes and schedule field usage return `404 schedule_feature_disabled`.

- `NEWSFEED_SCHEDULING_WORKER_ENABLED`
  - Controls scheduler publish worker execution.
  - When disabled, `process_due_scheduled_posts` returns a no-op summary (`worker_enabled=false`).

### Frontend/UI flag
- `VITE_NEWSFEED_SCHEDULING_UI_ENABLED`
  - Controls schedule controls visibility in:
    - composer (`CreatePost`)
    - edit dialog (`EditPostDialog`)
    - scheduled list panel (`ScheduledPostsPanel`)

## Staged rollout

### Stage 0 — Internal validation
- Enable flags only in internal/dev:
  - `NEWSFEED_SCHEDULING_API_ENABLED=true`
  - `NEWSFEED_SCHEDULING_WORKER_ENABLED=true`
  - `VITE_NEWSFEED_SCHEDULING_UI_ENABLED=true`
- Validation gate:
  - Create scheduled post, confirm hidden from feed pre-due.
  - Confirm scheduled listing/edit/cancel works for owner only.
  - Confirm due publish occurs and lag/error metrics emit.

### Stage 1 — Cohort rollout (5–10%)
- Enable UI + API for cohort environment/tenant subset.
- Keep worker enabled globally for published cohorts only.
- Validation gate:
  - Backlog stable: `newsfeed_schedule_backlog_due` not growing unexpectedly.
  - Throughput healthy: `newsfeed_schedule_operations_total{operation="publish",outcome="published"}`.
  - Failure ratio acceptable: retry/error/conflict outcomes below SLO threshold.

### Stage 2 — Expanded cohort (25–50%)
- Increase enabled cohort gradually.
- Validation gate:
  - `newsfeed_schedule_publish_lag_seconds` p95 under operational target.
  - Alert counters do not show sustained breaches:
    - `newsfeed_schedule_alerts_total{alert_type="error_threshold_breach"}`
    - `newsfeed_schedule_alerts_total{alert_type="lag_threshold_breach"}`

### Stage 3 — General availability
- Enable all three flags platform-wide.
- Validation gate:
  - 7-day stability window with no sustained lag/error alerts.
  - Support runbook updated with known failure patterns and remediation.

## Rollback checklist

1. **Immediate worker stop (publish freeze)**
   - Set `NEWSFEED_SCHEDULING_WORKER_ENABLED=false`.
   - Effect: no new scheduled posts are auto-published.

2. **Disable user-facing scheduling UI**
   - Set `VITE_NEWSFEED_SCHEDULING_UI_ENABLED=false`.
   - Effect: no new scheduling interactions exposed in client.

3. **Disable scheduling API paths**
   - Set `NEWSFEED_SCHEDULING_API_ENABLED=false`.
   - Effect: schedule-specific operations rejected (`schedule_feature_disabled`).

4. **Validate rollback state**
   - Check worker summaries report `worker_enabled=false`.
   - Confirm no growth in publish throughput for scheduled queue.
   - Confirm feed publishes for immediate posts remain unaffected.

5. **Recovery plan after rollback**
   - Investigate lag/error root cause (DDB throttling, index drift, validation regressions).
   - Re-enable in reverse order after fix:
     1) API, 2) worker, 3) UI.
