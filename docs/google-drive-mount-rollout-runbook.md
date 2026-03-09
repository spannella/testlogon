# Google Drive Mount Progressive Rollout + Kill Switch Runbook (GDM-061)

This runbook defines staged rollout and rollback/kill-switch procedures for Google Drive mounts.

## Objective

Roll out Google Drive mounts in controlled phases while preserving the ability to disable the feature immediately **without deploy**.

## Primary control (kill switch)

- Feature flag: `FILEMGR_GOOGLE_DRIVE_MOUNTS_ENABLED`
- Behavior when disabled:
  - Mount CRUD/admin reconcile routes return unsupported (`feature_not_enabled`).
  - Mounted-path dispatch is bypassed; file manager uses local-path behavior only.

Because this is environment/config driven, on-call can disable by configuration update + service restart/rolling restart, with no code change.

## Ownership

- Service owner: `platform-filemanager`
- Primary on-call: `platform-filemanager-oncall`
- Escalation: `infra-sre`

## Prerequisites before any phase

- [ ] OAuth config present and validated in startup logs:
  - `GOOGLE_OAUTH_CLIENT_ID`
  - `GOOGLE_OAUTH_CLIENT_SECRET`
  - `GOOGLE_OAUTH_REDIRECT_URI`
  - `GOOGLE_OAUTH_REDIRECT_URI_ALLOWLIST`
  - `GOOGLE_OAUTH_STATE_SIGNING_SECRET` (or fallback)
- [ ] Dashboard imported: `docs/dashboards/google-drive-mount-ops-dashboard.json`
- [ ] Alert thresholds active per `docs/google-drive-mount-observability-runbook.md`
- [ ] GDM-060 integration tests passing in CI

## Staged rollout plan

### Phase 0 — Internal users only

Audience:
- Internal staff and engineering-owned test users.

Actions:
1. Enable `FILEMGR_GOOGLE_DRIVE_MOUNTS_ENABLED=1` in internal/staging env.
2. Restrict access operationally to internal user set (org process gate).
3. Validate smoke flows:
   - OAuth connect/callback
   - mount create/list/patch/delete
   - list/download/upload/delete under mounted path
   - read-only enforcement
4. Monitor for 24-48h.

Promotion criteria:
- No sustained critical alerts.
- 401/403/429 error rates below warning thresholds for full observation window.
- No unresolved stale-mount reconciliation incidents.

---

### Phase 1 — Beta cohort

Audience:
- Explicit allowlist cohort (early adopters / selected customers).

Actions:
1. Keep feature enabled in production.
2. Expand access from internal-only to curated beta cohort (org process gate).
3. Run daily stale-mount reconciliation checks:
   - `GET /v1/fs/admin/mounts/reconcile?owner=<user_sub>`
4. Use remediation for stale mounts:
   - `POST /v1/fs/admin/mounts/{mount_id}/reconcile-disable?owner=<user_sub>`
   - or explicit disable route with reason.

Promotion criteria:
- Stable p95 mounted operation latency.
- Upload failure spike alert remains below warning/critical thresholds.
- Reconnect incidents operationally manageable with documented support workflow.

---

### Phase 2 — General availability

Audience:
- All eligible users.

Actions:
1. Keep feature enabled globally.
2. Remove manual cohort gate process.
3. Continue weekly review of:
   - mounted error rates (401/403/429)
   - p95 operation latency
   - upload failures
   - stale mount volume and remediation turnaround

Steady-state acceptance:
- Alert noise acceptable for on-call.
- No unresolved systemic credential-refresh regressions.

## Emergency kill switch and rollback

### Immediate mitigation (no deploy)

1. Set `FILEMGR_GOOGLE_DRIVE_MOUNTS_ENABLED=0` in affected environment.
2. Perform rolling restart / config reload for app processes.
3. Confirm behavior:
   - mount endpoints return `feature_not_enabled`
   - local FS operations remain healthy
4. Announce mitigation in incident channel.

### Rollback checklist

- [ ] Capture incident timestamp + triggering metric panel screenshots.
- [ ] Confirm kill switch propagation across all instances.
- [ ] Run sanity checks on core local `/v1/fs` paths.
- [ ] Pause any cohort expansion.
- [ ] Open follow-up issue with root-cause hypothesis and rollback state.

## On-call quick commands / API checks

- Verify feature flag value in runtime config/environment.
- Health-check admin reconcile endpoint for known owner:
  - `GET /v1/fs/admin/mounts/reconcile?owner=<user_sub>`
- Disable problematic mount quickly:
  - `POST /v1/fs/admin/mounts/{mount_id}/disable?owner=<user_sub>&reason=incident_kill_switch`

## Post-incident re-enable policy

Only re-enable `FILEMGR_GOOGLE_DRIVE_MOUNTS_ENABLED=1` after:
- [ ] root-cause fix validated in staging,
- [ ] GDM-060 integration suite passes,
- [ ] on-call approval from `platform-filemanager-oncall`.
