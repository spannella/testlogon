# Apple CalDAV Deployment Runbook (CAL-033)

## Purpose

This runbook describes how to safely deploy and roll out Apple CalDAV integration, including canary cohorts, rollback actions, and readiness gates for security, observability, and support.

---

## 1) Pre-deployment checklist (must pass)

### 1.1 Security readiness

- [ ] `CALENDAR_CONNECTION_SECRETS_TABLE_NAME` exists and encrypts data at rest.
- [ ] KMS key permissions for app runtime role are validated for encrypt/decrypt operations.
- [ ] Connection table does **not** store plaintext credentials (spot-check with redaction-safe admin tooling).
- [ ] Admin troubleshooting routes are restricted to general admin/root only.

### 1.2 Observability readiness

- [ ] Metrics endpoint includes `calendar_sync_*` series.
- [ ] Dashboard imported: `docs/dashboards/calendar-sync-ops-dashboard.json`.
- [ ] Alert rules loaded: `docs/alerts/calendar-sync-health-alerts.yml`.
- [ ] On-call routing for calendar alerts is confirmed.

### 1.3 Support readiness

- [ ] Support runbook for common failures is published (auth failure, dead letters, conflict spikes).
- [ ] Support/admin users have access to `/admin/calendar/integrations/apple/troubleshoot`.
- [ ] Repair procedures validated: relink and admin sync-now actions.

---

## 2) Environment configuration checklist

Set and verify the following env vars in target environment:

- `CALENDAR_INTEGRATIONS_ENABLED=1`
- `APPLE_CALDAV_ENABLED=0` (start disabled before rollout)
- `APPLE_CALDAV_BASE_URL=https://caldav.icloud.com`
- `APPLE_CALDAV_CONNECT_TIMEOUT_SECONDS=5`
- `APPLE_CALDAV_READ_TIMEOUT_SECONDS=10`
- `APPLE_CALDAV_RETRY_MAX_ATTEMPTS=3`
- `APPLE_CALDAV_POLL_INTERVAL_SECONDS=300`
- `APPLE_CALDAV_POLL_JITTER_SECONDS=30`
- `APPLE_CALDAV_POLL_BATCH_SIZE=50`
- `APPLE_CALDAV_INITIAL_IMPORT_LOOKBACK_DAYS=365`
- `APPLE_CALDAV_INITIAL_IMPORT_LOOKAHEAD_DAYS=30`
- `CALENDAR_CONNECTIONS_TABLE_NAME`
- `CALENDAR_CONNECTION_SECRETS_TABLE_NAME`
- `EXTERNAL_CALENDARS_TABLE_NAME`
- `EXTERNAL_EVENT_LINKS_TABLE_NAME`
- `CALENDAR_SYNC_RUNS_TABLE_NAME`

---

## 3) Rollout plan (canary cohorts)

### Phase 0: Dark launch (no user traffic)

1. Deploy with `CALENDAR_INTEGRATIONS_ENABLED=1`, `APPLE_CALDAV_ENABLED=0`.
2. Confirm app starts and no provider traffic occurs.
3. Validate dashboard and alert wiring with synthetic metric traffic.

### Phase 1: Internal canary (1-5% / allowlist)

1. Enable provider: `APPLE_CALDAV_ENABLED=1`.
2. Restrict onboarding to internal/support allowlist users.
3. Monitor for at least 24h:
   - Run success rate
   - p95 pull/push latency
   - Conflict rate
   - Queue backlog depth
   - Auth failure rate
4. Validate admin troubleshooting output for at least 3 successful and 3 failed test users.

### Phase 2: Beta canary (10-25%)

1. Expand to a controlled external cohort (invite-only).
2. Run for 48h with hourly checks on alert noise and backlog behavior.
3. Ensure support can triage without DB access using admin troubleshooting endpoint.

### Phase 3: General availability (100%)

1. Remove cohort restrictions.
2. Keep elevated monitoring for first 7 days post-GA.
3. Review alert thresholds after 1 week and tune if needed.

---

## 4) Rollback playbook

### Trigger conditions

Rollback immediately if any of the following persist >15m:

- Auth failures above alert threshold.
- Sync error rate above alert threshold.
- Push outbox backlog grows continuously without recovery.
- Critical data-integrity regressions or repeat conflict storms.

### Rollback steps

1. Set `APPLE_CALDAV_ENABLED=0` and redeploy (or toggle via runtime config pipeline).
2. Keep `CALENDAR_INTEGRATIONS_ENABLED=1` unless full subsystem rollback is required.
3. Confirm new connect/sync operations fail fast and no further provider traffic occurs.
4. Preserve tables and run history for incident analysis.
5. Communicate rollback status to support and on-call channels.

### Post-rollback validation

- [ ] Error-rate and auth-failure alerts return to baseline.
- [ ] Queue backlog stops increasing.
- [ ] Incident timeline recorded with root-cause hypotheses.

---

## 5) Known limitations (current release)

- Sync-token and ctag pull logic is scaffolded; full CalDAV REPORT behavior is still limited.
- Internal event soft-delete persistence path is currently placeholder-backed.
- Some repair actions are manual/admin-assisted (relink and sync-now), not fully automated self-heal.
- Conflict resolution is deterministic but may still require user confirmation for business intent.

---

## 6) Operational triage quick-reference

1. Open dashboard: `Calendar Sync Ops Health`.
2. If auth failures spike, verify credential validity and recent rotate/disconnect actions.
3. If error rate spikes, inspect latest run history + dead letters from admin troubleshooting endpoint.
4. If conflicts spike, review conflict audit trends and relink specific records where appropriate.
5. If backlog grows, prioritize outbox recovery and provider health checks.

---

## 7) Launch readiness gates (go/no-go)

Ship only when all are true:

- [ ] Security gates passed.
- [ ] Observability gates passed.
- [ ] Support gates passed.
- [ ] Post-launch hardening/load validation completed (`docs/runbooks/apple-caldav-post-launch-hardening.md`).
- [ ] Canary phase SLOs within thresholds for required soak period.
- [ ] Rollback drill completed in staging within the last release cycle.
