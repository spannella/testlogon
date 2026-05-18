# Google Calendar Staged Rollout Checklist (GCAL-024)

Date: 2026-04-05
Owner: Calendar Platform

## Rollout stages
1. **Internal users (stage 0)**
2. **Pilot cohort (stage 1)**
3. **Broad rollout (stage 2)**
4. **GA (stage 3)**

## Stage gates and go/no-go criteria

### Stage 0 → Stage 1 (Internal to Pilot)
- [ ] OAuth connect/disconnect success rate >= 99.5% over 24h.
- [ ] Outbound queue dead-letter rate <= 0.5% over 24h.
- [ ] Incremental sync p95 latency <= 15s.
- [ ] No unresolved Sev1/Sev2 incidents.
- [ ] Security/compliance review confirms audit payload redaction is effective.

### Stage 1 → Stage 2 (Pilot to Broad)
- [ ] Pilot cohort meets sync SLA for 5 consecutive days.
- [ ] Error budget burn <= 25% weekly for sync pipeline.
- [ ] Conflict rate below threshold (<= 2% of outbound writes).
- [ ] Manual replay operations do not exceed on-call runbook threshold.
- [ ] Product + SRE + Security sign-off recorded.

### Stage 2 → Stage 3 (Broad to GA)
- [ ] 14-day stability window complete.
- [ ] No unresolved Sev1/Sev2 incidents.
- [ ] On-call load within expected envelope (no sustained paging spikes).
- [ ] Stakeholder approval recorded (Product, SRE, Security, Compliance).

## Migration/backfill plan
- Run full import backfill for enabled mapped calendars.
- Validate incremental cursor integrity after first full pass.
- Track mismatch/skip statistics and reconcile outliers with manual sync run.

## Quality SLO monitors
- Sync success rate (inbound/outbound)
- Dead-letter growth
- Conflict spikes
- Token refresh/auth failures
- Outbox backlog saturation

## Rollback criteria
- Any Sev1
- Sustained Sev2 > 4h
- Dead-letter growth > threshold for 2 consecutive windows
- OAuth/token refresh auth failures > threshold in 30m

## Rollback actions
1. Set `GOOGLE_CALENDAR_WRITEBACK_ENABLED=false`.
2. If required, set `GOOGLE_CALENDAR_SYNC_ENABLED=false`.
3. Preserve outbox/DLQ data for forensics and replay.
4. Open incident + assign follow-up owners.
