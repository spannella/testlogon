# Messaging Message Controls Staged Rollout Checklist

This document executes MMC-025 by defining staged capability flags, canary phases, and rollback criteria.

## Runtime flags (no deploy required)

All flags are read at request time and can be toggled via environment/configuration rollout tooling.

- `MESSAGING_HIDE_CONTROLS_ENABLED`
  - Gates: hide/unhide endpoints + hidden messages listing.
- `MESSAGING_PINS_ENABLED`
  - Gates: pin/unpin endpoints + pins listing.
- `MESSAGING_REPORTING_ENABLED`
  - Gates: report endpoint.
- `MESSAGING_REPORT_RATE_LIMIT_ENABLED`
  - Auxiliary safety control for reporting abuse limits.
- `MESSAGING_COMPLIANCE_ARCHIVE_ENABLED`
  - Gates: immutable archive ingest emission from messaging lifecycle paths.
- `MESSAGING_COMPLIANCE_ARCHIVE_ENFORCE_WRITE_SUCCESS`
  - Gates: fail-closed vs best-effort archive write behavior.
- `MESSAGING_COMPLIANCE_EXPORT_ENABLED`
  - Gates: compliance export create/list/get/manifest/records endpoints.
- `MESSAGING_COMPLIANCE_LEGAL_HOLD_ENABLED`
  - Gates: legal-hold create/release/list endpoints.

## Staged rollout phases

### Phase 0 — Dark launch (all disabled)

- Set all three capabilities to `false` in staging and production.
- Verify endpoint behavior:
  - Disabled endpoints return `403` with clear capability-disabled detail.
- Validate telemetry and logs still emit for enabled baseline routes.

### Phase 1 — Staging canary

- Enable one capability at a time in staging:
  1. `MESSAGING_HIDE_CONTROLS_ENABLED=true`
  2. `MESSAGING_PINS_ENABLED=true`
  3. `MESSAGING_REPORTING_ENABLED=true`
  4. `MESSAGING_COMPLIANCE_ARCHIVE_ENABLED=true`
  5. `MESSAGING_COMPLIANCE_EXPORT_ENABLED=true`
  6. `MESSAGING_COMPLIANCE_LEGAL_HOLD_ENABLED=true`
- Keep `MESSAGING_COMPLIANCE_ARCHIVE_ENFORCE_WRITE_SUCCESS=false` in first canary pass; repeat a second pass with `true`.
- Run smoke tests + automated endpoint tests.
- Validate dashboard panels in `docs/dashboards/messaging-message-controls-dashboard.json` and `docs/dashboards/messaging-archive-health-dashboard.json`.

### Phase 2 — Production canary (5%)

- Enable flags for 5% tenant/account shard or canary environment slice.
- Monitor for 30–60 minutes:
  - API error ratio
  - report rate-limited spikes
  - report validation-error increases

### Phase 3 — Production ramp (25% → 50% → 100%)

- Increase traffic share incrementally with 30-minute hold periods.
- Continue monitoring each hold period before promotion.

## Rollback criteria

Trigger immediate rollback (set flags to `false`) if any are met:

- Message-controls API error ratio > 5% for 15 minutes.
- Report success traffic spike exceeds expected baseline with abuse indicators.
- Report rate-limited metric exceeds warning threshold persistently.
- On-call declares user-impacting regressions in hide/pin/report flows.
- Archive write failure ratio alert (`MessagingArchiveSustainedWriteFailures`) fires for 15 minutes.
- Integrity mismatch alert (`MessagingArchiveIntegrityChainMismatch`) fires at any level.

## Rollback playbook (validated in staging)

Validation completed in staging by toggling each flag off after enabling and confirming:

1. Endpoints are immediately denied (`403`) without deploy.
2. Existing data remains intact (no destructive migrations required).
3. Re-enabling restores behavior without data repair.

Operational rollback sequence:

1. Disable `MESSAGING_COMPLIANCE_EXPORT_ENABLED` and `MESSAGING_COMPLIANCE_LEGAL_HOLD_ENABLED`.
2. Set `MESSAGING_COMPLIANCE_ARCHIVE_ENFORCE_WRITE_SUCCESS=false` (switch from fail-closed to best-effort).
3. Disable `MESSAGING_COMPLIANCE_ARCHIVE_ENABLED` if archive path instability persists.
4. Disable `MESSAGING_REPORTING_ENABLED` first among message controls (highest abuse risk).
5. Disable `MESSAGING_PINS_ENABLED` if timeline UX instability persists.
6. Disable `MESSAGING_HIDE_CONTROLS_ENABLED` if per-user visibility path is implicated.
7. Keep `MESSAGING_REPORT_RATE_LIMIT_ENABLED=true` unless instructed by incident lead.

## Sign-off checklist

- [ ] Staging dark-launch checks completed.
- [ ] Staging canary phase completed for each capability.
- [ ] Production 5% canary completed and reviewed.
- [ ] Production ramp completed with no rollback triggers.
- [ ] Post-rollout review completed and thresholds tuned.


## Staging rollback drill validation (FCA-019)

Validated in staging using runtime env toggles without deploy:

1. Set `MESSAGING_COMPLIANCE_EXPORT_ENABLED=false` and verify all export endpoints immediately return `403`.
2. Set `MESSAGING_COMPLIANCE_LEGAL_HOLD_ENABLED=false` and verify legal-hold endpoints immediately return `403`.
3. Toggle `MESSAGING_COMPLIANCE_ARCHIVE_ENFORCE_WRITE_SUCCESS` between `false` and `true` and verify behavior changes without restart/deploy.
4. Re-enable all flags and confirm baseline success path recovers.

Rollback drill is considered successful when all toggles take effect in-request and recovery requires no data migration or deploy.
