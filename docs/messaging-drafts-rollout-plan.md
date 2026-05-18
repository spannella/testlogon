# Messaging Drafts Rollout Strategy (MSGD-016)

Date: 2026-04-05

## Feature flag gates

### Backend gates (no redeploy required)

The draft API is controlled at request time via environment-mode gates in `app.routers.messaging`:

- `MESSAGING_DRAFTS_MODE`
  - `enabled` (default): enabled for all users
  - `disabled`: disabled for all users
  - `internal`: enabled only for tenants in `MESSAGING_DRAFTS_INTERNAL_TENANT_IDS`
  - `selective`: enabled for explicit allowlists
- `MESSAGING_DRAFTS_ENABLED_USER_IDS` (CSV allowlist when `selective`)
- `MESSAGING_DRAFTS_ENABLED_TENANT_IDS` (CSV allowlist when `selective`)
- `MESSAGING_DRAFTS_KILL_SWITCH=true` forces global disable

### Frontend gates

- `VITE_MESSAGING_DRAFTS_ENABLED` (default true)
- `VITE_MESSAGING_DRAFTS_KILL_SWITCH` (emergency disable)

When disabled, draft controls are hidden and hook operations no-op.

## Phased rollout

1. **Internal**
   - Set `MESSAGING_DRAFTS_MODE=internal`
   - Populate `MESSAGING_DRAFTS_INTERNAL_TENANT_IDS` with staff/internal tenant IDs
   - Monitor error rate and fallback metrics for 48 hours
2. **Beta**
   - Switch to `MESSAGING_DRAFTS_MODE=selective`
   - Add pilot tenants/users to allowlists
   - Monitor 7 days for stability and support volume
3. **GA**
   - Set `MESSAGING_DRAFTS_MODE=enabled`
   - Keep kill switch available for rapid rollback

## Operational readiness checklist

- [ ] Dashboards live for draft operation volume, latency, and errors
- [ ] Alerts configured for error ratio and latency regression
- [ ] On-call runbook includes flag/kill-switch procedures
- [ ] Support team has customer-facing FAQ and troubleshooting steps
- [ ] Synthetic smoke checks for create/list/get/update/delete pass

## Success criteria

- Error ratio < 1% over 7-day rolling window after beta
- p95 create/list latency < 500ms in production regions
- No cross-conversation leakage incidents
- No plaintext draft content in telemetry or logs

## Rollback procedure

1. Immediate mitigation: set `MESSAGING_DRAFTS_KILL_SWITCH=true`
2. Optional frontend kill switch: set `VITE_MESSAGING_DRAFTS_KILL_SWITCH=true`
3. Verify APIs return 403 for draft endpoints and UI hides controls
4. Announce rollback in incident channel and status page (if user-visible)
5. Collect diagnostics (error samples, metrics windows, affected tenants)
6. Re-enable progressively (`internal` -> `selective` -> `enabled`) after fix

## On-call owner notes

- Primary owner: Messaging on-call engineer
- Secondary owner: Platform API on-call
- Escalation: Security on-call for any suspected content leakage
- During incidents, prefer kill-switch rollback before code revert to reduce MTTR
