# VNC Rollout & Operational Readiness Runbook (VNC-017)

## Purpose
Define phased rollout, rollback/kill-switch controls, and incident response for the brokered VNC feature.

## Feature Flags and Kill Switch (No Redeploy)

### Backend controls
- `VNC_FEATURE_ENABLED` (default: `true`)
- `VNC_FEATURE_KILL_SWITCH` (default: `false`)

Effective behavior:
- VNC API bootstrap is allowed only when:
  - `VNC_FEATURE_ENABLED=true`
  - `VNC_FEATURE_KILL_SWITCH=false`
- Disabled state returns `503` with `VNC_FEATURE_DISABLED`.

### Frontend controls
- `VITE_VNC_REMOTE_DESKTOP_ENABLED` (default: `true`)
- `VITE_VNC_REMOTE_DESKTOP_KILL_SWITCH` (default: `false`)

Effective behavior:
- Remote Desktop route/nav is shown only when enabled and not kill-switched.

## Phased Rollout

### Phase 0 — Internal users (dogfood)
**Entry criteria**
- VNC-012 security controls deployed (authz/rate-limit/TLS).
- VNC-013 observability dashboards and alerts configured.
- VNC-015 backend test suite green in CI.

**Execution**
- Backend enabled only for internal targets/users.
- Frontend enabled for internal environment only.

**Exit criteria**
- 7-day stability window.
- No unresolved P1/P0 incidents.
- Bootstrap success rate and bridge failure metrics within baseline.

### Phase 1 — Limited tenant cohort
**Entry criteria**
- Phase 0 exit criteria complete.
- Tenant allowlist finalized.
- On-call handoff and runbook review complete.

**Execution**
- Enable backend for allowlisted cohort (10–20% target footprint).
- Monitor failure/error-code distribution by target and tenant.

**Exit criteria**
- 14-day stability window.
- No sustained failure-rate alert breaches.
- Support queue and escalation volume within expected bounds.

### Phase 2 — General Availability (GA)
**Entry criteria**
- Phase 1 exit criteria complete.
- Incident/rollback drill completed in prior 30 days.
- Product/security sign-off.

**Execution**
- Enable flags globally.
- Keep kill-switch procedures active and tested.

**Exit criteria**
- 30-day post-GA review complete with action items tracked.

## Rollback Strategy

### Fast disable (preferred)
1. Set `VNC_FEATURE_KILL_SWITCH=true`.
2. Set `VITE_VNC_REMOTE_DESKTOP_KILL_SWITCH=true`.
3. Verify new bootstrap requests return `503 VNC_FEATURE_DISABLED`.
4. Notify support/on-call and update status page.

### Partial rollback
- Restrict access by target policy (`allowed_users`) and role.
- Keep feature enabled for internal-only while external cohort is disabled.

## Incident Triage (VNC degradation)
1. Confirm scope: global vs subset (target, tenant, role).
2. Check metrics:
   - `vnc_session_events_total` failures by `error_code` and `target_id`.
   - `vnc_bridge_failures_total` spikes.
   - `vnc_session_duration_seconds` anomalies.
3. Check logs/traces by `session_id` + `correlation_id`.
4. If impact is broad, execute fast-disable kill switch.
5. Capture incident timeline and mitigation actions.

## Rollout Checklist
- [ ] Security controls verified in env (VNC-012).
- [ ] Observability dashboards + alerts active (VNC-013).
- [ ] Backend and frontend test suites green (VNC-015, VNC-016).
- [ ] Cohort allowlist and support messaging prepared.
- [ ] Kill switch tested in staging.
- [ ] On-call escalation owner assigned.

## Tabletop Exercise Record
- Last tabletop date: `2026-03-05`
- Scenario: bridge failure spike + elevated `VNC_TARGET_UNREACHABLE`.
- Validation outcome: runbook and kill-switch steps completed successfully within SLO.
- Follow-ups:
  - [ ] rehearse tenant-scoped partial rollback quarterly
  - [ ] review threshold tuning after GA + 30 days
