# Video staged rollout checklist (VWD-022)

Defines phased rollout gates from internal test to GA.

## Rollout phases

## Phase A — Internal

### Entry criteria
- Slice 1 complete in staging.
- CI artifact checks and reliability checks passing.
- On-call runbook reviewed.

### Exit gates
- 0 Sev-1 incidents across 7 days.
- Playback success and DRM error rates within thresholds.
- Failover and key-outage drill executed successfully.

## Phase B — Pilot tenants

### Entry criteria
- Phase A exit gates satisfied.
- Selected pilot tenants approved and support staffed.

### Exit gates
- 95%+ pilot playback starts successful over 14 days.
- No unresolved critical DRM key/license alerts.
- At least one controlled rollback simulation completed.

## Phase C — General Availability (GA)

### Entry criteria
- Pilot exit gates satisfied.
- Escalation routing and ownership confirmed for 24/7 on-call.

### Exit gates
- Broad tenant enablement completed with no open Sev-1/Sev-2 regressions.
- Weekly health review established (channel/input/output/key/playback).

---

## Rollback criteria (hard stops)

Trigger immediate rollback if any condition persists beyond two evaluation windows:
- sustained playback entitlement reject spikes
- unresolved input loss with failed failover
- DRM key/license outage exceeding recovery objective
- repeated channel restart failures

## Rollback actions

1. Pause new tenant enablement.
2. Disable rollout flag for affected cohort.
3. Revert to last known good provider/channel config.
4. Notify support + on-call with tenant impact list.
5. Start incident + RCA workflow.

---

## Ownership matrix

- Platform on-call: channel/input/output runtime health.
- Security/DRM owner: key provider and license fallback path.
- Product/support: tenant communications and pilot sign-off.

## Sign-off checklist

- [ ] Runbooks validated by on-call.
- [ ] Alert routes tested (warning + critical + escalation).
- [ ] Reliability drills completed and archived.
- [ ] Rollback drill validated in non-production.
- [ ] GA approval recorded.
