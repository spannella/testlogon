# Once-Media Rollout Checklist and Staged Release Execution (MOM-052)

## Status

- Ticket: `MOM-052`
- State: `approved-for-rollout`
- Last updated: `2026-02-19`

## Approvals

- Product: **approved**
- Engineering (backend + client): **approved**
- Security: **approved**
- Operations/SRE: **approved**

---

## 1) Staged rollout cohorts and promotion criteria

### Cohort definitions

1. **C0 Internal (staff/dev only)**
   - Feature flags enabled for internal accounts only.
   - Intended duration: 24–48 hours.
2. **C1 Canary (1% eligible production users)**
   - Mixed DM/group traffic and all supported media kinds.
   - Intended duration: 24 hours minimum.
3. **C2 Limited beta (10% eligible production users)**
   - Expanded cohort with representative traffic patterns.
   - Intended duration: 48 hours minimum.
4. **C3 Broad rollout (50% eligible production users)**
   - Large-scale soak before full enablement.
   - Intended duration: 72 hours minimum.
5. **C4 General availability (100% eligible users)**

### Promotion gates (must all pass)

For each cohort, promotion to next stage requires all conditions over the gate window:

- Consume success rate (overall) `>= 99.0%` over 60 minutes.
- Consume error rate (overall) `<= 1.0%` over 60 minutes.
- `already_consumed` conflict rate `<= 0.3%` of consume attempts.
- Grant p95 latency `<= 250ms` and p99 latency `<= 500ms`.
- No P0/P1 incidents open for once-media functionality.
- Support ticket rate for once-media does not exceed baseline +25%.

If any gate fails, pause progression and execute rollback decision tree.

---

## 2) SLI/SLO definitions and thresholds

### SLIs

- **Consume success SLI**
  - `success_consume / total_consume`
  - Metric basis: `messaging_once_media_consume_total{outcome}`
- **Consume failure SLI**
  - `error_consume / total_consume`
  - Metric basis: `messaging_once_media_consume_total{outcome}`
- **Grant latency SLI**
  - p95, p99 from `messaging_once_media_grant_latency_seconds`
- **Conflict/race SLI**
  - `messaging_once_media_conflicts_total / total_consume`

### SLOs (production steady-state)

- Consume success SLO: `>= 99.5%` daily per media kind (`image`, `video`, `audio`).
- Consume failure SLO: `<= 0.5%` daily per media kind.
- Grant latency SLO: p95 `<= 200ms`, p99 `<= 400ms` daily.
- Conflict/race SLO: `<= 0.2%` daily.

### Alert thresholds during rollout

- Warning: consume failure `> 1.0%` for 15m.
- Critical: consume failure `> 3.0%` for 10m.
- Warning: grant p95 latency `> 350ms` for 15m.
- Critical: grant p99 latency `> 800ms` for 10m.

---

## 3) Rollback and kill-switch validation

### Pre-production rollback drill (staging)

Drill date: `2026-02-19`

Steps executed:

1. Enable once-media flags in staging (`image`, `video`, `audio`).
2. Send and consume once-image, once-video, and listen-once audio in DM and group chats.
3. Trigger global kill switch (`MESSAGING_ONCE_MEDIA_ENABLED=0`).
4. Verify outcomes:
   - once-media composer toggles hidden,
   - grant/consume endpoints disabled,
   - non-once media send/list behavior unaffected,
   - existing consumed state remains non-replayable.
5. Re-enable flags in staged order and re-run smoke checks.

Drill result: **pass**.

### Production rollback decision tree

- If critical SLO breach or P0 incident:
  1. Set `MESSAGING_ONCE_MEDIA_ENABLED=0`.
  2. Confirm disablement through dashboard + synthetic checks.
  3. Communicate incident status and freeze promotions.
  4. Open follow-up incident and remediation plan.
- If warning breach only:
  - hold at current cohort,
  - investigate and remediate,
  - continue only after two consecutive healthy gate windows.

---

## 4) Launch execution checklist

- [x] Product sign-off completed.
- [x] Engineering sign-off completed.
- [x] Security sign-off completed.
- [x] Observability dashboard and alerts configured.
- [x] Kill-switch and rollback drill completed in staging.
- [x] Support/moderation runbooks linked and acknowledged.
- [x] Promotion gates reviewed with on-call rotations.

Linked references:

- `docs/messaging-once-media-feature-flags-runbook.md`
- `docs/messaging-once-media-observability.md`
- `docs/messaging-once-media-support-moderation-runbook.md`
- `docs/messaging-once-media-threat-model.md`
