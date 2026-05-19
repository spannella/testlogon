# Newsfeed Unlock-Limit Monitoring & Alerting Spec

## Goal

Define minimum dashboard panels and alarm thresholds that must exist before broad rollout.

---

## Dashboard: `newsfeed-unlock-limit`

Create dashboard panels from structured logs/metrics with 5m and 1h views:

1. **Unlock attempts**
   - count of `unlock_attempt`
2. **Unlock successes**
   - count of `unlock_success`
3. **Unlock cap reached**
   - count of `unlock_limit_reached`
4. **Unlock payment failures**
   - count of `unlock_payment_failed`
5. **Throttle rejections**
   - count of `unlock_attempt_throttled` errors
6. **Lock expired rejections**
   - count of `post_lock_expired` errors
7. **Unlock-count drift**
   - `drift_posts` from reconciliation summary
8. **Repair activity**
   - count of `newsfeed_unlock_count_repair` events

---

## Required Alarms

### A1 — Unlock failure ratio high

- Signal: `(unlock_payment_failed + unlock_attempt_throttled + unlock_limit_reached where unexpected) / unlock_attempt`
- Window: 15 minutes
- Threshold: > 15% for 2 consecutive windows
- Severity: P2

### A2 — Payment failure spike

- Signal: `unlock_payment_failed`
- Window: 10 minutes
- Threshold: > 2x rolling 24h baseline OR > 20 events (whichever is higher)
- Severity: P2

### A3 — Contention spike

- Signal: `unlock_limit_reached` rate on posts not near cap baseline OR sudden surge in cap-reached per minute
- Window: 10 minutes
- Threshold: > 3x rolling 7d baseline
- Severity: P2

### A4 — Drift detected

- Signal: reconciliation summary `drift_posts`
- Schedule: after each periodic reconciliation run
- Threshold: `drift_posts > 0`
- Severity: P1 for sustained drift (>1 run), else P2

### A5 — Repair activity anomaly

- Signal: `newsfeed_unlock_count_repair` count
- Window: 1 hour
- Threshold: > 10 repairs/hour without active incident
- Severity: P2

---

## Alert Routing

- P1 -> primary + secondary on-call + incident channel.
- P2 -> primary on-call + team channel.
- Include runbook links in alarm description:
  - deployment runbook
  - reconciliation runbook

---

## Go/No-Go Gate

Before moving from cohort to broad rollout:

1. dashboard exists and has live data,
2. all required alarms enabled and tested,
3. on-call confirms notifications received,
4. no unresolved P1/P2 unlock-limit incidents.

