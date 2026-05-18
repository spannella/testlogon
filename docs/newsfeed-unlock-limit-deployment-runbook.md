# Newsfeed Unlock-Limit Deployment Runbook

## Scope

This runbook covers production launch of unlock-limit caps for locked posts, including:

- launch steps,
- monitoring/dashboard requirements,
- alarm thresholds,
- rollback actions,
- on-call response flow.

Related docs:

- `docs/newsfeed-unlock-limit-api-contract.md`
- `docs/newsfeed-unlock-limit-rollout-checklist.md`
- `docs/newsfeed-unlock-count-reconciliation-runbook.md`
- `docs/newsfeed-unlock-limit-monitoring-spec.md`

---

## 1) Pre-Launch Checklist (Required)

1. **Feature flags configured**
   - `NEWSFEED_UNLOCK_LIMIT_ENABLED`
   - `NEWSFEED_UNLOCK_LIMIT_ROLLOUT_MODE`
   - `NEWSFEED_UNLOCK_LIMIT_INTERNAL_USER_IDS`
   - `NEWSFEED_UNLOCK_LIMIT_COHORT_USER_IDS`
2. **Monitoring dashboards created** (see monitoring spec).
3. **Alarms created + verified** (test alarm path to on-call).
4. **Reconciliation script available**
   - `scripts/reconcile_newsfeed_unlock_counts.py`
5. **Backfill script available**
   - `scripts/backfill_newsfeed_unlock_limit_fields.py`
6. **On-call ack**
   - Primary + secondary on-call acknowledge rollout window.
7. **Support briefed**
   - Known user-facing messages for sold-out/expired and retry throttling.

Do **not** proceed unless all items are checked.

---

## 2) Launch Procedure

### Phase A — Internal

1. Set:
   - `NEWSFEED_UNLOCK_LIMIT_ENABLED=true`
   - `NEWSFEED_UNLOCK_LIMIT_ROLLOUT_MODE=internal`
   - internal allowlist users populated.
2. Validate:
   - create/edit capped post works,
   - first `N` unlocks succeed,
   - `N+1` rejected with `unlock_limit_reached`,
   - sold-out UX renders correctly.
3. Watch dashboards for at least 30 minutes.

### Phase B — Cohort

1. Set `NEWSFEED_UNLOCK_LIMIT_ROLLOUT_MODE=cohort`.
2. Populate `NEWSFEED_UNLOCK_LIMIT_COHORT_USER_IDS`.
3. Monitor for 24h:
   - unlock failure ratios,
   - payment failure rates,
   - contention spikes,
   - unlock-count drift.

### Phase C — Broad

1. Set `NEWSFEED_UNLOCK_LIMIT_ROLLOUT_MODE=broad`.
2. Continue elevated monitoring for first 24h.
3. Run reconciliation check at least once during first broad window.

---

## 3) Rollback Procedure

### Fast rollback (no deploy rollback)

1. Set `NEWSFEED_UNLOCK_LIMIT_ENABLED=false`.
2. Confirm traffic changes reflected in logs/dashboard within 5–10 minutes.
3. Keep alarms active while validating stabilization.

### Partial rollback

- Set rollout mode back to `internal` or `cohort`.

### Post-rollback integrity checks

1. Run:
   - `PYTHONPATH=. python scripts/reconcile_newsfeed_unlock_counts.py --table-name app_single_table`
2. If needed:
   - `PYTHONPATH=. python scripts/reconcile_newsfeed_unlock_counts.py --table-name app_single_table --apply`
3. Document incident timeline + affected post IDs.

---

## 4) On-Call Response Playbook

### Trigger conditions

- alarms for unlock failures, payment failures, or contention,
- support tickets indicating incorrect sold-out behavior,
- reconciliation drift growth.

### Triage steps

1. Check summary logs:
   - `newsfeed_unlock_count_reconcile_summary`
   - `newsfeed unlock lifecycle` events (`unlock_attempt`, `unlock_success`, `unlock_payment_failed`, `unlock_limit_reached`)
2. Identify blast radius:
   - affected users, posts, and time window.
3. Decide mitigation:
   - keep running,
   - narrow rollout to cohort/internal,
   - full feature disable.
4. If drift observed:
   - follow reconciliation runbook and repair with approval.

### Resolution criteria

- alarm cleared,
- failure/error rates back to baseline,
- no growing unlock-count drift,
- incident notes completed.

