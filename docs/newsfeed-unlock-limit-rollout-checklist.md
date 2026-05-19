# Newsfeed Unlock-Limit Rollout Checklist

## Feature Flags / Controls

Backend controls:

- `NEWSFEED_UNLOCK_LIMIT_ENABLED` (`true|false`)
- `NEWSFEED_UNLOCK_LIMIT_ROLLOUT_MODE` (`off|internal|cohort|broad`)
- `NEWSFEED_UNLOCK_LIMIT_INTERNAL_USER_IDS` (CSV)
- `NEWSFEED_UNLOCK_LIMIT_COHORT_USER_IDS` (CSV)

These allow enabling/disabling behavior without code rollback.

---

## Phase 0 — Off (safety baseline)

**Config**

- `NEWSFEED_UNLOCK_LIMIT_ENABLED=false`

**Go criteria**

- Service healthy and unlock baseline error rate stable.
- No unexpected `unlock_limit_feature_disabled` spikes for intended off windows.

**No-Go / rollback trigger**

- Elevated unlock/payment failure rates unrelated to rollout.

---

## Phase 1 — Internal

**Config**

- `NEWSFEED_UNLOCK_LIMIT_ENABLED=true`
- `NEWSFEED_UNLOCK_LIMIT_ROLLOUT_MODE=internal`
- `NEWSFEED_UNLOCK_LIMIT_INTERNAL_USER_IDS=<internal test accounts>`

**Go criteria**

- Internal scenarios pass:
  - create/edit capped locked posts
  - first `N` unlocks succeed; `N+1` rejected
  - sold-out and expired UX states visible
- Metrics/log checks:
  - no unexpected increase in payment failures
  - drift checks (`reconcile_newsfeed_unlock_counts.py`) show no sustained growth.

**No-Go / rollback trigger**

- Cap bypass detected (over-cap unlock success),
- reconciliation drift increasing across fresh posts,
- severe UX/API regressions.

---

## Phase 2 — Cohort

**Config**

- `NEWSFEED_UNLOCK_LIMIT_ROLLOUT_MODE=cohort`
- `NEWSFEED_UNLOCK_LIMIT_COHORT_USER_IDS=<pilot cohort>`
- keep internal IDs populated.

**Go criteria**

- Cohort KPIs stable for at least 24h:
  - unlock success/failure ratios within expected band
  - no unexplained `unlock_limit_feature_disabled` errors in cohort users
  - support/bug volume acceptable.
- Reconciliation job reports no critical drift.

**No-Go / rollback trigger**

- Material increase in unlock payment complaints,
- unrecoverable count drift,
- incorrect sold-out gating observed for cohort.

---

## Phase 3 — Broad

**Config**

- `NEWSFEED_UNLOCK_LIMIT_ROLLOUT_MODE=broad`

**Go criteria**

- All prior phase criteria met.
- On-call + support briefed with reconciliation and backfill runbooks.

**Rollback procedure**

1. Immediate kill switch: set `NEWSFEED_UNLOCK_LIMIT_ENABLED=false`.
2. If needed, downgrade to `internal` or `cohort` mode.
3. Run:
   - `scripts/reconcile_newsfeed_unlock_counts.py` (check mode)
   - `scripts/backfill_newsfeed_unlock_limit_fields.py --verify-only`
4. Open incident with drift/error snapshots and recovery notes.

