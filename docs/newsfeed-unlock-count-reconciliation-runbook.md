# Newsfeed Unlock Count Reconciliation Runbook

## Purpose

`unlock_count` on `Post` records should match the number of successful `Unlock` records (`Entity=Unlock`, `unlocked=true`) for the same `post_id`.

This runbook describes:

1. how to detect drift,
2. how to investigate root cause,
3. how to optionally repair drift safely.

---

## Tooling

Use:

- `scripts/reconcile_newsfeed_unlock_counts.py`

Modes:

- **check mode** (default): read-only drift detection
- **apply mode** (`--apply`): updates `Post.unlock_count` to observed cardinality

---

## Detection / Monitoring

Run periodic check (recommended cron/scheduler):

```bash
PYTHONPATH=. python scripts/reconcile_newsfeed_unlock_counts.py --table-name app_single_table
```

The job emits structured logs:

- `newsfeed_unlock_count_reconcile_progress`
- `newsfeed_unlock_count_drift`
- `newsfeed_unlock_count_reconcile_summary`

If `drift_posts > 0` in summary, create an incident/task and follow investigation below.

---

## Investigation Procedure

For each drifted `post_id`:

1. Capture `stored_unlock_count`, `actual_unlock_count`, and `delta` from drift logs.
2. Inspect post metadata:
   - `unlock_limit`
   - `unlock_count`
   - lock state/expiry timestamps.
3. Inspect unlock records for that `post_id`:
   - total records
   - count where `unlocked=true`
   - count where `in_progress=true`
4. Correlate with service logs around the same window:
   - `unlock_attempt`
   - `unlock_success`
   - `unlock_payment_failed`
   - `unlock_limit_reached`
5. Classify likely cause:
   - partial write/failed compensation
   - manual data edit
   - historical bug from pre-fix build.

---

## Optional Repair Procedure

If approved, run apply mode:

```bash
PYTHONPATH=. python scripts/reconcile_newsfeed_unlock_counts.py --table-name app_single_table --apply
```

Behavior:

- only drifted capped posts are updated,
- `unlock_count` is set to observed unlock-record cardinality,
- repair actions are logged as `newsfeed_unlock_count_repair`.

---

## Post-Repair Validation

1. Re-run check mode and confirm `drift_posts == 0`.
2. Spot-check a sample of repaired posts in UI/API for expected sold-out state.
3. Confirm no spike in unlock-related error rates after repair.

---

## Rollback Guidance

Rollback is typically not required because repair aligns `unlock_count` with source-of-truth unlock records.

If rollback is required for a specific post, restore prior `unlock_count` from captured drift logs / backup snapshots and document the reason in incident notes.

