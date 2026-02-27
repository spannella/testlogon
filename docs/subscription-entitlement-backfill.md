# Subscription Entitlement Backfill (CCE-067)

## Goal

Backfill active subscriptions into standardized entitlement records before full cutover.

## Job modes

Script: `scripts/subscription-entitlement-backfill.py`

- `--mode dry-run`: builds drift + reconciliation summary only
- `--mode apply`: writes/upserts entitlement rows deterministically
- `--mode rollback --batch-id <id>`: revokes entitlements written by a batch

## Dry-run output

The planner emits:

- ownership-tagged drifts (`owner_team`, `owner_contact`)
- recommended actions
- reconciliation summary counts (`subscription_count`, `drift_count`, `operations_count`)

## Deterministic reruns

Backfilled entitlement IDs are deterministic (`sha256(subscription_id + period_anchor)`), so apply reruns are idempotent upserts rather than duplicate records.

## Rollback

Rollback mode targets `backfill_batch_id` and sets matched entitlement rows to `revoked`, preserving auditability and allowing staged cutover rollback.

## Staging runbook checklist

1. Run dry-run and export report for Product/Billing/Support review.
2. Run apply in staging with a fixed `--batch-id`.
3. Re-run apply with the same `--batch-id` and verify deterministic no-duplication behavior.
4. Validate entitlement visibility and access checks for sampled subscribers.
5. Validate rollback path with `--mode rollback --batch-id <id>`.
