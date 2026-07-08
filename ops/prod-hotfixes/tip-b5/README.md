# TIP-B5 — tipping hardening (prod hotfix fold)

Live prod hotfix applied to `i-08f937fc705ebea75` (us-east-2) via SSM on 2026-07-08.
Prod code root: `/home/ubuntu/testlogon`. Backend restart: `bash /home/ubuntu/restart_backend.sh`.

## Backups (rollback)
Timestamp `1783497039`:
- `app/services/tips.py.bak_tipb5_1783497039`
- `app/services/tip_ledger.py.bak_tipb5_1783497039`
- `app/services/social_alerts.py.bak_tipb5_1783497039`
- `app/routers/messaging.py.bak_tipb5_1783497039`

Rollback = `cp <f>.bak_tipb5_1783497039 <f>` for each, `chown ubuntu:ubuntu`, restart.

## What changed
- **TIP-501** (`app/services/tips.py`, `app/services/tip_ledger.py`): the tip debit +
  credit + idempotency receipt are now written as ONE DynamoDB `TransactWriteItems`.
  The `TIPIDEMP#<key>` receipt is claimed with `attribute_not_exists(sk)` INSIDE the
  transaction, so a replay/race cannot double-charge and a partial write cannot orphan
  a credit (all-or-nothing). Row shape is UNCHANGED (net `type:"credit"`, 20% fee) —
  `build_tip_ledger_items` is the single source of truth shared by the transactional
  writer and the legacy best-effort `write_tip_ledger` (collaboration-split fallback).
- **TIP-502** (`app/services/tips.py::reverse_tip`): idempotent reversal. Writes a
  recipient clawback (`type:"reversal"`, net) + a tipper refund (`type:"refund"`, gross)
  + a `TIPREVERSAL#<tip_payment_id>` marker (double-reversal guard) in one transaction.
  NEITHER reversal entry is `type:"credit"`, so earnings are never inflated. Best-effort
  adjuncts: flips the original credit to `state:"reversed"` (drops it from
  `get_available_balance`) and issues a Stripe refund when a real PaymentIntent backed it.
- **Gate extension** (`app/routers/messaging.py`): `_dm_tip_gate_required` is now applied
  to `create_image_message` + `create_gallery_message`, so a gated recipient cannot be
  first-contacted with an un-tipped image/gallery (402 tip_required), matching the text path.
- **social_alerts ttl fix** (`app/services/social_alerts.py`): `_batch_alert` wrote
  `ttl = :ttl` — `ttl` is a DynamoDB reserved keyword, so the update silently failed.
  Now `#ttl = :ttl` with `ExpressionAttributeNames={"#ttl":"ttl"}`.

## Files here
- `app_services_tips.py`, `app_services_tip_ledger.py` — full replacement files
  (prod matched dev HEAD `be3e76dd` exactly, so applied as whole-file copies).
- `prod_patcher.py` — idempotent surgical patcher for the messaging gate + social_alerts
  ttl fix (prod variants differ from dev, so patched in place by function/anchor).
- `test_tips_charge_tip.py` — TIP-506 money-path guard tests (26 pass).

## Apply (from repo root on prod)
```
cp app/services/tips.py{,.bak_tipb5_$TS}; cp <this>/app_services_tips.py app/services/tips.py
cp app/services/tip_ledger.py{,.bak_tipb5_$TS}; cp <this>/app_services_tip_ledger.py app/services/tip_ledger.py
python3 <this>/prod_patcher.py   # patches messaging.py + social_alerts.py (idempotent)
chown ubuntu:ubuntu app/services/tips.py app/services/tip_ledger.py app/services/social_alerts.py app/routers/messaging.py
```
