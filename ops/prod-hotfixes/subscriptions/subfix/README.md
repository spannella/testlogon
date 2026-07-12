# SUBFIX — subscription cycle-order reconciler dead-letter (`missing_order`) root-cause fix

**Date** 2026-07-11 · **File** `app/services/subscription_cycle_orders.py` · **Backend-only, LIVE PROD HOTFIX via SSM + fold.**

## The bug (carried through the whole subscriptions program E0–E5)
On subscribe / renewal / trial-conversion, after the (correct) charge+credit+invoice,
`emit_subscription_cycle_order_and_reconcile` emits a canonical subscription *cycle order*
(the recurring-entitlement GRANT) and reconciles it. It logged
`subscription_cycle_reconciliation_invariant_failed reason=missing_order -> dead_lettered`.
Money path (charge/credit/invoice) was always correct; only the downstream grant dead-lettered.

## Root cause (TWO layers, both in `subscription_cycle_orders.py`)
1. **sk-less order read.** The prod `orders` table is a COMPOSITE key `(order_id HASH, sk RANGE)`;
   the header row is written under `sk="ORDER"` (ecom ORD-003). But
   `CanonicalOrderEntitlementsRepository.get_order` read with
   `get_item(Key={"order_id": order_id})` — **missing the `sk` range key** → DynamoDB raises
   `ValidationException`, which was swallowed by `except Exception: item=None` → the just-created
   order looked "missing" → `missing_order` dead-letter.
   *Same repo/method backs the ecom `CommerceEntitlementOrchestrator`, so the ecom prod noise
   `commerce_entitlement_orchestration_failed: order not found` had the SAME root cause.*
2. **NULL index-key on grant.** Once the order was found, `grant_entitlement` -> `put_entitlement`
   failed with `ValidationException: Invalid attribute value type`. The `entitlements` table backs
   GSIs on `ends_at/starts_at/status/sku` (all type S); a subscription entitlement legitimately has
   `ends_at=None`, and DynamoDB rejects a NULL value for an index-key attribute. This blocked every
   grant (subscription AND ecom) that lacked an `ends_at`.

## The fix
- `get_order` → new `_load_order_row`: read the header row with the composite key
  `{"order_id", "sk":"ORDER"}`, with fallbacks (single-key `get_item`, then a partition `query`
  preferring `sk=="ORDER"`). Schema-robust for legacy single-key tables.
- `emit_subscription_cycle_order` now best-effort stamps the cycle order header row `paid`
  (`_mark_subscription_order_paid`) — the cycle is already charged upstream, so the downstream
  reconcile grants an **ACTIVE** entitlement instead of `pending_payment`. Never breaks the money path.
- `TableBackedEntitlementsRepository.put_entitlement` drops `None`-valued attributes before `put_item`
  (sparse-index semantics) so `ends_at=None` no longer ValidationExceptions.
- Trial / $0 cycles are a clean NO-OP at the caller (`subscribe` skips emit when `status=="trialing"`;
  no invoice → no cycle order → no dead-letter). Handled, not dead-lettered.

Idempotent per `{subscription, billing period}`: order_id = `sha256("subscription_cycle:{sub}:invoice:{invoice}")[:32]`
(deterministic per cycle); entitlement_id = `sha256("{order}:{item}:{sku}:{type}")[:32]` guarded by
`attribute_not_exists(entitlement_id)`. Re-emit = same order, no duplicate grant.

## Apply / verify (idempotent, anchored)
- `apply_subfix.py`  — patch 1 (get_order composite read) + mark-order-paid + header const.
- `apply_subfix2.py` — patch 2 (put_entitlement None-strip).
  Env: `SUBFIX_TARGET=<path>`, `SUBFIX_BAK=<stamp>` (writes `.bak_<stamp>`), `--dry` to preview.
- `verify_subfix.py` — in-process prod verify (real subscribe, idempotent re-emit, E1 renewal sweep,
  trial no-op). **22/22 OVERALL ALL_PASS** on prod DDB.

## Prod hotfix record
- `.bak_subfix_1783817045`  (patch 1)  ·  `.bak_subfix2_1783817513` (patch 2)
- Final prod == dev sha256 `510261d9973e678b…`; restart openapi 200.

## Residual
- `store_integration.reserve` TypeError is SEPARATE (flag-gated, swallowed by `_safe_upstream`) — not this bug.
