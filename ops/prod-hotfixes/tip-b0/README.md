# TIP-B0 — centralized tip charge service (TIP-001..004)

Adds `app/services/tips.py` — the single `charge_tip(...) -> TipResult` seam every
tipping surface will call (surfaces migrated in TIP-005..011).

B0 is **behavior-preserving centralization**:
- PM-resolve chain: explicit -> `tip_default_payment_method_id` (tolerated absent) ->
  general `default_payment_method_id` -> blank-in-dev.
- PM ownership validated ONCE (the `PM#` scan previously duplicated across surfaces).
- delegate `can_tip` guard in ONE place (default-DENY; folds prod
  `messaging._delegate_guard_tip`).
- idempotency-key dedup (replay returns the stored receipt; no double ledger write).
- the EXISTING mock charge (mint `tip_<hex>`; **no real PaymentIntent** — that is B1/TIP-101)
  then the EXISTING `write_tip_ledger` **UNCHANGED** (net `type:"credit"`, 20% fee split).

This is a NEW file and lives in git on `android-impl`; this fold exists so prod can be
re-materialized after a redeploy. `apply.sh [DEST]` copies the file + py_compiles.
Restart: `su - ubuntu -c "bash /home/ubuntu/restart_backend.sh"`.
