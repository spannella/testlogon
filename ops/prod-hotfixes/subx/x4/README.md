# SUBX EPIC X4 — Creator tooling (mobile tier authoring + web console + reporting reconciliation)

Money-first subscriptions "rough edges" program. X4 turns the split-brain creator console into a
complete one: mobile tier AUTHORING (the Android console was GET-only), correct REPORTING that
reconciles to the ledger after refunds, per-tier revenue/subscriber analytics, and creator
subscriber ACTIONS (refund/comp) + a per-tier filter. Reuses X1's correct price/refund rails and
X3's tier level model.

## Backend change (single file, prod hotfix) — `app/routers/subscription_server.py`

**SUBX-42 — Reporting reconciliation (C4/C5/C3):**
- New `_creator_subscription_reversals(creator_id)` reads the T.billing subscription REVERSAL
  clawbacks (`type=reversal`, `meta.content_type=subscription`) that `_reverse_subscription_charge`
  books but the sub LEDGER never records.
- `list_earnings` (`/earnings`) now subtracts those reversals → adds `refunded_cents`; **net ==
  withdrawable balance** after any full/partial refund (was permanently overstated).
- `get_creator_subscription_analytics`:
  - `refunded_to_date`/`net_revenue_to_date` fold the T.billing reversals (was reading the empty sub
    ledger `refund`, so net overstated after every cancel/dispute).
  - **MRR** excludes gifts (`is_gift`) + non-renewing (`auto_renew=False` / `cancel_at_period_end`)
    + trials + past_due, and is computed off the **LIST price** (`list_price_cents`→`price_cents`),
    not the discounted charge (C3).

**SUBX-43 — Subscriber actions + per-tier analytics + labeling (C6/C7/C8/C9/C10):**
- `by_tier[]` (`SubE4TierBreakdownOut`): per-plan active/trialing/past_due counts + MRR + gross/net
  revenue. Revenue attributed to a subscription's current plan; **sums reconcile to the creator-wide
  aggregates** (per-tier ledger attribution runs in a 2nd pass, after the sub→plan map is built,
  because the CREATOR# partition returns `LEDGER#` before `SUB#`).
- Cohort **churn** (C7): `active_at_window_start` denominator = subs that existed at window start;
  `churn_rate = churned_in_window / active_at_window_start`.
- `past_due_mrr_cents` (C9) surfaced distinctly (recoverable book); window labels in the app.
- `display_order` on the plan model + `POST /api/creators/{id}/plans/reorder` + `list_plans` sorts
  by `display_order` then created_at (C10).
- `list_creator_subscribers` gains a `plan_id` per-tier filter (C6).

Prod is **byte-identical to dev HEAD** (`sha256 923cdad…`, confirmed via SSM before applying).
Applied via SSM (prod EC2 `i-08f937fc705ebea75`, us-east-2), DEV_MODE mock deployment (DDB-Local
:8001 on the prod host):
- `python apply_subx4_ssm.py` emits an SSM payload embedding `subx4_server.patch` (base64) →
  backup `subscription_server.py.bak_subx_1784155887`, `patch -p1 --forward`, `ast.parse` OK,
  `chown ubuntu:ubuntu`, restart `run_local_mock_backend.sh`.
- Verified live: **openapi 200**, `plans/reorder` route present, `by_tier`/`past_due_mrr_cents`
  fields present.

## App changes (assembleDebug GREEN)
- **SUBX-40** `SubscriptionsApi.kt`: added `createPlan`/`updatePlan`(PATCH)/`archivePlan`/
  `reorderPlans` + `refundSubscription` + `PlanWriteReqDto`/`PlanReorderReqDto`/`SubscriptionRefund*`;
  `level`+`display_order` on the plan DTO; `by_tier`/`past_due_mrr_cents`/`active_at_window_start`
  on the analytics DTO + `SubscriptionTierBreakdownDto`. Repository + domain mappers extended.
  **NEW** `CreatorTierManager{ViewModel,Screen}` — "Your subscription tiers": list own tiers +
  create/edit (name/price/interval/description/level/perks) + archive + up/down reorder. Dest
  `subscriptions/tiers/manage` (`CreatorTierManagerDest` + `creatorTierManagerDestination`); Growth
  hub entry `creator_tiers` ("Manage tiers"; `MoreRoutes.CREATOR_TIERS` + REGISTERED).
- **SUBX-43** `CreatorSubscribers{ViewModel,Screen}`: `by_tier` "Revenue by tier" cards +
  past_due-MRR + refunded-to-date + window label; per-tier **filter chips**; per-row **Refund**
  action (revokes access via the shared rail) with a confirm dialog.

## Web changes (type-coherent; BUILD DEFERRED — no node/tsc on the dev host)
- **SUBX-41** `App.tsx`: route the previously-unrouted subscriber page `MySubscriptions`
  (`/subscriptions/mine`) + a new creator `CreatorSubscribers` page (`/subscriptions/subscribers`)
  wired to the E4 endpoints (subscribers + analytics + remove/stop-renewal), so the E5 deep-links
  resolve on web. Flagged build-deferred.

## Deep-verify (live PROD DDB, in-process, self-cleaning) — `verify_subx4.py`
Run on the prod EC2 (`run_verify_prod_ssm.py` → SSM). **12/12 PASS, residue=0** on prod:
- 42A `/earnings` net == withdrawable balance pre-refund + after FULL refund (both 0, refunded=net).
- 42B partial refund: net/refunded reconcile to balance.
- 42C analytics net_to_date == balance after refund; refunded folds T.billing reversals.
- 42D MRR excludes gift + cancel-at-period-end; 42E MRR off LIST price (discounted sub counted at list).
- 43A past_due_mrr distinct + excluded from MRR; 43B cohort churn denom = active-at-window-start;
  43C by_tier reconciles to aggregates + ordered by display_order; 43D per-tier subscriber filter;
  43E reorder persists display_order; 40 create/patch/archive roundtrip.
- Regression on the dev DDB clone: X1 21/21, X2 19/19, X3 32/32 — money core + self-service + tier
  gating all intact.

## On-device (A15 SM-A156U R5CX821TA9R, admin crash1782189692@)
Growth hub → **Manage tiers** → "Your subscription tiers" (empty state + New tier FAB) → created a
**Gold $9.99/month** tier end-to-end via the real create endpoint (list shows it with Edit/Archive +
reorder chevrons); **Edit** pre-fills name/price/interval and patches. No crashes. The synthetic
Gold tier (`plan_838f4b46…`) was deleted from prod DDB afterward (residue 0).

## Residuals (non-blocking)
- Web is static-reviewed only (no tsc/build on the dev host) — flagged BUILD DEFERRED.
- Tier editor sends benefit labels only (no per-benefit `detail`); "comp/gift-a-fan" creator action
  reuses the existing gift flow rather than a new inline entry point (deferred polish).
- Per-tier analytics on-device wasn't exercised with live subscribers (admin has none); covered by
  the 43C verifier reconciliation instead.
