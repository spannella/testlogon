# TestLogon — Creator SUBSCRIPTIONS: audit + completion plan

**Repo:** `~/dev/testlogon` @ `6113275d` (branch `android-impl`). **Prod:** EC2 `i-08f937fc705ebea75`.
**Status of this doc:** synthesis of parallel deep audits A1 (backend core), A2 (lifecycle/billing), A3 (gating/app), A4 (money/notify). READ-ONLY audit — no code was changed.
**Prod-divergence:** unlike orders/ecom, the subscription subsystem does **not** diverge prod-vs-dev. `subscription_server.py` is byte-identical on prod (2092 lines, same service-file set, no hidden renewal engine, no cron). All citations below are dev-clone line numbers = prod line numbers.

Terminology: "tiers" are called **plans** in code. Core files:
- `app/routers/subscription_server.py` (2092 L — the engine)
- `app/services/subscription_access.py` (gating)
- `app/services/subscription_cycle_orders.py` (entitlement/reconcile adapter)
- `app/routers/admin_subscription_tiers.py` + `app/services/admin_subscription_tiers.py` (SEPARATE root-gated admin platform-plan surface, not creator plans)
- `app/services/billing_dunning.py`, `app/routers/billing_ccbill.py`, `app/services/billing_ccbill.py` (the OTHER, disconnected billing system — see below)
- App: `feature/subscriptions/*`, `data/subscriptions/SubscriptionsApi.kt`, `navigation/SubscriptionsNavigation.kt`

---

## 1. VERDICT

**The subscription subsystem is a sophisticated simulation, not a working recurring-revenue business.** It has a real tier/plan CRUD, a real subscribe endpoint, real content-gating primitives, and a real creator-payout mirror — but the money path and the recurring engine are hollow:

1. **The subscribe "charge" is fake.** `subscribe` fabricates an invoice stamped `status="paid"` unconditionally (`subscription_server.py:1057-1069`), `provider="stub"` (`:1021/:1024`), with **no PaymentIntent, no payment-method, no funds guard, no balance debit**. Grep for `stripe|_process_charge|payment_method|PaymentIntent|off_session|funds` across the 2092-line router = **zero hits**. A subscriber with $0 and no card "successfully" subscribes. This is materially weaker than the sibling money paths this same codebase already ships (tips → `tips.charge_tip` real funds-guarded stripe-mock PaymentIntent; ads → `ad_billing._process_charge` funds-guarded).

2. **There is NO recurring-renewal engine.** No scheduler, no cron, no asyncio sweep scans `current_period_end`. Renewal exists only reactively via an externally-POSTed `POST /api/billing/webhooks/{provider}` `invoice.paid` (`:1974/:2054-2083`) — but stub subscriptions never receive that event and nothing generates it. Net effect: a subscription is charged **once** at signup then simply lapses. It is a one-time purchase mislabeled with `auto_renew:True`.

3. **Even the webhook renewal pays the creator nothing.** The `invoice.paid` branch extends the period but does **not** call `save_ledger_entry` or `_mirror_creator_credit_to_billing` (`:2054-2083`). Only initial subscribe (`:1103`) and trial-convert (`:1562`) credit the creator.

4. **Two disconnected subscription systems.** The creator-tier system (mock charges, no engine) is the ONLY store content-gating reads. A **real** recurring engine exists — CCBill rebill (`billing_ccbill.py` + `billing_dunning.py`) — but it writes a different keyspace (`T.billing pk=user_sub`), is not wired to tiers, and `has_active_subscription` never reads it. The real engine and the product are not connected.

5. **Phantom revenue.** The creator IS credited real withdrawable dollars (`type:"credit"` net-of-10%-fee into `T.billing`, `_mirror_creator_credit_to_billing:645-707`) from a charge that collected no funds. Refunds don't claw it back (`/earnings` ignores `refund` entries; no negative billing mirror).

6. **Lifecycle never enforces.** `has_active_subscription` (`subscription_access.py:56-70`) treats `active/past_due/trialing` as valid **without checking `current_period_end`**, and nothing flips `canceling→canceled` or `active→expired` at period end. A lapsed or failed-payment sub keeps full access **forever**. There is no `expired` state, no grace period, no dunning beyond a single `past_due` flag.

7. **Whole requirements absent:** gifting (req 8) = zero code on dev **and** prod; MRR/churn/ARPU analytics (req 11) = none; 4 of 6 lifecycle notifications (renewed/failed/expiring/gifted) = none; app has no creator tier-authoring, no subscriber-management, no gifting, no creator-profile Subscribe entry, and video subscriber-locks flatten to a dead-end "forbidden" with no Subscribe CTA.

**Bottom line: the user's instinct is correct — subscriptions are INCOMPLETE.** The tier/subscribe/gate/payout scaffolding is real and reusable, but the three load-bearing pieces of a subscription business — a real charge, a recurring engine that re-charges and re-credits, and lifecycle/dunning enforcement — are missing or mocked.

---

## 2. COVERAGE MATRIX (13 requirements)

| # | Requirement | Status | Key evidence |
|---|---|---|---|
| 1 | **TIERS** — creator defines paid tiers (name/price/interval/benefits, CRUD) | **PARTIAL** | CRUD EXISTS: create `subscription_server.py:827-865`, list `:867`, patch `:877-911`, archive `:913-934`, bulk-price `:1288`. `PlanCreateIn:316-325` = name/price_cents/currency/interval(month\|year)/annual_price_cents/metadata/asset_paths. **GAP: no structured benefits/perks model** (perks only ride free-form `metadata`); no weekly/custom interval. **App tier-authoring UI MISSING** (app only GETs plans). |
| 2 | **SUBSCRIBE** — user subscribes → real CHARGE + record | **PARTIAL** | Endpoint `POST /api/plans/{id}/subscribe:936-1212` + 3-index record (`:1017-1038`, `build_subscription_items:541-549`) EXIST. **Charge is MOCK** — invoice `status="paid"` unconditionally `:1057-1069`, `provider="stub":1021`, no PM/funds guard (zero stripe refs). App flow exists but **discoverability broken** — only reachable via ad CTA (`AdCtaRouter.kt:90`) or self-browse; **no creator-profile Subscribe button**. No `next_billing_date` field (derived from `current_period_end`). |
| 3 | **RECURRING RENEWAL** — scheduled re-charge engine | **MISSING** | No scheduler/cron/asyncio sweep anywhere (grep `next_billing/process_renewal/due_subscription/run_renewals` = ∅). Renewal only via external webhook `:1974/:2054-2083` that stub subs never receive. Effectively one-time. |
| 4 | **LIFECYCLE** — active/trialing/past_due/canceled/expired + grace | **PARTIAL** | States: active, trialing (`:1009/1013`), past_due (webhook-only `:2083`), canceling (`:1350`), canceled. **No `expired` state, no grace, no sweeper** to transition over time. `has_active_subscription:56-70` ignores `current_period_end` → access never ends on lapse; `past_due` = access forever; `canceling` = loses access immediately (wrong). |
| 5 | **DUNNING** — retry → past_due → expire + notifications | **MISSING (for tiers)** | Tier `invoice.payment_failed` = single `status="past_due"` flip `:2083`, no retry/grace/notify/expire. A real dunning engine exists (`billing_dunning.py`, retry `3600,86400,172800`, loop `:283-302`) but defaults **OFF** (`settings.py:393`) and duns billing-balance autopay, **not tiers**. CCBill path IS wired (`billing_ccbill.py:747-772`) but disconnected from tiers. |
| 6 | **PRORATION + UPGRADE/DOWNGRADE** | **PARTIAL** | Immediate change WORKS: `change_subscription_plan:1585-1712` + `calculate_proration:806-825` (policies none/charge/credit/full), writes proration ledger. **Period-end change BROKEN**: writes `pending_plan_id/pending_apply_at:1610-1627` but **nothing reads them** (grep = 0 consumers) → never applies. Proration "charge" is again a stamped invoice, no real debit; proration credit → ledger only, no billing mirror (`:1699`). |
| 7 | **FREE TRIALS** | **PARTIAL** | Create WORKS: `trial_days`→`trialing`, trial_start/end, `period_end=trial_end` (`:1004-1013`); promo `free_trial_days:1001`; trial-end calendar event `:776-788`. **Auto-conversion MISSING** — convert is manual only `POST .../trial/convert:1485`; nothing charges at `trial_end` (no scheduler); trialing grants access indefinitely. |
| 8 | **GIFTING** | **MISSING** | Zero gift code on dev **and** prod (grep `gift` across `subscription_server.py`/`subscription_access.py`/`syndicate_subscriptions.py`/app = ∅). No purchase/recipient/redemption/gifter-pays. |
| 9 | **CANCELLATION + refunds** | **PARTIAL** | Cancel WORKS: cancel_at_period_end vs immediate `:1333-1388`, resume `:1390`, creator remove/stop-renewal `:1714/1779`. **Immediate cancel doesn't revoke access early** (access keyed off status, `canceling` loses access but `canceled` w/ period-end still ok). **Refunds bookkeeping-only** — `mark_invoice_refunded:266` called only from `remove_subscriber:1738`; **no real Stripe/CCBill refund API**, no self-serve refund, no proration refund, **no negative billing mirror** (creator withdrawable not clawed back). |
| 10 | **SUBSCRIBER-ONLY GATING** across surfaces | **PARTIAL** | VOD/video EXISTS (richest, per-content `access_mode`: `video_listing.py:1324/1523`, `vod_purchase.py:160/192`). Catalog/store EXISTS but coarse (`catalog.py:318/404/514/839/869` via creator-wide `can_access_creator`). Newsfeed PARTIAL — creator-wide only, gated posts silently filtered, **no locked/upsell card** (`newsfeed.py:2690`). Messaging EXISTS as pay-to-DM gate (`messaging.py:6143/6645/8317/…`). **Broadcast/live MISSING** (only ad-free `broadcast_ads.py:46`). **No per-post/per-message and no per-tier-LEVEL gating** (fan-club tier primitive `fan_club_access.py:11` defined but dead/unwired). App locks are dead-ends: video flattens `SubscriptionRequired`→`FORBIDDEN` with no CTA (`VideoDetailViewModel.kt:243-247`, `VideoDetailScreen.kt:575`). |
| 11 | **CREATOR SUBSCRIBER MGMT + MRR/analytics** | **PARTIAL** | Backend EXISTS: `count_active_subscribers:559`, list `:1237`, remove `:1714`, stop-renewal `:1779`, earnings `:1939` (but only sums `charge`/`fee`, ignores renewals & refunds). **No MRR/churn/ARPU/cohort anywhere.** **App screen MISSING entirely** (no subscriber list, no analytics). |
| 12 | **PAYOUTS** — creator earns + platform fee + renewal credits | **PARTIAL** | Signup credit EXISTS: `charge`+`fee` ledger (`fee=amount*FEE_BPS/10000`, `FEE_BPS=1000`=10%, `:30/:1085/:1101`) + `_mirror_creator_credit_to_billing` net→`T.billing` `type:"credit" reason="subscription_charge":645-707/1103`; also trial-convert `:1562`. **Renewal credit MISSING** (webhook `invoice.paid` writes no ledger/mirror `:2054-2083`). Credit is booked though subscriber never charged = phantom revenue. |
| 13 | **NOTIFICATIONS** — subscribed/renewed/failed/expiring/canceled/gifted | **PARTIAL** | Only **subscribed→creator** is a real default-on FCM push (`emit_social_alert("subscription_started"):1148-1166`, in `alerts.py DEFAULT_PUSH_EVENT_TYPES:143/163`). Subscriber-facing "started" = in-app/SSE only. canceled = `put_notification` in-app/SSE only `:1355-1366` (no push). **renewed / renewal-failed / expiring / gifted = MISSING.** |

**Score: 0 EXISTS-complete · 10 PARTIAL · 3 MISSING (3, 5, 8).**

---

## 3. TARGET DESIGN (a complete subscription system)

Design principle: **reuse the money/infra rails this codebase already ships.** Do not invent new payment or scheduler primitives.

### 3.1 Rails to reuse
- **Real charge:** the funds-guarded stripe-mock rail used by tips/ads — `ad_billing._process_charge` / `tips.charge_tip` pattern (off_session PaymentIntent against stripe-mock `localhost:12111`, funds guard, `payment_method_id`). Subscribe and every renewal must run through this, not the stub invoice.
- **Payout ledger:** `_split_revenue` / `type:"credit"` into `T.billing USER#{creator}` (`_mirror_creator_credit_to_billing:645-707`) that `creator_earnings._query_credit_entries` + `creator_payouts.get_available_balance` read. Keep the existing signup credit; ADD the identical credit on each renewal; ADD a negative mirror on refund.
- **Scheduled sweep:** the asyncio `register_task` + `while True: work(); await asyncio.sleep(interval)` pattern from `billing_dunning.py:283-302`, started in `app/main.py` startup (next to `start_billing_dunning_task`). Closest scan-and-transition analogue = `moderation_lifecycle.start_hold_sweep_task` (the 30d sweep).
- **Default-on push:** `emit_social_alert(...)` + adding new event types to `alerts.py DEFAULT_PUSH_EVENT_TYPES` (route map `:72`), prefs-gated dispatch (`social_alerts._dispatch_to_channels`).
- **Gating:** `subscription_access.has_active_subscription` / `can_access_creator` — extend to check `current_period_end` and tier-level, keep the same call-sites.

### 3.2 Data model additions
- **Tier/plan:** add a first-class `benefits: list[{key, label, description}]` (or `perks`) to `PlanCreateIn` (`:316`) + a `tier_level: int` for per-level gating (drives fan-club `get_subscriber_tier_level`). Keep month/year; optionally add `week`.
- **Subscription record:** add `next_billing_date` (authoritative, not derived), `cancel_at` timestamp, `grace_until`, `dunning_state`/`dunning_attempts`, `pending_change {plan_id, interval, price_cents, apply_at}` consumed by the sweeper, `payment_method_id`.
- **New status set:** `trialing → active → past_due → grace → canceled/expired`; add `expired`; `canceling` = flag on `active` (cancel_at_period_end), not a status that drops access.

### 3.3 The RECURRING RENEWAL engine (the headline build)
New `app/services/subscription_renewal.py` with `start_subscription_renewal_task()` registered in `app/main.py`, loop template from `billing_dunning.py:283-302`. Each tick sweeps `T.subscriptions` for rows due (`next_billing_date <= now`) across an index, and for each:
1. **Charge** the real PM via the stripe-mock rail (funds-guarded, idempotency key = `sub_id:period_end`).
2. On **success:** advance `current_period_end` + `next_billing_date += interval`, mint a real invoice, **credit the creator** (same `save_ledger_entry(charge/fee)` + `_mirror_creator_credit_to_billing` as signup — this fixes the renewal-doesn't-pay gap), emit `subscription_renewed` push.
3. On **failure:** open a subscription dunning schedule → `past_due` → retries (configurable, default `3600,86400,172800`) → `grace` → `expired`; emit `renewal_failed` + `subscription_expiring` pushes.
4. **Auto-convert trials** at `trial_end` (charge + `trialing→active`).
5. **Apply `pending_change`** at period end (the currently-dead period-end upgrade/downgrade path).
6. **Flip `canceling→canceled`** and **`active→expired`** at `current_period_end`.

"Auto-charge in a mock world" decision (see §5): either (a) really run the stripe-mock off_session PI each cycle (recommended — exercises the real rail, may fail like prod), or (b) simulate success deterministically. Either way the creator credit + invoice + notifications must fire identically.

### 3.4 Lifecycle + gating enforcement
- `has_active_subscription` (`subscription_access.py:56-70`) must also require `current_period_end > now` (or within grace). `canceling` keeps access until period end.
- Extend gating to **broadcast/live** (add a subscriber gate alongside `broadcast_ads.py:46`) and wire the dead **per-tier-level** primitive (`fan_club_access.can_view_content:11`) into read paths.
- Add **per-post subscriber-only** visibility (extend `newsfeed.py:1420` `Literal["followers","public"]` → add `subscribers`) and render **locked upsell cards** instead of silently filtering.
- App: video lock must route to `SubscriptionTiersDest` with a real Subscribe CTA (stop flattening `SubscriptionRequired`→`FORBIDDEN` in `VideoDetailViewModel.kt:243`).

### 3.5 App surfaces to add
- Creator-profile **Subscribe** entry (the missing organic path).
- Creator **tier-authoring** screen (wire the existing create/patch/archive endpoints + the `require_subscription` toggle `:1258/1264`).
- Creator **subscriber-management + MRR** screen (list/remove/stop-renewal/earnings + new MRR/churn aggregation).
- **Gifting** flow (new endpoint + recipient redemption + gifter-pays via the real charge rail).
- Wire the dangling `MySubscriptionsViewModel` to a real multi-sub list screen.

---

## 4. EPIC PLAN (dependency-ordered)

**7 epics, 28 tickets.** Effort: S ≤1d, M 2-3d, L 4-6d, XL >1wk. Money-path acceptance criteria are mandatory on every charging ticket: *what charges, who is credited, idempotency key, renewal correctness.*

### EPIC E0 — FOUNDATION: real charge + record + tier model
> Everything else depends on a real, funds-guarded charge and an authoritative record.

- **SUB-01 (backend, M)** — Real subscribe charge. Route `subscribe` (`:936-1212`) through the funds-guarded stripe-mock rail (`ad_billing._process_charge`/`tips.charge_tip` pattern) instead of the stub invoice (`:1057-1069`). Add `payment_method_id` to `SubscribeIn`. **Deps:** none. **AC:** subscriber with insufficient funds/no card is **rejected** (currently succeeds); on success a real PaymentIntent is authorized, invoice reflects the real provider id (not `stub_inv`), idempotency key = `sub_id:period_start`; creator credit unchanged (`:1103`).
- **SUB-02 (backend, S)** — Record fields. Add `next_billing_date`, `cancel_at`, `grace_until`, `dunning_state`, `payment_method_id`, `pending_change` to the subscription record (`:1017-1038`) + `build_subscription_items` (`:541-549`). **Deps:** none. **AC:** `next_billing_date` is authoritative and equals `current_period_end` at creation; summary reads the field, not a derived value (`:603-620`).
- **SUB-03 (backend, M)** — Benefits/perks + tier_level model. Add `benefits[]` + `tier_level` to `PlanCreateIn` (`:316-325`) and plan items (`build_plan_items:524-530`); expose on plan GET. **Deps:** none. **AC:** a tier persists structured perks + an integer level; existing plans default to level 0 / empty perks.
- **SUB-04 (app, M)** — Creator tier-authoring UI. New screen wiring create/patch/archive (`:827/877/913`) + benefits editor + `require_subscription` toggle (`:1258/1264`). Extend `SubscriptionsApi.kt` (currently GET-only). **Deps:** SUB-03. **AC:** a creator can author/edit/archive a tier and toggle subscriber-gating from the app.
- **SUB-05 (app, S)** — Creator-profile Subscribe entry. Add a Subscribe button in `feature/profile` → `SubscriptionTiersDest.build(creatorId)` (the only current organic path is the ad CTA `AdCtaRouter.kt:90`). **Deps:** none. **AC:** every creator profile routes to that creator's tiers.

### EPIC E1 — RECURRING RENEWAL + DUNNING ENGINE (the headline)
> Depends on E0 (real charge + `next_billing_date`).

- **SUB-10 (backend, L)** — Renewal sweeper. New `app/services/subscription_renewal.py` + `start_subscription_renewal_task()` in `app/main.py`, loop template `billing_dunning.py:283-302`, `job_registry.register_task`. Sweep `next_billing_date <= now`. **Deps:** SUB-01, SUB-02. **AC:** a due sub is re-charged via the real rail (idempotency `sub_id:period_end`, no double-charge on overlapping ticks), `current_period_end`+`next_billing_date` advance by exactly one interval, a real invoice is minted.
- **SUB-11 (backend, M)** — Renewal credits the creator. On renewal success emit `save_ledger_entry(charge/fee)` + `_mirror_creator_credit_to_billing` (the exact signup path `:1101-1103`), which the webhook branch omits (`:2054-2083`). **Deps:** SUB-10. **AC:** each successful renewal credits the creator net-of-fee to `T.billing` and appears in `/earnings`; a 3-cycle sub credits the creator 3×.
- **SUB-12 (backend, M)** — Subscription dunning. On renewal charge failure open a dunning schedule (reuse `billing_dunning` retry semantics, tier-scoped): retry `3600,86400,172800` → `past_due` → `grace_until` → `expired`. **Deps:** SUB-10. **AC:** a failing card retries on schedule, transitions past_due→grace→expired, and stops crediting the creator; no infinite past_due access.
- **SUB-13 (backend, S)** — Wire/enable existing dunning cleanly. Reconcile with `billing_dunning_enabled` (default OFF `settings.py:393`) — either a subscription-specific flag or extend the existing loop. **Deps:** SUB-12. **AC:** subscription dunning runs independently of the billing-balance autopay dunning.

### EPIC E2 — LIFECYCLE: proration/upgrade, trials, cancel, gifting
> Depends on E1 (sweeper exists to apply period-end changes).

- **SUB-20 (backend, M)** — Apply period-end plan changes. Consume `pending_change`/`pending_plan_id` (`:1610-1627`, currently 0 consumers) in the sweeper at `current_period_end`. **Deps:** SUB-10. **AC:** a scheduled upgrade/downgrade actually applies at period end and charges/credits proration correctly.
- **SUB-21 (backend, S)** — Real proration charge + credit mirror. Route `change_subscription_plan` proration (`:1585-1712`) through the real charge rail; mirror proration credit negatively/positively to `T.billing` (currently ledger-only `:1699`). **Deps:** SUB-01. **AC:** an immediate upgrade really debits the delta; a downgrade credit reaches withdrawable balance.
- **SUB-22 (backend, S)** — Auto-convert trials. Sweeper charges + flips `trialing→active` at `trial_end` via the real rail (replaces manual-only `:1485`). **Deps:** SUB-10. **AC:** a trial auto-charges at `trial_end`; on failure enters dunning; access does not persist un-charged.
- **SUB-23 (backend, M)** — Gifting endpoint. New `POST /api/plans/{id}/gift` — gifter pays via the real rail, recipient gets a subscription record (or a redemption code), creator credited as normal. **Deps:** SUB-01. **AC:** gifter is charged, recipient gains access, creator credited; grep `gift` currently = ∅.
- **SUB-24 (app, M)** — Gifting UI + redemption. **Deps:** SUB-23. **AC:** user can gift a tier and a recipient can redeem.
- **SUB-25 (backend, S)** — Cancellation semantics + real refunds. Fix `canceling` to keep access until period end (`subscription_access.py:64-70`); on immediate cancel with refund, call a real refund + **negative billing mirror** (currently `mark_invoice_refunded:266` is bookkeeping-only, no clawback, `/earnings` ignores `refund`). **Deps:** SUB-01, SUB-11. **AC:** immediate refund reverses subscriber charge AND claws back creator withdrawable; `/earnings` reflects refunds; cancel-at-period-end keeps access until `current_period_end`.

### EPIC E3 — LIFECYCLE ENFORCEMENT + GATING COMPLETENESS
> Depends on E1 (states + grace exist).

- **SUB-30 (backend, S)** — Access bounded by period + grace. `has_active_subscription` (`subscription_access.py:56-70`) must require `current_period_end > now` (or within `grace_until`). **Deps:** SUB-12. **AC:** a lapsed/expired sub loses access; `past_due` within grace keeps it, beyond grace loses it.
- **SUB-31 (backend, M)** — Per-tier-level gating. Wire the dead `fan_club_access.can_view_content:11` (`get_subscriber_tier_level >= required`) into content read paths. **Deps:** SUB-03. **AC:** a $5-tier subscriber is denied $20-tier content; owner always allowed.
- **SUB-32 (backend, M)** — Per-post subscriber-only. Extend `newsfeed.py:1420` visibility `Literal["followers","public"]` → add `subscribers`; gate in `can_view_post` (`:2690`). **Deps:** SUB-30. **AC:** a subscriber-only post is visible to active subs, gated to others.
- **SUB-33 (backend, S)** — Broadcast/live gating. Add a subscriber gate for live/broadcast content (today only ad-free `broadcast_ads.py:46`). **Deps:** SUB-30. **AC:** subscriber-only stream is playable by active subs, blocked otherwise.
- **SUB-34 (app, M)** — Locked-content upsell rendering. Stop flattening `SubscriptionRequired`→`FORBIDDEN` (`VideoDetailViewModel.kt:243-247`); render a Subscribe CTA routing to `SubscriptionTiersDest`. Render locked feed cards instead of silently filtering. **Deps:** SUB-05. **AC:** a gated video shows "Subscribe to watch" → tiers; a gated post shows a locked upsell card.

### EPIC E4 — CREATOR SUBSCRIBER MANAGEMENT + MRR
- **SUB-40 (backend, M)** — MRR/churn/ARPU aggregation. New endpoint aggregating active subs × price / interval-normalized, plus churn and ARPU, off the `CREATOR#` SUB# index (`count_active_subscribers:559`). Fix `/earnings` (`:1939`) to include renewals + refunds. **Deps:** SUB-11, SUB-25. **AC:** MRR reflects active recurring revenue; earnings include renewal credits and net of refunds.
- **SUB-41 (app, L)** — Creator subscriber-management screen. List (`:1237`), remove (`:1714`), stop-renewal (`:1779`), earnings (`:1939`), MRR/churn (SUB-40). **Deps:** SUB-40. **AC:** creator sees + manages subscribers and revenue in-app (none today).
- **SUB-42 (app, S)** — Subscriber multi-sub list. Wire the dangling `MySubscriptionsViewModel` to a real screen/nav. **Deps:** none. **AC:** a subscriber sees all their active subs (today `ManageSubscriptionScreen` shows only one via `pickCurrent()`).

### EPIC E5 — NOTIFICATIONS (default-on transactional)
> Depends on E1 (events to notify on exist).

- **SUB-50 (backend, S)** — Renewal notifications. `subscription_renewed` (both parties) on renewal success; add to `alerts.py DEFAULT_PUSH_EVENT_TYPES` (`:143/163`, route map `:72`). **Deps:** SUB-10. **AC:** successful renewal pushes to subscriber + creator by default.
- **SUB-51 (backend, S)** — Failure/dunning notifications. `renewal_failed` + escalating dunning notices, default-on push. **Deps:** SUB-12. **AC:** each retry/state-change notifies the subscriber.
- **SUB-52 (backend, S)** — Expiring/trial-ending reminders. Sweeper emits `subscription_expiring` / `trial_ending` N days before `next_billing_date`/`trial_end` (calendar event already exists `:770-800` but silent). **Deps:** SUB-10. **AC:** subscriber is reminded before renewal/trial-charge.
- **SUB-53 (backend, S)** — Cancel/gift push parity. Promote `subscription_canceled` (currently in-app/SSE only `:1355-1366`) to default-on push; add `subscription_gifted`. **Deps:** SUB-23. **AC:** cancel + gift both push by default.

**Ticket count by epic:** E0 = SUB-01..05 (5); E1 = SUB-10,11,12,13 (4); E2 = SUB-20..25 (6); E3 = SUB-30..34 (5); E4 = SUB-40,41,42 (3); E5 = SUB-50..53 (4). **Total = 27 tickets across 6 build epics (E0–E5).**

---

## 5. OPEN DECISIONS (user must decide before build)

1. **Real auto-charge on renewal, or simulate?** In the stripe-mock world an off_session PaymentIntent never truly "succeeds." Option (a) run the real rail each cycle (renewals can legitimately fail → exercises dunning) vs (b) deterministic simulated success. Recommendation: (a) for fidelity, with a dev flag to force success.
2. **Platform fee % on subscriptions.** Currently `SUBSCRIPTION_FEE_BPS=1000` (10%). Keep 10%, or match ads/tips/ecom rates?
3. **Default free-trial length** (and whether trials require a payment method up front).
4. **Grace-period length** after a failed renewal before access is cut (e.g. 3 / 7 / 14 days).
5. **Dunning retry schedule** — keep the existing `3600,86400,172800` (1h/1d/2d) or a longer real-world cadence (e.g. day 1/3/5/7)?
6. **Proration policy default** — none / charge-delta / credit / full-period (`calculate_proration` supports all).
7. **Cancel default** — cancel-at-period-end (keep access, current default) vs immediate.
8. **Gifting** — allow at all? gifter-pays only, or redemption codes? recurring gift or one-cycle?
9. **Per-post / per-tier-level gating scope** — ship binary "any active sub" first, or full tier-level differentiation from the start?
10. **Backfill phantom-revenue** — existing stub subscriptions credited creators real dollars with no funds collected. Reconcile/claw back, or grandfather?

---

*Synthesized from parallel audits A1–A4. No code changed. Cite this doc's matrix (§2) for status and §4 for the dependency-ordered build.*
