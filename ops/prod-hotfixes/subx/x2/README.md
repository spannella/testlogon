# SUBX EPIC X2 — Subscriber mobile self-service (SUBX-20..24)

Money-first subscriptions "rough edges" program. X2 makes the subscriber's mobile self-service loop
real: a My-Subscriptions list, correct-target Manage, PAST_DUE dunning recovery, honest reactivate,
and organic discovery/polish. One backend endpoint was added; the rest is Android.

## Backend change (prod hotfix)
`app/routers/subscription_server.py`:
- **NEW** `POST /api/subscriptions/{subscription_id}/retry-payment` (+ `SubscriptionRetryPaymentIn`).
  Subscriber-driven PAST_DUE recovery: optionally swaps the PM, then retries the failed renewal charge
  through the SAME funds-guarded rail the sweeper uses (`subscription_renewal._attempt_renewal`). A real
  collected charge clears `past_due -> active` and advances the period; a decline / missing / unowned PM
  returns HTTP 402 (NO phantom credit, NO free extension). Authz = subscriber or creator (403 else);
  `active` is idempotent (200, no double charge); non-past_due (canceled/expired) -> 409.

Apply: `apply_subx2.py` (idempotent string-insert; asserts single-anchor). Prod applied via SSM:
- backup `subscription_server.py.bak_subx_1784151203`
- `chown ubuntu:ubuntu`, restart `run_local_mock_backend.sh`, openapi 200, path present.

## App changes (assembleDebug GREEN)
- **SUBX-20** `MySubscriptionsScreen.kt` (NEW) over the existing `MySubscriptionsViewModel`; dest
  `subscriptions/mine` (`MySubscriptionsDest` + `mySubscriptionsDestination`); Shop-hub entry
  `more_entry_my_subscriptions`. Lists ALL subs; each row -> the correct-target Manage.
- **SUBX-21** `ManageSubscription{ViewModel,Screen}` + `SubscriptionsNavigation`: Manage route takes
  optional `subscriptionId`/`creatorId`/`creatorName`; `pickCurrent()` resolves the SPECIFIC sub (by id,
  then creator) instead of the global most-recent; headline shows the joined tier name + creator (was raw
  plan id). Tiers "Manage" (`SubscriptionTiersViewModel.NavigateToManage` now carries id+creator) opens
  the sub for THAT creator.
- **SUBX-22** PAST_DUE recovery: Manage adds `isPastDue` branch (banner + "Update payment method" -> AddCard
  + "Retry payment" -> `retryPayment` endpoint). Card-less subscribe also gets a real add-card button
  (`SubscribeScreen`). New repo/api `retryPayment` + `RetryPaymentReqDto`.
- **SUBX-23** honest reactivate: on `resume` failure the VM routes to the paid subscribe flow when the
  backend refuses a free resume (HTTP 409 lapsed / REQUIRES_NEW_METHOD / REQUIRES_ACTION) — never an
  active-but-locked false success.
- **SUBX-24** discovery + polish: creator-profile **Subscribe** button (`PublicProfileScreen` ->
  `SubscriptionTiersDest.build(creatorId, displayName)`); interval-aware up/down labels
  (`monthlyEquivCents`); subscribe SUCCESS screen now dwells with a "View content" CTA (no instant
  auto-pop); Shop hub renamed self-preview to "Your subscription tiers" + added "My subscriptions".

## Deep-verify (live prod DDB, self-cleaning)
`verify_subx2.py` — in-process against the real prod tables (sources `.env.local` for the app's AWS
creds; tagged rows scrubbed to 0 residue):
- **19/19 PASS, residue=0.** SUBX22 A(recover past_due->active + creator NET credit + period advance +
  dunning cleared + access restored), B(no-PM -> 402, stays past_due, no credit), C(PM-swap recovers),
  D(unowned-PM -> 402), E(stranger -> 403), F(active idempotent / canceled -> 409); CORE
  subscribe-credits / grants-access / immediate-cancel refunds+revokes.
- Regression: `x1/verify_subx1.py` re-run **21/21 PASS, residue=0** (X0/X1 money-correctness intact).

## On-device (A15 SM-A156U, admin crash1782189692@)
Seeded 2 real subs for the admin (active $9.99 / past_due $14.99), then scrubbed (25 deleted, residue 0).
- My subscriptions lists BOTH subs; past_due flagged.
- Tapping the past_due row opened the RIGHT sub ($14.99), not the active $9.99 (SUBX-21).
- Manage showed the recovery banner + Update/Retry; **Retry recovered past_due -> Active** with the
  renewal date advanced (SUBX-22).
- Creator profile (Mia Maker) showed the **Subscribe** button -> her tier browse (SUBX-24).

## Residuals (non-blocking)
- Gift @handle picker (F6) still a raw id field — deferred (needs a user-search surface); tracked for a
  later polish pass. All other SUBX-24 items shipped.
- My-subscriptions row title / Manage headline fall back to the raw plan id when the
  `GET /api/creators/{id}/plans` list is empty for that creator (seed artifact — the by-creator plan index
  isn't populated by a raw DDB seed); with real authored plans the join renders the tier name.
