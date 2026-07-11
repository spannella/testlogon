# SUB-E5 — Subscription notifications (default-on transactional, deep-linked)

FINAL epic of the subscriptions completion program (E0–E5). Completes + verifies the
full default-on transactional notification set, each carrying an `action_url` deep-link
and gated by the P2 default-ON push mechanism (opt-out via `push_opt_out_event_types`).

## What shipped
Backend (LIVE PROD HOTFIX via SSM, `.bak_sube5_1783755144` on 3 files):
- `app/services/alerts.py` — registered `subscription_new_subscriber`, `subscription_canceled`,
  `subscription_gifted` (+ the E1 events) in `ALERT_EVENT_TYPES`; added the 3 new events to
  `DEFAULT_PUSH_EVENT_TYPES` (default-ON); added `_build_action_url` fallback deep-links.
- `app/routers/subscription_server.py` — SUBSCRIBE now also notifies the SUBSCRIBER
  ("You subscribed to {creator}" → `/subscriptions/manage`, actor=creator so no self-suppress);
  GIFT now also notifies the GIFTER ("Your gift to {recipient} was sent" → `/subscriptions/manage`)
  and the CREATOR ("{recipient} joined via a gift subscription" → `/subscriptions/subscribers`);
  CANCEL now emits default-on PUSH to BOTH the subscriber (→ `/subscriptions/manage`) and the
  creator ("{name} canceled" → `/subscriptions/subscribers`).
- `app/services/subscription_renewal.py` — E1 sweeper: `_emit` gained an `action_url` param
  (creator-renewed → `/subscriptions/subscribers`, everything else → `/subscriptions/manage`);
  renewal_failed title now says "update your card"; NEW `_maybe_expiring_notice` emits an ADVANCE
  `subscription_expiring` notice N=`SUBSCRIPTION_EXPIRING_NOTICE_DAYS` (default 3) days before a
  NON-renewing sub (canceling / auto_renew off / trial-ending) lapses — fires ONCE per boundary
  (idempotent via the `expiring_notified_period` marker, survives repeated sweeps).

App (build-gate green, BUILD_EXIT=0):
- `feature/alerts/AlertsScreen.kt` + `navigation/AlertsNavigation.kt` — `isSubscriptionAlert`
  predicate + `onOpenSubscription(actionUrl)`; a subscription alert deep-links to
  `CreatorSubscribersDest` when the action_url contains `subscribers`, else `ManageSubscriptionDest`.

## Event → recipient(s) → deep-link matrix
| event | recipient(s) | deep-link |
|---|---|---|
| subscription_started | subscriber | /subscriptions/manage |
| subscription_started | creator | /subscriptions |
| subscription_new_subscriber (audit + registered) | creator | /subscriptions/subscribers |
| subscription_renewed | subscriber | /subscriptions/manage |
| subscription_renewed | creator | /subscriptions/subscribers |
| subscription_renewal_failed | subscriber | /subscriptions/manage |
| subscription_expiring (advance N=3d, idempotent) | subscriber | /subscriptions/manage |
| subscription_expired | subscriber | /subscriptions/manage |
| subscription_canceled | subscriber | /subscriptions/manage |
| subscription_canceled | creator | /subscriptions/subscribers |
| subscription_gifted | recipient | /subscriptions |
| subscription_gifted | gifter | /subscriptions/manage |
| subscription_gifted | creator | /subscriptions/subscribers |

All events default-ON in `DEFAULT_PUSH_EVENT_TYPES`, opt-out-able via `push_opt_out_event_types`.

## Files
- `apply_sube5.py` — anchored + idempotent backend patch (dev clone AND prod). Env: `DRY=1`
  probe (no write), `BAK=1` write `.bak_sube5_<ts>` backups first. `SUBE5_TS` pins the stamp.
- `app_sube5.py` — anchored + idempotent app deep-link wiring patch.
- `verify_sube5.py` — in-process prod-DDB verifier (drives REAL subscribe/gift/cancel endpoints
  + the E1 sweeper). **46/46 OVERALL ALL_PASS** on prod.

## Verify (prod DDB, in-process via SSM)
46/46 ALL_PASS: SUBSCRIBED both sides (+deep-links); RENEWED subscriber+creator; RENEWAL_FAILED
subscriber ("update your card") → past_due no-credit; EXPIRING_SOON advance fires once
(idempotent across sweeps, marker persisted); EXPIRED subscriber; CANCELED subscriber+creator;
GIFTED recipient+gifter+creator; every alert carries an action_url; every event default-ON +
opt-out suppresses.

## Residual (pre-existing, NOT SUB-E5)
- `subscription_cycle_reconciliation_invariant_failed reason=missing_order → dead_lettered`
  (money path correct; downstream recurring-grant reconciler only) — carried from E0/E1/E2.
- The audit→alert mirror (`alerts.audit_event`) writes a second, generically-titled
  `subscription_started` row at `/subscriptions` alongside the SUB-E5 deep-linked emit (both
  render; harmless duplication, pre-existing behaviour).
