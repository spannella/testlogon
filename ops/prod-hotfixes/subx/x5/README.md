# SUBX Epic X5 — Subscription notifications (SUBX-50..52)

Live prod hotfix (SSM) + dev-clone mirror + app. Closes the SUBSCRIPTIONS SMOOTHING program.

## What changed
Backend: `app/services/alerts.py`, `app/services/subscription_renewal.py`, `app/routers/subscription_server.py`.
App: `feature/alerts/AlertsScreen.kt`, `navigation/AlertsNavigation.kt`.

### SUBX-50 — deep-link targets (app + web)
- Renewal-engine `_decline`/_expire/_maybe_expiring_notice now deep-link the SUBSCRIBER to the
  SPECIFIC sub via `/subscriptions/manage?subscriptionId=…&creatorId=…` (new `_manage_url()`), so a
  `subscription_renewal_failed` push lands on the X2 PAST_DUE update-card RECOVERY screen (SUBX-21/22),
  not an arg-less manage list. Creator-side stays `/subscriptions/subscribers` (X4 console).
- Subscribe: the creator alert now uses the dedicated `subscription_new_subscriber` type + deep-links to
  `/subscriptions/subscribers` (was mis-typed `subscription_started` -> bare dead `/subscriptions`).
- App `AlertsNavigation` now parses `subscriptionId`/`creatorId` off the action_url query and routes to
  `ManageSubscriptionDest.build(...)` (the correct sub), fixing the inert manage deep-link on device.

### SUBX-51 — emit the missing / silent lifecycle notifications (all default-on, deep-linked)
- `subscription_new_subscriber` (creator) — now a real dedicated alert (was mis-typed).
- cancel-via-renewal-toggle (`POST /renewal` auto_renew=off) — was SILENT; now pushes both parties.
- plan-change — `subscription_changed` on immediate upgrade AND on scheduled-downgrade apply
  (renewal engine `_apply_pending_change`); new `_emit_subscription_changed()` helper.
- creator removal — promoted from in-app-only `put_notification` to a real default-on push + deep-link.
- trial convert — was SILENT; now pushes the subscriber a receipt (`subscription_converted`).
- Pre-renewal reminder (SUBX-52 minor): `_maybe_prerenewal_notice` — "renews in Nd for \" advance
  notice for AUTO-RENEW subs, idempotent per boundary.
- New alert types `subscription_changed`/`_removed`/`_converted` added to ALERT_EVENT_TYPES +
  DEFAULT_PUSH_EVENT_TYPES (default-on), plus `_build_action_url` fallbacks + the app event set.

### SUBX-52 — de-dupe + copy
- `audit_event` alert-mirror no longer double-writes a (mis-typed `security_event`) alert for
  `subscription_*` audit events (they are all delivered via emit_social_alert/put_notification).
  Guard: `if event not in _NO_ALERT_EVENTS and not event.startswith("subscription_")`. Webhook/SIEM
  audit trail preserved.

## Apply
- Backend: `python3 apply_subx5.py <repo_root>` (idempotent string-replace, asserts 1 hit each; ast.parse).
- App: `python3 apply_subx5_app.py <repo_root>/android`.
- Prod applied via SSM (i-08f937fc705ebea75), chown ubuntu:ubuntu, restart_backend.sh, openapi 200.
- Prod .bak: `*.bak_subx5_1784157630`. Dev .bak: `*.bak_subx5_1784157141` (backend) / `*.bak_subx5_1784157436` (app).

## Verify — `verify_subx5.py` (in-memory, ZERO DDB residue by construction): 27/27 PASS on dev AND prod.
Regression (prod DDB): verify_subx2 19/19, verify_subx4 12/12; (dev) verify_subx1 21/21, verify_subx3 32/32, x3_wire 8/8.
Prod health: openapi 200; webhook (X0 guard) 401 unauth. App: assembleDebug SUCCESSFUL, A15 launch clean.
