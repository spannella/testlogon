# ECOM-SELLER P1 + P2 (sold-push deep-link + default-on transactional push)

Follow-up polish on the seller-fulfilment feature. Backend = LIVE PROD HOTFIX via SSM
(`.bak_ecomp1p2_*`) + this fold; app = build-gate green.

## P1 — sold-push TAP deep-links to the exact sale
- **Backend** (`app/services/push.py`): `send_push_for_alert(..., action_url=None)` now
  includes the alert `action_url` in the FCM `data` payload. Generic for ANY alert: an
  explicit `action_url` is used if passed, otherwise it is resolved from the persisted
  alert row (`T.alerts` by `user_sub`+`alert_id`), so future deep-links work with no
  caller change. `app/services/seller_ship_groups.py::_notify_seller` passes the sale
  deep-link explicitly (`/seller/orders?sale={ship_group_id}`).
- **App**: the FCM tap now routes to the sale. `PushPayload.deepLink` /
  `NotificationDeepLink.Alert.actionUrl` carry the deep-link; `DeepLinkIntentFactory`
  puts `EXTRA_ACTION_URL`; `DeepLinkParser.parse` reads `action_url` from BOTH the
  app-built PendingIntent extras AND the raw FCM system-tray `data` extras (a generic
  alert push carries `alert_type`/`alert_id`/`action_url` with no `kind`).
  `MainActivity.routePendingNotificationDeepLink` handles `NotificationDeepLink.Alert`
  by reusing the SAME in-app resolver the Alerts row uses
  (`feature/alerts saleIdFromActionUrl` -> `SellerSalesDest.build(saleId)`).

## P2 — sold-push is ON BY DEFAULT (opt-out, not opt-in)
- `app/services/alerts.py`: new `DEFAULT_PUSH_EVENT_TYPES`
  (`shop_item_sold`, `subscription_started`, `post_tip`, `message_tip`) = transactional
  events that are push default-on. `send_push_for_alert` gate now =
  `explicit push_event_types UNION (DEFAULT_PUSH_EVENT_TYPES - push_opt_out_event_types)`.
  `get_alert_prefs`/`set_alert_prefs` gained `push_opt_out_event_types` (filtered to the
  default-on set) so a seller can still DISABLE the sold push.

## Files
- `apply_ecom_p1p2.py`  — idempotent anchored apply (dev clone + prod; `APPLY_ROOT`, `APPLY_BACKUP=1`).
- `verify_ecom_p1p2.py` — in-process prod verify (13/13 ALL_PASS): default-on / disable-able /
  opt-out filtered / non-default stays opt-in / FCM data carries action_url (explicit + from-row).
- `seed_ecom_demo.py` / `trigger_purchase.py` — demo prep (fresh phone-loginable seller+buyer+item+address)
  and the real buyer purchase that fires the shop_item_sold push.
- `upload_email_v3.py` — S3 upload + 7-day presign + SES email of the re-recorded V3.
- `seller_ship_groups.py` — full-file mirror of the prod service (P1 push call).

## Prod ops
Probe-first (`APPLY_ROOT=/tmp/probe...`), then real (`APPLY_BACKUP=1`), restart
`su - ubuntu -c "bash /home/ubuntu/restart_backend.sh"`, openapi 200. Prod anchors matched
the dev clone verbatim (no divergence in the patched regions).
