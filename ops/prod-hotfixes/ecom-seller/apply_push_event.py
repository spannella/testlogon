#!/usr/bin/env python3
"""ECOM-SELLER G1 push follow-up (idempotent).

Registers the `shop_item_sold` alert event in ALERT_EVENT_TYPES so that:
  * a seller can OPT IN to FCM push for it (set_alert_prefs filters push_event_types
    against ALERT_EVENT_TYPES -- an unregistered event is silently dropped), and
  * send_push_for_alert() actually dispatches (it early-returns when the alert_type
    is not in the user's enabled push_event_types).

Without this, the G1 in-app alert (write_alert) is written but the FCM push can
never be delivered. Run once on prod; anchored + idempotent.
"""
import sys, time
BASE = sys.argv[1] if len(sys.argv) > 1 else '/home/ubuntu/testlogon'
f = BASE + '/app/services/alerts.py'
src = open(f).read()
if 'shop_item_sold' in src:
    print('ALREADY_PRESENT'); sys.exit(0)
anchor = '    # Achievements (ENGAGE-001)\n    "achievement_unlocked",\n]'
if anchor not in src:
    anchor = '    "achievement_unlocked",\n]'
assert anchor in src, 'ALERT_EVENT_TYPES anchor not found'
bak = f + '.bak_ecomsell_push_%d' % int(time.time())
open(bak, 'w').write(src); print('BACKUP', bak)
add = anchor.replace('\n]', '\n    # Commerce / seller fulfillment (ECOM-SELLER G1: enables opt-in FCM push for shop_item_sold)\n    "shop_item_sold",\n]')
open(f, 'w').write(src.replace(anchor, add, 1))
print('PATCHED shop_item_sold registered -> restart backend + openapi 200')
