#!/usr/bin/env python3
"""ECOM-SELLER P1+P2 backend hotfix - idempotent, anchored.

P1: FCM data payload carries the alert action_url (deep-link) generically, so a
    tapped system-tray push opens directly to the target (e.g. the sale detail).
P2: transactional order/payment events (DEFAULT_PUSH_EVENT_TYPES incl.
    shop_item_sold) are push ON-BY-DEFAULT (opt-out via push_opt_out_event_types).

Runs on the divergent dev clone AND prod. Each edit is guarded (skips if already
present) and asserts its anchor matches exactly once. Set APPLY_ROOT env to target
a probe copy; defaults to the prod checkout. Set APPLY_BACKUP=1 to snapshot files.
"""
import os, time, py_compile

ROOT = os.environ.get("APPLY_ROOT", "/home/ubuntu/testlogon/")
if not ROOT.endswith("/"):
    ROOT += "/"
BACKUP = os.environ.get("APPLY_BACKUP", "") == "1"
TS = int(time.time())

PUSH = ROOT + "app/services/push.py"
ALERTS = ROOT + "app/services/alerts.py"
SSG = ROOT + "app/services/seller_ship_groups.py"

report = []
_backed = set()


def edit(path, old, new, marker):
    """Replace old->new unless marker already present. Assert old occurs once."""
    src = open(path).read()
    if marker in src:
        report.append(("SKIP_PRESENT", os.path.basename(path), marker[:38]))
        return False
    n = src.count(old)
    if n != 1:
        report.append(("ANCHOR_FAIL", os.path.basename(path), f"{marker[:38]} count={n}"))
        raise SystemExit(f"ANCHOR_FAIL {path} marker={marker!r} count={n}")
    if BACKUP and path not in _backed:
        open(path + f".bak_ecomp1p2_{TS}", "w").write(src)
        _backed.add(path)
    src = src.replace(old, new, 1)
    open(path, "w").write(src)
    report.append(("APPLIED", os.path.basename(path), marker[:38]))
    return True


# ---- push.py ---------------------------------------------------------------
edit(PUSH,
  'def send_push_for_alert(user_sub: str, alert_type: str, title: str, body: str, alert_id: str) -> None:',
  'def send_push_for_alert(user_sub: str, alert_type: str, title: str, body: str, alert_id: str, action_url: Optional[str] = None) -> None:',
  'action_url: Optional[str] = None) -> None:')

edit(PUSH,
  '    from app.services.alerts import get_alert_prefs\n'
  '    prefs = get_alert_prefs(user_sub)\n'
  '    enabled = set(prefs.get("push_event_types") or [])\n'
  '    if alert_type not in enabled:\n'
  '        return',
  '    from app.services.alerts import get_alert_prefs, DEFAULT_PUSH_EVENT_TYPES\n'
  '    prefs = get_alert_prefs(user_sub)\n'
  '    # P2 (ECOM-SELLER): effective push allowlist = explicitly-enabled events UNION the\n'
  '    # default-on transactional events the user has NOT opted out of (opt-out, not opt-in).\n'
  '    explicit = set(prefs.get("push_event_types") or [])\n'
  '    opted_out = set(prefs.get("push_opt_out_event_types") or [])\n'
  '    enabled = explicit | (set(DEFAULT_PUSH_EVENT_TYPES) - opted_out)\n'
  '    if alert_type not in enabled:\n'
  '        return',
  'enabled = explicit | (set(DEFAULT_PUSH_EVENT_TYPES) - opted_out)')

edit(PUSH,
  '    # Build type-specific URL for notification click target\n'
  '    url = _alert_url(alert_type, alert_id)',
  '    # P1 (ECOM-SELLER): resolve the deep-link - prefer an explicit action_url, else read\n'
  '    # it off the persisted alert row (generic: every alert stores its action_url).\n'
  '    if not action_url and alert_id:\n'
  '        try:\n'
  '            _it = T.alerts.get_item(Key={"user_sub": user_sub, "alert_id": alert_id}).get("Item")\n'
  '            if _it:\n'
  '                action_url = _it.get("action_url") or None\n'
  '        except Exception:\n'
  '            action_url = action_url or None\n'
  '\n'
  '    # Build the notification click target: the alert deep-link when present (P1),\n'
  '    # otherwise the type-specific fallback URL.\n'
  '    url = action_url or _alert_url(alert_type, alert_id)',
  'url = action_url or _alert_url(alert_type, alert_id)')

edit(PUSH,
  '                fcm_send(\n'
  '                    tok, title, body,\n'
  '                    data={"alert_id": alert_id, "alert_type": alert_type},\n'
  '                )',
  '                fcm_data = {"alert_id": alert_id, "alert_type": alert_type}\n'
  '                # P1: carry the deep-link so a tapped system-tray push routes to the target.\n'
  '                if action_url:\n'
  '                    fcm_data["action_url"] = action_url\n'
  '                fcm_send(tok, title, body, data=fcm_data)',
  'fcm_data["action_url"] = action_url')

# ---- alerts.py -------------------------------------------------------------
edit(ALERTS,
  '    "shop_item_sold",\n]',
  '    "shop_item_sold",\n]\n\n'
  '# ECOM-SELLER P2 - TRANSACTIONAL push events that are ON-BY-DEFAULT (opt-OUT, not\n'
  '# opt-in). A user receives these without manually enabling push prefs; they can\n'
  '# still disable one via ``push_opt_out_event_types``. Keep to genuinely\n'
  '# transactional order/payment events (never social/marketing noise).\n'
  'DEFAULT_PUSH_EVENT_TYPES: List[str] = [\n'
  '    "shop_item_sold",        # you sold an item -> ship it\n'
  '    "subscription_started",  # a subscription/payment succeeded\n'
  '    "post_tip",              # you received a tip\n'
  '    "message_tip",           # you received a message tip\n'
  ']',
  'DEFAULT_PUSH_EVENT_TYPES: List[str] = [')

edit(ALERTS,
  '            "toast_event_types": [], "push_event_types": [],\n'
  '            "webhook_urls": [], "webhook_event_types": [],',
  '            "toast_event_types": [], "push_event_types": [],\n'
  '            "push_opt_out_event_types": [],\n'
  '            "webhook_urls": [], "webhook_event_types": [],',
  '"push_opt_out_event_types": [],')

edit(ALERTS,
  '        "push_event_types": it.get("push_event_types", []),\n'
  '        "webhook_urls": it.get("webhook_urls", []),',
  '        "push_event_types": it.get("push_event_types", []),\n'
  '        "push_opt_out_event_types": it.get("push_opt_out_event_types", []),\n'
  '        "webhook_urls": it.get("webhook_urls", []),',
  '"push_opt_out_event_types": it.get(')

edit(ALERTS,
  '    push_event_types: Optional[List[str]] = None,\n'
  '    webhook_urls: Optional[List[str]] = None,',
  '    push_event_types: Optional[List[str]] = None,\n'
  '    push_opt_out_event_types: Optional[List[str]] = None,\n'
  '    webhook_urls: Optional[List[str]] = None,',
  'push_opt_out_event_types: Optional[List[str]] = None,')

edit(ALERTS,
  '    push_event_types = cur["push_event_types"] if push_event_types is None else push_event_types\n'
  '    webhook_urls = cur["webhook_urls"] if webhook_urls is None else webhook_urls',
  '    push_event_types = cur["push_event_types"] if push_event_types is None else push_event_types\n'
  '    push_opt_out_event_types = (\n'
  '        cur.get("push_opt_out_event_types", [])\n'
  '        if push_opt_out_event_types is None else push_opt_out_event_types\n'
  '    )\n'
  '    webhook_urls = cur["webhook_urls"] if webhook_urls is None else webhook_urls',
  'if push_opt_out_event_types is None else push_opt_out_event_types')

edit(ALERTS,
  '    push_types = [t for t in (push_event_types or []) if t in allowed]\n'
  '    webhook_types = [t for t in (webhook_event_types or []) if t in allowed]',
  '    push_types = [t for t in (push_event_types or []) if t in allowed]\n'
  '    # P2: opt-out only carries the default-on transactional events (opting out of a\n'
  '    # non-default event is a no-op - it is off already).\n'
  '    default_on = set(DEFAULT_PUSH_EVENT_TYPES)\n'
  '    push_opt_out = [t for t in (push_opt_out_event_types or []) if t in default_on]\n'
  '    webhook_types = [t for t in (webhook_event_types or []) if t in allowed]',
  'push_opt_out = [t for t in (push_opt_out_event_types or [])')

edit(ALERTS,
  '        "push_event_types": push_types,\n'
  '        "webhook_urls": webhook_urls_n,',
  '        "push_event_types": push_types,\n'
  '        "push_opt_out_event_types": push_opt_out,\n'
  '        "webhook_urls": webhook_urls_n,',
  '"push_opt_out_event_types": push_opt_out,')

# ---- seller_ship_groups.py (prod-only) -------------------------------------
if os.path.exists(SSG):
    edit(SSG,
      '        send_push_for_alert(seller, "shop_item_sold", title, body, alert_id or sg_id)',
      '        # P1: pass the sale deep-link so the FCM data payload carries action_url.\n'
      '        send_push_for_alert(seller, "shop_item_sold", title, body, alert_id or sg_id, action_url=action_url)',
      'action_url=action_url)')
else:
    report.append(("MISSING", os.path.basename(SSG), "no ecom lifecycle in this checkout"))

# ---- verify compile --------------------------------------------------------
for p in (PUSH, ALERTS, SSG):
    if os.path.exists(p):
        py_compile.compile(p, doraise=True)

print("APPLY_ROOT", ROOT, "BACKUP", BACKUP)
for r in report:
    print("  ", *r)
print("PYCOMPILE_OK")
print("APPLY_DONE")
