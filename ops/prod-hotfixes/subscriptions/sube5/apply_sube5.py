#!/usr/bin/env python3
"""SUB-E5 subscription-notifications hotfix. Anchored + idempotent. Runs on the
divergent dev clone AND prod. Completes the default-on transactional set:
SUBSCRIBED(both sides), CANCELED(both), GIFTED(recipient+gifter+creator),
EXPIRING_SOON advance N-day notice from the E1 sweeper (idempotent), and registers
every event default-ON in DEFAULT_PUSH_EVENT_TYPES + action_url deep-links.
Verify RENEWED/RENEWAL_FAILED/EXPIRED (E1) still fire."""
import sys, os, py_compile

ROOT = sys.argv[1] if len(sys.argv) > 1 else os.path.expanduser("~/dev/testlogon")

# (relpath, marker_substring_meaning_already_applied, old, new)
EDITS = [
    # ---------------- alerts.py ----------------
    ("app/services/alerts.py", "subscription_new_subscriber",
     '    "subscription_expired",         # SUB-E1: subscription access ended\n]',
     '    "subscription_expired",         # SUB-E1: subscription access ended\n'
     '    "subscription_new_subscriber",  # SUB-E5: a new subscriber joined (creator)\n'
     '    "subscription_canceled",        # SUB-E5: a subscription was canceled\n'
     '    "subscription_gifted",          # SUB-E5: a gift subscription\n]'),

    ("app/services/alerts.py", "# Subscriptions (SUB-E1/E5)",
     '    "cart.abandoned",\n    # Achievements (ENGAGE-001)',
     '    # Subscriptions (SUB-E1/E5): lifecycle notifications (default-on transactional)\n'
     '    "subscription_renewed","subscription_renewal_failed","subscription_expiring","subscription_expired",\n'
     '    "subscription_new_subscriber","subscription_canceled","subscription_gifted",\n'
     '    "cart.abandoned",\n    # Achievements (ENGAGE-001)'),

    ("app/services/alerts.py", '"subscription_renewed": "/subscriptions/manage"',
     '        "subscription_started": "/subscriptions",\n',
     '        "subscription_started": "/subscriptions",\n'
     '        "subscription_new_subscriber": "/subscriptions/subscribers",\n'
     '        "subscription_renewed": "/subscriptions/manage",\n'
     '        "subscription_renewal_failed": "/subscriptions/manage",\n'
     '        "subscription_expiring": "/subscriptions/manage",\n'
     '        "subscription_expired": "/subscriptions/manage",\n'
     '        "subscription_canceled": "/subscriptions/manage",\n'
     '        "subscription_gifted": "/subscriptions/manage",\n'),

    # ---------------- subscription_server.py: SUBSCRIBE (subscriber side) ----------------
    ("app/routers/subscription_server.py", "SUB-E5: notify the SUBSCRIBER too",
     '        logger.warning("subscription social alert failed creator=%s", plan["creator_id"], exc_info=True)\n'
     '    audit_event(\n        "subscription_started",\n        subscriber_id,\n',
     '        logger.warning("subscription social alert failed creator=%s", plan["creator_id"], exc_info=True)\n'
     '    # SUB-E5: notify the SUBSCRIBER too ("You subscribed to {creator}") - default-on push,\n'
     '    # deep-link to manage. actor=creator so emit_social_alert does NOT self-suppress.\n'
     '    try:\n'
     '        from app.services.social_alerts import emit_social_alert as _emit_sa\n'
     '        from app.services.profile import get_profile_identity as _gpi\n'
     '        _creator_name = _gpi(plan["creator_id"]).get("display_name") or plan["creator_id"]\n'
     '        _emit_sa(\n'
     '            recipient_user_id=subscriber_id,\n'
     '            alert_type="subscription_started",\n'
     '            actor_user_id=plan["creator_id"],\n'
     '            actor_display_name=_creator_name,\n'
     '            title=f"You subscribed to {_creator_name}",\n'
     '            details={"plan_id": plan_id, "creator_id": plan["creator_id"], "subscription_id": subscription_id},\n'
     '            action_url="/subscriptions/manage",\n'
     '        )\n'
     '    except Exception:\n'
     '        logger.warning("subscription social alert failed subscriber=%s", subscriber_id, exc_info=True)\n'
     '    audit_event(\n        "subscription_started",\n        subscriber_id,\n'),

    # ---------------- subscription_server.py: GIFT (gifter + creator) ----------------
    ("app/routers/subscription_server.py", "SUB-E5: notify the GIFTER",
     '        logger.warning("gift social alert failed recipient=%s", recipient_id, exc_info=True)\n'
     '    audit_event("subscription_gifted", gifter_id, request, outcome="success", subscription_id=subscription_id, plan_id=plan_id, recipient_id=recipient_id, price_cents=int(price_cents))\n',
     '        logger.warning("gift social alert failed recipient=%s", recipient_id, exc_info=True)\n'
     '    # SUB-E5: notify the GIFTER ("your gift was sent") + the CREATOR ("new subscriber via gift").\n'
     '    try:\n'
     '        from app.services.social_alerts import emit_social_alert as _emit_sa\n'
     '        from app.services.profile import get_profile_identity as _gpi\n'
     '        _recipient_name = _gpi(recipient_id).get("display_name") or recipient_id\n'
     '        _gifter_name2 = _gpi(gifter_id).get("display_name") or gifter_id\n'
     '        _emit_sa(\n'
     '            recipient_user_id=gifter_id,\n'
     '            alert_type="subscription_gifted",\n'
     '            actor_user_id=recipient_id,\n'
     '            actor_display_name=_recipient_name,\n'
     '            title=f"Your gift to {_recipient_name} was sent",\n'
     '            details={"plan_id": plan_id, "subscription_id": subscription_id, "recipient_id": recipient_id, "creator_id": plan["creator_id"]},\n'
     '            action_url="/subscriptions/manage",\n'
     '        )\n'
     '        _emit_sa(\n'
     '            recipient_user_id=plan["creator_id"],\n'
     '            alert_type="subscription_gifted",\n'
     '            actor_user_id=gifter_id,\n'
     '            actor_display_name=_gifter_name2,\n'
     '            title=f"{_recipient_name} joined via a gift subscription",\n'
     '            details={"plan_id": plan_id, "subscription_id": subscription_id, "subscriber_id": recipient_id, "gifter_id": gifter_id, "gift": True},\n'
     '            action_url="/subscriptions/subscribers",\n'
     '        )\n'
     '    except Exception:\n'
     '        logger.warning("gift social alert (gifter/creator) failed gifter=%s", gifter_id, exc_info=True)\n'
     '    audit_event("subscription_gifted", gifter_id, request, outcome="success", subscription_id=subscription_id, plan_id=plan_id, recipient_id=recipient_id, price_cents=int(price_cents))\n'),

    # ---------------- subscription_server.py: CANCEL (subscriber + creator push) ----------------
    ("app/routers/subscription_server.py", "SUB-E5: promote cancel to default-on PUSH",
     '        payload={"subscription_id": subscription_id, "creator_id": sub["creator_id"]},\n'
     '    )\n'
     '    audit_event(\n'
     '        "subscription_canceled",\n'
     '        sub["subscriber_id"],\n',
     '        payload={"subscription_id": subscription_id, "creator_id": sub["creator_id"]},\n'
     '    )\n'
     '    # SUB-E5: promote cancel to default-on PUSH for BOTH parties, deep-linked.\n'
     '    try:\n'
     '        from app.services.social_alerts import emit_social_alert as _emit_sa\n'
     '        from app.services.profile import get_profile_identity as _gpi\n'
     '        _c_name = _gpi(sub["creator_id"]).get("display_name") or sub["creator_id"]\n'
     '        _s_name = _gpi(sub["subscriber_id"]).get("display_name") or sub["subscriber_id"]\n'
     '        _ends = int(sub.get("current_period_end") or 0)\n'
     '        _sub_title = ("Your subscription to %s is canceled" % _c_name) if not sub.get("cancel_at_period_end") else ("Your subscription to %s ends soon" % _c_name)\n'
     '        _emit_sa(\n'
     '            recipient_user_id=sub["subscriber_id"],\n'
     '            alert_type="subscription_canceled",\n'
     '            actor_user_id=sub["creator_id"],\n'
     '            actor_display_name=_c_name,\n'
     '            title=_sub_title,\n'
     '            details={"subscription_id": subscription_id, "creator_id": sub["creator_id"], "ends_at": _ends, "cancel_at_period_end": bool(sub.get("cancel_at_period_end"))},\n'
     '            action_url="/subscriptions/manage",\n'
     '        )\n'
     '        _emit_sa(\n'
     '            recipient_user_id=sub["creator_id"],\n'
     '            alert_type="subscription_canceled",\n'
     '            actor_user_id=sub["subscriber_id"],\n'
     '            actor_display_name=_s_name,\n'
     '            title=f"{_s_name} canceled their subscription",\n'
     '            details={"subscription_id": subscription_id, "subscriber_id": sub["subscriber_id"]},\n'
     '            action_url="/subscriptions/subscribers",\n'
     '        )\n'
     '    except Exception:\n'
     '        logger.warning("cancel social alert failed sub=%s", subscription_id, exc_info=True)\n'
     '    audit_event(\n'
     '        "subscription_canceled",\n'
     '        sub["subscriber_id"],\n'),

    # ---------------- subscription_renewal.py ----------------
    ("app/services/subscription_renewal.py", 'action_url: str = "/subscriptions/manage"',
     'def _emit(alert_type: str, *, recipient: str, actor: str, title: str, details: Dict[str, Any]) -> None:',
     'def _emit(alert_type: str, *, recipient: str, actor: str, title: str, details: Dict[str, Any], action_url: str = "/subscriptions/manage") -> None:'),

    ("app/services/subscription_renewal.py", "action_url=action_url,\n        )\n    except Exception:\n        logger.warning(\"subscription alert",
     '            title=title,\n            details=details,\n            action_url="/subscriptions",\n        )',
     '            title=title,\n            details=details,\n            action_url=action_url,\n        )'),

    ("app/services/subscription_renewal.py", "update your card",
     '        title="Your subscription payment failed",',
     '        title="Your subscription payment failed — update your card",'),

    ("app/services/subscription_renewal.py", "SUB-E5 creator renewed deep-link",
     '        details={"subscription_id": subscription_id, "plan_id": sub.get("plan_id"), "subscriber_id": sub["subscriber_id"], "amount_cents": int(amount)},\n'
     '    )\n'
     '    _bucket = "trial_converted" if trial_conversion else "renewed"',
     '        details={"subscription_id": subscription_id, "plan_id": sub.get("plan_id"), "subscriber_id": sub["subscriber_id"], "amount_cents": int(amount)},\n'
     '        action_url="/subscriptions/subscribers",  # SUB-E5 creator renewed deep-link\n'
     '    )\n'
     '    _bucket = "trial_converted" if trial_conversion else "renewed"'),

    # summary bucket
    ("app/services/subscription_renewal.py", '"expiring_soon": [],',
     '        "trial_converted": [],\n        "plan_changed": [],\n    }',
     '        "trial_converted": [],\n        "plan_changed": [],\n        "expiring_soon": [],\n    }'),

    # advance-notice helper (inserted before _process)
    ("app/services/subscription_renewal.py", "def _maybe_expiring_notice",
     'def _process(sub: Dict[str, Any], now: int, summary: Dict[str, Any]) -> None:',
     'def _expiring_notice_days() -> int:\n'
     '    try:\n'
     '        return int(getattr(S, "subscription_expiring_notice_days", 3))\n'
     '    except Exception:\n'
     '        return 3\n'
     '\n'
     '\n'
     'def _maybe_expiring_notice(sub: Dict[str, Any], now: int, boundary: int, summary: Dict[str, Any]) -> None:\n'
     '    """SUB-E5 (SUB-52): emit an ADVANCE \'subscription_expiring\' notice N days before a\n'
     '    non-renewing subscription lapses (canceling / auto_renew off / trial ending). Fires\n'
     '    ONCE per boundary (idempotent via the ``expiring_notified_period`` marker so repeated\n'
     '    sweeps never re-notify)."""\n'
     '    if not boundary or boundary <= now:\n'
     '        return\n'
     '    window = _expiring_notice_days() * 86400\n'
     '    if boundary - now > window:\n'
     '        return\n'
     '    if int(sub.get("expiring_notified_period") or 0) == boundary:\n'
     '        return\n'
     '    sub["expiring_notified_period"] = boundary\n'
     '    sub["updated_at"] = now\n'
     '    _save(sub)\n'
     '    _emit(\n'
     '        "subscription_expiring",\n'
     '        recipient=sub["subscriber_id"],\n'
     '        actor=sub["creator_id"],\n'
     '        title="Your subscription is ending soon",\n'
     '        details={"subscription_id": sub["subscription_id"], "plan_id": sub.get("plan_id"), "creator_id": sub["creator_id"], "ends_at": boundary},\n'
     '    )\n'
     '    summary.setdefault("expiring_soon", []).append({"subscription_id": sub["subscription_id"], "ends_at": boundary})\n'
     '    logger.info("subscription_expiring_advance id=%s ends_at=%s", sub["subscription_id"], boundary)\n'
     '\n'
     '\n'
     'def _process(sub: Dict[str, Any], now: int, summary: Dict[str, Any]) -> None:'),

    # trialing branch advance notice
    ("app/services/subscription_renewal.py", "_maybe_expiring_notice(sub, now, trial_end, summary)",
     '        if trial_end and trial_end <= now:\n'
     '            _attempt_renewal(sub, now, summary, trial_conversion=True)\n'
     '        return',
     '        if trial_end and trial_end <= now:\n'
     '            _attempt_renewal(sub, now, summary, trial_conversion=True)\n'
     '        else:\n'
     '            _maybe_expiring_notice(sub, now, trial_end, summary)\n'
     '        return'),

    # canceling branch advance notice
    ("app/services/subscription_renewal.py", "_maybe_expiring_notice(sub, now, cpe, summary)\n        return\n    if status not in",
     '            logger.info("subscription_canceled_at_period_end id=%s", sub["subscription_id"])\n'
     '        return\n'
     '    if status not in ("active", "past_due"):\n'
     '        return',
     '            logger.info("subscription_canceled_at_period_end id=%s", sub["subscription_id"])\n'
     '        else:\n'
     '            _maybe_expiring_notice(sub, now, cpe, summary)\n'
     '        return\n'
     '    if status not in ("active", "past_due"):\n'
     '        return'),

    # active not-auto_renew advance notice
    ("app/services/subscription_renewal.py", "if not auto_renew or cancel_ape:",
     '        due = (nbd and nbd <= now) or (cpe and cpe <= now)\n'
     '        if not due:\n'
     '            return',
     '        due = (nbd and nbd <= now) or (cpe and cpe <= now)\n'
     '        if not due:\n'
     '            if not auto_renew or cancel_ape:\n'
     '                _maybe_expiring_notice(sub, now, cpe, summary)\n'
     '            return'),
]


def main():
    import time, shutil
    TS = os.environ.get("SUBE5_TS") or str(int(time.time()))
    from collections import defaultdict
    byfile = defaultdict(list)
    for relpath, marker, old, new in EDITS:
        byfile[relpath].append((marker, old, new))

    overall_ok = True
    for relpath, edits in byfile.items():
        path = os.path.join(ROOT, relpath)
        with open(path, "r", encoding="utf-8") as f:
            src = f.read()
        orig = src
        for marker, old, new in edits:
            if marker in src:
                print("SKIP  (already applied) %-42s :: %s" % (relpath, marker[:48]))
                continue
            cnt = src.count(old)
            if cnt != 1:
                print("FAIL  anchor count=%d (expected 1) %-30s :: %s" % (cnt, relpath, marker[:48]))
                overall_ok = False
                continue
            src = src.replace(old, new, 1)
            print("APPLY %-42s :: %s" % (relpath, marker[:48]))
        if src != orig and not os.environ.get("DRY"):
            if os.environ.get("BAK"):
                bak = path + ".bak_sube5_" + TS
                if not os.path.exists(bak):
                    shutil.copy2(path, bak)
                    print("BAK   %s" % bak)
            with open(path, "w", encoding="utf-8") as f:
                f.write(src)
            try:
                py_compile.compile(path, doraise=True)
                print("PYC   OK %s" % relpath)
            except py_compile.PyCompileError as e:
                print("PYC   FAIL %s :: %s" % (relpath, e))
                overall_ok = False
    print("OVERALL", "OK" if overall_ok else "FAIL")
    sys.exit(0 if overall_ok else 1)


if __name__ == "__main__":
    main()
